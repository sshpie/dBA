"""
dBA — a defensive "metadata firewall" in front of an ASR service.

The name is the audio unit (decibels, A-weighted): dBA sits on the wire and
measures what is riding in on the metadata before ASR ever hears the audio.

It behaves like a small SOC analyst scoped entirely to audio metadata. For every
upload it:
    ingest   -> save under a generated name (the original filename is untrusted)
    extract  -> ffprobe -> JSON (read-only introspection)
    analyze  -> structural checks + tag pattern-matching -> INDICATORS
    score    -> weighted risk score (0-100), mode-aware
    decide   -> disposition: allow | quarantine | reject
    sanitize -> ffmpeg re-mux, ALL metadata stripped (unless rejected)
    respond  -> forensic report JSON

Two endpoints:
    POST /sanitize-audio             — simple: strip + alert (backward compatible)
    POST /analyze-and-sanitize-audio — firewall: indicators + risk + disposition

Security posture: every metadata key/value is untrusted. Raw tag values are
never logged. All subprocess calls use argument lists (no shell). Output muxer
is chosen from an allowlist keyed on PROBED content, never the upload filename.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from pathlib import Path
from tempfile import gettempdir
from typing import Optional
from uuid import uuid4

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# --------------------------------------------------------------------------- #
# Configuration (env-overridable so it slots into a container cleanly)
# --------------------------------------------------------------------------- #
TEMP_DIR = Path(os.getenv("MD_TEMP_DIR", gettempdir()))
MAX_UPLOAD_BYTES = int(os.getenv("MD_MAX_UPLOAD_BYTES", str(200 * 1024 * 1024)))  # 200 MiB
READ_CHUNK = 1 << 20  # 1 MiB streaming read
FFPROBE_TIMEOUT = int(os.getenv("MD_FFPROBE_TIMEOUT", "30"))
FFMPEG_TIMEOUT = int(os.getenv("MD_FFMPEG_TIMEOUT", "120"))

VALUE_SNIPPET_LEN = 80  # indicators return only a short snippet, never the full value

# Only these technical fields are ever allowed to survive the policy engine.
ALLOWED_TECHNICAL_FIELDS = {"duration", "bit_rate", "sample_rate", "channels", "codec_name"}
# Tag keys explicitly permitted to pass through into sanitized output. Empty by
# default — the safe stance is that NO free-form tag survives. Add e.g. "language".
ALLOWED_TAG_KEYS: set[str] = set()

# Audio codecs we consider ordinary for an ASR pipeline. Anything else is an
# UNEXPECTED_CODEC indicator (rare codecs are a weak covert-channel signal).
CODEC_ALLOWLIST = {
    "pcm_s16le", "pcm_s24le", "pcm_s32le", "pcm_f32le", "pcm_u8", "pcm_mulaw", "pcm_alaw",
    "mp3", "aac", "flac", "vorbis", "opus",
}

# Detected container (ffprobe format_name token) -> (output extension, ffmpeg muxer).
FORMAT_MAP: dict[str, tuple[str, str]] = {
    "wav": ("wav", "wav"),
    "mp3": ("mp3", "mp3"),
    "flac": ("flac", "flac"),
    "ogg": ("ogg", "ogg"),
    "m4a": ("m4a", "ipod"),
    "mp4": ("m4a", "ipod"),
    "aac": ("aac", "adts"),
}

# Suspicious-content pattern registry. Each entry has a stable ID (so downstream
# SIEM/SOAR can key on it), a severity, and a regex. Matching only RAISES an
# indicator — the tag is dropped regardless.
SUSPICIOUS_PATTERNS: list[dict] = [
    {"id": "TAG_VIPER",           "severity": "high",   "regex": r"\[VIPER\]"},
    {"id": "TAG_SEIZURE_MARKER",  "severity": "high",   "regex": r"<SEIZURE_SHORT>"},
    {"id": "TAG_OPERATION_ID",    "severity": "high",   "regex": r"<OP_ID>|<OPERATION_ID>"},
    {"id": "TAG_DEBUG_FLAG",      "severity": "low",    "regex": r"-dbug\b"},
    {"id": "TAG_POTENTIAL_SHELL", "severity": "high",   "regex": r";\s*curl\b|\bwget\b|\bbash\s+-i"},
    {"id": "TAG_CMD_SUBSTITUTION","severity": "high",   "regex": r"\$\(|`"},
    {"id": "TAG_HTML_SCRIPT",     "severity": "medium", "regex": r"<script\b"},
    {"id": "TAG_GENERIC_URL",     "severity": "low",    "regex": r"\bhttps?://\S+"},
    {"id": "TAG_EMAIL_PII",       "severity": "low",    "regex": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"},
    {"id": "TAG_AWS_KEY",         "severity": "high",   "regex": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"},
    {"id": "TAG_PRIVATE_KEY",     "severity": "high",   "regex": r"-----BEGIN [A-Z ]*PRIVATE KEY-----"},
]
for _e in SUSPICIOUS_PATTERNS:  # compile once; IGNORECASE so casing tricks do not evade
    _e["compiled"] = re.compile(_e["regex"], re.IGNORECASE)

SEVERITY_WEIGHT = {"low": 10, "medium": 25, "high": 40}
VALID_MODES = {"strict", "lenient", "audit"}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("dBA")

app = FastAPI(
    title="dBA",
    version="2.0.0",
    description="dBA — defensive metadata firewall for audio uploaded to ASR pipelines.",
)


# --------------------------------------------------------------------------- #
# Response models
# --------------------------------------------------------------------------- #
class SanitizedMetadata(BaseModel):
    duration: Optional[float] = None
    bit_rate: Optional[int] = None
    sample_rate: Optional[int] = None
    channels: Optional[int] = None
    codec_name: Optional[str] = None
    container_format: Optional[str] = None
    tags: dict[str, str] = {}  # empty by default — no free-form text passes


class Alert(BaseModel):  # legacy /sanitize-audio shape
    key: str
    pattern: str
    value: str


class Indicator(BaseModel):
    id: str
    severity: str
    key: Optional[str] = None            # tag indicators
    pattern: Optional[str] = None        # tag indicators
    value_snippet: Optional[str] = None  # tag indicators — truncated, never full value
    detail: Optional[str] = None         # structural indicators


class SanitizeResponse(BaseModel):
    sanitized_metadata: SanitizedMetadata
    alerts: list[Alert]
    sanitized_file_path: Optional[str] = None


class AnalyzeResponse(BaseModel):
    sanitized_metadata: SanitizedMetadata
    indicators: list[Indicator]
    risk_score: int
    disposition: str
    sanitized_file_path: Optional[str] = None


# --------------------------------------------------------------------------- #
# small coercion helpers
# --------------------------------------------------------------------------- #
def _to_float(v) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _to_int(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _first_audio_stream(streams: list[dict]) -> dict:
    for s in streams:
        if s.get("codec_type") == "audio":
            return s
    return streams[0] if streams else {}


# --------------------------------------------------------------------------- #
# 1. INGEST — persist the upload under a generated name, size-capped
# --------------------------------------------------------------------------- #
async def save_upload(upload: UploadFile) -> Path:
    """Stream the upload to a temp file with a UUID name. The original filename
    is never used in any path or command — it is fully untrusted input."""
    dest = TEMP_DIR / f"upload_{uuid4().hex}"
    size = 0
    try:
        with dest.open("wb") as fh:
            while chunk := await upload.read(READ_CHUNK):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="uploaded file exceeds size limit")
                fh.write(chunk)
    except HTTPException:
        dest.unlink(missing_ok=True)
        raise
    if size == 0:
        dest.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="empty upload")
    return dest


# --------------------------------------------------------------------------- #
# 2. EXTRACT — read-only ffprobe introspection to JSON
# --------------------------------------------------------------------------- #
def extract_raw_metadata(path: Path) -> dict:
    """Run ffprobe with an argument list (no shell) and parse its JSON. ffprobe
    only READS the file; it never executes embedded content. `-show_format`
    includes the on-disk byte size, which the structural analysis relies on."""
    try:
        proc = subprocess.run(
            [
                "ffprobe", "-v", "quiet", "-hide_banner",
                "-print_format", "json",
                "-show_format", "-show_streams",
                str(path),
            ],
            capture_output=True, text=True, timeout=FFPROBE_TIMEOUT, check=False,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=422, detail="media introspection timed out")
    if proc.returncode != 0:
        raise HTTPException(status_code=422, detail="unable to parse media file")
    try:
        return json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        raise HTTPException(status_code=422, detail="malformed media metadata")


# --------------------------------------------------------------------------- #
# 3. ANALYSIS ENGINE
# --------------------------------------------------------------------------- #
def _iter_tag_matches(fmt: dict, streams: list[dict]):
    """Yield (key, pattern_entry, value) for every tag value matching a pattern,
    at both format- and stream-level. Single source of truth for both endpoints."""
    def walk(tags: dict):
        for key, value in (tags or {}).items():
            sval = "" if value is None else str(value)
            for entry in SUSPICIOUS_PATTERNS:
                if entry["compiled"].search(sval):
                    yield str(key), entry, sval

    yield from walk(fmt.get("tags", {}))
    for s in streams:
        yield from walk(s.get("tags", {}))


def _tag_indicators(fmt: dict, streams: list[dict]) -> list[Indicator]:
    """Content-based indicators: suspicious strings inside tag values."""
    return [
        Indicator(
            id=entry["id"],
            severity=entry["severity"],
            key=key,
            pattern=entry["regex"],
            value_snippet=value[:VALUE_SNIPPET_LEN],
        )
        for key, entry, value in _iter_tag_matches(fmt, streams)
    ]


def _structural_indicators(fmt: dict, streams: list[dict]) -> list[Indicator]:
    """Anomalies in the file's shape — independent of tag text. These catch
    covert channels / polyglots that carry NO suspicious strings at all."""
    out: list[Indicator] = []
    audio_streams = [s for s in streams if s.get("codec_type") == "audio"]
    non_audio = [s for s in streams if s.get("codec_type") not in (None, "audio")]

    audio0 = _first_audio_stream(streams)
    size = _to_int(fmt.get("size"))
    duration = _to_float(fmt.get("duration")) or _to_float(audio0.get("duration"))

    # Tiny duration but a large payload — classic "data hidden in a blip" shape.
    if duration is not None and size is not None and duration < 0.1 and size > 1_000_000:
        out.append(Indicator(
            id="UNUSUAL_DURATION", severity="medium",
            detail=f"Duration {duration:.3f}s but file size {size} bytes (suspicious ratio).",
        ))

    # On-disk size far exceeds what the AUDIO STREAM can explain => data appended
    # after the stream (trailing-payload / polyglot). We must use the STREAM's own
    # data rate, not format.bit_rate: ffprobe derives format.bit_rate from
    # size*8/duration, so comparing against it is circular and never fires.
    stream_bit_rate = _to_int(audio0.get("bit_rate"))
    if stream_bit_rate is None:  # PCM: derive from sample geometry
        sr = _to_int(audio0.get("sample_rate"))
        ch = _to_int(audio0.get("channels"))
        bps = _to_int(audio0.get("bits_per_sample")) or _to_int(audio0.get("bits_per_raw_sample"))
        if sr and ch and bps:
            stream_bit_rate = sr * ch * bps
    if size is not None and duration and stream_bit_rate:
        expected = (stream_bit_rate / 8.0) * duration
        if expected > 0 and size > expected * 2 + 65536:
            out.append(Indicator(
                id="TRAILING_DATA", severity="medium",
                detail=(f"File {size} bytes far exceeds ~{int(expected)} bytes of audio expected "
                        f"for the stream (possible appended payload)."),
            ))

    # Rare codec — weak signal, worth surfacing.
    for s in audio_streams:
        codec = s.get("codec_name")
        if codec and codec not in CODEC_ALLOWLIST:
            out.append(Indicator(
                id="UNEXPECTED_CODEC", severity="medium",
                detail=f"Audio codec '{codec}' is not on the expected allowlist.",
            ))

    # More than one audio stream where ASR expects one.
    if len(audio_streams) > 1:
        out.append(Indicator(
            id="MULTIPLE_AUDIO_STREAMS", severity="medium",
            detail=f"{len(audio_streams)} audio streams present (expected 1).",
        ))

    # Embedded non-audio stream (cover art / video / data) in an audio upload —
    # a place metadata and exploits can hide. We strip these with `-map 0:a`.
    if non_audio:
        kinds = sorted({s.get("codec_type", "unknown") for s in non_audio})
        out.append(Indicator(
            id="EMBEDDED_NONAUDIO_STREAM", severity="medium",
            detail=f"Non-audio stream(s) present: {', '.join(kinds)}.",
        ))

    return out


def _base_score(indicators: list[Indicator]) -> int:
    return min(100, sum(SEVERITY_WEIGHT.get(i.severity, 0) for i in indicators))


def _adjust_score(base: int, mode: str, n_indicators: int) -> int:
    if mode == "strict" and n_indicators > 0:
        base += 10
    elif mode == "lenient":
        base -= 10
    return max(0, min(100, base))


def _decide_disposition(score: int, mode: str) -> str:
    if mode == "audit":
        return "allow"  # audit never blocks — it observes and scores only
    allow_max, quarantine_max = {
        "strict":  (10, 40),
        "lenient": (30, 80),
    }.get(mode, (20, 60))  # default thresholds
    if score < allow_max:
        return "allow"
    if score < quarantine_max:
        return "quarantine"
    return "reject"


def analyze_metadata(raw_meta: dict, mode: str = "strict") -> tuple[SanitizedMetadata, list[Indicator], int, str]:
    """Central policy engine. Pure over raw_meta (no filesystem access) so it is
    unit-testable. Returns (sanitized_metadata, indicators, risk_score, disposition)."""
    fmt = raw_meta.get("format", {}) or {}
    streams = raw_meta.get("streams", []) or []
    audio = _first_audio_stream(streams)

    sanitized = SanitizedMetadata(
        duration=_to_float(fmt.get("duration") or audio.get("duration")),
        bit_rate=_to_int(fmt.get("bit_rate") or audio.get("bit_rate")),
        sample_rate=_to_int(audio.get("sample_rate")),
        channels=_to_int(audio.get("channels")),
        codec_name=audio.get("codec_name"),
        container_format=(fmt.get("format_name") or "").split(",")[0] or None,
        tags={k: str(v) for k, v in (fmt.get("tags", {}) or {}).items() if k in ALLOWED_TAG_KEYS},
    )

    indicators = _structural_indicators(fmt, streams) + _tag_indicators(fmt, streams)
    score = _adjust_score(_base_score(indicators), mode, len(indicators))
    disposition = _decide_disposition(score, mode)

    indicators.sort(key=lambda i: (-SEVERITY_WEIGHT.get(i.severity, 0), i.id))
    return sanitized, indicators, score, disposition


# --------------------------------------------------------------------------- #
# 4. SANITIZE — re-mux with all metadata stripped
# --------------------------------------------------------------------------- #
def _resolve_output_format(fmt: dict) -> tuple[str, str]:
    """Map ffprobe's detected format_name to an allowlisted (extension, muxer).
    Content-derived, filename-independent."""
    for token in (fmt.get("format_name") or "").split(","):
        if token.strip() in FORMAT_MAP:
            return FORMAT_MAP[token.strip()]
    raise HTTPException(status_code=415, detail="unsupported media format")


def produce_sanitized_audio(src: Path, fmt: dict) -> Path:
    """Write a metadata-free copy. `-map_metadata -1` drops input tags; `-map 0:a`
    keeps ONLY audio streams (dropping cover-art/video); `-c copy` avoids re-encode;
    `-bitexact` / `-fflags +bitexact` suppress ffmpeg's own encoder/version stamp
    (without it a stray `encoder=Lavf...` tag survives — a silent metadata leak)."""
    ext, muxer = _resolve_output_format(fmt)
    dst = TEMP_DIR / f"sanitized_{uuid4().hex}.{ext}"
    try:
        subprocess.run(
            [
                "ffmpeg", "-y", "-hide_banner", "-v", "error",
                "-fflags", "+bitexact",
                "-i", str(src),
                "-map", "0:a",
                "-map_metadata", "-1",
                "-c", "copy",
                "-bitexact",
                "-f", muxer,
                str(dst),
            ],
            capture_output=True, text=True, timeout=FFMPEG_TIMEOUT, check=True,
        )
    except subprocess.TimeoutExpired:
        dst.unlink(missing_ok=True)
        raise HTTPException(status_code=422, detail="sanitization timed out")
    except subprocess.CalledProcessError:
        dst.unlink(missing_ok=True)
        raise HTTPException(status_code=422, detail="failed to sanitize media")
    return dst


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #
@app.post("/analyze-and-sanitize-audio", response_model=AnalyzeResponse)
async def analyze_and_sanitize_audio(
    file: UploadFile = File(...),
    mode: str = Query("strict", description="strict | lenient | audit"),
) -> JSONResponse:
    """Metadata firewall: analyze, score, decide disposition, and (unless rejected)
    hand back a stripped copy for downstream ASR."""
    if mode not in VALID_MODES:
        raise HTTPException(status_code=400, detail=f"mode must be one of {sorted(VALID_MODES)}")

    src = await save_upload(file)
    try:
        raw = extract_raw_metadata(src)
        sanitized, indicators, score, disposition = analyze_metadata(raw, mode)

        # Log ONLY non-sensitive summary — indicator IDs, keys, score. Never raw values.
        log.info(
            "analyze mode=%s codec=%s indicators=%s score=%d disposition=%s",
            mode, sanitized.codec_name,
            sorted({i.id for i in indicators}), score, disposition,
        )

        if disposition == "reject":
            # Fail fast: do NOT produce or forward a sanitized file. 422 + full report.
            body = AnalyzeResponse(
                sanitized_metadata=sanitized, indicators=indicators,
                risk_score=score, disposition=disposition, sanitized_file_path=None,
            )
            return JSONResponse(status_code=422, content=body.model_dump())

        sanitized_path = str(produce_sanitized_audio(src, raw.get("format", {}) or {}))
        body = AnalyzeResponse(
            sanitized_metadata=sanitized, indicators=indicators,
            risk_score=score, disposition=disposition, sanitized_file_path=sanitized_path,
        )
        return JSONResponse(status_code=200, content=body.model_dump())
    finally:
        src.unlink(missing_ok=True)


@app.post("/sanitize-audio", response_model=SanitizeResponse)
async def sanitize_audio(
    file: UploadFile = File(...),
    strip: bool = Form(True),
) -> SanitizeResponse:
    """Simple path: strip metadata + return alerts (no scoring / disposition)."""
    src = await save_upload(file)
    try:
        raw = extract_raw_metadata(src)
        fmt = raw.get("format", {}) or {}
        streams = raw.get("streams", []) or []
        audio = _first_audio_stream(streams)

        sanitized_meta = SanitizedMetadata(
            duration=_to_float(fmt.get("duration") or audio.get("duration")),
            bit_rate=_to_int(fmt.get("bit_rate") or audio.get("bit_rate")),
            sample_rate=_to_int(audio.get("sample_rate")),
            channels=_to_int(audio.get("channels")),
            codec_name=audio.get("codec_name"),
            container_format=(fmt.get("format_name") or "").split(",")[0] or None,
            tags={},
        )
        alerts = [
            Alert(key=key, pattern=entry["regex"], value=value)
            for key, entry, value in _iter_tag_matches(fmt, streams)
        ]

        sanitized_path: Optional[str] = None
        if strip:
            sanitized_path = str(produce_sanitized_audio(src, fmt))

        log.info(
            "sanitize codec=%s alerts=%d alert_keys=%s stripped=%s",
            sanitized_meta.codec_name, len(alerts),
            sorted({a.key for a in alerts}), bool(strip),
        )
        return SanitizeResponse(
            sanitized_metadata=sanitized_meta, alerts=alerts, sanitized_file_path=sanitized_path,
        )
    finally:
        src.unlink(missing_ok=True)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}
