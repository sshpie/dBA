# dBA — audio metadata firewall

**dBA** (decibels, A-weighted) is a lightweight defensive **metadata firewall**
that neutralizes attacker-controlled audio metadata before it reaches ASR
pipelines, logs, or LLMs.

Audio-only (WAV, MP3, FLAC, Ogg, AAC, m4a via ffprobe). No images/EXIF.

## Overview

dBA is a lightweight FastAPI microservice that sits in front of ASR systems
(e.g., Whisper or faster-whisper). It inspects only audio file metadata (ID3
tags, RIFF INFO/LIST chunks, structural properties via ffprobe), assigns a risk
score based on suspicious indicators, decides allow / quarantine / reject,
strips all metadata with ffmpeg, and returns a clean audio file plus a forensic
JSON report.

## Why

Media metadata — WAV `LIST`/`INFO` chunks (`ISFT`, `ICMT`, `INAM`), MP3 ID3
tags, embedded cover-art streams — is attacker-controlled free-form text.
Forwarded downstream verbatim it is a log-injection, stored-XSS, prompt-
injection, PII-leak, and secret-exfil vector. dBA does three things at once:

1. **Reports** — structured indicators for suspicious tags *and* structural anomalies.
2. **Scores & decides** — a 0–100 risk score and an `allow` / `quarantine` / `reject` disposition.
3. **Removes** — a re-muxed copy with *all* metadata stripped, which is what you forward to ASR (never the original).

## Best places to deploy it

It shines in these environments:

- **Production voice AI / ASR systems** that accept user-uploaded or externally sourced audio
  - Customer support / contact-center voice bots
  - Voice agents (Retell, Vapi, PolyAI-style platforms, custom agents)
  - Any app that lets users upload recordings for transcription
- **LLM-powered conversational systems**
  - Where transcripts or any file-derived data might reach an LLM (prompt-injection risk via metadata is the key concern)
- **High-security or regulated domains**
  - Healthcare voice documentation
  - Finance / insurance call processing
  - Enterprise media ingestion pipelines
  - Any system that logs audio metadata or feeds it into other tools
- **Microservice / media-processing pipelines**
  - As the first hop before Whisper, Deepgram, AssemblyAI, or similar STT services
  - In Dockerized or Kubernetes setups where you want a small, focused security layer

## How dBA differs from existing tools

The primitives here are old — metadata stripping, content scanning, risk
scoring. What is uncommon is the combination and the placement: a security
control at the audio → ASR → LLM ingestion point.

- **vs. metadata strippers** (`ffmpeg -map_metadata -1`, exiftool, mutagen):
  those *remove* tags for privacy; dBA *inspects, risk-scores, and decides*
  (allow / quarantine / reject) before stripping, and emits a forensic report —
  a security control, not a privacy utility.
- **vs. enterprise CDR** (Content Disarm & Reconstruction — OPSWAT, Votiro,
  Glasswall): dBA applies the same disarm → reconstruct → report pattern, but is
  small, open-source, and purpose-built for the **audio → ASR → LLM** path —
  including prompt-injection-via-metadata and audio-container structural checks
  those document-centric suites do not focus on.
- **vs. DLP / WAF content scanning**: those inspect text payloads in transit;
  dBA sits at **file ingestion, before transcription**, and understands audio
  container structure (RIFF/ID3/streams), not just strings.
- **vs. voice-AI security research**: that field targets the *waveform*
  (adversarial perturbation, ultrasonic/inaudible injection, waveform
  steganography). dBA defends the *container metadata* channel into the
  pipeline — a distinct, under-addressed surface.

## Pipeline

```
ingest   -> save upload under a generated UUID name (filename never trusted)
extract  -> ffprobe -> JSON (read-only introspection; includes on-disk size)
analyze  -> structural checks + tag pattern-matching -> INDICATORS
score    -> weighted risk score (low+10 / med+25 / high+40, capped 100), mode-aware
decide   -> disposition: allow | quarantine | reject
sanitize -> ffmpeg -fflags +bitexact -map_metadata -1 -map 0:a -c copy -bitexact
respond  -> forensic report JSON
```

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/analyze-and-sanitize-audio?mode=strict\|lenient\|audit` | firewall: indicators + risk + disposition |
| POST | `/sanitize-audio` | simple: strip + alerts (backward-compatible) |
| GET  | `/healthz` | liveness |

### Modes

| Mode | allow if | quarantine if | else | notes |
|------|----------|---------------|------|-------|
| `strict`  | score < 10 | score < 40 | reject | +10 to score if any indicator present |
| default   | score < 20 | score < 60 | reject | (no mode / unknown falls back here) |
| `lenient` | score < 30 | score < 80 | reject | −10 to score |
| `audit`   | always allow | — | — | still computes score + indicators; never blocks |

`reject` returns **HTTP 422** with the full report and no `sanitized_file_path`
(fail-fast — the file is never sanitized or forwarded).

## Indicators

**Content** (suspicious strings in tag values) — each has a stable `id` for
SIEM/SOAR keying, a `severity`, the `key`, the `pattern`, and an 80-char
`value_snippet` (never the full value):

`TAG_VIPER`, `TAG_SEIZURE_MARKER`, `TAG_OPERATION_ID`, `TAG_DEBUG_FLAG`,
`TAG_POTENTIAL_SHELL`, `TAG_CMD_SUBSTITUTION`, `TAG_HTML_SCRIPT`,
`TAG_GENERIC_URL`, `TAG_EMAIL_PII`, `TAG_AWS_KEY`, `TAG_PRIVATE_KEY`.

**Structural** (file shape — fire even when tags are clean):

- `UNUSUAL_DURATION` — sub-0.1s clip but a multi-MB file.
- `TRAILING_DATA` — on-disk size far exceeds the audio stream's own data rate ×
  duration (appended payload / polyglot). Uses the **stream** bit_rate, not
  `format.bit_rate` (the latter is derived from file size and would be circular).
- `UNEXPECTED_CODEC` — codec off the expected allowlist.
- `MULTIPLE_AUDIO_STREAMS` — more than one audio stream.
- `EMBEDDED_NONAUDIO_STREAM` — cover-art/video/data stream in an audio upload.

## Run

Docker (ffmpeg/ffprobe baked in):

```bash
docker build -t dba .
docker run --rm -p 8000:8000 dba
```

Local (needs `ffmpeg` + `ffprobe` on `PATH`):

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

## Call it

```bash
curl -s -X POST "http://localhost:8000/analyze-and-sanitize-audio?mode=strict" \
  -F "file=@list_info_metadata.wav" | jq
```

Craft the spec's hostile WAV (`-fflags +bitexact` so ffmpeg keeps your `ISFT`
verbatim instead of overwriting it with its own encoder stamp):

```bash
ffmpeg -y -fflags +bitexact -f lavfi -i "sine=frequency=440:duration=0.01" -ar 16000 -ac 1 -bitexact \
  -metadata ISFT="[VIPER] <SEIZURE_SHORT> OP=<OPERATION_ID> -dbug" \
  -metadata ICMT="[VIPER] <OP_ID>" \
  -metadata INAM="-dbug" list_info_metadata.wav
```

Expected in `strict` mode: indicators `TAG_VIPER` / `TAG_SEIZURE_MARKER` /
`TAG_OPERATION_ID` / `TAG_DEBUG_FLAG`, `risk_score` 100, disposition `reject`
(HTTP 422). ffmpeg stores these WAV INFO keys as `encoder`/`comment`/`title`;
dBA walks **all** tags, so the payloads are caught regardless of key.

```json
{
  "sanitized_metadata": {
    "duration": 0.01, "bit_rate": null, "sample_rate": 16000,
    "channels": 1, "codec_name": "pcm_s16le", "container_format": "wav", "tags": {}
  },
  "indicators": [
    {"id":"TAG_VIPER","severity":"high","key":"encoder","pattern":"\\[VIPER\\]","value_snippet":"[VIPER] <SEIZURE_SHORT> OP=<OPERATION_ID> -dbug"}
  ],
  "risk_score": 100,
  "disposition": "reject",
  "sanitized_file_path": null
}
```

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

`tests/test_policy.py` exercises `analyze_metadata` as a pure function over
synthetic ffprobe dicts (no ffmpeg needed — fast, deterministic). It pins the
two subtle fixes: `TRAILING_DATA` must use the stream rate not `format.bit_rate`
(the circular-metric trap), and severity weights / thresholds / mode math.
`tests/test_endpoints.py` drives the real FastAPI + ffmpeg stack (skipped
automatically if ffmpeg/ffprobe are absent) and asserts the disposition matrix,
the 422 fail-fast, a provably metadata-free strip, and that raw tag values never
reach the logs.

## Security properties

- Original upload filename is never used in a path or command.
- All subprocess calls use argument lists — no `shell=True`, no `os.system`.
- Raw tag **values are never logged** (only indicator IDs, keys, score, disposition).
- Upload size cap (`MD_MAX_UPLOAD_BYTES`, default 200 MiB) + subprocess timeouts.
- Output muxer chosen from an allowlist keyed on ffprobe-detected format — never a caller-supplied extension.
- `-map 0:a` discards cover-art/video streams entirely; `-bitexact` suppresses ffmpeg's own encoder stamp so the strip is genuinely empty.
- Original metadata-bearing file deleted after each request; stripped copy left for the caller to forward and then delete.

## Configuration (env)

| Var | Default | Meaning |
|-----|---------|---------|
| `MD_TEMP_DIR` | system temp | working directory for uploads / output |
| `MD_MAX_UPLOAD_BYTES` | `209715200` | reject uploads larger than this |
| `MD_FFPROBE_TIMEOUT` | `30` | ffprobe timeout (s) |
| `MD_FFMPEG_TIMEOUT` | `120` | ffmpeg timeout (s) |

## Extending

- Add markers → append to `SUSPICIOUS_PATTERNS` (id/severity/regex).
- Allow specific tags through → add keys to `ALLOWED_TAG_KEYS` (e.g. `language`).
- New structural detector → add to `_structural_indicators`.
- Tune posture → adjust `SEVERITY_WEIGHT` or the threshold table in `_decide_disposition`.
```
