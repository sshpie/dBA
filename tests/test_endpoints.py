"""Integration tests driving the real FastAPI + ffmpeg stack.

Skipped automatically if ffmpeg/ffprobe are not installed.
"""
from __future__ import annotations

import logging
from pathlib import Path

import pytest

from conftest import requires_ffmpeg

pytestmark = requires_ffmpeg

ANALYZE = "/analyze-and-sanitize-audio"


def _post(client, path: Path, endpoint: str = ANALYZE, **params):
    with open(path, "rb") as f:
        return client.post(endpoint, params=params, files={"file": ("upload", f, "audio/wav")})


# --------------------------------------------------------------------------- #
# /analyze-and-sanitize-audio — disposition matrix
# --------------------------------------------------------------------------- #
def test_clean_file_allowed(client, clean_wav):
    r = _post(client, clean_wav, mode="strict")
    j = r.json()
    assert r.status_code == 200
    assert j["disposition"] == "allow"
    assert j["risk_score"] == 0
    assert j["sanitized_file_path"]  # a stripped copy is produced
    assert j["sanitized_metadata"]["tags"] == {}


def test_hostile_file_rejected_with_422_and_no_file(client, hostile_wav):
    r = _post(client, hostile_wav, mode="strict")
    j = r.json()
    assert r.status_code == 422              # fail-fast
    assert j["disposition"] == "reject"
    assert j["risk_score"] == 100
    assert j["sanitized_file_path"] is None  # nothing sanitized or forwarded


def test_hostile_file_audit_allows_but_scores(client, hostile_wav):
    r = _post(client, hostile_wav, mode="audit")
    j = r.json()
    assert r.status_code == 200
    assert j["disposition"] == "allow"
    assert j["risk_score"] == 100
    assert {i["id"] for i in j["indicators"]} >= {"TAG_VIPER", "TAG_OPERATION_ID"}


def test_padded_file_quarantined_on_structure_alone(client, padded_wav):
    r = _post(client, padded_wav, mode="strict")
    j = r.json()
    assert r.status_code == 200
    assert j["disposition"] == "quarantine"
    assert "TRAILING_DATA" in {i["id"] for i in j["indicators"]}


def test_invalid_mode_rejected(client, clean_wav):
    assert _post(client, clean_wav, mode="banana").status_code == 400


def test_empty_upload_rejected(client, tmp_dir):
    empty = tmp_dir / "empty.wav"
    empty.write_bytes(b"")
    assert _post(client, empty, mode="strict").status_code == 400


def test_unparseable_upload_rejected(client, tmp_dir):
    junk = tmp_dir / "junk.wav"
    junk.write_bytes(b"this is not audio" * 100)
    assert _post(client, junk, mode="strict").status_code == 422


# --------------------------------------------------------------------------- #
# strip correctness
# --------------------------------------------------------------------------- #
def test_sanitized_output_has_no_metadata(client, app_main, clean_wav):
    out = _post(client, clean_wav, mode="strict").json()["sanitized_file_path"]
    probed = app_main.extract_raw_metadata(Path(out))
    assert probed.get("format", {}).get("tags", {}) == {}
    for s in probed.get("streams", []):
        assert s.get("tags", {}) == {}


# --------------------------------------------------------------------------- #
# legacy /sanitize-audio
# --------------------------------------------------------------------------- #
def test_legacy_sanitize_returns_alerts(client, hostile_wav):
    r = _post(client, hostile_wav, endpoint="/sanitize-audio")
    j = r.json()
    assert r.status_code == 200
    assert len(j["alerts"]) > 0
    assert j["sanitized_metadata"]["tags"] == {}
    assert j["sanitized_file_path"]


# --------------------------------------------------------------------------- #
# security: raw tag values must never reach the logs
# --------------------------------------------------------------------------- #
def test_raw_tag_values_are_not_logged(client, hostile_wav, caplog):
    with caplog.at_level(logging.INFO, logger="dBA"):
        _post(client, hostile_wav, mode="audit")
    assert "TAG_VIPER" in caplog.text        # indicator IDs are logged
    assert "[VIPER]" not in caplog.text      # raw values are NOT


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}
