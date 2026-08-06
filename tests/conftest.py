"""Shared fixtures for the dBA test suite.

IMPORTANT: MD_TEMP_DIR is set BEFORE `import main`, because main reads its
configuration from the environment at import time. conftest.py is imported by
pytest before any test module, so setting it here applies to the whole run.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

# --- point the service at a throwaway working dir, then import it -------------
_TMP = tempfile.mkdtemp(prefix="dba-tests-")
os.environ["MD_TEMP_DIR"] = _TMP

import main  # noqa: E402  (must follow the env assignment above)
from fastapi.testclient import TestClient  # noqa: E402

# ffmpeg/ffprobe are only needed by the integration tests; the policy-engine
# tests run on synthetic dicts and need nothing external.
HAVE_FFMPEG = bool(shutil.which("ffmpeg") and shutil.which("ffprobe"))
requires_ffmpeg = pytest.mark.skipif(not HAVE_FFMPEG, reason="ffmpeg/ffprobe not on PATH")


def _ffmpeg(*args: str) -> None:
    subprocess.run(["ffmpeg", "-y", "-hide_banner", "-v", "error", *args], check=True)


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(_TMP, ignore_errors=True)


@pytest.fixture(scope="session")
def app_main():
    return main


@pytest.fixture(scope="session")
def client():
    return TestClient(main.app)


@pytest.fixture(scope="session")
def tmp_dir() -> Path:
    return Path(_TMP)


@pytest.fixture(scope="session")
def clean_wav(tmp_dir: Path) -> Path:
    """A benign 0.5s tone with no tags."""
    p = tmp_dir / "clean.wav"
    _ffmpeg("-fflags", "+bitexact", "-f", "lavfi", "-i", "sine=frequency=440:duration=0.5",
            "-ar", "16000", "-ac", "1", "-bitexact", str(p))
    return p


@pytest.fixture(scope="session")
def hostile_wav(tmp_dir: Path) -> Path:
    """The spec's hostile WAV. -fflags +bitexact keeps ISFT verbatim instead of
    letting ffmpeg overwrite it with its own encoder stamp."""
    p = tmp_dir / "hostile.wav"
    _ffmpeg("-fflags", "+bitexact", "-f", "lavfi", "-i", "sine=frequency=440:duration=0.01",
            "-ar", "16000", "-ac", "1", "-bitexact",
            "-metadata", "ISFT=[VIPER] <SEIZURE_SHORT> OP=<OPERATION_ID> -dbug",
            "-metadata", "ICMT=[VIPER] <OP_ID>",
            "-metadata", "INAM=-dbug",
            str(p))
    return p


@pytest.fixture(scope="session")
def padded_wav(clean_wav: Path, tmp_dir: Path) -> Path:
    """A real WAV with 5MB of trailing zeros appended (covert-channel shape)."""
    p = tmp_dir / "padded.wav"
    p.write_bytes(clean_wav.read_bytes() + b"\x00" * 5_000_000)
    return p
