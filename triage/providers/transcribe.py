"""Speech-to-text providers.

MockTranscriber lets the whole pipeline run offline: it reads a transcript
stored in the WAV file's LIST/INFO "ICMT" (comment) chunk, which the demo
samples include. WhisperTranscriber runs a real local model if the
optional openai-whisper package is installed.
"""

from __future__ import annotations

import struct
from pathlib import Path


class TranscriptionError(Exception):
    pass


def _riff_chunks(data: bytes):
    """Yield (chunk_id, payload) for each chunk in a RIFF file, recursing
    into LIST chunks."""
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        raise TranscriptionError("not a WAV file")
    pos = 12
    while pos + 8 <= len(data):
        cid = data[pos:pos + 4]
        (size,) = struct.unpack("<I", data[pos + 4:pos + 8])
        payload = data[pos + 8:pos + 8 + size]
        if cid == b"LIST" and payload[:4] == b"INFO":
            sub = 4
            while sub + 8 <= len(payload):
                sid = payload[sub:sub + 4]
                (ssize,) = struct.unpack("<I", payload[sub + 4:sub + 8])
                yield sid, payload[sub + 8:sub + 8 + ssize]
                sub += 8 + ssize + (ssize & 1)
        else:
            yield cid, payload
        pos += 8 + size + (size & 1)  # chunks are padded to even sizes


def wav_with_transcript(transcript: str, seconds: float = 0.5, rate: int = 8000) -> bytes:
    """Build a short silent mono WAV with the transcript in an ICMT chunk."""
    pcm = b"\x00\x00" * int(seconds * rate)
    fmt = struct.pack("<HHIIHH", 1, 1, rate, rate * 2, 2, 16)
    text = transcript.encode("utf-8") + b"\x00"
    if len(text) % 2:
        text += b"\x00"
    info = b"INFO" + b"ICMT" + struct.pack("<I", len(text)) + text
    body = (b"WAVE"
            + b"fmt " + struct.pack("<I", len(fmt)) + fmt
            + b"data" + struct.pack("<I", len(pcm)) + pcm
            + b"LIST" + struct.pack("<I", len(info)) + info)
    return b"RIFF" + struct.pack("<I", len(body)) + body


class MockTranscriber:
    name = "mock"

    def transcribe(self, path: Path) -> str:
        data = Path(path).read_bytes()
        if data[:4] != b"RIFF":
            raise TranscriptionError(
                "the mock transcriber only reads WAV files with an embedded transcript; "
                "set TRIAGE_TRANSCRIBER=whisper for real audio")
        for cid, payload in _riff_chunks(data):
            if cid == b"ICMT":
                return payload.rstrip(b"\x00").decode("utf-8", errors="replace").strip()
        raise TranscriptionError("WAV has no embedded transcript; use TRIAGE_TRANSCRIBER=whisper")


class WhisperTranscriber:
    name = "whisper"

    def __init__(self, model: str = "base"):
        try:
            import whisper  # type: ignore
        except ImportError as e:
            raise SystemExit("TRIAGE_TRANSCRIBER=whisper needs: pip install openai-whisper (and ffmpeg)") from e
        self._model = whisper.load_model(model)

    def transcribe(self, path: Path) -> str:
        result = self._model.transcribe(str(path), fp16=False)
        return str(result.get("text", "")).strip()


def make_transcriber(name: str):
    if name == "mock":
        return MockTranscriber()
    if name == "whisper":
        return WhisperTranscriber()
    raise SystemExit(f"unknown transcriber {name!r} (use mock or whisper)")
