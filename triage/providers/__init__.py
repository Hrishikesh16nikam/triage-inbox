"""Pluggable AI providers. Each has a dependency-free default so the
project runs anywhere, plus an optional real model."""

from .classify import Classification, OllamaClassifier, RuleClassifier, make_classifier
from .transcribe import MockTranscriber, TranscriptionError, WhisperTranscriber, make_transcriber, wav_with_transcript

__all__ = [
    "Classification", "OllamaClassifier", "RuleClassifier", "make_classifier",
    "MockTranscriber", "TranscriptionError", "WhisperTranscriber", "make_transcriber", "wav_with_transcript",
]
