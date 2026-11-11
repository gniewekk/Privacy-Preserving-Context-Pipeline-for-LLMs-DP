"""Protokół bazowy detektora (wzorzec Strategy — detekcja encji)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from domain.models import DetectedEntity, Language


class PIIDetector(Protocol):
    """Interfejs strategii detekcji PII/PHI/QID."""

    @property
    def detector_id(self) -> str: ...

    def detect(self, text: str, language: Language) -> Sequence[DetectedEntity]: ...

