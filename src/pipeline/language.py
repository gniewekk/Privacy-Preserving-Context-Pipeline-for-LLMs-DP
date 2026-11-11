"""Language detection adapters used by the inbound pipeline."""

from __future__ import annotations

from langdetect import DetectorFactory, detect_langs  # type: ignore[import-untyped]

from domain.protocols import LanguageDetector


class StatisticalLanguageDetector:
    """Detect English or Polish with a deterministic statistical language detector."""

    def __init__(
        self,
        supported_languages: frozenset[str] = frozenset({"en", "pl"}),
        min_confidence: float = 0.80,
    ) -> None:
        if not supported_languages:
            raise ValueError("At least one language must be configured.")
        self._supported_languages = frozenset(
            language.lower() for language in supported_languages
        )
        if not 0.0 <= min_confidence <= 1.0:
            raise ValueError("Language confidence threshold must be between 0.0 and 1.0.")
        self._min_confidence = min_confidence
        DetectorFactory.seed = 0

    def detect(self, text: str) -> str:
        """Return the detected ISO-639-1 code, or ``unknown`` when inconclusive."""
        if not text.strip():
            return "unknown"

        predictions = detect_langs(text)
        if not predictions:
            return "unknown"
        prediction = predictions[0]
        if float(prediction.prob) < self._min_confidence:
            return "unknown"
        detected = str(prediction.lang).lower()
        return detected if detected in self._supported_languages else "unknown"


def default_language_detector() -> LanguageDetector:
    """Create the production language detector."""
    return StatisticalLanguageDetector()
