"""Composite pattern hybrid PII detector (Regex, Transformer NER, and ContextRuleEnhancer)."""

from __future__ import annotations

from collections.abc import Sequence

from detectors.base import PIIDetector, register_detector, resolve_overlapping_spans
from detectors.heuristic import ContextRuleEnhancer
from domain.models import DetectedEntity


@register_detector("composite")
class CompositePIIDetector(PIIDetector):
    """Composite PIIDetector aggregating child detectors and applying ContextRuleEnhancer."""

    def __init__(
        self,
        detectors: Sequence[PIIDetector],
        enhancer: ContextRuleEnhancer | None = None,
    ) -> None:
        self._detectors: tuple[PIIDetector, ...] = tuple(detectors)
        self._enhancer = enhancer or ContextRuleEnhancer()

    @property
    def detector_id(self) -> str:
        child_ids = ",".join(d.detector_id for d in self._detectors)
        return f"composite[{child_ids}]"

    @property
    def detectors(self) -> tuple[PIIDetector, ...]:
        return self._detectors

    def detect(self, text: str, language: str = "en") -> Sequence[DetectedEntity]:
        """Execute all child detectors, apply contextual confidence boosting, and merge spans."""
        raw_entities: list[DetectedEntity] = []
        for detector in self._detectors:
            raw_entities.extend(detector.detect(text, language=language))

        enhanced = self._enhancer.enhance(text, raw_entities)
        return resolve_overlapping_spans(enhanced)
