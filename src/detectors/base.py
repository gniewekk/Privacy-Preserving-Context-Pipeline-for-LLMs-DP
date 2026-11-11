"""PIIDetector strategy protocol, @register_detector registry, and span merger."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Protocol, TypeVar, runtime_checkable

from domain.models import DetectedEntity


@runtime_checkable
class PIIDetector(Protocol):
    """Strategy interface for detecting PII/PHI and quasi-identifiers in text."""

    @property
    def detector_id(self) -> str:
        """Unique identifier of the detector strategy."""
        ...

    def detect(self, text: str, language: str = "en") -> Sequence[DetectedEntity]:
        """Detect sensitive entities in `text` for the given `language`."""
        ...


TDetector = TypeVar("TDetector", bound=type[PIIDetector])


class DetectorRegistry:
    """Global and instance-level registry for dynamic detector registration."""

    _registered: dict[str, type[PIIDetector]] = {}

    @classmethod
    def register(cls, name: str, detector_cls: type[PIIDetector]) -> None:
        """Register a detector class under `name`."""
        cls._registered[name] = detector_cls

    @classmethod
    def get(cls, name: str) -> type[PIIDetector]:
        """Retrieve a registered detector class by `name`."""
        if name not in cls._registered:
            raise KeyError(f"Detector {name!r} is not registered.")
        return cls._registered[name]

    @classmethod
    def available(cls) -> Mapping[str, type[PIIDetector]]:
        """Return a read-only copy of all registered detector classes."""
        return dict(cls._registered)


def register_detector(name: str) -> Callable[[TDetector], TDetector]:
    """Class decorator registering a PIIDetector implementation in DetectorRegistry."""

    def _decorator(detector_cls: TDetector) -> TDetector:
        DetectorRegistry.register(name, detector_cls)
        return detector_cls

    return _decorator


def resolve_overlapping_spans(
    entities: Sequence[DetectedEntity],
) -> tuple[DetectedEntity, ...]:
    """Merge overlapping DetectedEntity spans deterministically.

    Prioritizes wider character spans and higher confidence scores to favor recall
    (Privacy by Design: False Negatives are critical, False Positives are safe).
    Returned entities are sorted in ascending order of `start` offset.
    """
    if not entities:
        return ()

    # Sort by start ascending, then by span length descending, then confidence descending
    ranked = sorted(
        entities,
        key=lambda e: (e.start, -(e.end - e.start), -e.confidence, e.entity_type.value),
    )

    accepted: list[DetectedEntity] = []
    for candidate in ranked:
        if candidate.end <= candidate.start:
            continue
        overlap_index: int | None = None
        should_add = True
        for idx, existing in enumerate(accepted):
            # Check if candidate overlaps with existing
            if candidate.start < existing.end and candidate.end > existing.start:
                existing_len = existing.end - existing.start
                candidate_len = candidate.end - candidate.start
                # Replace existing only if candidate is longer or has higher confidence
                if candidate_len > existing_len or (
                    candidate_len == existing_len and candidate.confidence > existing.confidence
                ):
                    overlap_index = idx
                else:
                    should_add = False
                break

        if overlap_index is not None:
            accepted[overlap_index] = candidate
        elif should_add:
            accepted.append(candidate)

    return tuple(sorted(accepted, key=lambda e: (e.start, e.end)))
