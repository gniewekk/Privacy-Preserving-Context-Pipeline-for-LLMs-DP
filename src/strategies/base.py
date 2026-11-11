"""Protokół bazowy strategii anonimizacji (kontrakt ADR-002, AGENTS.md §3.2)."""

from __future__ import annotations

from typing import Protocol

from domain.models import AnonymizationRequest, AnonymizationResult, DetectedEntity


class AnonymizationStrategy(Protocol):
    """Interfejs strategii przekształcania encji PII/PHI/QID."""

    @property
    def strategy_id(self) -> str: ...

    def is_reversible(self) -> bool: ...

    def anonymize(
        self,
        entity: DetectedEntity,
        request: AnonymizationRequest,
    ) -> AnonymizationResult: ...

