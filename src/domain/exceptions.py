"""Typowane wyjątki domenowe.

Komunikaty NIGDY nie zawierają surowych wartości PII/PHI — wyłącznie liczby,
identyfikatory typów i nazwy konfiguracji (AGENTS.md §5.4).
"""

from __future__ import annotations


class PrivacyPipelineError(Exception):
    """Bazowy wyjątek potoku."""


class PipelineConfigurationError(PrivacyPipelineError):
    """Niekompletna lub sprzeczna konfiguracja (fail-fast przy budowie komponentów)."""


class ReIdentificationRiskError(PrivacyPipelineError):
    """Fail-closed: nie da się obniżyć ryzyka re-identyfikacji do progu k_min."""

    def __init__(self, k_after: float, k_min: int) -> None:
        self.k_after = k_after
        self.k_min = k_min
        super().__init__(
            f"Re-identification risk too high: estimated k={k_after:.4f} < k_min={k_min}."
        )


class UnsupportedEntityError(PrivacyPipelineError):
    """Strategia nie potrafi obsłużyć danej encji (np. brak drzewa generalizacji)."""

    def __init__(self, strategy_id: str, entity_type: str) -> None:
        super().__init__(f"Strategy '{strategy_id}' does not support entity type '{entity_type}'.")

