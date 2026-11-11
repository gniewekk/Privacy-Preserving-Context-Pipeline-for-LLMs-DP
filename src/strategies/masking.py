"""Strategia nieodwracalnego maskowania znaków (MaskingStrategy)."""

from __future__ import annotations

from domain.models import AnonymizationRequest, AnonymizationResult, DetectedEntity


class MaskingStrategy:
    """Zastępuje znaki encji symbolem maskującym (np. gwiazdką) lub etykietą [REDACTED]."""

    strategy_id: str = "masking_strategy"

    def __init__(
        self,
        *,
        mask_char: str = "*",
        preserve_length: bool = True,
    ) -> None:
        self.mask_char = mask_char
        self.preserve_length = preserve_length

    def is_reversible(self) -> bool:
        return False

    def anonymize(
        self,
        entity: DetectedEntity,
        request: AnonymizationRequest,
    ) -> AnonymizationResult:
        if self.preserve_length:
            replacement = self.mask_char * len(entity.value)
        else:
            replacement = f"[{entity.entity_type.value}_REDACTED]"

        return AnonymizationResult(
            replacement=replacement,
            strategy_id=self.strategy_id,
            entity_type=entity.entity_type,
            reversible=False,
        )

