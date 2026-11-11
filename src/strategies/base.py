"""AnonymizationStrategy protocol, @register_strategy decorator, and StrategySelector."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Protocol, TypeVar, runtime_checkable

from domain.models import (
    AnonymizationRequest,
    AnonymizationResult,
    DetectedEntity,
    EntityType,
)


@runtime_checkable
class AnonymizationStrategy(Protocol):
    """Strategy interface for anonymizing or pseudonymizing a single DetectedEntity."""

    @property
    def strategy_id(self) -> str:
        """Unique identifier of the anonymization strategy."""
        ...

    def can_reverse(self) -> bool:
        """Return True if the strategy produces reversible tokens backed by TokenizationVault."""
        ...

    def anonymize(
        self,
        entity: DetectedEntity,
        context: AnonymizationRequest,
    ) -> AnonymizationResult:
        """Transform `entity` according to `context` and return an AnonymizationResult."""
        ...


TStrategy = TypeVar("TStrategy", bound=type[AnonymizationStrategy])


class StrategySelector:
    """Selects an AnonymizationStrategy per EntityType (ARCHITECTURE.md §3.2)."""

    _registered_classes: dict[str, type[AnonymizationStrategy]] = {}

    def __init__(
        self,
        strategies: Mapping[EntityType, AnonymizationStrategy] | None = None,
        default_strategy: AnonymizationStrategy | None = None,
    ) -> None:
        self._strategies: dict[EntityType, AnonymizationStrategy] = (
            dict(strategies) if strategies is not None else {}
        )
        self._default_strategy = default_strategy

    @classmethod
    def register_class(cls, name: str, strategy_cls: type[AnonymizationStrategy]) -> None:
        """Register a strategy class by name."""
        cls._registered_classes[name] = strategy_cls

    @classmethod
    def get_class(cls, name: str) -> type[AnonymizationStrategy]:
        """Look up a registered strategy class by `name`."""
        if name not in cls._registered_classes:
            raise KeyError(f"Strategy {name!r} is not registered.")
        return cls._registered_classes[name]

    def register(self, entity_type: EntityType, strategy: AnonymizationStrategy) -> None:
        """Bind `strategy` instance to `entity_type`."""
        self._strategies[entity_type] = strategy

    def select(
        self,
        entity: DetectedEntity | EntityType,
        policy: Any = None,
    ) -> AnonymizationStrategy:
        """Return the strategy bound to the entity's type or the fallback strategy."""
        target_type = entity.entity_type if isinstance(entity, DetectedEntity) else entity
        if target_type in self._strategies:
            return self._strategies[target_type]
        if self._default_strategy is not None:
            return self._default_strategy
        raise KeyError(f"No AnonymizationStrategy registered for {target_type!r}.")

    def has_reversible_strategy(self) -> bool:
        """Return True if any bound or default strategy is reversible."""
        if self._default_strategy is not None and self._default_strategy.can_reverse():
            return True
        return any(s.can_reverse() for s in self._strategies.values())

    @property
    def registered_strategies(self) -> Mapping[EntityType, AnonymizationStrategy]:
        """Return a read-only view of registered entity-to-strategy bindings."""
        return dict(self._strategies)


def register_strategy(name: str) -> Callable[[TStrategy], TStrategy]:
    """Class decorator registering an AnonymizationStrategy in StrategySelector."""

    def _decorator(strategy_cls: TStrategy) -> TStrategy:
        StrategySelector.register_class(name, strategy_cls)
        return strategy_cls

    return _decorator


@register_strategy("tokenization")
class TokenizationStrategy(AnonymizationStrategy):
    """Deterministic tokenization strategy (`<ENTITY_TYPE_N>`) (ARCHITECTURE.md §3.2)."""

    def __init__(self, reversible: bool = False) -> None:
        self._reversible = reversible

    @property
    def strategy_id(self) -> str:
        return "tokenization_strategy"

    def can_reverse(self) -> bool:
        return self._reversible

    def anonymize(
        self,
        entity: DetectedEntity,
        context: AnonymizationRequest,
    ) -> AnonymizationResult:
        placeholder = f"<{entity.entity_type.value}_{context.entity_index}>"
        token_id = (
            f"tok_{context.request_id}_{entity.entity_type.value.lower()}_{context.entity_index}"
        )
        return AnonymizationResult(
            replacement_text=placeholder,
            entity_type=entity.entity_type,
            is_reversible=self._reversible,
            token_id=token_id if self._reversible else None,
        )


@register_strategy("masking")
class MaskingStrategy(AnonymizationStrategy):
    """Irreversible character masking strategy (ARCHITECTURE.md §3.2)."""

    def __init__(self, mask_char: str = "*", preserve_length: bool = True) -> None:
        self._mask_char = mask_char
        self._preserve_length = preserve_length

    @property
    def strategy_id(self) -> str:
        return "masking_strategy"

    def can_reverse(self) -> bool:
        return False

    def anonymize(
        self,
        entity: DetectedEntity,
        context: AnonymizationRequest,
    ) -> AnonymizationResult:
        replacement = (
            self._mask_char * len(entity.raw_value)
            if self._preserve_length
            else f"[REDACTED_{entity.entity_type.value}]"
        )
        return AnonymizationResult(
            replacement_text=replacement,
            entity_type=entity.entity_type,
            is_reversible=False,
        )
