"""AnonymizationStrategy protocol, @register_strategy decorator, and StrategySelector."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any, Protocol, TypeVar, runtime_checkable

from domain.models import (
    AnonymizationRequest,
    AnonymizationResult,
    DetectedEntity,
    EntityType,
    SecurityContext,
)
from domain.protocols import TokenizationVault


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

    def __init__(
        self,
        reversible: bool = False,
        vault: TokenizationVault | None = None,
    ) -> None:
        self._vault = vault
        self._reversible = True if vault is not None else reversible

    @property
    def strategy_id(self) -> str:
        return "tokenization_strategy"

    def can_reverse(self) -> bool:
        return self._reversible

    def with_vault(self, vault: TokenizationVault) -> TokenizationStrategy:
        """Return a copy of this strategy bound to `vault`."""
        return TokenizationStrategy(reversible=self._reversible, vault=vault)

    def anonymize(
        self,
        entity: DetectedEntity,
        context: AnonymizationRequest,
    ) -> AnonymizationResult:
        placeholder = f"<{entity.entity_type.value}_{context.entity_index}>"
        if self._reversible and self._vault is not None:
            sec_ctx = context.context or SecurityContext(
                request_id=context.request_id,
                tenant_id=context.tenant_id,
                data_class=entity.data_class,
            )
            record = self._vault.tokenize(entity.raw_value, entity.entity_type, sec_ctx)
            return AnonymizationResult(
                replacement_text=placeholder,
                entity_type=entity.entity_type,
                is_reversible=True,
                token_id=record.token_id,
                key_id=record.key_id,
            )

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


_SYNTHETIC_CATALOG: dict[EntityType, tuple[str, ...]] = {
    EntityType.PERSON: (
        "Piotr Wiśniewski",
        "Anna Zielińska",
        "Marek Kamiński",
        "Katarzyna Dąbrowska",
        "Tomasz Lewandowski",
    ),
    EntityType.LOCATION: (
        "Poznań",
        "Gdańsk",
        "Wrocław",
        "Lublin",
        "Szczecin",
    ),
    EntityType.ORGANIZATION: (
        "Polskie Zakłady Przemysłowe S.A.",
        "NovaTech Sp. z o.o.",
        "Centrum Usług Wspólnych Sp.k.",
        "Grupa Logistyczna Bałtyk S.A.",
    ),
    EntityType.EMAIL: (
        "p.wisniewski@example.org",
        "a.zielinska@example.org",
        "m.kaminski@example.org",
        "k.dabrowska@example.org",
    ),
    EntityType.PHONE: (
        "+48 501 234 567",
        "+48 602 345 678",
        "+48 703 456 789",
        "+48 804 567 890",
    ),
    EntityType.PESEL: (
        "85021012355",
        "92071314764",
        "78112409879",
        "90010112349",
    ),
    EntityType.NIP: (
        "123-456-32-18",
        "774-000-14-54",
    ),
    EntityType.REGON: (
        "123456785",
        "142187236",
    ),
    EntityType.IBAN: (
        "PL61 1090 1014 0000 0712 1981 2874",
        "PL27 1140 2004 0000 3002 0135 5387",
    ),
    EntityType.ID_CARD: (
        "ABA 300000",
    ),
    EntityType.DATE: (
        "1985-06-15",
        "1992-11-20",
        "2001-03-10",
        "1978-09-04",
    ),
    EntityType.SSN: (
        "234-56-7890",
        "345-67-8901",
    ),
    EntityType.AGE: (
        "42",
        "35",
        "58",
    ),
    EntityType.PROFESSION: (
        "inżynier systemowy",
        "analityk finansowy",
        "konsultant prawny",
    ),
}


@register_strategy("synthesis")
class SynthesisStrategy(AnonymizationStrategy):
    """Reversible synthetic data replacement strategy (ARCHITECTURE.md §3.2).

    Replaces real PII with realistic synthetic values for LLMs that reject raw `<ENTITY_N>`
    placeholders, while keeping the original plaintext encrypted exclusively inside
    `TokenizationVault` and mapped via `PipelineMemento`.
    """

    def __init__(
        self,
        vault: TokenizationVault | None = None,
        reversible: bool = True,
        custom_catalog: Mapping[EntityType, Sequence[str]] | None = None,
    ) -> None:
        self._vault = vault
        self._reversible = reversible
        self._catalog: dict[EntityType, tuple[str, ...]] = dict(_SYNTHETIC_CATALOG)
        if custom_catalog is not None:
            for entity_type, values in custom_catalog.items():
                if values:
                    self._catalog[entity_type] = tuple(values)

    @property
    def strategy_id(self) -> str:
        return "synthesis_strategy"

    def can_reverse(self) -> bool:
        return self._reversible

    def with_vault(self, vault: TokenizationVault) -> SynthesisStrategy:
        """Return a copy of this strategy bound to `vault`."""
        return SynthesisStrategy(
            vault=vault,
            reversible=self._reversible,
            custom_catalog=self._catalog,
        )

    def _select_synthetic_value(self, entity: DetectedEntity, entity_index: int) -> str:
        candidates = self._catalog.get(entity.entity_type)
        if not candidates:
            return f"SYNTH_{entity.entity_type.value}_{entity_index}"
        offset = max(entity_index - 1, 0) % len(candidates)
        candidate = candidates[offset]
        if candidate.casefold() == entity.raw_value.strip().casefold() and len(candidates) > 1:
            candidate = candidates[(offset + 1) % len(candidates)]
        return candidate

    def anonymize(
        self,
        entity: DetectedEntity,
        context: AnonymizationRequest,
    ) -> AnonymizationResult:
        synthetic_value = self._select_synthetic_value(entity, context.entity_index)
        if self._reversible and self._vault is not None:
            sec_ctx = context.context or SecurityContext(
                request_id=context.request_id,
                tenant_id=context.tenant_id,
                data_class=entity.data_class,
            )
            record = self._vault.tokenize(entity.raw_value, entity.entity_type, sec_ctx)
            return AnonymizationResult(
                replacement_text=synthetic_value,
                entity_type=entity.entity_type,
                is_reversible=True,
                token_id=record.token_id,
                key_id=record.key_id,
            )

        token_id = (
            f"tok_{context.request_id}_{entity.entity_type.value.lower()}_{context.entity_index}"
        )
        return AnonymizationResult(
            replacement_text=synthetic_value,
            entity_type=entity.entity_type,
            is_reversible=self._reversible,
            token_id=token_id if self._reversible else None,
        )
