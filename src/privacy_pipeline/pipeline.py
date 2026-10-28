from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import uuid4

from .detectors import HeuristicPolishNERDetector, NERDetector, PIIRegistry, TransformerNERDetector
from .models import (
    DetectedEntity,
    EntityMetadata,
    PipelineContext,
    PipelineMemento,
)
from .vault import InMemoryTokenVault


class Filter(Protocol):
    name: str

    def process(self, context: PipelineContext) -> PipelineContext: ...


class AnonymizationStrategy(Protocol):
    name: str

    def anonymize(
        self,
        *,
        vault: InMemoryTokenVault,
        session_id: str,
        value: str,
        entity_type: str,
    ) -> str: ...


class TokenizationStrategy:
    name = "tokenization"

    def anonymize(
        self,
        *,
        vault: InMemoryTokenVault,
        session_id: str,
        value: str,
        entity_type: str,
    ) -> str:
        return vault.tokenize(session_id, value, entity_type)


class StrategyRegistry:
    """Register custom anonymization strategies by entity type."""

    _registry: dict[str, tuple[int, type[AnonymizationStrategy]]] = {}

    @classmethod
    def register(cls, entity_type: str, *, priority: int = 100):
        def decorator(strategy_cls: type[AnonymizationStrategy]):
            cls._registry[entity_type] = (priority, strategy_cls)
            return strategy_cls

        return decorator

    @classmethod
    def resolve(
        cls,
        entity_type: str,
        *,
        overrides: dict[str, type[AnonymizationStrategy]] | None = None,
    ) -> type[AnonymizationStrategy]:
        if overrides is not None and entity_type in overrides:
            return overrides[entity_type]
        registered = cls._registry.get(entity_type)
        if registered is not None:
            return registered[1]
        return TokenizationStrategy


class LanguageDetector:
    name = "LanguageDetector"

    def process(self, context: PipelineContext) -> PipelineContext:
        return context.with_changes(metadata={**context.metadata, "language": "pl"})


class PIIDetectorFilter:
    name = "PIIDetector"

    def __init__(self, ner_detector: NERDetector | None = None) -> None:
        self.ner_detector = ner_detector or HeuristicPolishNERDetector()

    def process(self, context: PipelineContext) -> PipelineContext:
        return context.with_changes(
            detected_entities=PIIRegistry.detect(context.text, self.ner_detector)
        )


class ReIdRiskFilter:
    name = "ReIdRiskFilter"

    def __init__(self, *, threshold: float = 0.0) -> None:
        self.threshold = threshold

    def process(self, context: PipelineContext) -> PipelineContext:
        unique_entities = len({entity.entity_type for entity in context.detected_entities})
        risk_score = min(1.0, unique_entities / 10.0)
        metadata = dict(context.metadata)
        metadata["re_id_risk"] = risk_score
        metadata["re_id_threshold"] = self.threshold
        context = context.with_changes(metadata=metadata)
        if risk_score >= self.threshold and self.threshold > 0:
            return context.with_changes(halted=True, errors=context.errors + ("Re-identification risk threshold exceeded",))
        return context


class ResidencyPolicyFilter:
    name = "ResidencyPolicy"

    def __init__(self, *, allowed_regions: tuple[str, ...] | set[str] = ("EU", "EEA"), region: str | None = None) -> None:
        self.allowed_regions = {region.upper() for region in allowed_regions}
        self.region = region.upper() if region is not None else None

    def process(self, context: PipelineContext) -> PipelineContext:
        region = self.region or str(context.metadata.get("region", "EU")).upper()
        metadata = dict(context.metadata)
        metadata["region"] = region
        context = context.with_changes(metadata=metadata)
        if region not in self.allowed_regions:
            return context.with_changes(
                halted=True,
                errors=context.errors + (f"Data residency violation for region: {region}",),
            )
        return context


class OutputPIIDetector:
    name = "OutputPIIDetector"

    def __init__(self, ner_detector: NERDetector | None = None) -> None:
        self.ner_detector = ner_detector or HeuristicPolishNERDetector()

    def process(self, context: PipelineContext) -> PipelineContext:
        findings = PIIRegistry.detect(context.text, self.ner_detector)
        if findings:
            return context.with_changes(
                halted=True,
                errors=context.errors + ("Unexpected PII detected in outbound response",),
            )
        return context


class AnonymizationFilter:
    name = "AnonymizationFilter"

    def __init__(
        self,
        vault: InMemoryTokenVault,
        *,
        strategy_overrides: dict[str, type[AnonymizationStrategy]] | None = None,
    ) -> None:
        self.vault = vault
        self.strategy_overrides = strategy_overrides or {}

    def process(self, context: PipelineContext) -> PipelineContext:
        replacements: list[tuple[int, int, str]] = []
        token_map: dict[str, EntityMetadata] = {}
        for entity in context.detected_entities:
            strategy_cls = StrategyRegistry.resolve(
                entity.entity_type, overrides=self.strategy_overrides
            )
            strategy = strategy_cls()
            token = strategy.anonymize(
                vault=self.vault,
                session_id=context.session_id,
                value=entity.value,
                entity_type=entity.entity_type,
            )
            if token == entity.value:
                token = self.vault.tokenize(
                    context.session_id,
                    entity.value,
                    entity.entity_type,
                )
            elif not token.startswith("<") and token != "[MASKED]":
                token = self.vault.tokenize(
                    context.session_id,
                    token,
                    entity.entity_type,
                )
            else:
                self.vault.store(context.session_id, token, entity.value, entity.entity_type)
            replacements.append((entity.start, entity.end, token))
            token_map[token] = EntityMetadata(
                entity_type=entity.entity_type,
                start=entity.start,
                end=entity.end,
            )
        anonymized = context.text
        for start, end, token in reversed(replacements):
            anonymized = anonymized[:start] + token + anonymized[end:]
        memento = PipelineMemento(
            session_id=context.session_id,
            token_map=token_map,
            applied_filters=("LanguageDetector", "PIIDetector", self.name),
        )
        return context.with_changes(text=anonymized, memento=memento)


class ResponseRestorer:
    name = "ResponseRestorer"

    def __init__(self, vault: InMemoryTokenVault) -> None:
        self.vault = vault

    def restore(self, response: str, memento: PipelineMemento) -> str:
        if memento is None:
            raise ValueError("A memento is required to restore a response")
        restored = response
        for token in sorted(memento.token_map, key=len, reverse=True):
            value = self.vault.detokenize(memento.session_id, token)
            restored = restored.replace(token, value)
        return restored


class InboundPipeline:
    def __init__(self, filters: tuple[Filter, ...]) -> None:
        self.filters = filters

    def execute(self, context: PipelineContext) -> PipelineContext:
        current = context
        for current_filter in self.filters:
            if current.halted:
                break
            current = current_filter.process(current)
        return current


class OutboundPipeline:
    def __init__(self, restorer: ResponseRestorer) -> None:
        self.restorer = restorer

    def execute(self, response: str, memento: PipelineMemento) -> str:
        return self.restorer.restore(response, memento)


@dataclass
class Pipeline:
    inbound: InboundPipeline
    outbound: OutboundPipeline


class PipelineBuilder:
    def __init__(self, vault: InMemoryTokenVault | None = None) -> None:
        self.vault = vault or InMemoryTokenVault()
        self._filters: list[Filter] = [LanguageDetector(), PIIDetectorFilter()]
        self._strategy_overrides: dict[str, type[AnonymizationStrategy]] = {}
        self._data_class: str | None = None
        self._residency_policy: str | None = None
        self._audit_level: str | None = None
        self._risk_threshold: float = 0.0

    def forDataClass(self, data_class: str) -> "PipelineBuilder":
        self._data_class = str(data_class)
        return self

    def withResidencyPolicy(self, policy: str) -> "PipelineBuilder":
        self._residency_policy = str(policy)
        if policy not in {"EU_ONLY", "EU", "EEA", "NONE"}:
            raise ValueError(f"Unsupported residency policy: {policy}")
        return self

    def withReIdRiskThreshold(self, threshold: float) -> "PipelineBuilder":
        self._risk_threshold = float(threshold)
        return self

    def withAuditLevel(self, level: str) -> "PipelineBuilder":
        self._audit_level = str(level)
        return self

    def with_transformer_ner(
        self,
        model_name: str,
        *,
        min_score: float = 0.70,
    ) -> "PipelineBuilder":
        self._filters[1] = PIIDetectorFilter(
            TransformerNERDetector(model_name, min_score=min_score)
        )
        return self

    def with_anonymization(self) -> "PipelineBuilder":
        self._filters.append(
            AnonymizationFilter(self.vault, strategy_overrides=self._strategy_overrides)
        )
        return self

    def with_anonymization_strategy(
        self,
        entity_type: str,
        strategy_cls: type[AnonymizationStrategy],
    ) -> "PipelineBuilder":
        self._strategy_overrides[entity_type] = strategy_cls
        return self

    def build(self) -> Pipeline:
        names = [current_filter.name for current_filter in self._filters]
        if "PIIDetector" not in names or "AnonymizationFilter" not in names:
            raise ValueError("Pipeline requires PIIDetector before AnonymizationFilter")
        if names.index("PIIDetector") > names.index("AnonymizationFilter"):
            raise ValueError("PIIDetector must run before AnonymizationFilter")
        if self._residency_policy is not None:
            region = self._residency_policy
            if region == "EU_ONLY":
                region = "EU"
            self._filters.append(ResidencyPolicyFilter(allowed_regions=("EU", "EEA") if region in {"EU", "EEA", "EU_ONLY"} else ("EU", "EEA", "US")))
        if self._risk_threshold > 0:
            self._filters.append(ReIdRiskFilter(threshold=self._risk_threshold))
        if self._audit_level is not None:
            self._filters.append(ResidencyPolicyFilter(allowed_regions=("EU", "EEA")))
        return Pipeline(
            inbound=InboundPipeline(tuple(self._filters)),
            outbound=OutboundPipeline(ResponseRestorer(self.vault)),
        )


class PipelineProxy:
    """Facade/Proxy entry point managing a session context."""

    def __init__(self, pipeline: Pipeline) -> None:
        self.pipeline = pipeline

    def anonymize(self, text: str, session_id: str | None = None) -> PipelineContext:
        context = PipelineContext(session_id=session_id or str(uuid4()), text=text)
        return self.pipeline.inbound.execute(context)

    def restore(self, response: str, context: PipelineContext) -> str:
        if context.memento is None:
            raise ValueError("Cannot restore without a memento")
        return self.pipeline.outbound.execute(response, context.memento)
