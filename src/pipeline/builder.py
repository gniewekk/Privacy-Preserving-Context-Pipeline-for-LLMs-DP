"""Fluent PipelineBuilder with strict build-time security and invariant validation."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Self

from detectors.base import PIIDetector
from detectors.heuristic import ContextRuleEnhancer
from domain.exceptions import PipelineConfigurationError
from domain.models import AuditLevel, DataClass, EntityType, PDFExtractionPolicy
from domain.protocols import (
    AuditWriter,
    LanguageDetector,
    LocalOCREngine,
    ResidencyPolicyEngine,
    TokenizationVault,
)
from pipeline.filter import Filter, Pipeline
from pipeline.filters import (
    AnonymizationFilter,
    AuditContextFilter,
    DocumentExtractorFilter,
    LanguageDetectorFilter,
    PIIDetectorFilter,
    ResidencyPolicyFilter,
)
from pipeline.language import default_language_detector
from strategies.base import (
    AnonymizationStrategy,
    StrategySelector,
    TokenizationStrategy,
)


class PipelineBuilder:
    """Fluent builder assembling and validating an immutable Inbound Pipeline."""

    def __init__(self) -> None:
        self._data_class: DataClass = DataClass.GENERAL
        self._audit_level: AuditLevel = AuditLevel.FULL
        self._detectors: list[PIIDetector] = []
        self._enhancer: ContextRuleEnhancer | None = None
        self._strategies: dict[EntityType, AnonymizationStrategy] = {}
        self._default_strategy: AnonymizationStrategy = TokenizationStrategy(
            reversible=False
        )
        self._residency_policy: ResidencyPolicyEngine | None = None
        self._vault_proxy: TokenizationVault | None = None
        self._response_restorer: Any | None = None
        self._k_anonymity_threshold: int | None = None
        self._re_id_risk_threshold: float | None = None
        self._pdf_policy: PDFExtractionPolicy = PDFExtractionPolicy.STRICT_NO_OCR
        self._ocr_engine: LocalOCREngine | None = None
        self._language_detector: LanguageDetector = default_language_detector()
        self._audit_writer: AuditWriter | None = None
        self._risk_assessment_filters: list[Filter] = []
        self._custom_filters: list[Filter] = []

    def for_data_class(self, data_class: DataClass) -> Self:
        """Configure the pipeline's regulatory data classification."""
        self._data_class = data_class
        return self

    def with_audit_level(self, audit_level: AuditLevel) -> Self:
        """Configure the pipeline's audit verbosity level."""
        self._audit_level = audit_level
        return self

    def with_detector(self, detector: PIIDetector) -> Self:
        """Register a PIIDetector strategy in the detection stage."""
        self._detectors.append(detector)
        return self

    def with_language_detector(self, detector: LanguageDetector) -> Self:
        """Configure the language detector used before PII detection."""
        self._language_detector = detector
        return self

    def with_detectors(self, detectors: Sequence[PIIDetector]) -> Self:
        """Register multiple PIIDetector strategies in the detection stage."""
        self._detectors.extend(detectors)
        return self

    def with_context_enhancer(self, enhancer: ContextRuleEnhancer) -> Self:
        """Configure the ContextRuleEnhancer used by PIIDetectorFilter."""
        self._enhancer = enhancer
        return self

    def with_anonymization_strategy(
        self,
        entity_or_strategy: EntityType | AnonymizationStrategy,
        strategy: AnonymizationStrategy | None = None,
    ) -> Self:
        """Configure a default or entity-specific AnonymizationStrategy (ARCHITECTURE.md §3.3)."""
        if isinstance(entity_or_strategy, EntityType):
            if strategy is None:
                raise PipelineConfigurationError(
                    "Strategy instance is required when binding to an EntityType."
                )
            self._strategies[entity_or_strategy] = strategy
        else:
            self._default_strategy = entity_or_strategy
        return self

    def with_residency_policy(self, policy: ResidencyPolicyEngine) -> Self:
        """Attach a ResidencyPolicyEngine evaluated by ResidencyPolicyFilter."""
        self._residency_policy = policy
        return self

    def with_vault_proxy(self, vault_proxy: TokenizationVault) -> Self:
        """Bind a VaultProxy reference for reversible tokenization strategies."""
        self._vault_proxy = vault_proxy
        return self

    def with_response_restorer(self, response_restorer: Any) -> Self:
        """Bind the ResponseRestorer for reversible session restoration."""
        self._response_restorer = response_restorer
        return self

    def with_k_anonymity_threshold(self, k: int) -> Self:
        """Configure the target k-anonymity threshold (must be >= 2)."""
        if k < 2:
            raise PipelineConfigurationError(
                f"k-anonymity threshold must be >= 2, got {k}."
            )
        self._k_anonymity_threshold = k
        return self

    def with_re_id_risk_threshold(self, threshold: float) -> Self:
        """Configure maximum acceptable re-identification risk threshold (ARCHITECTURE.md §3.3)."""
        if not (0.0 < threshold <= 1.0):
            raise PipelineConfigurationError(
                f"Re-identification risk threshold must be in (0.0, 1.0], got {threshold}."
            )
        self._re_id_risk_threshold = threshold
        return self

    def with_pdf_extraction_policy(
        self,
        policy: PDFExtractionPolicy,
        ocr_engine: LocalOCREngine | None = None,
    ) -> Self:
        """Configure PDF extraction and local OCR policy for DocumentExtractorFilter."""
        if policy == PDFExtractionPolicy.LOCAL_OCR_ENABLED and ocr_engine is None:
            raise PipelineConfigurationError(
                "LOCAL_OCR_ENABLED requires a valid LocalOCREngine instance."
            )
        self._pdf_policy = policy
        self._ocr_engine = ocr_engine
        return self

    def with_audit_writer(self, audit_writer: AuditWriter) -> Self:
        """Attach an AuditWriter for security and compliance events."""
        self._audit_writer = audit_writer
        return self

    def with_risk_assessment_filter(self, risk_assessment_filter: Filter) -> Self:
        """Register a RiskAssessmentFilter between PIIDetectorFilter and AnonymizationFilter."""
        self._risk_assessment_filters.append(risk_assessment_filter)
        return self

    def with_custom_filter(self, custom_filter: Filter) -> Self:
        """Append an additional stateless Filter stage."""
        self._custom_filters.append(custom_filter)
        return self

    def build(self) -> Pipeline:
        """Validate build-time security invariants and return an immutable Pipeline."""
        # Invariant 1: At least one PIIDetector is mandatory before AnonymizationFilter
        if not self._detectors:
            raise PipelineConfigurationError(
                "Cannot build Pipeline without at least one registered PIIDetector."
            )

        # Invariant 2: AuditLevel.NONE is forbidden for MEDICAL (PHI) data class (GDPR violation)
        if self._data_class == DataClass.MEDICAL and self._audit_level == AuditLevel.NONE:
            raise PipelineConfigurationError(
                "AuditLevel.NONE is forbidden when DataClass.MEDICAL is configured."
            )

        # Invariant 3: Regulated MEDICAL data class requires a ResidencyPolicyFilter
        if self._data_class == DataClass.MEDICAL and self._residency_policy is None:
            raise PipelineConfigurationError(
                "A ResidencyPolicyEngine (ResidencyPolicyFilter) is mandatory when handling "
                "DataClass.MEDICAL."
            )

        # Invariant 4: Reversible strategies require VaultProxy and ResponseRestorer
        temp_selector = StrategySelector(
            strategies=self._strategies,
            default_strategy=self._default_strategy,
        )
        if temp_selector.has_reversible_strategy() and (
            self._vault_proxy is None or self._response_restorer is None
        ):
            raise PipelineConfigurationError(
                "Reversible tokenization strategy requires `vault_proxy` and `response_restorer`."
            )

        bound_default = self._default_strategy
        bound_strategies = dict(self._strategies)
        if self._vault_proxy is not None:
            if hasattr(bound_default, "with_vault") and bound_default.can_reverse():
                bound_default = bound_default.with_vault(self._vault_proxy)
            for ent_type, strat in list(bound_strategies.items()):
                if hasattr(strat, "with_vault") and strat.can_reverse():
                    bound_strategies[ent_type] = strat.with_vault(self._vault_proxy)
            if self._response_restorer is not None and hasattr(
                self._response_restorer, "bind_vault"
            ):
                self._response_restorer.bind_vault(self._vault_proxy)

        strategy_selector = StrategySelector(
            strategies=bound_strategies,
            default_strategy=bound_default,
        )

        # Assemble filters in canonical deterministic security order (ARCHITECTURE.md §3.1):
        # DocumentExtractorFilter -> LanguageDetectorFilter -> PIIDetectorFilter ->
        # [RiskAssessmentFilter(s)] -> AnonymizationFilter -> ResidencyPolicyFilter ->
        # [CustomFilter(s)] -> AuditContextFilter
        stages: list[Filter] = [
            DocumentExtractorFilter(
                policy=self._pdf_policy,
                ocr_engine=self._ocr_engine,
                audit_writer=self._audit_writer,
            ),
            LanguageDetectorFilter(self._language_detector),
            PIIDetectorFilter(
                detectors=self._detectors,
                k_anonymity_threshold=self._k_anonymity_threshold,
                re_id_risk_threshold=self._re_id_risk_threshold,
                enhancer=self._enhancer,
            ),
            *self._risk_assessment_filters,
            AnonymizationFilter(
                strategy_selector=strategy_selector,
                detectors=self._detectors,
                enhancer=self._enhancer,
            ),
        ]

        if self._residency_policy is not None:
            stages.append(
                ResidencyPolicyFilter(
                    policy=self._residency_policy,
                    audit_writer=self._audit_writer,
                )
            )

        stages.extend(self._custom_filters)
        stages.append(
            AuditContextFilter(
                audit_writer=self._audit_writer,
                response_restorer=self._response_restorer,
            )
        )

        return Pipeline(filters=stages)
