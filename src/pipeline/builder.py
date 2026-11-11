"""Fluent PipelineBuilder with strict build-time security and invariant validation."""

from __future__ import annotations

from typing import Any, Self

from detectors.base import PIIDetector
from domain.exceptions import PipelineConfigurationError
from domain.models import AuditLevel, DataClass, EntityType, PDFExtractionPolicy
from domain.protocols import AuditLogger, LocalOCREngine, ResidencyPolicy
from pipeline.filter import Filter, Pipeline
from pipeline.filters import (
    AnonymizationFilter,
    AuditContextFilter,
    DetectionFilter,
    DocumentExtractorFilter,
    LanguageDetectorFilter,
    ResidencyGate,
)
from strategies.base import (
    AnonymizationStrategy,
    PlaceholderTokenStrategy,
    StrategyRegistry,
)


class PipelineBuilder:
    """Fluent builder assembling and validating an immutable Inbound Pipeline."""

    def __init__(self) -> None:
        self._data_class: DataClass = DataClass.GENERAL
        self._audit_level: AuditLevel = AuditLevel.FULL
        self._detectors: list[PIIDetector] = []
        self._strategies: dict[EntityType, AnonymizationStrategy] = {}
        self._default_strategy: AnonymizationStrategy = PlaceholderTokenStrategy(
            reversible=False
        )
        self._residency_policy: ResidencyPolicy | None = None
        self._vault_proxy: Any | None = None
        self._memento_caretaker: Any | None = None
        self._k_anonymity_threshold: int | None = None
        self._pdf_policy: PDFExtractionPolicy = PDFExtractionPolicy.STRICT_NO_OCR
        self._ocr_engine: LocalOCREngine | None = None
        self._audit_logger: AuditLogger | None = None
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

    def with_strategy(
        self,
        entity_type: EntityType,
        strategy: AnonymizationStrategy,
    ) -> Self:
        """Bind an AnonymizationStrategy to a specific EntityType."""
        self._strategies[entity_type] = strategy
        return self

    def with_default_strategy(self, strategy: AnonymizationStrategy) -> Self:
        """Configure the fallback AnonymizationStrategy for unmapped entity types."""
        self._default_strategy = strategy
        return self

    def with_residency_policy(self, policy: ResidencyPolicy) -> Self:
        """Attach a ResidencyPolicy gate to enforce geographical compliance."""
        self._residency_policy = policy
        return self

    def with_vault_proxy(self, vault_proxy: Any) -> Self:
        """Bind a VaultProtectionProxy reference for reversible tokenization strategies."""
        self._vault_proxy = vault_proxy
        return self

    def with_memento_caretaker(self, caretaker: Any) -> Self:
        """Bind a Memento Caretaker for reversible session restoration."""
        self._memento_caretaker = caretaker
        return self

    def with_k_anonymity_threshold(self, k: int) -> Self:
        """Configure the target k-anonymity threshold (must be >= 2)."""
        if k < 2:
            raise PipelineConfigurationError(
                f"k-anonymity threshold must be >= 2, got {k}."
            )
        self._k_anonymity_threshold = k
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

    def with_audit_logger(self, audit_logger: AuditLogger) -> Self:
        """Attach an AuditLogger for security and compliance events."""
        self._audit_logger = audit_logger
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

        # Invariant 2: AuditLevel.NONE is forbidden for medical/PHI data class (GDPR violation)
        if self._data_class == DataClass.PHI and self._audit_level == AuditLevel.NONE:
            raise PipelineConfigurationError(
                "AuditLevel.NONE is forbidden when DataClass.PHI (MEDICAL) is configured."
            )

        # Invariant 3: Regulated PHI data class requires a ResidencyGate
        if self._data_class == DataClass.PHI and self._residency_policy is None:
            raise PipelineConfigurationError(
                "A ResidencyPolicy (ResidencyGate) is mandatory when handling DataClass.PHI."
            )

        registry = StrategyRegistry(
            strategies=self._strategies,
            default_strategy=self._default_strategy,
        )

        # Invariant 4: Reversible strategies require VaultProtectionProxy and Caretaker
        if registry.has_reversible_strategy() and (
            self._vault_proxy is None or self._memento_caretaker is None
        ):
            raise PipelineConfigurationError(
                "Reversible tokenization strategy requires `vault_proxy` and `memento_caretaker`."
            )

        # Assemble filters in canonical deterministic security order
        stages: list[Filter] = [
            DocumentExtractorFilter(
                policy=self._pdf_policy,
                ocr_engine=self._ocr_engine,
                audit_logger=self._audit_logger,
            ),
            LanguageDetectorFilter(),
            DetectionFilter(detectors=self._detectors),
            AnonymizationFilter(
                strategy_registry=registry,
                detectors=self._detectors,
            ),
        ]

        if self._residency_policy is not None:
            stages.append(
                ResidencyGate(
                    policy=self._residency_policy,
                    audit_logger=self._audit_logger,
                )
            )

        stages.extend(self._custom_filters)
        stages.append(AuditContextFilter(audit_logger=self._audit_logger))

        return Pipeline(filters=stages)
