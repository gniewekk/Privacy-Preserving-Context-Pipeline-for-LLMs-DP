"""Niezmienne modele domenowe i wyjątki."""

from domain.exceptions import (
    PipelineConfigurationError,
    PrivacyPipelineError,
    ReIdentificationRiskError,
    UnsupportedEntityError,
)
from domain.models import (
    AnonymizationRequest,
    AnonymizationResult,
    DATA_CLASS_SEVERITY,
    DataClass,
    DetectedEntity,
    EntityCategory,
    EntityType,
    Language,
    QIDGeneralizationStep,
    QuasiIdentifier,
    RiskAssessmentResult,
    RiskDecision,
    SensitiveAttributeAssessment,
)

__all__ = [
    "AnonymizationRequest",
    "AnonymizationResult",
    "DATA_CLASS_SEVERITY",
    "DataClass",
    "DetectedEntity",
    "EntityCategory",
    "EntityType",
    "Language",
    "PipelineConfigurationError",
    "PrivacyPipelineError",
    "QIDGeneralizationStep",
    "QuasiIdentifier",
    "ReIdentificationRiskError",
    "RiskAssessmentResult",
    "RiskDecision",
    "SensitiveAttributeAssessment",
    "UnsupportedEntityError",
]
