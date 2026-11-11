"""Niezmienne modele kontekstu potoku (PipelineContext)."""

from __future__ import annotations

from domain.models import DataClass, DetectedEntity, Language, RiskAssessmentResult

try:
    from pydantic import BaseModel as _PydanticBaseModel, ConfigDict, Field
    _USE_PYDANTIC = True
except ImportError:
    _USE_PYDANTIC = False

if _USE_PYDANTIC:
    class PipelineContext(_PydanticBaseModel):
        model_config = ConfigDict(frozen=True, extra="forbid")

        request_id: str = Field(min_length=1)
        tenant_id: str = Field(min_length=1)
        text: str = Field(repr=False)
        language: Language
        data_class: DataClass = DataClass.GENERAL
        entities: tuple[DetectedEntity, ...] = ()
        risk_assessment: RiskAssessmentResult | None = None
        sensitive_cohort: tuple[str, ...] = ()

        def evolve(self, **changes: object) -> PipelineContext:
            return self.model_copy(update=changes)

else:
    from dataclasses import dataclass, field, replace

    @dataclass(frozen=True)
    class PipelineContext:
        request_id: str
        tenant_id: str
        text: str = field(repr=False)
        language: Language
        data_class: DataClass = DataClass.GENERAL
        entities: tuple[DetectedEntity, ...] = ()
        risk_assessment: RiskAssessmentResult | None = None
        sensitive_cohort: tuple[str, ...] = ()

        def evolve(self, **changes: object) -> PipelineContext:
            return replace(self, **changes)
