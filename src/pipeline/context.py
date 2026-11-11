"""Immutable PipelineContext and filter execution metadata."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import override

from pydantic import BaseModel, ConfigDict, Field

from domain.models import (
    AnonymizationResult,
    AuditLevel,
    DataClass,
    DetectedEntity,
    DocumentAttachment,
    EndpointMetadata,
    SecurityPrincipal,
    ToolCallPayload,
)


class FilterRecord(BaseModel):
    """Immutable audit record of a single filter stage execution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    filter_name: str
    executed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class PipelineContext(BaseModel):
    """Immutable request context passed through the Pipes & Filters chain.

    Redacts `raw_text` in `__repr__` and `__str__` to prevent raw PII leakage in logs.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: str
    session_id: str | None = None
    tenant_id: str = "default"
    raw_text: str = Field(default="", repr=False)
    sanitized_text: str = ""
    language: str = "en"
    data_class: DataClass = DataClass.GENERAL
    audit_level: AuditLevel = AuditLevel.FULL
    k_anonymity_threshold: int | None = None
    re_id_risk_threshold: float | None = None
    detected_entities: tuple[DetectedEntity, ...] = ()
    anonymization_results: tuple[AnonymizationResult, ...] = ()
    placeholder_map: dict[str, str] = Field(default_factory=dict)
    tool_call: ToolCallPayload | None = None
    attachments: tuple[DocumentAttachment, ...] = ()
    target_endpoint: EndpointMetadata | None = None
    principal: SecurityPrincipal | None = None
    applied_filters: tuple[FilterRecord, ...] = ()

    @property
    def current_text(self) -> str:
        """Return `sanitized_text` if populated, otherwise `raw_text`."""
        return self.sanitized_text if self.sanitized_text != "" else self.raw_text

    def with_filter_record(self, filter_name: str) -> PipelineContext:
        """Return a new PipelineContext with `filter_name` appended to `applied_filters`."""
        record = FilterRecord(filter_name=filter_name)
        return self.model_copy(
            update={"applied_filters": (*self.applied_filters, record)}
        )

    @override
    def __repr__(self) -> str:
        return (
            f"PipelineContext(request_id={self.request_id!r}, tenant_id={self.tenant_id!r}, "
            f"language={self.language!r}, data_class={self.data_class!r}, "
            f"detected_entities={len(self.detected_entities)}, "
            f"applied_filters={[f.filter_name for f in self.applied_filters]!r})"
        )

    @override
    def __str__(self) -> str:
        return self.__repr__()
