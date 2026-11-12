"""Immutable PipelineContext and filter execution metadata."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, override

from pydantic import BaseModel, ConfigDict, Field

from domain.models import (
    AnonymizationResult,
    AuditLevel,
    DataClass,
    DetectedEntity,
    DocumentAttachment,
    EndpointMetadata,
    EntityType,
    SecurityPrincipal,
    ToolCall,
)

if TYPE_CHECKING:
    from state.memento import PipelineMemento


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
    tool_call: ToolCall | None = None
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

    def create_memento(
        self,
        *,
        expires_at: datetime | None = None,
        key_id: str | None = None,
        residency_jurisdiction: str = "EU",
    ) -> PipelineMemento:
        """Create an encapsulated, tamper-evident PipelineMemento snapshot (ADR-005)."""
        from state.memento import EntityMetadata, PipelineMemento

        token_map: dict[str, EntityMetadata] = {}
        inferred_key_id = key_id

        for res in self.anonymization_results:
            if res.is_reversible and res.token_id is not None:
                if inferred_key_id is None and res.key_id is not None:
                    inferred_key_id = res.key_id
                is_synthetic = not (
                    res.replacement_text.startswith("<")
                    and res.replacement_text.endswith(">")
                )
                token_map[res.replacement_text] = EntityMetadata(
                    token_id=res.token_id,
                    entity_type=res.entity_type,
                    key_id=res.key_id or inferred_key_id,
                    is_synthetic=is_synthetic,
                )

        for placeholder, tok_id in self.placeholder_map.items():
            if placeholder not in token_map:
                ent_type = EntityType.CUSTOM
                if placeholder.startswith("<") and "_" in placeholder:
                    raw_prefix = placeholder[1 : placeholder.rfind("_")]
                    if raw_prefix in EntityType.__members__:
                        ent_type = EntityType[raw_prefix]
                token_map[placeholder] = EntityMetadata(
                    token_id=tok_id,
                    entity_type=ent_type,
                    key_id=inferred_key_id,
                    is_synthetic=not (
                        placeholder.startswith("<") and placeholder.endswith(">")
                    ),
                )

        return PipelineMemento.create(
            request_id=self.request_id,
            session_id=self.session_id,
            tenant_id=self.tenant_id,
            data_class=self.data_class,
            residency_jurisdiction=residency_jurisdiction,
            version=1,
            applied_filters=self.applied_filters,
            expires_at=expires_at,
            key_id=inferred_key_id,
            sanitized_text=self.sanitized_text,
            token_map=token_map,
        )

    @classmethod
    def restore_from_memento(
        cls,
        memento: PipelineMemento,
        *,
        principal: SecurityPrincipal | None = None,
        target_endpoint: EndpointMetadata | None = None,
    ) -> PipelineContext:
        """Reconstruct a sanitized PipelineContext from a Memento after an LLM timeout (§3.5.B)."""
        memento.verify_integrity()
        placeholder_map = {k: v.token_id for k, v in memento.token_map.items()}
        results = tuple(
            AnonymizationResult(
                replacement_text=placeholder,
                entity_type=meta.entity_type,
                is_reversible=True,
                token_id=meta.token_id,
                key_id=meta.key_id,
            )
            for placeholder, meta in memento.token_map.items()
        )
        return cls(
            request_id=memento.request_id,
            session_id=memento.session_id,
            tenant_id=memento.tenant_id,
            raw_text="",
            sanitized_text=memento.sanitized_text,
            data_class=memento.data_class,
            anonymization_results=results,
            placeholder_map=placeholder_map,
            applied_filters=memento.applied_filters,
            principal=principal,
            target_endpoint=target_endpoint,
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
