"""PipelineProxy (Facade & Proxy entry point) normalizing text, PDF, and ToolCall payloads."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from domain.models import (
    AuditLevel,
    DataClass,
    DocumentAttachment,
    EndpointMetadata,
    SecurityPrincipal,
    ToolCallPayload,
)
from pipeline.context import PipelineContext
from pipeline.filter import Pipeline


class PipelineProxy:
    """Single entry point normalizing inputs (str, PDF, ToolCall) before pipeline execution."""

    def __init__(
        self,
        pipeline: Pipeline,
        default_data_class: DataClass = DataClass.GENERAL,
        default_audit_level: AuditLevel = AuditLevel.FULL,
    ) -> None:
        self._pipeline = pipeline
        self._default_data_class = default_data_class
        self._default_audit_level = default_audit_level

    def process_text(
        self,
        text: str,
        *,
        request_id: str | None = None,
        tenant_id: str = "default",
        principal: SecurityPrincipal | None = None,
        target_endpoint: EndpointMetadata | None = None,
        attachments: Sequence[DocumentAttachment] = (),
    ) -> PipelineContext:
        """Normalize a prompt and optional PDF attachments into PipelineContext and execute."""
        ctx = PipelineContext(
            request_id=request_id or f"req_{uuid.uuid4().hex[:12]}",
            tenant_id=tenant_id,
            raw_text=text,
            data_class=self._default_data_class,
            audit_level=self._default_audit_level,
            attachments=tuple(attachments),
            target_endpoint=target_endpoint,
            principal=principal,
        )
        return self._pipeline.execute(ctx)

    def process_tool_call(
        self,
        tool_call: ToolCallPayload,
        *,
        request_id: str | None = None,
        tenant_id: str = "default",
        principal: SecurityPrincipal | None = None,
        target_endpoint: EndpointMetadata | None = None,
    ) -> PipelineContext:
        """Sanitize a structured ToolCallPayload recursively while preserving JSON schema."""
        ctx = PipelineContext(
            request_id=request_id or f"req_{uuid.uuid4().hex[:12]}",
            session_id=tool_call.session_id,
            tenant_id=tenant_id,
            raw_text="",
            data_class=self._default_data_class,
            audit_level=self._default_audit_level,
            tool_call=tool_call,
            target_endpoint=target_endpoint,
            principal=principal,
        )
        return self._pipeline.execute(ctx)
