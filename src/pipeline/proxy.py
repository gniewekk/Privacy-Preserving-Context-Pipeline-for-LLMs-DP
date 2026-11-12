"""PipelineProxy (Facade & Proxy entry point) normalizing text, PDF, and ToolCall payloads."""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Iterator, Sequence
from typing import TYPE_CHECKING

from domain.models import (
    AuditLevel,
    DataClass,
    DocumentAttachment,
    EndpointMetadata,
    SecurityContext,
    SecurityPrincipal,
    ToolCall,
)
from pipeline.context import PipelineContext
from pipeline.filter import Pipeline
from pipeline.filters import OutputPIIDetector, StreamingResponseRestorer

if TYPE_CHECKING:
    from state.memento import PipelineMemento, ResponseRestorer


class PipelineProxy:
    """Single entry point normalizing inputs (str, PDF, ToolCall) and restoring outputs."""

    def __init__(
        self,
        pipeline: Pipeline,
        default_data_class: DataClass = DataClass.GENERAL,
        default_audit_level: AuditLevel = AuditLevel.FULL,
        *,
        response_restorer: ResponseRestorer | None = None,
        output_pii_detector: OutputPIIDetector | None = None,
    ) -> None:
        self._pipeline = pipeline
        self._default_data_class = default_data_class
        self._default_audit_level = default_audit_level
        self._response_restorer = response_restorer
        self._output_pii_detector = output_pii_detector

    def process_text(
        self,
        text: str,
        *,
        request_id: str | None = None,
        session_id: str | None = None,
        tenant_id: str = "default",
        principal: SecurityPrincipal | None = None,
        target_endpoint: EndpointMetadata | None = None,
        attachments: Sequence[DocumentAttachment] = (),
    ) -> PipelineContext:
        """Normalize a prompt and optional PDF attachments into PipelineContext and execute."""
        ctx = PipelineContext(
            request_id=request_id or f"req_{uuid.uuid4().hex[:12]}",
            session_id=session_id,
            tenant_id=tenant_id,
            raw_text=text,
            data_class=self._default_data_class,
            audit_level=self._default_audit_level,
            attachments=tuple(attachments),
            target_endpoint=target_endpoint,
            principal=principal,
        )
        result = self._pipeline.execute(ctx)
        if self._response_restorer is not None:
            self._response_restorer.store(result.create_memento())
        return result

    def process_tool_call(
        self,
        tool_call: ToolCall,
        *,
        request_id: str | None = None,
        tenant_id: str = "default",
        principal: SecurityPrincipal | None = None,
        target_endpoint: EndpointMetadata | None = None,
    ) -> PipelineContext:
        """Sanitize a structured ToolCall recursively while preserving JSON schema."""
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
        result = self._pipeline.execute(ctx)
        if self._response_restorer is not None:
            self._response_restorer.store(result.create_memento())
        return result

    def restore_response(
        self,
        response_text: str,
        memento: PipelineMemento | str,
        *,
        principal: SecurityPrincipal | None = None,
        context: SecurityContext | None = None,
        language: str = "en",
    ) -> str:
        """Run Outbound Pipeline (`OutputPIIDetector` -> `ResponseRestorer`) on `response_text`."""
        if self._response_restorer is None:
            raise RuntimeError("PipelineProxy requires `response_restorer` for outbound flow.")

        resolved_memento = (
            self._response_restorer.get(memento)
            if isinstance(memento, str)
            else memento
        )
        scanned = response_text
        if self._output_pii_detector is not None:
            allowed = (
                frozenset(resolved_memento.token_map.keys())
                if resolved_memento is not None
                else frozenset()
            )
            scanned = self._output_pii_detector.scan(
                response_text,
                language=language,
                allowed_replacements=allowed,
            )
        return self._response_restorer.restore_response(
            scanned,
            resolved_memento if resolved_memento is not None else memento,
            principal=principal,
            context=context,
        )

    def restore_stream(
        self,
        chunks: Iterable[str],
        memento: PipelineMemento | str,
        *,
        principal: SecurityPrincipal | None = None,
        context: SecurityContext | None = None,
        language: str = "en",
    ) -> Iterator[str]:
        """Run streaming Outbound Pipeline (`StreamingResponseRestorer`) over SSE `chunks`."""
        if self._response_restorer is None:
            raise RuntimeError("PipelineProxy requires `response_restorer` for streaming flow.")

        stream_restorer = StreamingResponseRestorer(
            self._response_restorer,
            output_pii_detector=self._output_pii_detector,
        )
        return stream_restorer.restore_stream(
            chunks,
            memento,
            principal=principal,
            context=context,
            language=language,
        )
