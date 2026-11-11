"""Core domain protocols for audit logging, residency policies, and local OCR."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from domain.models import AuditEvent, DataClass, EndpointMetadata


@runtime_checkable
class AuditLogger(Protocol):
    """Append-only audit logger interface."""

    def record(self, event: AuditEvent) -> None:
        """Record an immutable audit event."""
        ...

    def events(self) -> Sequence[AuditEvent]:
        """Return recorded audit events in chronological order."""
        ...


@runtime_checkable
class ResidencyPolicy(Protocol):
    """Policy specification evaluating whether a target LLM endpoint is compliant."""

    def is_allowed(self, data_class: DataClass, endpoint: EndpointMetadata) -> bool:
        """Return True if `data_class` may be dispatched to `endpoint`."""
        ...


@runtime_checkable
class LocalOCREngine(Protocol):
    """Network-isolated local OCR adapter for scanned PDFs when LOCAL_OCR_ENABLED is active."""

    def extract_text_from_pdf_bytes(self, pdf_bytes: bytes) -> str:
        """Extract text from raster/scanned PDF bytes strictly within the local boundary."""
        ...
