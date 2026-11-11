"""Core domain protocols for audit logging, residency, local OCR, token vault, and KMS."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from domain.models import (
    AuditEvent,
    DataClass,
    EndpointMetadata,
    EntityType,
    KeyStatus,
    RotationStrategy,
    SecurityContext,
    SecurityPrincipal,
    TokenRecord,
)


@runtime_checkable
class AuditWriter(Protocol):
    """Append-only AuditWriter interface persisting events to the immutable AuditLog."""

    def record(self, event: AuditEvent) -> None:
        """Record an immutable audit event."""
        ...

    def events(self) -> Sequence[AuditEvent]:
        """Return recorded audit events in chronological order."""
        ...


@runtime_checkable
class ResidencyPolicyEngine(Protocol):
    """ResidencyPolicyEngine evaluating whether a target LLM endpoint is compliant."""

    def is_allowed(self, data_class: DataClass, endpoint: EndpointMetadata) -> bool:
        """Return True if `data_class` may be dispatched to `endpoint`."""
        ...


@runtime_checkable
class LocalOCREngine(Protocol):
    """Network-isolated local OCR adapter for scanned PDFs when LOCAL_OCR_ENABLED is active."""

    def extract_text_from_pdf_bytes(self, pdf_bytes: bytes) -> str:
        """Extract text from raster/scanned PDF bytes strictly within the local boundary."""
        ...


@runtime_checkable
class LanguageDetector(Protocol):
    """Language detection strategy used before language-specific PII detectors."""

    def detect(self, text: str) -> str:
        """Return a normalized ISO-639-1 language code or ``unknown``."""
        ...


@runtime_checkable
class TokenizationVault(Protocol):
    """Token vault interface implemented by both VaultProxy and VaultCore (ADR-004)."""

    def tokenize(
        self,
        plaintext: str,
        entity_type: EntityType,
        context: SecurityContext,
    ) -> TokenRecord:
        """Encrypt `plaintext` and return the stored TokenRecord (never the plaintext)."""
        ...

    def de_tokenize(
        self,
        token_id: str,
        principal: SecurityPrincipal,
        context: SecurityContext,
    ) -> str:
        """Return the original value of `token_id` for an authorized `principal`."""
        ...

    def rotate_keys(
        self,
        principal: SecurityPrincipal,
        context: SecurityContext,
        strategy: RotationStrategy = RotationStrategy.RE_ENCRYPT,
    ) -> str:
        """Rotate the active key for `context.data_class` and return the new `key_id`."""
        ...


@runtime_checkable
class KMS(Protocol):
    """Key management service issuing versioned AES-256 keys (ARCHITECTURE.md §6.3)."""

    def active_key_id(self, data_class: DataClass, session_id: str | None = None) -> str:
        """Return the ACTIVE `key_id` used to encrypt new TokenRecords."""
        ...

    def get_key(self, key_id: str) -> bytes:
        """Return key material; raise KeyExpiredError for EXPIRED or REVOKED keys."""
        ...

    def key_status(self, key_id: str) -> KeyStatus:
        """Return the lifecycle status of `key_id`."""
        ...

    def rotate(self, data_class: DataClass) -> str:
        """Issue a new ACTIVE key for `data_class`, mark the previous one DEPRECATED."""
        ...

    def set_key_status(self, key_id: str, status: KeyStatus) -> None:
        """Move `key_id` to DEPRECATED, EXPIRED or REVOKED; reactivation is forbidden."""
        ...
