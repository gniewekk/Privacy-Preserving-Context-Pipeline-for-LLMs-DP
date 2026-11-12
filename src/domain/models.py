"""Immutable Pydantic v2 domain models, enums, tool calls, PDF attachments, and audit events."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, override

from pydantic import BaseModel, ConfigDict, Field


class DataClass(StrEnum):
    """Classification of data sensitivity and regulatory regime (ARCHITECTURE.md §6.5)."""

    ANONYMOUS = "ANONYMOUS"
    GENERAL = "GENERAL"
    FINANCIAL = "FINANCIAL"
    LEGAL = "LEGAL"
    MEDICAL = "MEDICAL"


class AuditLevel(StrEnum):
    """Audit verbosity level configured via PipelineBuilder."""

    NONE = "NONE"
    MINIMAL = "MINIMAL"
    FULL = "FULL"


class PDFExtractionPolicy(StrEnum):
    """Policy governing scanned PDFs and embedded images in DocumentExtractorFilter."""

    STRICT_NO_OCR = "STRICT_NO_OCR"
    LOCAL_OCR_ENABLED = "LOCAL_OCR_ENABLED"


class EntityType(StrEnum):
    """Canonical PII/PHI and quasi-identifier entity categories (Poland & USA)."""

    PERSON = "PERSON"
    ORGANIZATION = "ORGANIZATION"
    LOCATION = "LOCATION"
    # Polish identifiers
    PESEL = "PESEL"
    NIP = "NIP"
    REGON = "REGON"
    IBAN = "IBAN"
    ID_CARD = "ID_CARD"
    # US & international identifiers
    SSN = "SSN"
    ITIN = "ITIN"
    EIN = "EIN"
    ABA_ROUTING = "ABA_ROUTING"
    CREDIT_CARD = "CREDIT_CARD"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    DATE = "DATE"
    AGE = "AGE"
    PROFESSION = "PROFESSION"
    MEDICAL_CONDITION = "MEDICAL_CONDITION"
    CUSTOM = "CUSTOM"


class Permission(StrEnum):
    """Granular RBAC permissions enforced by VaultProxy."""

    TOKENIZE = "TOKENIZE"
    DETOKENIZE = "DETOKENIZE"
    ROTATE_KEYS = "ROTATE_KEYS"
    AUDIT_READ = "AUDIT_READ"


class KeyStatus(StrEnum):
    """Lifecycle status of a versioned KMS key (ARCHITECTURE.md §5.5)."""

    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class RotationStrategy(StrEnum):
    """Handling of TokenRecords encrypted under a rotated key (ARCHITECTURE.md §5.5)."""

    RE_ENCRYPT = "RE_ENCRYPT"
    RETAIN_OLD_KEY = "RETAIN_OLD_KEY"
    EXPIRE = "EXPIRE"


class AuditAction(StrEnum):
    """Auditable security actions across the pipeline and vault."""

    TOKENIZE = "TOKENIZE"
    DETOKENIZE = "DETOKENIZE"
    ROTATE_KEYS = "ROTATE_KEYS"
    RESIDENCY_CHECK = "RESIDENCY_CHECK"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    DOCUMENT_EXTRACTION = "DOCUMENT_EXTRACTION"
    PIPELINE_EXECUTION = "PIPELINE_EXECUTION"
    OUTPUT_PII_SCAN = "OUTPUT_PII_SCAN"
    TOOL_EXECUTION = "TOOL_EXECUTION"
    RETENTION_PURGE = "RETENTION_PURGE"


class AuditOutcome(StrEnum):
    """Outcome of an audited operation."""

    GRANTED = "GRANTED"
    DENIED = "DENIED"
    BLOCKED = "BLOCKED"
    COMPLETED = "COMPLETED"


class DetectedEntity(BaseModel):
    """Immutable value object representing a detected PII/PHI span.

    Redacts `raw_value` in `__repr__` and `__str__` to prevent accidental PII leakage.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_type: EntityType
    start: int = Field(ge=0)
    end: int = Field(ge=0)
    raw_value: str = Field(repr=False)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    data_class: DataClass = DataClass.GENERAL
    detector_id: str = "default"

    @override
    def __repr__(self) -> str:
        return (
            f"DetectedEntity(entity_type={self.entity_type!r}, "
            f"span=({self.start}, {self.end}), length={len(self.raw_value)}, "
            f"confidence={self.confidence:.2f}, detector_id={self.detector_id!r})"
        )

    @override
    def __str__(self) -> str:
        return self.__repr__()


class SecurityPrincipal(BaseModel):
    """Immutable caller identity and RBAC claims."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    principal_id: str
    tenant_id: str
    roles: frozenset[str] = frozenset()
    permissions: frozenset[Permission] = frozenset()
    expires_at: datetime | None = None


class SecurityContext(BaseModel):
    """Request-scoped security and regulatory metadata."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: str
    tenant_id: str
    session_id: str | None = None
    data_class: DataClass = DataClass.GENERAL
    jurisdiction: str = "EU"


class AnonymizationRequest(BaseModel):
    """Contextual parameters passed to an AnonymizationStrategy."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: str
    tenant_id: str
    principal: SecurityPrincipal | None = None
    context: SecurityContext | None = None
    entity_index: int = Field(default=1, ge=1)


class AnonymizationResult(BaseModel):
    """Output returned by an AnonymizationStrategy for a single entity."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    replacement_text: str
    entity_type: EntityType
    is_reversible: bool
    token_id: str | None = None
    key_id: str | None = None


class ToolCall(BaseModel):
    """Structured LLM ToolCall payload normalized by PipelineProxy (§4)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    name: str
    arguments: dict[str, Any]
    session_id: str | None = None


class DocumentAttachment(BaseModel):
    """Binary document attachment (e.g., PDF) intercepted by DocumentExtractorFilter."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    filename: str
    content_bytes: bytes = Field(repr=False)
    mime_type: str = "application/pdf"

    @override
    def __repr__(self) -> str:
        return (
            f"DocumentAttachment(filename={self.filename!r}, "
            f"mime_type={self.mime_type!r}, size_bytes={len(self.content_bytes)})"
        )

    @override
    def __str__(self) -> str:
        return self.__repr__()


class EndpointMetadata(BaseModel):
    """Declarative metadata describing a target LLM endpoint's jurisdiction."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider_id: str
    region: str
    is_eu_compliant: bool
    data_processing_agreement: bool = False
    certifications: frozenset[str] = frozenset()


class TokenRecord(BaseModel):
    """Encrypted vault entry binding a token to its AES-256-GCM ciphertext (ARCHITECTURE.md §3.4).

    `tenant_id`, `request_id` and `entity_type` form the AAD, so altering them breaks decryption.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    token_id: str
    encrypted_value: bytes = Field(repr=False)
    nonce: bytes = Field(repr=False, min_length=12, max_length=12)
    key_id: str
    entity_type: EntityType
    data_class: DataClass = DataClass.GENERAL
    tenant_id: str
    request_id: str
    session_id: str | None = None
    created_at: datetime
    expires_at: datetime | None = None


class AuditEvent(BaseModel):
    """Tamper-evident audit record (never contains raw PII/PHI)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    timestamp: datetime
    action: AuditAction
    outcome: AuditOutcome
    principal_id: str
    tenant_id: str
    request_id: str
    session_id: str | None = None
    token_id: str | None = None
    entity_type: EntityType | None = None
    reason: str | None = None
    previous_hash: str | None = None
    event_hash: str | None = None
