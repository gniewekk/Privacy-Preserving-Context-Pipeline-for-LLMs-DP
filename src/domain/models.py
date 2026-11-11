"""Immutable Pydantic v2 domain models, enums, tool calls, PDF attachments, and audit events."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, override

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class DataClass(StrEnum):
    """Classification of data sensitivity and regulatory regime (ARCHITECTURE.md §6.5)."""

    ANONYMOUS = "ANONYMOUS"
    GENERAL = "GENERAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    FINANCIAL = "FINANCIAL"
    LEGAL = "LEGAL"
    PHI = "PHI"
    MEDICAL = "PHI"


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
    """Granular RBAC permissions enforced by VaultProtectionProxy."""

    TOKENIZE = "TOKENIZE"
    DETOKENIZE = "DETOKENIZE"
    ROTATE_KEYS = "ROTATE_KEYS"
    AUDIT_READ = "AUDIT_READ"


class AuditAction(StrEnum):
    """Auditable security actions across the pipeline and vault."""

    TOKENIZE = "TOKENIZE"
    DETOKENIZE = "DETOKENIZE"
    ROTATE_KEYS = "ROTATE_KEYS"
    RESIDENCY_CHECK = "RESIDENCY_CHECK"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    DOCUMENT_EXTRACTION = "DOCUMENT_EXTRACTION"
    PIPELINE_EXECUTION = "PIPELINE_EXECUTION"


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
    data_class: DataClass = DataClass.CONFIDENTIAL
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


class ToolCallPayload(BaseModel):
    """Structured LLM ToolCall / FunctionCall payload normalized by PipelineProxy."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    id: str
    name: str
    arguments: dict[str, Any]
    session_id: str | None = Field(
        default=None,
        validation_alias=AliasChoices("session_id", "sessionId"),
    )

    @property
    def sessionId(self) -> str | None:
        """ARCHITECTURE.md (§4) camelCase property alias for `session_id`."""
        return self.session_id


# ARCHITECTURE.md (§4) canonical name alias
ToolCall = ToolCallPayload


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
    certifications: frozenset[str] = frozenset()


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
    token_id: str | None = None
    entity_type: EntityType | None = None
    reason: str | None = None
