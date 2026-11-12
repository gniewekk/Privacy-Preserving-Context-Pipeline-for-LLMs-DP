"""Memento pattern for request-scoped state restoration and data retention lifecycle.

Implements:
- `EntityMetadata` & `PipelineMemento` (ARCHITECTURE.md §3.5, ADR-005, ADR-007)
- `ResponseRestorer` (Caretaker + Outbound Filter stage with Polish inflection & malformed
  placeholder recovery)
- `RetentionPolicyEngine` & `RetentionWorker` (GDPR Art. 17 erasure, TTL purge, and
  crypto-shredding without leaking PII to append-only audit logs)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import threading
import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Self, override

from pydantic import BaseModel, ConfigDict, Field

from domain.exceptions import (
    TokenExpiredError,
    UnauthorizedVaultAccessError,
    VaultError,
    VaultIntegrityError,
)
from domain.models import (
    AuditAction,
    AuditEvent,
    AuditOutcome,
    DataClass,
    EntityType,
    KeyStatus,
    Permission,
    SecurityContext,
    SecurityPrincipal,
)
from domain.protocols import KMS, AuditWriter, TokenizationVault
from pipeline.context import FilterRecord

if TYPE_CHECKING:
    from pipeline.context import PipelineContext
    from vault.vault import VaultCore

type Clock = Callable[[], datetime]

_DEFAULT_RETENTION_TTL = timedelta(hours=24)
_CANONICAL_PLACEHOLDER_RE = re.compile(r"^<[A-Z_]+_[0-9]+>$")
_MALFORMED_PLACEHOLDER_RE = re.compile(
    r"(?:<\s*([A-Za-z_]+_[0-9]+)\s*>|\[\s*([A-Za-z_]+_[0-9]+)\s*\]|\{\s*([A-Za-z_]+_[0-9]+)\s*\})"
)
_POLISH_PLACEHOLDER_SUFFIX_RE = re.compile(
    r"(<[A-Z_]+_[0-9]+>)(?:-(?:em|iem|owi|a|u|ą|ę|ie|y)|(?P<bare>em|iem|owi|a|u|ą|ę))\b"
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _inflect_polish_word(word: str, suffix: str) -> str:
    """Apply basic Polish case inflection to an alphabetic word."""
    s = suffix.lower().lstrip("-")
    if not word or not word.isalpha():
        return word

    lower = word.lower()
    # Masculine adjectives/surnames ending in -ski / -cki / -dzki
    if lower.endswith(("ski", "cki", "dzki")):
        stem = word[:-1]  # ends with 'k' or 'c'
        if s in ("a", "ego"):
            return f"{stem}iego"
        if s in ("owi", "emu"):
            return f"{stem}iemu"
        if s in ("em", "iem", "im"):
            return f"{stem}im"
        return word

    # Feminine names/surnames ending in -a
    if lower.endswith("a"):
        stem = word[:-1]
        if s in ("a", "y"):
            return f"{stem}ie" if lower.endswith(("ka", "ga")) else f"{stem}y"
        if s == "ą":
            return f"{stem}ą"
        if s == "ę":
            return f"{stem}ę"
        return word

    # Standard consonant-ending masculine names/surnames (e.g., Jan, Piotr, Kowal, Nowak)
    if s == "a":
        return f"{word}a"
    if s == "owi":
        return f"{word}owi"
    if s in ("em", "iem"):
        if lower.endswith(("k", "g")):
            return f"{word}iem"
        return f"{word}em"
    if s == "u":
        return f"{word}u"
    return word


def _inflect_polish_full_name(full_name: str, suffix: str) -> str:
    """Inflect a Polish full name (`Imię Nazwisko`) according to `suffix`."""
    parts = full_name.split(" ")
    if not parts:
        return full_name
    return " ".join(_inflect_polish_word(part, suffix) for part in parts)


def _polish_inflected_variants(full_name: str) -> dict[str, str]:
    """Return a map of `{inflected_form: suffix}` for a Polish full name."""
    variants: dict[str, str] = {}
    for suffix in ("a", "owi", "em", "u", "ą", "ę"):
        inflected = _inflect_polish_full_name(full_name, suffix)
        if inflected != full_name:
            variants[inflected] = suffix
    return variants


class EntityMetadata(BaseModel):
    """Opaque token metadata stored inside PipelineMemento (never contains raw PII)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    token_id: str
    entity_type: EntityType
    key_id: str | None = None
    is_synthetic: bool = False


def _compute_memento_checksum(
    *,
    request_id: str,
    session_id: str | None,
    tenant_id: str,
    data_class: DataClass,
    residency_jurisdiction: str,
    version: int,
    applied_filters: tuple[FilterRecord, ...],
    timestamp: datetime,
    expires_at: datetime | None,
    key_id: str | None,
    sanitized_text: str,
    token_map: Mapping[str, EntityMetadata],
) -> bytes:
    """Compute a deterministic SHA-256 integrity digest over all Memento fields."""
    payload = {
        "request_id": request_id,
        "session_id": session_id,
        "tenant_id": tenant_id,
        "data_class": data_class.value,
        "residency_jurisdiction": residency_jurisdiction,
        "version": version,
        "applied_filters": [
            {"filter_name": f.filter_name, "executed_at": f.executed_at.isoformat()}
            for f in applied_filters
        ],
        "timestamp": timestamp.isoformat(),
        "expires_at": expires_at.isoformat() if expires_at is not None else None,
        "key_id": key_id,
        "sanitized_text": sanitized_text,
        "token_map": {
            k: {
                "token_id": v.token_id,
                "entity_type": v.entity_type.value,
                "key_id": v.key_id,
                "is_synthetic": v.is_synthetic,
            }
            for k, v in sorted(token_map.items())
        },
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).digest()


class PipelineMemento(BaseModel):
    """Encapsulated, tamper-evident snapshot of request-scoped anonymization state (ADR-005).

    Stores only `placeholder -> EntityMetadata` pointers (never raw plaintext PII).
    Original values exist exclusively encrypted inside `VaultCore`.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: str
    session_id: str | None = None
    tenant_id: str = "default"
    data_class: DataClass = DataClass.GENERAL
    residency_jurisdiction: str = "EU"
    version: int = Field(default=1, ge=1)
    applied_filters: tuple[FilterRecord, ...] = ()
    timestamp: datetime = Field(default_factory=_utc_now)
    expires_at: datetime | None = None
    key_id: str | None = None
    sanitized_text: str = ""
    token_map: dict[str, EntityMetadata] = Field(default_factory=dict, repr=False)
    checksum: bytes = Field(default=b"", repr=False)

    @classmethod
    def create(
        cls,
        *,
        request_id: str,
        session_id: str | None = None,
        tenant_id: str = "default",
        data_class: DataClass = DataClass.GENERAL,
        residency_jurisdiction: str = "EU",
        version: int = 1,
        applied_filters: tuple[FilterRecord, ...] = (),
        timestamp: datetime | None = None,
        expires_at: datetime | None = None,
        key_id: str | None = None,
        sanitized_text: str = "",
        token_map: Mapping[str, EntityMetadata] | None = None,
    ) -> Self:
        """Create a sealed PipelineMemento with an integrity checksum."""
        ts = timestamp if timestamp is not None else _utc_now()
        frozen_map = dict(token_map) if token_map is not None else {}
        digest = _compute_memento_checksum(
            request_id=request_id,
            session_id=session_id,
            tenant_id=tenant_id,
            data_class=data_class,
            residency_jurisdiction=residency_jurisdiction,
            version=version,
            applied_filters=applied_filters,
            timestamp=ts,
            expires_at=expires_at,
            key_id=key_id,
            sanitized_text=sanitized_text,
            token_map=frozen_map,
        )
        return cls(
            request_id=request_id,
            session_id=session_id,
            tenant_id=tenant_id,
            data_class=data_class,
            residency_jurisdiction=residency_jurisdiction,
            version=version,
            applied_filters=applied_filters,
            timestamp=ts,
            expires_at=expires_at,
            key_id=key_id,
            sanitized_text=sanitized_text,
            token_map=frozen_map,
            checksum=digest,
        )

    def verify_integrity(self) -> None:
        """Verify the cryptographic SHA-256 checksum of this Memento snapshot."""
        expected = _compute_memento_checksum(
            request_id=self.request_id,
            session_id=self.session_id,
            tenant_id=self.tenant_id,
            data_class=self.data_class,
            residency_jurisdiction=self.residency_jurisdiction,
            version=self.version,
            applied_filters=self.applied_filters,
            timestamp=self.timestamp,
            expires_at=self.expires_at,
            key_id=self.key_id,
            sanitized_text=self.sanitized_text,
            token_map=self.token_map,
        )
        if not self.checksum or self.checksum != expected:
            raise VaultIntegrityError(
                f"PipelineMemento integrity check failed for request_id={self.request_id!r}."
            )

    def expand(
        self,
        additional_tokens: Mapping[str, EntityMetadata],
        *,
        session_id: str | None = None,
        tenant_id: str | None = None,
        key_id: str | None = None,
    ) -> Self:
        """Atomically expand this Memento with new tool-result tokens (ADR-007).

        Verifies existing integrity, enforces `session_id` and `tenant_id` continuity,
        increments `version` by 1, and recomputes `checksum`.
        """
        self.verify_integrity()
        if session_id is not None and self.session_id != session_id:
            raise UnauthorizedVaultAccessError(
                "Cannot expand PipelineMemento across mismatched session_id boundaries."
            )
        if tenant_id is not None and self.tenant_id != tenant_id:
            raise UnauthorizedVaultAccessError(
                "Cannot expand PipelineMemento across mismatched tenant_id boundaries."
            )
        merged_map = dict(self.token_map)
        merged_map.update(additional_tokens)
        return self.create(
            request_id=self.request_id,
            session_id=self.session_id,
            tenant_id=self.tenant_id,
            data_class=self.data_class,
            residency_jurisdiction=self.residency_jurisdiction,
            version=self.version + 1,
            applied_filters=self.applied_filters,
            timestamp=self.timestamp,
            expires_at=self.expires_at,
            key_id=key_id if key_id is not None else self.key_id,
            sanitized_text=self.sanitized_text,
            token_map=merged_map,
        )

    @override
    def __repr__(self) -> str:
        return (
            f"PipelineMemento(request_id={self.request_id!r}, session_id={self.session_id!r}, "
            f"tenant_id={self.tenant_id!r}, version={self.version}, "
            f"token_count={len(self.token_map)}, key_id={self.key_id!r}, "
            f"expires_at={self.expires_at.isoformat() if self.expires_at else None!r})"
        )

    @override
    def __str__(self) -> str:
        return self.__repr__()


class RetentionPolicyEngine:
    """Determines retention TTL (`expires_at`) for TokenRecords and Mementos (§6.2).

    Default TTL is 24 hours per GDPR Art. 17 & ARCHITECTURE.md §6.2. Custom per-DataClass
    policies may tighten retention but cannot exceed `max_ttl` without an explicit legal hold.
    """

    def __init__(
        self,
        default_ttl: timedelta = _DEFAULT_RETENTION_TTL,
        *,
        max_ttl: timedelta = _DEFAULT_RETENTION_TTL,
        class_ttls: Mapping[DataClass, timedelta] | None = None,
        clock: Clock = _utc_now,
    ) -> None:
        if default_ttl <= timedelta(0):
            raise ValueError("default_ttl must be positive.")
        if default_ttl > max_ttl:
            raise ValueError("default_ttl cannot exceed max_ttl without legal hold.")
        self._default_ttl = default_ttl
        self._max_ttl = max_ttl
        self._class_ttls: dict[DataClass, timedelta] = {}
        if class_ttls is not None:
            for dc, ttl in class_ttls.items():
                if ttl <= timedelta(0) or ttl > max_ttl:
                    raise ValueError(
                        f"Retention TTL for {dc.value} must be in (0, max_ttl]."
                    )
                self._class_ttls[dc] = ttl
        self._clock = clock

    def ttl_for(self, data_class: DataClass = DataClass.GENERAL) -> timedelta:
        """Return the configured retention TTL for `data_class`."""
        return self._class_ttls.get(data_class, self._default_ttl)

    def compute_expires_at(
        self,
        created_at: datetime | None = None,
        data_class: DataClass = DataClass.GENERAL,
        *,
        legal_hold_ttl: timedelta | None = None,
    ) -> datetime:
        """Compute `expires_at` timestamp for a newly created token or session Memento."""
        base_time = created_at if created_at is not None else self._clock()
        if legal_hold_ttl is not None:
            if legal_hold_ttl <= timedelta(0):
                raise ValueError("legal_hold_ttl must be positive.")
            return base_time + legal_hold_ttl
        return base_time + self.ttl_for(data_class)

    def is_expired(
        self,
        expires_at: datetime | None,
        now: datetime | None = None,
    ) -> bool:
        """Return True if `expires_at` is set and has elapsed relative to `now`."""
        if expires_at is None:
            return False
        effective_now = now if now is not None else self._clock()
        return expires_at <= effective_now


class ResponseRestorer:
    """Caretaker managing PipelineMemento lifecycle and restoring LLM responses (§3.5, ADR-005).

    Also implements the `Filter` interface so it can serve as the final stage of the
    Outbound Pipeline (`OutputPIIDetector` -> `ResponseRestorer`).
    """

    def __init__(
        self,
        vault: TokenizationVault | None = None,
        *,
        retention_policy: RetentionPolicyEngine | None = None,
        audit_writer: AuditWriter | None = None,
        clock: Clock = _utc_now,
    ) -> None:
        self._vault = vault
        self._retention_policy = retention_policy or RetentionPolicyEngine(clock=clock)
        self._audit_writer = audit_writer
        self._clock = clock
        self._mementos_by_request: dict[str, PipelineMemento] = {}
        self._mementos_by_session: dict[str, PipelineMemento] = {}
        self._expired_request_ids: set[str] = set()
        self._expired_session_ids: set[str] = set()
        self._lock = threading.RLock()

    @property
    def filter_name(self) -> str:
        return "ResponseRestorer"

    def bind_vault(self, vault: TokenizationVault) -> None:
        """Bind a `TokenizationVault` instance if not supplied at construction time."""
        self._vault = vault

    def store(self, memento: PipelineMemento) -> PipelineMemento:
        """Verify and store `memento` indexed by `request_id` (and `session_id` if present)."""
        memento.verify_integrity()
        effective = memento
        if effective.expires_at is None:
            effective = PipelineMemento.create(
                request_id=memento.request_id,
                session_id=memento.session_id,
                tenant_id=memento.tenant_id,
                data_class=memento.data_class,
                residency_jurisdiction=memento.residency_jurisdiction,
                version=memento.version,
                applied_filters=memento.applied_filters,
                timestamp=memento.timestamp,
                expires_at=self._retention_policy.compute_expires_at(
                    memento.timestamp, memento.data_class
                ),
                key_id=memento.key_id,
                sanitized_text=memento.sanitized_text,
                token_map=memento.token_map,
            )
        with self._lock:
            self._expired_request_ids.discard(effective.request_id)
            self._mementos_by_request[effective.request_id] = effective
            if effective.session_id is not None:
                self._expired_session_ids.discard(effective.session_id)
                self._mementos_by_session[effective.session_id] = effective
        return effective

    def get(self, request_id: str) -> PipelineMemento | None:
        """Retrieve an active, non-expired `PipelineMemento` by `request_id`."""
        with self._lock:
            memento = self._mementos_by_request.get(request_id)
            if memento is None:
                if request_id in self._expired_request_ids:
                    raise TokenExpiredError(
                        f"PipelineMemento for request_id={request_id!r} has expired."
                    )
                return None
            if self._retention_policy.is_expired(memento.expires_at, self._clock()):
                self._mark_expired_unlocked(memento)
                raise TokenExpiredError(
                    f"PipelineMemento for request_id={request_id!r} has expired."
                )
            memento.verify_integrity()
            return memento

    def get_by_session(self, session_id: str) -> PipelineMemento | None:
        """Retrieve the latest active, non-expired `PipelineMemento` for `session_id`."""
        with self._lock:
            memento = self._mementos_by_session.get(session_id)
            if memento is None:
                if session_id in self._expired_session_ids:
                    raise TokenExpiredError(
                        f"PipelineMemento for session_id={session_id!r} has expired."
                    )
                return None
            if self._retention_policy.is_expired(memento.expires_at, self._clock()):
                self._mark_expired_unlocked(memento)
                raise TokenExpiredError(
                    f"PipelineMemento for session_id={session_id!r} has expired."
                )
            memento.verify_integrity()
            return memento

    def evict_expired(self, now: datetime | None = None) -> int:
        """Evict all expired Mementos from memory and return the number of evicted entries."""
        effective_now = now if now is not None else self._clock()
        evicted = 0
        with self._lock:
            for _req_id, memento in list(self._mementos_by_request.items()):
                if self._retention_policy.is_expired(memento.expires_at, effective_now):
                    self._mark_expired_unlocked(memento)
                    evicted += 1
        return evicted

    def invalidate(self, request_id: str) -> bool:
        """Remove the Memento for `request_id` (used for atomic rollback or session cleanup)."""
        with self._lock:
            self._expired_request_ids.discard(request_id)
            memento = self._mementos_by_request.pop(request_id, None)
            if memento is None:
                return False
            if (
                memento.session_id is not None
                and self._mementos_by_session.get(memento.session_id) is memento
            ):
                self._mementos_by_session.pop(memento.session_id, None)
            return True

    def invalidate_session(self, session_id: str) -> int:
        """Remove all Mementos associated with `session_id`."""
        removed = 0
        with self._lock:
            self._expired_session_ids.discard(session_id)
            self._mementos_by_session.pop(session_id, None)
            for req_id, memento in list(self._mementos_by_request.items()):
                if memento.session_id == session_id:
                    self._expired_request_ids.discard(req_id)
                    self._mementos_by_request.pop(req_id, None)
                    removed += 1
        return removed

    def _mark_expired_unlocked(self, memento: PipelineMemento) -> None:
        self._mementos_by_request.pop(memento.request_id, None)
        self._expired_request_ids.add(memento.request_id)
        if memento.session_id is not None:
            self._expired_session_ids.add(memento.session_id)
            if self._mementos_by_session.get(memento.session_id) is memento:
                self._mementos_by_session.pop(memento.session_id, None)

    def _verify_caller_authorization(
        self,
        memento: PipelineMemento,
        principal: SecurityPrincipal | None,
        context: SecurityContext | None,
    ) -> tuple[SecurityPrincipal, SecurityContext]:
        sec_ctx = context or SecurityContext(
            request_id=memento.request_id,
            tenant_id=memento.tenant_id,
            session_id=memento.session_id,
            data_class=memento.data_class,
            jurisdiction=memento.residency_jurisdiction,
        )
        if principal is None:
            self._record_denied_audit(memento, "anonymous", "Missing SecurityPrincipal.")
            raise UnauthorizedVaultAccessError(
                "SecurityPrincipal with DETOKENIZE permission is required for restoration."
            )
        if Permission.DETOKENIZE not in principal.permissions:
            self._record_denied_audit(
                memento, principal.principal_id, "Principal lacks DETOKENIZE permission."
            )
            raise UnauthorizedVaultAccessError(
                f"Principal {principal.principal_id!r} lacks DETOKENIZE permission."
            )
        if principal.tenant_id != memento.tenant_id or sec_ctx.tenant_id != memento.tenant_id:
            self._record_denied_audit(
                memento, principal.principal_id, "Cross-tenant restoration denied."
            )
            raise UnauthorizedVaultAccessError(
                "Tenant mismatch between SecurityPrincipal/SecurityContext and PipelineMemento."
            )
        if (
            memento.session_id is not None
            and sec_ctx.session_id is not None
            and sec_ctx.session_id != memento.session_id
        ):
            self._record_denied_audit(
                memento, principal.principal_id, "Cross-session restoration denied."
            )
            raise UnauthorizedVaultAccessError(
                "Session mismatch between SecurityContext and PipelineMemento."
            )
        if principal.expires_at is not None and principal.expires_at <= self._clock():
            self._record_denied_audit(
                memento, principal.principal_id, "SecurityPrincipal credentials expired."
            )
            raise UnauthorizedVaultAccessError(
                f"Principal {principal.principal_id!r} credentials have expired."
            )
        return principal, sec_ctx

    def _record_denied_audit(
        self,
        memento: PipelineMemento,
        principal_id: str,
        reason: str,
    ) -> None:
        if self._audit_writer is None:
            return
        self._audit_writer.record(
            AuditEvent(
                event_id=f"evt_{uuid.uuid4().hex[:12]}",
                timestamp=self._clock(),
                action=AuditAction.DETOKENIZE,
                outcome=AuditOutcome.DENIED,
                principal_id=principal_id,
                tenant_id=memento.tenant_id,
                request_id=memento.request_id,
                session_id=memento.session_id,
                reason=reason,
            )
        )

    @staticmethod
    def _normalize_malformed_placeholders(
        text: str,
        known_placeholders: set[str],
    ) -> str:
        """Recover placeholders slightly mangled by the LLM (e.g. `[PERSON_1]`, `< person_1 >`)."""
        if not known_placeholders:
            return text

        def _replacer(match: re.Match[str]) -> str:
            inner = match.group(1) or match.group(2) or match.group(3)
            if not inner:
                return match.group(0)
            canonical = f"<{inner.upper()}>"
            if canonical in known_placeholders:
                return canonical
            return match.group(0)

        return _MALFORMED_PLACEHOLDER_RE.sub(_replacer, text)

    def restore_response(
        self,
        response_text: str,
        memento: PipelineMemento | str,
        principal: SecurityPrincipal | None = None,
        context: SecurityContext | None = None,
    ) -> str:
        """Restore placeholders or synthetic values in `response_text` via `TokenizationVault`."""
        resolved_memento = (
            self.get(memento) if isinstance(memento, str) else memento
        )
        if resolved_memento is None:
            raise VaultError(f"No PipelineMemento found for {memento!r}.")

        resolved_memento.verify_integrity()
        if self._retention_policy.is_expired(resolved_memento.expires_at, self._clock()):
            self.invalidate(resolved_memento.request_id)
            raise TokenExpiredError(
                f"PipelineMemento for request_id={resolved_memento.request_id!r} has expired."
            )

        if not resolved_memento.token_map or not response_text:
            return response_text

        if self._vault is None:
            raise VaultError("ResponseRestorer requires a bound TokenizationVault.")

        auth_principal, sec_ctx = self._verify_caller_authorization(
            resolved_memento, principal, context
        )

        known_keys = set(resolved_memento.token_map.keys())
        normalized_text = self._normalize_malformed_placeholders(response_text, known_keys)

        # Determine which placeholders / synthetic values actually appear in the response
        resolved_originals: dict[str, str] = {}
        synthetic_inflections: dict[str, tuple[str, str]] = {}

        for placeholder, meta in resolved_memento.token_map.items():
            needs_lookup = placeholder in normalized_text
            if not needs_lookup and (meta.is_synthetic or not placeholder.startswith("<")):
                for inflected_form in _polish_inflected_variants(placeholder):
                    if inflected_form in normalized_text:
                        needs_lookup = True
                        break
            if needs_lookup:
                original_value = self._vault.de_tokenize(
                    meta.token_id,
                    auth_principal,
                    sec_ctx,
                )
                resolved_originals[placeholder] = original_value
                if not placeholder.startswith("<"):
                    for inflected_synth, suffix in _polish_inflected_variants(placeholder).items():
                        synthetic_inflections[inflected_synth] = (original_value, suffix)

        if not resolved_originals:
            return normalized_text

        # Step 1: Handle Polish morphological suffixes glued to `<ENTITY_N>` placeholders
        # e.g., `<PERSON_1>em` -> `Janem Kowalskim`, `<PERSON_1>-owi` -> `Janowi Kowalskiemu`
        def _replace_suffixed_placeholder(match: re.Match[str]) -> str:
            placeholder = match.group(1)
            full_match = match.group(0)
            suffix = full_match[len(placeholder) :]
            if placeholder not in resolved_originals:
                return full_match
            original = resolved_originals[placeholder]
            return _inflect_polish_full_name(original, suffix)

        restored = _POLISH_PLACEHOLDER_SUFFIX_RE.sub(
            _replace_suffixed_placeholder, normalized_text
        )

        # Step 2: Replace inflected synthetic Polish person names first (longest match first)
        for inflected_synth in sorted(synthetic_inflections, key=len, reverse=True):
            original_person, suffix = synthetic_inflections[inflected_synth]
            restored = restored.replace(
                inflected_synth,
                _inflect_polish_full_name(original_person, suffix),
            )

        # Step 3: Replace exact placeholders and synthetic values (longest first)
        for placeholder in sorted(resolved_originals, key=len, reverse=True):
            restored = restored.replace(placeholder, resolved_originals[placeholder])

        return restored

    def process(self, context: PipelineContext) -> PipelineContext:
        """Execute ResponseRestorer as a stateless Filter stage in the Outbound Pipeline."""
        memento = self.get(context.request_id)
        if memento is None and context.session_id is not None:
            memento = self.get_by_session(context.session_id)
        if memento is None:
            if not context.placeholder_map:
                return context
            memento = context.create_memento(
                expires_at=self._retention_policy.compute_expires_at(
                    data_class=context.data_class
                )
            )
        restored = self.restore_response(
            context.current_text,
            memento,
            principal=context.principal,
            context=SecurityContext(
                request_id=context.request_id,
                tenant_id=context.tenant_id,
                session_id=context.session_id,
                data_class=context.data_class,
            ),
        )
        return context.model_copy(update={"sanitized_text": restored})


class RetentionWorker:
    """Asynchronous and synchronous worker purging expired TokenRecords and Mementos (§6.2).

    Implements operational right-to-erasure (GDPR Art. 17) and logs tamper-evident
    `TOKEN_PURGE` audit events without ever recording raw PII values.
    """

    def __init__(
        self,
        vault_core: VaultCore,
        *,
        response_restorer: ResponseRestorer | None = None,
        kms: KMS | None = None,
        audit_writer: AuditWriter | None = None,
        clock: Clock = _utc_now,
    ) -> None:
        self._vault_core = vault_core
        self._response_restorer = response_restorer
        self._kms = kms
        self._audit_writer = audit_writer
        self._clock = clock

    def _record_purge_event(
        self,
        *,
        token_id: str,
        tenant_id: str,
        request_id: str,
        session_id: str | None,
        entity_type: EntityType | None,
        reason: str,
    ) -> None:
        if self._audit_writer is None:
            return
        prev_events = self._audit_writer.events()
        previous_hash = prev_events[-1].event_hash if prev_events else "genesis"
        timestamp = self._clock()
        event_id = f"evt_{uuid.uuid4().hex[:12]}"
        hash_input = (
            f"{event_id}|{timestamp.isoformat()}|{AuditAction.RETENTION_PURGE.value}|"
            f"{AuditOutcome.COMPLETED.value}|retention_worker|{tenant_id}|{request_id}|"
            f"{session_id}|{token_id}|{reason}|{previous_hash}"
        )
        event_hash = f"sha256:{hashlib.sha256(hash_input.encode('utf-8')).hexdigest()}"
        self._audit_writer.record(
            AuditEvent(
                event_id=event_id,
                timestamp=timestamp,
                action=AuditAction.RETENTION_PURGE,
                outcome=AuditOutcome.COMPLETED,
                principal_id="retention_worker",
                tenant_id=tenant_id,
                request_id=request_id,
                session_id=session_id,
                token_id=token_id,
                entity_type=entity_type,
                reason=reason,
                previous_hash=previous_hash,
                event_hash=event_hash,
            )
        )

    def run_once(self, now: datetime | None = None) -> int:
        """Purge all expired TokenRecords and Mementos; return count of purged Vault records."""
        effective_now = now if now is not None else self._clock()
        expired_ids = self._vault_core.expired_token_ids(effective_now)
        purged_count = 0

        for token_id in expired_ids:
            record = self._vault_core.find_record(token_id)
            if self._vault_core.expire(token_id):
                purged_count += 1
                if record is not None:
                    self._record_purge_event(
                        token_id=token_id,
                        tenant_id=record.tenant_id,
                        request_id=record.request_id,
                        session_id=record.session_id,
                        entity_type=record.entity_type,
                        reason="RETENTION_TTL_EXPIRED",
                    )

        if self._response_restorer is not None:
            self._response_restorer.evict_expired(effective_now)

        return purged_count

    async def run_async(
        self,
        interval_seconds: float = 60.0,
        *,
        max_iterations: int = 1,
    ) -> int:
        """Asynchronously execute retention purge cycles."""
        total_purged = 0
        for idx in range(max_iterations):
            total_purged += self.run_once()
            if idx + 1 < max_iterations and interval_seconds > 0:
                await asyncio.sleep(interval_seconds)
        return total_purged

    def forget_session(
        self,
        session_id: str,
        *,
        data_class: DataClass | None = None,
        crypto_shred_keys: bool = True,
    ) -> int:
        """Execute GDPR Art. 17 right-to-erasure for `session_id` (purge + crypto-shredding).

        Irreversibly deletes all session TokenRecords, invalidates session Mementos,
        expires session DEKs in KMS, and writes PII-free audit events.
        """
        token_ids = self._vault_core.session_token_ids(session_id)
        shredded_keys: set[str] = set()
        purged_count = 0

        for token_id in token_ids:
            record = self._vault_core.find_record(token_id)
            if self._vault_core.expire(token_id):
                purged_count += 1
                if record is not None:
                    shredded_keys.add(record.key_id)
                    self._record_purge_event(
                        token_id=token_id,
                        tenant_id=record.tenant_id,
                        request_id=record.request_id,
                        session_id=record.session_id,
                        entity_type=record.entity_type,
                        reason="GDPR_ART17_ERASURE",
                    )

        if crypto_shred_keys and self._kms is not None:
            if data_class is not None:
                try:
                    active_id = self._kms.active_key_id(data_class, session_id)
                    shredded_keys.add(active_id)
                except VaultError:
                    pass
            for key_id in shredded_keys:
                try:
                    status = self._kms.key_status(key_id)
                    if status not in (KeyStatus.EXPIRED, KeyStatus.REVOKED):
                        self._kms.set_key_status(key_id, KeyStatus.EXPIRED)
                except VaultError:
                    continue

        if self._response_restorer is not None:
            self._response_restorer.invalidate_session(session_id)

        return purged_count
