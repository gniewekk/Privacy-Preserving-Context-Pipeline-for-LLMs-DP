"""VaultCore: AES-256-GCM token storage behind VaultProxy (ARCHITECTURE.md §3.4, §5.5).

Package-private: only `vault.proxy` and dedicated unit tests may instantiate VaultCore.
Authorization and auditing are VaultProxy's responsibility.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from domain.exceptions import KeyExpiredError, TokenExpiredError, VaultError, VaultIntegrityError
from domain.models import (
    EntityType,
    KeyStatus,
    RotationStrategy,
    SecurityContext,
    SecurityPrincipal,
    TokenRecord,
)
from domain.protocols import KMS

_NONCE_LENGTH_BYTES = 12
_DEFAULT_TOKEN_TTL = timedelta(hours=24)

type Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _aad(record: TokenRecord) -> bytes:
    """Bind the ciphertext to every metadata field of its TokenRecord."""
    metadata = record.model_dump(mode="json", exclude={"encrypted_value", "nonce"})
    return json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()


class VaultCore:
    """Encrypts, stores, decrypts and re-keys TokenRecords; implements TokenizationVault."""

    def __init__(
        self,
        kms: KMS,
        *,
        token_ttl: timedelta | None = _DEFAULT_TOKEN_TTL,
        clock: Clock = _utc_now,
    ) -> None:
        self._kms = kms
        self._token_ttl = token_ttl
        self._clock = clock
        self._records: dict[str, TokenRecord] = {}
        self._lock = threading.RLock()

    def tokenize(
        self,
        plaintext: str,
        entity_type: EntityType,
        context: SecurityContext,
    ) -> TokenRecord:
        created_at = self._clock()
        unsealed = TokenRecord(
            token_id=f"tok_{secrets.token_hex(16)}",
            encrypted_value=b"",
            nonce=os.urandom(_NONCE_LENGTH_BYTES),
            key_id=self._kms.active_key_id(context.data_class, context.session_id),
            entity_type=entity_type,
            data_class=context.data_class,
            tenant_id=context.tenant_id,
            request_id=context.request_id,
            session_id=context.session_id,
            created_at=created_at,
            expires_at=created_at + self._token_ttl if self._token_ttl is not None else None,
        )
        record = self._seal(unsealed, plaintext)
        with self._lock:
            self._records[record.token_id] = record
        return record

    def de_tokenize(
        self,
        token_id: str,
        principal: SecurityPrincipal,
        context: SecurityContext,
    ) -> str:
        record = self.find_record(token_id)
        if record is None:
            raise VaultError("Token is not available.")
        if record.expires_at is not None and record.expires_at <= self._clock():
            raise TokenExpiredError(f"Token {token_id!r} exceeded its retention TTL.")
        return self._open(record)

    def rotate_keys(
        self,
        principal: SecurityPrincipal,
        context: SecurityContext,
        strategy: RotationStrategy = RotationStrategy.RE_ENCRYPT,
    ) -> str:
        new_key_id = self._kms.rotate(context.data_class)
        with self._lock:
            snapshot = [
                r for r in self._records.values() if r.data_class is context.data_class
            ]
        retired = [r for r in snapshot if self._kms.key_status(r.key_id) is KeyStatus.DEPRECATED]
        retired_key_ids = {r.key_id for r in retired}

        if strategy is RotationStrategy.RE_ENCRYPT:
            self._re_encrypt(retired)
        if strategy is not RotationStrategy.RETAIN_OLD_KEY:
            now = self._clock()
            with self._lock:
                still_referenced = {
                    r.key_id
                    for r in self._records.values()
                    if r.expires_at is None or r.expires_at > now
                }
            for key_id in retired_key_ids:
                if strategy is RotationStrategy.EXPIRE or key_id not in still_referenced:
                    self._kms.set_key_status(key_id, KeyStatus.EXPIRED)
        return new_key_id

    def find_record(self, token_id: str) -> TokenRecord | None:
        """Return stored metadata and ciphertext for VaultProxy authorization decisions."""
        with self._lock:
            return self._records.get(token_id)

    def expire(self, token_id: str) -> bool:
        """Irreversibly delete `token_id`; return False if it was already absent."""
        with self._lock:
            return self._records.pop(token_id, None) is not None

    def _re_encrypt(self, records: list[TokenRecord]) -> None:
        now = self._clock()
        replacements: dict[str, tuple[TokenRecord, TokenRecord]] = {}
        for old in records:
            if old.expires_at is not None and old.expires_at <= now:
                continue
            try:
                plaintext = self._open(old)
            except KeyExpiredError:
                continue
            unsealed = old.model_copy(
                update={
                    "key_id": self._kms.active_key_id(old.data_class, old.session_id),
                    "nonce": os.urandom(_NONCE_LENGTH_BYTES),
                }
            )
            replacements[old.token_id] = (old, self._seal(unsealed, plaintext))
        with self._lock:
            for token_id, (old, new) in replacements.items():
                if self._records.get(token_id) is old:
                    self._records[token_id] = new

    def _seal(self, unsealed: TokenRecord, plaintext: str) -> TokenRecord:
        cipher = AESGCM(self._kms.get_key(unsealed.key_id))
        ciphertext = cipher.encrypt(unsealed.nonce, plaintext.encode(), _aad(unsealed))
        return unsealed.model_copy(update={"encrypted_value": ciphertext})

    def _open(self, record: TokenRecord) -> str:
        cipher = AESGCM(self._kms.get_key(record.key_id))
        try:
            return cipher.decrypt(record.nonce, record.encrypted_value, _aad(record)).decode()
        except InvalidTag:
            raise VaultIntegrityError("Token record failed integrity verification.") from None
