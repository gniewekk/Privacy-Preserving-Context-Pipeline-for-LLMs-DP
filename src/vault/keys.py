"""KMS implementation with an MK -> KEK -> DEK hierarchy and KeyRotation scheduling."""

from __future__ import annotations

import base64
import binascii
import os
import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Self

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict, Field

from domain.exceptions import (
    KeyExpiredError,
    PipelineConfigurationError,
    VaultError,
    VaultIntegrityError,
)
from domain.models import DataClass, KeyStatus

_KEY_LENGTH_BYTES = 32
_NONCE_LENGTH_BYTES = 12
_DEFAULT_DEK_TTL = timedelta(hours=24)
_DEFAULT_KEK_MAX_AGE = timedelta(days=90)
_USABLE_STATUSES = frozenset({KeyStatus.ACTIVE, KeyStatus.DEPRECATED})
_TERMINAL_STATUSES = frozenset({KeyStatus.EXPIRED, KeyStatus.REVOKED})
_ALLOWED_TRANSITIONS: dict[KeyStatus, frozenset[KeyStatus]] = {
    KeyStatus.ACTIVE: frozenset({KeyStatus.DEPRECATED, *_TERMINAL_STATUSES}),
    KeyStatus.DEPRECATED: _TERMINAL_STATUSES,
    KeyStatus.EXPIRED: frozenset(),
    KeyStatus.REVOKED: frozenset(),
}

type Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


class _KeyKind(StrEnum):
    KEK = "KEK"
    DEK = "DEK"


class _KeyEntry(BaseModel):
    """Wrapped key material; `wrapped_key` is None once the key is crypto-shredded."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    key_id: str
    kind: _KeyKind
    data_class: DataClass
    parent_id: str
    session_id: str | None = None
    version: int = Field(default=1, ge=1)
    wrapped_key: bytes | None = Field(default=None, repr=False)
    nonce: bytes = Field(repr=False)
    status: KeyStatus = KeyStatus.ACTIVE
    created_at: datetime

    def aad(self) -> bytes:
        return f"{self.kind}|{self.key_id}|{self.data_class}|{self.parent_id}".encode()


class InMemoryKMS:
    """In-process KMS simulating MK -> KEK (per DataClass) -> DEK (per session) (§6.3).

    Only DEK material leaves the KMS; the MK and KEKs are used exclusively for key wrapping.
    """

    _MASTER_KEY_ID = "mk"

    def __init__(
        self,
        master_key: bytes,
        *,
        dek_ttl: timedelta = _DEFAULT_DEK_TTL,
        clock: Clock = _utc_now,
    ) -> None:
        if len(master_key) != _KEY_LENGTH_BYTES:
            raise PipelineConfigurationError("KMS master key must be exactly 256 bits.")
        self._master = AESGCM(master_key)
        self._dek_ttl = dek_ttl
        self._clock = clock
        self._entries: dict[str, _KeyEntry] = {}
        self._lock = threading.RLock()

    @classmethod
    def from_environment(
        cls,
        env_var: str = "PIPELINE_KMS_MASTER_KEY",
        *,
        dek_ttl: timedelta = _DEFAULT_DEK_TTL,
        clock: Clock = _utc_now,
    ) -> Self:
        """Load a base64-encoded 256-bit master key from `env_var`."""
        encoded = os.environ.get(env_var)
        if not encoded:
            raise PipelineConfigurationError(f"KMS master key variable {env_var!r} is not set.")
        try:
            master_key = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise PipelineConfigurationError(
                f"KMS master key variable {env_var!r} is not valid base64."
            ) from None
        return cls(master_key, dek_ttl=dek_ttl, clock=clock)

    def active_key_id(self, data_class: DataClass, session_id: str | None = None) -> str:
        with self._lock:
            kek = self._active_kek(data_class)
            now = self._clock()
            for entry in list(self._entries.values()):
                if (
                    entry.kind is _KeyKind.DEK
                    and entry.status is KeyStatus.ACTIVE
                    and entry.data_class is data_class
                    and entry.session_id == session_id
                ):
                    if entry.parent_id == kek.key_id and now - entry.created_at < self._dek_ttl:
                        return entry.key_id
                    self._replace_status(entry, KeyStatus.DEPRECATED)
            return self._issue_dek(kek, session_id).key_id

    def get_key(self, key_id: str) -> bytes:
        with self._lock:
            dek = self._entries.get(key_id)
            if dek is None or dek.kind is not _KeyKind.DEK:
                raise KeyExpiredError("Requested key is not available for decryption.")
            kek = self._entries[dek.parent_id]
            if (
                dek.status not in _USABLE_STATUSES
                or kek.status not in _USABLE_STATUSES
                or dek.wrapped_key is None
            ):
                raise KeyExpiredError(f"Key {key_id!r} is {dek.status.value} and cannot be used.")
            kek_material = self._unwrap(self._master, kek)
            return self._unwrap(AESGCM(kek_material), dek)

    def key_status(self, key_id: str) -> KeyStatus:
        with self._lock:
            entry = self._entries.get(key_id)
            if entry is None:
                raise VaultError(f"Unknown key_id {key_id!r}.")
            return entry.status

    def rotate(self, data_class: DataClass) -> str:
        with self._lock:
            previous = self._active_kek(data_class)
            self._replace_status(previous, KeyStatus.DEPRECATED)
            for entry in list(self._entries.values()):
                if entry.parent_id == previous.key_id and entry.status is KeyStatus.ACTIVE:
                    self._replace_status(entry, KeyStatus.DEPRECATED)
            return self._issue_kek(data_class, previous.version + 1).key_id

    def set_key_status(self, key_id: str, status: KeyStatus) -> None:
        with self._lock:
            entry = self._entries.get(key_id)
            if entry is None:
                raise VaultError(f"Unknown key_id {key_id!r}.")
            if entry.status is status:
                return
            if status not in _ALLOWED_TRANSITIONS[entry.status]:
                raise VaultError(
                    f"Illegal key status transition {entry.status.value} -> {status.value}."
                )
            self._replace_status(entry, status)
            if entry.kind is _KeyKind.KEK and status in _TERMINAL_STATUSES:
                for child in list(self._entries.values()):
                    if child.parent_id == key_id and child.status not in _TERMINAL_STATUSES:
                        self._replace_status(child, status)

    def active_kek_created_at(self, data_class: DataClass) -> datetime | None:
        """Return the creation time of the ACTIVE KEK for `data_class`, if one exists."""
        with self._lock:
            kek = self._find_active_kek(data_class)
            return kek.created_at if kek is not None else None

    def _find_active_kek(self, data_class: DataClass) -> _KeyEntry | None:
        for entry in self._entries.values():
            if (
                entry.kind is _KeyKind.KEK
                and entry.data_class is data_class
                and entry.status is KeyStatus.ACTIVE
            ):
                return entry
        return None

    def _active_kek(self, data_class: DataClass) -> _KeyEntry:
        kek = self._find_active_kek(data_class)
        if kek is not None:
            return kek
        versions = [
            e.version
            for e in self._entries.values()
            if e.kind is _KeyKind.KEK and e.data_class is data_class
        ]
        return self._issue_kek(data_class, max(versions, default=0) + 1)

    def _issue_kek(self, data_class: DataClass, version: int) -> _KeyEntry:
        entry = _KeyEntry(
            key_id=f"kek_{data_class.value.lower()}_v{version}",
            kind=_KeyKind.KEK,
            data_class=data_class,
            parent_id=self._MASTER_KEY_ID,
            version=version,
            nonce=os.urandom(_NONCE_LENGTH_BYTES),
            created_at=self._clock(),
        )
        return self._store_wrapped(entry, self._master)

    def _issue_dek(self, kek: _KeyEntry, session_id: str | None) -> _KeyEntry:
        entry = _KeyEntry(
            key_id=f"dek_{uuid.uuid4().hex}",
            kind=_KeyKind.DEK,
            data_class=kek.data_class,
            parent_id=kek.key_id,
            session_id=session_id,
            nonce=os.urandom(_NONCE_LENGTH_BYTES),
            created_at=self._clock(),
        )
        return self._store_wrapped(entry, AESGCM(self._unwrap(self._master, kek)))

    def _store_wrapped(self, entry: _KeyEntry, wrapping_key: AESGCM) -> _KeyEntry:
        material = AESGCM.generate_key(bit_length=256)
        wrapped = wrapping_key.encrypt(entry.nonce, material, entry.aad())
        stored = entry.model_copy(update={"wrapped_key": wrapped})
        self._entries[stored.key_id] = stored
        return stored

    def _unwrap(self, wrapping_key: AESGCM, entry: _KeyEntry) -> bytes:
        if entry.wrapped_key is None:
            raise KeyExpiredError(f"Key {entry.key_id!r} has been destroyed.")
        try:
            return wrapping_key.decrypt(entry.nonce, entry.wrapped_key, entry.aad())
        except InvalidTag:
            raise VaultIntegrityError("Wrapped key failed integrity verification.") from None

    def _replace_status(self, entry: _KeyEntry, status: KeyStatus) -> None:
        update: dict[str, object] = {"status": status}
        if status in _TERMINAL_STATUSES:
            update["wrapped_key"] = None
        self._entries[entry.key_id] = entry.model_copy(update=update)


class KeyRotation:
    """Scheduler rotating KEKs older than `kek_max_age` (ARCHITECTURE.md §5.5, §6.3).

    `rotate` is the callable performing the rotation, normally `VaultProxy.rotate_keys`
    bound to a system principal, so scheduled rotations are authorized and audited.
    """

    def __init__(
        self,
        kms: InMemoryKMS,
        *,
        kek_max_age: timedelta = _DEFAULT_KEK_MAX_AGE,
        clock: Clock = _utc_now,
    ) -> None:
        self._kms = kms
        self._kek_max_age = kek_max_age
        self._clock = clock

    def due(self) -> tuple[DataClass, ...]:
        """Return data classes whose ACTIVE KEK exceeded `kek_max_age`."""
        now = self._clock()
        due: list[DataClass] = []
        for data_class in DataClass:
            created_at = self._kms.active_kek_created_at(data_class)
            if created_at is not None and now - created_at >= self._kek_max_age:
                due.append(data_class)
        return tuple(due)

    def run(self, rotate: Callable[[DataClass], str]) -> dict[DataClass, str]:
        """Rotate every due data class and return the new key ids."""
        return {data_class: rotate(data_class) for data_class in self.due()}
