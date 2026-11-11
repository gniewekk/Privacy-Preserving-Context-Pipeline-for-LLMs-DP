"""Osoba B: Token Vault, KMS, immutable audit, and residency contracts."""

from __future__ import annotations

import base64
import os
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import ValidationError

from detectors.regex import RegexPIIDetector
from domain.exceptions import (
    KeyExpiredError,
    PipelineConfigurationError,
    TokenExpiredError,
    VaultError,
    VaultIntegrityError,
)
from domain.models import (
    AnonymizationRequest,
    AnonymizationResult,
    AuditAction,
    AuditEvent,
    AuditOutcome,
    DataClass,
    DetectedEntity,
    EndpointMetadata,
    EntityType,
    KeyStatus,
    Permission,
    RotationStrategy,
    SecurityContext,
    SecurityPrincipal,
    TokenRecord,
)
from domain.protocols import KMS, TokenizationVault
from pipeline.builder import PipelineBuilder
from pipeline.context import PipelineContext
from vault.keys import InMemoryKMS, KeyRotation
from vault.vault import VaultCore

PESEL = "44051401458"
PERSON = "Jan Kowalski"


class FakeClock:
    """Controllable clock for TTL and rotation schedule tests."""

    def __init__(self) -> None:
        self.now = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def kms(clock: FakeClock) -> InMemoryKMS:
    return InMemoryKMS(AESGCM.generate_key(bit_length=256), clock=clock)


@pytest.fixture
def core(kms: InMemoryKMS, clock: FakeClock) -> VaultCore:
    return VaultCore(kms, clock=clock)


def _context(
    data_class: DataClass = DataClass.GENERAL,
    session_id: str | None = "sess_1",
    tenant_id: str = "tenant_a",
) -> SecurityContext:
    return SecurityContext(
        request_id="req_1", tenant_id=tenant_id, session_id=session_id, data_class=data_class
    )


def _principal(*permissions: Permission, tenant_id: str = "tenant_a") -> SecurityPrincipal:
    return SecurityPrincipal(
        principal_id="svc_a", tenant_id=tenant_id, permissions=frozenset(permissions)
    )


def _token_record(**overrides: object) -> TokenRecord:
    fields: dict[str, object] = {
        "token_id": "tok_abc",
        "encrypted_value": os.urandom(32),
        "nonce": os.urandom(12),
        "key_id": "key_v1",
        "entity_type": EntityType.PESEL,
        "tenant_id": "tenant_a",
        "request_id": "req_1",
        "session_id": "sess_1",
        "created_at": datetime.now(UTC),
    }
    fields.update(overrides)
    return TokenRecord.model_validate(fields)


def test_key_lifecycle_and_rotation_enums_match_architecture() -> None:
    assert set(KeyStatus) == {
        KeyStatus.ACTIVE,
        KeyStatus.DEPRECATED,
        KeyStatus.EXPIRED,
        KeyStatus.REVOKED,
    }
    assert set(RotationStrategy) == {
        RotationStrategy.RE_ENCRYPT,
        RotationStrategy.RETAIN_OLD_KEY,
        RotationStrategy.EXPIRE,
    }


def test_token_record_is_immutable_and_hides_ciphertext_in_repr() -> None:
    record = _token_record()

    with pytest.raises(ValidationError):
        record.key_id = "key_v2"  # type: ignore[misc]

    rendered = repr(record) + str(record)
    assert "encrypted_value" not in rendered
    assert "nonce" not in rendered
    assert record.encrypted_value.hex() not in rendered


@pytest.mark.parametrize("nonce_length", [0, 11, 13, 16])
def test_token_record_rejects_non_96_bit_nonce(nonce_length: int) -> None:
    with pytest.raises(ValidationError):
        _token_record(nonce=os.urandom(nonce_length))


def test_audit_event_hash_chain_fields_default_to_unset() -> None:
    event = AuditEvent(
        event_id="evt_1",
        timestamp=datetime.now(UTC),
        action=AuditAction.DETOKENIZE,
        outcome=AuditOutcome.DENIED,
        principal_id="svc_b",
        tenant_id="tenant_a",
        request_id="req_1",
    )
    assert event.session_id is None
    assert event.previous_hash is None
    assert event.event_hash is None


def test_endpoint_without_declared_dpa_is_treated_as_uncovered() -> None:
    endpoint = EndpointMetadata(provider_id="llm-us", region="us-east-1", is_eu_compliant=False)
    assert endpoint.data_processing_agreement is False


def test_anonymization_filter_propagates_session_id_to_strategies() -> None:
    seen_session_ids: list[str | None] = []

    class SessionSpyStrategy:
        @property
        def strategy_id(self) -> str:
            return "session_spy"

        def can_reverse(self) -> bool:
            return False

        def anonymize(
            self, entity: DetectedEntity, context: AnonymizationRequest
        ) -> AnonymizationResult:
            assert context.context is not None
            seen_session_ids.append(context.context.session_id)
            return AnonymizationResult(
                replacement_text=f"<{entity.entity_type.value}>",
                entity_type=entity.entity_type,
                is_reversible=False,
            )

    pipeline = (
        PipelineBuilder()
        .with_detector(RegexPIIDetector())
        .with_anonymization_strategy(SessionSpyStrategy())
        .build()
    )
    pipeline.execute(
        PipelineContext(request_id="req_1", session_id="sess_42", raw_text="PESEL 44051401458")
    )

    assert seen_session_ids == ["sess_42"]


# --- KMS (MK -> KEK -> DEK) -------------------------------------------------------------


def test_kms_satisfies_protocol_and_issues_256_bit_deks(kms: InMemoryKMS) -> None:
    assert isinstance(kms, KMS)
    key_id = kms.active_key_id(DataClass.MEDICAL, "sess_1")

    key = kms.get_key(key_id)

    assert len(key) == 32
    assert kms.key_status(key_id) is KeyStatus.ACTIVE
    assert kms.get_key(key_id) == key


@pytest.mark.parametrize("length", [0, 16, 24, 31, 33])
def test_kms_rejects_master_key_that_is_not_256_bit(length: int) -> None:
    with pytest.raises(PipelineConfigurationError, match="256 bits"):
        InMemoryKMS(os.urandom(length))


def test_kms_loads_master_key_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    master_key = AESGCM.generate_key(bit_length=256)
    monkeypatch.setenv("PIPELINE_KMS_MASTER_KEY", base64.b64encode(master_key).decode())

    kms = InMemoryKMS.from_environment()

    assert len(kms.get_key(kms.active_key_id(DataClass.GENERAL))) == 32


def test_kms_environment_errors_never_echo_key_material(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PIPELINE_KMS_MASTER_KEY", raising=False)
    with pytest.raises(PipelineConfigurationError, match="not set"):
        InMemoryKMS.from_environment()

    monkeypatch.setenv("PIPELINE_KMS_MASTER_KEY", "not-base64-secret!!")
    with pytest.raises(PipelineConfigurationError) as exc_info:
        InMemoryKMS.from_environment()
    assert "not-base64-secret" not in str(exc_info.value)


def test_kms_isolates_deks_per_session_and_data_class(kms: InMemoryKMS) -> None:
    medical_a = kms.active_key_id(DataClass.MEDICAL, "sess_a")
    medical_b = kms.active_key_id(DataClass.MEDICAL, "sess_b")
    financial_a = kms.active_key_id(DataClass.FINANCIAL, "sess_a")

    assert medical_a == kms.active_key_id(DataClass.MEDICAL, "sess_a")
    assert len({medical_a, medical_b, financial_a}) == 3
    assert kms.get_key(medical_a) != kms.get_key(medical_b)


def test_kms_never_releases_kek_material(kms: InMemoryKMS) -> None:
    kms.active_key_id(DataClass.MEDICAL, "sess_1")

    with pytest.raises(KeyExpiredError):
        kms.get_key("kek_medical_v1")
    with pytest.raises(KeyExpiredError):
        kms.get_key("dek_does_not_exist")


def test_kms_rotates_dek_after_ttl_and_keeps_old_dek_readable(
    kms: InMemoryKMS, clock: FakeClock
) -> None:
    first = kms.active_key_id(DataClass.GENERAL, "sess_1")
    first_key = kms.get_key(first)

    clock.advance(timedelta(hours=24))
    second = kms.active_key_id(DataClass.GENERAL, "sess_1")

    assert second != first
    assert kms.key_status(first) is KeyStatus.DEPRECATED
    assert kms.get_key(first) == first_key


def test_kek_rotation_deprecates_previous_generation(kms: InMemoryKMS) -> None:
    old_dek = kms.active_key_id(DataClass.MEDICAL, "sess_1")
    old_key = kms.get_key(old_dek)

    new_kek = kms.rotate(DataClass.MEDICAL)

    assert new_kek == "kek_medical_v2"
    assert kms.key_status("kek_medical_v1") is KeyStatus.DEPRECATED
    assert kms.key_status(old_dek) is KeyStatus.DEPRECATED
    assert kms.get_key(old_dek) == old_key
    new_dek = kms.active_key_id(DataClass.MEDICAL, "sess_1")
    assert new_dek != old_dek
    assert kms.key_status(new_kek) is KeyStatus.ACTIVE


@pytest.mark.parametrize("terminal", [KeyStatus.EXPIRED, KeyStatus.REVOKED])
def test_terminal_dek_status_crypto_shreds_key(kms: InMemoryKMS, terminal: KeyStatus) -> None:
    dek = kms.active_key_id(DataClass.GENERAL, "sess_1")

    kms.set_key_status(dek, terminal)

    with pytest.raises(KeyExpiredError):
        kms.get_key(dek)
    assert kms.active_key_id(DataClass.GENERAL, "sess_1") != dek


def test_revoking_kek_cascades_to_all_its_deks(kms: InMemoryKMS) -> None:
    deks = [kms.active_key_id(DataClass.MEDICAL, f"sess_{i}") for i in range(3)]

    kms.set_key_status("kek_medical_v1", KeyStatus.REVOKED)

    for dek in deks:
        assert kms.key_status(dek) is KeyStatus.REVOKED
        with pytest.raises(KeyExpiredError):
            kms.get_key(dek)
    assert kms.active_key_id(DataClass.MEDICAL, "sess_0") not in deks


def test_key_status_transitions_are_one_way_and_idempotent(kms: InMemoryKMS) -> None:
    dek = kms.active_key_id(DataClass.GENERAL)
    kms.set_key_status(dek, KeyStatus.EXPIRED)
    kms.set_key_status(dek, KeyStatus.EXPIRED)

    for forbidden in (KeyStatus.ACTIVE, KeyStatus.DEPRECATED, KeyStatus.REVOKED):
        with pytest.raises(VaultError, match="Illegal key status transition"):
            kms.set_key_status(dek, forbidden)
    with pytest.raises(VaultError, match="Unknown key_id"):
        kms.set_key_status("dek_missing", KeyStatus.REVOKED)


def test_tampered_wrapped_dek_fails_integrity_check(kms: InMemoryKMS) -> None:
    dek = kms.active_key_id(DataClass.GENERAL)
    entry = kms._entries[dek]
    assert entry.wrapped_key is not None
    tampered = bytes([entry.wrapped_key[0] ^ 0x01]) + entry.wrapped_key[1:]
    kms._entries[dek] = entry.model_copy(update={"wrapped_key": tampered})

    with pytest.raises(VaultIntegrityError) as exc_info:
        kms.get_key(dek)
    assert "InvalidTag" not in str(exc_info.value)


def test_kms_repr_and_errors_never_expose_key_bytes(kms: InMemoryKMS) -> None:
    dek = kms.active_key_id(DataClass.GENERAL)
    key = kms.get_key(dek)
    entry = kms._entries[dek]
    assert entry.wrapped_key is not None

    rendered = repr(entry) + str(entry)
    for secret in (key, entry.wrapped_key):
        assert secret.hex() not in rendered

    kms.set_key_status(dek, KeyStatus.REVOKED)
    with pytest.raises(KeyExpiredError) as exc_info:
        kms.get_key(dek)
    assert key.hex() not in str(exc_info.value)


def test_key_rotation_schedule_rotates_keks_older_than_90_days(
    kms: InMemoryKMS, clock: FakeClock
) -> None:
    kms.active_key_id(DataClass.MEDICAL)
    clock.advance(timedelta(days=60))
    kms.active_key_id(DataClass.FINANCIAL)
    scheduler = KeyRotation(kms, clock=clock)

    assert scheduler.due() == ()

    clock.advance(timedelta(days=30))
    rotated = scheduler.run(kms.rotate)

    assert rotated == {DataClass.MEDICAL: "kek_medical_v2"}
    assert scheduler.due() == ()


# --- VaultCore (AES-256-GCM token storage) ----------------------------------------------


def test_vault_core_round_trips_value_and_binds_record_metadata(core: VaultCore) -> None:
    assert isinstance(core, TokenizationVault)
    ctx = _context(DataClass.MEDICAL)

    record = core.tokenize(PESEL, EntityType.PESEL, ctx)

    assert record.token_id.startswith("tok_")
    assert record.entity_type is EntityType.PESEL
    assert (record.tenant_id, record.request_id, record.session_id) == (
        "tenant_a",
        "req_1",
        "sess_1",
    )
    assert record.expires_at == record.created_at + timedelta(hours=24)
    assert PESEL.encode() not in record.encrypted_value
    assert core.de_tokenize(record.token_id, _principal(Permission.DETOKENIZE), ctx) == PESEL


def test_vault_core_uses_fresh_nonce_and_token_id_per_encryption(core: VaultCore) -> None:
    records = [core.tokenize(PERSON, EntityType.PERSON, _context()) for _ in range(1000)]

    assert len({r.nonce for r in records}) == 1000
    assert len({r.token_id for r in records}) == 1000
    assert len({r.encrypted_value for r in records}) == 1000


def test_vault_core_rejects_token_past_ttl(core: VaultCore, clock: FakeClock) -> None:
    record = core.tokenize(PESEL, EntityType.PESEL, _context())
    clock.advance(timedelta(hours=24))

    with pytest.raises(TokenExpiredError) as exc_info:
        core.de_tokenize(record.token_id, _principal(Permission.DETOKENIZE), _context())
    assert PESEL not in str(exc_info.value)


def test_vault_core_rejects_unknown_token(core: VaultCore) -> None:
    with pytest.raises(VaultError, match="not available"):
        core.de_tokenize("tok_missing", _principal(Permission.DETOKENIZE), _context())


@pytest.mark.parametrize(
    "field",
    ["encrypted_value", "nonce", "tenant_id", "request_id", "entity_type", "expires_at"],
)
def test_vault_core_detects_tampered_record(core: VaultCore, field: str) -> None:
    record = core.tokenize(PESEL, EntityType.PESEL, _context())
    tampered_values: dict[str, object] = {
        "encrypted_value": bytes([record.encrypted_value[0] ^ 0x01]) + record.encrypted_value[1:],
        "nonce": os.urandom(12),
        "tenant_id": "tenant_b",
        "request_id": "req_other",
        "entity_type": EntityType.NIP,
        "expires_at": record.created_at + timedelta(days=365),
    }
    core._records[record.token_id] = record.model_copy(update={field: tampered_values[field]})

    with pytest.raises(VaultIntegrityError) as exc_info:
        core.de_tokenize(record.token_id, _principal(Permission.DETOKENIZE), _context())
    message = str(exc_info.value)
    assert PESEL not in message
    assert "InvalidTag" not in message


def test_vault_core_detects_ciphertext_swapped_between_records(core: VaultCore) -> None:
    first = core.tokenize(PESEL, EntityType.PESEL, _context())
    second = core.tokenize("90010112345", EntityType.PESEL, _context())
    core._records[first.token_id] = first.model_copy(
        update={"encrypted_value": second.encrypted_value, "nonce": second.nonce}
    )

    with pytest.raises(VaultIntegrityError):
        core.de_tokenize(first.token_id, _principal(Permission.DETOKENIZE), _context())


def test_rotation_re_encrypt_moves_tokens_to_new_key_and_shreds_old_one(
    core: VaultCore, kms: InMemoryKMS
) -> None:
    ctx = _context(DataClass.MEDICAL)
    before = core.tokenize(PESEL, EntityType.PESEL, ctx)

    new_kek = core.rotate_keys(_principal(Permission.ROTATE_KEYS), ctx, RotationStrategy.RE_ENCRYPT)

    after = core.find_record(before.token_id)
    assert after is not None
    assert new_kek == "kek_medical_v2"
    assert after.key_id != before.key_id
    assert after.nonce != before.nonce
    assert kms.key_status(before.key_id) is KeyStatus.EXPIRED
    assert core.de_tokenize(before.token_id, _principal(Permission.DETOKENIZE), ctx) == PESEL


def test_rotation_retain_old_key_keeps_tokens_readable_until_ttl(
    core: VaultCore, kms: InMemoryKMS, clock: FakeClock
) -> None:
    ctx = _context(DataClass.FINANCIAL)
    record = core.tokenize(PESEL, EntityType.PESEL, ctx)

    core.rotate_keys(_principal(Permission.ROTATE_KEYS), ctx, RotationStrategy.RETAIN_OLD_KEY)

    assert core.find_record(record.token_id) == record
    assert kms.key_status(record.key_id) is KeyStatus.DEPRECATED
    assert core.de_tokenize(record.token_id, _principal(Permission.DETOKENIZE), ctx) == PESEL
    assert core.tokenize(PERSON, EntityType.PERSON, ctx).key_id != record.key_id

    clock.advance(timedelta(hours=24))
    with pytest.raises(TokenExpiredError):
        core.de_tokenize(record.token_id, _principal(Permission.DETOKENIZE), ctx)


def test_rotation_expire_makes_old_tokens_unrecoverable(
    core: VaultCore, kms: InMemoryKMS
) -> None:
    ctx = _context(DataClass.GENERAL)
    record = core.tokenize(PESEL, EntityType.PESEL, ctx)

    core.rotate_keys(_principal(Permission.ROTATE_KEYS), ctx, RotationStrategy.EXPIRE)

    assert kms.key_status(record.key_id) is KeyStatus.EXPIRED
    with pytest.raises(KeyExpiredError):
        core.de_tokenize(record.token_id, _principal(Permission.DETOKENIZE), ctx)


def test_rotation_only_affects_requested_data_class(core: VaultCore, kms: InMemoryKMS) -> None:
    medical = core.tokenize(PESEL, EntityType.PESEL, _context(DataClass.MEDICAL))
    general = core.tokenize(PERSON, EntityType.PERSON, _context(DataClass.GENERAL))

    core.rotate_keys(
        _principal(Permission.ROTATE_KEYS), _context(DataClass.MEDICAL), RotationStrategy.EXPIRE
    )

    assert kms.key_status(medical.key_id) is KeyStatus.EXPIRED
    assert kms.key_status(general.key_id) is KeyStatus.ACTIVE
    assert core.find_record(general.token_id) == general


def test_re_encrypt_skips_tokens_whose_key_was_already_revoked(
    core: VaultCore, kms: InMemoryKMS
) -> None:
    ctx = _context(DataClass.MEDICAL)
    lost = core.tokenize(PESEL, EntityType.PESEL, ctx)
    kms.set_key_status(lost.key_id, KeyStatus.REVOKED)
    survivor = core.tokenize(PERSON, EntityType.PERSON, ctx)

    core.rotate_keys(_principal(Permission.ROTATE_KEYS), ctx, RotationStrategy.RE_ENCRYPT)

    assert core.de_tokenize(survivor.token_id, _principal(Permission.DETOKENIZE), ctx) == PERSON
    with pytest.raises(KeyExpiredError):
        core.de_tokenize(lost.token_id, _principal(Permission.DETOKENIZE), ctx)


def test_expire_deletes_token_idempotently(core: VaultCore) -> None:
    record = core.tokenize(PESEL, EntityType.PESEL, _context())

    assert core.expire(record.token_id) is True
    assert core.expire(record.token_id) is False
    assert core.find_record(record.token_id) is None


def test_vault_core_never_leaks_plaintext_to_logs_or_repr(
    core: VaultCore, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("DEBUG")
    ctx = _context(DataClass.MEDICAL)
    record = core.tokenize(PESEL, EntityType.PESEL, ctx)
    core.de_tokenize(record.token_id, _principal(Permission.DETOKENIZE), ctx)
    core.rotate_keys(_principal(Permission.ROTATE_KEYS), ctx)

    assert PESEL not in caplog.text
    assert PESEL not in repr(record) + str(record)
