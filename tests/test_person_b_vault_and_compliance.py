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
    RotationStrategy,
    TokenRecord,
)
from domain.protocols import KMS
from pipeline.builder import PipelineBuilder
from pipeline.context import PipelineContext
from vault.keys import InMemoryKMS, KeyRotation


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
