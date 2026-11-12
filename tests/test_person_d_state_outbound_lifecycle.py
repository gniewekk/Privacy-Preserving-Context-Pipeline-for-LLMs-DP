"""Comprehensive unit, integration, PoC, and security abuse tests for Osoba D's scope.

Covers:
1. `PipelineMemento` & `ResponseRestorer` (ADR-005): opaque state, SHA-256 checksum integrity,
   crash recovery after LLM timeout (`restore_from_memento`), and TTL eviction.
2. Outbound Pipeline (`OutputPIIDetector` -> `ResponseRestorer`) & `StreamingResponseRestorer`
   (ADR-006): SSE `<...>` 64-byte window buffering across chunk boundaries, literal `<` flush,
   hallucinated/leaked PII blocking & redaction.
3. Polish morphological inflection & `SynthesisStrategy` (PoC 1): `<PERSON_1>em` / `<PERSON_1>a`
   case inflection, malformed placeholder recovery, and reversible synthetic data mapping.
4. `ToolExecutionMiddleware` & Dynamic Memento Expansion (Scenario 5.6, ADR-007, PoC 2):
   bi-directional agentic `ToolCall` sanitization (`<PERSON_1>` + `<DATE_1>`).
5. `RetentionPolicyEngine`, `RetentionWorker` & GDPR Art. 17 Right to Erasure (Scenario 5.5,
   PoC 3): TTL purge, session crypto-shredding (`EXPIRE`), and hash-chained PII-free audit logs.
6. Mandatory negative/abuse tests: unauthorized detokenization, cross-tenant/session isolation,
   tampered Memento checksum, expired tokens/keys, and zero raw PII leakage assertions.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from detectors import (
    HeuristicPIIDetector,
    PIIDetector,
    PolishTransformerNERDetector,
    RegexPIIDetector,
)
from dispatchers import LLMDispatcher, ToolExecutionMiddleware
from domain import (
    AuditAction,
    AuditEvent,
    AuditOutcome,
    DataClass,
    DetectedEntity,
    EndpointMetadata,
    EntityType,
    HardStopError,
    KeyExpiredError,
    KeyStatus,
    Permission,
    RotationStrategy,
    SecurityContext,
    SecurityPrincipal,
    TokenExpiredError,
    ToolCall,
    UnauthorizedVaultAccessError,
    VaultIntegrityError,
)
from pipeline import (
    MAX_PLACEHOLDER_LENGTH,
    OutputPIIDetector,
    Pipeline,
    PipelineBuilder,
    PipelineContext,
    PipelineProxy,
    StreamingResponseRestorer,
)
from state import (
    EntityMetadata,
    PipelineMemento,
    ResponseRestorer,
    RetentionPolicyEngine,
    RetentionWorker,
)
from strategies import (
    StrategySelector,
    SynthesisStrategy,
    TokenizationStrategy,
)
from vault.keys import InMemoryKMS
from vault.vault import VaultCore

RAW_PERSON = "Jan Kowalski"
RAW_PESEL = "44051401458"
RAW_BIRTH_DATE = "1990-01-01"
LEAKED_PESEL = "90010112349"


class ControllableClock:
    """Deterministic clock for TTL, Memento expiration, and RetentionWorker tests."""

    def __init__(self) -> None:
        self.now = datetime(2026, 11, 12, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


class InMemoryAuditLog:
    """In-memory AuditWriter recording events for verification."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self._events.append(event)

    def events(self) -> Sequence[AuditEvent]:
        return tuple(self._events)


def _fake_polish_ner(text: str) -> Sequence[Mapping[str, Any]]:
    """Deterministic Polish NER test double for person, organization, and location spans."""
    results: list[dict[str, Any]] = []
    catalog = (
        ("Jan Kowalski", "persName", 0.992),
        ("Anna Nowak", "persName", 0.991),
        ("Piotr Wiśniewski", "persName", 0.988),
        ("Warszawa", "placeName", 0.990),
        ("Krakowie", "nam_loc_gpe_city", 0.985),
    )
    for surface, label, score in catalog:
        idx = text.find(surface)
        if idx != -1:
            results.append(
                {
                    "entity_group": label,
                    "score": score,
                    "word": surface,
                    "start": idx,
                    "end": idx + len(surface),
                }
            )
    return results


class DateRegexDetector(PIIDetector):
    """Deterministic ISO-8601 date (`YYYY-MM-DD`) detector for Scenario 5.6 tool output."""

    @property
    def detector_id(self) -> str:
        return "iso_date_detector"

    def detect(self, text: str, language: str = "en") -> Sequence[DetectedEntity]:
        import re

        matches: list[DetectedEntity] = []
        for m in re.finditer(r"\b\d{4}-\d{2}-\d{2}\b", text):
            matches.append(
                DetectedEntity(
                    entity_type=EntityType.DATE,
                    start=m.start(),
                    end=m.end(),
                    raw_value=m.group(0),
                    confidence=1.0,
                    detector_id=self.detector_id,
                )
            )
        return tuple(matches)


@pytest.fixture
def clock() -> ControllableClock:
    return ControllableClock()


@pytest.fixture
def kms(clock: ControllableClock) -> InMemoryKMS:
    return InMemoryKMS(AESGCM.generate_key(bit_length=256), clock=clock)


@pytest.fixture
def vault_core(kms: InMemoryKMS, clock: ControllableClock) -> VaultCore:
    return VaultCore(kms, clock=clock)


@pytest.fixture
def audit_log() -> InMemoryAuditLog:
    return InMemoryAuditLog()


@pytest.fixture
def authorized_principal() -> SecurityPrincipal:
    return SecurityPrincipal(
        principal_id="crm-service-v2",
        tenant_id="tenant_a",
        roles=frozenset({"CASE_WORKER"}),
        permissions=frozenset({Permission.TOKENIZE, Permission.DETOKENIZE}),
    )


# --- 1. Memento Lifecycle, Integrity Checksum & Crash Recovery (ADR-005) ----------------


def test_memento_creation_encapsulation_and_tamper_detection(
    vault_core: VaultCore,
    clock: ControllableClock,
    authorized_principal: SecurityPrincipal,
) -> None:
    """Verify PipelineMemento stores zero raw PII and detects any checksum tampering."""
    restorer = ResponseRestorer(vault_core, clock=clock)
    detectors: list[PIIDetector] = [
        RegexPIIDetector(),
        PolishTransformerNERDetector(ner_pipeline=_fake_polish_ner),
    ]
    pipeline = (
        PipelineBuilder()
        .with_detectors(detectors)
        .with_anonymization_strategy(TokenizationStrategy(reversible=True, vault=vault_core))
        .with_vault_proxy(vault_core)
        .with_response_restorer(restorer)
        .build()
    )
    proxy = PipelineProxy(pipeline, response_restorer=restorer)

    ctx = proxy.process_text(
        f"{RAW_PERSON}, PESEL {RAW_PESEL}, skarży się na fakturę 7/2026",
        request_id="req_memento_1",
        session_id="sess_memento_1",
        tenant_id="tenant_a",
        principal=authorized_principal,
    )

    memento = restorer.get("req_memento_1")
    assert memento is not None
    assert memento.version == 1
    assert memento.session_id == "sess_memento_1"
    assert "<PERSON_1>" in memento.token_map
    assert "<PESEL_1>" in memento.token_map

    # Verify zero raw PII in repr, str, or JSON dump of Memento
    serialized = repr(memento) + str(memento) + str(memento.model_dump())
    assert RAW_PERSON not in serialized
    assert RAW_PESEL not in serialized

    # Verify crash recovery (LLM timeout -> retry from Memento without re-anonymizing)
    recovered_ctx = PipelineContext.restore_from_memento(
        memento, principal=authorized_principal
    )
    assert recovered_ctx.sanitized_text == ctx.sanitized_text
    assert recovered_ctx.placeholder_map == ctx.placeholder_map
    assert "<PERSON_1>" in recovered_ctx.sanitized_text
    assert "<PESEL_1>" in recovered_ctx.sanitized_text

    # Tamper with Memento version or token_map -> must fail closed with VaultIntegrityError
    tampered = memento.model_copy(update={"version": 99})
    with pytest.raises(VaultIntegrityError, match="integrity check failed"):
        tampered.verify_integrity()
    with pytest.raises(VaultIntegrityError):
        restorer.restore_response(
            "Sprawa <PERSON_1>",
            tampered,
            principal=authorized_principal,
        )


# --- 2. Outbound Pipeline, OutputPIIDetector & Streaming SSE (ADR-006) ------------------


def test_outbound_pipeline_happy_path_and_output_pii_detector_blocking(
    vault_core: VaultCore,
    clock: ControllableClock,
    audit_log: InMemoryAuditLog,
    authorized_principal: SecurityPrincipal,
) -> None:
    """Verify Scenario 5.1 Outbound flow and OutputPIIDetector blocking leaked LLM PII."""
    restorer = ResponseRestorer(vault_core, audit_writer=audit_log, clock=clock)
    detectors: list[PIIDetector] = [
        RegexPIIDetector(),
        PolishTransformerNERDetector(ner_pipeline=_fake_polish_ner),
        HeuristicPIIDetector(),
    ]
    output_detector = OutputPIIDetector(
        detectors=detectors,
        redact_on_leak=False,
        audit_writer=audit_log,
        response_restorer=restorer,
    )
    inbound_pipeline = (
        PipelineBuilder()
        .with_detectors(detectors)
        .with_anonymization_strategy(TokenizationStrategy(reversible=True, vault=vault_core))
        .with_vault_proxy(vault_core)
        .with_response_restorer(restorer)
        .with_audit_writer(audit_log)
        .build()
    )
    proxy = PipelineProxy(
        inbound_pipeline,
        response_restorer=restorer,
        output_pii_detector=output_detector,
    )

    proxy.process_text(
        f"{RAW_PERSON}, PESEL {RAW_PESEL}, skarży się na fakturę 7/2026",
        request_id="req_out_1",
        session_id="sess_out_1",
        tenant_id="tenant_a",
        principal=authorized_principal,
    )

    # 1. Clean LLM response containing only placeholders -> restored accurately
    llm_reply = "Sprawa <PERSON_1> (PESEL <PESEL_1>) dotyczy faktury 7/2026."
    restored_reply = proxy.restore_response(
        llm_reply,
        "req_out_1",
        principal=authorized_principal,
        language="pl",
    )
    assert restored_reply == f"Sprawa {RAW_PERSON} (PESEL {RAW_PESEL}) dotyczy faktury 7/2026."

    # 2. Outbound Pipeline composed as a Pipe (`OutputPIIDetector` -> `ResponseRestorer`)
    outbound_pipe = Pipeline([output_detector, restorer])
    out_ctx = outbound_pipe.execute(
        PipelineContext(
            request_id="req_out_1",
            session_id="sess_out_1",
            tenant_id="tenant_a",
            raw_text=llm_reply,
            language="pl",
            principal=authorized_principal,
        )
    )
    assert out_ctx.sanitized_text == (
        f"Sprawa {RAW_PERSON} (PESEL {RAW_PESEL}) dotyczy faktury 7/2026."
    )
    assert [f.filter_name for f in out_ctx.applied_filters] == [
        "OutputPIIDetector",
        "ResponseRestorer",
    ]

    # 3. LLM leaks/hallucinates a new PESEL in its response -> blocked before de-tokenization!
    leaked_llm_reply = (
        f"Sprawa <PERSON_1> przypomina przypadek pacjenta o PESEL {LEAKED_PESEL}."
    )
    with pytest.raises(HardStopError, match="OutputPIIDetector blocked") as exc_info:
        proxy.restore_response(
            leaked_llm_reply,
            "req_out_1",
            principal=authorized_principal,
            language="pl",
        )
    assert LEAKED_PESEL not in str(exc_info.value)
    assert RAW_PERSON not in str(exc_info.value)
    assert audit_log.events()[-1].action is AuditAction.OUTPUT_PII_SCAN
    assert audit_log.events()[-1].outcome is AuditOutcome.BLOCKED

    # 4. Redaction mode on OutputPIIDetector redacts leaked PII while restoring valid tokens
    redacting_detector = OutputPIIDetector(
        detectors=detectors,
        redact_on_leak=True,
        audit_writer=audit_log,
        response_restorer=restorer,
    )
    redacting_proxy = PipelineProxy(
        inbound_pipeline,
        response_restorer=restorer,
        output_pii_detector=redacting_detector,
    )
    redacted_and_restored = redacting_proxy.restore_response(
        leaked_llm_reply,
        "req_out_1",
        principal=authorized_principal,
        language="pl",
    )
    assert RAW_PERSON in redacted_and_restored
    assert LEAKED_PESEL not in redacted_and_restored
    assert "[REDACTED_PESEL]" in redacted_and_restored


def test_streaming_response_restorer_placeholder_window_buffering(
    vault_core: VaultCore,
    clock: ControllableClock,
    authorized_principal: SecurityPrincipal,
) -> None:
    """Verify ADR-006: SSE chunks splitting `<PERSON_1>` and `<PESEL_1>` are atomically restored."""
    assert MAX_PLACEHOLDER_LENGTH == 64
    restorer = ResponseRestorer(vault_core, clock=clock)
    detectors: list[PIIDetector] = [
        RegexPIIDetector(),
        PolishTransformerNERDetector(ner_pipeline=_fake_polish_ner),
    ]
    output_detector = OutputPIIDetector(detectors=detectors, response_restorer=restorer)
    pipeline = (
        PipelineBuilder()
        .with_detectors(detectors)
        .with_anonymization_strategy(TokenizationStrategy(reversible=True, vault=vault_core))
        .with_vault_proxy(vault_core)
        .with_response_restorer(restorer)
        .build()
    )
    proxy = PipelineProxy(
        pipeline,
        response_restorer=restorer,
        output_pii_detector=output_detector,
    )

    proxy.process_text(
        f"{RAW_PERSON}, PESEL {RAW_PESEL}",
        request_id="req_stream_1",
        session_id="sess_stream_1",
        tenant_id="tenant_a",
        principal=authorized_principal,
    )

    # SSE chunks splitting `<PERSON_1>` across 3 chunks and containing literal `<` comparison
    sse_chunks = [
        "Kwota < 100 PLN dla <PER",
        "SON_",
        "1> (PESEL <PESEL",
        "_1>) została zatwierdzona.",
    ]
    emitted_chunks = list(
        proxy.restore_stream(
            sse_chunks,
            "req_stream_1",
            principal=authorized_principal,
            language="pl",
        )
    )
    reassembled = "".join(emitted_chunks)
    assert reassembled == (
        f"Kwota < 100 PLN dla {RAW_PERSON} (PESEL {RAW_PESEL}) została zatwierdzona."
    )
    assert "<PERSON_1>" not in reassembled
    assert "<PESEL_1>" not in reassembled

    # Also verify async SSE streaming (`restore_stream_async`)
    async def _produce_async_chunks() -> AsyncIterator[str]:
        for c in sse_chunks:
            yield c

    async def _collect_async() -> str:
        stream_restorer = StreamingResponseRestorer(
            restorer, output_pii_detector=output_detector
        )
        parts: list[str] = []
        async for item in stream_restorer.restore_stream_async(
            _produce_async_chunks(),
            "req_stream_1",
            principal=authorized_principal,
            language="pl",
        ):
            parts.append(item)
        return "".join(parts)

    async_reassembled = asyncio.run(_collect_async())
    assert async_reassembled == reassembled


# --- 3. PoC 1: Polish Morphological Inflection vs. SynthesisStrategy --------------------


def test_poc_1_polish_inflection_with_placeholders_and_synthesis_strategy(
    vault_core: VaultCore,
    clock: ControllableClock,
    authorized_principal: SecurityPrincipal,
) -> None:
    """PoC 1: Verify Polish case inflection on `<PERSON_1>em` and SynthesisStrategy."""
    restorer = ResponseRestorer(vault_core, clock=clock)
    detectors: list[PIIDetector] = [
        RegexPIIDetector(),
        PolishTransformerNERDetector(ner_pipeline=_fake_polish_ner),
    ]

    # Part A: Placeholder tokenization where LLM attaches Polish case endings
    # (`<PERSON_1>em`, `<PERSON_1>a`) or slightly mangles brackets (`[PERSON_1]`)
    tok_pipeline = (
        PipelineBuilder()
        .with_detectors(detectors)
        .with_anonymization_strategy(TokenizationStrategy(reversible=True, vault=vault_core))
        .with_vault_proxy(vault_core)
        .with_response_restorer(restorer)
        .build()
    )
    tok_proxy = PipelineProxy(tok_pipeline, response_restorer=restorer)
    tok_proxy.process_text(
        f"Pacjent {RAW_PERSON} zgłosił się na wizytę.",
        request_id="req_poc_inflect",
        tenant_id="tenant_a",
        principal=authorized_principal,
    )

    inflected_llm_output = (
        "Rozmawiałem z <PERSON_1>em w sprawie dokumentacji <PERSON_1>a, "
        "przekazałem zalecenia <PERSON_1>owi (potwierdził [PERSON_1])."
    )
    restored_inflected = tok_proxy.restore_response(
        inflected_llm_output,
        "req_poc_inflect",
        principal=authorized_principal,
        language="pl",
    )
    assert restored_inflected == (
        "Rozmawiałem z Janem Kowalskim w sprawie dokumentacji Jana Kowalskiego, "
        "przekazałem zalecenia Janowi Kowalskiemu (potwierdził Jan Kowalski)."
    )

    # Part B: SynthesisStrategy (`Jan Kowalski` -> `Piotr Wiśniewski`, reversible via Vault)
    synth_strategy = SynthesisStrategy(vault=vault_core, reversible=True)
    assert synth_strategy.can_reverse() is True
    assert StrategySelector.get_class("synthesis") is SynthesisStrategy

    synth_pipeline = (
        PipelineBuilder()
        .with_detectors(detectors)
        .with_anonymization_strategy(synth_strategy)
        .with_vault_proxy(vault_core)
        .with_response_restorer(restorer)
        .build()
    )
    synth_proxy = PipelineProxy(synth_pipeline, response_restorer=restorer)
    synth_ctx = synth_proxy.process_text(
        f"Klient {RAW_PERSON} (PESEL {RAW_PESEL}) złożył wniosek.",
        request_id="req_poc_synth",
        tenant_id="tenant_a",
        principal=authorized_principal,
    )

    # Verify synthetic text contains realistic surrogates, no `<...>` tags, and no real PII
    assert RAW_PERSON not in synth_ctx.sanitized_text
    assert RAW_PESEL not in synth_ctx.sanitized_text
    assert "<PERSON_1>" not in synth_ctx.sanitized_text
    assert "Piotr Wiśniewski" in synth_ctx.sanitized_text
    assert "85021012355" in synth_ctx.sanitized_text

    # LLM responds using inflected synthetic Polish forms (`Piotra Wiśniewskiego`)
    synth_llm_reply = (
        "Wniosek Piotra Wiśniewskiego (PESEL 85021012355) został omówiony "
        "z Piotrem Wiśniewskim."
    )
    synth_restored = synth_proxy.restore_response(
        synth_llm_reply,
        "req_poc_synth",
        principal=authorized_principal,
        language="pl",
    )
    assert synth_restored == (
        f"Wniosek Jana Kowalskiego (PESEL {RAW_PESEL}) został omówiony "
        "z Janem Kowalskim."
    )


# --- 4. Scenario 5.6 & ADR-007: Anonymized Agentic Tool Calling & Dynamic Expansion -----


def test_scenario_5_6_agentic_tool_calling_and_dynamic_memento_expansion(
    vault_core: VaultCore,
    clock: ControllableClock,
    audit_log: InMemoryAuditLog,
    authorized_principal: SecurityPrincipal,
) -> None:
    """Verify Scenario 5.6 & ADR-007: ToolExecutionMiddleware and Dynamic Memento Expansion."""
    restorer = ResponseRestorer(vault_core, audit_writer=audit_log, clock=clock)
    detectors: list[PIIDetector] = [
        RegexPIIDetector(),
        DateRegexDetector(),
        PolishTransformerNERDetector(ner_pipeline=_fake_polish_ner),
    ]
    output_detector = OutputPIIDetector(
        detectors=detectors,
        audit_writer=audit_log,
        response_restorer=restorer,
    )
    pipeline = (
        PipelineBuilder()
        .with_detectors(detectors)
        .with_anonymization_strategy(TokenizationStrategy(reversible=True, vault=vault_core))
        .with_vault_proxy(vault_core)
        .with_response_restorer(restorer)
        .with_audit_writer(audit_log)
        .build()
    )
    proxy = PipelineProxy(
        pipeline,
        response_restorer=restorer,
        output_pii_detector=output_detector,
    )

    # Simulated internal database accessible only inside the trusted boundary
    observed_db_queries: list[str] = []

    def get_birth_date(user_id: str) -> dict[str, str]:
        observed_db_queries.append(user_id)
        assert user_id == RAW_PERSON  # DB receives resolved real name, never `<PERSON_1>`
        return {"birth_date": RAW_BIRTH_DATE}

    tool_middleware = ToolExecutionMiddleware(
        vault=vault_core,
        response_restorer=restorer,
        detectors=detectors,
        tools={"get_birth_date": get_birth_date},
        audit_writer=audit_log,
    )

    # Step 1: User asks "Kiedy urodził się Jan Kowalski?"
    inbound_ctx = proxy.process_text(
        f"Kiedy urodził się {RAW_PERSON}?",
        request_id="req_agent_1",
        session_id="sess_agent_1",
        tenant_id="tenant_a",
        principal=authorized_principal,
    )
    assert inbound_ctx.sanitized_text == "Kiedy urodził się <PERSON_1>?"
    initial_memento = restorer.get_by_session("sess_agent_1")
    assert initial_memento is not None
    assert initial_memento.version == 1
    assert set(initial_memento.token_map.keys()) == {"<PERSON_1>"}

    # Step 2: External LLM emits ToolCall referencing `<PERSON_1>`
    llm_tool_call = ToolCall(
        id="call_db_1",
        name="get_birth_date",
        arguments={"user_id": "<PERSON_1>"},
        session_id="sess_agent_1",
    )
    sanitized_tool_result = tool_middleware.intercept(
        llm_tool_call,
        principal=authorized_principal,
        language="pl",
    )

    # Verify LLM receives only tokenized tool output (`<DATE_1>`), never raw birth date
    assert observed_db_queries == [RAW_PERSON]
    assert sanitized_tool_result == {"birth_date": "<DATE_1>"}
    assert RAW_BIRTH_DATE not in str(sanitized_tool_result)

    # Verify Dynamic Memento Expansion incremented version to 2 and added `<DATE_1>`
    expanded_memento = restorer.get_by_session("sess_agent_1")
    assert expanded_memento is not None
    assert expanded_memento.version == 2
    assert set(expanded_memento.token_map.keys()) == {"<PERSON_1>", "<DATE_1>"}

    # Step 3: LLM produces final answer combining `<PERSON_1>` and `<DATE_1>`
    final_llm_answer = "<PERSON_1> urodził się <DATE_1>."
    final_user_response = proxy.restore_response(
        final_llm_answer,
        expanded_memento,
        principal=authorized_principal,
        language="pl",
    )
    assert final_user_response == f"{RAW_PERSON} urodził się {RAW_BIRTH_DATE}."


def test_llm_dispatcher_protocol_compliance() -> None:
    """Verify custom dispatcher adapters satisfy the abstract LLMDispatcher protocol (§4)."""

    class FakeEUDispatcher:
        @property
        def endpoint_metadata(self) -> EndpointMetadata:
            return EndpointMetadata(
                provider_id="eu_provider",
                region="eu-central-1",
                is_eu_compliant=True,
                data_processing_agreement=True,
            )

        def dispatch(self, sanitized_prompt: str) -> str:
            return f"Echo: {sanitized_prompt}"

    dispatcher = FakeEUDispatcher()
    assert isinstance(dispatcher, LLMDispatcher)
    assert dispatcher.endpoint_metadata.is_eu_compliant is True
    assert dispatcher.dispatch("<PERSON_1>") == "Echo: <PERSON_1>"


# --- 5. RetentionPolicyEngine, RetentionWorker & GDPR Art. 17 vs Audit Log (PoC 3) ------


def test_retention_policy_engine_and_worker_ttl_purge(
    vault_core: VaultCore,
    kms: InMemoryKMS,
    clock: ControllableClock,
    audit_log: InMemoryAuditLog,
    authorized_principal: SecurityPrincipal,
) -> None:
    """Verify RetentionPolicyEngine TTL calculation and RetentionWorker idempotent purge."""
    policy = RetentionPolicyEngine(
        default_ttl=timedelta(hours=24),
        max_ttl=timedelta(hours=24),
        class_ttls={DataClass.MEDICAL: timedelta(hours=12)},
        clock=clock,
    )
    assert policy.ttl_for(DataClass.GENERAL) == timedelta(hours=24)
    assert policy.ttl_for(DataClass.MEDICAL) == timedelta(hours=12)

    with pytest.raises(ValueError, match="max_ttl"):
        RetentionPolicyEngine(
            default_ttl=timedelta(hours=48),
            max_ttl=timedelta(hours=24),
        )

    restorer = ResponseRestorer(
        vault_core, retention_policy=policy, audit_writer=audit_log, clock=clock
    )
    worker = RetentionWorker(
        vault_core,
        response_restorer=restorer,
        kms=kms,
        audit_writer=audit_log,
        clock=clock,
    )

    sec_ctx = SecurityContext(
        request_id="req_ret_1",
        tenant_id="tenant_a",
        session_id="sess_ret_1",
        data_class=DataClass.GENERAL,
    )
    record = vault_core.tokenize(RAW_PESEL, EntityType.PESEL, sec_ctx)
    restorer.store(
        PipelineMemento.create(
            request_id="req_ret_1",
            session_id="sess_ret_1",
            tenant_id="tenant_a",
            timestamp=clock(),
            token_map={
                "<PESEL_1>": EntityMetadata(
                    token_id=record.token_id,
                    entity_type=EntityType.PESEL,
                    key_id=record.key_id,
                )
            },
        )
    )

    # Before TTL expires: worker purges 0 records
    assert worker.run_once() == 0
    assert vault_core.find_record(record.token_id) is not None

    # Advance clock past 24h TTL: worker purges the record idempotently
    clock.advance(timedelta(hours=25))
    assert asyncio.run(worker.run_async(interval_seconds=0.0, max_iterations=1)) == 1
    assert worker.run_once() == 0  # Idempotent second run
    assert vault_core.find_record(record.token_id) is None

    with pytest.raises(TokenExpiredError):
        restorer.get("req_ret_1")


def test_poc_3_gdpr_art17_erasure_crypto_shredding_and_hash_chained_audit_log(
    vault_core: VaultCore,
    kms: InMemoryKMS,
    clock: ControllableClock,
    audit_log: InMemoryAuditLog,
    authorized_principal: SecurityPrincipal,
) -> None:
    """PoC 3: Verify GDPR Art. 17 erasure + crypto-shredding vs append-only AuditLog."""
    restorer = ResponseRestorer(vault_core, audit_writer=audit_log, clock=clock)
    worker = RetentionWorker(
        vault_core,
        response_restorer=restorer,
        kms=kms,
        audit_writer=audit_log,
        clock=clock,
    )

    sec_ctx = SecurityContext(
        request_id="req_gdpr_1",
        tenant_id="tenant_a",
        session_id="sess_gdpr_1",
        data_class=DataClass.MEDICAL,
    )
    rec_person = vault_core.tokenize(RAW_PERSON, EntityType.PERSON, sec_ctx)
    rec_pesel = vault_core.tokenize(RAW_PESEL, EntityType.PESEL, sec_ctx)
    restorer.store(
        PipelineMemento.create(
            request_id="req_gdpr_1",
            session_id="sess_gdpr_1",
            tenant_id="tenant_a",
            data_class=DataClass.MEDICAL,
            timestamp=clock(),
            key_id=rec_person.key_id,
            token_map={
                "<PERSON_1>": EntityMetadata(
                    token_id=rec_person.token_id,
                    entity_type=EntityType.PERSON,
                    key_id=rec_person.key_id,
                ),
                "<PESEL_1>": EntityMetadata(
                    token_id=rec_pesel.token_id,
                    entity_type=EntityType.PESEL,
                    key_id=rec_pesel.key_id,
                ),
            },
        )
    )

    # Execute GDPR Art. 17 right to be forgotten for `sess_gdpr_1`
    purged = worker.forget_session(
        "sess_gdpr_1",
        data_class=DataClass.MEDICAL,
        crypto_shred_keys=True,
    )
    assert purged == 2

    # 1. Records are removed from VaultCore and Memento is evicted
    assert vault_core.find_record(rec_person.token_id) is None
    assert vault_core.find_record(rec_pesel.token_id) is None
    assert restorer.get_by_session("sess_gdpr_1") is None

    # 2. Session DEK is crypto-shredded (KeyStatus.EXPIRED -> wrapped_key destroyed)
    assert kms.key_status(rec_person.key_id) is KeyStatus.EXPIRED
    with pytest.raises(KeyExpiredError):
        kms.get_key(rec_person.key_id)

    # 3. AuditLog preserves an intact hash chain (`previous_hash` -> `event_hash`) with ZERO PII
    purge_events = [
        e for e in audit_log.events() if e.action is AuditAction.RETENTION_PURGE
    ]
    assert len(purge_events) == 2
    assert purge_events[0].previous_hash == "genesis"
    assert purge_events[0].event_hash is not None
    assert purge_events[1].previous_hash == purge_events[0].event_hash
    assert purge_events[1].reason == "GDPR_ART17_ERASURE"

    for event in audit_log.events():
        dumped = str(event.model_dump()) + repr(event)
        assert RAW_PERSON not in dumped
        assert RAW_PESEL not in dumped


# --- 6. Mandatory Negative / Abuse Security Tests (Scenarios 2 & 5) ---------------------


def test_negative_unauthorized_restoration_and_cross_tenant_session_isolation(
    vault_core: VaultCore,
    kms: InMemoryKMS,
    clock: ControllableClock,
    audit_log: InMemoryAuditLog,
    authorized_principal: SecurityPrincipal,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify Scenario 2 & 5 abuse cases: RBAC denial, cross-tenant/session, key expiration."""
    caplog.set_level("DEBUG")
    restorer = ResponseRestorer(vault_core, audit_writer=audit_log, clock=clock)
    detectors: list[PIIDetector] = [
        RegexPIIDetector(),
        PolishTransformerNERDetector(ner_pipeline=_fake_polish_ner),
    ]
    pipeline = (
        PipelineBuilder()
        .with_detectors(detectors)
        .with_anonymization_strategy(TokenizationStrategy(reversible=True, vault=vault_core))
        .with_vault_proxy(vault_core)
        .with_response_restorer(restorer)
        .build()
    )
    proxy = PipelineProxy(pipeline, response_restorer=restorer)

    proxy.process_text(
        f"{RAW_PERSON}, PESEL {RAW_PESEL}",
        request_id="req_sec_1",
        session_id="sess_sec_1",
        tenant_id="tenant_a",
        principal=authorized_principal,
    )
    memento = restorer.get("req_sec_1")
    assert memento is not None

    # Abuse 1: Missing principal -> UnauthorizedVaultAccessError + DENIED AuditEvent
    with pytest.raises(UnauthorizedVaultAccessError):
        proxy.restore_response("Sprawa <PERSON_1>", memento, principal=None)
    assert audit_log.events()[-1].outcome is AuditOutcome.DENIED

    # Abuse 2: Principal lacking Permission.DETOKENIZE
    no_perm_principal = SecurityPrincipal(
        principal_id="svc_no_detok",
        tenant_id="tenant_a",
        permissions=frozenset({Permission.TOKENIZE}),
    )
    with pytest.raises(UnauthorizedVaultAccessError, match="DETOKENIZE"):
        proxy.restore_response("Sprawa <PERSON_1>", memento, principal=no_perm_principal)
    assert audit_log.events()[-1].outcome is AuditOutcome.DENIED

    # Abuse 3: Cross-tenant principal attempting to restore tenant_a's Memento
    other_tenant_principal = SecurityPrincipal(
        principal_id="svc_tenant_b",
        tenant_id="tenant_b",
        permissions=frozenset({Permission.DETOKENIZE}),
    )
    with pytest.raises(UnauthorizedVaultAccessError, match="Tenant mismatch"):
        proxy.restore_response(
            "Sprawa <PERSON_1>", memento, principal=other_tenant_principal
        )
    assert audit_log.events()[-1].outcome is AuditOutcome.DENIED

    # Abuse 4: Cross-session expansion attempt on Memento
    with pytest.raises(UnauthorizedVaultAccessError, match="session_id"):
        memento.expand({}, session_id="sess_attacker")

    # Abuse 5: RotationStrategy.EXPIRE invalidates old keys -> restoration fails closed
    vault_core.rotate_keys(
        SecurityPrincipal(
            principal_id="admin",
            tenant_id="tenant_a",
            permissions=frozenset({Permission.ROTATE_KEYS}),
        ),
        SecurityContext(
            request_id="req_sec_1",
            tenant_id="tenant_a",
            session_id="sess_sec_1",
            data_class=DataClass.GENERAL,
        ),
        strategy=RotationStrategy.EXPIRE,
    )
    with pytest.raises(KeyExpiredError) as exc_info:
        proxy.restore_response(
            "Sprawa <PERSON_1>", memento, principal=authorized_principal
        )

    # Zero PII leakage assertion across logs and exceptions
    assert RAW_PERSON not in str(exc_info.value)
    assert RAW_PESEL not in str(exc_info.value)
    assert RAW_PERSON not in caplog.text
    assert RAW_PESEL not in caplog.text

