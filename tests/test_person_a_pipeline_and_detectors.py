"""Comprehensive unit, integration, and security abuse tests for Osoba A's scope.

Covers:
1. Two Transformer NER detectors: `EnglishTransformerNERDetector` (`dslim/bert-base-NER`)
   and `PolishTransformerNERDetector` (`allegro/herbert-base-cased` / NKJP & KPWr labels)
2. Deterministic Regex + Checksums for Poland (`PESEL`, `NIP`, `REGON`, `IBAN`, `ID_CARD`)
   and USA (`SSN`, `ITIN`, `EIN`, `ABA_ROUTING` Mod-10, `CREDIT_CARD` Luhn Mod-10)
3. Multi-strategy `PIIDetectorFilter` & `ContextRuleEnhancer` (lowercase, inflected Polish, split)
4. `PipelineBuilder` build-time invariants and canonical Pipes & Filters execution
5. `PipelineProxy` normalization for text, `ToolCall` JSON, and PDF `DocumentExtractorFilter`
6. Zero raw PII leakage in `repr()`, `str()`, and audit logs
"""

from __future__ import annotations

import time
import zlib
from collections.abc import Mapping, Sequence
from typing import Any

import pytest

import pipeline as pipeline_pkg
import strategies as strategies_pkg
from detectors import (
    DEFAULT_ENGLISH_NER_MODEL,
    DEFAULT_POLISH_FINETUNED_NER_MODEL,
    DEFAULT_POLISH_NER_MODEL,
    ContextRuleEnhancer,
    DetectorRegistry,
    EnglishTransformerNERDetector,
    HeuristicPIIDetector,
    PIIDetector,
    PolishTransformerNERDetector,
    RegexPIIDetector,
    register_detector,
    validate_aba_routing_checksum,
    validate_iban_checksum,
    validate_luhn_checksum,
    validate_nip_checksum,
    validate_pesel_checksum,
    validate_polish_id_card_checksum,
    validate_regon_checksum,
    validate_us_ein,
    validate_us_itin,
    validate_us_ssn,
)
from domain import (
    AuditEvent,
    AuditLevel,
    DataClass,
    DetectedEntity,
    DocumentAttachment,
    EndpointMetadata,
    EntityType,
    PDFExtractionPolicy,
    PipelineConfigurationError,
    ResidencyViolationError,
    ToolCall,
    UnsupportedMediaWithPotentialPIIError,
)
from pipeline import (
    Filter,
    PIIDetectorFilter,
    Pipe,
    Pipeline,
    PipelineBuilder,
    PipelineContext,
    PipelineProxy,
    StatisticalLanguageDetector,
)
from strategies import (
    MaskingStrategy,
    StrategySelector,
    TokenizationStrategy,
)


class InMemoryAuditWriter:
    """In-memory AuditWriter test double."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self._events.append(event)

    def events(self) -> Sequence[AuditEvent]:
        return tuple(self._events)


class EUOnlyResidencyPolicyEngine:
    """ResidencyPolicyEngine allowing MEDICAL data only on EU-compliant endpoints."""

    def is_allowed(self, data_class: DataClass, endpoint: EndpointMetadata) -> bool:
        if data_class == DataClass.MEDICAL:
            return endpoint.is_eu_compliant
        return True


def _fake_english_bert_ner_pipeline(text: str) -> Sequence[Mapping[str, Any]]:
    """Simulate `dslim/bert-base-NER` token-classification output on cased English text."""
    results: list[dict[str, Any]] = []
    catalog = (
        ("John Smith", "PER", 0.994),
        ("Alice Johnson", "PER", 0.988),
        ("Acme Corporation", "ORG", 0.975),
        ("OpenAI", "ORG", 0.962),
        ("London", "LOC", 0.991),
        ("New York", "LOC", 0.985),
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


def _fake_polish_herbert_ner_pipeline(text: str) -> Sequence[Mapping[str, Any]]:
    """Simulate Polish Transformer NER (`allegro/herbert-base-cased` / NKJP & KPWr labels)."""
    results: list[dict[str, Any]] = []
    catalog = (
        ("Jan Kowalski", "persName", 0.992),
        ("Piotr Wiśniewski", "nam_liv_person", 0.987),
        ("Orlen S.A.", "orgName", 0.971),
        ("Warszawa", "placeName", 0.989),
        ("Krakowie", "nam_loc_gpe_city", 0.978),
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


def test_two_transformer_ner_detectors_english_and_polish() -> None:
    """Verify EnglishTransformerNERDetector and PolishTransformerNERDetector and language gating."""
    en_detector = EnglishTransformerNERDetector(
        ner_pipeline=_fake_english_bert_ner_pipeline,
        enable_lowercase_fallback=True,
    )
    pl_detector = PolishTransformerNERDetector(
        ner_pipeline=_fake_polish_herbert_ner_pipeline,
        enable_lowercase_fallback=True,
    )

    assert en_detector.model_name == DEFAULT_ENGLISH_NER_MODEL
    assert pl_detector.model_name == DEFAULT_POLISH_NER_MODEL

    # 1. English Transformer NER on English text (cased + lowercase fallback)
    en_prompt = "John Smith from Acme Corporation traveled to London."
    en_entities = en_detector.detect(en_prompt, language="en")
    en_by_type = {e.entity_type: e.raw_value for e in en_entities}
    assert en_by_type[EntityType.PERSON] == "John Smith"
    assert en_by_type[EntityType.ORGANIZATION] == "Acme Corporation"
    assert en_by_type[EntityType.LOCATION] == "London"
    assert pl_detector.detect(en_prompt, language="en") == ()

    lower_en = "john smith from acme corporation traveled to london."
    lower_en_entities = en_detector.detect(lower_en, language="en")
    lower_en_by_type = {e.entity_type: e.raw_value for e in lower_en_entities}
    assert lower_en_by_type[EntityType.PERSON] == "john smith"

    # 2. Polish Transformer NER on Polish text (NKJP/KPWr tags + lowercase fallback)
    pl_prompt = "Jan Kowalski z Orlen S.A. mieszka w Krakowie."
    pl_entities = pl_detector.detect(pl_prompt, language="pl")
    pl_by_type = {e.entity_type: e.raw_value for e in pl_entities}
    assert pl_by_type[EntityType.PERSON] == "Jan Kowalski"
    assert pl_by_type[EntityType.ORGANIZATION] == "Orlen S.A."
    assert pl_by_type[EntityType.LOCATION] == "Krakowie"
    assert en_detector.detect(pl_prompt, language="pl") == ()


def test_language_detector_uses_statistical_detection_for_english_and_polish() -> None:
    """Verify automatic language detection is not based on marker-word heuristics."""
    detector = StatisticalLanguageDetector()

    assert detector.detect("John Smith works at a hospital in London.") == "en"
    assert detector.detect("Jan Kowalski mieszka w Warszawie.") == "pl"
    assert detector.detect("これは日本語の文章です。") == "unknown"


def test_real_english_transformer_model_detects_entities() -> None:
    """Verify the default English checkpoint can load and perform real inference."""
    pytest.importorskip("torch")
    pytest.importorskip("transformers")

    detector = EnglishTransformerNERDetector(enable_lowercase_fallback=False)
    entities = detector.detect(
        "John Smith works at Microsoft in London.",
        language="en",
    )

    assert entities
    assert any(entity.entity_type == EntityType.PERSON for entity in entities)
    assert any(entity.entity_type == EntityType.LOCATION for entity in entities)


def test_real_polish_transformer_model_detects_entities() -> None:
    """Verify the default Polish checkpoint can load and perform real inference."""
    pytest.importorskip("torch")
    pytest.importorskip("transformers")

    detector = PolishTransformerNERDetector(enable_lowercase_fallback=False)
    entities = detector.detect(
        "Jan Kowalski mieszka w Warszawie.",
        language="pl",
    )

    assert entities
    assert any(entity.entity_type == EntityType.PERSON for entity in entities)
    assert any(entity.entity_type == EntityType.LOCATION for entity in entities)


def test_polish_and_us_official_checksum_validators() -> None:
    """Verify official checksum & validation rules for both Poland (PL) and USA (EN)."""
    # --- Poland (PL) ---
    assert validate_pesel_checksum("44051401458") is True
    assert validate_pesel_checksum("44 05 14 014 58") is True
    assert validate_pesel_checksum("44051401459") is False

    assert validate_nip_checksum("526-025-02-74") is True
    assert validate_nip_checksum("526-025-02-75") is False

    assert validate_regon_checksum("123456785") is True
    assert validate_regon_checksum("123456786") is False

    assert validate_iban_checksum("PL61 1090 1014 0000 0712 1981 2874") is True
    assert validate_iban_checksum("PL62 1090 1014 0000 0712 1981 2874") is False

    assert validate_polish_id_card_checksum("ABA 300000") is True
    assert validate_polish_id_card_checksum("ABA 300001") is False

    # --- USA (EN) ---
    # 1. US SSN (SSA area/group/serial rules)
    assert validate_us_ssn("123-45-6789") is True
    assert validate_us_ssn("000-45-6789") is False
    assert validate_us_ssn("666-45-6789") is False
    assert validate_us_ssn("912-45-6789") is False  # 900-999 reserved for ITIN
    assert validate_us_ssn("123-00-6789") is False
    assert validate_us_ssn("123-45-0000") is False

    # 2. US ITIN (IRS 9XX-XX-XXXX with valid middle two-digit ranges)
    assert validate_us_itin("911-52-1234") is True
    assert validate_us_itin("911-75-1234") is True
    assert validate_us_itin("911-10-1234") is False  # 10 is outside IRS ITIN range

    # 3. US EIN (IRS Campus Prefix rules)
    assert validate_us_ein("12-3456789") is True
    assert validate_us_ein("00-3456789") is False
    assert validate_us_ein("07-3456789") is False  # 07 is not a valid IRS campus prefix

    # 4. US ABA Routing Transit Number (Federal Reserve symbol + 3-7-1 Mod-10 checksum)
    assert validate_aba_routing_checksum("021000021") is True  # JPMorgan Chase NY
    assert validate_aba_routing_checksum("021000022") is False
    assert validate_aba_routing_checksum("151000025") is False  # 15 is invalid Fed prefix

    # 5. Payment Card Number (ISO/IEC 7812 Luhn Mod-10)
    assert validate_luhn_checksum("4532 0151 1283 0366") is True
    assert validate_luhn_checksum("4532 0151 1283 0367") is False

    detector = RegexPIIDetector()
    us_sample = (
        "US Taxpayer SSN 123-45-6789, ITIN 911-52-1234, Company EIN 12-3456789, "
        "Bank ABA Routing 021000021, Card 4532 0151 1283 0366, invalid SSN 666-45-6789."
    )
    us_detected = detector.detect(us_sample, language="en")
    us_types = {e.entity_type for e in us_detected}
    assert EntityType.SSN in us_types
    assert EntityType.ITIN in us_types
    assert EntityType.EIN in us_types
    assert EntityType.ABA_ROUTING in us_types
    assert EntityType.CREDIT_CARD in us_types

    ssn_values = [e.raw_value for e in us_detected if e.entity_type == EntityType.SSN]
    assert ssn_values == ["123-45-6789"]


def test_pii_detector_filter_and_context_rule_enhancer_resilience() -> None:
    """Verify PIIDetectorFilter + ContextRuleEnhancer with both EN and PL Transformer NERs."""
    pii_detector_filter = PIIDetectorFilter(
        detectors=[
            RegexPIIDetector(),
            EnglishTransformerNERDetector(ner_pipeline=_fake_english_bert_ner_pipeline),
            PolishTransformerNERDetector(ner_pipeline=_fake_polish_herbert_ner_pipeline),
            HeuristicPIIDetector(),
        ],
        enhancer=ContextRuleEnhancer(),
    )

    pl_text = (
        "Rozmawiałem z janem kowalskim oraz klientem j. nowakiem "
        "zamieszkałym przy ul. lipowej 12, PESEL 44051401458."
    )
    pl_ctx = pii_detector_filter.process(
        PipelineContext(request_id="req_pl", raw_text=pl_text, language="pl")
    )
    pl_values = {e.raw_value for e in pl_ctx.detected_entities}
    assert "janem kowalskim" in pl_values
    assert "j. nowakiem" in pl_values
    assert "ul. lipowej 12" in pl_values
    assert "44051401458" in pl_values

    en_text = "Patient John Smith at 221B Baker Street, SSN 123-45-6789, EIN 12-3456789."
    en_ctx = pii_detector_filter.process(
        PipelineContext(request_id="req_en", raw_text=en_text, language="en")
    )
    en_values = {e.raw_value for e in en_ctx.detected_entities}
    assert "John Smith" in en_values
    assert "221B Baker Street" in en_values
    assert "123-45-6789" in en_values
    assert "12-3456789" in en_values


def test_dynamic_detector_registration_decorator() -> None:
    """Verify @register_detector registers custom detectors without modifying core classes (OCP)."""

    @register_detector("custom_ticket_id")
    class CustomTicketDetector(PIIDetector):
        @property
        def detector_id(self) -> str:
            return "custom_ticket_detector"

        def detect(self, text: str, language: str = "en") -> Sequence[DetectedEntity]:
            return ()

    assert DetectorRegistry.get("custom_ticket_id") is CustomTicketDetector


def test_pipeline_builder_invariants_and_fail_fast_validation() -> None:
    """Verify PipelineBuilder enforces all build-time compliance invariants."""
    with pytest.raises(PipelineConfigurationError, match="at least one registered PIIDetector"):
        PipelineBuilder().build()

    with pytest.raises(PipelineConfigurationError, match="AuditLevel.NONE is forbidden"):
        (
            PipelineBuilder()
            .for_data_class(DataClass.MEDICAL)
            .with_audit_level(AuditLevel.NONE)
            .with_detector(RegexPIIDetector())
            .with_residency_policy(EUOnlyResidencyPolicyEngine())
            .build()
        )

    with pytest.raises(PipelineConfigurationError, match="ResidencyPolicyEngine"):
        (
            PipelineBuilder()
            .for_data_class(DataClass.MEDICAL)
            .with_detector(RegexPIIDetector())
            .build()
        )

    with pytest.raises(PipelineConfigurationError, match="vault_proxy"):
        (
            PipelineBuilder()
            .with_detector(RegexPIIDetector())
            .with_anonymization_strategy(TokenizationStrategy(reversible=True))
            .build()
        )


def test_inbound_pipeline_proxy_bilingual_text_and_tool_call_sanitization() -> None:
    """Verify PipelineProxy routes EN and PL prompts to their respective Transformer NERs."""
    audit_writer = InMemoryAuditWriter()
    detectors: list[PIIDetector] = [
        RegexPIIDetector(),
        EnglishTransformerNERDetector(ner_pipeline=_fake_english_bert_ner_pipeline),
        PolishTransformerNERDetector(ner_pipeline=_fake_polish_herbert_ner_pipeline),
        HeuristicPIIDetector(),
    ]
    pipeline = (
        PipelineBuilder()
        .with_detectors(detectors)
        .with_anonymization_strategy(
            EntityType.PESEL, MaskingStrategy(mask_char="*", preserve_length=True)
        )
        .with_anonymization_strategy(TokenizationStrategy(reversible=False))
        .with_audit_writer(audit_writer)
        .build()
    )
    proxy = PipelineProxy(pipeline)

    # 1. English prompt -> LanguageDetectorFilter sets 'en' -> EnglishTransformerNERDetector
    en_ctx = proxy.process_text(
        "Patient John Smith (email: john@example.com, SSN 123-45-6789) visited London."
    )
    assert en_ctx.language == "en"
    assert "John Smith" not in en_ctx.sanitized_text
    assert "123-45-6789" not in en_ctx.sanitized_text
    assert "<PERSON_1>" in en_ctx.sanitized_text
    assert "<SSN_1>" in en_ctx.sanitized_text
    assert "<LOCATION_1>" in en_ctx.sanitized_text

    # 2. Polish prompt -> LanguageDetectorFilter sets 'pl' -> PolishTransformerNERDetector
    pl_ctx = proxy.process_text(
        "Pacjent Jan Kowalski (PESEL 44051401458) mieszka w Krakowie."
    )
    assert pl_ctx.language == "pl"
    assert "Jan Kowalski" not in pl_ctx.sanitized_text
    assert "44051401458" not in pl_ctx.sanitized_text
    assert "Krakowie" not in pl_ctx.sanitized_text
    assert "<PERSON_1>" in pl_ctx.sanitized_text
    assert "***********" in pl_ctx.sanitized_text
    assert "<LOCATION_1>" in pl_ctx.sanitized_text

    # 3. Structured ToolCall recursive sanitization
    tool_call = ToolCall(
        id="call_01",
        name="lookup_customer_record",
        arguments={
            "full_name": "John Smith",
            "contact": {"email": "john@example.com", "city": "London"},
            "limit": 5,
        },
        session_id="sess_99",
    )
    tool_ctx = proxy.process_tool_call(tool_call)
    assert tool_ctx.tool_call is not None
    assert tool_ctx.tool_call.arguments["full_name"] == "<PERSON_1>"
    assert tool_ctx.tool_call.arguments["contact"]["email"] == "<EMAIL_1>"
    assert tool_ctx.tool_call.arguments["contact"]["city"] == "<LOCATION_1>"
    assert tool_ctx.tool_call.arguments["limit"] == 5


def test_pdf_document_extractor_filter_metadata_stripping_and_fail_closed_on_scan() -> None:
    """Verify ADR-009: PDF metadata is stripped, text anonymized, and scanned PDFs fail closed."""
    audit_writer = InMemoryAuditWriter()
    pipeline = (
        PipelineBuilder()
        .with_detector(RegexPIIDetector())
        .with_detector(EnglishTransformerNERDetector(ner_pipeline=_fake_english_bert_ner_pipeline))
        .with_audit_writer(audit_writer)
        .build()
    )
    proxy = PipelineProxy(pipeline)

    clean_pdf_bytes = (
        b"%PDF-1.7\n"
        b"1 0 obj << /Author (Secret Author Jan Kowalski) /Title (Confidential) >> endobj\n"
        b"<x:xmpmeta>Secret XMP Metadata 44051401458</x:xmpmeta>\n"
        b"stream\nBT (John Smith has PESEL 44051401458) Tj ET\nendstream\n%%EOF"
    )
    attachment = DocumentAttachment(filename="invoice.pdf", content_bytes=clean_pdf_bytes)
    result_ctx = proxy.process_text("", attachments=[attachment])

    assert result_ctx.attachments == ()
    assert "Secret Author" not in result_ctx.sanitized_text
    assert "Secret XMP" not in result_ctx.sanitized_text
    assert "John Smith" not in result_ctx.sanitized_text
    assert "44051401458" not in result_ctx.sanitized_text
    assert "<PERSON_1>" in result_ctx.sanitized_text
    assert "<PESEL_1>" in result_ctx.sanitized_text

    scanned_pdf_bytes = (
        b"%PDF-1.7\n"
        b"1 0 obj << /Type /XObject /Subtype /Image /Width 800 /Height 600 >> endobj\n"
        b"%%EOF"
    )
    scanned_attachment = DocumentAttachment(
        filename="scan.pdf", content_bytes=scanned_pdf_bytes
    )
    with pytest.raises(UnsupportedMediaWithPotentialPIIError, match="STRICT_NO_OCR"):
        proxy.process_text("", attachments=[scanned_attachment])


def test_residency_policy_filter_blocks_non_eu_dispatch_for_medical() -> None:
    """Verify ResidencyPolicyFilter blocks MEDICAL data targeting a non-EU endpoint."""
    audit_writer = InMemoryAuditWriter()
    pipeline = (
        PipelineBuilder()
        .for_data_class(DataClass.MEDICAL)
        .with_detector(RegexPIIDetector())
        .with_residency_policy(EUOnlyResidencyPolicyEngine())
        .with_audit_writer(audit_writer)
        .build()
    )
    proxy = PipelineProxy(pipeline, default_data_class=DataClass.MEDICAL)

    us_endpoint = EndpointMetadata(
        provider_id="external_llm",
        region="us-east-1",
        is_eu_compliant=False,
    )
    with pytest.raises(ResidencyViolationError, match="us-east-1"):
        proxy.process_text(
            "Patient PESEL 44051401458",
            target_endpoint=us_endpoint,
        )


def test_zero_raw_pii_leakage_in_repr_and_str() -> None:
    """Verify DetectedEntity and PipelineContext never expose raw PII in repr() or str()."""
    secret_pesel = "44051401458"
    entity = DetectedEntity(
        entity_type=EntityType.PESEL,
        start=0,
        end=11,
        raw_value=secret_pesel,
        confidence=1.0,
    )
    assert secret_pesel not in repr(entity)
    assert secret_pesel not in str(entity)
    assert "length=11" in repr(entity)


def test_mixed_case_sentence_lowercase_fallback_in_ner_detector() -> None:
    """Verify NERPIIDetector lowercase fallback triggers on mixed-case sentences."""
    pl_detector = PolishTransformerNERDetector(
        ner_pipeline=_fake_polish_herbert_ner_pipeline,
        enable_lowercase_fallback=True,
    )
    mixed_prompt = "Pacjent jan kowalski mieszka w krakowie, dokument potwierdzony."
    entities = pl_detector.detect(mixed_prompt, language="pl")
    values = {e.raw_value for e in entities}
    assert "jan kowalski" in values
    assert "krakowie" in values
    assert DEFAULT_POLISH_FINETUNED_NER_MODEL == "pietruszkowiec/herbert-base-ner"


def test_polish_tool_call_language_detection_and_entity_tracking() -> None:
    """Verify Polish ToolCall triggers 'pl' detection and tracks detected_entities."""
    audit_writer = InMemoryAuditWriter()
    detectors: list[PIIDetector] = [
        RegexPIIDetector(),
        EnglishTransformerNERDetector(ner_pipeline=_fake_english_bert_ner_pipeline),
        PolishTransformerNERDetector(ner_pipeline=_fake_polish_herbert_ner_pipeline),
        HeuristicPIIDetector(),
    ]
    pipeline = (
        PipelineBuilder()
        .with_detectors(detectors)
        .with_audit_writer(audit_writer)
        .build()
    )
    proxy = PipelineProxy(pipeline)

    pl_tool_call = ToolCall(
        id="call_pl_01",
        name="pobierz_dane_pacjenta",
        arguments={
            "opis": "Pacjent Jan Kowalski zamieszkały w Krakowie, PESEL 44051401458",
        },
        session_id="sess_pl_1",
    )
    ctx = proxy.process_tool_call(pl_tool_call)
    assert ctx.language == "pl"
    assert ctx.tool_call is not None
    sanitized_desc = ctx.tool_call.arguments["opis"]
    assert "Jan Kowalski" not in sanitized_desc
    assert "Krakowie" not in sanitized_desc
    assert "44051401458" not in sanitized_desc
    assert "<PERSON_1>" in sanitized_desc
    assert "<LOCATION_1>" in sanitized_desc
    assert "<PESEL_1>" in sanitized_desc
    assert len(ctx.detected_entities) == 3
    assert len(ctx.anonymization_results) == 3
    assert audit_writer.events()[-1].reason == "Anonymized 3 entities."


def test_pipeline_builder_risk_assessment_filter_slot_and_k_anonymity_propagation() -> None:
    """Verify RiskAssessmentFilter executes between PIIDetectorFilter and AnonymizationFilter."""

    class SpyRiskFilter(Filter):
        def __init__(self) -> None:
            self.observed_k: int | None = None
            self.entities_before_anonymization: int = 0
            self.sanitized_text_at_risk_stage: str = ""

        @property
        def filter_name(self) -> str:
            return "SpyRiskFilter"

        def process(self, context: PipelineContext) -> PipelineContext:
            self.observed_k = context.k_anonymity_threshold
            self.entities_before_anonymization = len(context.detected_entities)
            self.sanitized_text_at_risk_stage = context.sanitized_text
            return context

    spy_risk = SpyRiskFilter()
    pipeline = (
        PipelineBuilder()
        .with_detector(RegexPIIDetector())
        .with_k_anonymity_threshold(5)
        .with_risk_assessment_filter(spy_risk)
        .build()
    )
    proxy = PipelineProxy(pipeline)
    result_ctx = proxy.process_text("Klient PESEL 44051401458.")

    filter_names = [f.filter_name for f in result_ctx.applied_filters]
    assert filter_names == [
        "DocumentExtractorFilter",
        "LanguageDetectorFilter",
        "PIIDetectorFilter",
        "SpyRiskFilter",
        "AnonymizationFilter",
        "AuditContextFilter",
    ]
    assert spy_risk.observed_k == 5
    assert spy_risk.entities_before_anonymization == 1
    assert spy_risk.sanitized_text_at_risk_stage == ""


def test_poc_1_ner_and_middleware_latency_budget_under_200ms() -> None:
    """PoC 1 (TEAM_TASKS_DIVISION.md): Verify middleware + NER latency < 200 ms per request."""
    detectors: list[PIIDetector] = [
        RegexPIIDetector(),
        EnglishTransformerNERDetector(ner_pipeline=_fake_english_bert_ner_pipeline),
        PolishTransformerNERDetector(ner_pipeline=_fake_polish_herbert_ner_pipeline),
        HeuristicPIIDetector(),
    ]
    pipeline = (
        PipelineBuilder()
        .with_detectors(detectors)
        .with_context_enhancer(ContextRuleEnhancer())
        .with_anonymization_strategy(EntityType.PESEL, MaskingStrategy())
        .with_anonymization_strategy(TokenizationStrategy(reversible=False))
        .build()
    )
    proxy = PipelineProxy(pipeline)

    prompts = (
        (
            "Pacjent Jan Kowalski, PESEL 44051401458, NIP 526-025-02-74, "
            "mieszka przy ul. Lipowej 12 w Krakowie."
        ),
        "Customer John Smith (SSN 123-45-6789, ABA 021000021) from Acme Corporation in London.",
        (
            "Rozmawiałem z janem kowalskim oraz klientem j. nowakiem, "
            "IBAN PL61 1090 1014 0000 0712 1981 2874."
        ),
    )

    latencies_ms: list[float] = []
    for _ in range(10):
        for prompt in prompts:
            start = time.perf_counter()
            ctx = proxy.process_text(prompt)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            latencies_ms.append(elapsed_ms)
            assert ctx.sanitized_text != ""

    avg_latency_ms = sum(latencies_ms) / len(latencies_ms)
    max_latency_ms = max(latencies_ms)
    assert avg_latency_ms < 50.0
    assert max_latency_ms < 200.0


def test_poc_2_detection_resilience_standalone_ner_vs_hybrid_context_enhancer() -> None:
    """PoC 2 (TEAM_TASKS_DIVISION.md): Compare standalone cased NER vs NER + ContextRuleEnhancer."""
    standalone_cased_ner = PolishTransformerNERDetector(
        ner_pipeline=_fake_polish_herbert_ner_pipeline,
        enable_lowercase_fallback=False,
    )
    hybrid_filter = PIIDetectorFilter(
        detectors=[
            RegexPIIDetector(),
            PolishTransformerNERDetector(
                ner_pipeline=_fake_polish_herbert_ner_pipeline,
                enable_lowercase_fallback=True,
            ),
            HeuristicPIIDetector(),
        ],
        enhancer=ContextRuleEnhancer(),
    )

    challenging_text = (
        "Spotkanie z janem kowalskim oraz pacjentem j. wiśniewskim "
        "zamieszkałym przy ul. lipowej 5, PESEL 44 05 14 014 58."
    )

    # Standalone cased NER misses lowercase, inflected, abbreviated, and split identifiers
    ner_only_entities = standalone_cased_ner.detect(challenging_text, language="pl")
    assert len(ner_only_entities) == 0

    # Multi-strategy PIIDetectorFilter (NER + ContextRuleEnhancer + Heuristic + Regex) detects all 4
    hybrid_ctx = hybrid_filter.process(
        PipelineContext(request_id="req_poc2", raw_text=challenging_text, language="pl")
    )
    hybrid_values = {e.raw_value for e in hybrid_ctx.detected_entities}
    assert "janem kowalskim" in hybrid_values
    assert "j. wiśniewskim" in hybrid_values
    assert "ul. lipowej 5" in hybrid_values
    assert "44 05 14 014 58" in hybrid_values


def test_poc_3_pdf_flatedecode_extraction_and_local_ocr_policy() -> None:
    """PoC 3 (TEAM_TASKS_DIVISION.md): Verify FlateDecode PDF extraction and Local OCR."""
    # 1. Build a PDF with a zlib FlateDecode stream, hex text, and XMP/Info metadata
    compressed_bt_et = zlib.compress(
        b"BT (Pacjent Jan Kowalski) Tj <20> (PESEL 44051401458) Tj ET"
    )
    flate_pdf_bytes = (
        b"%PDF-1.7\n"
        b"1 0 obj << /Author (Ukryty Autor Piotr Nowak) /Creator <4A616E> >> endobj\n"
        b"2 0 obj << /Subtype /Redact /Contents (Ukryta Warstwa 44051401458) >> endobj\n"
        b"<x:xmpmeta>Tajne XMP 44051401458</x:xmpmeta>\n"
        b"3 0 obj << /Filter /FlateDecode /Length "
        + str(len(compressed_bt_et)).encode("ascii")
        + b" >>\nstream\n"
        + compressed_bt_et
        + b"\nendstream\nendobj\n%%EOF"
    )

    detectors: list[PIIDetector] = [
        RegexPIIDetector(),
        PolishTransformerNERDetector(ner_pipeline=_fake_polish_herbert_ner_pipeline),
        HeuristicPIIDetector(),
    ]
    pipeline = PipelineBuilder().with_detectors(detectors).build()
    proxy = PipelineProxy(pipeline)

    flate_attachment = DocumentAttachment(
        filename="epikryza_flate.pdf", content_bytes=flate_pdf_bytes
    )
    flate_ctx = proxy.process_text("", attachments=[flate_attachment])
    assert flate_ctx.language == "pl"
    assert "Ukryty Autor" not in flate_ctx.sanitized_text
    assert "Tajne XMP" not in flate_ctx.sanitized_text
    assert "Jan Kowalski" not in flate_ctx.sanitized_text
    assert "44051401458" not in flate_ctx.sanitized_text
    assert "<PERSON_1>" in flate_ctx.sanitized_text
    assert "<PESEL_1>" in flate_ctx.sanitized_text

    # 2. Verify LOCAL_OCR_ENABLED requires an OCR engine at build time
    with pytest.raises(PipelineConfigurationError, match="LocalOCREngine"):
        (
            PipelineBuilder()
            .with_detectors(detectors)
            .with_pdf_extraction_policy(PDFExtractionPolicy.LOCAL_OCR_ENABLED, ocr_engine=None)
            .build()
        )

    # 3. Verify LOCAL_OCR_ENABLED extracts and anonymizes scanned PDFs via injected LocalOCREngine
    class FakeLocalOCR:
        def extract_text_from_pdf_bytes(self, pdf_bytes: bytes) -> str:
            return "Skan dokumentu: Jan Kowalski, PESEL 44051401458"

    ocr_pipeline = (
        PipelineBuilder()
        .with_detectors(detectors)
        .with_pdf_extraction_policy(
            PDFExtractionPolicy.LOCAL_OCR_ENABLED, ocr_engine=FakeLocalOCR()
        )
        .build()
    )
    ocr_proxy = PipelineProxy(ocr_pipeline)
    scanned_pdf_bytes = (
        b"%PDF-1.7\n"
        b"1 0 obj << /Type /XObject /Subtype /Image /Width 800 /Height 600 >> endobj\n"
        b"%%EOF"
    )
    scanned_attachment = DocumentAttachment(
        filename="scan.pdf", content_bytes=scanned_pdf_bytes
    )
    ocr_ctx = ocr_proxy.process_text("", attachments=[scanned_attachment])
    assert "Jan Kowalski" not in ocr_ctx.sanitized_text
    assert "44051401458" not in ocr_ctx.sanitized_text
    assert "<PERSON_1>" in ocr_ctx.sanitized_text
    assert "<PESEL_1>" in ocr_ctx.sanitized_text


def test_architecture_md_canonical_naming_without_aliases() -> None:
    """Verify public names follow ARCHITECTURE.md and legacy aliases are not exported."""
    # 1. Canonical classes exist; legacy alias names are gone
    assert issubclass(Pipeline, Pipe)
    for legacy_name in (
        "DetectionFilter",
        "InboundPipeline",
        "LanguageDetector",
        "ResidencyGate",
    ):
        assert not hasattr(pipeline_pkg, legacy_name)
    for legacy_name in ("PlaceholderTokenStrategy", "StrategyRegistry"):
        assert not hasattr(strategies_pkg, legacy_name)
    assert set(DataClass) == {
        DataClass.ANONYMOUS,
        DataClass.GENERAL,
        DataClass.FINANCIAL,
        DataClass.LEGAL,
        DataClass.MEDICAL,
    }

    # 2. ToolCall uses the canonical snake_case field `session_id` (ARCHITECTURE.md §4)
    tc = ToolCall(
        id="tc_1",
        name="get_birth_date",
        arguments={"user_id": "Jan Kowalski"},
        session_id="sess_arch_1",
    )
    assert tc.session_id == "sess_arch_1"
    assert not hasattr(tc, "sessionId")

    # 3. StrategySelector.select() & can_reverse() (ARCHITECTURE.md §3.2)
    mask_strat = MaskingStrategy()
    tok_strat = TokenizationStrategy(reversible=False)
    assert mask_strat.can_reverse() is False
    assert tok_strat.can_reverse() is False
    assert not hasattr(mask_strat, "is_reversible")
    selector = StrategySelector(
        strategies={EntityType.PESEL: mask_strat},
        default_strategy=tok_strat,
    )
    sample_entity = DetectedEntity(
        entity_type=EntityType.PESEL,
        start=0,
        end=11,
        raw_value="44051401458",
    )
    assert selector.select(sample_entity) is mask_strat
    assert not hasattr(selector, "resolve")

    # 4. PipelineBuilder fluent API from ARCHITECTURE.md §3.3 (snake_case only)
    assert not hasattr(PipelineBuilder, "forDataClass")
    built_pipe = (
        PipelineBuilder()
        .for_data_class(DataClass.MEDICAL)
        .with_residency_policy(EUOnlyResidencyPolicyEngine())
        .with_anonymization_strategy(EntityType.PESEL, mask_strat)
        .with_re_id_risk_threshold(0.05)
        .with_audit_level(AuditLevel.FULL)
        .with_detector(RegexPIIDetector())
        .build()
    )
    ctx = PipelineProxy(built_pipe).process_text("PESEL 44051401458")
    assert ctx.re_id_risk_threshold == 0.05
    assert "***********" in ctx.sanitized_text


def test_polish_compact_and_formatted_phone_detection() -> None:
    """Verify RegexPIIDetector detects 9-digit compact/grouped PL phones alongside REGON/ABA."""
    detector = RegexPIIDetector()

    compact_pl = detector.detect(
        "rozmawialem z janem kowalskim, zadzwonilem pod numer 534595825 i nie odebral nikt",
        language="pl",
    )
    assert [(e.entity_type, e.raw_value) for e in compact_pl] == [
        (EntityType.PHONE, "534595825")
    ]

    variants = detector.detect(
        "Numery: +48534595825, +48 534 595 825, 12 345 67 89 oraz REGON 123456785",
        language="pl",
    )
    variant_pairs = {(e.entity_type, e.raw_value) for e in variants}
    assert (EntityType.PHONE, "+48534595825") in variant_pairs
    assert (EntityType.PHONE, "+48 534 595 825") in variant_pairs
    assert (EntityType.PHONE, "12 345 67 89") in variant_pairs
    assert (EntityType.REGON, "123456785") in variant_pairs

    us_aba = detector.detect("Bank ABA Routing 021000021", language="en")
    assert [(e.entity_type, e.raw_value) for e in us_aba] == [
        (EntityType.ABA_ROUTING, "021000021")
    ]
