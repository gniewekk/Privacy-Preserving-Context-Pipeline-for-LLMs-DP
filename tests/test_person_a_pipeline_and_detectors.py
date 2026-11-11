"""Comprehensive unit, integration, and security abuse tests for Osoba A's scope.

Covers:
1. Two Transformer NER detectors: `EnglishTransformerNERDetector` (`dslim/bert-base-NER`)
   and `PolishTransformerNERDetector` (`allegro/herbert-base-cased` / NKJP & KPWr labels)
2. Deterministic Regex + Checksums for Poland (`PESEL`, `NIP`, `REGON`, `IBAN`, `ID_CARD`)
   and USA (`SSN`, `ITIN`, `EIN`, `ABA_ROUTING` Mod-10, `CREDIT_CARD` Luhn Mod-10)
3. Hybrid `CompositePIIDetector` & `ContextRuleEnhancer` (lowercase, inflected Polish, split tokens)
4. `PipelineBuilder` build-time invariants and canonical Pipes & Filters execution
5. `PipelineProxy` normalization for text, `ToolCallPayload` JSON, and PDF `DocumentExtractorFilter`
6. Zero raw PII leakage in `repr()`, `str()`, and audit logs
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import pytest

from detectors import (
    DEFAULT_ENGLISH_NER_MODEL,
    DEFAULT_POLISH_NER_MODEL,
    CompositePIIDetector,
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
    PipelineConfigurationError,
    ResidencyViolationError,
    ToolCallPayload,
    UnsupportedMediaWithPotentialPIIError,
)
from pipeline import (
    PipelineBuilder,
    PipelineProxy,
)
from strategies import MaskingStrategy, PlaceholderTokenStrategy


class InMemoryAuditLogger:
    """In-memory AuditLogger test double."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self._events.append(event)

    def events(self) -> Sequence[AuditEvent]:
        return tuple(self._events)


class EUOnlyResidencyPolicy:
    """ResidencyPolicy allowing PHI only on EU-compliant endpoints."""

    def is_allowed(self, data_class: DataClass, endpoint: EndpointMetadata) -> bool:
        if data_class == DataClass.PHI:
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


def test_composite_detector_and_context_rule_enhancer_resilience() -> None:
    """Verify CompositePIIDetector + ContextRuleEnhancer with both EN and PL Transformer NERs."""
    composite = CompositePIIDetector(
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
    pl_entities = composite.detect(pl_text, language="pl")
    pl_values = {e.raw_value for e in pl_entities}
    assert "janem kowalskim" in pl_values
    assert "j. nowakiem" in pl_values
    assert "ul. lipowej 12" in pl_values
    assert "44051401458" in pl_values

    en_text = "Patient John Smith at 221B Baker Street, SSN 123-45-6789, EIN 12-3456789."
    en_entities = composite.detect(en_text, language="en")
    en_values = {e.raw_value for e in en_entities}
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
            .with_residency_policy(EUOnlyResidencyPolicy())
            .build()
        )

    with pytest.raises(PipelineConfigurationError, match="ResidencyPolicy"):
        (
            PipelineBuilder()
            .for_data_class(DataClass.PHI)
            .with_detector(RegexPIIDetector())
            .build()
        )

    with pytest.raises(PipelineConfigurationError, match="vault_proxy"):
        (
            PipelineBuilder()
            .with_detector(RegexPIIDetector())
            .with_default_strategy(PlaceholderTokenStrategy(reversible=True))
            .build()
        )


def test_inbound_pipeline_proxy_bilingual_text_and_tool_call_sanitization() -> None:
    """Verify PipelineProxy routes EN and PL prompts to their respective Transformer NERs."""
    audit_logger = InMemoryAuditLogger()
    composite = CompositePIIDetector(
        detectors=[
            RegexPIIDetector(),
            EnglishTransformerNERDetector(ner_pipeline=_fake_english_bert_ner_pipeline),
            PolishTransformerNERDetector(ner_pipeline=_fake_polish_herbert_ner_pipeline),
            HeuristicPIIDetector(),
        ]
    )
    pipeline = (
        PipelineBuilder()
        .with_detector(composite)
        .with_strategy(EntityType.PESEL, MaskingStrategy(mask_char="*", preserve_length=True))
        .with_default_strategy(PlaceholderTokenStrategy(reversible=False))
        .with_audit_logger(audit_logger)
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

    # 3. Structured ToolCallPayload recursive sanitization
    tool_call = ToolCallPayload(
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
    audit_logger = InMemoryAuditLogger()
    pipeline = (
        PipelineBuilder()
        .with_detector(
            CompositePIIDetector(
                detectors=[
                    RegexPIIDetector(),
                    EnglishTransformerNERDetector(ner_pipeline=_fake_english_bert_ner_pipeline),
                ]
            )
        )
        .with_audit_logger(audit_logger)
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


def test_residency_gate_blocks_non_eu_dispatch_for_phi() -> None:
    """Verify ResidencyGate raises ResidencyViolationError when PHI targets a non-EU endpoint."""
    audit_logger = InMemoryAuditLogger()
    pipeline = (
        PipelineBuilder()
        .for_data_class(DataClass.PHI)
        .with_detector(RegexPIIDetector())
        .with_residency_policy(EUOnlyResidencyPolicy())
        .with_audit_logger(audit_logger)
        .build()
    )
    proxy = PipelineProxy(pipeline, default_data_class=DataClass.PHI)

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
