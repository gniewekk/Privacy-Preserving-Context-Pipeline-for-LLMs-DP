"""Stateless filters for the Inbound Pipes & Filters pipeline (Osoba A)."""

from __future__ import annotations

import re
import uuid
import zlib
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from detectors.base import PIIDetector, resolve_overlapping_spans
from detectors.heuristic import ContextRuleEnhancer
from domain.exceptions import (
    ResidencyViolationError,
    UnsupportedMediaWithPotentialPIIError,
)
from domain.models import (
    AnonymizationRequest,
    AnonymizationResult,
    AuditAction,
    AuditEvent,
    AuditLevel,
    AuditOutcome,
    DataClass,
    DetectedEntity,
    EntityType,
    PDFExtractionPolicy,
    SecurityContext,
)
from domain.protocols import AuditWriter, LanguageDetector, LocalOCREngine, ResidencyPolicyEngine
from pipeline.context import PipelineContext
from pipeline.filter import Filter
from pipeline.language import default_language_detector
from strategies.base import StrategySelector

# Regex helpers for local, zero-network PDF metadata stripping & text stream extraction
_PDF_XMP_PATTERN = re.compile(rb"<x:xmpmeta\b.*?</x:xmpmeta>", re.DOTALL | re.IGNORECASE)
_PDF_INFO_TAG_PATTERN = re.compile(
    rb"/(?:Author|Creator|Producer|Title|Subject|Keywords)\s*(?:\([^)]*\)|<[0-9A-Fa-f]*>)",
    re.IGNORECASE,
)
_PDF_HIDDEN_ANNOT_PATTERN = re.compile(
    rb"<<[^>]*?/Subtype\s*/(?:Redact|Hidden|Watermark)[^>]*?>>",
    re.DOTALL | re.IGNORECASE,
)
_PDF_IMAGE_SUBTYPE_PATTERN = re.compile(rb"/Subtype\s*/Image\b")
_PDF_STREAM_BLOCK_PATTERN = re.compile(
    rb"(<<[^>]*?>>)?\s*stream\r?\n(.*?)\r?\nendstream",
    re.DOTALL,
)
_PDF_TEXT_BLOCK_PATTERN = re.compile(rb"BT\b(.*?)\bET", re.DOTALL)
_PDF_STRING_TOKEN_PATTERN = re.compile(
    rb"\(([^()\\]*(?:\\.[^()\\]*)*)\)|<([0-9A-Fa-f]{2,})>"
)
_MAX_DECOMPRESSED_PDF_STREAM_BYTES = 10 * 1024 * 1024  # 10 MB safety cap against zip bombs

def _extract_bt_et_fragments(content_bytes: bytes) -> list[str]:
    """Extract literal and hex-encoded text strings from PDF BT...ET blocks."""
    fragments: list[str] = []
    for bt_match in _PDF_TEXT_BLOCK_PATTERN.finditer(content_bytes):
        block = bt_match.group(1)
        for token_match in _PDF_STRING_TOKEN_PATTERN.finditer(block):
            literal_part = token_match.group(1)
            hex_part = token_match.group(2)
            if literal_part is not None:
                decoded = (
                    literal_part.replace(rb"\(", b"(")
                    .replace(rb"\)", b")")
                    .replace(rb"\\", b"\\")
                    .decode("utf-8", errors="ignore")
                    .strip()
                )
                if decoded:
                    fragments.append(decoded)
            elif hex_part is not None and len(hex_part) % 2 == 0:
                try:
                    raw_hex = bytes.fromhex(hex_part.decode("ascii"))
                    decoded_hex = raw_hex.decode("utf-8", errors="ignore").strip()
                    if decoded_hex:
                        fragments.append(decoded_hex)
                except ValueError:
                    continue
    return fragments


def _extract_clean_pdf_text(raw_pdf_bytes: bytes) -> tuple[str, bool]:
    """Strip XMP/Info metadata from PDF bytes, decompress FlateDecode streams, and extract text."""
    if not raw_pdf_bytes.startswith(b"%PDF-"):
        raise UnsupportedMediaWithPotentialPIIError(
            "Invalid or unsupported binary document header; expected PDF attachment."
        )

    has_embedded_image = bool(_PDF_IMAGE_SUBTYPE_PATTERN.search(raw_pdf_bytes))

    # Strip XMP metadata streams, /Info dictionary tags, and hidden annotation layers
    scrubbed = _PDF_XMP_PATTERN.sub(b"", raw_pdf_bytes)
    scrubbed = _PDF_INFO_TAG_PATTERN.sub(b"", scrubbed)
    scrubbed = _PDF_HIDDEN_ANNOT_PATTERN.sub(b"", scrubbed)

    extracted_fragments: list[str] = []
    stream_matches = list(_PDF_STREAM_BLOCK_PATTERN.finditer(scrubbed))

    if stream_matches:
        for stream_match in stream_matches:
            stream_dict = stream_match.group(1) or b""
            stream_data = stream_match.group(2)
            # Skip metadata or image object streams
            if b"/Subtype /Image" in stream_dict or b"/Type /Metadata" in stream_dict:
                continue
            payload = stream_data
            if b"/FlateDecode" in stream_dict:
                try:
                    decompressor = zlib.decompressobj()
                    payload = decompressor.decompress(
                        stream_data, _MAX_DECOMPRESSED_PDF_STREAM_BYTES
                    )
                except zlib.error:
                    payload = b""
            payload_scrubbed = _PDF_XMP_PATTERN.sub(b"", payload)
            payload_scrubbed = _PDF_INFO_TAG_PATTERN.sub(b"", payload_scrubbed)
            extracted_fragments.extend(_extract_bt_et_fragments(payload_scrubbed))
    else:
        extracted_fragments.extend(_extract_bt_et_fragments(scrubbed))

    return " ".join(extracted_fragments).strip(), has_embedded_image


def _collect_json_strings(value: Any) -> list[str]:
    """Recursively collect all string leaf values from a JSON-like structure."""
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, dict):
        out: list[str] = []
        for v in value.values():
            out.extend(_collect_json_strings(v))
        return out
    if isinstance(value, (list, tuple)):
        out_list: list[str] = []
        for item in value:
            out_list.extend(_collect_json_strings(item))
        return out_list
    return []


class DocumentExtractorFilter(Filter):
    """Extracts text from PDF attachments, strips XMP/Info metadata, and fails closed on scans."""

    def __init__(
        self,
        policy: PDFExtractionPolicy = PDFExtractionPolicy.STRICT_NO_OCR,
        ocr_engine: LocalOCREngine | None = None,
        audit_writer: AuditWriter | None = None,
    ) -> None:
        self._policy = policy
        self._ocr_engine = ocr_engine
        self._audit_writer = audit_writer

    @property
    def filter_name(self) -> str:
        return "DocumentExtractorFilter"

    def _record_block_audit(self, context: PipelineContext, reason: str) -> None:
        if self._audit_writer is None:
            return
        self._audit_writer.record(
            AuditEvent(
                event_id=f"evt_{uuid.uuid4().hex[:12]}",
                timestamp=datetime.now(UTC),
                action=AuditAction.DOCUMENT_EXTRACTION,
                outcome=AuditOutcome.BLOCKED,
                principal_id=(
                    context.principal.principal_id if context.principal else "anonymous"
                ),
                tenant_id=context.tenant_id,
                request_id=context.request_id,
                reason=reason,
            )
        )

    def process(self, context: PipelineContext) -> PipelineContext:
        if not context.attachments:
            return context

        extracted_texts: list[str] = []
        if context.raw_text.strip():
            extracted_texts.append(context.raw_text.strip())

        for attachment in context.attachments:
            text_layer, has_image = _extract_clean_pdf_text(attachment.content_bytes)
            needs_ocr = has_image or not text_layer

            if needs_ocr:
                if (
                    self._policy == PDFExtractionPolicy.LOCAL_OCR_ENABLED
                    and self._ocr_engine is not None
                ):
                    ocr_text = self._ocr_engine.extract_text_from_pdf_bytes(
                        attachment.content_bytes
                    ).strip()
                    if not ocr_text and not text_layer:
                        self._record_block_audit(
                            context, "Scanned PDF yielded empty text after local OCR."
                        )
                        raise UnsupportedMediaWithPotentialPIIError(
                            "Scanned PDF yielded no extractable text; blocked fail-closed."
                        )
                    combined = " ".join(part for part in (text_layer, ocr_text) if part)
                    extracted_texts.append(combined)
                else:
                    self._record_block_audit(
                        context,
                        "UNSUPPORTED_MEDIA_WITH_POTENTIAL_PII: scanned PDF in STRICT_NO_OCR mode.",
                    )
                    raise UnsupportedMediaWithPotentialPIIError(
                        "UNSUPPORTED_MEDIA_WITH_POTENTIAL_PII: PDF contains scanned/raster "
                        "imagery or lacks a text layer while STRICT_NO_OCR is active."
                    )
            else:
                extracted_texts.append(text_layer)

        merged_text = "\n".join(extracted_texts)
        # Clear binary attachments so raw binaries never leave the boundary (ADR-009)
        return context.model_copy(
            update={
                "raw_text": merged_text,
                "attachments": (),
            }
        )


class LanguageDetectorFilter(Filter):
    """Detects prompt or ToolCall language before PII detection."""

    def __init__(self, detector: LanguageDetector | None = None) -> None:
        self._detector = detector or default_language_detector()

    @property
    def filter_name(self) -> str:
        return "LanguageDetectorFilter"

    def process(self, context: PipelineContext) -> PipelineContext:
        text = context.current_text
        if not text.strip() and context.tool_call is not None:
            text = " ".join(_collect_json_strings(context.tool_call.arguments))
        if not text.strip():
            return context

        return context.model_copy(update={"language": self._detector.detect(text)})


class PIIDetectorFilter(Filter):
    """Stateless filter orchestrating registered PIIDetector strategies (ARCHITECTURE.md §3.1)."""

    def __init__(
        self,
        detectors: Sequence[PIIDetector],
        k_anonymity_threshold: int | None = None,
        re_id_risk_threshold: float | None = None,
        enhancer: ContextRuleEnhancer | None = None,
    ) -> None:
        self._detectors: tuple[PIIDetector, ...] = tuple(detectors)
        self._k_anonymity_threshold = k_anonymity_threshold
        self._re_id_risk_threshold = re_id_risk_threshold
        self._enhancer = enhancer or ContextRuleEnhancer()

    @property
    def filter_name(self) -> str:
        return "PIIDetectorFilter"

    def process(self, context: PipelineContext) -> PipelineContext:
        text = context.current_text
        all_detected: list[DetectedEntity] = []
        if text.strip():
            for detector in self._detectors:
                all_detected.extend(detector.detect(text, language=context.language))

        enhanced = self._enhancer.enhance(text, all_detected) if all_detected else ()
        merged = resolve_overlapping_spans(enhanced)
        elevated_class = context.data_class
        if any(e.data_class == DataClass.MEDICAL for e in merged):
            elevated_class = DataClass.MEDICAL
        elif context.tool_call is not None:
            for arg_str in _collect_json_strings(context.tool_call.arguments):
                for detector in self._detectors:
                    if any(
                        e.data_class == DataClass.MEDICAL
                        for e in detector.detect(arg_str, language=context.language)
                    ):
                        elevated_class = DataClass.MEDICAL
                        break

        effective_k = (
            context.k_anonymity_threshold
            if context.k_anonymity_threshold is not None
            else self._k_anonymity_threshold
        )
        effective_risk = (
            context.re_id_risk_threshold
            if context.re_id_risk_threshold is not None
            else self._re_id_risk_threshold
        )

        return context.model_copy(
            update={
                "detected_entities": merged,
                "data_class": elevated_class,
                "k_anonymity_threshold": effective_k,
                "re_id_risk_threshold": effective_risk,
            }
        )


class AnonymizationFilter(Filter):
    """Stateless filter delegating PII transformation to StrategySelector (ARCHITECTURE.md §3.2)."""

    def __init__(
        self,
        strategy_selector: StrategySelector,
        detectors: Sequence[PIIDetector] = (),
        enhancer: ContextRuleEnhancer | None = None,
    ) -> None:
        self._strategy_selector = strategy_selector
        self._detectors: tuple[PIIDetector, ...] = tuple(detectors)
        self._enhancer = enhancer or ContextRuleEnhancer()

    @property
    def filter_name(self) -> str:
        return "AnonymizationFilter"

    def _anonymize_string(
        self,
        text: str,
        entities: Sequence[DetectedEntity],
        context: PipelineContext,
        counters: dict[EntityType, int],
        placeholder_map: dict[str, str],
        results_acc: list[AnonymizationResult],
    ) -> str:
        if not entities:
            return text

        sec_context = SecurityContext(
            request_id=context.request_id,
            tenant_id=context.tenant_id,
            session_id=context.session_id,
            data_class=context.data_class,
        )

        # Replace from right to left so character offsets remain valid
        chars = list(text)
        ordered_asc = sorted(entities, key=lambda e: (e.start, e.end))
        entity_replacements: list[tuple[DetectedEntity, AnonymizationResult]] = []

        for entity in ordered_asc:
            idx = counters.get(entity.entity_type, 0) + 1
            counters[entity.entity_type] = idx
            strategy = self._strategy_selector.select(entity, sec_context)
            req = AnonymizationRequest(
                request_id=context.request_id,
                tenant_id=context.tenant_id,
                principal=context.principal,
                context=sec_context,
                entity_index=idx,
            )
            res = strategy.anonymize(entity, req)
            results_acc.append(res)
            if res.token_id is not None:
                placeholder_map[res.replacement_text] = res.token_id
            entity_replacements.append((entity, res))

        for entity, res in reversed(entity_replacements):
            chars[entity.start : entity.end] = list(res.replacement_text)

        return "".join(chars)

    def _sanitize_json_value(
        self,
        value: Any,
        context: PipelineContext,
        counters: dict[EntityType, int],
        placeholder_map: dict[str, str],
        results_acc: list[AnonymizationResult],
        entities_acc: list[DetectedEntity],
    ) -> Any:
        if isinstance(value, str):
            detected: list[DetectedEntity] = []
            for detector in self._detectors:
                detected.extend(detector.detect(value, language=context.language))
            enhanced = self._enhancer.enhance(value, detected) if detected else ()
            merged = resolve_overlapping_spans(enhanced)
            entities_acc.extend(merged)
            return self._anonymize_string(
                value, merged, context, counters, placeholder_map, results_acc
            )
        if isinstance(value, dict):
            return {
                str(k): self._sanitize_json_value(
                    v, context, counters, placeholder_map, results_acc, entities_acc
                )
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [
                self._sanitize_json_value(
                    item, context, counters, placeholder_map, results_acc, entities_acc
                )
                for item in value
            ]
        return value

    def process(self, context: PipelineContext) -> PipelineContext:
        counters: dict[EntityType, int] = {}
        placeholder_map: dict[str, str] = dict(context.placeholder_map)
        results_acc: list[AnonymizationResult] = list(context.anonymization_results)
        entities_acc: list[DetectedEntity] = list(context.detected_entities)

        sanitized_text = self._anonymize_string(
            context.current_text,
            context.detected_entities,
            context,
            counters,
            placeholder_map,
            results_acc,
        )

        sanitized_tool_call = context.tool_call
        if context.tool_call is not None:
            sanitized_args = self._sanitize_json_value(
                context.tool_call.arguments,
                context,
                counters,
                placeholder_map,
                results_acc,
                entities_acc,
            )
            sanitized_tool_call = context.tool_call.model_copy(
                update={"arguments": sanitized_args}
            )

        return context.model_copy(
            update={
                "sanitized_text": sanitized_text,
                "detected_entities": tuple(entities_acc),
                "anonymization_results": tuple(results_acc),
                "placeholder_map": placeholder_map,
                "tool_call": sanitized_tool_call,
            }
        )


class ResidencyPolicyFilter(Filter):
    """Enforces data residency via an injected ResidencyPolicyEngine (ARCHITECTURE.md §3.1)."""

    def __init__(
        self,
        policy: ResidencyPolicyEngine,
        audit_writer: AuditWriter | None = None,
    ) -> None:
        self._policy = policy
        self._audit_writer = audit_writer

    @property
    def filter_name(self) -> str:
        return "ResidencyPolicyFilter"

    def process(self, context: PipelineContext) -> PipelineContext:
        if context.target_endpoint is None:
            return context

        allowed = self._policy.is_allowed(context.data_class, context.target_endpoint)
        if not allowed:
            if self._audit_writer is not None:
                self._audit_writer.record(
                    AuditEvent(
                        event_id=f"evt_{uuid.uuid4().hex[:12]}",
                        timestamp=datetime.now(UTC),
                        action=AuditAction.RESIDENCY_CHECK,
                        outcome=AuditOutcome.BLOCKED,
                        principal_id=(
                            context.principal.principal_id
                            if context.principal
                            else "anonymous"
                        ),
                        tenant_id=context.tenant_id,
                        request_id=context.request_id,
                        reason=(
                            f"Target endpoint region {context.target_endpoint.region!r} "
                            f"violates residency policy for {context.data_class.value!r}."
                        ),
                    )
                )
            raise ResidencyViolationError(
                f"Disallowed target endpoint region {context.target_endpoint.region!r} "
                f"for data class {context.data_class.value!r}."
            )
        return context


class AuditContextFilter(Filter):
    """Records inbound pipeline completion metadata without logging raw PII."""

    def __init__(self, audit_writer: AuditWriter | None = None) -> None:
        self._audit_writer = audit_writer

    @property
    def filter_name(self) -> str:
        return "AuditContextFilter"

    def process(self, context: PipelineContext) -> PipelineContext:
        if self._audit_writer is not None and context.audit_level != AuditLevel.NONE:
            self._audit_writer.record(
                AuditEvent(
                    event_id=f"evt_{uuid.uuid4().hex[:12]}",
                    timestamp=datetime.now(UTC),
                    action=AuditAction.PIPELINE_EXECUTION,
                    outcome=AuditOutcome.COMPLETED,
                    principal_id=(
                        context.principal.principal_id if context.principal else "anonymous"
                    ),
                    tenant_id=context.tenant_id,
                    request_id=context.request_id,
                    reason=f"Anonymized {len(context.detected_entities)} entities.",
                )
            )
        return context
