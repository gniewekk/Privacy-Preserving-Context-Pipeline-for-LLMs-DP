"""Strategy pattern implementations for PII/PHI detection (English & Polish)."""

from detectors.base import (
    DetectorRegistry,
    PIIDetector,
    register_detector,
    resolve_overlapping_spans,
)
from detectors.heuristic import ContextRuleEnhancer, HeuristicPIIDetector
from detectors.ner import (
    DEFAULT_ENGLISH_NER_MODEL,
    DEFAULT_POLISH_FINETUNED_NER_MODEL,
    DEFAULT_POLISH_NER_MODEL,
    EnglishTransformerNERDetector,
    NERPIIDetector,
    PolishTransformerNERDetector,
)
from detectors.regex import (
    RegexPIIDetector,
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

__all__ = [
    "ContextRuleEnhancer",
    "DEFAULT_ENGLISH_NER_MODEL",
    "DEFAULT_POLISH_FINETUNED_NER_MODEL",
    "DEFAULT_POLISH_NER_MODEL",
    "DetectorRegistry",
    "EnglishTransformerNERDetector",
    "HeuristicPIIDetector",
    "NERPIIDetector",
    "PIIDetector",
    "PolishTransformerNERDetector",
    "RegexPIIDetector",
    "register_detector",
    "resolve_overlapping_spans",
    "validate_aba_routing_checksum",
    "validate_iban_checksum",
    "validate_luhn_checksum",
    "validate_nip_checksum",
    "validate_pesel_checksum",
    "validate_polish_id_card_checksum",
    "validate_regon_checksum",
    "validate_us_ein",
    "validate_us_itin",
    "validate_us_ssn",
]
