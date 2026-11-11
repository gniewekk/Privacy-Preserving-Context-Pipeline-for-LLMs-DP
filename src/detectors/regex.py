"""Deterministic regex and mathematical checksum PII detectors for Poland (PL) and USA (EN)."""

from __future__ import annotations

import re
from collections.abc import Sequence

from detectors.base import PIIDetector, register_detector, resolve_overlapping_spans
from domain.models import DataClass, DetectedEntity, EntityType

# ============================================================================
# Precompiled Regex Patterns (Poland & USA, including split/spaced Level B forms)
# ============================================================================

# Poland (PL)
_PESEL_PATTERN = re.compile(
    r"(?<!\d)(?:\d{11}|\d{2}[\s\-]\d{2}[\s\-]\d{2}[\s\-]\d{3}[\s\-]\d{2}|\d{2}\s\d{2}\s\d{2}\s\d{5})(?!\d)"
)
_NIP_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(?:PL\s*)?(?:\d{10}|\d{3}[\s\-]\d{3}[\s\-]\d{2}[\s\-]\d{2}|\d{3}[\s\-]\d{2}[\s\-]\d{2}[\s\-]\d{3})(?!\d)"
)
_REGON_PATTERN = re.compile(r"(?<!\d)(?:\d{14}|\d{9})(?!\d)")
_IBAN_PATTERN = re.compile(
    r"\b[A-Z]{2}\s*\d{2}(?:[\s\-]*[A-Z0-9]{4}){3,7}(?:[\s\-]*[A-Z0-9]{1,4})?\b"
)
_ID_CARD_PATTERN = re.compile(r"\b[A-Z]{3}\s?\d{6}\b")

# USA (EN) & International
_SSN_OR_ITIN_PATTERN = re.compile(r"(?<!\d)\d{3}[\s\-]\d{2}[\s\-]\d{4}(?!\d)")
_EIN_PATTERN = re.compile(r"(?<!\d)\d{2}-\d{7}(?!\d)")
_ABA_ROUTING_PATTERN = re.compile(r"(?<!\d)\d{9}(?!\d)")
_CREDIT_CARD_PATTERN = re.compile(
    r"(?<!\d)(?:\d{4}[\s\-]){3}\d{4}(?!\d)|(?<!\d)\d{16}(?!\d)"
)
_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_PHONE_PATTERN = re.compile(
    r"(?<!\d)(?:\+\d{1,3}[\s\-]?)?(?:\(\d{2,3}\)[\s\-]?|\d{3}[\s\-])\d{3}[\s\-]\d{3,4}(?!\d)"
)

# Official IRS valid 2-digit EIN Campus Prefixes
_VALID_IRS_EIN_PREFIXES: frozenset[str] = frozenset(
    {
        "01",
        "02",
        "03",
        "04",
        "05",
        "06",
        "10",
        "11",
        "12",
        "13",
        "14",
        "15",
        "16",
        "20",
        "21",
        "22",
        "23",
        "24",
        "25",
        "26",
        "27",
        "30",
        "31",
        "32",
        "33",
        "34",
        "35",
        "36",
        "37",
        "38",
        "39",
        "40",
        "41",
        "42",
        "43",
        "44",
        "45",
        "46",
        "47",
        "48",
        "50",
        "51",
        "52",
        "53",
        "54",
        "55",
        "56",
        "57",
        "58",
        "59",
        "60",
        "61",
        "62",
        "63",
        "64",
        "65",
        "66",
        "67",
        "68",
        "71",
        "72",
        "73",
        "74",
        "75",
        "76",
        "77",
        "80",
        "81",
        "82",
        "83",
        "84",
        "85",
        "86",
        "87",
        "88",
        "90",
        "91",
        "92",
        "93",
        "94",
        "95",
        "98",
        "99",
    }
)


# ============================================================================
# Polish Official Checksum Validators (PESEL, NIP, REGON, IBAN, ID_CARD)
# ============================================================================


def validate_pesel_checksum(raw: str) -> bool:
    """Validate an 11-digit Polish PESEL using Modulo-10 weights and date sanity."""
    digits = re.sub(r"[\s\-]", "", raw)
    if len(digits) != 11 or not digits.isdigit():
        return False

    month = int(digits[2:4])
    day = int(digits[4:6])
    base_month = month % 20
    if not (1 <= base_month <= 12 and 1 <= day <= 31):
        return False

    weights = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    checksum = sum(int(digits[i]) * weights[i] for i in range(10))
    control = (10 - (checksum % 10)) % 10
    return control == int(digits[10])


def validate_nip_checksum(raw: str) -> bool:
    """Validate a 10-digit Polish NIP using Modulo-11 weights."""
    cleaned = re.sub(r"^(?:PL\s*)", "", raw, flags=re.IGNORECASE)
    digits = re.sub(r"[\s\-]", "", cleaned)
    if len(digits) != 10 or not digits.isdigit():
        return False

    weights = (6, 5, 7, 2, 3, 4, 5, 6, 7)
    checksum = sum(int(digits[i]) * weights[i] for i in range(9)) % 11
    if checksum == 10:
        return False
    return checksum == int(digits[9])


def validate_regon_checksum(raw: str) -> bool:
    """Validate a 9-digit or 14-digit Polish REGON using Modulo-11 weights."""
    digits = re.sub(r"[\s\-]", "", raw)
    if not digits.isdigit() or len(digits) not in (9, 14):
        return False

    weights_9 = (8, 9, 2, 3, 4, 5, 6, 7)
    checksum_9 = sum(int(digits[i]) * weights_9[i] for i in range(8)) % 11
    control_9 = 0 if checksum_9 == 10 else checksum_9
    if control_9 != int(digits[8]):
        return False

    if len(digits) == 14:
        weights_14 = (2, 4, 8, 5, 0, 9, 7, 3, 6, 1, 2, 4, 8)
        checksum_14 = sum(int(digits[i]) * weights_14[i] for i in range(13)) % 11
        control_14 = 0 if checksum_14 == 10 else checksum_14
        return control_14 == int(digits[13])

    return True


def validate_iban_checksum(raw: str) -> bool:
    """Validate an IBAN (including 28-char Polish PL IBAN) using ISO 13616 Modulo-97."""
    compact = re.sub(r"[\s\-]", "", raw).upper()
    if len(compact) < 15 or len(compact) > 34 or not compact.isalnum():
        return False
    if compact.startswith("PL") and len(compact) != 28:
        return False

    rearranged = compact[4:] + compact[:4]
    numeric_chars: list[str] = []
    for ch in rearranged:
        if ch.isdigit():
            numeric_chars.append(ch)
        elif "A" <= ch <= "Z":
            numeric_chars.append(str(ord(ch) - ord("A") + 10))
        else:
            return False

    return int("".join(numeric_chars)) % 97 == 1


def validate_polish_id_card_checksum(raw: str) -> bool:
    """Validate a Polish ID card number (3 letters + 6 digits) using ICAO 7-3-1 Modulo-10."""
    compact = re.sub(r"\s+", "", raw).upper()
    if len(compact) != 9 or not compact[:3].isalpha() or not compact[3:].isdigit():
        return False

    weights = (7, 3, 1, 0, 7, 3, 1, 7, 3)
    total = 0
    for idx, ch in enumerate(compact):
        val = (ord(ch) - ord("A") + 10) if ch.isalpha() else int(ch)
        total += val * weights[idx]

    check_digit = int(compact[3])
    return (total % 10) == check_digit


# ============================================================================
# US Official Checksum & Structural Validators (SSN, ITIN, EIN, ABA, Luhn)
# ============================================================================


def validate_us_ssn(raw: str) -> bool:
    """Validate a 9-digit US Social Security Number (SSN) per official SSA rules.

    SSA Rules:
    - Area number (first 3 digits) cannot be 000, 666, or 900-999 (reserved for ITIN).
    - Group number (middle 2 digits) cannot be 00.
    - Serial number (last 4 digits) cannot be 0000.
    """
    digits = re.sub(r"[\s\-]", "", raw)
    if len(digits) != 9 or not digits.isdigit():
        return False

    area = int(digits[:3])
    group = int(digits[3:5])
    serial = int(digits[5:])

    if area in (0, 666) or area >= 900:
        return False
    return group != 0 and serial != 0


def validate_us_itin(raw: str) -> bool:
    """Validate a 9-digit US Individual Taxpayer Identification Number (ITIN) per IRS rules.

    IRS Rules:
    - Always 9 digits beginning with '9'.
    - 4th and 5th digits (middle two digits) must be in ranges: 50-65, 70-88, 90-92, or 94-99.
    - Last 4 digits cannot be 0000.
    """
    digits = re.sub(r"[\s\-]", "", raw)
    if len(digits) != 9 or not digits.isdigit() or digits[0] != "9":
        return False

    middle = int(digits[3:5])
    serial = int(digits[5:])
    valid_middle = (
        (50 <= middle <= 65)
        or (70 <= middle <= 88)
        or (90 <= middle <= 92)
        or (94 <= middle <= 99)
    )
    return valid_middle and serial != 0


def validate_us_ein(raw: str) -> bool:
    """Validate a 9-digit US Employer Identification Number (EIN, XX-XXXXXXX) per IRS rules.

    IRS Rules:
    - First 2 digits must match an official IRS Campus Prefix.
    - Last 7 digits cannot be 0000000.
    """
    digits = re.sub(r"[\s\-]", "", raw)
    if len(digits) != 9 or not digits.isdigit():
        return False

    prefix = digits[:2]
    sequence = int(digits[2:])
    return prefix in _VALID_IRS_EIN_PREFIXES and sequence != 0


def validate_aba_routing_checksum(raw: str) -> bool:
    """Validate a 9-digit US ABA Routing Transit Number (RTN) using Federal Reserve & Mod-10 rules.

    ABA Rules:
    - First 2 digits (Federal Reserve Routing Symbol) must be in 00-12, 21-32, 61-72, or 80.
    - Weighted Modulo-10 checksum with weights (3, 7, 1, 3, 7, 1, 3, 7, 1) must be divisible by 10.
    """
    digits = re.sub(r"[\s\-]", "", raw)
    if len(digits) != 9 or not digits.isdigit():
        return False

    fed_symbol = int(digits[:2])
    valid_fed = (
        (0 <= fed_symbol <= 12)
        or (21 <= fed_symbol <= 32)
        or (61 <= fed_symbol <= 72)
        or fed_symbol == 80
    )
    if not valid_fed:
        return False

    weights = (3, 7, 1, 3, 7, 1, 3, 7, 1)
    checksum = sum(int(digits[i]) * weights[i] for i in range(9))
    return (checksum % 10) == 0


def validate_luhn_checksum(raw: str) -> bool:
    """Validate a 13-to-19 digit payment card number using ISO/IEC 7812 Luhn Mod-10."""
    digits = re.sub(r"[\s\-]", "", raw)
    if not (13 <= len(digits) <= 19) or not digits.isdigit():
        return False
    if len(set(digits)) == 1:
        return False

    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        n = int(ch)
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return (total % 10) == 0


@register_detector("regex")
class RegexPIIDetector(PIIDetector):
    """Deterministic regex + checksum PII detector supporting Poland (PL) and USA (EN)."""

    @property
    def detector_id(self) -> str:
        return "regex_pii_detector"

    def detect(self, text: str, language: str = "en") -> Sequence[DetectedEntity]:
        """Scan `text` for Polish, US, and international structured PII identifiers."""
        detected: list[DetectedEntity] = []

        # 1. IBAN (ISO 13616 Mod-97)
        for match in _IBAN_PATTERN.finditer(text):
            candidate = match.group(0)
            if validate_iban_checksum(candidate):
                detected.append(
                    DetectedEntity(
                        entity_type=EntityType.IBAN,
                        start=match.start(),
                        end=match.end(),
                        raw_value=candidate,
                        confidence=1.0,
                        data_class=DataClass.FINANCIAL,
                        detector_id=self.detector_id,
                    )
                )

        # 2. Credit Card (ISO/IEC 7812 Luhn Mod-10)
        for match in _CREDIT_CARD_PATTERN.finditer(text):
            candidate = match.group(0)
            if validate_luhn_checksum(candidate):
                detected.append(
                    DetectedEntity(
                        entity_type=EntityType.CREDIT_CARD,
                        start=match.start(),
                        end=match.end(),
                        raw_value=candidate,
                        confidence=0.99,
                        data_class=DataClass.FINANCIAL,
                        detector_id=self.detector_id,
                    )
                )

        # 3. Polish PESEL (Mod-10 + Date)
        for match in _PESEL_PATTERN.finditer(text):
            candidate = match.group(0)
            if validate_pesel_checksum(candidate):
                detected.append(
                    DetectedEntity(
                        entity_type=EntityType.PESEL,
                        start=match.start(),
                        end=match.end(),
                        raw_value=candidate,
                        confidence=1.0,
                        data_class=DataClass.CONFIDENTIAL,
                        detector_id=self.detector_id,
                    )
                )

        # 4. Polish NIP (Mod-11)
        for match in _NIP_PATTERN.finditer(text):
            candidate = match.group(0)
            if validate_nip_checksum(candidate):
                detected.append(
                    DetectedEntity(
                        entity_type=EntityType.NIP,
                        start=match.start(),
                        end=match.end(),
                        raw_value=candidate,
                        confidence=0.98,
                        data_class=DataClass.FINANCIAL,
                        detector_id=self.detector_id,
                    )
                )

        # 5. US SSN & US ITIN (SSA / IRS rules)
        for match in _SSN_OR_ITIN_PATTERN.finditer(text):
            candidate = match.group(0)
            if validate_us_ssn(candidate):
                detected.append(
                    DetectedEntity(
                        entity_type=EntityType.SSN,
                        start=match.start(),
                        end=match.end(),
                        raw_value=candidate,
                        confidence=0.99,
                        data_class=DataClass.CONFIDENTIAL,
                        detector_id=self.detector_id,
                    )
                )
            elif validate_us_itin(candidate):
                detected.append(
                    DetectedEntity(
                        entity_type=EntityType.ITIN,
                        start=match.start(),
                        end=match.end(),
                        raw_value=candidate,
                        confidence=0.99,
                        data_class=DataClass.FINANCIAL,
                        detector_id=self.detector_id,
                    )
                )

        # 6. US EIN (IRS Campus Prefix rules)
        for match in _EIN_PATTERN.finditer(text):
            candidate = match.group(0)
            if validate_us_ein(candidate):
                detected.append(
                    DetectedEntity(
                        entity_type=EntityType.EIN,
                        start=match.start(),
                        end=match.end(),
                        raw_value=candidate,
                        confidence=0.97,
                        data_class=DataClass.FINANCIAL,
                        detector_id=self.detector_id,
                    )
                )

        # 7. US ABA Routing Transit Number (3-7-1 Mod-10) & Polish REGON (Mod-11)
        for match in _REGON_PATTERN.finditer(text):
            candidate = match.group(0)
            is_en_aba = (
                language == "en"
                and len(candidate) == 9
                and validate_aba_routing_checksum(candidate)
            )
            if is_en_aba:
                detected.append(
                    DetectedEntity(
                        entity_type=EntityType.ABA_ROUTING,
                        start=match.start(),
                        end=match.end(),
                        raw_value=candidate,
                        confidence=0.96,
                        data_class=DataClass.FINANCIAL,
                        detector_id=self.detector_id,
                    )
                )
            elif validate_regon_checksum(candidate):
                detected.append(
                    DetectedEntity(
                        entity_type=EntityType.REGON,
                        start=match.start(),
                        end=match.end(),
                        raw_value=candidate,
                        confidence=0.95,
                        data_class=DataClass.FINANCIAL,
                        detector_id=self.detector_id,
                    )
                )
            elif len(candidate) == 9 and validate_aba_routing_checksum(candidate):
                detected.append(
                    DetectedEntity(
                        entity_type=EntityType.ABA_ROUTING,
                        start=match.start(),
                        end=match.end(),
                        raw_value=candidate,
                        confidence=0.95,
                        data_class=DataClass.FINANCIAL,
                        detector_id=self.detector_id,
                    )
                )

        # 8. Polish ID Card (ICAO 7-3-1 Mod-10)
        for match in _ID_CARD_PATTERN.finditer(text):
            candidate = match.group(0)
            if validate_polish_id_card_checksum(candidate):
                detected.append(
                    DetectedEntity(
                        entity_type=EntityType.ID_CARD,
                        start=match.start(),
                        end=match.end(),
                        raw_value=candidate,
                        confidence=0.99,
                        data_class=DataClass.CONFIDENTIAL,
                        detector_id=self.detector_id,
                    )
                )

        # 9. Email addresses
        for match in _EMAIL_PATTERN.finditer(text):
            detected.append(
                DetectedEntity(
                    entity_type=EntityType.EMAIL,
                    start=match.start(),
                    end=match.end(),
                    raw_value=match.group(0),
                    confidence=0.99,
                    data_class=DataClass.CONFIDENTIAL,
                    detector_id=self.detector_id,
                )
            )

        # 10. Phone numbers
        for match in _PHONE_PATTERN.finditer(text):
            detected.append(
                DetectedEntity(
                    entity_type=EntityType.PHONE,
                    start=match.start(),
                    end=match.end(),
                    raw_value=match.group(0),
                    confidence=0.90,
                    data_class=DataClass.CONFIDENTIAL,
                    detector_id=self.detector_id,
                )
            )

        return resolve_overlapping_spans(detected)
