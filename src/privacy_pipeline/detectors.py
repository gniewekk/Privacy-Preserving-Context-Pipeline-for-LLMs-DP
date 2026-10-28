from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Protocol

from .models import DetectedEntity


class NERDetector(Protocol):
    def detect(self, text: str) -> Iterable[DetectedEntity]: ...


class HeuristicPolishNERDetector:
    """Dependency-free fallback for simple PERSON mentions.

    This is intentionally conservative and is not a replacement for a trained
    Polish NER model. It only catches adjacent capitalized words in natural
    text, e.g. ``Jan Kowalski``.
    """

    _name_pair = re.compile(
        r"(?<![\w-])([A-ZĄĆĘŁŃÓŚŹŻ][a-ząćęłńóśźż]+)"
        r"\s+([A-ZĄĆĘŁŃÓŚŹŻ][a-ząćęłńóśźż]+)(?![\w-])"
    )
    _excluded = {
        "Kontakt",
        "Numer",
        "Dane",
    }

    def detect(self, text: str) -> list[DetectedEntity]:
        entities: list[DetectedEntity] = []
        for match in self._name_pair.finditer(text):
            first_name, surname = match.groups()
            if first_name in self._excluded or surname in self._excluded:
                continue
            entities.append(
                DetectedEntity(
                    entity_type="PERSON",
                    value=match.group(),
                    start=match.start(),
                    end=match.end(),
                )
            )
        # Labelled name fields may be followed by punctuation or prose; scan
        # the value itself so labels such as "Kontakt:" don't hide the name.
        for match in re.finditer(r"(?i)\b(?:kontakt|imię i nazwisko|osoba)\s*[:#-]\s*([^,.;]+)", text):
            value = match.group(1).strip()
            name = self._name_pair.fullmatch(value)
            if name and name.group(1) not in self._excluded and name.group(2) not in self._excluded:
                start = match.start(1) + len(match.group(1)) - len(match.group(1).lstrip())
                entities.append(DetectedEntity("PERSON", value, start, start + len(value)))
        return entities


class TransformerNERDetector:
    """Transformer-backed NER adapter.

    The model is loaded lazily, so importing the package does not download
    anything. Use a Polish model fine-tuned for token classification, not the
    plain ``allegro/herbert-base-cased`` language model.
    """

    def __init__(
        self,
        model_name: str,
        *,
        aggregation_strategy: str = "simple",
        min_score: float = 0.70,
    ) -> None:
        self.model_name = model_name
        self.aggregation_strategy = aggregation_strategy
        self.min_score = min_score
        self._pipeline = None

    def _load(self):
        if self._pipeline is None:
            try:
                from transformers import pipeline
            except ImportError as exc:
                raise RuntimeError(
                    "Transformer NER requires the 'ner' extra: uv sync --extra ner"
                ) from exc
            self._pipeline = pipeline(
                "token-classification",
                model=self.model_name,
                aggregation_strategy=self.aggregation_strategy,
            )
        return self._pipeline

    def detect(self, text: str) -> list[DetectedEntity]:
        results = self._load()(text)
        entities: list[DetectedEntity] = []
        for result in results:
            score = float(result.get("score", 0.0))
            label = str(result.get("entity_group", result.get("entity", ""))).upper()
            if score < self.min_score:
                continue
            if "PER" in label:
                entity_type = "PERSON"
            elif "ORG" in label:
                entity_type = "ORGANIZATION"
            elif "LOC" in label or "GPE" in label:
                entity_type = "LOCATION"
            else:
                continue
            start = int(result["start"])
            end = int(result["end"])
            entities.append(
                DetectedEntity(entity_type, text[start:end], start, end)
            )
        return entities


class PIIRegistry:
    """Combines deterministic identifiers, context rules and optional NER."""

    _custom_detectors: dict[str, tuple[int, object]] = {}

    @classmethod
    def register_detector(cls, entity_type: str, *, priority: int = 100):
        def decorator(detector_cls):
            cls._custom_detectors[entity_type] = (priority, detector_cls)
            return detector_cls

        return decorator

    _patterns = (
        ("ADDRESS", re.compile(r"(?i)(?<!\w)(?:ul(?:ica)?\.?|al(?:eja)?\.?|pl(?:ac)?\.?)\s+[\wąćęłńóśźż-]+(?:\s+[\wąćęłńóśźż-]+)*\s+\d+[A-Za-z]?(?:/\d+)?(?:,?\s+\d{2}-\d{3}\s+[\wąćęłńóśźż-]+(?:\s+[\wąćęłńóśźż-]+)*)?")),
        ("ORGANIZATION", re.compile(r"(?<!\w)[A-ZĄĆĘŁŃÓŚŹŻ][\w&.-]*\s+(?i:sp\.?\s*z\s*o\.?\s*o\.?|s\.?a\.?|s\.?c\.?|llc|ltd\.?|inc\.?|gmbh|fundacja|stowarzyszenie)")),
        ("EMAIL", re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+\.[A-Za-z]{2,}(?!\w)")),
        (
            "PHONE",
            re.compile(r"(?<!\d)(?:\+48[\s-]?)?(?:\d[\s-]?){9}(?!\d)"),
        ),
        ("PESEL", re.compile(r"(?<!\d)\d{11}(?!\d)")),
        ("NIP", re.compile(r"(?<!\d)(?:\d{3}[- ]?){2}\d{2}[- ]?\d{2}(?!\d)")),
        ("REGON", re.compile(r"(?<!\d)(?:\d{9}|\d{14})(?!\d)")),
        ("IBAN", re.compile(r"(?<![A-Z0-9])PL\s?\d{2}(?:\s?\d{4}){6}(?![A-Z0-9])")),
        ("ID_CARD", re.compile(r"(?<![A-Z0-9])[A-Z]{3}\s?\d{6}(?![A-Z0-9])")),
    )
    _context_patterns = (
        ("PESEL", re.compile(r"(?i)\bpesel\b\s*[:#-]?\s*(\d{11})")),
        ("DIAGNOSIS", re.compile(r"(?i)\bdiagnoz(?:a|ie|ę)\b\s*[:#-]?\s*([^,.]+)")),
        ("DATE_OF_BIRTH", re.compile(r"(?i)\bur\.\s*(\d{1,2}[./-]\d{1,2}[./-]\d{2,4})")),
    )

    @classmethod
    def detect(
        cls, text: str, ner_detector: NERDetector | None = None
    ) -> list[DetectedEntity]:
        entities: list[DetectedEntity] = []
        for entity_type, pattern in cls._patterns:
            for match in pattern.finditer(text):
                value = cls._normalize(entity_type, match.group())
                if not cls._valid(entity_type, value):
                    continue
                entities.append(
                    DetectedEntity(entity_type, value, match.start(), match.end())
                )
        for entity_type, pattern in cls._context_patterns:
            for match in pattern.finditer(text):
                value = match.group(1).strip()
                if not value:
                    continue
                start, end = match.start(1), match.end(1)
                entities.append(DetectedEntity(entity_type, value, start, end))
        for entity_type, (_, detector_cls) in sorted(
            cls._custom_detectors.items(), key=lambda item: item[1][0]
        ):
            detector = detector_cls()
            entities.extend(detector.detect(text))
        if ner_detector is None:
            ner_detector = HeuristicPolishNERDetector()
        entities.extend(ner_detector.detect(text))
        return cls._remove_overlaps(entities)

    @staticmethod
    def _normalize(entity_type: str, value: str) -> str:
        if entity_type in {"NIP", "REGON", "IBAN", "ID_CARD"}:
            return value.replace(" ", "").replace("-", "")
        return value

    @staticmethod
    def _valid(entity_type: str, value: str) -> bool:
        if entity_type == "PESEL":
            return PIIRegistry._valid_pesel(value)
        if entity_type == "NIP":
            digits = value
            if len(digits) != 10:
                return False
            return sum(int(digit) * weight for digit, weight in zip(digits, (6, 5, 7, 2, 3, 4, 5, 6, 7))) % 11 == int(digits[-1])
        if entity_type == "REGON":
            weights = (8, 9, 2, 3, 4, 5, 6, 7) if len(value) == 9 else (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5, 6)
            return sum(int(digit) * weight for digit, weight in zip(value, weights)) % 11 == int(value[-1])
        if entity_type == "IBAN":
            rearranged = value[4:] + value[:4]
            numeric = "".join(str(ord(char) - 55) if char.isalpha() else char for char in rearranged)
            return int(numeric) % 97 == 1
        return True

    @staticmethod
    def _valid_pesel(value: str) -> bool:
        weights = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
        checksum = (10 - sum(int(digit) * weight for digit, weight in zip(value, weights)) % 10) % 10
        return checksum == int(value[-1])

    @staticmethod
    def _remove_overlaps(entities: list[DetectedEntity]) -> tuple[DetectedEntity, ...]:
        result: list[DetectedEntity] = []
        for entity in sorted(entities, key=lambda item: (item.start, -(item.end - item.start))):
            if any(entity.start < existing.end and existing.start < entity.end for existing in result):
                continue
            result.append(entity)
        return tuple(sorted(result, key=lambda item: (item.start, item.end)))
