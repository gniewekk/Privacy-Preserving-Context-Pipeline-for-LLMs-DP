"""Detektor Quasi-Identyfikatorów (QID: Wiek, Zawód, Lokalizacja).

Obsługuje język polski (PL) i angielski (EN):
1. Wiek (AGE): wzorce liczbowo-tekstowe z ekstrakcją wartości numerycznej.
2. Zawód (PROFESSION): słownik ISCO-08 / KZiS oraz reguły kontekstowe.
3. Lokalizacja (LOCATION): słownik TERYT / GeoNames oraz reguły kontekstowe.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from domain.models import DetectedEntity, EntityCategory, EntityType, Language
from resources.stats.prevalence import DemographicStats
from resources.taxonomies.geography import GEO_ALIASES, GEO_NODES, GeographyTaxonomy
from resources.taxonomies.occupations import OCCUPATION_ALIASES, ISCO_NODES, OccupationTaxonomy


class QIDDetector:
    """Wielojęzyczny detektor Quasi-Identyfikatorów (wiek, zawód, lokalizacja)."""

    detector_id: str = "qid_detector_multilingual"

    # Wzorce wieku: PL i EN
    _AGE_PATTERNS_PL = (
        re.compile(r"(?i)\b(?:lat\s+(\d{1,3})|(\d{1,3})\s+lat(?:a)?)\b"),
        re.compile(r"(?i)\b(?:wiek(?:u)?\s*[:#-]?\s*(\d{1,3})(?:\s+lat(?:a)?)?)\b"),
    )
    _AGE_PATTERNS_EN = (
        re.compile(r"(?i)\b(?:(\d{1,3})\s*(?:years?\s+old|-year-old|yo))\b"),
        re.compile(r"(?i)\b(?:age\s*[:#-]?\s*(\d{1,3})|aged\s+(\d{1,3}))\b"),
    )

    # Kontekstowe reguły dla zawodu
    _PROFESSION_CONTEXT_PL = re.compile(
        r"(?i)\b(?:zawód|stanowisko|specjalizacja|pracuje\s+jako)\s*[:#-]?\s*([a-ząćęłńóśźż]+(?:\s+[a-ząćęłńóśźż]+)?)"
    )
    _PROFESSION_CONTEXT_EN = re.compile(
        r"(?i)\b(?:profession|occupation|position|works\s+as\s+(?:a\s+|an\s+)?)\s*[:#-]?\s*([a-z]+(?:\s+[a-z]+)?)"
    )

    # Kontekstowe reguły dla lokalizacji
    _LOCATION_CONTEXT_PL = re.compile(
        r"(?i)\b(?:miejsce\s+zamieszkania|miejscowość|zamieszkał[ya]\s+w|miasto|gmina)\s*[:#-]?\s*([A-ZĄĆĘŁŃÓŚŹŻ][a-ząćęłńóśźż]+(?:\s+[A-ZĄĆĘŁŃÓŚŹŻ][a-ząćęłńóśźż]+)?)"
    )
    _LOCATION_CONTEXT_EN = re.compile(
        r"(?i)\b(?:residence|city|lives\s+in|residing\s+in|location)\s*[:#-]?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)"
    )

    def detect(self, text: str, language: Language) -> Sequence[DetectedEntity]:
        entities: list[DetectedEntity] = []

        # 1. Ekstrakcja wieku (AGE)
        age_patterns = self._AGE_PATTERNS_PL if language == Language.PL else self._AGE_PATTERNS_EN
        for pattern in age_patterns:
            for match in pattern.finditer(text):
                full_val = match.group(0)
                num = DemographicStats.extract_age_number(full_val)
                if num is not None:
                    entities.append(
                        DetectedEntity(
                            entity_type=EntityType.AGE,
                            category=EntityCategory.QUASI_IDENTIFIER,
                            start=match.start(),
                            end=match.end(),
                            value=full_val,
                            confidence=0.95,
                            detector_id=self.detector_id,
                            canonical_id="AGE",
                            numeric_value=num,
                        )
                    )

        # 2. Ekstrakcja zawodu (PROFESSION) - słownik ISCO-08 + aliasy
        all_occupation_terms = list(OCCUPATION_ALIASES.keys())
        for term in sorted(all_occupation_terms, key=len, reverse=True):
            pattern = re.compile(rf"(?<![\wąćęłńóśźż])({re.escape(term)})(?![\wąćęłńóśźż])", re.IGNORECASE)
            for m in pattern.finditer(text):
                code = OCCUPATION_ALIASES[term.lower()]
                entities.append(
                    DetectedEntity(
                        entity_type=EntityType.PROFESSION,
                        category=EntityCategory.QUASI_IDENTIFIER,
                        start=m.start(1),
                        end=m.end(1),
                        value=m.group(1),
                        confidence=0.92,
                        detector_id=self.detector_id,
                        canonical_id=code,
                    )
                )

        # Kontekstowe reguły zawodu
        prof_context = self._PROFESSION_CONTEXT_PL if language == Language.PL else self._PROFESSION_CONTEXT_EN
        for match in prof_context.finditer(text):
            val = match.group(1).strip()
            node = OccupationTaxonomy.lookup(val)
            entities.append(
                DetectedEntity(
                    entity_type=EntityType.PROFESSION,
                    category=EntityCategory.QUASI_IDENTIFIER,
                    start=match.start(1),
                    end=match.end(1),
                    value=val,
                    confidence=0.85 if node else 0.70,
                    detector_id=self.detector_id,
                    canonical_id=node.code if node else None,
                )
            )

        # 3. Ekstrakcja lokalizacji (LOCATION) - słownik TERYT / GeoNames + aliasy
        all_geo_terms = list(GEO_ALIASES.keys())
        for term in sorted(all_geo_terms, key=len, reverse=True):
            if term in {"us", "usa", "polska"}:  # kraje ignorujemy jako domyślne punkty wyjścia
                continue
            pattern = re.compile(rf"(?<![\wąćęłńóśźż])({re.escape(term)})(?![\wąćęłńóśźż])", re.IGNORECASE)
            for m in pattern.finditer(text):
                node_id = GEO_ALIASES[term.lower()]
                entities.append(
                    DetectedEntity(
                        entity_type=EntityType.LOCATION,
                        category=EntityCategory.QUASI_IDENTIFIER,
                        start=m.start(1),
                        end=m.end(1),
                        value=m.group(1),
                        confidence=0.93,
                        detector_id=self.detector_id,
                        canonical_id=node_id,
                    )
                )

        # Kontekstowe reguły lokalizacji
        loc_context = self._LOCATION_CONTEXT_PL if language == Language.PL else self._LOCATION_CONTEXT_EN
        for match in loc_context.finditer(text):
            val = match.group(1).strip()
            gnode = GeographyTaxonomy.lookup(val)
            entities.append(
                DetectedEntity(
                    entity_type=EntityType.LOCATION,
                    category=EntityCategory.QUASI_IDENTIFIER,
                    start=match.start(1),
                    end=match.end(1),
                    value=val,
                    confidence=0.88 if gnode else 0.70,
                    detector_id=self.detector_id,
                    canonical_id=gnode.canonical_id if gnode else None,
                )
            )

        return self._resolve_overlaps(entities)

    @staticmethod
    def _resolve_overlaps(entities: list[DetectedEntity]) -> list[DetectedEntity]:
        if not entities:
            return []
        sorted_entities = sorted(entities, key=lambda e: (e.start, -(e.end - e.start), -e.confidence))
        result: list[DetectedEntity] = []
        for e in sorted_entities:
            if not any(e.overlaps(existing) for existing in result):
                result.append(e)
        return sorted(result, key=lambda e: (e.start, e.end))

