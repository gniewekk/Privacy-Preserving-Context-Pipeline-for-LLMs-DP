"""Tabele statystyczne częstości występowania cech demograficznych (PL: GUS, EN: US Census).

Służy do estymacji k-anonimowości:
    k_hat = N_pop * prod(P(Q_i))
gdzie P(Q_i) to prawdopodobieństwo a priori danej cechy (wiek, zawód, lokalizacja)
w populacji referencyjnej.
"""

from __future__ import annotations

import re
from typing import Mapping

from domain.models import Language
from resources.taxonomies.geography import (
    POLAND_POPULATION,
    US_POPULATION,
    GeographyTaxonomy,
)
from resources.taxonomies.occupations import OccupationTaxonomy

# Rozkład piramidy wieku (udział dekad w populacji)
AGE_DECADE_DISTRIBUTION: Mapping[Language, dict[tuple[int, int], float]] = {
    Language.PL: {
        (0, 10): 0.095,
        (10, 20): 0.100,
        (20, 30): 0.105,
        (30, 40): 0.150,
        (40, 50): 0.160,
        (50, 60): 0.125,
        (60, 70): 0.135,
        (70, 80): 0.085,
        (80, 90): 0.035,
        (90, 120): 0.010,
    },
    Language.EN: {
        (0, 10): 0.115,
        (10, 20): 0.125,
        (20, 30): 0.135,
        (30, 40): 0.135,
        (40, 50): 0.125,
        (50, 60): 0.125,
        (60, 70): 0.115,
        (70, 80): 0.075,
        (80, 90): 0.035,
        (90, 120): 0.015,
    },
}

_AGE_NUM_REGEX = re.compile(r"(\d{1,3})")


class DemographicStats:
    """Modele statystyczne i prawdopodobieństwa brzegowe dla PL i EN."""

    @classmethod
    def get_population(cls, language: Language) -> int:
        return POLAND_POPULATION if language == Language.PL else US_POPULATION

    @classmethod
    def extract_age_number(cls, raw_text: str) -> int | None:
        m = _AGE_NUM_REGEX.search(raw_text)
        if not m:
            return None
        val = int(m.group(1))
        return val if 0 <= val <= 120 else None

    @classmethod
    def get_age_probability(cls, age: int, level: int, language: Language) -> float:
        """Prawdopodobieństwo wieku dla zadanego poziomu uogólnienia."""
        distribution = AGE_DECADE_DISTRIBUTION.get(language, AGE_DECADE_DISTRIBUTION[Language.EN])
        clamped = min(max(age, 0), 119)
        lower_decade = (clamped // 10) * 10
        upper_decade = lower_decade + 10
        decade_prob = distribution.get((lower_decade, upper_decade), 0.08)

        if level <= 0:
            # Pojedynczy rocznik to ok. 1/10 dekady
            return decade_prob / 10.0
        if level == 1:
            # Przedział 10-letni
            return decade_prob
        if level == 2:
            # Przedział 20-letni
            lower_b = (clamped // 20) * 20
            p1 = distribution.get((lower_b, lower_b + 10), 0.06)
            p2 = distribution.get((lower_b + 10, lower_b + 20), 0.06)
            return p1 + p2
        # Poziom 3: szeroka kategoria (dziecko / dorosły / senior)
        if clamped < 18:
            return 0.20
        if clamped >= 65:
            return 0.18
        return 0.62

    @classmethod
    def generalize_age(cls, raw_text: str, steps: int, language: Language) -> str:
        """Uogólnia wiek w zadanym języku."""
        if steps <= 0:
            return raw_text
        age = cls.extract_age_number(raw_text)
        if age is None:
            return raw_text

        if steps == 1:
            low = (age // 10) * 10
            high = low + 10
            if language == Language.PL:
                return f"lat {low}-{high}" if "lat " in raw_text.lower() else f"{low}-{high} lat"
            return f"{low}-{high} years old"

        if steps == 2:
            low = (age // 20) * 20
            high = low + 20
            if language == Language.PL:
                return f"lat {low}-{high}" if "lat " in raw_text.lower() else f"{low}-{high} lat"
            return f"{low}-{high} years old"

        # steps >= 3
        if age < 18:
            return "osoba niepełnoletnia" if language == Language.PL else "minor"
        if age >= 65:
            return "senior (65+ lat)" if language == Language.PL else "senior (65+)"
        return "osoba dorosła" if language == Language.PL else "adult"

    @classmethod
    def get_qid_probability(
        cls,
        dimension_id: str,
        value: str,
        language: Language,
        level: int = 0,
        canonical_id: str | None = None,
        numeric_value: int | None = None,
    ) -> float:
        """Zwraca prawdopodobieństwo a priori P(Q_i) na poziomie generalizacji `level`."""
        if dimension_id == "AGE":
            age = numeric_value if numeric_value is not None else cls.extract_age_number(value)
            if age is None:
                return 0.10
            return cls.get_age_probability(age, level, language)

        if dimension_id == "PROFESSION":
            code = canonical_id
            if code is None:
                node = OccupationTaxonomy.lookup(value)
                code = node.code if node else None
            if code is None:
                return 0.005
            # Generalizacja kodu o `level` kroków
            curr_code = code
            for _ in range(level):
                curr_node = OccupationTaxonomy.get_node(curr_code)
                if curr_node and curr_node.parent_code:
                    curr_code = curr_node.parent_code
                else:
                    break
            return OccupationTaxonomy.get_prevalence(curr_code, language)

        if dimension_id == "LOCATION":
            cid = canonical_id
            if cid is None:
                gnode = GeographyTaxonomy.lookup(value)
                cid = gnode.canonical_id if gnode else None
            if cid is None:
                return 0.001
            curr_id = cid
            for _ in range(level):
                curr_gnode = GeographyTaxonomy.get_node(curr_id)
                if curr_gnode and curr_gnode.parent_id:
                    curr_id = curr_gnode.parent_id
                else:
                    break
            return GeographyTaxonomy.get_prevalence(curr_id, language)

        return 0.01

