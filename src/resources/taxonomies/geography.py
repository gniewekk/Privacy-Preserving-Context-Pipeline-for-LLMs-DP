"""Hierarchia podziału terytorialnego i geografii (dwujęzyczna: TERYT dla PL, GeoNames dla EN).

Poziomy generalizacji:
- Poziom 3: Miejscowość / Gmina (City / Municipality)
- Poziom 2: Powiat / Hrabstwo (County / District)
- Poziom 1: Województwo / Stan (Province / State / Region)
- Poziom 0: Kraj / Korzeń (Country: Polska / United States)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from domain.models import Language


@dataclass(frozen=True)
class GeoNode:
    """Węzeł taksonomii geograficznej."""

    canonical_id: str
    level: int  # 3 (miasto), 2 (powiat), 1 (województwo/stan), 0 (kraj)
    parent_id: str | None
    labels: Mapping[Language, str]
    population: int
    prevalence: Mapping[Language, float]


POLAND_POPULATION: int = 37_600_000
US_POPULATION: int = 335_000_000

GEO_NODES: dict[str, GeoNode] = {
    # ========================== POLSKA (TERYT) ==========================
    # --- Miejscowości (Poziom 3) ---
    "PL-M-SEPOLNO": GeoNode(
        canonical_id="PL-M-SEPOLNO",
        level=3,
        parent_id="PL-P-SEPOLNO",
        labels={
            Language.PL: "Sępólno Krajeńskie",
            Language.EN: "Sepolno Krajenskie",
        },
        population=9_000,
        prevalence={Language.PL: 9_000 / POLAND_POPULATION, Language.EN: 9_000 / POLAND_POPULATION},
    ),
    "PL-M-USTRZYKI": GeoNode(
        canonical_id="PL-M-USTRZYKI",
        level=3,
        parent_id="PL-P-BIESZCZADY",
        labels={
            Language.PL: "Ustrzyki Dolne",
            Language.EN: "Ustrzyki Dolne",
        },
        population=8_800,
        prevalence={Language.PL: 8_800 / POLAND_POPULATION, Language.EN: 8_800 / POLAND_POPULATION},
    ),
    "PL-M-HEL": GeoNode(
        canonical_id="PL-M-HEL",
        level=3,
        parent_id="PL-P-PUCK",
        labels={
            Language.PL: "Hel",
            Language.EN: "Hel",
        },
        population=3_200,
        prevalence={Language.PL: 3_200 / POLAND_POPULATION, Language.EN: 3_200 / POLAND_POPULATION},
    ),
    "PL-M-TORUN": GeoNode(
        canonical_id="PL-M-TORUN",
        level=3,
        parent_id="PL-W-KUJ-POM",
        labels={
            Language.PL: "Toruń",
            Language.EN: "Torun",
        },
        population=195_000,
        prevalence={Language.PL: 195_000 / POLAND_POPULATION, Language.EN: 195_000 / POLAND_POPULATION},
    ),
    "PL-M-WARSZAWA": GeoNode(
        canonical_id="PL-M-WARSZAWA",
        level=3,
        parent_id="PL-W-MAZ",
        labels={
            Language.PL: "Warszawa",
            Language.EN: "Warsaw",
        },
        population=1_860_000,
        prevalence={Language.PL: 1_860_000 / POLAND_POPULATION, Language.EN: 1_860_000 / POLAND_POPULATION},
    ),
    "PL-M-KRAKOW": GeoNode(
        canonical_id="PL-M-KRAKOW",
        level=3,
        parent_id="PL-W-MALOPOLSKIE",
        labels={
            Language.PL: "Kraków",
            Language.EN: "Krakow",
        },
        population=804_000,
        prevalence={Language.PL: 804_000 / POLAND_POPULATION, Language.EN: 804_000 / POLAND_POPULATION},
    ),
    # --- Powiaty (Poziom 2) ---
    "PL-P-SEPOLNO": GeoNode(
        canonical_id="PL-P-SEPOLNO",
        level=2,
        parent_id="PL-W-KUJ-POM",
        labels={
            Language.PL: "powiat sępoleński",
            Language.EN: "Sepolno County",
        },
        population=40_000,
        prevalence={Language.PL: 40_000 / POLAND_POPULATION, Language.EN: 40_000 / POLAND_POPULATION},
    ),
    "PL-P-BIESZCZADY": GeoNode(
        canonical_id="PL-P-BIESZCZADY",
        level=2,
        parent_id="PL-W-PODKARPACKIE",
        labels={
            Language.PL: "powiat bieszczadzki",
            Language.EN: "Bieszczady County",
        },
        population=21_000,
        prevalence={Language.PL: 21_000 / POLAND_POPULATION, Language.EN: 21_000 / POLAND_POPULATION},
    ),
    "PL-P-PUCK": GeoNode(
        canonical_id="PL-P-PUCK",
        level=2,
        parent_id="PL-W-POMORSKIE",
        labels={
            Language.PL: "powiat pucki",
            Language.EN: "Puck County",
        },
        population=90_000,
        prevalence={Language.PL: 90_000 / POLAND_POPULATION, Language.EN: 90_000 / POLAND_POPULATION},
    ),
    # --- Województwa (Poziom 1) ---
    "PL-W-KUJ-POM": GeoNode(
        canonical_id="PL-W-KUJ-POM",
        level=1,
        parent_id="PL-COUNTRY",
        labels={
            Language.PL: "woj. kujawsko-pomorskie",
            Language.EN: "Kuyavian-Pomeranian Voivodeship",
        },
        population=2_000_000,
        prevalence={Language.PL: 2_000_000 / POLAND_POPULATION, Language.EN: 2_000_000 / POLAND_POPULATION},
    ),
    "PL-W-PODKARPACKIE": GeoNode(
        canonical_id="PL-W-PODKARPACKIE",
        level=1,
        parent_id="PL-COUNTRY",
        labels={
            Language.PL: "woj. podkarpackie",
            Language.EN: "Subcarpathian Voivodeship",
        },
        population=2_070_000,
        prevalence={Language.PL: 2_070_000 / POLAND_POPULATION, Language.EN: 2_070_000 / POLAND_POPULATION},
    ),
    "PL-W-POMORSKIE": GeoNode(
        canonical_id="PL-W-POMORSKIE",
        level=1,
        parent_id="PL-COUNTRY",
        labels={
            Language.PL: "woj. pomorskie",
            Language.EN: "Pomeranian Voivodeship",
        },
        population=2_360_000,
        prevalence={Language.PL: 2_360_000 / POLAND_POPULATION, Language.EN: 2_360_000 / POLAND_POPULATION},
    ),
    "PL-W-MAZ": GeoNode(
        canonical_id="PL-W-MAZ",
        level=1,
        parent_id="PL-COUNTRY",
        labels={
            Language.PL: "woj. mazowieckie",
            Language.EN: "Masovian Voivodeship",
        },
        population=5_510_000,
        prevalence={Language.PL: 5_510_000 / POLAND_POPULATION, Language.EN: 5_510_000 / POLAND_POPULATION},
    ),
    "PL-W-MALOPOLSKIE": GeoNode(
        canonical_id="PL-W-MALOPOLSKIE",
        level=1,
        parent_id="PL-COUNTRY",
        labels={
            Language.PL: "woj. małopolskie",
            Language.EN: "Lesser Poland Voivodeship",
        },
        population=3_430_000,
        prevalence={Language.PL: 3_430_000 / POLAND_POPULATION, Language.EN: 3_430_000 / POLAND_POPULATION},
    ),
    "PL-COUNTRY": GeoNode(
        canonical_id="PL-COUNTRY",
        level=0,
        parent_id=None,
        labels={
            Language.PL: "Polska",
            Language.EN: "Poland",
        },
        population=POLAND_POPULATION,
        prevalence={Language.PL: 1.0, Language.EN: 1.0},
    ),

    # ========================== USA / INTERNATIONAL (GeoNames) ==========================
    # --- Miasta (Poziom 3) ---
    "US-M-CAMBRIDGE": GeoNode(
        canonical_id="US-M-CAMBRIDGE",
        level=3,
        parent_id="US-C-MIDDLESEX",
        labels={
            Language.PL: "Cambridge",
            Language.EN: "Cambridge",
        },
        population=118_000,
        prevalence={Language.PL: 118_000 / US_POPULATION, Language.EN: 118_000 / US_POPULATION},
    ),
    "US-M-BOSTON": GeoNode(
        canonical_id="US-M-BOSTON",
        level=3,
        parent_id="US-C-SUFFOLK",
        labels={
            Language.PL: "Boston",
            Language.EN: "Boston",
        },
        population=675_000,
        prevalence={Language.PL: 675_000 / US_POPULATION, Language.EN: 675_000 / US_POPULATION},
    ),
    "US-M-AUSTIN": GeoNode(
        canonical_id="US-M-AUSTIN",
        level=3,
        parent_id="US-C-TRAVIS",
        labels={
            Language.PL: "Austin",
            Language.EN: "Austin",
        },
        population=975_000,
        prevalence={Language.PL: 975_000 / US_POPULATION, Language.EN: 975_000 / US_POPULATION},
    ),
    "US-M-SEATTLE": GeoNode(
        canonical_id="US-M-SEATTLE",
        level=3,
        parent_id="US-C-KING",
        labels={
            Language.PL: "Seattle",
            Language.EN: "Seattle",
        },
        population=750_000,
        prevalence={Language.PL: 750_000 / US_POPULATION, Language.EN: 750_000 / US_POPULATION},
    ),
    # --- Hrabstwa / Powiaty US (Poziom 2) ---
    "US-C-MIDDLESEX": GeoNode(
        canonical_id="US-C-MIDDLESEX",
        level=2,
        parent_id="US-S-MA",
        labels={
            Language.PL: "hrabstwo Middlesex",
            Language.EN: "Middlesex County",
        },
        population=1_630_000,
        prevalence={Language.PL: 1_630_000 / US_POPULATION, Language.EN: 1_630_000 / US_POPULATION},
    ),
    "US-C-SUFFOLK": GeoNode(
        canonical_id="US-C-SUFFOLK",
        level=2,
        parent_id="US-S-MA",
        labels={
            Language.PL: "hrabstwo Suffolk",
            Language.EN: "Suffolk County",
        },
        population=790_000,
        prevalence={Language.PL: 790_000 / US_POPULATION, Language.EN: 790_000 / US_POPULATION},
    ),
    "US-C-TRAVIS": GeoNode(
        canonical_id="US-C-TRAVIS",
        level=2,
        parent_id="US-S-TX",
        labels={
            Language.PL: "hrabstwo Travis",
            Language.EN: "Travis County",
        },
        population=1_300_000,
        prevalence={Language.PL: 1_300_000 / US_POPULATION, Language.EN: 1_300_000 / US_POPULATION},
    ),
    "US-C-KING": GeoNode(
        canonical_id="US-C-KING",
        level=2,
        parent_id="US-S-WA",
        labels={
            Language.PL: "hrabstwo King",
            Language.EN: "King County",
        },
        population=2_270_000,
        prevalence={Language.PL: 2_270_000 / US_POPULATION, Language.EN: 2_270_000 / US_POPULATION},
    ),
    # --- Stany / Regiony (Poziom 1) ---
    "US-S-MA": GeoNode(
        canonical_id="US-S-MA",
        level=1,
        parent_id="US-COUNTRY",
        labels={
            Language.PL: "stan Massachusetts",
            Language.EN: "Massachusetts",
        },
        population=7_000_000,
        prevalence={Language.PL: 7_000_000 / US_POPULATION, Language.EN: 7_000_000 / US_POPULATION},
    ),
    "US-S-TX": GeoNode(
        canonical_id="US-S-TX",
        level=1,
        parent_id="US-COUNTRY",
        labels={
            Language.PL: "stan Teksas",
            Language.EN: "Texas",
        },
        population=30_000_000,
        prevalence={Language.PL: 30_000_000 / US_POPULATION, Language.EN: 30_000_000 / US_POPULATION},
    ),
    "US-S-WA": GeoNode(
        canonical_id="US-S-WA",
        level=1,
        parent_id="US-COUNTRY",
        labels={
            Language.PL: "stan Waszyngton",
            Language.EN: "Washington",
        },
        population=7_800_000,
        prevalence={Language.PL: 7_800_000 / US_POPULATION, Language.EN: 7_800_000 / US_POPULATION},
    ),
    "US-COUNTRY": GeoNode(
        canonical_id="US-COUNTRY",
        level=0,
        parent_id=None,
        labels={
            Language.PL: "Stany Zjednoczone",
            Language.EN: "United States",
        },
        population=US_POPULATION,
        prevalence={Language.PL: 1.0, Language.EN: 1.0},
    ),
}

# Aliasy fleksyjne (miejscowniki, skróty)
GEO_ALIASES: dict[str, str] = {
    # PL
    "sępólno krajeńskie": "PL-M-SEPOLNO",
    "sępólnie krajeńskim": "PL-M-SEPOLNO",
    "sępólna krajeńskiego": "PL-M-SEPOLNO",
    "ustrzyki dolne": "PL-M-USTRZYKI",
    "ustrzykach dolnych": "PL-M-USTRZYKI",
    "hel": "PL-M-HEL",
    "helu": "PL-M-HEL",
    "toruń": "PL-M-TORUN",
    "toruniu": "PL-M-TORUN",
    "warszawa": "PL-M-WARSZAWA",
    "warszawie": "PL-M-WARSZAWA",
    "kraków": "PL-M-KRAKOW",
    "krakowie": "PL-M-KRAKOW",
    "powiat sępoleński": "PL-P-SEPOLNO",
    "powiecie sępoleńskim": "PL-P-SEPOLNO",
    "powiat bieszczadzki": "PL-P-BIESZCZADY",
    "powiecie bieszczadzkim": "PL-P-BIESZCZADY",
    "woj. kujawsko-pomorskie": "PL-W-KUJ-POM",
    "kujawsko-pomorskie": "PL-W-KUJ-POM",
    "województwo kujawsko-pomorskie": "PL-W-KUJ-POM",
    "woj. podkarpackie": "PL-W-PODKARPACKIE",
    "podkarpackie": "PL-W-PODKARPACKIE",
    "województwo podkarpackie": "PL-W-PODKARPACKIE",
    "polska": "PL-COUNTRY",
    "polski": "PL-COUNTRY",
    "w polsce": "PL-COUNTRY",
    # EN
    "cambridge": "US-M-CAMBRIDGE",
    "in cambridge": "US-M-CAMBRIDGE",
    "boston": "US-M-BOSTON",
    "in boston": "US-M-BOSTON",
    "austin": "US-M-AUSTIN",
    "in austin": "US-M-AUSTIN",
    "seattle": "US-M-SEATTLE",
    "in seattle": "US-M-SEATTLE",
    "middlesex county": "US-C-MIDDLESEX",
    "suffolk county": "US-C-SUFFOLK",
    "travis county": "US-C-TRAVIS",
    "king county": "US-C-KING",
    "massachusetts": "US-S-MA",
    "texas": "US-S-TX",
    "washington": "US-S-WA",
    "united states": "US-COUNTRY",
    "usa": "US-COUNTRY",
    "us": "US-COUNTRY",
}


class GeographyTaxonomy:
    """Interfejs dostępu do taksonomii podziału terytorialnego (TERYT / GeoNames)."""

    @classmethod
    def lookup(cls, text: str) -> GeoNode | None:
        normalized = text.strip().lower()
        node_id = GEO_ALIASES.get(normalized)
        if node_id is None:
            for node in GEO_NODES.values():
                for label in node.labels.values():
                    if label.lower() == normalized:
                        return node
            return None
        return GEO_NODES.get(node_id)

    @classmethod
    def get_node(cls, canonical_id: str) -> GeoNode | None:
        return GEO_NODES.get(canonical_id)

    @classmethod
    def generalize(cls, canonical_id: str, steps: int, language: Language) -> str:
        """Wspina się o `steps` poziomów w górę drzewa terytorialnego."""
        node = GEO_NODES.get(canonical_id)
        if node is None or steps <= 0:
            return node.labels.get(language, canonical_id) if node else canonical_id

        curr = node
        for _ in range(steps):
            if curr.parent_id is None or curr.parent_id not in GEO_NODES:
                break
            curr = GEO_NODES[curr.parent_id]

        return curr.labels.get(language, curr.labels.get(Language.EN, curr.canonical_id))

    @classmethod
    def max_steps(cls, canonical_id: str) -> int:
        node = GEO_NODES.get(canonical_id)
        if node is None:
            return 0
        steps = 0
        curr = node
        while curr.parent_id and curr.parent_id in GEO_NODES:
            steps += 1
            curr = GEO_NODES[curr.parent_id]
        return steps

    @classmethod
    def get_prevalence(cls, canonical_id: str, language: Language) -> float:
        node = GEO_NODES.get(canonical_id)
        if node is None:
            return 0.0001
        return node.prevalence.get(language, node.prevalence.get(Language.EN, 0.0001))

