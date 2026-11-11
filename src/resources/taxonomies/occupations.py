"""Taksonomia zawodowa ISCO-08 / KZiS (dwujęzyczna: PL i EN).

ISCO-08 (International Standard Classification of Occupations) stanowi podstawę
zarówno polskiej Klasyfikacji Zawodów i Specjalności (KZiS), jak i międzynarodowych
standardów statystycznych (ILO/OECD).

Struktura poziomów:
- Poziom 4: Jednostka / wąska specjalizacja (4 cyfry, np. 2212 - lekarze specjaliści)
- Poziom 3: Grupa elementarna (3 cyfry, np. 221 - lekarze)
- Poziom 2: Podgrupa duża (2 cyfry, np. 22 - specjaliści ochrony zdrowia)
- Poziom 1: Wielka grupa (1 cyfra, np. 2 - specjaliści)
- Poziom 0: Korzeń taksonomii (osoba aktywna zawodowo)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from domain.models import Language


@dataclass(frozen=True)
class OccupationNode:
    """Węzeł taksonomii ISCO-08."""

    code: str
    level: int  # 4 (najbardziej szczegółowy), 3, 2, 1, 0 (korzeń)
    parent_code: str | None
    labels: Mapping[Language, str]
    # Szacowany udział w populacji ogólnej danego kraju (PL i US/EN)
    prevalence: Mapping[Language, float]


# Wbudowane węzły taksonomii ISCO-08 z etykietami PL i EN
ISCO_NODES: dict[str, OccupationNode] = {
    # --- Poziom 4: Wąskie specjalizacje medyczne i techniczne ---
    "2212.1": OccupationNode(
        code="2212.1",
        level=4,
        parent_code="2212",
        labels={
            Language.PL: "neurochirurg",
            Language.EN: "neurosurgeon",
        },
        prevalence={
            Language.PL: 500 / 37_600_000,       # ~500 w PL
            Language.EN: 4_200 / 335_000_000,    # ~4.2k w US
        },
    ),
    "2212.2": OccupationNode(
        code="2212.2",
        level=4,
        parent_code="2212",
        labels={
            Language.PL: "kardiochirurg",
            Language.EN: "cardiac surgeon",
        },
        prevalence={
            Language.PL: 400 / 37_600_000,
            Language.EN: 3_800 / 335_000_000,
        },
    ),
    "2212.3": OccupationNode(
        code="2212.3",
        level=4,
        parent_code="2212",
        labels={
            Language.PL: "onkolog dziecięcy",
            Language.EN: "pediatric oncologist",
        },
        prevalence={
            Language.PL: 250 / 37_600_000,
            Language.EN: 2_500 / 335_000_000,
        },
    ),
    "2212.4": OccupationNode(
        code="2212.4",
        level=4,
        parent_code="2212",
        labels={
            Language.PL: "kardiolog",
            Language.EN: "cardiologist",
        },
        prevalence={
            Language.PL: 6_500 / 37_600_000,
            Language.EN: 35_000 / 335_000_000,
        },
    ),
    "2212": OccupationNode(
        code="2212",
        level=3,
        parent_code="221",
        labels={
            Language.PL: "lekarz specjalista",
            Language.EN: "specialist medical practitioner",
        },
        prevalence={
            Language.PL: 95_000 / 37_600_000,
            Language.EN: 650_000 / 335_000_000,
        },
    ),
    "2211": OccupationNode(
        code="2211",
        level=3,
        parent_code="221",
        labels={
            Language.PL: "lekarz ogólny",
            Language.EN: "generalist medical practitioner",
        },
        prevalence={
            Language.PL: 60_000 / 37_600_000,
            Language.EN: 380_000 / 335_000_000,
        },
    ),
    "221": OccupationNode(
        code="221",
        level=2,
        parent_code="22",
        labels={
            Language.PL: "lekarz",
            Language.EN: "medical doctor",
        },
        prevalence={
            Language.PL: 155_000 / 37_600_000,
            Language.EN: 1_030_000 / 335_000_000,
        },
    ),
    "2221": OccupationNode(
        code="2221",
        level=3,
        parent_code="22",
        labels={
            Language.PL: "pielęgniarka",
            Language.EN: "nursing professional",
        },
        prevalence={
            Language.PL: 240_000 / 37_600_000,
            Language.EN: 3_200_000 / 335_000_000,
        },
    ),
    "22": OccupationNode(
        code="22",
        level=1,
        parent_code="2",
        labels={
            Language.PL: "pracownik służby zdrowia",
            Language.EN: "health professional",
        },
        prevalence={
            Language.PL: 650_000 / 37_600_000,
            Language.EN: 6_500_000 / 335_000_000,
        },
    ),
    # --- IT & Inżynieria ---
    "2512": OccupationNode(
        code="2512",
        level=3,
        parent_code="25",
        labels={
            Language.PL: "programista",
            Language.EN: "software developer",
        },
        prevalence={
            Language.PL: 280_000 / 37_600_000,
            Language.EN: 2_100_000 / 335_000_000,
        },
    ),
    "25": OccupationNode(
        code="25",
        level=1,
        parent_code="2",
        labels={
            Language.PL: "specjalista technologii informacyjno-komunikacyjnych",
            Language.EN: "information and communications technology professional",
        },
        prevalence={
            Language.PL: 550_000 / 37_600_000,
            Language.EN: 4_800_000 / 335_000_000,
        },
    ),
    # --- Prawo ---
    "2611": OccupationNode(
        code="2611",
        level=3,
        parent_code="26",
        labels={
            Language.PL: "prawnik",
            Language.EN: "lawyer",
        },
        prevalence={
            Language.PL: 85_000 / 37_600_000,
            Language.EN: 1_350_000 / 335_000_000,
        },
    ),
    "26": OccupationNode(
        code="26",
        level=1,
        parent_code="2",
        labels={
            Language.PL: "specjalista w dziedzinie prawa i nauk społecznych",
            Language.EN: "legal, social and cultural professional",
        },
        prevalence={
            Language.PL: 320_000 / 37_600_000,
            Language.EN: 3_200_000 / 335_000_000,
        },
    ),
    # --- Wielkie grupy (Poziom 1 i 0) ---
    "2": OccupationNode(
        code="2",
        level=1,
        parent_code="ROOT",
        labels={
            Language.PL: "specjalista",
            Language.EN: "professional",
        },
        prevalence={
            Language.PL: 3_600_000 / 37_600_000,
            Language.EN: 42_000_000 / 335_000_000,
        },
    ),
    "ROOT": OccupationNode(
        code="ROOT",
        level=0,
        parent_code=None,
        labels={
            Language.PL: "osoba aktywna zawodowo",
            Language.EN: "employed person",
        },
        prevalence={
            Language.PL: 17_200_000 / 37_600_000,
            Language.EN: 165_000_000 / 335_000_000,
        },
    ),
}

# Mapa odmian fleksyjnych i synonimów w PL i EN -> kod ISCO
OCCUPATION_ALIASES: dict[str, str] = {
    # PL
    "neurochirurg": "2212.1",
    "neurochirurga": "2212.1",
    "neurochirurgiem": "2212.1",
    "kardiochirurg": "2212.2",
    "kardiochirurga": "2212.2",
    "kardiochirurgiem": "2212.2",
    "onkolog dziecięcy": "2212.3",
    "onkologa dziecięcego": "2212.3",
    "kardiolog": "2212.4",
    "kardiologa": "2212.4",
    "kardiologiem": "2212.4",
    "lekarz specjalista": "2212",
    "lekarza specjalisty": "2212",
    "lekarzem specjalistą": "2212",
    "lekarz ogólny": "2211",
    "lekarz": "221",
    "lekarzem": "221",
    "lekarza": "221",
    "pielęgniarka": "2221",
    "pielęgniarki": "2221",
    "pielęgniarką": "2221",
    "programista": "2512",
    "programisty": "2512",
    "programistą": "2512",
    "inżynier oprogramowania": "2512",
    "prawnik": "2611",
    "prawnika": "2611",
    "prawnikiem": "2611",
    "adwokat": "2611",
    "radca prawny": "2611",
    # EN
    "neurosurgeon": "2212.1",
    "cardiac surgeon": "2212.2",
    "heart surgeon": "2212.2",
    "pediatric oncologist": "2212.3",
    "cardiologist": "2212.4",
    "specialist doctor": "2212",
    "specialist physician": "2212",
    "general practitioner": "2211",
    "gp": "2211",
    "physician": "221",
    "doctor": "221",
    "medical doctor": "221",
    "nurse": "2221",
    "registered nurse": "2221",
    "software developer": "2512",
    "software engineer": "2512",
    "programmer": "2512",
    "coder": "2512",
    "lawyer": "2611",
    "attorney": "2611",
    "barrister": "2611",
    "solicitor": "2611",
}


class OccupationTaxonomy:
    """Interfejs dostępu do taksonomii ISCO-08 zoptymalizowany pod lookup w pamięci."""

    @classmethod
    def lookup(cls, text: str) -> OccupationNode | None:
        """Wyszukuje węzeł taksonomii po nazwie lub aliasie (PL/EN, case-insensitive)."""
        normalized = text.strip().lower()
        code = OCCUPATION_ALIASES.get(normalized)
        if code is None:
            # Sprawdzenie bezpośrednio po kodzie lub etykiecie
            if normalized in ISCO_NODES:
                return ISCO_NODES[normalized]
            for node in ISCO_NODES.values():
                for label in node.labels.values():
                    if label.lower() == normalized:
                        return node
            return None
        return ISCO_NODES.get(code)

    @classmethod
    def get_node(cls, code: str) -> OccupationNode | None:
        return ISCO_NODES.get(code)

    @classmethod
    def generalize(cls, code: str, steps: int, language: Language) -> str:
        """Wspina się o `steps` kroków w górę hierarchii ISCO-08 i zwraca etykietę w zadanym języku."""
        node = ISCO_NODES.get(code)
        if node is None or steps <= 0:
            return node.labels.get(language, code) if node else code

        curr = node
        for _ in range(steps):
            if curr.parent_code is None or curr.parent_code not in ISCO_NODES:
                break
            curr = ISCO_NODES[curr.parent_code]

        return curr.labels.get(language, curr.labels.get(Language.EN, curr.code))

    @classmethod
    def max_steps(cls, code: str) -> int:
        """Zwraca maksymalną liczbę kroków do korzenia."""
        node = ISCO_NODES.get(code)
        if node is None:
            return 0
        steps = 0
        curr = node
        while curr.parent_code and curr.parent_code in ISCO_NODES:
            steps += 1
            curr = ISCO_NODES[curr.parent_code]
        return steps

    @classmethod
    def get_prevalence(cls, code: str, language: Language) -> float:
        node = ISCO_NODES.get(code)
        if node is None:
            return 0.001
        return node.prevalence.get(language, node.prevalence.get(Language.EN, 0.001))

