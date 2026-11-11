"""Zasoby medyczne: ICD-10, ICD-9, leki (INN, RPL, RxNorm) oraz kategorie kliniczne.

Wspiera pełną dwujęzyczność (PL i EN) dla:
- Kodów i opisów jednostek chorobowych ICD-10
- Kodów procedur medycznych ICD-9
- Nazw międzynarodowych leków (INN) oraz nazw handlowych (PL/EN)
- Uogólniania rozpoznań klinicznych do bezpiecznych kategorii nadrzędnych
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from domain.models import Language


@dataclass(frozen=True)
class ICD10Entry:
    code: str
    chapter: str
    category: str  # np. ONCOLOGY, CARDIOLOGY
    names: Mapping[Language, str]
    population_prevalence: float


ICD10_REGISTRY: dict[str, ICD10Entry] = {
    "C71": ICD10Entry(
        code="C71",
        chapter="II",
        category="ONCOLOGY",
        names={
            Language.PL: "Nowotwór złośliwy mózgu",
            Language.EN: "Malignant neoplasm of brain",
        },
        population_prevalence=0.002,
    ),
    "C34": ICD10Entry(
        code="C34",
        chapter="II",
        category="ONCOLOGY",
        names={
            Language.PL: "Nowotwór złośliwy oskrzela i płuca",
            Language.EN: "Malignant neoplasm of bronchus and lung",
        },
        population_prevalence=0.008,
    ),
    "C50": ICD10Entry(
        code="C50",
        chapter="II",
        category="ONCOLOGY",
        names={
            Language.PL: "Nowotwór złośliwy piersi",
            Language.EN: "Malignant neoplasm of breast",
        },
        population_prevalence=0.012,
    ),
    "I10": ICD10Entry(
        code="I10",
        chapter="IX",
        category="CARDIOLOGY",
        names={
            Language.PL: "Nadciśnienie tętnicze pierwotne",
            Language.EN: "Essential (primary) hypertension",
        },
        population_prevalence=0.32,
    ),
    "I21": ICD10Entry(
        code="I21",
        chapter="IX",
        category="CARDIOLOGY",
        names={
            Language.PL: "Ostry zawał mięśnia sercowego",
            Language.EN: "Acute myocardial infarction",
        },
        population_prevalence=0.04,
    ),
    "I25": ICD10Entry(
        code="I25",
        chapter="IX",
        category="CARDIOLOGY",
        names={
            Language.PL: "Przewlekła choroba niedokrwienna serca",
            Language.EN: "Chronic ischaemic heart disease",
        },
        population_prevalence=0.08,
    ),
    "E11": ICD10Entry(
        code="E11",
        chapter="IV",
        category="ENDOCRINOLOGY",
        names={
            Language.PL: "Cukrzyca typu 2",
            Language.EN: "Type 2 diabetes mellitus",
        },
        population_prevalence=0.09,
    ),
    "E10": ICD10Entry(
        code="E10",
        chapter="IV",
        category="ENDOCRINOLOGY",
        names={
            Language.PL: "Cukrzyca typu 1",
            Language.EN: "Type 1 diabetes mellitus",
        },
        population_prevalence=0.01,
    ),
    "F32": ICD10Entry(
        code="F32",
        chapter="V",
        category="PSYCHIATRY",
        names={
            Language.PL: "Epizod depresyjny",
            Language.EN: "Depressive episode",
        },
        population_prevalence=0.06,
    ),
    "F20": ICD10Entry(
        code="F20",
        chapter="V",
        category="PSYCHIATRY",
        names={
            Language.PL: "Schizofrenia",
            Language.EN: "Schizophrenia",
        },
        population_prevalence=0.01,
    ),
    "G40": ICD10Entry(
        code="G40",
        chapter="VI",
        category="NEUROLOGY",
        names={
            Language.PL: "Padaczka",
            Language.EN: "Epilepsy",
        },
        population_prevalence=0.01,
    ),
    "G35": ICD10Entry(
        code="G35",
        chapter="VI",
        category="NEUROLOGY",
        names={
            Language.PL: "Stwardnienie rozsiane",
            Language.EN: "Multiple sclerosis",
        },
        population_prevalence=0.003,
    ),
    "J45": ICD10Entry(
        code="J45",
        chapter="X",
        category="PULMONOLOGY",
        names={
            Language.PL: "Astma oskrzelowa",
            Language.EN: "Asthma",
        },
        population_prevalence=0.06,
    ),
    "B20": ICD10Entry(
        code="B20",
        chapter="I",
        category="INFECTIOUS",
        names={
            Language.PL: "Choroba wywołana przez HIV",
            Language.EN: "Human immunodeficiency virus [HIV] disease",
        },
        population_prevalence=0.001,
    ),
}

# Referencyjny rozkład kategorii klinicznych w populacji chorych (do t-closeness)
GLOBAL_CATEGORY_DISTRIBUTION: dict[str, float] = {
    "CARDIOLOGY": 0.42,
    "ENDOCRINOLOGY": 0.22,
    "PULMONOLOGY": 0.14,
    "NEUROLOGY": 0.08,
    "PSYCHIATRY": 0.08,
    "ONCOLOGY": 0.05,
    "INFECTIOUS": 0.01,
}

# Etykiety generalizacji per kategoria (właściwe dla wybranego języka)
CATEGORY_GENERALIZED_LABELS: dict[str, dict[Language, str]] = {
    "ONCOLOGY": {
        Language.PL: "schorzenie onkologiczne",
        Language.EN: "oncological condition",
    },
    "CARDIOLOGY": {
        Language.PL: "schorzenie kardiologiczne",
        Language.EN: "cardiovascular condition",
    },
    "ENDOCRINOLOGY": {
        Language.PL: "schorzenie endokrynologiczne",
        Language.EN: "endocrine disorder",
    },
    "PSYCHIATRY": {
        Language.PL: "zaburzenie zdrowia psychicznego",
        Language.EN: "mental health condition",
    },
    "NEUROLOGY": {
        Language.PL: "schorzenie neurologiczne",
        Language.EN: "neurological disorder",
    },
    "PULMONOLOGY": {
        Language.PL: "schorzenie układu oddechowego",
        Language.EN: "respiratory condition",
    },
    "INFECTIOUS": {
        Language.PL: "choroba zakaźna",
        Language.EN: "infectious disease",
    },
}

# Słownik pojęć medycznych w tekście swobodnym (PL i EN) mapowanych na kategorię
MEDICAL_TERMS: dict[str, tuple[str, str]] = {
    # PL -> (kategoria, kanoniczny kod ICD-10)
    "guz mózgu": ("ONCOLOGY", "C71"),
    "rzadki guz mózgu": ("ONCOLOGY", "C71"),
    "glejak wielopostaciowy": ("ONCOLOGY", "C71"),
    "glejak": ("ONCOLOGY", "C71"),
    "nowotwór złośliwy": ("ONCOLOGY", "C34"),
    "rak płuca": ("ONCOLOGY", "C34"),
    "rak piersi": ("ONCOLOGY", "C50"),
    "nadciśnienie tętnicze": ("CARDIOLOGY", "I10"),
    "nadciśnienie": ("CARDIOLOGY", "I10"),
    "zawał mięśnia sercowego": ("CARDIOLOGY", "I21"),
    "zawał serca": ("CARDIOLOGY", "I21"),
    "cukrzyca typu 2": ("ENDOCRINOLOGY", "E11"),
    "cukrzyca typu 1": ("ENDOCRINOLOGY", "E10"),
    "cukrzyca": ("ENDOCRINOLOGY", "E11"),
    "depresja": ("PSYCHIATRY", "F32"),
    "epizod depresyjny": ("PSYCHIATRY", "F32"),
    "schizofrenia": ("PSYCHIATRY", "F20"),
    "stwardnienie rozsiane": ("NEUROLOGY", "G35"),
    "padaczka": ("NEUROLOGY", "G40"),
    "astma oskrzelowa": ("PULMONOLOGY", "J45"),
    "astma": ("PULMONOLOGY", "J45"),
    # EN -> (kategoria, kanoniczny kod ICD-10)
    "brain tumor": ("ONCOLOGY", "C71"),
    "brain tumour": ("ONCOLOGY", "C71"),
    "glioblastoma": ("ONCOLOGY", "C71"),
    "malignant neoplasm": ("ONCOLOGY", "C34"),
    "lung cancer": ("ONCOLOGY", "C34"),
    "breast cancer": ("ONCOLOGY", "C50"),
    "hypertension": ("CARDIOLOGY", "I10"),
    "high blood pressure": ("CARDIOLOGY", "I10"),
    "myocardial infarction": ("CARDIOLOGY", "I21"),
    "heart attack": ("CARDIOLOGY", "I21"),
    "type 2 diabetes": ("ENDOCRINOLOGY", "E11"),
    "type 1 diabetes": ("ENDOCRINOLOGY", "E10"),
    "diabetes": ("ENDOCRINOLOGY", "E11"),
    "depression": ("PSYCHIATRY", "F32"),
    "depressive episode": ("PSYCHIATRY", "F32"),
    "schizophrenia": ("PSYCHIATRY", "F20"),
    "multiple sclerosis": ("NEUROLOGY", "G35"),
    "epilepsy": ("NEUROLOGY", "G40"),
    "asthma": ("PULMONOLOGY", "J45"),
}

# Leki: nazwy międzynarodowe INN + handlowe PL i EN
MEDICATIONS: set[str] = {
    # INN (International Nonproprietary Names)
    "metformin",
    "metformina",
    "atorvastatin",
    "atorwastatyna",
    "lisinopril",
    "lizynopryl",
    "amlodipine",
    "amlodypina",
    "omeprazole",
    "omeprazol",
    "paracetamol",
    "acetaminophen",
    "ibuprofen",
    "bisoprolol",
    "pembrolizumab",
    "insulin",
    "insulina",
    "levothyroxine",
    "lewotyroksyna",
    # PL Brands (RPL / Rejestr Produktów Leczniczych)
    "metformax",
    "glikofag",
    "euthyrox",
    "letrox",
    "prestarium",
    "concor",
    "encorton",
    "xarelto",
    "polprazol",
    "ketonal",
    # EN Brands (RxNorm / FDA)
    "glucophage",
    "lipitor",
    "norvasc",
    "prilosec",
    "tylenol",
    "advil",
    "keytruda",
    "synthroid",
    "zoloft",
    "prozac",
}


class ICD10Taxonomy:
    """Interfejs dostępu do danych medycznych ICD-10 i słowników leków."""

    @classmethod
    def lookup_code(cls, code: str) -> ICD10Entry | None:
        prefix = code.strip().upper()
        if "." in prefix:
            prefix = prefix.split(".")[0]
        return ICD10_REGISTRY.get(prefix)

    @classmethod
    def lookup_term(cls, term: str) -> tuple[str, str] | None:
        return MEDICAL_TERMS.get(term.strip().lower())

    @classmethod
    def is_known_medication(cls, term: str) -> bool:
        return term.strip().lower() in MEDICATIONS

    @classmethod
    def generalize_category(cls, category: str, language: Language) -> str:
        cat_labels = CATEGORY_GENERALIZED_LABELS.get(category.upper())
        if cat_labels:
            return cat_labels.get(language, cat_labels[Language.EN])
        return "schorzenie medyczne" if language == Language.PL else "medical condition"

