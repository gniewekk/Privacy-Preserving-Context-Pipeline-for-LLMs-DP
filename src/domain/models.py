"""Niezmienne modele domenowe wspólne dla całego potoku (zakres Osoby C + kontrakty wspólne).

Wszystkie modele są niezmiennymi obiektami wartości (AGENTS.md §1: Pydantic v2 / frozen dataclasses).
Obsługują Pydantic v2 jeśli jest zainstalowany, oraz zapewniają pełną kompatybilność w środowiskach
minimalnych bez zewnętrznych bibliotek (Python 3.11+ dataclasses).

Modele ukrywają surowe wartości PII/PHI w `repr` i `str` (AGENTS.md §5.4).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Mapping, Self

try:
    from pydantic import BaseModel as _PydanticBaseModel, ConfigDict, Field, model_validator
    _USE_PYDANTIC = True
except ImportError:
    _USE_PYDANTIC = False
    _PydanticBaseModel = object  # type: ignore[assignment, misc]


class Language(StrEnum):
    """Języki obsługiwane przez potok. Wartość przekazuje LanguageDetector (Osoba A)."""

    PL = "pl"
    EN = "en"


class DataClass(StrEnum):
    """Klasa danych całego żądania — decyduje m.in. o blokadzie Residency (Osoba B)."""

    GENERAL = "GENERAL"
    PII = "PII"
    FINANCIAL = "FINANCIAL"
    MEDICAL = "MEDICAL"


DATA_CLASS_SEVERITY: dict[DataClass, int] = {
    DataClass.GENERAL: 0,
    DataClass.PII: 1,
    DataClass.FINANCIAL: 2,
    DataClass.MEDICAL: 3,
}


class EntityCategory(StrEnum):
    """Kategoria encji — po niej (a nie po konkretnym typie) rozgałęziają się reguły potoku."""

    PII = "PII"  # bezpośrednie identyfikatory (Osoba A)
    PHI = "PHI"  # dane o zdrowiu (Osoba C)
    QUASI_IDENTIFIER = "QUASI_IDENTIFIER"  # cechy pośrednio identyfikujące (Osoba C)


class EntityType(StrEnum):
    """Typy encji rozpoznawane w potoku (PII, PHI, Quasi-identyfikatory)."""

    # --- PII (Osoba A) ---
    PERSON = "PERSON"
    PESEL = "PESEL"
    SSN = "SSN"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    IBAN = "IBAN"
    # --- PHI (Osoba C) ---
    ICD10_CODE = "ICD10_CODE"  # kod rozpoznania, np. C71.9
    ICD9_PROCEDURE = "ICD9_PROCEDURE"  # kod procedury, np. 88.72
    MEDICAL_CONDITION = "MEDICAL_CONDITION"  # opis choroby, np. "glejak" / "glioblastoma"
    MEDICATION = "MEDICATION"  # lek (INN lub nazwa handlowa)
    DOSAGE = "DOSAGE"  # dawkowanie, np. "150 mg na dobę"
    LAB_RESULT = "LAB_RESULT"  # wynik badania, np. "HbA1c: 7.8%"
    HOSPITALIZATION = "HOSPITALIZATION"  # pobyt w szpitalu / oddział
    # --- Quasi-identyfikatory (Osoba C) ---
    AGE = "AGE"
    PROFESSION = "PROFESSION"
    LOCATION = "LOCATION"


if _USE_PYDANTIC:
    _FROZEN = ConfigDict(frozen=True, extra="forbid")

    class DomainBaseModel(_PydanticBaseModel):
        model_config = _FROZEN

    class DetectedEntity(DomainBaseModel):
        entity_type: EntityType
        category: EntityCategory
        start: int = Field(ge=0)
        end: int = Field(gt=0)
        value: str = Field(min_length=1, repr=False)
        confidence: float = Field(ge=0.0, le=1.0)
        detector_id: str = Field(min_length=1)
        canonical_id: str | None = Field(default=None, repr=False)
        numeric_value: int | None = Field(default=None, repr=False)

        @model_validator(mode="after")
        def _check_span(self) -> Self:
            if self.end <= self.start or len(self.value) != self.end - self.start:
                raise ValueError("Niespójny zakres encji (start/end/długość wartości).")
            return self

        @property
        def length(self) -> int:
            return self.end - self.start

        def overlaps(self, other: DetectedEntity) -> bool:
            return self.start < other.end and other.start < self.end

        def __str__(self) -> str:
            return (
                f"DetectedEntity(type={self.entity_type.value}, span=[{self.start}:{self.end}], "
                f"length={self.length}, confidence={self.confidence:.2f})"
            )

    class QuasiIdentifier(DomainBaseModel):
        entity: DetectedEntity
        dimension_id: str

        @property
        def canonical_id(self) -> str | None:
            return self.entity.canonical_id

        @property
        def numeric_value(self) -> int | None:
            return self.entity.numeric_value

    class QIDGeneralizationStep(DomainBaseModel):
        start: int = Field(ge=0)
        end: int = Field(gt=0)
        entity_type: EntityType
        dimension_id: str
        level: int = Field(ge=0)
        suppressed: bool = False
        probability_before: float = Field(ge=0.0, le=1.0)
        probability_after: float = Field(ge=0.0, le=1.0)

        def matches(self, entity: DetectedEntity) -> bool:
            return (self.start, self.end, self.entity_type) == (
                entity.start,
                entity.end,
                entity.entity_type,
            )

    class SensitiveAttributeAssessment(DomainBaseModel):
        sample_size: int = Field(ge=0)
        distinct_l: int | None = None
        entropy_l: float | None = None
        t_closeness: float | None = None
        l_threshold: int
        t_threshold: float

        @property
        def is_l_diverse(self) -> bool | None:
            return None if self.distinct_l is None else self.distinct_l >= self.l_threshold

        @property
        def is_t_close(self) -> bool | None:
            return None if self.t_closeness is None else self.t_closeness <= self.t_threshold

    class RiskDecision(StrEnum):
        PASS = "PASS"
        GENERALIZE = "GENERALIZE"
        REJECT = "REJECT"

    class RiskAssessmentResult(DomainBaseModel):
        registry_id: str
        language: Language
        population: int = Field(gt=0)
        qid_count: int = Field(ge=0)
        k_estimate: float = Field(ge=0.0)
        k_after: float = Field(ge=0.0)
        k_min: int = Field(ge=1)
        uniqueness_score: float = Field(ge=0.0, le=1.0)
        uniqueness_after: float = Field(ge=0.0, le=1.0)
        steps: tuple[QIDGeneralizationStep, ...] = ()
        sensitive: SensitiveAttributeAssessment
        decision: RiskDecision

        @property
        def is_k_anonymous(self) -> bool:
            return self.k_estimate >= self.k_min

        def step_for(self, entity: DetectedEntity) -> QIDGeneralizationStep | None:
            return next((step for step in self.steps if step.matches(entity)), None)

    class AnonymizationRequest(DomainBaseModel):
        request_id: str
        language: Language
        data_class: DataClass
        generalization_level: int = Field(default=0, ge=0)

    class AnonymizationResult(DomainBaseModel):
        replacement: str = Field(repr=False)
        strategy_id: str
        entity_type: EntityType
        reversible: bool

else:
    from dataclasses import dataclass, field

    @dataclass(frozen=True)
    class DetectedEntity:
        entity_type: EntityType
        category: EntityCategory
        start: int
        end: int
        value: str = field(repr=False)
        confidence: float
        detector_id: str
        canonical_id: str | None = field(default=None, repr=False)
        numeric_value: int | None = field(default=None, repr=False)

        def __post_init__(self) -> None:
            if self.start < 0:
                raise ValueError("start must be >= 0")
            if self.end <= self.start or len(self.value) != self.end - self.start:
                raise ValueError("Niespójny zakres encji (start/end/długość wartości).")
            if not (0.0 <= self.confidence <= 1.0):
                raise ValueError("confidence must be between 0.0 and 1.0")

        @property
        def length(self) -> int:
            return self.end - self.start

        def overlaps(self, other: DetectedEntity) -> bool:
            return self.start < other.end and other.start < self.end

        def __str__(self) -> str:
            return (
                f"DetectedEntity(type={self.entity_type.value}, span=[{self.start}:{self.end}], "
                f"length={self.length}, confidence={self.confidence:.2f})"
            )

    @dataclass(frozen=True)
    class QuasiIdentifier:
        entity: DetectedEntity
        dimension_id: str

        @property
        def canonical_id(self) -> str | None:
            return self.entity.canonical_id

        @property
        def numeric_value(self) -> int | None:
            return self.entity.numeric_value

    @dataclass(frozen=True)
    class QIDGeneralizationStep:
        start: int
        end: int
        entity_type: EntityType
        dimension_id: str
        level: int
        suppressed: bool = False
        probability_before: float = 0.0
        probability_after: float = 0.0

        def matches(self, entity: DetectedEntity) -> bool:
            return (self.start, self.end, self.entity_type) == (
                entity.start,
                entity.end,
                entity.entity_type,
            )

    @dataclass(frozen=True)
    class SensitiveAttributeAssessment:
        sample_size: int
        l_threshold: int
        t_threshold: float
        distinct_l: int | None = None
        entropy_l: float | None = None
        t_closeness: float | None = None

        @property
        def is_l_diverse(self) -> bool | None:
            return None if self.distinct_l is None else self.distinct_l >= self.l_threshold

        @property
        def is_t_close(self) -> bool | None:
            return None if self.t_closeness is None else self.t_closeness <= self.t_threshold

    class RiskDecision(StrEnum):
        PASS = "PASS"
        GENERALIZE = "GENERALIZE"
        REJECT = "REJECT"

    @dataclass(frozen=True)
    class RiskAssessmentResult:
        registry_id: str
        language: Language
        population: int
        qid_count: int
        k_estimate: float
        k_after: float
        k_min: int
        uniqueness_score: float
        uniqueness_after: float
        sensitive: SensitiveAttributeAssessment
        decision: RiskDecision
        steps: tuple[QIDGeneralizationStep, ...] = ()

        @property
        def is_k_anonymous(self) -> bool:
            return self.k_estimate >= self.k_min

        def step_for(self, entity: DetectedEntity) -> QIDGeneralizationStep | None:
            return next((step for step in self.steps if step.matches(entity)), None)

    @dataclass(frozen=True)
    class AnonymizationRequest:
        request_id: str
        language: Language
        data_class: DataClass
        generalization_level: int = 0

    @dataclass(frozen=True)
    class AnonymizationResult:
        replacement: str = field(repr=False)
        strategy_id: str
        entity_type: EntityType
        reversible: bool
