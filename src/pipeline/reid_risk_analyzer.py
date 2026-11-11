"""Silnik oceny ryzyka re-identyfikacji i filtr k-anonimowości (Pipes & Filters).

Realizuje:
1. Estymację k-anonimowości: k_hat = N_pop * prod(P(Q_i))
2. Obliczanie Uniqueness Score: 1 / k_hat
3. Miary wyższego rzędu: l-różnorodność (distinct & entropy) i t-bliskość (TVD)
4. Zachłanne planowanie minimalnej generalizacji taksonomicznej (ISCO-08, TERYT, GeoNames, Wiek)
5. Klasyfikację klasy danych: wykrycie PHI podnosi context.data_class do DataClass.MEDICAL
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Sequence
from typing import Mapping

from domain.exceptions import ReIdentificationRiskError
from domain.models import (
    DATA_CLASS_SEVERITY,
    DataClass,
    DetectedEntity,
    EntityCategory,
    EntityType,
    Language,
    QIDGeneralizationStep,
    RiskAssessmentResult,
    RiskDecision,
    SensitiveAttributeAssessment,
)
from pipeline.context import PipelineContext
from resources.stats.prevalence import DemographicStats
from resources.taxonomies.geography import GeographyTaxonomy
from resources.taxonomies.icd10 import GLOBAL_CATEGORY_DISTRIBUTION, ICD10Taxonomy
from resources.taxonomies.occupations import OccupationTaxonomy


class ReIdRiskAnalyzer:
    """Silnik analityczny oceny ryzyka re-identyfikacji."""

    def __init__(
        self,
        *,
        k_min: int = 5,
        l_threshold: int = 3,
        t_threshold: float = 0.30,
    ) -> None:
        self.k_min = k_min
        self.l_threshold = l_threshold
        self.t_threshold = t_threshold

    def analyze(
        self,
        entities: Sequence[DetectedEntity],
        language: Language,
        sensitive_cohort: Sequence[str] | None = None,
    ) -> RiskAssessmentResult:
        # 1. Filtrujemy wyłącznie quasi-identyfikatory
        qids = [e for e in entities if e.category == EntityCategory.QUASI_IDENTIFIER]
        pop = DemographicStats.get_population(language)

        # 2. Prawdopodobieństwa początkowe
        initial_probs: list[float] = []
        for q in qids:
            dim = q.entity_type.value
            p = DemographicStats.get_qid_probability(
                dimension_id=dim,
                value=q.value,
                language=language,
                level=0,
                canonical_id=q.canonical_id,
                numeric_value=q.numeric_value,
            )
            initial_probs.append(p)

        # 3. Estymacja k_hat początkowego
        joint_p = 1.0
        for p in initial_probs:
            joint_p *= p
        k_estimate = float(pop) * joint_p if qids else float(pop)

        uniqueness_score = 0.0
        if qids:
            uniqueness_score = 1.0 if k_estimate <= 1.0 else min(1.0, 1.0 / k_estimate)

        # 4. Ocena wrażliwych atrybutów (l-diversity & t-closeness)
        sensitive_assessment = self._evaluate_sensitive(entities, sensitive_cohort)

        # 5. Jeśli k_estimate >= k_min, brak konieczności generalizacji
        if k_estimate >= self.k_min or not qids:
            return RiskAssessmentResult(
                registry_id=f"GUS_{language.value.upper()}",
                language=language,
                population=pop,
                qid_count=len(qids),
                k_estimate=k_estimate,
                k_after=k_estimate,
                k_min=self.k_min,
                uniqueness_score=uniqueness_score,
                uniqueness_after=uniqueness_score,
                steps=tuple(
                    QIDGeneralizationStep(
                        start=q.start,
                        end=q.end,
                        entity_type=q.entity_type,
                        dimension_id=q.entity_type.value,
                        level=0,
                        suppressed=False,
                        probability_before=initial_probs[i],
                        probability_after=initial_probs[i],
                    )
                    for i, q in enumerate(qids)
                ),
                sensitive=sensitive_assessment,
                decision=RiskDecision.PASS,
            )

        # 6. Adaptacyjna minimalna generalizacja (k_estimate < k_min)
        steps, k_after = self._plan_generalization(qids, initial_probs, pop, language)
        uniqueness_after = 1.0 if k_after <= 1.0 else min(1.0, 1.0 / k_after)

        decision = RiskDecision.GENERALIZE if k_after >= self.k_min else RiskDecision.REJECT

        return RiskAssessmentResult(
            registry_id=f"GUS_{language.value.upper()}",
            language=language,
            population=pop,
            qid_count=len(qids),
            k_estimate=k_estimate,
            k_after=k_after,
            k_min=self.k_min,
            uniqueness_score=uniqueness_score,
            uniqueness_after=uniqueness_after,
            steps=steps,
            sensitive=sensitive_assessment,
            decision=decision,
        )

    def _plan_generalization(
        self,
        qids: list[DetectedEntity],
        initial_probs: list[float],
        population: int,
        language: Language,
    ) -> tuple[tuple[QIDGeneralizationStep, ...], float]:
        """Zachłanna wspinaczka po drzewach ontologicznych: podnosi cechę o najniższym P(Q_i)."""
        levels = [0] * len(qids)
        max_levels = [self._get_max_steps(q) for q in qids]
        curr_probs = list(initial_probs)

        def compute_k() -> float:
            prod = 1.0
            for p in curr_probs:
                prod *= p
            return float(population) * prod

        curr_k = compute_k()

        while curr_k < self.k_min:
            # Szukamy QID, który można jeszcze podnieść i który ma najniższe P(Q_i)
            best_idx: int | None = None
            min_p = 2.0
            for i, q in enumerate(qids):
                if levels[i] < max_levels[i]:
                    if curr_probs[i] < min_p:
                        min_p = curr_probs[i]
                        best_idx = i

            if best_idx is None:
                # Nie da się już bardziej uogólnić
                break

            levels[best_idx] += 1
            dim = qids[best_idx].entity_type.value
            curr_probs[best_idx] = DemographicStats.get_qid_probability(
                dimension_id=dim,
                value=qids[best_idx].value,
                language=language,
                level=levels[best_idx],
                canonical_id=qids[best_idx].canonical_id,
                numeric_value=qids[best_idx].numeric_value,
            )
            curr_k = compute_k()

        steps_res = tuple(
            QIDGeneralizationStep(
                start=q.start,
                end=q.end,
                entity_type=q.entity_type,
                dimension_id=q.entity_type.value,
                level=levels[i],
                suppressed=False,
                probability_before=initial_probs[i],
                probability_after=curr_probs[i],
            )
            for i, q in enumerate(qids)
        )
        return steps_res, curr_k

    def _evaluate_sensitive(
        self,
        entities: Sequence[DetectedEntity],
        sensitive_cohort: Sequence[str] | None,
    ) -> SensitiveAttributeAssessment:
        categories: list[str] = []
        if sensitive_cohort:
            categories.extend(sensitive_cohort)
        else:
            for e in entities:
                if e.category == EntityCategory.PHI:
                    if e.entity_type == EntityType.ICD10_CODE and e.canonical_id:
                        entry = ICD10Taxonomy.lookup_code(e.canonical_id)
                        if entry:
                            categories.append(entry.category)
                    elif e.entity_type == EntityType.MEDICAL_CONDITION and e.canonical_id:
                        entry = ICD10Taxonomy.lookup_code(e.canonical_id)
                        if entry:
                            categories.append(entry.category)

        if len(categories) < 2:
            return SensitiveAttributeAssessment(
                sample_size=len(categories),
                distinct_l=None,
                entropy_l=None,
                t_closeness=None,
                l_threshold=self.l_threshold,
                t_threshold=self.t_threshold,
            )

        counts = Counter(categories)
        total = len(categories)
        distinct_l = len(counts)

        # Entropia Shannona H = - sum(p * log2(p))
        entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
        entropy_l = 2**entropy

        # Total Variation Distance dla t-closeness
        all_cats = set(counts.keys()) | set(GLOBAL_CATEGORY_DISTRIBUTION.keys())
        tvd = 0.5 * sum(
            abs((counts.get(cat, 0) / total) - GLOBAL_CATEGORY_DISTRIBUTION.get(cat, 0.0))
            for cat in all_cats
        )

        return SensitiveAttributeAssessment(
            sample_size=total,
            distinct_l=distinct_l,
            entropy_l=round(entropy_l, 4),
            t_closeness=round(tvd, 4),
            l_threshold=self.l_threshold,
            t_threshold=self.t_threshold,
        )

    @staticmethod
    def _get_max_steps(qid: DetectedEntity) -> int:
        if qid.entity_type == EntityType.AGE:
            return 3
        if qid.entity_type == EntityType.PROFESSION:
            code = qid.canonical_id
            return OccupationTaxonomy.max_steps(code) if code else 2
        if qid.entity_type == EntityType.LOCATION:
            cid = qid.canonical_id
            return GeographyTaxonomy.max_steps(cid) if cid else 3
        return 0


class DataClassifierFilter:
    """Filtr klasyfikacji danych: jeśli w entities jest PHI, podnosi data_class do MEDICAL."""

    filter_id: str = "data_classifier_filter"

    def process(self, context: PipelineContext) -> PipelineContext:
        has_phi = any(e.category == EntityCategory.PHI for e in context.entities)
        new_class = context.data_class
        if has_phi and DATA_CLASS_SEVERITY[DataClass.MEDICAL] > DATA_CLASS_SEVERITY[context.data_class]:
            new_class = DataClass.MEDICAL

        if new_class != context.data_class:
            return context.evolve(data_class=new_class)
        return context


class ReIdRiskFilter:
    """Filtr oceny k-anonimowości i planowania generalizacji w Pipes & Filters."""

    filter_id: str = "reid_risk_filter"

    def __init__(
        self,
        analyzer: ReIdRiskAnalyzer | None = None,
        *,
        fail_closed: bool = True,
    ) -> None:
        self.analyzer = analyzer or ReIdRiskAnalyzer()
        self.fail_closed = fail_closed

    def process(self, context: PipelineContext) -> PipelineContext:
        assessment = self.analyzer.analyze(
            entities=context.entities,
            language=context.language,
            sensitive_cohort=context.sensitive_cohort,
        )

        # Jeśli fail_closed i ryzyko niemożliwe do obniżenia do k_min -> Fail-closed
        if self.fail_closed and assessment.decision == RiskDecision.REJECT:
            raise ReIdentificationRiskError(assessment.k_after, assessment.k_min)

        return context.evolve(risk_assessment=assessment)

