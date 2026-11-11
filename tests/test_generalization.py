"""Testy jednostkowe strategii uogólniania (GeneralizationStrategy) oraz maskowania (MaskingStrategy)."""

from __future__ import annotations

import unittest

from domain.models import (
    AnonymizationRequest,
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
from strategies.generalization import GeneralizationStrategy
from strategies.masking import MaskingStrategy
from strategies.selector import StrategySelector


class TestGeneralizationAndMasking(unittest.TestCase):
    def setUp(self) -> None:
        self.gen_strategy = GeneralizationStrategy()
        self.mask_strategy = MaskingStrategy(preserve_length=True)

    def test_generalization_pl_language(self) -> None:
        req_pl = AnonymizationRequest(
            request_id="r1",
            language=Language.PL,
            data_class=DataClass.GENERAL,
            generalization_level=1,
        )

        # Zawód (ISCO-08 w PL)
        ent_prof = DetectedEntity(
            entity_type=EntityType.PROFESSION,
            category=EntityCategory.QUASI_IDENTIFIER,
            start=0,
            end=12,
            value="neurochirurg",
            confidence=0.9,
            detector_id="d1",
            canonical_id="2212.1",
        )
        res_prof = self.gen_strategy.anonymize(ent_prof, req_pl)
        self.assertEqual(res_prof.replacement, "lekarz specjalista")
        self.assertFalse(res_prof.reversible)

        # Lokalizacja (TERYT w PL)
        ent_loc = DetectedEntity(
            entity_type=EntityType.LOCATION,
            category=EntityCategory.QUASI_IDENTIFIER,
            start=0,
            end=18,
            value="Sępólno Krajeńskie",
            confidence=0.9,
            detector_id="d1",
            canonical_id="PL-M-SEPOLNO",
        )
        # 1 krok -> powiat sępoleński
        res_loc_1 = self.gen_strategy.anonymize(ent_loc, req_pl)
        self.assertEqual(res_loc_1.replacement, "powiat sępoleński")

        # 2 kroki -> woj. kujawsko-pomorskie
        req_pl_2 = AnonymizationRequest(
            request_id="r2",
            language=Language.PL,
            data_class=DataClass.GENERAL,
            generalization_level=2,
        )
        res_loc_2 = self.gen_strategy.anonymize(ent_loc, req_pl_2)
        self.assertEqual(res_loc_2.replacement, "woj. kujawsko-pomorskie")

        # Wiek w PL
        ent_age = DetectedEntity(
            entity_type=EntityType.AGE,
            category=EntityCategory.QUASI_IDENTIFIER,
            start=0,
            end=6,
            value="lat 47",
            confidence=0.9,
            detector_id="d1",
            numeric_value=47,
        )
        res_age = self.gen_strategy.anonymize(ent_age, req_pl)
        self.assertEqual(res_age.replacement, "lat 40-50")

        # Kod ICD-10 w PL
        ent_icd = DetectedEntity(
            entity_type=EntityType.ICD10_CODE,
            category=EntityCategory.PHI,
            start=0,
            end=3,
            value="C71",
            confidence=1.0,
            detector_id="d1",
            canonical_id="C71",
        )
        res_icd = self.gen_strategy.anonymize(ent_icd, req_pl)
        self.assertEqual(res_icd.replacement, "schorzenie onkologiczne")

    def test_generalization_en_language(self) -> None:
        req_en = AnonymizationRequest(
            request_id="r-en",
            language=Language.EN,
            data_class=DataClass.GENERAL,
            generalization_level=1,
        )

        # Profession (ISCO-08 in EN)
        ent_prof = DetectedEntity(
            entity_type=EntityType.PROFESSION,
            category=EntityCategory.QUASI_IDENTIFIER,
            start=0,
            end=12,
            value="neurosurgeon",
            confidence=0.9,
            detector_id="d1",
            canonical_id="2212.1",
        )
        res_prof = self.gen_strategy.anonymize(ent_prof, req_en)
        self.assertEqual(res_prof.replacement, "specialist medical practitioner")

        # Location (GeoNames in EN)
        ent_loc = DetectedEntity(
            entity_type=EntityType.LOCATION,
            category=EntityCategory.QUASI_IDENTIFIER,
            start=0,
            end=9,
            value="Cambridge",
            confidence=0.9,
            detector_id="d1",
            canonical_id="US-M-CAMBRIDGE",
        )
        res_loc = self.gen_strategy.anonymize(ent_loc, req_en)
        self.assertEqual(res_loc.replacement, "Middlesex County")

        # Age in EN
        ent_age = DetectedEntity(
            entity_type=EntityType.AGE,
            category=EntityCategory.QUASI_IDENTIFIER,
            start=0,
            end=12,
            value="47 years old",
            confidence=0.9,
            detector_id="d1",
            numeric_value=47,
        )
        res_age = self.gen_strategy.anonymize(ent_age, req_en)
        self.assertEqual(res_age.replacement, "40-50 years old")

        # ICD-10 in EN
        ent_icd = DetectedEntity(
            entity_type=EntityType.ICD10_CODE,
            category=EntityCategory.PHI,
            start=0,
            end=3,
            value="C71",
            confidence=1.0,
            detector_id="d1",
            canonical_id="C71",
        )
        res_icd = self.gen_strategy.anonymize(ent_icd, req_en)
        self.assertEqual(res_icd.replacement, "oncological condition")

    def test_masking_strategy(self) -> None:
        req = AnonymizationRequest(
            request_id="m1",
            language=Language.PL,
            data_class=DataClass.GENERAL,
        )
        ent = DetectedEntity(
            entity_type=EntityType.PESEL,
            category=EntityCategory.PII,
            start=0,
            end=11,
            value="90010112345",
            confidence=1.0,
            detector_id="d1",
        )
        # Zachowanie długości (gwiazdki)
        res_len = self.mask_strategy.anonymize(ent, req)
        self.assertEqual(res_len.replacement, "***********")
        self.assertEqual(len(res_len.replacement), 11)

        # Bez zachowania długości
        mask_tag = MaskingStrategy(preserve_length=False)
        res_tag = mask_tag.anonymize(ent, req)
        self.assertEqual(res_tag.replacement, "[PESEL_REDACTED]")

    def test_strategy_selector(self) -> None:
        selector = StrategySelector(
            generalization_strategy=self.gen_strategy,
            masking_strategy=self.mask_strategy,
        )

        qid_ent = DetectedEntity(
            entity_type=EntityType.PROFESSION,
            category=EntityCategory.QUASI_IDENTIFIER,
            start=0,
            end=12,
            value="neurochirurg",
            confidence=0.9,
            detector_id="d1",
            canonical_id="2212.1",
        )

        risk_report = RiskAssessmentResult(
            registry_id="GUS_PL",
            language=Language.PL,
            population=37_600_000,
            qid_count=1,
            k_estimate=0.5,
            k_after=50.0,
            k_min=5,
            uniqueness_score=1.0,
            uniqueness_after=0.02,
            steps=(
                QIDGeneralizationStep(
                    start=0,
                    end=12,
                    entity_type=EntityType.PROFESSION,
                    dimension_id="PROFESSION",
                    level=2,
                    suppressed=False,
                    probability_before=0.00001,
                    probability_after=0.0025,
                ),
            ),
            sensitive=SensitiveAttributeAssessment(
                sample_size=0,
                l_threshold=3,
                t_threshold=0.30,
            ),
            decision=RiskDecision.GENERALIZE,
        )

        req = AnonymizationRequest(
            request_id="sel-1",
            language=Language.PL,
            data_class=DataClass.GENERAL,
            generalization_level=0,
        )

        # Selektor powinien przekierować do GeneralizationStrategy z dostosowanym levelem = 2
        strat, adj_req = selector.select(qid_ent, req, risk_report)
        self.assertIs(strat, self.gen_strategy)
        self.assertEqual(adj_req.generalization_level, 2)

        res = strat.anonymize(qid_ent, adj_req)
        self.assertEqual(res.replacement, "lekarz")


if __name__ == "__main__":
    unittest.main()

