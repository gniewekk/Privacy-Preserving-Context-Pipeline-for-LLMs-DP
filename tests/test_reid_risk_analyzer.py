"""Testy jednostkowe silnika oceny ryzyka re-identyfikacji i k-anonimowości (PL i EN)."""

from __future__ import annotations

import unittest

from detectors.qid_detector import QIDDetector
from domain.exceptions import ReIdentificationRiskError
from domain.models import EntityCategory, EntityType, Language, RiskDecision
from pipeline.context import PipelineContext
from pipeline.reid_risk_analyzer import ReIdRiskAnalyzer, ReIdRiskFilter


class TestReIdRiskAnalyzer(unittest.TestCase):
    def setUp(self) -> None:
        self.qid_detector = QIDDetector()
        self.analyzer = ReIdRiskAnalyzer(k_min=5, l_threshold=3, t_threshold=0.30)

    def test_qid_extraction_pl_and_en(self) -> None:
        text_pl = "Pacjent, lat 47, zawód: neurochirurg, zamieszkały w Sępólnie Krajeńskim."
        entities_pl = self.qid_detector.detect(text_pl, Language.PL)
        types_pl = {e.entity_type for e in entities_pl}
        self.assertIn(EntityType.AGE, types_pl)
        self.assertIn(EntityType.PROFESSION, types_pl)
        self.assertIn(EntityType.LOCATION, types_pl)
        age_ent = next(e for e in entities_pl if e.entity_type == EntityType.AGE)
        self.assertEqual(age_ent.numeric_value, 47)

        text_en = "Patient, 47 years old, profession: neurosurgeon, residing in Cambridge."
        entities_en = self.qid_detector.detect(text_en, Language.EN)
        types_en = {e.entity_type for e in entities_en}
        self.assertIn(EntityType.AGE, types_en)
        self.assertIn(EntityType.PROFESSION, types_en)
        self.assertIn(EntityType.LOCATION, types_en)
        age_en = next(e for e in entities_en if e.entity_type == EntityType.AGE)
        self.assertEqual(age_en.numeric_value, 47)

    def test_risk_estimation_rare_profile_triggers_generalization_pl(self) -> None:
        # Rzadki profil w PL: 47-letni neurochirurg w Sępólnie Krajeńskim (populacja 37.6 mln)
        text = "Pacjent, lat 47, zawód: neurochirurg, zamieszkały w Sępólnie Krajeńskim."
        entities = self.qid_detector.detect(text, Language.PL)
        result = self.analyzer.analyze(entities, Language.PL)

        # Przed generalizacją k̂ < 1 (mniej niż 1 osoba w Polsce!)
        self.assertLess(result.k_estimate, 1.0)
        self.assertEqual(result.uniqueness_score, 1.0)
        self.assertFalse(result.is_k_anonymous)

        # Algorytm zachłanny podnosi cechy w drzewie ISCO / TERYT, osiągając k_after >= 5
        self.assertEqual(result.decision, RiskDecision.GENERALIZE)
        self.assertGreaterEqual(result.k_after, 5.0)
        self.assertLess(result.uniqueness_after, 0.25)
        self.assertTrue(len(result.steps) > 0)

    def test_risk_estimation_rare_profile_triggers_generalization_en(self) -> None:
        # Rzadki profil w EN/US: 47-year-old neurosurgeon in Cambridge (populacja 335 mln)
        text = "Patient, 47 years old, profession: neurosurgeon, residing in Cambridge."
        entities = self.qid_detector.detect(text, Language.EN)
        result = self.analyzer.analyze(entities, Language.EN)

        self.assertLess(result.k_estimate, 5.0)
        self.assertEqual(result.decision, RiskDecision.GENERALIZE)
        self.assertGreaterEqual(result.k_after, 5.0)

    def test_common_profile_passes_without_generalization(self) -> None:
        # Powszechny profil: 35-latek w Warszawie (PL)
        text = "Pacjent w wieku 35 lat, zamieszkały w Warszawie."
        entities = self.qid_detector.detect(text, Language.PL)
        result = self.analyzer.analyze(entities, Language.PL)

        self.assertGreaterEqual(result.k_estimate, 50.0)
        self.assertEqual(result.decision, RiskDecision.PASS)
        # Wszystkie kroki mają level = 0
        for step in result.steps:
            self.assertEqual(step.level, 0)

    def test_l_diversity_and_t_closeness_evaluation(self) -> None:
        # Homogeniczna kohorta z rzadką chorobą (5x ONCOLOGY)
        homo_cohort = ["ONCOLOGY", "ONCOLOGY", "ONCOLOGY", "ONCOLOGY", "ONCOLOGY"]
        assessment_homo = self.analyzer._evaluate_sensitive([], homo_cohort)
        self.assertEqual(assessment_homo.distinct_l, 1)
        self.assertFalse(assessment_homo.is_l_diverse)
        self.assertFalse(assessment_homo.is_t_close)  # t-closeness TVD > 0.30

        # Zróżnicowana kohorta
        diverse_cohort = ["CARDIOLOGY", "CARDIOLOGY", "ENDOCRINOLOGY", "PULMONOLOGY", "NEUROLOGY"]
        assessment_div = self.analyzer._evaluate_sensitive([], diverse_cohort)
        self.assertGreaterEqual(assessment_div.distinct_l, 3)
        self.assertTrue(assessment_div.is_l_diverse)
        self.assertTrue(assessment_div.is_t_close)

    def test_filter_fail_closed_on_rejection(self) -> None:
        # Wymóg k_min = 100 mln (niemożliwy do osiągnięcia nawet w całej populacji Polski)
        filter_strict = ReIdRiskFilter(ReIdRiskAnalyzer(k_min=100_000_000), fail_closed=True)
        text = "lat 47, neurochirurg"
        entities = self.qid_detector.detect(text, Language.PL)
        context = PipelineContext(
            request_id="req-2",
            tenant_id="tenant-1",
            text=text,
            language=Language.PL,
            entities=tuple(entities),
        )
        with self.assertRaises(ReIdentificationRiskError):
            filter_strict.process(context)


if __name__ == "__main__":
    unittest.main()
