"""Testy jednostkowe detektora medycznego PHIDetector (PL i EN)."""

from __future__ import annotations

import unittest

from detectors.phi_detector import PHIDetector
from domain.models import DataClass, EntityCategory, EntityType, Language
from pipeline.context import PipelineContext
from pipeline.reid_risk_analyzer import DataClassifierFilter


class TestPHIDetector(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = PHIDetector()
        self.classifier = DataClassifierFilter()

    def test_icd10_detection_pl_and_en(self) -> None:
        # Kod ICD-10 w tekście polskim
        text_pl = "U pacjenta rozpoznano ICD-10: C71.9 oraz I10."
        entities_pl = self.detector.detect(text_pl, Language.PL)
        types_pl = [e.entity_type for e in entities_pl]
        self.assertIn(EntityType.ICD10_CODE, types_pl)
        c71 = next(e for e in entities_pl if "C71" in e.value)
        self.assertEqual(c71.canonical_id, "C71")
        self.assertEqual(c71.category, EntityCategory.PHI)

        # Kod ICD-10 w tekście angielskim
        text_en = "Patient was diagnosed with ICD-10: E11.9 and I21."
        entities_en = self.detector.detect(text_en, Language.EN)
        types_en = [e.entity_type for e in entities_en]
        self.assertIn(EntityType.ICD10_CODE, types_en)
        e11 = next(e for e in entities_en if "E11" in e.value)
        self.assertEqual(e11.canonical_id, "E11")

    def test_icd9_procedure_detection(self) -> None:
        text_pl = "Wykonano procedurę ICD-9: 88.72 w znieczuleniu."
        entities_pl = self.detector.detect(text_pl, Language.PL)
        proc_pl = next(e for e in entities_pl if e.entity_type == EntityType.ICD9_PROCEDURE)
        self.assertEqual(proc_pl.value, "88.72")

        text_en = "Surgical procedure 99.25 was successfully performed."
        entities_en = self.detector.detect(text_en, Language.EN)
        proc_en = next(e for e in entities_en if e.entity_type == EntityType.ICD9_PROCEDURE)
        self.assertEqual(proc_en.value, "99.25")

    def test_free_text_conditions_pl_and_en(self) -> None:
        text_pl = "W wywiadzie: zdiagnozowano rzadki guz mózgu oraz nadciśnienie tętnicze."
        entities_pl = self.detector.detect(text_pl, Language.PL)
        values_pl = [e.value.lower() for e in entities_pl]
        self.assertTrue(any("guz mózgu" in v for v in values_pl))
        self.assertTrue(any("nadciśnienie" in v for v in values_pl))

        text_en = "Patient reports a history of glioblastoma and type 2 diabetes."
        entities_en = self.detector.detect(text_en, Language.EN)
        values_en = [e.value.lower() for e in entities_en]
        self.assertTrue(any("glioblastoma" in v for v in values_en))
        self.assertTrue(any("type 2 diabetes" in v for v in values_en))

    def test_medications_inn_and_brands(self) -> None:
        # PL: INN i marka RPL (Metformina, Euthyrox)
        text_pl = "Zalecono Euthyrox 50 mcg rano oraz Metformina 850 mg."
        entities_pl = self.detector.detect(text_pl, Language.PL)
        meds_pl = [e.value.lower() for e in entities_pl if e.entity_type == EntityType.MEDICATION]
        self.assertIn("euthyrox", meds_pl)
        self.assertIn("metformina", meds_pl)

        # EN: INN i marka RxNorm/FDA (Metformin, Lipitor)
        text_en = "Prescribed Lipitor 20 mg and Metformin 500 mg."
        entities_en = self.detector.detect(text_en, Language.EN)
        meds_en = [e.value.lower() for e in entities_en if e.entity_type == EntityType.MEDICATION]
        self.assertIn("lipitor", meds_en)
        self.assertIn("metformin", meds_en)

    def test_dosage_and_lab_results_pl_and_en(self) -> None:
        text_pl = "Dawkowanie: 500 mg na dobę. Wynik badania: HbA1c: 7.8%, glukoza na czczo: 145 mg/dl."
        entities_pl = self.detector.detect(text_pl, Language.PL)
        types_pl = {e.entity_type for e in entities_pl}
        self.assertIn(EntityType.DOSAGE, types_pl)
        self.assertIn(EntityType.LAB_RESULT, types_pl)

        text_en = "Dosage: 500 mg daily. Labs show fasting glucose: 145 mg/dL and HbA1c: 7.8%."
        entities_en = self.detector.detect(text_en, Language.EN)
        types_en = {e.entity_type for e in entities_en}
        self.assertIn(EntityType.DOSAGE, types_en)
        self.assertIn(EntityType.LAB_RESULT, types_en)

    def test_hl7_v2_and_fhir_structured_formats(self) -> None:
        # HL7 v2
        hl7_text = "DG1|1|C71|C71^Glioblastoma^ICD10|\nOBX|1|NM|GLU^Glucose||145|mg/dl|"
        entities_hl7 = self.detector.detect(hl7_text, Language.EN)
        self.assertTrue(len(entities_hl7) >= 2)

        # HL7 FHIR Condition
        fhir_json = """{
            "resourceType": "Condition",
            "code": {
                "coding": [
                    {"system": "http://hl7.org/fhir/sid/icd-10", "code": "C71", "display": "Brain tumor"}
                ]
            }
        }"""
        entities_fhir = self.detector.detect(fhir_json, Language.EN)
        codes = [e.value for e in entities_fhir if e.entity_type == EntityType.ICD10_CODE]
        self.assertIn("C71", codes)

    def test_phi_detection_elevates_data_class_to_medical(self) -> None:
        text = "Badanie kontrolne: zdiagnozowano nadciśnienie tętnicze."
        entities = self.detector.detect(text, Language.PL)
        context = PipelineContext(
            request_id="req-1",
            tenant_id="tenant-1",
            text=text,
            language=Language.PL,
            data_class=DataClass.GENERAL,
            entities=tuple(entities),
        )
        updated_context = self.classifier.process(context)
        self.assertEqual(updated_context.data_class, DataClass.MEDICAL)


if __name__ == "__main__":
    unittest.main()

