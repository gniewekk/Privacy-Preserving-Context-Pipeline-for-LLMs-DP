import unittest

from privacy_pipeline.detectors import TransformerNERDetector


class TransformerNERTests(unittest.TestCase):
    def setUp(self) -> None:
        print(f"\n[TEST] {self.id()}")

    def test_maps_person_organization_and_location_labels_to_entity_types(self) -> None:
        detector = TransformerNERDetector("local-test-model", min_score=0.5)
        detector._pipeline = lambda text: [
            {"score": 0.99, "entity_group": "PER", "start": 0, "end": 12},
            {"score": 0.95, "entity_group": "ORG", "start": 15, "end": 19},
            {"score": 0.90, "entity_group": "LOC", "start": 20, "end": 25},
            {"score": 0.49, "entity_group": "PER", "start": 0, "end": 12},
            {"score": 0.99, "entity_group": "MISC", "start": 0, "end": 12},
        ]
        text = "jan Kowalski w Acme Łodzi"
        print(f"Tekst przed szyfrowaniem: {text}")
        entities = detector.detect(text)
        print(f"Tekst po przetwarzaniu: {[entity.value for entity in entities]}")
        self.assertEqual([entity.entity_type for entity in entities], ["PERSON", "ORGANIZATION", "LOCATION"])
        self.assertEqual([entity.value for entity in entities], ["jan Kowalski", "Acme", "Łodzi"])


if __name__ == "__main__":
    unittest.main()
