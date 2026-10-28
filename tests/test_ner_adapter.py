import unittest

from privacy_pipeline.detectors import TransformerNERDetector


class TransformerNERTests(unittest.TestCase):
    def test_maps_person_organization_and_location_labels_to_entity_types(self) -> None:
        detector = TransformerNERDetector("local-test-model", min_score=0.5)
        detector._pipeline = lambda text: [
            {"score": 0.99, "entity_group": "PER", "start": 0, "end": 12},
            {"score": 0.95, "entity_group": "ORG", "start": 15, "end": 19},
            {"score": 0.90, "entity_group": "LOC", "start": 20, "end": 25},
            {"score": 0.49, "entity_group": "PER", "start": 0, "end": 12},
            {"score": 0.99, "entity_group": "MISC", "start": 0, "end": 12},
        ]
        text = "Jan Kowalski w Acme Łodzi"
        entities = detector.detect(text)
        self.assertEqual([entity.entity_type for entity in entities], ["PERSON", "ORGANIZATION", "LOCATION"])
        self.assertEqual([entity.value for entity in entities], ["Jan Kowalski", "Acme", "Łodzi"])


if __name__ == "__main__":
    unittest.main()
