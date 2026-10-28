import unittest

from privacy_pipeline.pipeline import PipelineBuilder


class BuilderConfigurationTests(unittest.TestCase):
    def test_requires_anonymization_to_build_pipeline(self) -> None:
        with self.assertRaisesRegex(ValueError, "AnonymizationFilter"):
            PipelineBuilder().build()


if __name__ == "__main__":
    unittest.main()
