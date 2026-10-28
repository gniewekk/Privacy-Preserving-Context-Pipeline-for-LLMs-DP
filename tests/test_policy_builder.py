import unittest

from privacy_pipeline.pipeline import PipelineBuilder


class BuilderPolicyTests(unittest.TestCase):
    def test_rejects_medical_data_class_in_non_medical_scope(self) -> None:
        with self.assertRaisesRegex(ValueError, "Medical data support is out of scope"):
            PipelineBuilder().forDataClass("MEDICAL").with_anonymization().build()

    def test_rejects_unknown_data_class(self) -> None:
        with self.assertRaisesRegex(ValueError, "Unsupported data class"):
            PipelineBuilder().forDataClass("MYSTERY").with_anonymization().build()

    def test_none_residency_policy_adds_no_residency_gate(self) -> None:
        pipeline = (
            PipelineBuilder().withResidencyPolicy("NONE").with_anonymization().build()
        )
        self.assertNotIn("ResidencyPolicy", [f.name for f in pipeline.inbound.filters])

    def test_rejects_unknown_residency_policy(self) -> None:
        with self.assertRaisesRegex(ValueError, "Unsupported residency policy"):
            PipelineBuilder().withResidencyPolicy("MOON").with_anonymization().build()

    def test_audit_level_is_visible_in_built_pipeline_context(self) -> None:
        pipeline = (
            PipelineBuilder().withAuditLevel("FULL").with_anonymization().build()
        )
        context = pipeline.inbound.execute(
            __import__("privacy_pipeline").PipelineContext("audit", "hello")
        )
        self.assertEqual(context.metadata["audit_level"], "FULL")


if __name__ == "__main__":
    unittest.main()
