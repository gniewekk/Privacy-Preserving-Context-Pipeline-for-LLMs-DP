import json
import unittest

from privacy_pipeline import (
    DetectedEntity,
    EntityMetadata,
    InMemoryTokenVault,
    OutputPIIDetector,
    PipelineBuilder,
    PipelineContext,
    PipelineMemento,
    PipelineProxy,
)
from privacy_pipeline.pipeline import OutboundPipeline, ResponseRestorer


class ReliabilityTests(unittest.TestCase):
    def test_outbound_pipeline_scans_before_restoring(self) -> None:
        vault = InMemoryTokenVault()
        pipeline = PipelineBuilder(vault).with_anonymization().build()
        proxy = PipelineProxy(pipeline)
        context = proxy.anonymize("Kontakt jan@example.com", session_id="outbound")

        with self.assertRaisesRegex(ValueError, "Unexpected PII"):
            proxy.restore("Nowa dana: leak@example.com " + context.text, context)

    def test_outbound_pipeline_allows_known_tokens_then_restores(self) -> None:
        vault = InMemoryTokenVault()
        proxy = PipelineProxy(PipelineBuilder(vault).with_anonymization().build())
        context = proxy.anonymize("Kontakt jan@example.com", session_id="outbound-safe")
        self.assertEqual(proxy.restore("Kontakt " + context.text.split()[-1], context), "Kontakt jan@example.com")

    def test_memento_json_round_trip_and_integrity_check(self) -> None:
        original = PipelineMemento(
            session_id="snapshot-1",
            token_map={"<EMAIL_1>": EntityMetadata("EMAIL", 0, 16)},
            applied_filters=("PIIDetector",),
        )
        encoded = original.to_json()
        restored = PipelineMemento.from_json(encoded)
        self.assertEqual(restored.token_map, original.token_map)
        self.assertEqual(restored.session_id, original.session_id)
        self.assertNotIn("jan@example.com", encoded)

        payload = json.loads(encoded)
        payload["token_map"]["<EMAIL_1>"]["entity_type"] = "PERSON"
        with self.assertRaisesRegex(ValueError, "integrity"):
            PipelineMemento.from_json(json.dumps(payload))

    def test_memento_extension_is_versioned_and_keeps_values_out_of_snapshot(self) -> None:
        vault = InMemoryTokenVault()
        original = PipelineMemento(session_id="dynamic", token_map={})
        extended = vault.extend_memento(original, "2000-01-02", "DATE")
        self.assertEqual(extended.version, 2)
        self.assertIn("<DATE_1>", extended.token_map)
        self.assertNotIn("2000-01-02", extended.to_json())
        self.assertEqual(vault.detokenize("dynamic", "<DATE_1>"), "2000-01-02")

    def test_context_recovery_snapshot_omits_cleartext_and_restores_state(self) -> None:
        vault = InMemoryTokenVault()
        proxy = PipelineProxy(PipelineBuilder(vault).with_anonymization().build())
        context = proxy.anonymize("Jan Kowalski jan@example.com", session_id="recover")
        encoded = context.to_snapshot_json()
        self.assertNotIn("Jan Kowalski", encoded)
        self.assertNotIn("jan@example.com", encoded)
        recovered = proxy.recover(encoded)
        self.assertEqual(recovered.text, context.text)
        self.assertEqual(recovered.memento, context.memento)
        self.assertEqual(proxy.restore(recovered.text, recovered), "Jan Kowalski jan@example.com")

    def test_tool_result_extends_existing_memento_before_restoration(self) -> None:
        vault = InMemoryTokenVault()
        proxy = PipelineProxy(PipelineBuilder(vault).with_anonymization().build())
        context = proxy.anonymize("Jan Kowalski", session_id="tool-session")
        context, tool_token = proxy.anonymize_tool_result(context, "2000-01-02", "DATE")
        self.assertIsNotNone(context.memento)
        assert context.memento is not None
        self.assertEqual(context.memento.version, 2)
        self.assertNotIn("2000-01-02", context.memento.to_json())
        self.assertEqual(proxy.restore(f"{context.text} born {tool_token}", context), "Jan Kowalski born 2000-01-02")

    def test_context_snapshot_rejects_tampering(self) -> None:
        vault = InMemoryTokenVault()
        proxy = PipelineProxy(PipelineBuilder(vault).with_anonymization().build())
        context = proxy.anonymize("jan@example.com", session_id="tamper")
        payload = json.loads(context.to_snapshot_json())
        payload["text"] = "jan@example.com"
        with self.assertRaisesRegex(ValueError, "integrity"):
            proxy.recover(json.dumps(payload))

    def test_snapshot_refuses_pre_anonymized_context(self) -> None:
        context = PipelineContext(
            session_id="unsafe", text="jan@example.com",
            detected_entities=(DetectedEntity("EMAIL", "jan@example.com", 0, 15),),
        )
        with self.assertRaisesRegex(ValueError, "anonymized"):
            context.to_snapshot_json()

    def test_builder_does_not_mutate_filters_across_builds(self) -> None:
        builder = PipelineBuilder().with_anonymization().withResidencyPolicy("EU_ONLY")
        first = builder.build()
        second = builder.build()
        self.assertEqual([f.name for f in first.inbound.filters], [f.name for f in second.inbound.filters])

    def test_pipeline_is_immutable_after_build(self) -> None:
        pipeline = PipelineBuilder().with_anonymization().build()
        with self.assertRaises((AttributeError, TypeError)):
            pipeline.inbound = None

    def test_builder_rejects_unsafe_audit_level_for_personal_data(self) -> None:
        with self.assertRaisesRegex(ValueError, "FULL"):
            (PipelineBuilder().forDataClass("PERSONAL").withAuditLevel("NONE")
             .with_anonymization().build())

    def test_builder_rejects_invalid_risk_threshold(self) -> None:
        with self.assertRaisesRegex(ValueError, "between 0 and 1"):
            PipelineBuilder().withReIdRiskThreshold(1.1)

    def test_builder_includes_output_detector_in_outbound_filters(self) -> None:
        pipeline = PipelineBuilder().with_anonymization().build()
        self.assertTrue(any(isinstance(f, OutputPIIDetector) for f in pipeline.outbound.filters))


if __name__ == "__main__":
    unittest.main()
