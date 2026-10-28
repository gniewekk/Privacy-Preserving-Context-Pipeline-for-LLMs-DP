import unittest

from privacy_pipeline import (
    DetectedEntity,
    InMemoryTokenVault,
    OutputPIIDetector,
    PIIRegistry,
    PipelineBuilder,
    PipelineContext,
    PipelineProxy,
    ReIdRiskFilter,
    ResidencyPolicyFilter,
)


class PipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        vault = InMemoryTokenVault()
        pipeline = PipelineBuilder(vault).with_anonymization().build()
        self.proxy = PipelineProxy(pipeline)

    def _print_flow(self, original: str, context, restored: str | None = None) -> None:
        print(f"\n[WEJŚCIE]       {original}")
        print(f"[DETEKCJA]      {context.detected_entities}")
        print(f"[TOKENIZACJA]   {context.text}")
        print(f"[MEMENTO]       {context.memento}")
        if restored is not None:
            print(f"[DETOKENIZACJA] {restored}")

    def test_tokenization_and_detokenization_round_trip(self) -> None:
        original = "Kontakt: Jan@example.com, PESEL 44051401458."
        context = self.proxy.anonymize(
            original,
            session_id="session-1",
        )

        self.assertNotIn("Jan@example.com", context.text)
        self.assertNotIn("44051401458", context.text)
        tokenized_response = f"Odpowiedź dla {context.text}"
        print(f"[LLM]           {tokenized_response}")
        restored = self.proxy.restore(tokenized_response, context)
        self._print_flow(original, context, restored)
        self.assertEqual(
            restored,
            "Odpowiedź dla Kontakt: Jan@example.com, PESEL 44051401458.",
        )

    def test_repeated_value_reuses_token_and_is_restored_everywhere(self) -> None:
        original = "Jan@example.com wysłał wiadomość do Anna@example.com."
        context = self.proxy.anonymize(original, session_id="session-2")

        self.assertEqual(context.text.count("<EMAIL_1>"), 1)
        self.assertEqual(context.text.count("<EMAIL_2>"), 1)
        restored = self.proxy.restore(context.text, context)
        self._print_flow(original, context, restored)
        self.assertEqual(restored, original)

    def test_memento_contains_metadata_but_no_cleartext(self) -> None:
        original = "PESEL 44051401458"
        context = self.proxy.anonymize(original, session_id="session-3")
        self._print_flow(original, context)

        self.assertIsNotNone(context.memento)
        self.assertNotIn("44051401458", repr(context.memento))
        self.assertEqual(context.memento.version, 1)

    def test_invalid_pesel_is_not_tokenized(self) -> None:
        original = "Numer 44051401459"
        context = self.proxy.anonymize(original, session_id="session-4")
        self._print_flow(original, context)

        self.assertEqual(context.text, "Numer 44051401459")
        self.assertEqual(context.detected_entities, ())

    def test_person_is_detected_without_label(self) -> None:
        original = "Jan Kowalski skarży się na fakturę."
        context = self.proxy.anonymize(original, session_id="session-5")
        restored = self.proxy.restore(context.text, context)
        self._print_flow(original, context, restored)

        self.assertIn("<PERSON_1>", context.text)
        self.assertNotIn("Jan Kowalski", context.text)
        self.assertEqual(restored, original)

    def test_context_rules_detect_labeled_sensitive_values(self) -> None:
        original = "Diagnoza: nadciśnienie, ur. 01.02.1990."
        context = self.proxy.anonymize(original, session_id="session-6")
        restored = self.proxy.restore(context.text, context)
        self._print_flow(original, context, restored)

        self.assertNotIn("nadciśnienie", context.text)
        self.assertNotIn("01.02.1990", context.text)
        self.assertEqual(restored, original)

    def test_contact_prefix_does_not_hide_following_person_name(self) -> None:
        entities = PIIRegistry.detect("Kontakt: Anna Nowak, proszę oddzwonić")
        self.assertIn(("PERSON", "Anna Nowak"), [(e.entity_type, e.value) for e in entities])

    def test_detects_polish_street_address_with_postal_code(self) -> None:
        text = "Proszę wysłać list na ul. Długa 5, 00-001 Warszawa."
        entities = PIIRegistry.detect(text)
        addresses = [e for e in entities if e.entity_type == "ADDRESS"]
        self.assertTrue(addresses)
        self.assertEqual(text[addresses[0].start:addresses[0].end], "ul. Długa 5, 00-001 Warszawa")

    def test_detects_organization_with_legal_suffix(self) -> None:
        entities = PIIRegistry.detect("Umowę podpisała Acme Sp. z o.o.")
        self.assertIn(("ORGANIZATION", "Acme Sp. z o.o."), [(e.entity_type, e.value) for e in entities])

    def test_registered_detector_is_used_for_custom_entity_type(self) -> None:
        @PIIRegistry.register_detector("CUSTOM_ID", priority=10)
        class CustomIDDetector:
            def detect(self, text: str):
                if "CUSTOM-123" not in text:
                    return ()
                return (
                    DetectedEntity(
                        entity_type="CUSTOM_ID",
                        value="CUSTOM-123",
                        start=text.index("CUSTOM-123"),
                        end=text.index("CUSTOM-123") + len("CUSTOM-123"),
                    ),
                )

        original = "Dokument CUSTOM-123 jest do weryfikacji."
        context = self.proxy.anonymize(original, session_id="session-7")
        self.assertIn("<CUSTOM_ID_1>", context.text)
        self.assertEqual(self.proxy.restore(context.text, context), original)

    def test_custom_strategy_can_override_default_tokenization(self) -> None:
        class MaskStrategy:
            name = "mask"

            def anonymize(self, *, vault, session_id, value, entity_type) -> str:
                return "[MASKED]"

        vault = InMemoryTokenVault()
        pipeline = (
            PipelineBuilder(vault)
            .with_anonymization_strategy("EMAIL", MaskStrategy)
            .with_anonymization()
            .build()
        )
        proxy = PipelineProxy(pipeline)
        context = proxy.anonymize("Kontakt: jan@example.com", session_id="session-8")

        print(f"\n[CUSTOM STRATEGY] {context.text}")
        self.assertIn("[MASKED]", context.text)
        self.assertEqual(proxy.restore(context.text, context), "Kontakt: jan@example.com")

    def test_builder_registers_residency_and_risk_policies(self) -> None:
        pipeline = (
            PipelineBuilder()
            .forDataClass("PERSONAL")
            .withAuditLevel("FULL")
            .withResidencyPolicy("EU_ONLY")
            .withReIdRiskThreshold(0.2)
            .with_anonymization()
            .build()
        )

        names = [f.name for f in pipeline.inbound.filters]
        print(f"\n[BUILDER POLICIES] {names}")
        self.assertIn("ResidencyPolicy", names)
        self.assertIn("ReIdRiskFilter", names)

    def test_reid_risk_filter_halts_when_threshold_is_exceeded(self) -> None:
        context = PipelineContext(
            session_id="session-risk",
            text="Jan Kowalski, PESEL 44051401458",
            detected_entities=(
                DetectedEntity("PERSON", "Jan Kowalski", 0, 12),
                DetectedEntity("PESEL", "44051401458", 14, 25),
            ),
        )

        result = ReIdRiskFilter(threshold=0.1).process(context)
        print(f"\n[REID RISK] halted={result.halted}, errors={result.errors}, metadata={result.metadata}")

        self.assertTrue(result.halted)
        self.assertIn("Re-identification risk threshold exceeded", result.errors)

    def test_residency_policy_filter_blocks_non_eu_regions(self) -> None:
        context = PipelineContext(
            session_id="session-residency",
            text="test",
            metadata={"region": "US"},
        )

        result = ResidencyPolicyFilter(allowed_regions=("EU", "EEA")).process(context)
        print(f"\n[RESIDENCY] halted={result.halted}, errors={result.errors}, metadata={result.metadata}")

        self.assertTrue(result.halted)
        self.assertIn("Data residency violation for region: US", result.errors)

    def test_output_pii_detector_blocks_unexpected_email_in_response(self) -> None:
        context = PipelineContext(
            session_id="session-output",
            text="Odpowiedź: jan@example.com",
        )

        result = OutputPIIDetector().process(context)
        print(f"\n[OUTPUT PII] halted={result.halted}, errors={result.errors}")

        self.assertTrue(result.halted)
        self.assertIn("Unexpected PII detected in outbound response", result.errors)


if __name__ == "__main__":
    unittest.main()
