import unittest

from privacy_pipeline import PipelineContext


class ImmutableContextTests(unittest.TestCase):
    def test_context_metadata_is_read_only(self) -> None:
        context = PipelineContext("immutable", "safe", metadata={"region": "EU"})
        with self.assertRaises(TypeError):
            context.metadata["region"] = "US"


if __name__ == "__main__":
    unittest.main()
