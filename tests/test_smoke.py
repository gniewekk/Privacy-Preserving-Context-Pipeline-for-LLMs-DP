"""Smoke tests verifying package layout and security stack availability."""

from __future__ import annotations

import unittest

import detectors
import dispatchers
import domain
import pipeline
import state
import strategies
import vault


class TestSmoke(unittest.TestCase):
    def test_package_layout(self) -> None:
        """Verify target architecture packages import cleanly."""
        self.assertIsNotNone(domain)
        self.assertIsNotNone(pipeline)
        self.assertIsNotNone(detectors)
        self.assertIsNotNone(strategies)
        self.assertIsNotNone(vault)
        self.assertIsNotNone(state)
        self.assertIsNotNone(dispatchers)

    def test_security_stack_if_installed(self) -> None:
        """Verify security dependencies when installed in CI / dev environment."""
        try:
            import cryptography.hazmat.primitives.ciphers.aead as aead
            import fastapi
            import pydantic
        except ImportError:
            self.skipTest("Optional dependencies (pydantic/cryptography/fastapi) not installed in local environment")

        self.assertTrue(pydantic.__version__.startswith("2."))
        self.assertNotEqual(fastapi.__version__, "")
        key = aead.AESGCM.generate_key(bit_length=256)
        self.assertEqual(len(key), 32)


if __name__ == "__main__":
    unittest.main()
