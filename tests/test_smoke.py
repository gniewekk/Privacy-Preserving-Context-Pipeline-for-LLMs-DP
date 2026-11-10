"""Smoke tests verifying package layout and security stack availability."""

import cryptography.hazmat.primitives.ciphers.aead as aead
import fastapi
import pydantic

import detectors
import dispatchers
import domain
import pipeline
import state
import strategies
import vault


def test_package_layout_and_core_dependencies() -> None:
    """Verify target architecture packages and core security dependencies import cleanly."""
    assert domain is not None
    assert pipeline is not None
    assert detectors is not None
    assert strategies is not None
    assert vault is not None
    assert state is not None
    assert dispatchers is not None
    assert pydantic.__version__.startswith("2.")
    assert fastapi.__version__ != ""
    key = aead.AESGCM.generate_key(bit_length=256)
    assert len(key) == 32
