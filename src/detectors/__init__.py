"""Interfejsy i implementacje strategii detekcji PII/PHI/QID."""

from detectors.base import PIIDetector
from detectors.phi_detector import PHIDetector
from detectors.qid_detector import QIDDetector

__all__ = [
    "PHIDetector",
    "PIIDetector",
    "QIDDetector",
]
