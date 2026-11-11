"""Typed domain exceptions enforcing fail-closed behavior and zero raw PII/PHI leakage."""

from __future__ import annotations


class PipelineError(Exception):
    """Base exception for all privacy pipeline errors."""


class PipelineConfigurationError(PipelineError):
    """Raised at build time when PipelineBuilder structural or compliance invariants fail."""


class HardStopError(PipelineError):
    """Base exception for fail-closed pipeline hard stops."""


class ResidencyViolationError(HardStopError):
    """Raised when regulated PII/PHI is routed to a non-compliant jurisdiction."""


class ReIdentificationRiskError(HardStopError):
    """Raised when quasi-identifiers fail to satisfy the target k-anonymity threshold."""


class UnsupportedMediaWithPotentialPIIError(HardStopError):
    """Raised fail-closed when binary/scanned PDF media cannot be safely extracted locally."""


class VaultError(PipelineError):
    """Base exception for cryptographic token vault operations."""


class UnauthorizedVaultAccessError(VaultError):
    """Raised by VaultProtectionProxy when RBAC or tenant verification fails."""


class TokenExpiredError(VaultError):
    """Raised when attempting to detokenize a token past its retention TTL."""


class KeyExpiredError(VaultError):
    """Raised when a cryptographic key is EXPIRED or REVOKED."""


class VaultIntegrityError(VaultError):
    """Raised when AES-256-GCM ciphertext or AAD authentication fails."""
