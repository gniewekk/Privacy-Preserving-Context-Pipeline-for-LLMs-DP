"""Strategy pattern interfaces and registry for PII/PHI anonymization."""

from strategies.base import (
    AnonymizationStrategy,
    MaskingStrategy,
    PlaceholderTokenStrategy,
    StrategyRegistry,
    register_strategy,
)

__all__ = [
    "AnonymizationStrategy",
    "MaskingStrategy",
    "PlaceholderTokenStrategy",
    "StrategyRegistry",
    "register_strategy",
]
