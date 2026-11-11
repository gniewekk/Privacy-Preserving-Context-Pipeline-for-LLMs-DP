"""Strategy pattern interfaces and StrategySelector for PII/PHI anonymization."""

from strategies.base import (
    AnonymizationStrategy,
    MaskingStrategy,
    StrategySelector,
    TokenizationStrategy,
    register_strategy,
)

__all__ = [
    "AnonymizationStrategy",
    "MaskingStrategy",
    "StrategySelector",
    "TokenizationStrategy",
    "register_strategy",
]
