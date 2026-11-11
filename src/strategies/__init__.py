"""Wymienne strategie anonimizacji (wzorzec Strategy)."""

from strategies.base import AnonymizationStrategy
from strategies.generalization import GeneralizationStrategy
from strategies.masking import MaskingStrategy
from strategies.selector import StrategySelector

__all__ = [
    "AnonymizationStrategy",
    "GeneralizationStrategy",
    "MaskingStrategy",
    "StrategySelector",
]
