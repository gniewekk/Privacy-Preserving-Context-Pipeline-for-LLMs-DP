"""Selektor strategii anonimizacji (StrategySelector — OCP & Dependency Injection).

Rozstrzyga, która strategia anonimizacji ma zostać zastosowana dla danej encji
na podstawie:
1. Wyników analizy ryzyka k-anonimowości (RiskAssessmentResult):
   - Quasi-identyfikatory z wymogiem generalizacji (level > 0) -> GeneralizationStrategy
2. Kategorii encji i typu:
   - Dane zbędne lub maskowane z urzędu -> MaskingStrategy
   - Encje zarejestrowane dla odwracalnej tokenizacji (Osoba B/D) -> TokenizationStrategy
"""

from __future__ import annotations

from typing import Mapping

from domain.models import (
    AnonymizationRequest,
    DetectedEntity,
    EntityCategory,
    EntityType,
    RiskAssessmentResult,
)
from strategies.base import AnonymizationStrategy
from strategies.generalization import GeneralizationStrategy
from strategies.masking import MaskingStrategy


class StrategySelector:
    """Wybiera strategię anonimizacji bez inspekcji konkretnych typów w filtrach (OCP)."""

    def __init__(
        self,
        *,
        default_strategy: AnonymizationStrategy | None = None,
        type_strategies: Mapping[EntityType, AnonymizationStrategy] | None = None,
        generalization_strategy: GeneralizationStrategy | None = None,
        masking_strategy: MaskingStrategy | None = None,
    ) -> None:
        self.generalization_strategy = generalization_strategy or GeneralizationStrategy()
        self.masking_strategy = masking_strategy or MaskingStrategy()
        self.default_strategy = default_strategy or self.masking_strategy
        self._type_strategies = dict(type_strategies or {})

    def register_strategy(
        self,
        entity_type: EntityType,
        strategy: AnonymizationStrategy,
    ) -> None:
        self._type_strategies[entity_type] = strategy

    def select(
        self,
        entity: DetectedEntity,
        request: AnonymizationRequest,
        risk_assessment: RiskAssessmentResult | None = None,
    ) -> tuple[AnonymizationStrategy, AnonymizationRequest]:
        """Wybiera strategię i dostosowuje AnonymizationRequest (np. poziom generalizacji)."""
        # 1. Sprawdzenie, czy encja jest quasi-identyfikatorem podlegającym generalizacji
        if entity.category == EntityCategory.QUASI_IDENTIFIER and risk_assessment is not None:
            step = risk_assessment.step_for(entity)
            if step is not None and step.level > 0:
                adjusted_request = AnonymizationRequest(
                    request_id=request.request_id,
                    language=request.language,
                    data_class=request.data_class,
                    generalization_level=step.level,
                )
                return self.generalization_strategy, adjusted_request

        # 2. Sprawdzenie rejestracji per typ encji
        if entity.entity_type in self._type_strategies:
            return self._type_strategies[entity.entity_type], request

        # 3. Domyślne mapowanie dla kategorii
        if entity.category == EntityCategory.QUASI_IDENTIFIER:
            return self.generalization_strategy, request

        return self.default_strategy, request

