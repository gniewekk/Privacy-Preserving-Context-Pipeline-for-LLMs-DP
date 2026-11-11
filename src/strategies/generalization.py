"""Strategia generalizacji hierarchicznej (k-anonimowość, OCP).

Wspiera uogólnianie wartości z zachowaniem języka promptu (Language.PL / Language.EN):
- Wiek: przedziały 10-letnie, 20-letnie, kategorie demograficzne
- Zawód: drzewo ISCO-08 / KZiS
- Lokalizacja: podział administracyjny TERYT (PL) oraz GeoNames (EN)
- Kody medyczne ICD-10: uogólnienie do kategorii klinicznych
"""

from __future__ import annotations

from domain.models import (
    AnonymizationRequest,
    AnonymizationResult,
    DetectedEntity,
    EntityType,
    Language,
)
from resources.stats.prevalence import DemographicStats
from resources.taxonomies.geography import GeographyTaxonomy
from resources.taxonomies.icd10 import ICD10Taxonomy
from resources.taxonomies.occupations import OccupationTaxonomy


class GeneralizationStrategy:
    """Strategia wspinaczki po drzewach taksonomicznych (nieodwracalna)."""

    strategy_id: str = "generalization_strategy"

    def __init__(self, default_steps: int = 1) -> None:
        self.default_steps = default_steps

    def is_reversible(self) -> bool:
        return False

    def anonymize(
        self,
        entity: DetectedEntity,
        request: AnonymizationRequest,
    ) -> AnonymizationResult:
        steps = request.generalization_level if request.generalization_level > 0 else self.default_steps
        lang = request.language

        replacement = entity.value

        if entity.entity_type == EntityType.AGE:
            replacement = DemographicStats.generalize_age(entity.value, steps=steps, language=lang)

        elif entity.entity_type == EntityType.PROFESSION:
            code = entity.canonical_id
            if code is None:
                node = OccupationTaxonomy.lookup(entity.value)
                code = node.code if node else None
            if code:
                replacement = OccupationTaxonomy.generalize(code, steps=steps, language=lang)
            else:
                replacement = "specjalista" if lang == Language.PL else "professional"

        elif entity.entity_type == EntityType.LOCATION:
            cid = entity.canonical_id
            if cid is None:
                gnode = GeographyTaxonomy.lookup(entity.value)
                cid = gnode.canonical_id if gnode else None
            if cid:
                replacement = GeographyTaxonomy.generalize(cid, steps=steps, language=lang)
            else:
                replacement = "region" if lang == Language.PL else "region"

        elif entity.entity_type in {EntityType.ICD10_CODE, EntityType.MEDICAL_CONDITION}:
            code = entity.canonical_id or entity.value
            entry = ICD10Taxonomy.lookup_code(code)
            if entry:
                replacement = ICD10Taxonomy.generalize_category(entry.category, language=lang)
            else:
                replacement = "schorzenie medyczne" if lang == Language.PL else "medical condition"

        return AnonymizationResult(
            replacement=replacement,
            strategy_id=self.strategy_id,
            entity_type=entity.entity_type,
            reversible=False,
        )

