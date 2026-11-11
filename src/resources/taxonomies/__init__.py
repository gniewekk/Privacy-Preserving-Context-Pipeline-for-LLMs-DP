"""Taksonomie referencyjne dla potoku prywatności (zawody, geografia, medycyna)."""

from resources.taxonomies.geography import (
    POLAND_POPULATION,
    US_POPULATION,
    GeoNode,
    GeographyTaxonomy,
)
from resources.taxonomies.icd10 import (
    GLOBAL_CATEGORY_DISTRIBUTION,
    ICD10Entry,
    ICD10Taxonomy,
)
from resources.taxonomies.occupations import (
    OccupationNode,
    OccupationTaxonomy,
)

__all__ = [
    "GLOBAL_CATEGORY_DISTRIBUTION",
    "GeoNode",
    "GeographyTaxonomy",
    "ICD10Entry",
    "ICD10Taxonomy",
    "OccupationNode",
    "OccupationTaxonomy",
    "POLAND_POPULATION",
    "US_POPULATION",
]

