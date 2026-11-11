"""Kontrakt filtra (Pipes & Filters, AGENTS.md §3.1).

UWAGA (styk z Osobą A): minimalny protokół; właścicielem pliku jest Osoba A.
"""

from __future__ import annotations

from typing import Protocol

from pipeline.context import PipelineContext


class Filter(Protocol):
    """Bezstanowy filtr: przyjmuje kontekst i zwraca NOWY kontekst lub rzuca wyjątek domenowy."""

    @property
    def filter_id(self) -> str: ...

    def process(self, context: PipelineContext) -> PipelineContext: ...

