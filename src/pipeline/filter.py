"""Abstract Filter protocol and immutable Pipe/Pipeline runner."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from pipeline.context import PipelineContext


@runtime_checkable
class Filter(Protocol):
    """Stateless filter stage in the Pipes & Filters architecture."""

    @property
    def filter_name(self) -> str:
        """Canonical name of the filter stage."""
        ...

    def process(self, context: PipelineContext) -> PipelineContext:
        """Consume immutable `context` and return an evolved `PipelineContext`."""
        ...


@runtime_checkable
class Pipe(Protocol):
    """Pipes & Filters chain interface (ARCHITECTURE.md §3.1)."""

    def add_filter(self, filter_stage: Filter) -> Pipe:
        """Return a new chain with `filter_stage` appended."""
        ...

    def execute(self, context: PipelineContext) -> PipelineContext:
        """Run `context` through every configured filter."""
        ...


class Pipeline(Pipe):
    """Immutable, thread-safe Pipes & Filters runner built by PipelineBuilder."""

    def __init__(self, filters: Sequence[Filter]) -> None:
        self._filters: tuple[Filter, ...] = tuple(filters)

    @property
    def filters(self) -> tuple[Filter, ...]:
        """Return the immutable tuple of configured filters."""
        return self._filters

    def add_filter(self, filter_stage: Filter) -> Pipeline:
        """Return a new immutable Pipeline with `filter_stage` appended (ARCHITECTURE.md §3.1)."""
        return Pipeline((*self._filters, filter_stage))

    def execute(self, context: PipelineContext) -> PipelineContext:
        """Execute all filters sequentially with fail-closed short-circuiting on exception."""
        current = context
        for stage in self._filters:
            current = stage.process(current)
            current = current.with_filter_record(stage.filter_name)
        return current
