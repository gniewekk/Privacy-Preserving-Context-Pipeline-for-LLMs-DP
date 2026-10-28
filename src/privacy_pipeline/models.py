from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True)
class DetectedEntity:
    entity_type: str
    value: str
    start: int
    end: int


@dataclass(frozen=True)
class EntityMetadata:
    entity_type: str
    start: int
    end: int


@dataclass(frozen=True)
class PipelineMemento:
    """Snapshot containing token metadata only; never cleartext PII."""

    session_id: str
    token_map: Mapping[str, EntityMetadata]
    version: int = 1
    applied_filters: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "token_map", MappingProxyType(dict(self.token_map)))

    def extend(self, token: str, metadata: EntityMetadata) -> "PipelineMemento":
        updated = dict(self.token_map)
        updated[token] = metadata
        return PipelineMemento(
            session_id=self.session_id,
            token_map=updated,
            version=self.version + 1,
            applied_filters=self.applied_filters,
        )


@dataclass(frozen=True)
class PipelineContext:
    session_id: str
    text: str
    detected_entities: tuple[DetectedEntity, ...] = ()
    memento: PipelineMemento | None = None
    halted: bool = False
    errors: tuple[str, ...] = ()
    metadata: Mapping[str, object] = field(default_factory=dict)

    def with_changes(self, **changes: object) -> "PipelineContext":
        values = {
            "session_id": self.session_id,
            "text": self.text,
            "detected_entities": self.detected_entities,
            "memento": self.memento,
            "halted": self.halted,
            "errors": self.errors,
            "metadata": self.metadata,
        }
        values.update(changes)
        return PipelineContext(**values)
