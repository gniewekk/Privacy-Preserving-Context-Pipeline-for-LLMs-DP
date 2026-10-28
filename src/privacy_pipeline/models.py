from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
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

    @staticmethod
    def _payload(
        session_id: str,
        token_map: Mapping[str, EntityMetadata],
        version: int,
        applied_filters: tuple[str, ...],
    ) -> dict[str, object]:
        return {
            "session_id": session_id,
            "token_map": {
                token: {"entity_type": item.entity_type, "start": item.start, "end": item.end}
                for token, item in sorted(token_map.items())
            },
            "version": version,
            "applied_filters": list(applied_filters),
        }

    def to_json(self) -> str:
        payload = self._payload(self.session_id, self.token_map, self.version, self.applied_filters)
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        payload["checksum"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, serialized: str) -> "PipelineMemento":
        try:
            payload = json.loads(serialized)
            checksum = payload.pop("checksum")
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if not isinstance(checksum, str) or not hmac.compare_digest(checksum, expected):
                raise ValueError("Memento integrity check failed")
            entries = {
                token: EntityMetadata(**metadata)
                for token, metadata in payload["token_map"].items()
            }
            return cls(
                session_id=payload["session_id"],
                token_map=entries,
                version=int(payload["version"]),
                applied_filters=tuple(payload.get("applied_filters", ())),
            )
        except ValueError:
            raise
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid Memento snapshot") from exc

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

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    def to_snapshot_json(self) -> str:
        if self.memento is None:
            raise ValueError("Only an anonymized context can be snapshotted")
        if any(entity.value and entity.value in self.text for entity in self.detected_entities):
            raise ValueError("Context still contains cleartext PII; anonymize it before snapshotting")
        payload: dict[str, object] = {
            "session_id": self.session_id,
            "text": self.text,
            "memento": json.loads(self.memento.to_json()),
            "halted": self.halted,
            "errors": list(self.errors),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        payload["checksum"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_snapshot_json(cls, serialized: str) -> "PipelineContext":
        try:
            payload = json.loads(serialized)
            checksum = payload.pop("checksum")
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if not isinstance(checksum, str) or not hmac.compare_digest(checksum, expected):
                raise ValueError("PipelineContext snapshot integrity check failed")
            memento = PipelineMemento.from_json(json.dumps(payload["memento"]))
            if memento.session_id != payload["session_id"]:
                raise ValueError("Snapshot sessionId does not match Memento")
            return cls(
                session_id=payload["session_id"],
                text=payload["text"],
                memento=memento,
                halted=bool(payload["halted"]),
                errors=tuple(payload["errors"]),
            )
        except ValueError:
            raise
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid PipelineContext snapshot") from exc

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
