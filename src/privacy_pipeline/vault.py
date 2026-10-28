from __future__ import annotations

from dataclasses import dataclass
from threading import RLock


@dataclass(frozen=True)
class TokenRecord:
    token: str
    session_id: str
    entity_type: str


class InMemoryTokenVault:
    """Small local Vault substitute for the skeleton and tests.

    Production code should replace this adapter with an authenticated service
    and encrypted storage. The pipeline only depends on its public contract.
    """

    def __init__(self) -> None:
        self._values: dict[tuple[str, str], str] = {}
        self._records: dict[tuple[str, str], TokenRecord] = {}
        self._counter: dict[tuple[str, str], int] = {}
        self._lock = RLock()

    def store(self, session_id: str, token: str, value: str, entity_type: str) -> str:
        with self._lock:
            key = (session_id, token)
            existing = self._values.get(key)
            if existing is not None:
                if existing != value:
                    raise ValueError(
                        f"Token '{token}' is already mapped to a different value for session '{session_id}'"
                    )
                return token
            self._values[key] = value
            self._records[key] = TokenRecord(
                token=token, session_id=session_id, entity_type=entity_type
            )
            return token

    def tokenize(self, session_id: str, value: str, entity_type: str) -> str:
        with self._lock:
            for (stored_session, stored_token), stored_value in self._values.items():
                record = self._records[(stored_session, stored_token)]
                if (
                    stored_session == session_id
                    and stored_value == value
                    and record.entity_type == entity_type
                ):
                    return stored_token
            counter_key = (session_id, entity_type)
            self._counter[counter_key] = self._counter.get(counter_key, 0) + 1
            token = f"<{entity_type}_{self._counter[counter_key]}>"
            self._values[(session_id, token)] = value
            self._records[(session_id, token)] = TokenRecord(
                token=token, session_id=session_id, entity_type=entity_type
            )
            return token

    def detokenize(self, session_id: str, token: str) -> str:
        with self._lock:
            try:
                return self._values[(session_id, token)]
            except KeyError as exc:
                raise KeyError(f"Unknown token for session: {token}") from exc

    def record(self, session_id: str, token: str) -> TokenRecord:
        return self._records[(session_id, token)]

    def extend_memento(self, memento, value: str, entity_type: str):
        """Tokenize a tool result and atomically extend its session snapshot."""
        from .models import EntityMetadata, PipelineMemento

        if not isinstance(memento, PipelineMemento):
            raise TypeError("memento must be a PipelineMemento")
        with self._lock:
            token = self.tokenize(memento.session_id, value, entity_type)
            extended = memento.extend(token, EntityMetadata(entity_type, 0, len(value)))
            record = self._records[(memento.session_id, token)]
        return extended

    def extend_memento_with_token(self, memento, value: str, entity_type: str):
        extended = self.extend_memento(memento, value, entity_type)
        token = next(token for token in extended.token_map if token not in memento.token_map)
        return extended, token
