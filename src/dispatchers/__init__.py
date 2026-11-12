"""Abstract LLMDispatcher protocol and ToolExecutionMiddleware for agentic workflows."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from detectors.base import PIIDetector, resolve_overlapping_spans
from detectors.heuristic import ContextRuleEnhancer
from domain.exceptions import (
    PipelineError,
    UnauthorizedVaultAccessError,
    VaultError,
)
from domain.models import (
    AnonymizationRequest,
    AuditAction,
    AuditEvent,
    AuditOutcome,
    DetectedEntity,
    EndpointMetadata,
    EntityType,
    SecurityContext,
    SecurityPrincipal,
    ToolCall,
)
from domain.protocols import AuditWriter, TokenizationVault
from state.memento import EntityMetadata, PipelineMemento, ResponseRestorer
from strategies.base import StrategySelector, TokenizationStrategy


@runtime_checkable
class LLMDispatcher(Protocol):
    """Abstract external LLM provider adapter carrying declarative EndpointMetadata (§4)."""

    @property
    def endpoint_metadata(self) -> EndpointMetadata:
        """Declarative provider and jurisdiction metadata for ResidencyPolicyFilter."""
        ...

    def dispatch(self, sanitized_prompt: str) -> str:
        """Send `sanitized_prompt` to the external LLM and return its raw response."""
        ...


class ToolExecutionMiddleware:
    """Intercepts agentic ToolCalls, detokenizes args in-boundary, and expands Memento (ADR-007).

    Implements Scenario 5.6:
    1. Intercepts `ToolCall` with pseudonymized arguments (`{"user_id": "<PERSON_1>"}`).
    2. De-tokenizes arguments via `TokenizationVault` for an authorized `SecurityPrincipal`.
    3. Executes the registered local tool handler with plaintext arguments inside the boundary.
    4. Immediately detects and tokenizes PII in the tool output (`"1990-01-01"` -> `"<DATE_1>"`).
    5. Atomically expands `PipelineMemento` (`version + 1`) and updates `ResponseRestorer`.
    6. Returns only the sanitized tool result to the LLM.
    """

    def __init__(
        self,
        vault: TokenizationVault,
        response_restorer: ResponseRestorer,
        detectors: Sequence[PIIDetector],
        *,
        strategy_selector: StrategySelector | None = None,
        enhancer: ContextRuleEnhancer | None = None,
        tools: Mapping[str, Callable[..., Any]] | None = None,
        audit_writer: AuditWriter | None = None,
    ) -> None:
        self._vault = vault
        self._response_restorer = response_restorer
        self._response_restorer.bind_vault(vault)
        self._detectors: tuple[PIIDetector, ...] = tuple(detectors)
        self._enhancer = enhancer or ContextRuleEnhancer()
        self._strategy_selector = strategy_selector or StrategySelector(
            default_strategy=TokenizationStrategy(reversible=True, vault=vault)
        )
        self._tools: dict[str, Callable[..., Any]] = dict(tools) if tools is not None else {}
        self._audit_writer = audit_writer

    def register_tool(self, name: str, handler: Callable[..., Any]) -> None:
        """Register a local tool callable invoked when `ToolCall.name == name`."""
        self._tools[name] = handler

    def _resolve_memento(
        self,
        tool_call: ToolCall,
        memento: PipelineMemento | str | None,
    ) -> PipelineMemento:
        if isinstance(memento, PipelineMemento):
            resolved = memento
        elif isinstance(memento, str):
            found = self._response_restorer.get(memento)
            if found is None:
                found = self._response_restorer.get_by_session(memento)
            if found is None:
                raise VaultError(f"No PipelineMemento found for identifier {memento!r}.")
            resolved = found
        elif tool_call.session_id is not None:
            found_sess = self._response_restorer.get_by_session(tool_call.session_id)
            if found_sess is None:
                raise VaultError(
                    f"No PipelineMemento found for session_id={tool_call.session_id!r}."
                )
            resolved = found_sess
        else:
            raise VaultError("ToolCall interception requires a session_id or PipelineMemento.")

        resolved.verify_integrity()
        if (
            tool_call.session_id is not None
            and resolved.session_id is not None
            and tool_call.session_id != resolved.session_id
        ):
            raise UnauthorizedVaultAccessError(
                "ToolCall session_id does not match active PipelineMemento session_id."
            )
        return resolved

    def _detokenize_value(
        self,
        value: Any,
        memento: PipelineMemento,
        principal: SecurityPrincipal | None,
        sec_ctx: SecurityContext,
    ) -> Any:
        if isinstance(value, str):
            return self._response_restorer.restore_response(
                value,
                memento,
                principal=principal,
                context=sec_ctx,
            )
        if isinstance(value, dict):
            return {
                str(k): self._detokenize_value(v, memento, principal, sec_ctx)
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [
                self._detokenize_value(item, memento, principal, sec_ctx) for item in value
            ]
        return value

    @staticmethod
    def _initial_entity_counters(memento: PipelineMemento) -> dict[EntityType, int]:
        counters: dict[EntityType, int] = {}
        for placeholder, meta in memento.token_map.items():
            current = counters.get(meta.entity_type, 0)
            idx = current + 1
            if placeholder.startswith("<") and placeholder.endswith(">") and "_" in placeholder:
                suffix = placeholder[placeholder.rfind("_") + 1 : -1]
                if suffix.isdigit():
                    idx = max(idx, int(suffix))
            counters[meta.entity_type] = idx
        return counters

    def _anonymize_tool_string(
        self,
        text: str,
        *,
        memento: PipelineMemento,
        principal: SecurityPrincipal | None,
        sec_ctx: SecurityContext,
        language: str,
        counters: dict[EntityType, int],
        new_tokens: dict[str, EntityMetadata],
    ) -> str:
        if not text.strip():
            return text

        raw_detected: list[DetectedEntity] = []
        for detector in self._detectors:
            raw_detected.extend(detector.detect(text, language=language))
        enhanced = self._enhancer.enhance(text, raw_detected) if raw_detected else ()
        merged = resolve_overlapping_spans(enhanced)
        if not merged:
            return text

        chars = list(text)
        ordered = sorted(merged, key=lambda e: (e.start, e.end))
        replacements: list[tuple[DetectedEntity, str]] = []

        for entity in ordered:
            idx = counters.get(entity.entity_type, 0) + 1
            counters[entity.entity_type] = idx
            strategy = self._strategy_selector.select(entity, sec_ctx)
            if hasattr(strategy, "with_vault") and strategy.can_reverse():
                strategy = strategy.with_vault(self._vault)
            req = AnonymizationRequest(
                request_id=sec_ctx.request_id,
                tenant_id=sec_ctx.tenant_id,
                principal=principal,
                context=sec_ctx,
                entity_index=idx,
            )
            res = strategy.anonymize(entity, req)
            if res.is_reversible and res.token_id is not None:
                is_synth = not (
                    res.replacement_text.startswith("<")
                    and res.replacement_text.endswith(">")
                )
                new_tokens[res.replacement_text] = EntityMetadata(
                    token_id=res.token_id,
                    entity_type=res.entity_type,
                    key_id=res.key_id,
                    is_synthetic=is_synth,
                )
            replacements.append((entity, res.replacement_text))

        for entity, replacement_text in reversed(replacements):
            chars[entity.start : entity.end] = list(replacement_text)

        return "".join(chars)

    def _sanitize_tool_output(
        self,
        output: Any,
        *,
        memento: PipelineMemento,
        principal: SecurityPrincipal | None,
        sec_ctx: SecurityContext,
        language: str,
        counters: dict[EntityType, int],
        new_tokens: dict[str, EntityMetadata],
    ) -> Any:
        if isinstance(output, str):
            return self._anonymize_tool_string(
                output,
                memento=memento,
                principal=principal,
                sec_ctx=sec_ctx,
                language=language,
                counters=counters,
                new_tokens=new_tokens,
            )
        if isinstance(output, dict):
            return {
                str(k): self._sanitize_tool_output(
                    v,
                    memento=memento,
                    principal=principal,
                    sec_ctx=sec_ctx,
                    language=language,
                    counters=counters,
                    new_tokens=new_tokens,
                )
                for k, v in output.items()
            }
        if isinstance(output, list):
            return [
                self._sanitize_tool_output(
                    item,
                    memento=memento,
                    principal=principal,
                    sec_ctx=sec_ctx,
                    language=language,
                    counters=counters,
                    new_tokens=new_tokens,
                )
                for item in output
            ]
        return output

    def intercept(
        self,
        tool_call: ToolCall,
        memento: PipelineMemento | str | None = None,
        *,
        principal: SecurityPrincipal | None = None,
        context: SecurityContext | None = None,
        language: str = "en",
    ) -> Any:
        """Intercept `tool_call`, detokenize args, run tool, tokenize output & expand Memento."""
        if tool_call.name not in self._tools:
            raise PipelineError(f"Tool {tool_call.name!r} is not registered.")

        active_memento = self._resolve_memento(tool_call, memento)
        sec_ctx = context or SecurityContext(
            request_id=active_memento.request_id,
            tenant_id=active_memento.tenant_id,
            session_id=active_memento.session_id,
            data_class=active_memento.data_class,
            jurisdiction=active_memento.residency_jurisdiction,
        )

        # 1. Scoped JIT detokenization of tool call arguments inside the trusted boundary
        resolved_args = self._detokenize_value(
            tool_call.arguments,
            active_memento,
            principal,
            sec_ctx,
        )

        # 2. Execute local tool handler and discard plaintext arguments
        handler = self._tools[tool_call.name]
        raw_result = handler(**resolved_args)
        del resolved_args

        # 3. Immediate tokenization of tool output and Dynamic Memento Expansion
        counters = self._initial_entity_counters(active_memento)
        new_tokens: dict[str, EntityMetadata] = {}
        sanitized_result = self._sanitize_tool_output(
            raw_result,
            memento=active_memento,
            principal=principal,
            sec_ctx=sec_ctx,
            language=language,
            counters=counters,
            new_tokens=new_tokens,
        )
        del raw_result

        if new_tokens:
            new_key_id = next(
                (m.key_id for m in new_tokens.values() if m.key_id is not None),
                active_memento.key_id,
            )
            expanded = active_memento.expand(
                new_tokens,
                session_id=active_memento.session_id,
                tenant_id=active_memento.tenant_id,
                key_id=new_key_id,
            )
            self._response_restorer.store(expanded)

        if self._audit_writer is not None:
            self._audit_writer.record(
                AuditEvent(
                    event_id=f"evt_{uuid.uuid4().hex[:12]}",
                    timestamp=datetime.now(UTC),
                    action=AuditAction.TOOL_EXECUTION,
                    outcome=AuditOutcome.COMPLETED,
                    principal_id=principal.principal_id if principal else "anonymous",
                    tenant_id=sec_ctx.tenant_id,
                    request_id=sec_ctx.request_id,
                    session_id=sec_ctx.session_id,
                    reason=(
                        f"Executed tool {tool_call.name!r} and expanded Memento with "
                        f"{len(new_tokens)} new tokens."
                    ),
                )
            )

        return sanitized_result


__all__ = [
    "LLMDispatcher",
    "ToolExecutionMiddleware",
]
