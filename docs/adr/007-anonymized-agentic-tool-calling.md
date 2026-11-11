# ADR-007: Anonymized Agentic Tool Calling & Dynamic Memento Expansion

- **Status:** Accepted
- **Date:** 2026-11-10
- **Component:** `src/pipeline/`, `src/state/memento.py`, `src/dispatchers/`

---

## 1. Context & Problem

In agentic LLM workflows (Scenario 5.6 in `ARCHITECTURE.md`), the model does not merely reply with free text—it emits structured `ToolCall` / `ToolCall` requests (e.g., `get_birth_date(user_id="<PERSON_1>")`) to query internal databases or APIs.

This introduces two architectural challenges:
1. **Zero Plaintext Exposure to the LLM:** The LLM only knows the pseudonym `<PERSON_1>`, whereas the internal database requires the real identifier (`"Jan Kowalski"`). Conversely, the database response (`"1990-01-01"`) contains new sensitive PII that must never be returned to the LLM in plaintext.
2. **Multi-Hop State Continuity:** When the tool output (`"1990-01-01"`) is tokenized into `<DATE_1>` before being fed back to the LLM, the final LLM answer (`"<PERSON_1> urodził się <DATE_1>"`) contains placeholders from *both* the initial user prompt and the intermediate tool execution.

---

## 2. Decision

We introduce **Bi-Directional Tool Call Sanitization** combined with **Versioned Dynamic Memento Expansion**:

1. **Structured `ToolCall` Interception:**
   - Inbound prompts are tokenized as usual (`"Jan Kowalski"` -> `<PERSON_1>`), and the LLM receives only pseudonymized context alongside tool schemas.
   - When the LLM emits a `ToolCall(name=..., arguments={"user_id": "<PERSON_1>"})`, the middleware intercepts the call inside the trusted boundary.
2. **Scoped Just-In-Time Detokenization for Tool Execution:**
   - `ToolExecutionMiddleware` requests detokenization of `<PERSON_1>` via `VaultProxy.de_tokenize()` using a scoped service principal, executes the database query with the resolved value, and immediately discards the plaintext from memory.
3. **Outbound Tool Result Tokenization & Memento Evolution:**
   - The raw tool output (`"1990-01-01"`) is passed through `PIIDetectorFilter` and `AnonymizationFilter`, producing `<DATE_1>` and storing its ciphertext in `VaultCore`.
   - `PipelineContext` creates a new evolved `PipelineMemento` snapshot (incrementing `version` and appending `<DATE_1> -> tok_id` to the encapsulated mapping) and updates `ResponseRestorer` for the active `request_id`.
   - Only the sanitized tool result (`{"birth_date": "<DATE_1>"}`) is returned to the LLM.

---

## 3. Rejected Alternatives

### Alternative A: Granting the LLM Direct Database Tool Access with Plaintext Arguments
Allowing the LLM to see raw identifiers so it can construct database queries directly.
- **Why Rejected:** Violates the core privacy boundary. Once raw PII is sent to an external LLM provider, GDPR data minimization and residency guarantees are broken.

### Alternative B: Stateless Per-Hop Mementos Without Session Evolution
Creating an isolated Memento for the tool call that overwrites the initial prompt's Memento.
- **Why Rejected:** The final LLM response references tokens from both the initial prompt (`<PERSON_1>`) and the tool result (`<DATE_1>`). Overwriting the original Memento would leave `<PERSON_1>` unresolved during final response restoration.

---

## 4. Trade-offs & Consequences

### Positive
- **End-to-End Zero Trust for Agentic Loops:** The external LLM orchestrates multi-step tool reasoning over pseudonymized symbols (`<PERSON_1>`, `<DATE_1>`) without ever observing plaintext PII.
- **Full Auditability:** Both the intermediate tool-argument detokenization and the final user-response detokenization are independently authorized and logged by `VaultProxy`.

### Negative / Mitigations
- **Additional Round-Trip Latency:** Intercepting tool calls adds a local detokenization + re-tokenization step per tool invocation. *Mitigation:* Local AES-256-GCM vault operations execute in microseconds in-process, negligible compared to LLM network inference latency.

---

## 5. Compliance with Scenarios

- **Scenario 1 & 2 (Pseudonymization & Authorized Detokenization):** Extends reversible tokenization and RBAC enforcement to structured `ToolCall` payloads.
- **Scenario 3 (Data Residency):** Prevents sensitive database records fetched during tool calls from leaking to non-compliant external LLM endpoints.
- **Scenario 6 (Extensibility):** Prepares the architecture for multi-hop agentic sanitization changes without altering core `Filter` or `TokenizationVault` interfaces.
