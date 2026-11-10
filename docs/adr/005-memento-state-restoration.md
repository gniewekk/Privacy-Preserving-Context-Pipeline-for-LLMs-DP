# ADR-005: Encapsulated Request-Scoped State Restoration via Memento Pattern

- **Status:** Accepted
- **Date:** 2026-11-10
- **Component:** `src/state/memento.py` (`AnonymizationMemento`, `Caretaker`, `SessionOriginator`)

---

## 1. Context & Problem

During an LLM interaction (Scenario 1), the inbound pipeline replaces sensitive entities with contextual placeholders (e.g., `<PERSON_1>`, `<IBAN_1>`). While the encrypted plaintext values live inside `TokenVault` (protected by `VaultProtectionProxy`), the system must also track **request-scoped execution state** across the asynchronous/synchronous LLM round-trip:
- Which placeholder strings (`<PERSON_1>`) map to which vault `token_id` references (`tok_9f8a...`) for this specific `request_id`,
- Which `key_id` version was active when the request was tokenized,
- The residency policy jurisdiction and tenant binding of the request,
- Support for safe rollback if a downstream filter (`ResidencyGate` or `RiskAssessmentFilter`) halts the pipeline after partial tokenization has already occurred.

If this state is exposed as a public mutable `dict[str, str]` on `PipelineContext` or passed directly to external orchestrators, middleware or plugins could tamper with placeholder-to-token mappings (causing cross-entity substitution or cross-tenant token injection) or inadvertently serialize internal vault references into application logs.

---

## 2. Decision

We implement the **Memento Pattern** (`src/state/memento.py`) comprising three strict roles:

1. **`SessionOriginator` (`Originator`):**
   - Creates an immutable `AnonymizationMemento` snapshot at the end of inbound tokenization and consumes the memento during outbound response restoration (`restore_response()`).
2. **`AnonymizationMemento` (`Memento`):**
   - Captures opaque state: `request_id`, `tenant_id`, `created_at`, `expires_at`, `key_version_id`, `residency_jurisdiction`, and an encapsulated read-only mapping of `placeholder -> token_id`.
   - **Strict Encapsulation:** `AnonymizationMemento` never stores raw plaintext PII—only opaque `token_id` references whose ciphertexts reside in `TokenVault`. External classes (including `Caretaker`) can inspect only narrow metadata (`request_id`, `expires_at`), while the internal mapping state is accessible exclusively to the authorized `SessionOriginator`.
3. **`Caretaker`:**
   - Stores and retrieves `AnonymizationMemento` instances indexed by `request_id` for the duration of the LLM call, enforcing strict TTL eviction and single-use/idempotent lifecycle cleanup.

---

## 3. Rejected Alternatives

### Alternative A: Exposing Public Mutable `token_map: dict[str, str]` on `PipelineContext`
Passing a plain dictionary of placeholder mappings through every filter and out to the HTTP controller.
- **Why Rejected:** Breaks encapsulation and violates immutability. Any downstream filter, logging middleware, or caller could mutate the dictionary (e.g., swapping `<PERSON_1>` to point to another user's `token_id`) or accidentally dump internal vault token identifiers in debug traces.

### Alternative B: Storing Plaintext Directly Inside the Memento Snapshot
Caching `{ "<PERSON_1>": "Jan Kowalski" }` in memory inside `AnonymizationMemento` to avoid calling `VaultProtectionProxy` on response restoration.
- **Why Rejected:** Fatal security flaw. Storing unencrypted PII in a Memento would bypass `VaultProtectionProxy` RBAC enforcement, evade AES-256-GCM encryption at rest, and omit mandatory detokenization audit logging (violating Scenario 2 and Scenario 5).

---

## 4. Trade-offs & Consequences

### Positive
- **Zero Plaintext in State Snapshots:** Because `AnonymizationMemento` stores only `placeholder -> token_id` pointers, restoring a response *still* requires passing through `VaultProtectionProxy.detokenize()`, guaranteeing RBAC verification, key expiration checks, and immutable audit logging on every restoration.
- **Tamper-Resistant Encapsulation:** External components (`Caretaker`, FastAPI controllers, `LLMDispatcher`) cannot read or alter the internal token bindings inside `AnonymizationMemento`.
- **Clean Atomic Rollback:** If `ResidencyGate` aborts an inbound request after `AnonymizationFilter` has already created tokens, `Caretaker` and `SessionOriginator` can use the Memento to cleanly invalidate/purge the orphaned request tokens.

### Negative / Mitigations
- **Memory Management for Orphaned Mementos:** If an external LLM call times out and never reaches the outbound pipeline, the Memento could remain in `Caretaker`. *Mitigation:* `Caretaker` enforces a strict TTL (`expires_at`) and evicts expired mementos automatically.

---

## 5. Compliance with Scenarios

- **Scenario 1 (Pseudonymization & Restoration):** `SessionOriginator` snapshots `<PERSON_1> -> tok_id` into `AnonymizationMemento` before LLM dispatch and uses it to drive authorized detokenization via `VaultProtectionProxy` when the LLM response arrives.
- **Scenario 2 (Unauthorized Detokenization):** Even if a caller possesses a valid `request_id` Memento handle, restoration delegates every token lookup to `VaultProtectionProxy.detokenize()`, which blocks unauthorized principals and writes a `DENIED` audit log.
- **Scenario 5 (Key Rotation & Expiration):** `AnonymizationMemento` records `key_version_id` and `expires_at`; expired mementos or tokens encrypted under revoked keys fail closed during restoration.
