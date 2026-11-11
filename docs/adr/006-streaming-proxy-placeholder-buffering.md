# ADR-006: Streaming Response Detokenization via Placeholder Window Buffering

- **Status:** Accepted
- **Date:** 2026-11-10
- **Component:** `src/pipeline/` (`StreamingResponseRestorer`, `OutboundPipeline`)

---

## 1. Context & Problem

Modern LLM providers return completions incrementally via Server-Sent Events (SSE) token streams. When our inbound pipeline replaces sensitive PII with placeholders such as `<PERSON_1>` or `<IBAN_1>`, the LLM's streamed response may split a single placeholder across multiple SSE chunks (e.g., chunk 1: `"Sprawa <PER"`, chunk 2: `"SON_1"`, chunk 3: `"> dotyczy..."`).

This creates a tension between two requirements:
1. **Low Time-To-First-Token (TTFT) & Bounded Memory:** Buffering the entire LLM response until ` [DONE]` before running `OutputPIIDetector` and `ResponseRestorer` destroys streaming responsiveness.
2. **Fail-Closed Security & Atomic Placeholder Resolution:** Emitting partial chunks directly without buffering placeholder boundaries would leak raw `<PERSON_1>` fragments to the client, prevent `VaultProxy` from detokenizing the placeholder, or allow newly hallucinated PII to slip through before `OutputPIIDetector` can inspect it.

---

## 2. Decision

We implement a **Bounded Placeholder Window Buffer** inside the outbound streaming filter (`StreamingResponseRestorer`):

1. **Pass-Through Outside Delimiters:** Characters outside placeholder delimiters (`<` ... `>`) are scanned in sliding context windows and emitted downstream immediately to preserve streaming latency.
2. **Delimiter Hold-Back Buffer:** Upon encountering an opening `<` character, the stream processor holds subsequent characters in a small bounded lookahead buffer (capped at `MAX_PLACEHOLDER_LENGTH = 64` bytes) until:
   - A matching closing `>` is received and matches the canonical placeholder pattern (`^<[A-Z_]+_[0-9]+>$`), at which point the complete token is validated through `OutputPIIDetector`, resolved via `PipelineContext` + `VaultProxy.de_tokenize()`, and emitted as restored plaintext (or redacted on policy failure).
   - A non-placeholder character or buffer limit is reached without a valid placeholder match, at which point the held buffer is flushed safely after output PII verification.
3. **Fail-Closed on Output PII Leak:** If `OutputPIIDetector` detects unexpected raw PII/PHI in the outbound stream (e.g., training data memorization or prompt-injection leakage), the stream is immediately terminated with a security event or redacted before reaching the caller.

---

## 3. Rejected Alternatives

### Alternative A: Full-Response Buffering Before Detokenization
Waiting for the complete LLM generation to finish before running outbound filters.
- **Why Rejected:** Eliminates the UX and latency benefits of SSE streaming, increases memory pressure under high concurrency, and fails if the client relies on incremental chunk delivery.

### Alternative B: Naive Chunk-by-Chunk String Replacement (`chunk.replace("<PERSON_1>", value)`)
Running string replacement independently on each raw SSE chunk as it arrives.
- **Why Rejected:** Fails deterministically whenever an LLM tokenizer splits `<PERSON_1>` across two or more SSE chunks, leaving unresolved `<PERSON_1>` tokens in the user-facing output.

---

## 4. Trade-offs & Consequences

### Positive
- **Sub-Millisecond Streaming Overhead:** Non-placeholder text flows immediately while placeholders are atomically reassembled and de_tokenized.
- **Preserves RBAC & Audit Guarantees:** Every resolved placeholder still passes through `VaultProxy` and `PipelineMemento` verification.
- **Change Readiness:** Directly prepares the outbound pipeline for streaming response sanitization.

### Negative / Mitigations
- **Slight Jitter on `<` Characters:** Any literal `<` in normal text (e.g., mathematical comparisons `a < b`) briefly buffers until the first non-token character (such as a space or lowercase letter) is seen. *Mitigation:* Strict regex prefix matching flushes non-matching `<` sequences as soon as the first invalid character arrives (typically 1–2 tokens).

---

## 5. Compliance with Scenarios

- **Scenario 1 (Pseudonymization & Restoration):** Guarantees that `<PERSON_1>` and `<PESEL_1>` placeholders are accurately restored even when streamed across chunk boundaries.
- **Scenario 2 (Unauthorized Detokenization):** If the streaming consumer lacks `DETOKENIZE` permission, `VaultProxy` denies restoration and logs the attempt without stalling or crashing the pipeline.
- **Scenario 6 (Extensibility):** Provides a clean streaming abstraction decoupled from concrete LLM provider SDKs.
