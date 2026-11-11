# ADR-001: Synchronous Prompt/Response Sanitization via Pipes & Filters

- **Status:** Accepted
- **Date:** 2026-11-10
- **Component:** `src/pipeline/` (`Filter`, `Pipe`, `PipelineContext`)

---

## 1. Context & Problem

Our system acts as a real-time privacy-preserving middleware between client applications and external Large Language Models (LLMs). Before an inbound prompt reaches an external LLM provider, it must undergo a deterministic sequence of transformations and policy checks:
1. Language and entity detection (PII/PHI identification),
2. Re-identification risk evaluation ($k$-anonymity check on quasi-identifiers),
3. Redaction, masking, generalization, or reversible tokenization,
4. Regulatory data residency enforcement (e.g., blocking PHI from leaving the EU),
5. Pre-dispatch audit logging.

On the return path, the LLM response must be scanned for leaked PII and selectively re-identified for authorized callers. We need an architectural pattern that enforces strict Single Responsibility Principle (SRP), supports deterministic fail-closed short-circuiting when a security gate fails, guarantees thread safety across concurrent FastAPI requests, and allows different pipeline topologies per tenant or data classification without duplicating orchestration logic.

---

## 2. Decision

We adopt the **Pipes & Filters** architectural pattern (`src/pipeline/`) operating over an immutable, strictly typed `PipelineContext` (Pydantic v2 `frozen=True` model).

- **`Filter` Interface:** Every processing stage implements a single method:
  ```python
  class Filter(Protocol):
      def process(self, context: PipelineContext) -> PipelineContext: ...
  ```
- **Stateless Filters:** Concrete filters (`PIIDetectorFilter`, `RiskAssessmentFilter`, `AnonymizationFilter`, `ResidencyPolicyFilter`, `ResponseRestorer`) store only immutable configuration and injected interfaces (`PIIDetector`, `StrategySelector`, `ResidencyPolicyEngine`, `TokenizationVault`). All per-request data travels exclusively inside `PipelineContext`.
- **Fail-Closed Short-Circuiting:** Any filter may halt execution immediately by raising a typed domain exception (e.g., `ResidencyViolationError`, `ReIdentificationRiskError`), preventing downstream dispatch to the external LLM and triggering an immutable audit event.
- **Zero Concrete Branching:** Filters never inspect concrete detector or strategy class types via `if/elif` or `match/case`.

---

## 3. Rejected Alternatives

### Alternative A: Monolithic `SanitizationService` Class
A single procedural service orchestrating detection, risk calculation, vault encryption, residency checks, and LLM dispatch in one method (`sanitize_and_send()`).
- **Why Rejected:** Violates SRP and the Open-Closed Principle (OCP). Reordering stages, making $k$-anonymity optional for non-analytic workloads, or accommodating new architectural change requests would require editing a high-risk central method, increasing regression and security bypass risks.

### Alternative B: Asynchronous Event-Driven Message Broker (Kafka / RabbitMQ Choreography)
Publishing prompts and intermediate sanitization states as asynchronous events across decoupled broker topics.
- **Why Rejected:** LLM chat completions and agentic tool calls are synchronous request/response workflows requiring sub-50ms middleware overhead. Introducing an external message broker adds operational complexity, serialization latency, and expands the attack surface (persisting raw or partially sanitized PII in broker logs before anonymization completes).

---

## 4. Trade-offs & Consequences

### Positive
- **Deterministic Ordering & Fail-Closed Security:** A `ResidencyPolicyFilter` filter is guaranteed to run before `LLMDispatcher`, ensuring zero network egress on policy violation.
- **Concurrency Safety:** Because filters are stateless and `PipelineContext` is frozen, a single built `Pipeline` instance can safely process thousands of concurrent requests without race conditions or state bleed between tenants.
- **Isolated Unit Testing:** Each filter can be unit-tested in complete isolation by passing a synthetic `PipelineContext` and asserting on the returned context or raised exception.

### Negative / Mitigations
- **Copy Overhead of Immutable Context:** Creating a new `PipelineContext` via `.model_copy(update={...})` at each filter stage introduces minor allocation overhead. *Mitigation:* `PipelineContext` contains lightweight tuple references and metadata; measured Pydantic v2 shallow copy overhead is <15 microseconds per filter.

---

## 5. Compliance with Scenarios

- **Scenario 1 (Pseudonymization Happy Path):** Inbound `PIIDetectorFilter` -> `AnonymizationFilter` replaces PII with `<PERSON_1>` tokens; outbound `ResponseRestorer` restores values for authorized callers.
- **Scenario 3 (EU Data Residency Block for PHI):** `ResidencyPolicyFilter` inspects `context.detected_entities` for `PHI` tags and compares against `context.target_endpoint.region`, raising `ResidencyViolationError` before any network call occurs.
- **Scenario 4 (Re-identification Risk / $k$-Anonymity):** `RiskAssessmentFilter` evaluates quasi-identifier combinations in `PipelineContext` and invokes generalization or halts execution if $k < k_{\text{min}}$.
- **Scenario 6 (Extensibility):** New filters can be inserted into the pipe without modifying any existing filter implementation.
