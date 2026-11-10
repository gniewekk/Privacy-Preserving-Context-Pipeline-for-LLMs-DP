# AI Agent Governance & Architecture Instructions (`AGENTS.md`)

> **Project:** LLM Anonymization & Pseudonymization Pipeline  
> **Course:** University Design Patterns & Security Project (4-Person Team | 4 Milestones: Weeks 2, 4, 6, 8)  
> **Python Runtime:** Python 3.12+  
> **Core Stack:** Pydantic v2, FastAPI, `cryptography` (AES-256-GCM), `pytest`, `ruff`, `mypy`, `bandit`, `pip-audit`

This file is the **authoritative specification** for all AI coding agents and human developers working in this repository. Every generated file, refactoring, and test case must strictly comply with the architectural invariants, design patterns, and security boundaries defined below.

---

## 1. Tech Stack & Mandatory Verification Commands

Before considering any task complete or opening a Pull Request, all five verification gates must pass with zero errors or high/medium warnings:

```bash
# 1. Unit, integration, and security abuse test suite
pytest -v

# 2. Strict static type checking across all source modules
mypy --strict src/

# 3. Linting, import sorting, and formatting verification
ruff check src/ tests/

# 4. Static Application Security Testing (SAST)
bandit -r src/

# 5. Supply-chain and dependency vulnerability scanning
pip-audit
```

### Coding Standards
- **Python 3.12+ typing syntax:** Use modern type parameters (`type Alias = ...`, `list[str]`, `dict[str, Any]`, `X | Y`, `Self`, `@override`). Avoid legacy `typing.List`, `typing.Dict`, or `typing.Optional`.
- **Pydantic v2:** Use `BaseModel` with `ConfigDict(frozen=True, extra="forbid")` for immutable value objects, contexts, and audit payloads. Never use deprecated Pydantic v1 methods (`.dict()`, `.parse_obj()`, `class Config:`).
- **Cryptography:** Use `cryptography.hazmat.primitives.ciphers.aead.AESGCM` exclusively for authenticated encryption. Never use unauthenticated modes (ECB, CBC without MAC) or custom cryptographic primitives.

---

## 2. Target Repository Module Structure

```text
src/
├── domain/          # Immutable Pydantic v2 models, enums, exceptions, RBAC claims, audit events
├── pipeline/        # Pipes & Filters core + PipelineBuilder
│   ├── context.py   # Immutable PipelineContext & execution metadata
│   ├── filter.py    # Abstract Filter protocol/ABC and Pipe runner
│   ├── filters.py   # Concrete stateless filters (DetectionFilter, AnonymizationFilter, ResidencyGate, etc.)
│   └── builder.py   # Fluent PipelineBuilder with structural invariant validation
├── detectors/       # Strategy pattern for PII/PHI detection (PIIDetector interface + Regex, NER, Heuristic)
├── strategies/      # Strategy pattern for anonymization (AnonymizationStrategy interface + Masking, Tokenization, k-Anonymity)
├── vault/           # Protection Proxy + AES-256-GCM TokenVault + KeyManager
│   ├── vault.py     # Internal TokenVault (package-private; NEVER accessed directly by callers)
│   ├── proxy.py     # VaultProtectionProxy enforcing RBAC and writing immutable audit logs
│   └── keys.py      # KeyManager with key_id versioning, rotation, and TTL expiration
├── state/           # Memento pattern for safe request-scoped context restoration
│   └── memento.py   # AnonymizationMemento & Caretaker
└── dispatchers/     # Abstract LLMDispatcher interface and provider adapters
```

---

## 3. Strict Design Pattern Rules (No Leaky Abstractions)

### 3.1 Pipes & Filters (`src/pipeline/`)
- **Stateless Filters:** Every filter must implement the `Filter` interface (`def process(self, context: PipelineContext) -> PipelineContext`). Filters must hold **zero mutable per-request state** so a built `Pipeline` instance is completely thread-safe and reusable across concurrent FastAPI requests.
- **Immutable Context:** `PipelineContext` must be an immutable (`frozen=True`) Pydantic v2 model. Filters return a new evolved context via `.model_copy(update={...})` or raise a typed domain exception (`ResidencyViolationError`, `ReIdentificationRiskError`, `UnauthorizedVaultAccessError`) to trigger a fail-closed hard stop.
- **Zero Concrete Branching:** Filters (`DetectionFilter`, `AnonymizationFilter`, `ResidencyGate`, `RestorationFilter`) **MUST NOT** contain `if/elif/else` or `match/case` branches checking concrete detector types, entity names, or strategy class types. All polymorphism is delegated to injected interfaces or strategy registries.

### 3.2 Strategy Pattern (`src/strategies/`, `src/detectors/`)
- **`PIIDetector` Interface (`src/detectors/`):**
  - Defines `detect(self, text: str, language: str) -> Sequence[DetectedEntity]`.
  - Concrete implementations include `RegexPIIDetector` (PESEL, SSN, Email, IBAN), `NERPIIDetector`, and `HeuristicPIIDetector`.
- **`AnonymizationStrategy` Interface (`src/strategies/`):**
  - Defines `anonymize(self, entity: DetectedEntity, context: AnonymizationRequest) -> AnonymizationResult` and `is_reversible(self) -> bool`.
  - Concrete implementations include `MaskingStrategy` (irreversible), `ReversibleTokenizationStrategy` (stores encrypted mapping via `VaultProtectionProxy`), and `KAnonymityGeneralizationStrategy` (quasi-identifier hierarchy generalization).
- **Strict Open-Closed Principle (OCP):**
  - Adding a new detector (e.g., Scenario 6: Polish IBAN detector with Modulo-97 checksum validation) or a new anonymization strategy **MUST require zero line modifications** to `src/pipeline/` core classes. New implementations are registered via the `StrategyRegistry` / `PipelineBuilder`.

### 3.3 Builder Pattern (`src/pipeline/builder.py`)
- **`PipelineBuilder` Fluent Interface:**
  - Provides fluent configuration methods: `.with_detector(...)`, `.with_strategy(...)`, `.with_residency_policy(...)`, `.with_vault_proxy(...)`, `.with_k_anonymity_threshold(...)`, and `.build()`.
- **Build-Time Invariant Validation:**
  - `.build()` must validate pipeline completeness before returning an immutable `Pipeline`:
    1. At least one `PIIDetector` is configured before `AnonymizationFilter`.
    2. If `ReversibleTokenizationStrategy` is registered, a valid `VaultProtectionProxy` and `Caretaker` must be bound.
    3. If the pipeline handles `PHI` or regulated data classes, a `ResidencyGate` filter is mandatory.
    4. Conflicting or incomplete configurations fail fast at build time with `PipelineConfigurationError`.

### 3.4 Protection Proxy (`src/vault/proxy.py`)
- **`VaultProtectionProxy` Wrapping `TokenVault`:**
  - Both `VaultProtectionProxy` and `TokenVault` implement the `VaultProtocol` interface.
  - **Mandatory Access Control:** Before executing `detokenize(...)` or `rotate_keys(...)`, `VaultProtectionProxy` verifies the caller's `SecurityPrincipal` (RBAC roles, clearance scope, tenant match, and token expiration).
  - **Mandatory Audit Logging:** Every call to `tokenize`, `detokenize`, and `rotate_keys` writes a tamper-evident `AuditEvent` to the `AuditLogger` **regardless of whether access was GRANTED or DENIED**.
  - **Encapsulation Boundary:** Direct instantiation or invocation of `TokenVault` outside `src/vault/proxy.py` and dedicated unit tests is **strictly forbidden**. Pipeline filters and restoration services may only hold a reference to `VaultProtectionProxy` (typed as `VaultProtocol`).

### 3.5 Memento Pattern (`src/state/memento.py`)
- **`AnonymizationMemento` & `Caretaker`:**
  - `Originator` (the outbound/inbound tokenization coordinator) creates an opaque `AnonymizationMemento` capturing request-scoped state: placeholder-to-token-ID bindings, `key_id` version used during encryption, residency jurisdiction tag, and creation timestamp.
  - **Opaque State:** `AnonymizationMemento` exposes no public getters or mutable fields for internal token mappings to external classes; only the authorized `Originator` can unpack its state during response re-identification or rollback.
  - **`Caretaker`:** Manages the lifecycle of mementos per `request_id` with strict TTL eviction and zero persistence of raw plaintext PII.

---

## 4. Week 6 "Hidden Change Request" Readiness

In Week 6 (Milestone 3), the instructors will introduce an unannounced architectural change request (e.g., new regulatory jurisdiction, multi-hop agentic tool-calling sanitization, streaming response detokenization, or a new hybrid cryptographic/synthetic strategy). To guarantee survival without core rewrites:

1. **FORBIDDEN — Hardcoded Providers:** Never hardcode `"openai"`, `"anthropic"`, `"azure"`, or provider URLs inside `src/pipeline/`, `src/vault/`, or `src/state/`. All external LLM interactions go through an abstract `LLMDispatcher` protocol carrying declarative `EndpointMetadata` (provider ID, region, certifications).
2. **FORBIDDEN — Hardcoded Jurisdictions:** Never hardcode `if region == "US":` or `if region != "EU":` inside `ResidencyGate`. Jurisdiction rules must be evaluated via injected `ResidencyPolicy` specifications.
3. **FORBIDDEN — Hardcoded Entity or Strategy Names:** Never write `if entity.type == "PESEL":` inside `AnonymizationFilter`. Use a configurable `StrategySelector` / registry mapping `EntityCategory` or `EntityType` to `AnonymizationStrategy` instances.
4. **Dependency Injection Only:** Every external collaborator (`AuditLogger`, `KeyManager`, `VaultProtocol`, `ResidencyPolicy`, `LLMDispatcher`) must be injected via interfaces (`typing.Protocol` or `abc.ABC`).

---

## 5. Non-Negotiable Security Rules

1. **Zero Hardcoded Secrets:**
   - Cryptographic keys, salts, API tokens, and HMAC secrets must never appear in source code, default arguments, or committed `.env` files. Load keys exclusively via `KeyManager` backed by environment variables or an injected KMS provider. Test fixtures must generate ephemeral random keys at runtime via `AESGCM.generate_key(bit_length=256)`.
2. **Authenticated Encryption & Key Lifecycle (`AES-256-GCM`):**
   - All reversible tokens stored in `TokenVault` must be encrypted with **AES-256-GCM** using a unique 96-bit (12-byte) cryptographic nonce (`os.urandom(12)`) per encryption operation and bound with Associated Authenticated Data (`AAD`) containing `tenant_id`, `request_id`, and `entity_type`.
   - Every encrypted record must store `key_id` (version identifier), `created_at`, and `expires_at`.
   - `KeyManager` must support key rotation (`ACTIVE`, `DECRYPT_ONLY`, `REVOKED`/`EXPIRED`) so existing tokens encrypted under a rotated `DECRYPT_ONLY` key remain detokenizable until their TTL expires, while expired or revoked keys raise `KeyExpiredError`.
3. **Strict EU Data Residency Gate:**
   - Payloads containing `PHI` (Protected Health Information) or EU-restricted PII must be evaluated by `ResidencyGate` against the target `LLMDispatcher`'s declared jurisdiction before leaving the boundary. Non-compliant targets trigger an immediate fail-closed `ResidencyViolationError` and an immutable `AuditEvent`.
4. **NEVER Log Raw PII/PHI or Plaintext Secrets:**
   - Logs, audit trails, exception messages, and FastAPI HTTP error responses **MUST NEVER** contain raw PII/PHI strings, plaintext values, or cryptographic key bytes.
   - Custom exceptions and Pydantic `__repr__` / `__str__` methods on sensitive models must redact raw values (e.g., logging `entity_type="PESEL", token_id="tok_8f3a...", length=11` instead of the raw national ID).

---

## 6. Testing Rules (Positive + Negative/Abuse Coverage)

Every pull request and feature implementation must include:
1. **Positive Unit & Integration Tests:** Verify expected behavior across all 6 core scenarios (happy-path pseudonymization + Memento restoration, k-anonymity generalization, IBAN extension).
2. **Mandatory Negative / Abuse Security Tests:**
   - **Unauthorized Detokenization (Scenario 2):** Caller lacking `DETOKENIZE` permission or belonging to a different tenant receives `UnauthorizedVaultAccessError`, receives zero plaintext data, and triggers a `DENIED` audit log entry.
   - **Data Residency Violation (Scenario 3):** Attempting to dispatch PHI to a non-EU endpoint (`US-EAST`) halts the pipeline before `LLMDispatcher.dispatch()` is invoked and records a residency violation audit event.
   - **Re-Identification Risk (Scenario 4):** Quasi-identifier combinations violating $k$-anonymity ($k < k_{\text{target}}$) are either generalized to meet $k$ or rejected fail-closed.
   - **Key Rotation & Token Expiration (Scenario 5):** Detokenizing with an expired token TTL or a `REVOKED` `key_id` raises `TokenExpiredError` / `KeyExpiredError` and logs the failed attempt.
   - **Ciphertext / AAD Tampering:** Modifying ciphertext, nonce, or AAD (`tenant_id` mismatch) raises an authentication failure (`InvalidTag` wrapped in `VaultIntegrityError`) without leaking oracle details.
   - **Zero PII Leakage Assertion:** Assert that captured logs (`caplog`) and raised exception strings do not contain raw input PII substrings.
