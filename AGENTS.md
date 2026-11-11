# AI Agent Governance & Architecture Instructions (`AGENTS.md`)

> **Project:** LLM Anonymization & Pseudonymization Pipeline  
> **Course:** University Design Patterns & Security Project (4-Person Team)  
> **Python Runtime:** Python 3.12+  
> **Core Stack:** Pydantic v2, FastAPI, `cryptography` (AES-256-GCM), `pytest`, `ruff`, `mypy`, `bandit`, `pip-audit`

This file is the **authoritative specification** for all AI coding agents and human developers working in this repository, fully aligned with [`ARCHITECTURE.md`](ARCHITECTURE.md). Every generated file, refactoring, and test case must strictly comply with the architectural invariants, design patterns, and security boundaries defined below.

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
- **Naming (single source of truth = `ARCHITECTURE.md`):** Every class, interface, filter, enum member, and method must use exactly the name defined in `ARCHITECTURE.md`. **Aliases are forbidden** — no `Foo = Bar` re-exports, no duplicate camelCase/snake_case method pairs, no Pydantic `validation_alias` for alternative field names, and no registering one strategy under several names. Python methods and fields use `snake_case` consistently (`for_data_class`, `with_re_id_risk_threshold`, `can_reverse`, `add_filter`, `de_tokenize`, `session_id`, `key_id`). Exceptions keep the PEP 8 `Error` suffix (`HardStop` → `HardStopError`).

---

## 2. Target Repository Module Structure

```text
src/
├── domain/          # Immutable Pydantic v2 models (DetectedEntity, ToolCall, DocumentAttachment, DataClass, AuditEvent), exceptions (HardStopError, ResidencyViolationError, UnsupportedMediaWithPotentialPIIError), and protocols (AuditWriter, ResidencyPolicyEngine, LocalOCREngine)
├── pipeline/        # Pipes & Filters core + PipelineBuilder + PipelineProxy
│   ├── context.py   # Immutable PipelineContext (Memento Originator) & FilterRecord execution metadata
│   ├── filter.py    # Filter interface, Pipe interface, and its immutable Pipeline implementation (Inbound Pipeline)
│   ├── filters.py   # Stateless filters: DocumentExtractorFilter, LanguageDetectorFilter, PIIDetectorFilter, RiskAssessmentFilter, AnonymizationFilter, ResidencyPolicyFilter, AuditContextFilter
│   ├── builder.py   # Fluent PipelineBuilder with build-time structural invariant validation
│   └── proxy.py     # PipelineProxy entry point normalizing text, PDF attachments, and ToolCall JSON payloads
├── detectors/       # Strategy pattern for PII/PHI detection (PIIDetector interface + RegexPIIDetector, NERPIIDetector, PolishTransformerNERDetector, EnglishTransformerNERDetector, HeuristicPIIDetector, ContextRuleEnhancer)
├── strategies/      # Strategy pattern for anonymization (AnonymizationStrategy interface + StrategySelector, TokenizationStrategy, MaskingStrategy, GeneralizationStrategy, SynthesisStrategy)
├── vault/           # Protection Proxy + AES-256-GCM VaultCore + KMS
│   ├── vault.py     # Internal VaultCore & TokenRecord (package-private; NEVER accessed directly by callers)
│   ├── proxy.py     # VaultProxy enforcing AuthN/AuthZ and writing immutable audit events via AuditWriter
│   └── keys.py      # KMS with key_id versioning, KeyRotation scheduling, and TTL expiration
├── state/           # Memento pattern for safe request-scoped context restoration
│   └── memento.py   # PipelineMemento & ResponseRestorer
└── dispatchers/     # Abstract LLMDispatcher interface and provider adapters
```

---

## 3. Strict Design Pattern Rules (No Leaky Abstractions)

### 3.1 Pipes & Filters (`src/pipeline/`)
- **Stateless Filters:** Every filter must implement the `Filter` interface (`def process(self, context: PipelineContext) -> PipelineContext`). Filters must hold **zero mutable per-request state** so a built `Pipeline` instance is completely thread-safe and reusable across concurrent FastAPI requests.
- **`Pipe` Interface:** `Pipe` declares `add_filter(filter) -> Pipe` and `execute(context) -> PipelineContext`; `Pipeline` is its immutable implementation and plays the role of the `Inbound Pipeline`.
- **Canonical Filter Chain (`ARCHITECTURE.md` §3.1):**
  `DocumentExtractorFilter` → `LanguageDetectorFilter` → `PIIDetectorFilter` → `RiskAssessmentFilter` → `AnonymizationFilter` → `ResidencyPolicyFilter` → `AuditContextFilter`.
  The outbound chain is `OutputPIIDetector` → `ResponseRestorer`. `RiskAssessmentFilter` delegates the k-anonymity computation to `ReIdRiskAnalyzer`; `ResidencyPolicyFilter` delegates jurisdiction decisions to `ResidencyPolicyEngine`.
- **Immutable Context:** `PipelineContext` must be an immutable (`frozen=True`) Pydantic v2 model. Filters return a new evolved context via `.model_copy(update={...})` or raise a typed domain exception (`HardStopError`, `ResidencyViolationError`, `ReIdentificationRiskError`, `UnauthorizedVaultAccessError`, `UnsupportedMediaWithPotentialPIIError`) to trigger a fail-closed hard stop.
- **Zero Concrete Branching:** Filters (`DocumentExtractorFilter`, `LanguageDetectorFilter`, `PIIDetectorFilter`, `RiskAssessmentFilter`, `AnonymizationFilter`, `ResidencyPolicyFilter`, `AuditContextFilter`, `OutputPIIDetector`, `ResponseRestorer`) **MUST NOT** contain `if/elif/else` or `match/case` branches checking concrete detector types, entity names, or strategy class types. All polymorphism is delegated to injected interfaces or `StrategySelector` / `DetectorRegistry`.

### 3.2 Strategy Pattern (`src/strategies/`, `src/detectors/`)
- **`PIIDetector` Interface (`src/detectors/`):**
  - Defines `detect(self, text: str, language: str) -> Sequence[DetectedEntity]`.
  - Concrete implementations include `RegexPIIDetector` (deterministic regex + checksums for PL `PESEL`, `NIP`, `REGON`, `IBAN`, `ID_CARD` and US `SSN`, `ITIN`, `EIN`, `ABA_ROUTING`, `CREDIT_CARD`), `NERPIIDetector` (base of `EnglishTransformerNERDetector` and `PolishTransformerNERDetector`), and `HeuristicPIIDetector` + `ContextRuleEnhancer` (mitigating capitalization bias and Polish inflection).
- **`AnonymizationStrategy` Interface (`src/strategies/`):**
  - Defines `anonymize(self, entity: DetectedEntity, context: AnonymizationRequest) -> AnonymizationResult` and `can_reverse(self) -> bool` (`ARCHITECTURE.md` §3.2).
  - Selected dynamically via `StrategySelector.select(entity, policy)`.
  - Concrete implementations: `TokenizationStrategy` (reversible when backed by `TokenizationVault`), `MaskingStrategy` (irreversible), `GeneralizationStrategy` (quasi-identifier hierarchy generalization for k-anonymity), and optional `SynthesisStrategy`.
- **Strict Open-Closed Principle (OCP):**
  - Adding a new detector (e.g., Scenario 6: Polish IBAN detector with Modulo-97 checksum validation) or a new anonymization strategy **MUST require zero line modifications** to `src/pipeline/` core classes. New implementations are registered via `DetectorRegistry`, `StrategySelector`, or `PipelineBuilder`.

### 3.3 Builder Pattern (`src/pipeline/builder.py`)
- **`PipelineBuilder` Fluent Interface (`ARCHITECTURE.md` §3.3):**
  - Provides fluent configuration methods (snake_case forms of `ARCHITECTURE.md` names, no aliases):
    - `.for_data_class(...)` (`DataClass.MEDICAL`, `DataClass.FINANCIAL`, `DataClass.LEGAL`, `DataClass.GENERAL`, `DataClass.ANONYMOUS`)
    - `.with_residency_policy(...)` (takes a `ResidencyPolicyEngine`)
    - `.with_anonymization_strategy(...)` (default strategy, or `EntityType` + strategy binding)
    - `.with_re_id_risk_threshold(...)` and `.with_k_anonymity_threshold(...)` (`k_min`)
    - `.with_audit_level(...)` (`AuditLevel.FULL`, `AuditLevel.MINIMAL`, `AuditLevel.NONE`)
    - `.with_audit_writer(...)`
    - `.with_detector(...)` / `.with_detectors(...)` / `.with_context_enhancer(...)`
    - `.with_risk_assessment_filter(...)` / `.with_custom_filter(...)`
    - `.with_vault_proxy(...)` / `.with_response_restorer(...)`
    - `.with_pdf_extraction_policy(...)` (`PDFExtractionPolicy.STRICT_NO_OCR`, `PDFExtractionPolicy.LOCAL_OCR_ENABLED`)
    - `.build()`
- **Build-Time Invariant Validation:**
  - `.build()` must validate pipeline completeness before returning an immutable `Pipeline`:
    1. At least one `PIIDetector` is configured before `AnonymizationFilter`.
    2. If a reversible `TokenizationStrategy` is registered, a valid `VaultProxy` and `ResponseRestorer` must be bound.
    3. If the pipeline handles `DataClass.MEDICAL`, `AuditLevel.NONE` is forbidden and a `ResidencyPolicyFilter` (configured with a `ResidencyPolicyEngine`) is mandatory.
    4. Conflicting or incomplete configurations fail fast at build time with `PipelineConfigurationError`.

### 3.4 Protection Proxy (`src/vault/proxy.py`, `src/pipeline/proxy.py`)
- **`PipelineProxy` (`src/pipeline/proxy.py`):**
  - Single entry point normalizing raw text prompts, `DocumentAttachment` (PDFs), and structured `ToolCall` JSON payloads before invoking the `Pipeline`.
- **`VaultProxy` Wrapping `VaultCore`:**
  - Both `VaultProxy` and `VaultCore` implement the `TokenizationVault` interface.
  - **Mandatory Access Control:** Before executing `de_tokenize(...)` or `rotate_keys(...)`, `VaultProxy` verifies the caller's `SecurityPrincipal` (AuthN, RBAC/ABAC roles, tenant/session match, and token expiration).
  - **Mandatory Audit Logging:** Every call to `tokenize`, `de_tokenize`, and `rotate_keys` writes a tamper-evident `AuditEvent` through the `AuditWriter` to the immutable `AuditLog` **regardless of whether access was GRANTED or DENIED**.
  - **Encapsulation Boundary:** Direct instantiation or invocation of `VaultCore` outside `src/vault/proxy.py` and dedicated unit tests is **strictly forbidden**. Pipeline filters and restoration services may only hold a reference to `VaultProxy` (typed as `TokenizationVault`).

### 3.5 Memento Pattern (`src/state/memento.py`)
- **`PipelineMemento` & `ResponseRestorer`:**
  - The Originator (`PipelineContext`) creates an opaque `PipelineMemento` capturing request-scoped state: `session_id`, `token_map` (token-to-`EntityMetadata` bindings without raw PII), `version` (incremented on Dynamic Memento Expansion during agentic `ToolCall` execution by `ToolExecutionMiddleware`), `applied_filters` (`FilterRecord` list), `timestamp`, `key_id` version, and integrity `checksum`.
  - **Opaque State:** `PipelineMemento` exposes no public getters or mutable fields for raw PII values; original values exist exclusively encrypted inside `VaultCore`.
  - **`ResponseRestorer`:** Manages the lifecycle of mementos per `request_id` / `session_id` with strict TTL eviction (`RetentionPolicyEngine` sets `expires_at`, `RetentionWorker` purges) and zero persistence of raw plaintext PII.

---

## 4. Extensibility & Change Request Readiness

To guarantee that new architectural requirements (e.g., new regulatory jurisdictions, multi-hop agentic `ToolCall` sanitization, PDF `Extract-Then-Anonymize` processing, streaming response de-tokenization, or new hybrid cryptographic/synthetic strategies) can be introduced without core rewrites:

1. **FORBIDDEN — Hardcoded Providers:** Never hardcode `"openai"`, `"anthropic"`, `"azure"`, or provider URLs inside `src/pipeline/`, `src/vault/`, or `src/state/`. All external LLM interactions go through an abstract `LLMDispatcher` protocol carrying declarative `EndpointMetadata` (provider ID, region, certifications).
2. **FORBIDDEN — Hardcoded Jurisdictions:** Never hardcode `if region == "US":` or `if region != "EU":` inside `ResidencyPolicyFilter`. Jurisdiction rules must be evaluated via an injected `ResidencyPolicyEngine`.
3. **FORBIDDEN — Hardcoded Entity or Strategy Names:** Never write `if entity.type == "PESEL":` inside `AnonymizationFilter`. Use a configurable `StrategySelector` mapping `EntityType` to `AnonymizationStrategy` instances.
4. **Dependency Injection Only:** Every external collaborator (`AuditWriter`, `KMS`, `TokenizationVault`, `ResidencyPolicyEngine`, `LocalOCREngine`, `LLMDispatcher`) must be injected via interfaces (`typing.Protocol` or `abc.ABC`).

---

## 5. Non-Negotiable Security Rules

1. **Zero Hardcoded Secrets:**
   - Cryptographic keys, salts, API tokens, and HMAC secrets must never appear in source code, default arguments, or committed `.env` files. Load keys exclusively via `KMS` backed by environment variables or an injected KMS provider. Test fixtures must generate ephemeral random keys at runtime via `AESGCM.generate_key(bit_length=256)`.
2. **Authenticated Encryption & Key Lifecycle (`AES-256-GCM`):**
   - All reversible `TokenRecord` entries stored in `VaultCore` must be encrypted with **AES-256-GCM** using a unique 96-bit (12-byte) cryptographic nonce (`os.urandom(12)`) per encryption operation and bound with Associated Authenticated Data (`AAD`) containing `tenant_id`, `request_id`, and `entity_type`.
   - Every encrypted `TokenRecord` must store `key_id` (version identifier), `created_at`, and `expires_at`.
   - `KMS` must support key rotation (`ARCHITECTURE.md` §5.5): rotation strategies `RE_ENCRYPT`, `RETAIN_OLD_KEY`, `EXPIRE` and key statuses `ACTIVE`, `DEPRECATED`, `EXPIRED`, `REVOKED`, so existing tokens encrypted under a rotated key remain de-tokenizable until their TTL expires, while expired or revoked keys raise `KeyExpiredError`.
3. **Strict EU Data Residency Gate & Extract-Then-Anonymize PDF Gate:**
   - Payloads containing `DataClass.MEDICAL` or EU-restricted PII must be evaluated by `ResidencyPolicyFilter` against the target `LLMDispatcher`'s declared jurisdiction before leaving the boundary. Non-compliant targets trigger an immediate fail-closed `ResidencyViolationError` and an immutable `AuditEvent`.
   - Raw PDF binaries must never leave `PipelineProxy`; `DocumentExtractorFilter` strips XMP/Info metadata and fails closed with `UnsupportedMediaWithPotentialPIIError` (`HardStopError`) on scanned/image PDFs when `PDFExtractionPolicy.STRICT_NO_OCR` is active.
4. **NEVER Log Raw PII/PHI or Plaintext Secrets:**
   - Logs, audit trails, exception messages, and FastAPI HTTP error responses **MUST NEVER** contain raw PII/PHI strings, plaintext values, or cryptographic key bytes.
   - Custom exceptions and Pydantic `__repr__` / `__str__` methods on sensitive models (`DetectedEntity`, `DocumentAttachment`) must redact raw values (e.g., logging `entity_type="PESEL", token_id="tok_8f3a...", length=11` instead of the raw national ID).

---

## 6. Testing Rules (Positive + Negative/Abuse Coverage)

Every pull request and feature implementation must include:
1. **Positive Unit & Integration Tests:** Verify expected behavior across all core scenarios (happy-path pseudonymization + Memento restoration, k-anonymity generalization, IBAN/checksum extension, agentic `ToolCall` sanitization, and PDF extraction).
2. **Mandatory Negative / Abuse Security Tests:**
   - **Unauthorized De-tokenization (Scenario 2):** Caller lacking `DETOKENIZE` permission or belonging to a different tenant/session receives `UnauthorizedVaultAccessError`, receives zero plaintext data, and triggers a `DENIED` audit log entry.
   - **Data Residency Violation (Scenario 3):** Attempting to dispatch `MEDICAL` data to a non-EU endpoint (`us-east-1`) halts the pipeline via `ResidencyPolicyFilter` before `LLMDispatcher.dispatch()` is invoked and records a residency violation `AuditEvent`.
   - **Re-Identification Risk (Scenario 4):** Quasi-identifier combinations violating $k$-anonymity ($k < k_{\text{min}}$) detected by `ReIdRiskAnalyzer` are generalized via `GeneralizationStrategy` or rejected fail-closed with `ReIdentificationRiskError`.
   - **Key Rotation & Token Expiration (Scenario 5):** De-tokenizing with an expired token TTL or a `REVOKED` / `EXPIRED` `key_id` raises `TokenExpiredError` / `KeyExpiredError` and logs the failed attempt.
   - **Ciphertext / AAD Tampering:** Modifying ciphertext, nonce, or AAD (`tenant_id` mismatch) raises an authentication failure (`InvalidTag` wrapped in `VaultIntegrityError`) without leaking oracle details.
   - **Raw Binary / Scanned PDF Blocking (ADR-009):** Passing a scanned/image-only PDF under `STRICT_NO_OCR` raises `UnsupportedMediaWithPotentialPIIError` (`HardStopError`) and records a `BLOCKED` `AuditEvent`.
   - **Zero PII Leakage Assertion:** Assert that captured logs (`caplog`) and raised exception strings do not contain raw input PII substrings.
