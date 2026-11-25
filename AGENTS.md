# AI Agent Governance & Architecture Instructions (`AGENTS.md`)

> **Project:** Privacy-Preserving Context Pipeline for LLMs (EU / EEA Compliance)  
> **Course:** University Design Patterns & Security Project (4-Person Team)  
> **Python Runtime:** Python 3.12+  
> **Core Stack:** Pydantic v2, FastAPI, `cryptography` (AES-256-GCM), `pytest`, `ruff`, `mypy`, `bandit`, `pip-audit`

This file is the **authoritative engineering governance specification** for all AI coding agents and human developers working in this repository. **[`ARCHITECTURE.md`](ARCHITECTURE.md) (v2.4) is the single source of truth** for architectural decisions, patterns, component names, and compliance boundaries. Every generated file, refactoring, and test case must strictly comply with [`ARCHITECTURE.md`](ARCHITECTURE.md) and the rules below.

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
- **Pydantic v2:** Use `BaseModel` with `ConfigDict(frozen=True, extra="forbid")` for immutable value objects, contexts, configurations, and audit payloads. Never use deprecated Pydantic v1 methods (`.dict()`, `.parse_obj()`, `class Config:`).
- **Cryptography:** Use `cryptography.hazmat.primitives.ciphers.aead.AESGCM` exclusively for authenticated encryption. Never use unauthenticated modes (ECB, CBC without MAC) or custom cryptographic primitives.
- **Naming (single source of truth = `ARCHITECTURE.md`):** Every class, interface, handler, enum member, audit event type, and method must use the exact name defined in `ARCHITECTURE.md`. **Aliases are forbidden** — no `Foo = Bar` re-exports, no duplicate camelCase/snake_case method pairs, no Pydantic `validation_alias` for alternative field names, and no registering one strategy under several names. Python methods and fields use `snake_case` consistently (`for_data_class`, `add_handler`, `set_next`, `handle`, `is_enabled`, `can_reverse`, `de_tokenize`, `session_id`, `key_id`). Exceptions keep the PEP 8 `Error` suffix (`HardStopError`, `ResidencyViolationError`, `ReIdentificationRiskError`, `UnauthorizedVaultAccessError`, `UnsupportedMediaWithPotentialPIIError`, `TokenExpiredError`, `KeyExpiredError`, `VaultIntegrityError`, `PipelineConfigurationError`).

---

## 2. Target Repository Module Structure

```text
src/
├── domain/          # Immutable Pydantic v2 models (DetectedEntity, ToolCall, DocumentAttachment, ExtractedDocument, DataClass, AuditEvent, TokenRecord, KeyStatus, RotationStrategy, UserPipelineConfig, EntityCluster, EntityOccurrence, EndpointMetadata, SecurityPrincipal), exceptions, and protocols (AuditWriter, ResidencyPolicyEngine, LocalOCREngine, TokenizationVault, KMS, PublicDataDemographicsProvider, DocumentExtractorStrategy, LLMProviderAdapter)
├── gateway/         # Single Edge Entry Point (ZERO edge proxy)
│   └── api.py       # APIGateway: TLS/mTLS termination, AuthN/AuthZ, rate limiting, protocol adapters (/v1/process, /v1/chat/completions, /v1/messages)
├── pipeline/        # Pure Chain of Responsibility core + PipelineBuilder + DynamicCoRFactory
│   ├── context.py   # Immutable PipelineContext (Memento Originator) & FilterRecord execution metadata
│   ├── handler.py   # FilterHandler protocol & BaseFilterHandler ABC (is_enabled, set_next, handle, _process)
│   ├── handlers.py  # Inbound CoR handlers (DocumentExtractorHandler, LanguageDetectorHandler, PIIDetectorHandler, RiskAssessmentHandler, AnonymizationHandler, ResidencyPolicyHandler, AuditContextHandler) & Outbound CoR handlers (OutputPIIDetectorHandler, WindowBufferingHandler, ResponseRestorer)
│   └── builder.py   # Fluent PipelineBuilder + DynamicCoRFactory with build-time Fail-Closed invariant validation
├── detectors/       # Strategy pattern for EU/PL PII/PHI detection (PIIDetector interface + RegexPIIDetector, TransformerNERDetector, ContextRuleEnhancer)
├── extractors/      # Strategy pattern for sandboxed Extract-Then-Anonymize document parsing (DocumentExtractorStrategy for PDF, DOCX, XLSX/ODS, CSV/TSV, TXT/MD, OCR images, Archives)
├── strategies/      # Strategy pattern for anonymization (AnonymizationStrategy interface + StrategySelector, TokenizationStrategy, MaskingStrategy, GeneralizationStrategy, SynthesisStrategy)
├── vault/           # Protection Proxy (ONLY Proxy in the system) + AES-256-GCM VaultCore + KMS + WORM Audit
│   ├── vault.py     # Internal VaultCore storing encrypted TokenRecords in TokenDB (package-private; NEVER accessed directly by callers)
│   ├── proxy.py     # VaultProxy enforcing AuthN/AuthZ (RBAC/ABAC, rate limiting) and writing immutable AuditEvents via AuditWriter
│   ├── keys.py      # InMemoryKMS / CloudKMS implementing KMS (MK → KEK → DEK hierarchy) with key_id versioning, KeyStatus, and RotationStrategy
│   └── audit.py     # AuditLog (SHA-256 RFC 8785 hash-chained, append-only WORM AuditWriter) & SIEM alerting protocol
├── state/           # Memento pattern & retention lifecycle
│   └── memento.py   # PipelineMemento (EntityCluster, EntityOccurrence, Dynamic Memento Expansion), RetentionPolicyEngine & RetentionWorker
└── dispatchers/     # Multi-Provider LLM Dispatcher, EEA provider adapters & Residency policy
    ├── dispatcher.py # MultiProviderLLMDispatcher, LLMProviderAdapter implementations & EgressGateway integration
    └── residency.py  # ResidencyPolicyEngine evaluating EEA Data Residency rules
```

---

## 3. Strict Design Pattern Rules (No Leaky Abstractions)

### 3.1 Chain of Responsibility (`src/pipeline/`) — ADR-001
- **Pure Chain of Responsibility (NO Pipes & Filters):** Request processing uses synchronous in-memory **Chain of Responsibility** (`FilterHandler` protocol and `BaseFilterHandler` ABC) passing an immutable `PipelineContext`. Do not introduce `Pipe` or intermediate queue abstractions.
- **Stateless, Configurable Handlers:** Every handler implements `BaseFilterHandler` (`is_enabled`, `set_next`, `handle`, `_process`). Disabled handlers (`is_enabled == False`) delegate immediately to `_next_handler`. Handlers must hold **zero mutable per-request state** so built chains are thread-safe and reusable across concurrent FastAPI requests.
- **Canonical Inbound Chain (`ARCHITECTURE.md` §2, §3.1):**
  `DocumentExtractorHandler` → `LanguageDetectorHandler` → `PIIDetectorHandler` → `RiskAssessmentHandler` → `AnonymizationHandler` → `ResidencyPolicyHandler` → `AuditContextHandler`.
- **Canonical Outbound Chain (`ARCHITECTURE.md` §2, §3.5, ADR-006):**
  `OutputPIIDetectorHandler` → `WindowBufferingHandler` (SSE `<...>` token window buffering) → `ResponseRestorer`.
- **Fail-Closed Short-Circuit:** Any handler detecting a privacy, compliance, extraction, or integrity violation immediately raises a typed domain exception (`HardStopError`, `ResidencyViolationError`, `ReIdentificationRiskError`, `UnauthorizedVaultAccessError`, `UnsupportedMediaWithPotentialPIIError`, `VaultIntegrityError`) to abort the chain and return the corresponding HTTP error code (`ARCHITECTURE.md` §6.3).
- **Immutable Context & Zero Concrete Branching:** `PipelineContext` must be an immutable (`frozen=True`) Pydantic v2 model evolved via `.model_copy(update={...})`. Handlers **MUST NOT** contain `if/elif/else` or `match/case` branches checking concrete detector types, entity names, or strategy class types — all polymorphism is delegated to injected interfaces (`StrategySelector`, `PIIDetector`, `DocumentExtractorStrategy`, `ResidencyPolicyEngine`, `PublicDataDemographicsProvider`).

### 3.2 Strategy Pattern (`src/detectors/`, `src/strategies/`, `src/extractors/`, `src/dispatchers/`) — ADR-002
- **`PIIDetector` (`src/detectors/`):**
  - Defines `detect(self, text: str, language: str) -> Sequence[DetectedEntity]`.
  - **100% Poland & EU / EEA Scope (`ARCHITECTURE.md` §6.2):** Concrete implementations target exclusively Polish and EU identifiers:
    - `RegexPIIDetector`: PL `PESEL` (date, gender, $d_{11}$ checksum), `NIP` (mod 11), `REGON` (9/14-digit checksum), `ID_CARD` (Dowód Osobisty RP checksum), `PASSPORT` (RP); EU `IBAN` (ISO 13616 Modulo-97 for all EU member states), `VAT_EU`/`TIN` (VIES), `EKUZ`/`EHIC`, `eIDAS` (ICAO 9303), payment cards (Luhn). **Do NOT implement non-EU/US identifiers (`SSN`, `ITIN`, `EIN`, `ABA_ROUTING`).**
    - `TransformerNERDetector` (HerBERT for PL, multilingual GLiNER/RoBERTa for EU languages, mitigating capitalization bias) and `ContextRuleEnhancer` (PL name dictionaries, TERYT localities, contextual keywords).
- **`AnonymizationStrategy` (`src/strategies/`):**
  - Defines `anonymize(self, entity: DetectedEntity, request: AnonymizationRequest) -> AnonymizationResult` and `can_reverse(self) -> bool`.
  - Selected dynamically via `StrategySelector`.
  - Concrete implementations: `TokenizationStrategy` (reversible polymorphic tokenization backed by `VaultProxy`), `MaskingStrategy` (irreversible), `GeneralizationStrategy` (TERYT / NUTS / KZiS / ISCO-08 hierarchy generalization via `PublicDataDemographicsProvider`), and `SynthesisStrategy` (consistent synthetic data fallback).
- **`DocumentExtractorStrategy` (`src/extractors/`):**
  - Defines `supports(self, mime_type: str) -> bool` and `extract(self, attachment: DocumentAttachment) -> ExtractedDocument`.
  - Covers PDF (`PyMuPDF`/`pdfplumber`), DOCX (`python-docx`, reject VBA macros), XLSX/ODS (`openpyxl` with `data_only=True`), CSV/TSV (formula-injection sanitization), TXT/MD, Images (local OCR only under `LOCAL_OCR_ENABLED`), and Archives (Zip-Bomb protection).
- **`LLMProviderAdapter` (`src/dispatchers/`):**
  - Defines `endpoint_metadata` and `invoke(self, sanitized_prompt: str, params: dict[str, Any]) -> LLMResponse` for EEA providers (Mistral AI, Azure OpenAI EU, Anthropic Claude EOG, local vLLM/Ollama).
- **Strict Open-Closed Principle (OCP):** Adding a new EU detector, anonymization strategy, document extractor, or LLM provider adapter **MUST require zero line modifications** to `src/pipeline/` core handlers.

### 3.3 Builder & Dynamic CoR Factory (`src/pipeline/builder.py`) — ADR-003, ADR-011
- **`PipelineBuilder` & `DynamicCoRFactory` (`ARCHITECTURE.md` §3.3):**
  - `DynamicCoRFactory` translates declarative `UserPipelineConfig` profiles into fluent `PipelineBuilder` calls (`.for_data_class(...)`, `.add_handler(...)`, `.build()`).
  - **Build-Time Fail-Closed Invariant Validation (`.build()`):**
    1. Chain must contain at least one handler.
    2. An **active** (`is_enabled == True`) `PIIDetectorHandler` must precede an active `AnonymizationHandler`.
    3. An **active** `ResidencyPolicyHandler` must follow `AnonymizationHandler` (before egress).
    4. If a reversible `TokenizationStrategy` is registered, a valid `VaultProxy` and `ResponseRestorer` must be bound.
    5. For `DataClass.MEDICAL` (PHI), **active** `AnonymizationHandler`, `ResidencyPolicyHandler`, and `AuditContextHandler` (`AuditLevel.NONE` forbidden) are strictly mandatory.
    6. Any violation fails fast at build time with `PipelineConfigurationError`.

### 3.4 Edge API Gateway & Vault Protection Proxy (`src/gateway/`, `src/vault/proxy.py`) — ADR-004, ADR-010
- **`APIGateway` at the Edge (ZERO Edge Proxy):**
  - `APIGateway` is the sole edge entry point handling TLS/mTLS termination, AuthN (JWT / API Key), AuthZ (RBAC/ABAC), rate limiting, and universal protocol endpoints (`/v1/process`, `/v1/chat/completions`, `/v1/messages`).
  - **Do NOT introduce a `PipelineProxy`** or any secondary proxy at the ingress layer.
- **`VaultProxy` Wrapping `VaultCore` (THE ONLY Protection Proxy in the System):**
  - Both `VaultProxy` and `VaultCore` implement the `TokenizationVault` protocol.
  - **Mandatory Access Control:** Before `de_tokenize(...)` or `rotate_keys(...)`, `VaultProxy` verifies `SecurityPrincipal` (AuthN, RBAC/ABAC roles, `tenant_id` and `session_id` match, token TTL).
  - **Mandatory Audit Logging:** Every `tokenize`, `de_tokenize`, and `rotate_keys` call writes an immutable `AuditEvent` through `AuditWriter` to `AuditLog` **regardless of whether access was GRANTED (`DETOKENIZE_SUCCESS`) or DENIED (`DETOKENIZE_DENIED`)**.
  - **Encapsulation Boundary:** Direct instantiation or invocation of `VaultCore` or `TokenDB` outside `src/vault/proxy.py` and dedicated unit tests is **strictly forbidden**. Handlers and `ResponseRestorer` may only depend on `VaultProxy` (typed as `TokenizationVault`).

### 3.5 Memento Pattern & Outbound Chain (`src/state/memento.py`, `src/pipeline/handlers.py`) — ADR-005, ADR-006, ADR-007, ADR-013
- **Polymorphic Coreference Clustering (`PipelineMemento`):**
  - Repeated occurrences of the same PII receive unique instance tokens (e.g., `<PERSON_ALPHA_INST_1>`, `<PERSON_ALPHA_INST_2>`) with an injected coreference rule (`[COREFERENCE: <PERSON_ALPHA_INST_1> == <PERSON_ALPHA_INST_2>]`).
  - `PipelineMemento` stores immutable `EntityCluster` objects (`cluster_id`, `entity_type`, `vault_record_id`, `occurrences: tuple[EntityOccurrence, ...]`) with **zero raw PII** and increments `version` on **Dynamic Memento Expansion** during agentic `ToolCall` execution.
- **Outbound Chain & Retention:**
  - `OutputPIIDetectorHandler` scans LLM outputs for unexpected/hallucinated PII before restoration.
  - `WindowBufferingHandler` buffers only `<...>` token spans in SSE streams so split placeholders are de-tokenized atomically.
  - `ResponseRestorer` resolves tokens via `PipelineMemento` and `VaultProxy`.
  - `RetentionPolicyEngine` sets session/record `expires_at` (GDPR Art. 17) and `RetentionWorker` purges expired mementos and `TokenDB` records.

---

## 4. Extensibility & Change Request Readiness

1. **FORBIDDEN — Hardcoded Providers:** Never hardcode `"openai"`, `"anthropic"`, `"mistral"`, `"azure"`, or provider URLs inside `src/pipeline/`, `src/vault/`, or `src/state/`. All external LLM interactions go through `MultiProviderLLMDispatcher` and injected `LLMProviderAdapter` instances carrying `EndpointMetadata`.
2. **FORBIDDEN — Hardcoded Jurisdictions:** Never hardcode `if region == "US":` or `if region != "EU":` inside `ResidencyPolicyHandler`. Jurisdiction decisions must be delegated to an injected `ResidencyPolicyEngine`.
3. **FORBIDDEN — Hardcoded Entity or Strategy Names:** Never write `if entity.type == "PESEL":` inside `AnonymizationHandler`. Use a configurable `StrategySelector`.
4. **Zero-Network-Call Runtime for k-Anonymity (ADR-012):** `RiskAssessmentHandler` must query the local offline `PublicDataDemographicsProvider` (GUS BDL / TERYT / Eurostat NUTS) and must never make live external HTTP calls during request processing.
5. **Dependency Injection Only:** Every external collaborator (`AuditWriter`, `KMS`, `TokenizationVault`, `ResidencyPolicyEngine`, `PublicDataDemographicsProvider`, `LocalOCREngine`, `LLMProviderAdapter`) must be injected via interfaces (`typing.Protocol` or `abc.ABC`).

---

## 5. Non-Negotiable Security Rules

1. **Zero Hardcoded Secrets:**
   - Cryptographic keys, salts, API tokens, and HMAC secrets must never appear in source code, default arguments, or committed `.env` files. Load keys exclusively via `KMS`. Test fixtures must generate ephemeral random keys at runtime via `AESGCM.generate_key(bit_length=256)`.
2. **Authenticated Encryption & Key Lifecycle (`AES-256-GCM`, `ARCHITECTURE.md` §5.5, §6.5):**
   - All `TokenRecord` entries in `VaultCore` must be encrypted with **AES-256-GCM** using a unique 96-bit nonce (`os.urandom(12)`) per operation and bound with AAD `tenant_id || session_id || entity_type`.
   - Every `TokenRecord` stores `record_id`, `tenant_id`, `session_id`, `entity_type`, `key_id`, `nonce`, `ciphertext`, `created_at`, and `expires_at`.
   - `KMS` (MK → KEK → DEK) must support `KeyStatus` (`ACTIVE`, `DEPRECATED`, `EXPIRED`, `REVOKED`) and `RotationStrategy` (`RE_ENCRYPT`, `RETAIN_OLD_KEY`, `EXPIRE`). Expired/revoked keys raise `KeyExpiredError` (HTTP 410, `TOKEN_OR_KEY_EXPIRED`).
3. **Strict EEA Data Residency Gate & Multi-Format Extract-Then-Anonymize Gate (`ARCHITECTURE.md` §6.1, §6.3, §6.7):**
   - Non-EEA endpoints trigger an immediate Fail-Closed `ResidencyViolationError` (HTTP **451 Unavailable For Legal Reasons**, audit `RESIDENCY_VIOLATION_BLOCKED`) before `MultiProviderLLMDispatcher` sends any payload.
   - Raw binaries must never reach an LLM. `DocumentExtractorHandler` strips metadata, rejects VBA macros and Zip-Bombs, sanitizes CSV/XLSX formulas, and fails closed with `UnsupportedMediaWithPotentialPIIError` (HTTP **415 Unsupported Media Type**, audit `RAW_BINARY_EXTRACTION_BLOCKED`) on scanned PDFs/images when `PDFExtractionPolicy.STRICT_NO_OCR` is active.
4. **Tamper-Evident WORM Audit & Zero PII Leakage (`ARCHITECTURE.md` §6.8):**
   - `AuditLog` computes `event_hash = SHA-256(previous_hash || canonical_json(payload))` (RFC 8785 canonical JSON).
   - Logs, audit trails, exception messages, and FastAPI HTTP error responses **MUST NEVER** contain raw PII/PHI strings, plaintext values, or cryptographic key bytes. Sensitive models (`DetectedEntity`, `DocumentAttachment`) must redact raw values in `__repr__` / `__str__`.

---

## 6. Testing Rules (Positive + Negative/Abuse Coverage)

Every pull request and feature implementation must include:
1. **Positive Unit & Integration Tests:**
   - Polymorphic pseudonymization + coreference metadata + `PipelineMemento` / `ResponseRestorer` round-trip (Scenario 5.1).
   - GUS/Eurostat offline k-anonymity generalization via `PublicDataDemographicsProvider` (Scenario 5.4).
   - EU/PL identifier checksums (`PESEL`, `NIP`, `REGON`, `ID_CARD`, EU `IBAN` Modulo-97) and OCP extension test without modifying `src/pipeline/`.
   - Agentic `ToolCall` sanitization + Dynamic Memento Expansion (`version` increment, Scenario 5.6).
   - Multi-provider selection (`X-Target-Provider` / OpenAI & Anthropic adapters) + SSE `WindowBufferingHandler` with tokens split across chunks (Scenario 5.7, ADR-006).
   - Multi-format document extraction (PDF, DOCX, XLSX, CSV, TXT).
2. **Mandatory Negative / Abuse Security Tests (Fail-Closed):**
   - **Unauthorized De-tokenization (Scenario 5.2):** Missing role or mismatched `tenant_id`/`session_id` raises `UnauthorizedVaultAccessError` (HTTP 403), returns zero plaintext, and logs `DETOKENIZE_DENIED`.
   - **EEA Data Residency Violation (Scenario 5.3):** Dispatching `DataClass.MEDICAL` or EU-restricted data to a non-EEA region halts at `ResidencyPolicyHandler` with `ResidencyViolationError` (HTTP 451) before `MultiProviderLLMDispatcher` is invoked, logging `RESIDENCY_VIOLATION_BLOCKED`.
   - **Re-Identification Risk (Scenario 5.4):** Quasi-identifiers remaining at $k < k_{min}$ after generalization fail closed with `ReIdentificationRiskError` (HTTP 422), logging `RE_IDENTIFICATION_RISK_REJECT`.
   - **Key Rotation & Expiration (Scenario 5.5):** Expired token TTL or `EXPIRED`/`REVOKED` `key_id` raises `TokenExpiredError` / `KeyExpiredError` (HTTP 410), logging `TOKEN_OR_KEY_EXPIRED`.
   - **Ciphertext / Nonce / AAD Tampering:** Modifying ciphertext, nonce, or AAD raises `VaultIntegrityError` (HTTP 500) and logs `VAULT_INTEGRITY_TAMPERING` without leaking oracle details.
   - **Raw Binary / Scanned PDF / Macro / Zip-Bomb Blocking (ADR-009, ADR-014):** Scanned PDF or image under `STRICT_NO_OCR` raises `UnsupportedMediaWithPotentialPIIError` (HTTP 415) and logs `RAW_BINARY_EXTRACTION_BLOCKED`.
   - **Builder Invariant Enforcement (ADR-003):** Attempting to build a `DataClass.MEDICAL` chain with disabled `AnonymizationHandler`, `ResidencyPolicyHandler`, or `AuditContextHandler` raises `PipelineConfigurationError`.
   - **Zero PII Leakage Assertion:** Assert that captured logs (`caplog`), `AuditLog` entries, and raised exception strings contain zero raw input PII substrings.
