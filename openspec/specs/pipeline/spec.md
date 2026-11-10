# Pipeline & Builder Specification (`openspec/specs/pipeline/spec.md`)

## Requirements

### Requirement: Stateless Pipes & Filters over Immutable Context
Every filter in `src/pipeline/` SHALL implement `process(context: PipelineContext) -> PipelineContext`, hold zero per-request mutable state, and return a new frozen `PipelineContext` instance or fail closed with a typed domain exception.

#### Scenario: Scenario 1 — Inbound Sanitization and Outbound Restoration
- **GIVEN** a built `Pipeline` configured with `DetectionFilter`, `AnonymizationFilter`, `ResidencyGate`, and `RestorationFilter`
- **WHEN** an inbound prompt containing `"Jan Kowalski, PESEL 90010112345"` is processed
- **THEN** the outbound prompt dispatched to `LLMDispatcher` contains only placeholders (`<PERSON_1>`, `***********`) and zero plaintext PII

#### Scenario: Scenario 3 — Fail-Closed EU Data Residency Gate for PHI
- **GIVEN** a `PipelineContext` containing detected `PHI` (medical data class) and a target `LLMDispatcher` endpoint in region `us-east-1`
- **WHEN** `ResidencyGate.process(context)` executes
- **THEN** the filter raises `ResidencyViolationError` before `LLMDispatcher.dispatch()` is invoked and emits an immutable `AuditEvent`

### Requirement: Build-Time Invariant Validation via PipelineBuilder
`PipelineBuilder.build()` SHALL validate pipeline completeness before returning an immutable `Pipeline`.

#### Scenario: Reject Incomplete Pipeline Missing Detectors or Vault Proxy
- **GIVEN** a `PipelineBuilder` configured with `ReversibleTokenizationStrategy` but without a `PIIDetector` or `VaultProtectionProxy`
- **WHEN** `.build()` is called
- **THEN** `PipelineConfigurationError` is raised immediately at build time
