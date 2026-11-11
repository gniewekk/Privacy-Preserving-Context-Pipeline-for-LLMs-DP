# ADR-003: Composing Multi-Stage Compliance Pipelines via Fluent Builder

- **Status:** Accepted
- **Date:** 2026-11-10
- **Component:** `src/pipeline/builder.py` (`PipelineBuilder`)

---

## 1. Context & Problem

A valid privacy pipeline requires assembling multiple interdependent components: one or more `PIIDetector` strategies, a `StrategySelector` mapping entity types to `AnonymizationStrategy` implementations, an optional `GeneralizationStrategy` with a target $k$ threshold, a `ResidencyPolicyEngine` gate, a `VaultProxy` with an `AuditWriter`, and a `ResponseRestorer` for `PipelineMemento` state.

Constructing a `Pipeline` directly via a monolithic `__init__` constructor or ad-hoc list of filters creates severe security hazards:
1. **Misordered Filters:** Placing `ResidencyPolicyFilter` or `AnonymizationFilter` *after* `LLMDispatcher` or *before* `PIIDetectorFilter` silently bypasses PII protection.
2. **Broken Dependencies:** Registering `TokenizationStrategy` without configuring a `VaultProxy` or `ResponseRestorer` causes runtime failures mid-request.
3. **Missing Compliance Gates:** Configuring a medical (`PHI`) pipeline without an active `ResidencyPolicyFilter` violates GDPR / EU AI Act residency rules.

---

## 2. Decision

We implement the **Builder Pattern** via `PipelineBuilder` (`src/pipeline/builder.py`) with a fluent interface and strict build-time invariant validation in `.build()`.

```python
pipeline = (
    PipelineBuilder()
    .with_detector(RegexPIIDetector())
    .with_detector(NERPIIDetector())
    .with_anonymization_strategy(EntityType.PERSON, TokenizationStrategy(reversible=True))
    .with_anonymization_strategy(EntityType.PESEL, MaskingStrategy())
    .with_k_anonymity_threshold(5)
    .with_residency_policy(EUResidencyPolicy(allowed_regions=frozenset({"eu-central-1", "eu-west-1"})))
    .with_vault_proxy(vault_proxy)
    .with_response_restorer(response_restorer)
    .build()
)
```

### Build-Time Invariants Enforced by `.build()`
1. **Mandatory Detection Stage:** At least one `PIIDetector` must be registered; otherwise `.build()` raises `PipelineConfigurationError`.
2. **Canonical Stage Ordering:** Regardless of the order in which fluent `.with_*()` methods are called by the developer, `.build()` assembles the internal filter chain in the canonical security order:
   `DocumentExtractorFilter` -> `LanguageDetectorFilter` -> `PIIDetectorFilter` -> `RiskAssessmentFilter` -> `AnonymizationFilter` -> `ResidencyPolicyFilter` -> `AuditContextFilter`.
3. **Reversible Strategy Coupling:** If any registered `AnonymizationStrategy.can_reverse()` is `True`, both `vault_proxy` and `response_restorer` must be present.
4. **Immutability After Build:** `.build()` returns an immutable `Pipeline` containing a `tuple[Filter, ...]` that cannot be mutated at runtime.

---

## 3. Rejected Alternatives

### Alternative A: Telescoping Constructor (`Pipeline(detectors=..., strategies=..., residency=..., vault=...)`)
Passing all collaborators directly to `Pipeline.__init__`.
- **Why Rejected:** Poor readability, error-prone boolean/optional parameter combinations, and pushes filter ordering responsibility onto the caller, making it trivial to accidentally omit `ResidencyPolicyFilter` or misorder filters.

### Alternative B: Static Factory Methods Only (`PipelineFactory.create_eu_medical_pipeline()`)
Providing fixed factory methods for predefined pipeline profiles.
- **Why Rejected:** While preset directors/factories are convenient, relying *only* on fixed factory methods prevents custom composition when new detectors (Scenario 6 IBAN) or new requirements arrive, forcing edits to the factory class for every permutation. (Note: Preset helper methods may still delegate to `PipelineBuilder` internally).

---

## 4. Trade-offs & Consequences

### Positive
- **Fail-Fast Security Guarantees:** Invalid or insecure pipeline topologies are caught at application startup (`.build()`) rather than leaking PII at runtime.
- **Canonical Ordering Guarantee:** Developers cannot accidentally place `AnonymizationFilter` before `PIIDetectorFilter` even if they call `.with_anonymization_strategy()` before `.with_detector()`.
- **Clean Test Fixtures:** Integration and abuse tests can fluently construct minimal or specialized pipelines in 4–5 lines of readable code.

### Negative / Mitigations
- **Additional Boilerplate Class:** Requires maintaining `PipelineBuilder` alongside `Pipeline`. *Mitigation:* Because `PipelineBuilder` assembles abstract interfaces (`PIIDetector`, `AnonymizationStrategy`, `ResidencyPolicyEngine`), adding new strategy implementations requires zero changes to `PipelineBuilder`.

---

## 5. Compliance with Scenarios

- **Scenario 1 & 2:** Ensures `VaultProxy` and `ResponseRestorer` are wired whenever reversible tokenization is enabled.
- **Scenario 3 (EU Data Residency):** Guarantees `ResidencyPolicyFilter` is positioned before external LLM dispatch whenever residency policies are configured.
- **Scenario 4 ($k$-Anonymity):** Validates that a `GeneralizationHierarchy` is bound when `.with_k_anonymity_threshold(k)` is configured.
- **Scenario 6 (IBAN Extension):** Allows registering `PolishIBANDetector` and its strategy fluently via `.with_detector(...)` and `.with_anonymization_strategy(...)` without modifying `PipelineBuilder`.
