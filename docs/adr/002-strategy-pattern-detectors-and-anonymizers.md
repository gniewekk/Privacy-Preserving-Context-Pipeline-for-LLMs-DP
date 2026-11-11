# ADR-002: Pluggable PII Detectors and Anonymization Algorithms via Strategy Pattern

- **Status:** Accepted
- **Date:** 2026-11-10
- **Component:** `src/detectors/`, `src/strategies/`

---

## 1. Context & Problem

The pipeline must detect diverse PII/PHI categories (Polish PESEL, SSN, email addresses, medical diagnoses, quasi-identifiers, and future financial identifiers like Polish IBANs) and apply distinct transformation policies depending on the entity type and regulatory context:
1. **Irreversible Masking:** For identifiers irrelevant to the LLM's reasoning (e.g., `PESEL` -> `***********`).
2. **Reversible Cryptographic Tokenization:** For entities that must be restored in the LLM's response for authorized users (e.g., `Jan Kowalski` -> `<PERSON_1>`).
3. **$k$-Anonymity Generalization:** For quasi-identifiers (age, city, postal code) where combinations could re-identify an individual even after direct identifiers are removed.

Furthermore, Scenario 6 requires adding a new detector/strategy (such as Polish IBAN detection and formatting-preserving masking) and accommodating future change requests without core modifications. If `PIIDetectorFilter` or `AnonymizationFilter` contains conditional branching (`if entity.type == "PESEL": ...`), every new entity or algorithm violates the Open-Closed Principle (OCP) and risks breaking existing sanitization logic.

---

## 2. Decision

We apply the **Strategy Pattern** to both detection (`src/detectors/`) and anonymization (`src/strategies/`), backed by a declarative `StrategyRegistry` / `StrategySelector`.

### 1. `PIIDetector` Strategy Interface
```python
class PIIDetector(Protocol):
    @property
    def detector_id(self) -> str: ...
    def detect(self, text: str, language: str) -> Sequence[DetectedEntity]: ...
```
- Concrete strategies: `RegexPIIDetector` (with optional checksum validators such as PESEL Mod-10 or IBAN Mod-97), `NERPIIDetector`, and `HeuristicPIIDetector`.
- `PIIDetectorFilter` iterates over an injected `Sequence[PIIDetector]`, merges overlapping spans deterministically (highest confidence / longest span wins), and never inspects the concrete detector class.

### 2. `AnonymizationStrategy` Interface
```python
class AnonymizationStrategy(Protocol):
    @property
    def strategy_id(self) -> str: ...
    def is_reversible(self) -> bool: ...
    def anonymize(
        self, entity: DetectedEntity, request: AnonymizationRequest
    ) -> AnonymizationResult: ...
```
- Concrete strategies:
  - `MaskingStrategy`: Irreversible character replacement (`*` or `[REDACTED_TYPE]`).
  - `TokenizationStrategy`: Generates a deterministic or random placeholder (`<PERSON_1>`) and stores the plaintext mapping in `VaultProxy` using AES-256-GCM.
  - `GeneralizationStrategy`: Maps fine-grained quasi-identifiers (e.g., `age=34`, `city="Sępólno Krajeńskie"`) up a `GeneralizationHierarchy` (`age="30-39"`, `region="Kujawsko-Pomorskie"`) until $k \ge k_{\text{target}}$.

---

## 3. Rejected Alternatives

### Alternative A: Conditional `if/elif/match` Dispatch Inside `AnonymizationFilter`
Hardcoding strategy selection inside `AnonymizationFilter.process()` based on `EntityType` enums.
- **Why Rejected:** Directly violates OCP and `AGENTS.md`. Adding a Polish IBAN detector or a synthetic data replacement strategy would force edits to core pipeline classes and require modifying exhaustive `match` blocks across the codebase.

### Alternative B: Class Inheritance Hierarchy on `DetectedEntity` (`PeselEntity.anonymize()`)
Embedding the anonymization algorithm directly as a method on entity subclasses.
- **Why Rejected:** Couples *what* was detected to *how* it is anonymized. The same `PERSON` or `IBAN` entity may require `TokenizationStrategy` in a customer-support workflow but `MaskingStrategy` in an analytics summarization workflow.

---

## 4. Trade-offs & Consequences

### Positive
- **Zero-Touch Extensibility (OCP):** Adding `PolishIBANDetector` and an `IBANPartialMaskingStrategy` in Scenario 6 requires creating new classes in `src/detectors/` and `src/strategies/` and registering them via `PipelineBuilder`—zero lines changed in `src/pipeline/`.
- **Runtime Policy Switching:** Different tenants or endpoints can bind different `AnonymizationStrategy` instances to the same `EntityType` without code changes.
- **Independent Testability:** Checksum logic (PESEL, IBAN) and generalization hierarchies can be unit-tested with fast property-based tests completely independent of the pipeline or cryptographic vault.

### Negative / Mitigations
- **Span Conflict Resolution:** When multiple `PIIDetector` strategies run on the same prompt, their detected character spans may overlap (e.g., a regex email detector and a NER person detector). *Mitigation:* `PIIDetectorFilter` uses a deterministic span resolver (preferring higher sensitivity/confidence and wider span bounds) before passing entities to `AnonymizationFilter`.

---

## 5. Compliance with Scenarios

- **Scenario 1 (Pseudonymization):** `TokenizationStrategy` delegates encryption to `VaultProxy` and records token placeholders in `PipelineMemento`.
- **Scenario 4 ($k$-Anonymity Generalization):** `GeneralizationStrategy` generalizes quasi-identifier attributes until the equivalence class size satisfies $k$.
- **Scenario 6 (IBAN / New Detector Extension):** Proves that new detectors and anonymization algorithms plug into the pipeline via `PipelineBuilder` without modifying core pipeline files.
