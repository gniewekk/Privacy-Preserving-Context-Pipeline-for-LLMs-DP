# Detection & Anonymization Strategy Specification (`openspec/specs/detection-anonymization/spec.md`)

## Requirements

### Requirement: Open-Closed Strategy Dispatch
`DetectionFilter` and `AnonymizationFilter` SHALL delegate exclusively to `PIIDetector` and `AnonymizationStrategy` interfaces without concrete type branching (`if/elif` or `match/case`).

#### Scenario: Scenario 4 — k-Anonymity Generalization on Quasi-Identifiers
- **GIVEN** a prompt with quasi-identifiers (`age=47`, `profession="neurochirurg"`, `city="Sępólno Krajeńskie"`) whose equivalence class size $k < k_{\text{target}}$
- **WHEN** `KAnonymityGeneralizationStrategy` processes the entities
- **THEN** attributes are generalized up their hierarchy until $k \ge k_{\text{target}}$ or rejected fail-closed with `ReIdentificationRiskError`

#### Scenario: Scenario 6 — Zero-Core-Modification Extension (Polish IBAN)
- **GIVEN** a new `PolishIBANDetector` (with ISO 13616 Modulo-97 checksum validation) and an IBAN strategy registered via `PipelineBuilder`
- **WHEN** a prompt containing a Polish IBAN (`PL61 1090 1014 0000 0712 1981 2874`) is processed
- **THEN** the IBAN is detected and anonymized with zero modifications to `src/pipeline/` modules
