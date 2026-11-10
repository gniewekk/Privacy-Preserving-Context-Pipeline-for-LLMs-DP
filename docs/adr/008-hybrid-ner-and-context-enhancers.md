# ADR-008: Hybrid Unstructured PII Detection (Ensemble NER & Context Enhancers)

- **Status:** Accepted
- **Date:** 2026-11-10
- **Component:** `src/detectors/` (`PIIDetector`, `RegexPIIDetector`, `NERPIIDetector`, `HeuristicPIIDetector`)

---

## 1. Context & Problem

Deterministic regular expressions and checksum validators (e.g., Modulo-10 for Polish PESEL, Modulo-97 for IBAN) achieve near-100% precision on structured identifiers but fail completely on unstructured natural-language PII such as Polish personal names, street addresses, or clinical descriptions.

Conversely, relying solely on standard pretrained Transformer Named Entity Recognition (NER) models introduces two critical risks in Polish and multilingual prompts:
1. **Capitalization & Inflection Bias:** Users frequently type prompts in all-lowercase (`"jan kowalski mieszka przy ul. lipowej"`), with typos, or in Polish grammatical cases (*narzędnik/miejscownik*: `"z janem kowalskim"`), causing standard NER models to suffer sharp drops in recall (False Negatives).
2. **Heavy ML Runtime Dependencies:** Loading `torch` and `transformers` in every unit test or lightweight deployment environment slows down CI and bloats container images.

---

## 2. Decision

We design the detection layer around a composable **Hybrid Ensemble of `PIIDetector` Strategies** orchestrated by `DetectionFilter`:

1. **Tier 1 — Deterministic Regex + Checksum Detectors (`RegexPIIDetector`):**
   - Zero-dependency detectors for structured identifiers (PESEL, SSN, Email, Phone, Polish IBAN) combining normalized regex matching with mathematical checksum verification to eliminate false positives on random digit sequences.
2. **Tier 2 — Contextual & Gazetteer Heuristic Detectors (`HeuristicPIIDetector`):**
   - Lightweight context-window analyzers (`ContextRuleEnhancer`) and dictionary lookups that identify lowercase or inflected entities preceded by trigger markers (e.g., `"pacjent:"`, `"klient"`, `"nazywam się"`, `"ul."`, `"zamieszkały"`) and boost confidence scores for lowercase spans.
3. **Tier 3 — Optional Transformer NER Adapter (`NERPIIDetector`):**
   - Pluggable adapter for Transformer NER models (such as `HerBERT` or `GLiNER`) isolated behind the `PIIDetector` protocol and packaged under the optional `[project.optional-dependencies] ner` group (`torch`, `transformers`).
4. **Deterministic Span Merging:**
   - When multiple registered `PIIDetector` strategies emit overlapping `DetectedEntity` spans, `DetectionFilter` resolves overlaps deterministically by prioritizing higher-confidence and wider-span matches (favoring recall over precision in accordance with Privacy by Design).

---

## 3. Rejected Alternatives

### Alternative A: Regex-Only Detection
Using only regular expressions for all PII categories including names and locations.
- **Why Rejected:** Unacceptable False Negative rate on unstructured text, inflected Polish surnames, and free-form medical notes.

### Alternative B: Mandatory Heavy Transformer Model in Core Dependencies
Making PyTorch and HuggingFace Transformers mandatory runtime dependencies for all pipeline instances.
- **Why Rejected:** Pulls >2 GB of CUDA/PyTorch packages into the base environment, slows down CI security gates (`pytest`, `pip-audit`), and violates dependency isolation when only deterministic/heuristic detectors are needed.

---

## 4. Trade-offs & Consequences

### Positive
- **High Recall on Informal & Inflected Text:** Combining heuristic context rules with optional NER mitigates capitalization bias on lowercase Polish inputs.
- **Fast, Lightweight Core CI:** Core unit tests, `mypy --strict`, and `pip-audit` run rapidly without requiring GPU/CUDA wheels, while `NERPIIDetector` can be injected via `PipelineBuilder.with_detector(...)` whenever ML-grade extraction is enabled.

### Negative / Mitigations
- **Increased False Positives from Conservative Thresholds:** Boosting confidence via context keywords may occasionally anonymize benign nouns near trigger words. *Mitigation:* In a privacy-preserving pipeline, a False Positive (over-anonymization) is safe, whereas a False Negative (PII leak) is a critical security failure.

---

## 5. Compliance with Scenarios

- **Scenario 1 (Pseudonymization):** Detects both structured (`PESEL`) and unstructured (`PERSON`) entities in a single pass.
- **Scenario 4 ($k$-Anonymity):** Extracts demographic quasi-identifiers (age, profession, location) for downstream risk evaluation.
- **Scenario 6 (New Detector Extension):** New detectors (e.g., `PolishIBANDetector`) implement `PIIDetector` and plug into the ensemble without modifying `DetectionFilter`.
