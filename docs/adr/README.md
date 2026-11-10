# Architecture Decision Records (`docs/adr/`)

This directory contains the Architecture Decision Records (ADRs) governing the design patterns, cryptographic boundaries, and extensibility guarantees of the **LLM Anonymization & Pseudonymization Pipeline**.

## ADR Index

| ID | Title | Primary Pattern | Status | Scenarios Addressed |
| :--- | :--- | :--- | :--- | :--- |
| [ADR-001](001-pipes-and-filters-pipeline.md) | Synchronous Prompt/Response Sanitization via Pipes & Filters | **Pipes & Filters** | Accepted | Scenarios 1, 3, 4, 6 |
| [ADR-002](002-strategy-pattern-detectors-and-anonymizers.md) | Pluggable PII Detectors and Anonymization Algorithms via Strategy Pattern | **Strategy** | Accepted | Scenarios 1, 4, 6 + Week 6 Change Request |
| [ADR-003](003-pipeline-builder.md) | Composing Multi-Stage Compliance Pipelines via Fluent Builder | **Builder** | Accepted | Scenarios 1, 3, 4, 6 |
| [ADR-004](004-protection-proxy-token-vault.md) | Access-Controlled Cryptographic Token Vault via Protection Proxy | **Protection Proxy** | Accepted | Scenarios 1, 2, 5 |
| [ADR-005](005-memento-state-restoration.md) | Encapsulated Request-Scoped State Restoration via Memento Pattern | **Memento** | Accepted | Scenarios 1, 2, 5 |

---

## Standard ADR Template

Every new ADR added during Milestones 1–4 must follow the sections below:
1. **Status** (`Proposed` | `Accepted` | `Superseded by ADR-00X`)
2. **Context & Problem**
3. **Decision**
4. **Rejected Alternatives**
5. **Trade-offs & Consequences**
6. **Compliance with Project Scenarios**
