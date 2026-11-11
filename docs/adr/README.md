# Architecture Decision Records (`docs/adr/`)

This directory contains the Architecture Decision Records (ADRs) governing the design patterns, cryptographic boundaries, and extensibility guarantees of the **LLM Anonymization & Pseudonymization Pipeline**.

## ADR Index

| ID | Title | Primary Pattern / Mechanism | Status | Scenarios Addressed |
| :--- | :--- | :--- | :--- | :--- |
| [ADR-001](001-pipes-and-filters-pipeline.md) | Synchronous Prompt/Response Sanitization via Pipes & Filters | **Pipes & Filters** | Accepted | Scenarios 1, 3, 4, 6 |
| [ADR-002](002-strategy-pattern-detectors-and-anonymizers.md) | Pluggable PII Detectors and Anonymization Algorithms via Strategy Pattern | **Strategy** | Accepted | Scenarios 1, 4, 6 |
| [ADR-003](003-pipeline-builder.md) | Composing Multi-Stage Compliance Pipelines via Fluent Builder | **Builder** | Accepted | Scenarios 1, 3, 4, 6 |
| [ADR-004](004-protection-proxy-token-vault.md) | Access-Controlled Cryptographic Token Vault via Protection Proxy | **Protection Proxy** | Accepted | Scenarios 1, 2, 5 |
| [ADR-005](005-memento-state-restoration.md) | Encapsulated Request-Scoped State Restoration via Memento Pattern | **Memento** | Accepted | Scenarios 1, 2, 5 |
| [ADR-006](006-streaming-proxy-placeholder-buffering.md) | Streaming Response Detokenization via Placeholder Window Buffering | **Pipes & Filters (Streaming)** | Accepted | Scenarios 1, 2, 6 |
| [ADR-007](007-anonymized-agentic-tool-calling.md) | Anonymized Agentic Tool Calling & Dynamic Memento Expansion | **Memento + Proxy** | Accepted | Scenarios 1, 2, 3 + Agentic Workflows |
| [ADR-008](008-hybrid-ner-and-context-enhancers.md) | Hybrid Unstructured PII Detection (Ensemble NER & Context Enhancers) | **Strategy** | Accepted | Scenarios 1, 4, 6 |
| [ADR-009](009-pdf-extract-then-anonymize.md) | Extract-Then-Anonymize PDF Processing (Fail-Closed on Raw Binaries) | **Pipes & Filters (Fail-Closed Gate)** | Accepted | Scenarios 1, 3 + Multimodal Inputs |

---

## Standard ADR Template

Every new ADR added to the project must follow the sections below:
1. **Status** (`Proposed` | `Accepted` | `Superseded by ADR-00X`)
2. **Context & Problem**
3. **Decision**
4. **Rejected Alternatives**
5. **Trade-offs & Consequences**
6. **Compliance with Project Scenarios**
