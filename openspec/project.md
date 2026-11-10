# Project Context (`openspec/project.md`)

## Purpose
Privacy-preserving context sanitization and pseudonymization middleware for Large Language Models (LLMs). Detects PII/PHI in inbound prompts, documents, and agentic tool calls; applies pluggable anonymization strategies (masking, reversible AES-256-GCM tokenization, $k$-anonymity generalization); enforces EU data residency gates; and restores authorized tokens in responses via the Memento and Protection Proxy patterns.

## Tech Stack
- **Language:** Python 3.12+ (modern type syntax, strict `mypy`)
- **Domain Modeling:** Pydantic v2 (`ConfigDict(frozen=True, extra="forbid")`)
- **API / Middleware:** FastAPI
- **Cryptography:** `cryptography` (`AESGCM` 256-bit authenticated encryption with AAD)
- **Verification & SAST:** `pytest`, `mypy --strict`, `ruff`, `bandit`, `pip-audit`

## Core Design Patterns & Architecture References
- **Pipes & Filters (`src/pipeline/`):** Stateless `Filter` stages operating over an immutable `PipelineContext` ([ADR-001](../docs/adr/001-pipes-and-filters-pipeline.md), [ADR-006](../docs/adr/006-streaming-proxy-placeholder-buffering.md), [ADR-009](../docs/adr/009-pdf-extract-then-anonymize.md)).
- **Strategy (`src/detectors/`, `src/strategies/`):** Open-Closed (`OCP`) pluggable `PIIDetector` and `AnonymizationStrategy` interfaces ([ADR-002](../docs/adr/002-strategy-pattern-detectors-and-anonymizers.md), [ADR-008](../docs/adr/008-hybrid-ner-and-context-enhancers.md)).
- **Builder (`src/pipeline/builder.py`):** Fluent `PipelineBuilder` enforcing build-time structural invariants ([ADR-003](../docs/adr/003-pipeline-builder.md)).
- **Protection Proxy (`src/vault/`):** `VaultProtectionProxy` gating package-private `TokenVault` with RBAC, tenant isolation, and tamper-evident audit logging ([ADR-004](../docs/adr/004-protection-proxy-token-vault.md)).
- **Memento (`src/state/`):** `AnonymizationMemento`, `SessionOriginator`, and `Caretaker` managing opaque request-scoped token state without storing raw PII ([ADR-005](../docs/adr/005-memento-state-restoration.md), [ADR-007](../docs/adr/007-anonymized-agentic-tool-calling.md)).

## Non-Negotiable Constraints
See root [`AGENTS.md`](../AGENTS.md) and [`docs/security/STRIDE.md`](../docs/security/STRIDE.md).
