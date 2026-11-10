# Cryptographic Vault, Protection Proxy & Memento Specification (`openspec/specs/vault-memento/spec.md`)

## Requirements

### Requirement: RBAC-Enforced and Audited Token Vault via Protection Proxy
All callers outside `src/vault/proxy.py` SHALL access the vault exclusively through `VaultProtectionProxy`, which enforces RBAC permissions, tenant isolation, AES-256-GCM authenticated encryption (with `tenant_id`, `request_id`, `entity_type` AAD), and mandatory audit logging on every operation.

#### Scenario: Scenario 2 — Unauthorized Detokenization Block & Audit Logging
- **GIVEN** a `SecurityPrincipal` lacking `Permission.DETOKENIZE` or belonging to a mismatched `tenant_id`
- **WHEN** `VaultProtectionProxy.detokenize()` is called
- **THEN** `UnauthorizedVaultAccessError` is raised, zero plaintext is returned, and an `AuditEvent(outcome="DENIED")` is recorded

#### Scenario: Scenario 5 — Key Rotation and Token Expiration
- **GIVEN** tokens encrypted under `key_v1` followed by a key rotation to `key_v2` (`key_v1` transitioned to `DECRYPT_ONLY` or `REVOKED`)
- **WHEN** detokenization is requested for an unexpired token under `DECRYPT_ONLY` vs. an expired token or `REVOKED` key
- **THEN** valid `DECRYPT_ONLY` tokens decrypt cleanly while expired tokens or `REVOKED` keys fail closed with `TokenExpiredError` / `KeyExpiredError` and emit an audit event

### Requirement: Opaque Request-Scoped State via Memento
`AnonymizationMemento` SHALL store only encapsulated `placeholder -> token_id` references and metadata, never raw plaintext PII.
