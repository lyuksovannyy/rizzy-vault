# Architecture Decision Records

This directory holds rizzy-vault's Architecture Decision Records (ADRs). Each ADR is one decision: the context, what was decided, what it costs, what else was considered, and what the owner still has to answer. The format and the rules come from [ADR 0001](0001-record-architecture-decisions.md). New ADRs start from the [template](0000-template.md).

Related documents:

- [ROADMAP.md](../ROADMAP.md): scope and milestones. It is the source of truth for *what* we build.
- [THREAT_MODEL.md](../THREAT_MODEL.md): goals, non-goals and security invariants.
- [CRYPTO.md](../CRYPTO.md): the detailed cryptographic specification that ADRs 0003–0009 decide on.

## Lifecycle

```text
Proposed ──► Accepted ──► Superseded by ADR NNNN
    │
    └──────► Rejected
```

| Status | Meaning |
|---|---|
| **Proposed** | Written and open for review. May be merged to `main` for discussion. **Not binding: code must not rely on it.** |
| **Accepted** | Binding. Only the project owner accepts. The owner's answers to "Open questions for the owner" go into the Decision section first. |
| **Rejected** | Declined by the owner. The file stays so that nobody has to reconstruct the reasoning. |
| **Superseded by ADR NNNN** | Replaced by a newer Accepted ADR. Only the status line changes. |

**Who decides:** the project owner accepts or rejects every ADR.

**Accepted ADRs are immutable.** Allowed edits are the status line, typo and link fixes, and dated `## Amendments` entries for changes the ADR itself provides for (for example, the crate table in ADR 0009 or the license allow-list in ADR 0017). Anything else is a new ADR that supersedes the old one.

## The ADR-first rule

**An Accepted ADR must exist before code for any of the following is merged:**

- cryptography: constructions, primitives, parameters, key handling;
- protocol: authentication, sessions, the wire protocol, API versioning;
- persistent formats: ciphertext envelope, op log, export files, local cache, and schema changes that alter what the server stores;
- security boundaries: server roles, trust boundaries, what each component may see;
- a new cryptographic dependency ([ADR 0009](0009-crypto-dependency-policy.md));
- crate boundaries and dependency direction ([ADR 0016](0016-workspace-layout.md));
- licensing and contribution terms ([ADR 0017](0017-licensing.md)).

Proposed is not enough. If the relevant ADR is Proposed, or no ADR exists, stop: write or update the ADR and get it accepted first. Spikes that inform an ADR live on a branch or outside `crates/`, and are never merged into a shipped crate.

Refactors that keep behaviour, bug fixes, tests, docs, UI work within an accepted stack and non-crypto dependencies do not need an ADR. They follow [CONTRIBUTING.md](../../CONTRIBUTING.md).

## Writing a new ADR

1. Copy [0000-template.md](0000-template.md) to `NNNN-kebab-title.md`, using the next free number. Numbers are never reused.
2. Fill every section. Tag claims about crates, audits, standards and benchmarks as V (verified), L (likely) or U (unverified).
3. Add a row to the index below in the same PR.
4. Open the PR with `Status: Proposed`. Acceptance is a separate change by the owner.

## Index

| # | Title | Status | Milestone |
|---|---|---|---|
| 0000 | [Template](0000-template.md) | Template | – |
| 0001 | [Record architecture decisions](0001-record-architecture-decisions.md) | Proposed | M0 |
| 0002 | [Own protocol, not Bitwarden-API compatible](0002-own-protocol.md) | Proposed | M1 |
| 0003 | [Authentication: OPAQUE](0003-authentication-opaque.md) | Proposed | M1 |
| 0004 | [Key derivation: Argon2id and the Secret Key](0004-key-derivation-argon2id-secret-key.md) | Proposed | M1 |
| 0005 | [Symmetric encryption: AEAD and key commitment](0005-symmetric-encryption-aead.md) | Proposed | M1 |
| 0006 | [Key hierarchy, per-user keypairs and key wrapping](0006-key-hierarchy.md) | Proposed | M1 |
| 0007 | [Versioned ciphertext envelope and crypto agility](0007-ciphertext-envelope.md) | Proposed | M1 |
| 0008 | [Account recovery: Emergency Kit](0008-account-recovery.md) | Proposed | M1 |
| 0009 | [Cryptographic dependency and memory-hygiene policy](0009-crypto-dependency-policy.md) | Proposed | M1 |
| 0010 | [Server shape: modular monolith with roles](0010-server-shape.md) | Proposed | M1 (`api`, `web`, `worker`) / M3 (`notify`, `icons`) / M6 (`smtp`) |
| 0011 | [Storage: SQLite and PostgreSQL via sqlx](0011-storage.md) | Proposed | M1 (SQLite) / M3 (PostgreSQL supported) |
| 0012 | [Sync engine: op log, HLC and version vectors](0012-sync-engine.md) | Proposed | M1 (engine, Server mode) / M4 (On-device mode) |
| 0013 | [Shared Rust client core (wasm + UniFFI)](0013-shared-client-core.md) | Proposed | M1 (wasm, CLI) / M3 (Tauri) / M7 (UniFFI) |
| 0014 | [UI stack](0014-ui-stack.md) | Proposed | M1 (web vault) / M2 (extension) / M3 (design system, desktop) |
| 0015 | [Desktop shell: Tauri](0015-desktop-tauri.md) | Proposed | M3 |
| 0016 | [Workspace layout and crate boundaries](0016-workspace-layout.md) | Proposed | M0 (rules, current crates) / M1–M9 (planned crates) |
| 0017 | [Licensing and contribution terms](0017-licensing.md) | Proposed | M0 |

## Gates

- **Before external contributions are merged:** 0001, 0016 and 0017 Accepted. Documentation PRs are exempt.
- **Before any vault code in M1:** 0002–0009 and 0016 Accepted. 0002–0009 are reviewed as one set against [CRYPTO.md](../CRYPTO.md). A Rejected ADR blocks its area until an Accepted replacement exists.
- **Before server and client scaffolding in M1:** 0010–0014 Accepted.
- **Before desktop work in M3:** 0015 Accepted.
