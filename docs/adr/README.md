# Architecture Decision Records

This directory holds rizzy-vault's Architecture Decision Records (ADRs). Each ADR is one decision: the context, what was decided, what it costs, what else was considered, and what the owner still has to answer. The format and the rules come from [ADR 0020](0020-partial-supersession.md), which carries ADR 0001's rules forward and adds partial supersession. New ADRs start from the [template](0000-template.md).

Related documents:

- [ROADMAP.md](../ROADMAP.md): scope and milestones. It is the source of truth for *what* we build.
- [THREAT_MODEL.md](../THREAT_MODEL.md): goals, non-goals and security invariants.
- [CRYPTO.md](../CRYPTO.md): the detailed cryptographic specification that ADRs 0003–0009 decide on.

## Lifecycle

```text
Proposed ──► Accepted ──► Partially superseded by ADR NNNN (§…)
    │            │
    │            └──────► Superseded by ADR NNNN
    └──────► Rejected
```

| Status | Meaning |
|---|---|
| **Proposed** | Written and open for review. May be merged to `main` for discussion. **Not binding: code must not rely on it.** |
| **Accepted** | Binding. Only the project owner accepts. The owner's answers to "Open questions for the owner" go into the Decision section first. |
| **Rejected** | Declined by the owner. The file stays so that nobody has to reconstruct the reasoning. |
| **Partially superseded by ADR NNNN (§…)** | The parts ADR NNNN names are replaced and no longer bind. Everything else stays binding. Only the status line changes; the old text stays. |
| **Superseded by ADR NNNN** | Replaced by a newer Accepted ADR. Only the status line changes. |

**Who decides:** the project owner accepts or rejects every ADR.

**Accepted ADRs are immutable.** Allowed edits are the status line, typo and link fixes, and dated `## Amendments` entries for changes the ADR itself provides for (for example, the crate table in ADR 0009 or the license allow-list in ADR 0017). Anything else is a new ADR that supersedes the old one, in full or in the parts it names ([ADR 0020](0020-partial-supersession.md) point 9).

## The ADR-first rule

**An Accepted ADR must exist before code for any of the following is merged:**

- cryptography: constructions, primitives, parameters, key handling;
- protocol: authentication, sessions, the wire protocol, API versioning;
- persistent formats: ciphertext envelope, op log, export files, local cache, and schema changes that alter what the server stores;
- security boundaries: server roles, trust boundaries, what each component may see;
- a new cryptographic dependency ([ADR 0009](0009-crypto-dependency-policy.md));
- crate boundaries and dependency direction ([ADR 0016](0016-workspace-layout.md));
- licensing and contribution terms ([ADR 0017](0017-licensing.md)).

The parts of a Partially superseded ADR that no later Accepted ADR names count as Accepted. Proposed is not enough. If the relevant ADR is Proposed, or no ADR exists, stop: write or update the ADR and get it accepted first. Spikes that inform an ADR live on a branch or outside `crates/`, and are never merged into a shipped crate.

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
| 0001 | [Record architecture decisions](0001-record-architecture-decisions.md) | Superseded by [0020](0020-partial-supersession.md) | M0 |
| 0002 | [Own protocol, not Bitwarden-API compatible](0002-own-protocol.md) | Partially superseded by [0022](0022-server-mode-only.md) (point 3 in part) | M1 |
| 0003 | [Authentication: OPAQUE](0003-authentication-opaque.md) | Partially superseded by [0022](0022-server-mode-only.md) (point 10) | M1 |
| 0004 | [Key derivation: Argon2id and the Secret Key](0004-key-derivation-argon2id-secret-key.md) | Accepted | M1 |
| 0005 | [Symmetric encryption: AEAD and key commitment](0005-symmetric-encryption-aead.md) | Accepted | M1 |
| 0006 | [Key hierarchy, per-user keypairs and key wrapping](0006-key-hierarchy.md) | Partially superseded by [0022](0022-server-mode-only.md) (point 1 in part, point 11 in part, Risks in part) | M1 |
| 0007 | [Versioned ciphertext envelope and crypto agility](0007-ciphertext-envelope.md) | Accepted | M1 |
| 0008 | [Account recovery: Emergency Kit](0008-account-recovery.md) | Partially superseded by [0022](0022-server-mode-only.md) (point 7) | M1 |
| 0009 | [Cryptographic dependency and memory-hygiene policy](0009-crypto-dependency-policy.md) | Partially superseded by [0019](0019-native-clients.md) ("RNG rules" in part) | M1 |
| 0010 | [Server shape: modular monolith with roles](0010-server-shape.md) | Partially superseded by [0022](0022-server-mode-only.md) (§1 in part) | M1 (`api`, `web`, `worker`) / M3 (`notify`, `icons`) / M6 (`smtp`) |
| 0011 | [Storage: SQLite and PostgreSQL via sqlx](0011-storage.md) | Partially superseded by [0022](0022-server-mode-only.md) (point 9 in part, "Transactions and concurrency" in part, "What is stored, by sync mode", "Backups" in part) | M1 (SQLite) / M3 (PostgreSQL supported) |
| 0012 | [Sync engine: op log, HLC and version vectors](0012-sync-engine.md) | Partially superseded by [0018](0018-item-record-encoding.md) (§1 in part, §3 in part, §4 in part, §5 in part, §6 in part, §7 in part, §12 in part); [0021](0021-server-compaction.md) (§6 in part, §7 in part); [0022](0022-server-mode-only.md) (Milestone line, §5 in part, §6 in part, §8, §9 in part, §10, §11, §12 in part, owner decisions 3, 5 and 8, Risks in part) | M1 (engine, Server mode) |
| 0013 | [Shared Rust client core (wasm + UniFFI)](0013-shared-client-core.md) | Partially superseded by [0022](0022-server-mode-only.md) (§3 in part); [0019](0019-native-clients.md) (Milestone line, Context in part, §1 in part, §2 in part, §3 in part, §5, §6 in part, Negative in part, Risks in part) | M1 (wasm, CLI) / M3 (native desktop bindings) / M7 (UniFFI) |
| 0014 | [UI stack for the web platforms](0014-ui-stack.md) | Partially superseded by [0022](0022-server-mode-only.md) (§6) | M1 (web vault) / M2 (extensions) / M3 (design system) / M5 (share page) |
| 0015 | [Desktop shell: Tauri](0015-desktop-tauri.md) | Superseded by [0019](0019-native-clients.md) | M3 |
| 0016 | [Workspace layout and crate boundaries](0016-workspace-layout.md) | Partially superseded by [0022](0022-server-mode-only.md) (§3 in part); [0019](0019-native-clients.md) (§3 in part, R2 in part, R5, R6, R7 in part, §5 in part, §7, Risks in part, Alternatives considered in part) | M0 (rules, current crates) / M1–M9 (planned crates) |
| 0017 | [Licensing and contribution terms](0017-licensing.md) | Accepted | M0 |
| 0018 | [Item-record encoding: canonical binary layout and the M1 item schema](0018-item-record-encoding.md) | Accepted | M1 |
| 0019 | [Native desktop and mobile clients in separate repositories](0019-native-clients.md) | Accepted | M3 (desktop) / M7 (mobile) |
| 0020 | [Record architecture decisions, with partial supersession](0020-partial-supersession.md) | Accepted | M0 |
| 0021 | [Server-side compaction with concurrent snapshots](0021-server-compaction.md) | Accepted | M1 (server; Accepted before step 3) |
| 0022 | [Server mode only: On-device sync parked](0022-server-mode-only.md) | Accepted | M1 (scope) / post-1.0 (parked) |
| 0023 | [Logical database backup file format](0023-logical-backup-format.md) | Accepted | M1 |
| 0024 | [Disabling core dumps through rustix](0024-core-dump-disabling-rustix.md) | Accepted | M1 (server, `rv`) / M3 (bindings) |
| 0025 | [Key rotation upload: the vault half and the rotation cut-off](0025-rotation-vault-half.md) | Accepted | M1 |
| 0026 | [Client device state and encrypted local cache](0026-client-device-state-and-cache.md) | Accepted | M1 (`rv`) / M2 (extension) / M3 (`rizzy-ffi`) |
| 0027 | [Export payload encoding and plaintext export](0027-export-payload.md) | Accepted | M1 |
| 0028 | [`/api/v1` HTTP conventions](0028-api-v1-http-conventions.md) | Accepted | M1 |
| 0029 | [KeePass KDBX import: legacy primitives in `rizzy-import`](0029-kdbx-import.md) | Proposed | M3 |
| 0030 | [Client-side TLS for `rv`](0030-client-tls-rv.md) | Proposed | M1 |
| 0031 | [Retiring old OPAQUE setups](0031-retiring-old-opaque-setups.md) | Proposed | M1 |

## Gates

- **Before external contributions are merged:** 0020, 0016 and 0017 Accepted, and ADR 0017's App Store permission (Decision 3) committed. Documentation PRs are exempt.
- **Before any vault code in M1:** 0002–0009 and 0016 Accepted. 0002–0009 are reviewed as one set against [CRYPTO.md](../CRYPTO.md). A Rejected ADR blocks its area until an Accepted replacement exists.
- **Before server and client scaffolding in M1:** 0010–0014 Accepted.
- **Before desktop work in M3:** 0019 Accepted. For Windows (Linux): spike S2 (S3) recorded as passed, in an ADR 0019 `## Amendments` entry, for the route of ADR 0019 owner decision 8 (9); or, after a failed spike, an Accepted ADR that records the replacement route.
