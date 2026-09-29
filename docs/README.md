# Documentation index

This page says where each topic is documented and which code implements it. It is an index, not a design description: every design lives in the document it links to, and only there.

**Which documents bind.**
- [ROADMAP.md](ROADMAP.md) is the source of truth for scope.
- [CRYPTO.md](CRYPTO.md) is the normative cryptographic specification.
- The invariants in [THREAT_MODEL.md §8](THREAT_MODEL.md#8-security-invariants) are requirements.
- Only **Accepted** ADRs bind, and the parts of a Partially superseded ADR that no later Accepted ADR names ([ADR 0020](adr/0020-partial-supersession.md) point 9). A Proposed ADR is open for review, and no code may rely on it. The lifecycle and the ADR-first rule are in [adr/README.md](adr/README.md).

"Not implemented" below means that no code exists for that part yet. The state of each milestone is in the [top-level README](../README.md#status).

## Encryption and the key hierarchy

Each CRYPTO.md section, and the `rizzy-core` module that implements it. Module names link to their source files.

| CRYPTO.md | Topic | `rizzy-core` module |
|---|---|---|
| [§1](CRYPTO.md#1-goals-non-goals-and-rules) | Goals, non-goals, rules, the list of our own compositions | Crate contract in [`lib.rs`](../crates/rizzy-core/src/lib.rs) |
| [§2](CRYPTO.md#2-conventions) | Conventions: integers, strings, labels, identifiers, normalisation | [`encoding`](../crates/rizzy-core/src/encoding.rs), [`labels`](../crates/rizzy-core/src/labels.rs), [`ids`](../crates/rizzy-core/src/ids.rs), [`normalize`](../crates/rizzy-core/src/normalize.rs) |
| [§3](CRYPTO.md#3-primitives) | Primitives and the crates that provide them | Pins in the root [`Cargo.toml`](../Cargo.toml); policy in [ADR 0009](adr/0009-crypto-dependency-policy.md) |
| [§4](CRYPTO.md#4-key-hierarchy) | Key hierarchy: diagram, inventory, derivations, identifiers, epochs, key ids | [`keys`](../crates/rizzy-core/src/keys/mod.rs), [`labels`](../crates/rizzy-core/src/labels.rs), [`ids`](../crates/rizzy-core/src/ids.rs) |
| [§5](CRYPTO.md#5-opaque-integration) | OPAQUE integration | [`opaque`](../crates/rizzy-core/src/opaque/mod.rs), [`rng`](../crates/rizzy-core/src/rng.rs) (the opaque-ke RNG adapter) |
| [§5.10](CRYPTO.md#510-sessions-after-authentication) | Sessions after authentication | [`sign`](../crates/rizzy-core/src/sign/mod.rs) (`device-auth`, `device-request`) |
| [§5.11](CRYPTO.md#511-server-side-encryption-not-zero-knowledge) | Server-side encryption (not zero knowledge) | [`server_seal`](../crates/rizzy-core/src/server_seal.rs) |
| [§6](CRYPTO.md#6-kdf-parameters) | KDF parameters and the client-enforced floor | [`kdf`](../crates/rizzy-core/src/kdf.rs) |
| [§7](CRYPTO.md#7-secret-key) | Secret Key | [`secret_key`](../crates/rizzy-core/src/secret_key.rs) |
| [§8.1–§8.4](CRYPTO.md#8-item-and-field-encryption) | AEAD, nonces, key commitment, AAD and purposes | [`envelope`](../crates/rizzy-core/src/envelope/mod.rs) |
| [§8.5](CRYPTO.md#85-plaintext-framing-and-padding) | Plaintext framing and padding | [`padding`](../crates/rizzy-core/src/padding.rs) |
| [§9](CRYPTO.md#9-envelope-format) | Envelope format, algorithm registry, parsing rules | [`envelope`](../crates/rizzy-core/src/envelope/mod.rs); HPKE envelopes in [`hpke`](../crates/rizzy-core/src/hpke/mod.rs); signature container in [`sign`](../crates/rizzy-core/src/sign/mod.rs); base64url in [`encoding`](../crates/rizzy-core/src/encoding.rs) |
| [§10.1](CRYPTO.md#101-hpke-key-wrapping) | HPKE key wrapping | [`hpke`](../crates/rizzy-core/src/hpke/mod.rs), [`keys`](../crates/rizzy-core/src/keys/mod.rs) |
| [§10.2–§10.3](CRYPTO.md#102-ed25519-signatures-and-signed-statements) | Signed statements, public key authenticity | [`sign`](../crates/rizzy-core/src/sign/mod.rs) |
| [§11](CRYPTO.md#11-flows) | Flows (signup, login, unlock, rotation, recovery, …) | The M1 building blocks are in `rizzy-core`. The client side of signup, login, unlock (§11.1–§11.4), device sessions (§5.10), the encrypted export (§11.14), and standard and full key rotation with device revocation (§11.6, §11.8, [ADR 0025](adr/0025-rotation-vault-half.md)) is in [`crates/rizzy-client`](../crates/rizzy-client/src/lib.rs) (M1 step 4); password change and recovery (§11.5, §11.9) are not. The server side is in the server (M1 step 3). |
| [§11.14](CRYPTO.md#1114-encrypted-export-m1) | Encrypted export | `rizzy-core` [`export`](../crates/rizzy-core/src/export.rs) (key and envelope); `rizzy-client` [`export`](../crates/rizzy-client/src/export.rs) (JSON file writer and size-capped reader, fuzzed by `client_export`). The payload encoding inside `data` is not defined (no ADR), so the client takes and returns it as opaque bytes |
| [§11.15](CRYPTO.md#1115-totp-m1) | TOTP | [`totp`](../crates/rizzy-core/src/totp.rs) |
| [§12](CRYPTO.md#12-randomness-memory-hygiene-and-side-channels) | Randomness, memory hygiene, side channels | [`rng`](../crates/rizzy-core/src/rng.rs), [`secret`](../crates/rizzy-core/src/secret.rs), [`error`](../crates/rizzy-core/src/error.rs), [`generator`](../crates/rizzy-core/src/generator/mod.rs) |
| [§13](CRYPTO.md#13-post-quantum-readiness) | Post-quantum readiness | No post-quantum algorithm yet; post-1.0 ([ROADMAP §4.3](ROADMAP.md#43-cryptography--authentication-m0m1-audited-in-m8)) |
| [§14](CRYPTO.md#14-what-a-malicious-server-can-still-do) | What a malicious server can still do | – |
| [§15](CRYPTO.md#15-testing) | Testing | [Test vectors](#tests-vectors-and-fuzzing) below |

Symmetric encryption and the envelope are decided in [ADR 0005](adr/0005-symmetric-encryption-aead.md) and [ADR 0007](adr/0007-ciphertext-envelope.md), and the key hierarchy in [ADR 0006](adr/0006-key-hierarchy.md). The `rizzy-core` crate documentation (`cargo doc`, below) has the same module map with finer section numbers.

## Where is X documented?

### Security design

| Topic | Decision | Specification | Code |
|---|---|---|---|
| Authentication (OPAQUE) | [ADR 0003](adr/0003-authentication-opaque.md) | [CRYPTO §5](CRYPTO.md#5-opaque-integration) | [`opaque`](../crates/rizzy-core/src/opaque/mod.rs) |
| Own protocol, not Bitwarden-compatible | [ADR 0002](adr/0002-own-protocol.md) | [CRYPTO §5.10](CRYPTO.md#510-sessions-after-authentication) (sessions, request signing) | Wire protocol not implemented (M1 step 3) |
| Key derivation and the Secret Key | [ADR 0004](adr/0004-key-derivation-argon2id-secret-key.md) | [CRYPTO §6](CRYPTO.md#6-kdf-parameters), [§7](CRYPTO.md#7-secret-key) | [`kdf`](../crates/rizzy-core/src/kdf.rs), [`secret_key`](../crates/rizzy-core/src/secret_key.rs), [`opaque`](../crates/rizzy-core/src/opaque/mod.rs) |
| Envelopes, key wrapping, signatures | [ADR 0005](adr/0005-symmetric-encryption-aead.md), [0006](adr/0006-key-hierarchy.md), [0007](adr/0007-ciphertext-envelope.md) | [CRYPTO §8](CRYPTO.md#8-item-and-field-encryption), [§9](CRYPTO.md#9-envelope-format), [§10](CRYPTO.md#10-asymmetric-cryptography) | [`envelope`](../crates/rizzy-core/src/envelope/mod.rs), [`padding`](../crates/rizzy-core/src/padding.rs), [`hpke`](../crates/rizzy-core/src/hpke/mod.rs), [`sign`](../crates/rizzy-core/src/sign/mod.rs), [`keys`](../crates/rizzy-core/src/keys/mod.rs) |
| Account recovery (Emergency Kit) | [ADR 0008](adr/0008-account-recovery.md) | [CRYPTO §11.9](CRYPTO.md#119-recovery-with-the-emergency-kit) | Recovery code in [`secret_key`](../crates/rizzy-core/src/secret_key.rs); wrap key and auth token in [`keys`](../crates/rizzy-core/src/keys/mod.rs). Flow not implemented. |
| Crypto dependencies, memory hygiene, RNG rules | [ADR 0009](adr/0009-crypto-dependency-policy.md) | [CRYPTO §3](CRYPTO.md#3-primitives), [§12](CRYPTO.md#12-randomness-memory-hygiene-and-side-channels) | [`deny.toml`](../deny.toml), `cargo xtask check-deps` ([`crates/xtask`](../crates/xtask/src/main.rs)), [`secret`](../crates/rizzy-core/src/secret.rs), [`rng`](../crates/rizzy-core/src/rng.rs) |
| Threat model: adversaries, trust boundaries, invariants, accepted risks | – | [THREAT_MODEL.md](THREAT_MODEL.md): [§0](THREAT_MODEL.md#0-the-short-version) short version, [§4](THREAT_MODEL.md#4-adversaries) adversaries, [§5](THREAT_MODEL.md#5-server-controlled-parameter-attacks) server-controlled parameters, [§8](THREAT_MODEL.md#8-security-invariants) invariants, [§9](THREAT_MODEL.md#9-accepted-risks-and-out-of-scope) accepted risks | Invariants are cited as `INV-nn` in code and tests |

### Services, sync and clients

| Topic | Decision | Status and notes |
|---|---|---|
| Server shape and roles (`api`, `web`, `notify`, `worker`, `smtp`, `icons`), deployment profiles | [ADR 0010](adr/0010-server-shape.md) (Accepted) | [`crates/rizzy-server`](../crates/rizzy-server/src/lib.rs) (binary `rizzy-vault`) runs the M1 roles on axum and tokio: `api` serves every `rizzy-proto` message under `/api/v1` and `GET /api/meta` over [`crates/rizzy-domain-auth`](../crates/rizzy-domain-auth/src/lib.rs) and [`crates/rizzy-domain-vault`](../crates/rizzy-domain-vault/src/lib.rs), with body-size limits, bearer tokens and per-request device signatures; `web` serves ADR 0010 §4's fixed page with the INV-49 CSP (the web vault is step 5); `worker` purges expired auth state and runs compaction, as the one active worker per database (on PostgreSQL, a session-level advisory lock on a dedicated connection, [`crates/rizzy-storage`](../crates/rizzy-storage/src/leader_lock.rs); on SQLite, the writer lock). Startup checks, the secrets file, `secrets init`/`rotate`, `backup-secrets`, `migrate`, and `backup`/`restore` with the backup file of [ADR 0023](adr/0023-logical-backup-format.md) are in (a restore into PostgreSQL waits for ADR 0023's instance lock and is refused); core-dump disabling at process start (INV-60, [ADR 0024](adr/0024-core-dump-disabling-rustix.md), also in `rv`) is in; the rootless Podman CI job is not. The image ([`deploy/Containerfile`](../deploy/Containerfile)), the profile A compose file ([`deploy/compose.yaml`](../deploy/compose.yaml), with a Caddy proxy) and the operator guide ([self-hosting.md](self-hosting.md)) are in. The listener has a header-read timeout, a connection cap and a bounded shutdown, and a request that needs a session is refused before its body is read. Tested in-process against SQLite, with an automated backup → wipe → restore drill in its fast form (`tests/drill.rs`; the full ADR 0011 drill with simulated clients waits for `rizzy-client`) (the HTTP end-to-end flow with client-side crypto waits for an owner decision on ADR 0016 test dependencies); fuzzed by `server_headers`, `server_config`, `server_secrets_file`. Per-role threats: [THREAT_MODEL §7](THREAT_MODEL.md#7-stride-per-component). |
| API: own protocol, `/api/v1` request and response types | [ADR 0002](adr/0002-own-protocol.md) (Accepted) | [`crates/rizzy-proto`](../crates/rizzy-proto/src/lib.rs) (M1 step 3): the M1 message types with size limits, the error body and `GET /api/meta`, fuzzed by `proto_json`. No Accepted ADR fixes the endpoint paths or the header carriage of bearer tokens and request signatures: [`crates/rizzy-server`](../crates/rizzy-server/src/lib.rs) holds provisional pre-v1.0 choices, pending owner confirmation, in its `http::api` (paths, methods, status codes) and `http::headers` (header forms) modules. The `openapi` schema derive is not defined yet (see its crate documentation) |
| Storage (SQLite, PostgreSQL, migrations, backups) | [ADR 0011](adr/0011-storage.md) (Accepted), as [ADR 0022](adr/0022-server-mode-only.md) §2 and [ADR 0021](adr/0021-server-compaction.md) §2 amend it | In progress (M1 step 3). [`crates/rizzy-storage`](../crates/rizzy-storage/src/lib.rs) has the pools and PRAGMAs, the transaction types and engine dispatch, the per-account lock, the SQLite writer lock, the embedded migrations with the initial `auth` and `vault` schema, the pre-migration copy, `VACUUM INTO`, the logical dump and restore, the backup file's canonical writer and strict parser of [ADR 0023](adr/0023-logical-backup-format.md) (trailing SHA-256, size limits, a committed known-answer file, fuzzed by `db_backup_parse`) and the restore generation and reconciliation epochs. The PostgreSQL tests run only with `RIZZY_TEST_POSTGRES_URL`; the CI job ADR 0011 point 3 requires is not added yet. |
| Sync engine: op log, HLC, version vectors, merge | [ADR 0012](adr/0012-sync-engine.md) (Accepted) | In progress (M1 step 2). [`crates/rizzy-sync`](../crates/rizzy-sync/src/lib.rs) has the HLC, dots and version vectors, the canonical op and snapshot headers, the record layer (ADR 0018 §3–§5, §10) and the compaction rules (ADR 0021 §2–§4, §9), the merge engine and causal delivery. The server side (upload, Fetch with covers, the compaction job, restore healing) is [`crates/rizzy-domain-vault`](../crates/rizzy-domain-vault/src/lib.rs) (M1 step 3). Server mode is the only sync mode; On-device sync is parked post-1.0 ([ROADMAP §4.6](ROADMAP.md#46-sync-m1-onward)). Sync invariants: [THREAT_MODEL §8.4](THREAT_MODEL.md#84-sync-and-state). |
| Item-record encoding and the M1 item schema | [ADR 0018](adr/0018-item-record-encoding.md) (Accepted) | Schema layer (ADR 0018 §2: item types, field keys and tag keys, values, display rules, item times, list order) in [`item`](../crates/rizzy-core/src/item/mod.rs), with known-answer vectors in `items.json` and the fuzz targets `item_value` and `item_key`. The record layer (op, snapshot and tombstone data in `rizzy-sync`) is not implemented (M1 step 2) |
| Shared Rust client core (wasm, UniFFI) | [ADR 0013](adr/0013-shared-client-core.md) (Accepted) | [`crates/rizzy-client`](../crates/rizzy-client/src/lib.rs) (M1 step 4): sans-I/O flows, the sync driver, item edits and the export reader (fuzzed by `client_export`), tested against an in-memory fake server; the device-state and cache byte layouts are not defined (no ADR), so both stay in memory. `rizzy-wasm` is not implemented (M1 step 5). `rizzy-wasm`'s macro expansion gets a committed, reviewed baseline ([ADR 0019](adr/0019-native-clients.md) §4.1) |
| UI stack for the web platforms | [ADR 0014](adr/0014-ui-stack.md) (Accepted; React) | Not implemented (M1 step 5). With 0010–0014 Accepted, the gate for server and client scaffolding is open ([gates](adr/README.md#gates)) |
| Native desktop and mobile clients, binding crates, client repositories | [ADR 0019](adr/0019-native-clients.md) (Accepted; supersedes [ADR 0015](adr/0015-desktop-tauri.md), Tauri) | Not implemented. macOS in M3; Windows once spike S2 passes, Linux once S3 passes; iOS and Android in M7 ([ROADMAP §4.5](ROADMAP.md#45-design-ui--ux--1password-feel-m3), [§4.10](ROADMAP.md#410-mobile--passkeys-m7)). The apps live in `rizzy-vault-apple`, `-android`, `-windows` and `-linux`; all Rust, the binding crates `rizzy-ffi` and `rizzy-ffi-cpp` included, stays here |
| Command-line client `rv` | [ADR 0013](adr/0013-shared-client-core.md) (Accepted) | [`crates/rizzy-cli`](../crates/rizzy-cli/src/main.rs) is a skeleton (`--help`, `--version`); M1 step 4. Threats: [THREAT_MODEL §7.5](THREAT_MODEL.md#75-cli-rv-m1). |
| Import from other password managers | [ADR 0002](adr/0002-own-protocol.md) (Accepted) point 2 | [`crates/rizzy-import`](../crates/rizzy-import/src/lib.rs) (M1 step 4): Bitwarden JSON (unencrypted), 1Password 1PUX, KeePass XML, generic, Chrome and Firefox CSV, into create ops of the ADR 0018 item schema, with per-entry warnings; its own bounded JSON, CSV, XML, zip and DEFLATE readers into zeroizing buffers; XML DTDs refused. KeePass KDBX and Bitwarden encrypted exports are not read (they need ADR 0009 approval of the other product's crypto). Fuzzed by `import_bitwarden`, `import_1pux`, `import_keepass_xml`, `import_csv`, `import_chrome_csv`, `import_firefox_csv`. Threats: [THREAT_MODEL A16](THREAT_MODEL.md#a16-malicious-import-files-and-shared-content) |

### Code, tooling and process

| Topic | Where |
|---|---|
| Running a server: install, configuration, the secrets file, TLS, upgrades, backup, restore and the restore drill | [self-hosting.md](self-hosting.md) (operator guide); the image and compose files in [`deploy/`](../deploy/) ([ADR 0010](adr/0010-server-shape.md) §4, [ADR 0011](adr/0011-storage.md) "Backups") |
| Workspace layout, crate boundaries, dependency direction | [ADR 0016](adr/0016-workspace-layout.md) (Accepted), with the binding crates in [ADR 0019](adr/0019-native-clients.md) §1.4; enforced by `cargo xtask check-deps` and `cargo xtask check-clippy` ([`crates/xtask`](../crates/xtask/src/main.rs)) |
| Licensing and contribution terms | [ADR 0017](adr/0017-licensing.md) (Accepted); [LICENSE](../LICENSE); license allow-list in [`deny.toml`](../deny.toml) |
| Third-party material in the repository | [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) |
| How decisions are recorded | [ADR 0020](adr/0020-partial-supersession.md) (Accepted; carries [ADR 0001](adr/0001-record-architecture-decisions.md) forward and adds partial supersession); [adr/README.md](adr/README.md) (index, lifecycle, gates); [template](adr/0000-template.md) |
| Scope and milestones | [ROADMAP.md](ROADMAP.md): [§3](ROADMAP.md#3-milestones) milestones, [§4](ROADMAP.md#4-moscow-by-area) MoSCoW, [§6](ROADMAP.md#6-risks--hard-truths) risks |
| Contributing: prerequisites, pre-push gate, lints, documentation rules, workflow | [CONTRIBUTING.md](../CONTRIBUTING.md) |
| Rules for AI coding agents | [CLAUDE.md](../CLAUDE.md) |
| Reporting a vulnerability, supported versions | [SECURITY.md](../SECURITY.md) |
| CI | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) (every PR: the checks, the DCO sign-off check `cargo xtask check-signoff`, the amd64 and arm64 image builds; image publishing is off by default), [`.github/workflows/fuzz.yml`](../.github/workflows/fuzz.yml) (weekly fuzzing) |
| Toolchain, lints, cargo aliases | [`rust-toolchain.toml`](../rust-toolchain.toml), workspace lints in [`Cargo.toml`](../Cargo.toml), [`clippy.toml`](../clippy.toml), [`.cargo/config.toml`](../.cargo/config.toml) (`cargo lint`, `cargo check-wasm`, `cargo xtask`) |

## Tests, vectors and fuzzing

| Topic | Where |
|---|---|
| Testing requirements | [CRYPTO §15](CRYPTO.md#15-testing); [CONTRIBUTING, Testing expectations](../CONTRIBUTING.md#testing-expectations) |
| Known-answer vectors: files, format, how they are made and changed | [crates/rizzy-core/tests/vectors/README.md](../crates/rizzy-core/tests/vectors/README.md) |
| Fuzz targets | [`fuzz/Cargo.toml`](../fuzz/Cargo.toml) (the target list) and [`fuzz/fuzz_targets/`](../fuzz/fuzz_targets/); a separate workspace, run weekly on nightly |
| Sync convergence property tests | Required by [ADR 0012 §12](adr/0012-sync-engine.md#12-testing); not implemented (M1 step 2) |

## Generated code documentation

Every public and private non-test item carries a doc comment; `cargo lint` fails otherwise ([CONTRIBUTING, Documentation](../CONTRIBUTING.md#documentation)). Module documentation explains the logic and cites the specification sections it implements. Build it with:

```sh
cargo doc --workspace --no-deps --open                            # public API
cargo doc --workspace --no-deps --document-private-items --open   # internals too
```

## Not written yet

These documents arrive with the code they describe ([CONTRIBUTING, Documentation](../CONTRIBUTING.md#documentation)):
- user documentation for each client;
- a CHANGELOG, from the first tagged release.
