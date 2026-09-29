# rizzy-vault

A self-hostable, end-to-end encrypted, zero-knowledge password manager written in Rust.

> **Pre-alpha. Do not store real secrets in it.** There is no release, and nothing has had an external security audit. v1.0 (end of M8) requires one ([SECURITY.md](SECURITY.md)).

## What it is

rizzy-vault borrows from three existing products ([ROADMAP §1](docs/ROADMAP.md#1-what-we-are-building-one-paragraph)). From Bitwarden and Vaultwarden it takes the zero-knowledge vault, the self-hosted single-binary server and sync, the org and collection model, and open source, but not their wire protocol or legacy crypto: it is not a Bitwarden-API-compatible server. From 1Password it takes the visual polish, Watchtower-style health checks, item sharing by link and the Secret Key idea, as inspiration only, never a clone. From AliasVault it takes one-click alias identities with a built-in receive-only mailbox, encrypted at ingress with the user's public key; mail is an optional module, not the core. The target users, in order: personal use, then enthusiasts and families, then small and medium businesses.

## Security model

- **End-to-end encrypted, zero knowledge.** Clients encrypt every item under a key hierarchy (account key, vault keys, item keys) in a versioned, key-committing envelope. The server stores ciphertext and metadata. It never sees a master password, a password-equivalent, the Secret Key or any key that decrypts vault data.
- **OPAQUE login and a mandatory Secret Key.** Login uses OPAQUE (RFC 9807) with Argon2id as its key-stretching function, so no password-equivalent ever reaches the server. Every account also has a 128-bit Secret Key, kept on the user's devices and in the Emergency Kit and mixed into the password input. A stolen database, even with the server's OPAQUE secrets, gives nothing to brute-force offline.
- **Signed ops and signed account state.** Each device has Ed25519 keys certified by the account's identity key. Ops, snapshots, key grants, the device set and the account state are signed statements. With context-bound AAD and client-side allow-lists, this means the server cannot forge or swap data, move ciphertext between contexts, downgrade algorithms or KDF parameters, or substitute the account's own keys and devices undetected. Any device that has seen the newer state detects a rollback or a fork. Other users' public keys (sharing, M9) are trusted on first use: a server that substitutes one at first contact wins unless the users compare fingerprints out of band ([THREAT_MODEL §5.4](docs/THREAT_MODEL.md#54-public-key-substitution), accepted risk AR-6).
- **Limits, stated plainly.** The web vault is only as trustworthy as the server that serves it. Malware on an unlocked device wins. The server sees metadata, and it can delete or withhold data.

Details: [threat model](docs/THREAT_MODEL.md) (start with [§0](docs/THREAT_MODEL.md#0-the-short-version)) and [cryptographic design](docs/CRYPTO.md) (what a malicious server can still do: [§14](docs/CRYPTO.md#14-what-a-malicious-server-can-still-do)).

## Status

Scope and milestones are defined in [docs/ROADMAP.md](docs/ROADMAP.md#3-milestones). No milestone has a tagged release yet.

| Milestone | State |
|---|---|
| **M0** Foundations | **Deliverables in place, not formally closed.** The workspace, toolchain pin, lints, CI, cargo-deny policy, crypto design, ADRs, and security and contribution policy exist. M0 has no tag or "what we learned" note yet ([ROADMAP §3](docs/ROADMAP.md#3-milestones)). [ADR 0017](docs/adr/0017-licensing.md) (licensing) was Accepted on 2026-09-27; its App Store permission text and CI sign-off check are not done yet. [THREAT_MODEL.md](docs/THREAT_MODEL.md) became normative on 2026-09-27. |
| **M1** Core vault (MVP) | **In progress.** Step 1, the `rizzy-core` cryptography, is implemented, with known-answer vectors, property tests and fuzz targets. It has been through an independent review, and every confirmed finding is fixed. The remaining steps, in planned order, are below. |
| **M2–M10** | Not started. M4 is removed: Server mode is the only sync mode, and On-device sync is parked post-1.0 ([ROADMAP §3](docs/ROADMAP.md#3-milestones)). |

The remaining M1 steps. Every ADR is Accepted (2026-09-27; see the [index](docs/adr/README.md#index)), with its "On acceptance" edits made. Step 2 is in progress.

1. **Step 2:** the item schema in `rizzy-core` ([ADR 0018](docs/adr/0018-item-record-encoding.md)) and the sync engine in `rizzy-sync` ([ADR 0012](docs/adr/0012-sync-engine.md) and ADR 0018: HLC, version vectors, op log, merge, tombstones, the evidence merge), with convergence property tests seeded from the merge spike ([`spikes/merge-model`](spikes/merge-model/README.md)), and the caller of the durable-certificate expiry rule ([CRYPTO.md §10.2](docs/CRYPTO.md#102-ed25519-signatures-and-signed-statements)).
2. **Step 3:** the server (ADRs 0010, 0011 and [0021](docs/adr/0021-server-compaction.md), which is Accepted before any step 3 code): API, SQLite storage, OPAQUE and device authentication with request signing, op upload and fetch with compaction and restore healing, backup and restore (the backup reader refuses a `data` field over `MAX_DATA_FIELD_LEN` before decoding, [CRYPTO.md §11.14](docs/CRYPTO.md#1114-encrypted-export-m1)), and the container image with its compose file and operator docs.
3. **Step 4:** the client core, the `rv` CLI with its encrypted local cache, import, and the encrypted export writer and reader (which caps the whole file before JSON parsing) with its fuzz target.
4. **Step 5:** the wasm bindings and the React web vault ([ADR 0014](docs/adr/0014-ui-stack.md)). The `unsafe` that wasm-bindgen generates is audited third-party code, with a committed, reviewed expansion baseline and an xtask `unsafe` token scan over our own source ([ADR 0019](docs/adr/0019-native-clients.md) §4.1, owner decision 7).

ADRs 0010–0014 are Accepted, so the gate for server and client scaffolding (steps 3–5) is open ([ADR gates](docs/adr/README.md#gates)). No fuzz target has run in CI yet: after the first push of this work, run `.github/workflows/fuzz.yml` once by hand (`workflow_dispatch`).

## Repository layout

```text
crates/rizzy-core     crypto, envelopes, key hierarchy, item models (no I/O, builds for wasm32)
crates/rizzy-sync     sync engine (skeleton; code arrives in M1 step 2)
crates/rizzy-proto    /api/v1 request and response types, serde (no I/O, builds for wasm32)
crates/rizzy-storage  server storage: sqlx pools, migrations, account lock, backup and restore
crates/rizzy-bus      in-process domain events for the server (ids only; M1 step 3)
crates/rizzy-domain-auth  server auth domain: OPAQUE, sessions, devices, signed state, 2FA, recovery
crates/rizzy-domain-vault  server vault domain: op and snapshot upload, Fetch, compaction, restore healing
crates/rizzy-server   server binary `rizzy-vault` (skeleton: --help and --version only)
crates/rizzy-cli      command-line client `rv` (skeleton: --help and --version only)
crates/xtask          repository checks: `cargo xtask check-deps`, `cargo xtask check-clippy`
docs/                 roadmap, threat model, crypto design, ADRs; index in docs/README.md
fuzz/                 cargo-fuzz targets; its own workspace, run on nightly
```

`xtask` and `fuzz/` are never shipped. Crate boundaries and the dependency direction (core ← sync ← leaf crates) are set by [ADR 0016](docs/adr/0016-workspace-layout.md).

## Building and checking

Prerequisites are in [CONTRIBUTING.md](CONTRIBUTING.md#prerequisites): rustup and cargo-deny. rustup picks up the pinned toolchain from [`rust-toolchain.toml`](rust-toolchain.toml) automatically. Then:

```sh
cargo build --workspace
cargo test --workspace
```

Before every push, run the full gate in [CONTRIBUTING.md](CONTRIBUTING.md#checks-to-run-before-every-push). CI runs exactly that list, and a PR is not reviewed until it passes.

## Documentation

- **[docs/README.md](docs/README.md)** is the index: where each topic (encryption, authentication, sync, server roles, clients, tooling, process) is documented, and which code implements it.
- **Code documentation:** every public and private non-test item carries a doc comment, and `cargo lint` enforces it. To build and open them:

  ```sh
  cargo doc --workspace --no-deps --open
  cargo doc --workspace --no-deps --document-private-items --open   # internals too
  ```

  The `rizzy-core` crate page maps each module to the [CRYPTO.md](docs/CRYPTO.md) sections it implements.
- **Decisions** are Architecture Decision Records in [docs/adr/](docs/adr/README.md). Only Accepted ADRs are binding.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) first. Code in the ADR-first areas (cryptography, authentication and protocol, persistent formats, security boundaries, crypto dependencies, crate boundaries, licensing) needs an Accepted ADR before it is merged. AI coding agents also follow [CLAUDE.md](CLAUDE.md).

## Reporting a vulnerability

Never report a vulnerability in a public issue, pull request or discussion. Follow [SECURITY.md](SECURITY.md) and use GitHub's private vulnerability reporting.

## License

rizzy-vault is licensed under the GNU Affero General Public License, version 3 only (`AGPL-3.0-only`; [LICENSE](LICENSE)), as [ADR 0017](docs/adr/0017-licensing.md) decides. Contributions come in under the same license, with a Developer Certificate of Origin 1.1 sign-off ([CONTRIBUTING.md](CONTRIBUTING.md#sign-off)). Copyright the rizzy-vault contributors; see the git history.

## Third-party notices

[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) lists third-party material copied into this repository. Today that is EFF's Long Wordlist (CC BY 4.0), compiled into `rizzy-core` for the passphrase generator. Every artifact that contains `rizzy-core` must show its attribution. Notices for Cargo and npm dependencies will be generated per release artifact ([ADR 0017](docs/adr/0017-licensing.md) §7).
