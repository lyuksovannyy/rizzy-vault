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
| **M0** Foundations | **Deliverables in place, not formally closed.** The workspace, toolchain pin, lints, CI, cargo-deny policy, crypto design, ADRs, and security and contribution policy exist. M0 has no tag or "what we learned" note yet ([ROADMAP §3](docs/ROADMAP.md#3-milestones)), and two of its deliverables are still Proposed: [THREAT_MODEL.md](docs/THREAT_MODEL.md) and [ADR 0017](docs/adr/0017-licensing.md) (licensing). |
| **M1** Core vault (MVP) | **In progress.** Step 1, the `rizzy-core` cryptography, is implemented, with known-answer vectors, property tests and fuzz targets. It has been through an independent review, and every confirmed finding is fixed. The remaining steps, in planned order, are below. |
| **M2–M10** | Not started. |

The remaining M1 steps:

1. **Step 2:** the item schema in `rizzy-core` and the sync engine in `rizzy-sync`, with convergence property tests. The engine follows [ADR 0012](docs/adr/0012-sync-engine.md). The item schema waits for [ADR 0018](docs/adr/0018-item-record-encoding.md), which is Proposed.
2. **Step 3:** the server: API, SQLite storage, OPAQUE and device authentication, op upload and fetch, backup and restore, and the container image with its compose file.
3. **Step 4:** the client core, the `rv` CLI with its encrypted local cache, import, and the encrypted export writer.
4. **Step 5:** the wasm bindings and the React web vault ([ADR 0014](docs/adr/0014-ui-stack.md)).

Server and client scaffolding (steps 3–5) also waits for ADRs 0010–0014 to be Accepted ([ADR gates](docs/adr/README.md#gates)). ADR 0014 is still Proposed.

## Repository layout

```text
crates/rizzy-core     crypto, envelopes, key hierarchy, item models (no I/O, builds for wasm32)
crates/rizzy-sync     sync engine (skeleton; code arrives in M1 step 2)
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

rizzy-vault is licensed under the GNU Affero General Public License, version 3 ([LICENSE](LICENSE)). The crate manifests declare `AGPL-3.0-only`. The final choice between "only" and "or later", and the contribution terms (DCO or CLA), belong to [ADR 0017](docs/adr/0017-licensing.md), which is still Proposed.

## Third-party notices

[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) lists third-party material copied into this repository. Today that is EFF's Long Wordlist (CC BY 4.0), compiled into `rizzy-core` for the passphrase generator. Every artifact that contains `rizzy-core` must show its attribution. Notices for Cargo and npm dependencies will be generated per release artifact ([ADR 0017](docs/adr/0017-licensing.md) §7).
