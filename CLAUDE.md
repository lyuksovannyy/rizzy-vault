# CLAUDE.md: rules for AI coding agents

rizzy-vault is a self-hostable, end-to-end encrypted, zero-knowledge password manager in Rust. A mistake here leaks people's passwords. Follow these rules exactly. If a rule blocks the task, stop and ask the owner; do not work around it.

## Before you start

0. If [docs/HANDOFF.md](docs/HANDOFF.md) exists, read it first: it holds the current state and next steps from the previous session.
1. Read [docs/ROADMAP.md](docs/ROADMAP.md). It is the source of truth for scope and milestones.
   - Find the row your task implements.
   - If there is no row, the task is out of scope. Ask.
2. Read [docs/adr/README.md](docs/adr/README.md), then every ADR your task touches. For security work, also read the relevant parts of [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and [docs/CRYPTO.md](docs/CRYPTO.md).
3. Check the ADR's **Status** line. Only `Accepted` is binding.
   - As of 2026-09-25, ADRs 0001–0013, 0015 and 0016 are Accepted; 0014 (UI stack: React chosen, the rest open) and 0017 are Proposed.
4. Do not recreate `docs/ARCHITECTURE.md`. It was deliberately removed; do not link to it either.

## The ADR gate (hard stop)

- **Code only with an Accepted ADR.** Never implement cryptography, authentication, protocol or wire formats, persistent formats (envelope, op log, export, cache), security boundaries, crate boundaries or licensing changes without one.
- **Proposed is not enough.** If the ADR is Proposed or missing, stop and ask the owner. You may draft or update a Proposed ADR from [0000-template.md](docs/adr/0000-template.md), as a separate change, if asked.
- **Never change an ADR's Status.** Setting or changing `Accepted`, `Rejected` or `Superseded` is the owner's act alone ([ADR 0001](docs/adr/0001-record-architecture-decisions.md) points 3-4). Never edit the Context, Decision or Consequences of an Accepted ADR. A change to an Accepted decision is a new ADR with `Status: Proposed`. Any ADR you draft is `Status: Proposed` and gets a row in [docs/adr/README.md](docs/adr/README.md) in the same change.
- **No home-made crypto.** No new constructions, no "simple" custom schemes, no parameter changes below the floors in CRYPTO.md. The server's word is never trusted for KDF parameters, algorithm ids or public keys.
- **When they disagree:** an Accepted ADR wins over CRYPTO.md and THREAT_MODEL.md on a *mechanism*. Fix the doc in the same change. A conflict about a *goal or invariant* means stop and ask.

## Crate boundaries

The rules are set by [ADR 0016](docs/adr/0016-workspace-layout.md), Accepted on 2026-09-25. Read it before touching crate boundaries. In short, for the current crates:

- **`rizzy-core`:** crypto, envelopes, item models.
  - No I/O: no filesystem, network, clock or OS randomness.
  - Randomness and time are injected (`rand_core::CryptoRng`).
  - Must build for `wasm32-unknown-unknown`.
- **`rizzy-sync`:** the sync engine. It depends on `rizzy-core` only and follows the same no-I/O and wasm rules. Everything the server uses from it is ciphertext only. The field merge, however, receives decrypted field writes from `rizzy-client` as opaque bytes in zeroizing types, so `rizzy-sync` is in the plaintext audit scope ([ADR 0012](docs/adr/0012-sync-engine.md) §13 and owner decision 6, accepted 2026-09-25).
- **`rizzy-server`** (binary `rizzy-vault`) and **`rizzy-cli`** (binary `rv`) are leaf crates. Nothing depends on them.
- Dependencies point one way: core ← sync ← leaves. Never the reverse.
- Only leaf crates depend on `getrandom` directly. It never appears in the dependency closure of `rizzy-core` or `rizzy-sync`, and only the wasm bindings crate enables `wasm_js` ([ADR 0009](docs/adr/0009-crypto-dependency-policy.md#rng-rules), [ADR 0016](docs/adr/0016-workspace-layout.md) R1–R2).
- Adding, splitting or merging crates needs an ADR 0016 change first.

## Code rules

- `unsafe` is forbidden in every crate. No exceptions, no workarounds through FFI crates.
- No `unwrap`, `expect`, `panic!`, `todo!`, `dbg!` or `println!` in non-test code. Return errors.
- **Never log secrets.** That covers plaintext, keys, master passwords, Secret Keys, recovery codes, tokens and decrypted fields. It applies to logs, error messages, panic messages and `Debug` output. Secret types zeroize on drop and redact `Debug`.
- Untrusted input (imports, envelopes, URLs, MIME, API bodies) is size-limited and parsed without panics. Add a fuzz target.
- Crypto changes need known-answer vectors ([CRYPTO.md §15](docs/CRYPTO.md#15-testing)). The sync engine needs property tests for convergence.
- Silence a lint only with `#[expect(lint, reason = "...")]` at the narrowest scope.

## Dependencies

- **Justify every new crate:** what it does, why it is needed, its maintainer, its advisories, its transitive dependencies.
- **Run `cargo deny check`** before proposing a new crate. It must pass with no new `ignore`, ban exception or license addition.
- **Crypto crates** follow the approval checklist and exact pins in [ADR 0009](docs/adr/0009-crypto-dependency-policy.md).
- **Where versions go:** declared in `[workspace.dependencies]`, crates.io only, `default-features = false` where possible.
- **Do not modify** `deny.toml`, `rust-toolchain.toml`, `.github/workflows/`, `.cargo/config.toml` or `.claude/` unless the task explicitly asks for it.

## Before any push (all must pass)

```sh
cargo fmt --all -- --check
cargo lint
cargo test --workspace --locked
cargo check-wasm
cargo deny check
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

## Process

- **Commits:** Conventional Commits (`feat(core): ...`), see [CONTRIBUTING.md](CONTRIBUTING.md).
- **Never add `Signed-off-by` yourself.** No `git commit -s`, no `--signoff`. The sign-off is the DCO certification ([ADR 0017](docs/adr/0017-licensing.md) Decision 4), and only a human can make it. The human adds it after reviewing the change (`git commit --amend -s` or `git rebase --signoff`). Mark AI assistance with a `Co-Authored-By:` trailer.
- **Commit and push only when asked.** Never push to `main`.
- **Keep ROADMAP.md authoritative.** A change in scope is a ROADMAP edit the owner approves, not something an ADR or the code decides.
- **Report honestly.** State what you verified and what you did not. Mark unverified facts about crates, audits and standards as unverified.
