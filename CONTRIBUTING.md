# Contributing to rizzy-vault

rizzy-vault is in **M0 (Foundations)**. There is no product code yet, only design documents and a Cargo workspace skeleton.

- **Most useful now:** review of [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/CRYPTO.md](docs/CRYPTO.md) and the [ADRs](docs/adr/README.md).
- **Code PRs** in the ADR-first areas (see [ADR first](#adr-first)) are accepted only when an **Accepted** ADR covers them. Until ADRs [0001](docs/adr/0001-record-architecture-decisions.md), [0016](docs/adr/0016-workspace-layout.md) and [0017](docs/adr/0017-licensing.md) are Accepted, only documentation PRs from outside contributors are merged.

Security vulnerabilities are **never** reported in public issues or PRs. See [SECURITY.md](SECURITY.md).

Scope is defined in [docs/ROADMAP.md](docs/ROADMAP.md). A feature that is not there is out of scope until a PR adds it there first.

## Prerequisites

1. **rustup**, from <https://rustup.rs>.
2. **The pinned toolchain.** [`rust-toolchain.toml`](rust-toolchain.toml) pins Rust **1.94.1** with `rustfmt`, `clippy` and the `wasm32-unknown-unknown` target. rustup selects it automatically inside the repository. To install it explicitly, run this in the repository root, which is what CI does:

   ```sh
   rustup toolchain install
   ```

   This form needs rustup 1.28 or later. On older rustup, run `rustup self update` first, or run `rustup show` in the repository root instead.

3. **cargo-deny**, for the supply-chain checks:

   ```sh
   cargo install cargo-deny --locked
   ```

Nothing else is needed today. The JavaScript toolchain for the web vault and extension arrives with [ADR 0014](docs/adr/0014-ui-stack.md).

## Checks to run before every push

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs exactly these, and a PR is not reviewed until they pass:

```sh
cargo fmt --all -- --check
cargo lint                          # alias: clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked     # CI runs this on Linux, macOS and Windows
cargo check-wasm                    # alias: check -p rizzy-core -p rizzy-sync --target wasm32-unknown-unknown --locked
cargo deny check                    # advisories, licenses, bans, sources (deny.toml)
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

Notes:

- `cargo lint` and `cargo check-wasm` are aliases defined in [`.cargo/config.toml`](.cargo/config.toml).
- On Windows PowerShell, set the rustdoc flag with `$env:RUSTDOCFLAGS="-D warnings"` before the last command.
- CI runs cargo-deny with `--all-features`. `deny.toml` sets `[graph] all-features = true`, so a plain `cargo deny check` checks the same graph.
- `cargo deny check` also covers the RustSec advisory checks that `cargo audit` would run.
- `--locked` everywhere means `Cargo.lock` must be committed and up to date. If a check fails with "lock file needs to be updated", run the matching command without `--locked`, review the lockfile diff, and commit it.
- To auto-format: `cargo fmt --all`.

### Lints

The workspace lints in [`Cargo.toml`](Cargo.toml) apply to every crate:

- `unsafe_code = "forbid"`. There is no exception mechanism. `unsafe` is not accepted, in any crate, for any reason.
- `clippy::all` is `deny`.
- `clippy::pedantic`, `unwrap_used`, `expect_used`, `panic`, `print_stdout` and `print_stderr` are `warn`. **`cargo lint` passes `-D warnings`, so every one of them fails CI.**
- `dbg_macro`, `todo` and `unimplemented` are `deny`.
- [`clippy.toml`](clippy.toml) allows `unwrap`, `expect` and printing inside tests.

If a lint is wrong for a specific line, silence it at the narrowest scope, with a reason:

```rust
#[expect(clippy::cast_possible_truncation, reason = "length is bounded by MAX_ITEM_SIZE (u32)")]
```

Do not add blanket `allow`s at crate level.

## Workflow

1. **Before non-trivial work, open or find an issue.** Say which ROADMAP row and which ADR it implements.
2. **Branch from `main`.** Name the branch `type/short-description`, e.g. `docs/threat-model-a13`.
3. **Keep PRs small and about one thing.** A refactor and a behaviour change are two PRs.
4. **The PR description states:**
   - what changed and why;
   - the ROADMAP row and the ADR(s) it relies on;
   - for security-relevant changes, the THREAT_MODEL invariants it affects (see the checklist below);
   - the reason for any change to `deny.toml` or `Cargo.lock` outside a normal dependency bump.
5. **Review.** Every PR needs the owner's review and green CI. PRs are squash-merged. The PR title becomes the commit title, so it follows the commit convention below. The commit body keeps every `Signed-off-by:` and `Co-authored-by:` trailer from the PR's commits; those trailers are the DCO and authorship record ([ADR 0017](docs/adr/0017-licensing.md) Decision 4).
6. **Dependabot.** Dependabot PRs are reviewed like any other PR. They are **never** auto-merged. A PR that touches a crypto crate also follows [ADR 0009](docs/adr/0009-crypto-dependency-policy.md#pinning-and-updates).

### Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/), kept simple:

```text
type(scope): imperative summary, max 72 characters

Why the change is needed, if the summary does not say it.

Signed-off-by: Your Name <you@example.com>
```

- **Types:** `feat`, `fix`, `docs`, `refactor`, `test`, `perf`, `build`, `ci`, `chore`.
- **Scope:** a crate or area, such as `core`, `sync`, `server`, `cli`, `adr`, `docs`, `ci` or `deps`.
- **Breaking changes:** mark them with `!`, e.g. `feat(core)!: ...`. The body says what breaks.
- **Security fixes:** use `fix` and keep the message neutral until the advisory is public. Do not describe the vulnerability in a commit on a public branch before disclosure.

### Sign-off

Contribution terms are decided in [ADR 0017](docs/adr/0017-licensing.md), which is still **Proposed**:

- The recommendation is the Developer Certificate of Origin 1.1. Until the owner decides, sign off every commit with `git commit -s`.
- If the owner picks a CLA instead, you will be asked to sign it before your PR is merged, and signing it also covers your earlier contributions. Earlier contributions from people who do not sign are rewritten.
- Contributions are licensed under the project license, AGPL-3.0 (see ADR 0017 for "only" vs "or later"), inbound = outbound.

## ADR first

**Accepted ADRs come before code** in these areas. **Proposed is not enough.**

- cryptography;
- authentication and protocol;
- persistent formats;
- security boundaries;
- crypto dependencies;
- crate boundaries;
- licensing.

The list and the process are in [docs/adr/README.md](docs/adr/README.md). If your change needs an ADR that is missing or still Proposed:

1. write or update the ADR from the [template](docs/adr/0000-template.md);
2. open it as its own PR;
3. wait for the owner to accept it.

A code PR that gets ahead of its ADR is closed, however good the code is.

## Security-sensitive changes: checklist

Copy the relevant items into the PR description and tick them. A PR is security-sensitive if it touches any of:

- **Cryptography or key handling** (anything in `rizzy-core` crypto modules)
  - [ ] Implements an **Accepted** ADR and matches [CRYPTO.md](docs/CRYPTO.md) byte for byte.
  - [ ] No new construction, no raw AEAD/HKDF/opaque-ke call outside its owning module ([ADR 0009](docs/adr/0009-crypto-dependency-policy.md#our-code)).
  - [ ] Secrets are in zeroizing types, never `Clone`/`Debug`/`Display`/`Serialize`; secret comparisons use `subtle`.
  - [ ] Known-answer vectors added or updated. Changing an existing vector means a version bump and an ADR note.
  - [ ] Randomness is injected (`rand_core::CryptoRng`), never pulled from `getrandom`/`rand` inside `rizzy-core` or `rizzy-sync`.
- **Authentication, sessions, sharing, sync or server-supplied parameters**
  - [ ] Lists the [THREAT_MODEL.md](docs/THREAT_MODEL.md) invariants (INV-xx) the change affects and how each stays true.
  - [ ] Anything the server sends back is authenticated or checked against a client-side floor or allow-list. The client never trusts server-supplied KDF parameters, algorithm ids or public keys.
  - [ ] A negative test with a malicious-server test double, where applicable ([CRYPTO.md §15](docs/CRYPTO.md#15-testing)).
- **Parsing untrusted input** (import files, envelopes, URLs, MIME, share fragments, API requests)
  - [ ] Every input has a size limit, and parsing returns errors, never panics (no `unwrap`, no indexing that can go out of bounds, no unbounded recursion).
  - [ ] A fuzz target exists or is extended for the parser.
- **New dependency**
  - [ ] Justified per [Adding dependencies](#adding-dependencies). For crypto crates, follow the ADR 0009 approval checklist.
- **Logging and errors**
  - [ ] No secrets, plaintext, keys, tokens, master passwords, Secret Keys or recovery codes in logs, error messages or panic messages. Server log fields come from an allow-list.
- **`unsafe`**
  - [ ] None. It is forbidden workspace-wide. A PR that needs it is redesigned.
- **CI, workflows, `deny.toml`, release tooling**
  - [ ] The reason is in the PR description. No new secrets in PR workflows, no `pull_request_target`, and permissions stay `contents: read` unless an ADR says otherwise.

## Testing expectations

- **Unit tests.** Put them next to the code (`#[cfg(test)]`). Every bug fix comes with a regression test that fails without the fix.
- **Integration tests.** Put them in `crates/<crate>/tests/`. They must not need the network or any external service.
- **Determinism.** `rizzy-core` and `rizzy-sync` take randomness and time from the caller. Tests use seeded RNGs and fixed clocks, never the OS RNG or the wall clock.
- **Property tests** (proptest) are required for:
  - the sync engine: random edit, offline and reconnect sequences on N simulated devices must converge ([ROADMAP §6.8](docs/ROADMAP.md#6-risks--hard-truths));
  - envelope round-trips and tamper rejection;
  - every parse/serialise pair.
- **Fuzzing** (cargo-fuzz) is required for every parser of untrusted input:
  - import formats;
  - envelope and signature containers;
  - URL normalisation;
  - MIME (M6);
  - share-link fragments.

  cargo-fuzz needs nightly, so fuzzing runs in a separate job, not in the PR checks ([ADR 0009](docs/adr/0009-crypto-dependency-policy.md), open question 4).
- **Test vectors for crypto:**
  - our own known-answer vectors, committed under `crates/rizzy-core/tests/vectors/`;
  - upstream RFC vectors;
  - Wycheproof, run against our pinned crates.

  The same vectors must pass natively and on wasm32. The full list is in [CRYPTO.md §15](docs/CRYPTO.md#15-testing).
- **Test-only dependencies** (proptest, cargo-fuzz targets) are dev-dependencies and follow the same dependency rules.

## Adding dependencies

Every new dependency is attack surface and a maintenance cost. The PR that adds one explains:

1. **Why:** what it does, and why `std`, an existing dependency or a few lines of our own code are not enough.
2. **Who:** maintainer, activity, downloads, known advisories (RustSec), audit history if it is security-relevant.
3. **What it pulls in:** new transitive crates and duplicate versions (cargo-deny warns on them). Keep `default-features = false` and enable only what is needed.
4. **Portability:** for anything reachable from `rizzy-core` or `rizzy-sync`, `cargo check-wasm` must still pass. These crates do no I/O and never depend on `getrandom` ([ADR 0009](docs/adr/0009-crypto-dependency-policy.md#rng-rules), [ADR 0016](docs/adr/0016-workspace-layout.md)).
5. **Checks:** `cargo deny check` passes, with no new `ignore` entries and no ban exceptions. Changing `deny.toml` is a security decision and needs its own reason.

Rules:

- Dependencies come from crates.io only. `deny.toml` enforces this for registry and git sources. It does not check path dependencies, so a path dependency outside the workspace is rejected in review.
- Declare the version once in `[workspace.dependencies]` in the root `Cargo.toml`, and use `dep.workspace = true` in the crate.
- Commit the `Cargo.lock` change in the same PR.
- **A cryptographic crate** (anything that touches key material, randomness, or encryption, hashing or signature code paths) additionally needs the approval procedure and exact pin from [ADR 0009](docs/adr/0009-crypto-dependency-policy.md#approving-a-new-crypto-crate).
- Licenses must be on the allow-list in [`deny.toml`](deny.toml). The policy behind it is [ADR 0017](docs/adr/0017-licensing.md#5-the-dependency-license-allow-list-is-denytoml).

## AI coding agents

AI-assisted contributions follow the same rules. [CLAUDE.md](CLAUDE.md) states them in the form agents read. The human who opens the PR is responsible for every line in it.

- The human who opens the PR adds the `Signed-off-by` line after reviewing the change (`git commit --amend -s` or `git rebase --signoff`). Agents never add it: the sign-off is a human certification.
- Mark AI assistance with a `Co-Authored-By:` trailer.
