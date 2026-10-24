# Contributing to rizzy-vault

rizzy-vault is at **M0 done, M1 in progress**, with M2 (browser extension and matching) under way too. M1 step 1, the `rizzy-core` cryptography, is implemented. Steps 2–5 (item schema and sync engine, server, client core and `rv` CLI, wasm bindings and web vault) all have code landed; none is formally closed. The [README](README.md#status) has the details.

- **Most useful now:** review of [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/CRYPTO.md](docs/CRYPTO.md) and the [ADRs](docs/adr/README.md).
- **Code PRs** in the ADR-first areas (see [ADR first](#adr-first)) are accepted only when an **Accepted** ADR covers them. ADRs [0020](docs/adr/0020-partial-supersession.md) (which carries ADR 0001 forward), [0016](docs/adr/0016-workspace-layout.md) and [0017](docs/adr/0017-licensing.md) (licensing and contribution terms) are Accepted. Until ADR 0017's App Store permission (Decision 3) is committed, only documentation PRs from outside contributors are merged.

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

4. **Node.js 24 or later and pnpm**, for the web vault, its packages and the browser extension ([ADR 0014](docs/adr/0014-ui-stack.md)). Node's own corepack picks up the pinned pnpm version from `package.json`'s `packageManager` field:

   ```sh
   corepack enable
   ```

   `cargo xtask build-wasm` also needs `wasm-bindgen-cli` installed at the exact version `Cargo.lock` pins for `wasm-bindgen` (see the `web` job in [ci.yml](.github/workflows/ci.yml) for the install command).

5. **OpenSSL headers and pkg-config.** `rizzy-domain-auth` uses `webauthn-rs` for security keys as a second factor, which builds `openssl-sys` against the system OpenSSL ([ADR 0077](docs/adr/0077-webauthn-rs-integration-fixes.md) §8; our own code never names OpenSSL, and TLS stays rustls). On Debian and Ubuntu: `sudo apt-get install libssl-dev pkg-config`; on Fedora: `sudo dnf install openssl-devel pkgconf`; on macOS: `brew install openssl@3` and `export OPENSSL_DIR=$(brew --prefix openssl@3)`; on Windows: an OpenSSL installation named by `OPENSSL_DIR`. Without pkg-config, `OPENSSL_INCLUDE_DIR` and `OPENSSL_LIB_DIR` work too (for example `/usr/include` and `/usr/lib/x86_64-linux-gnu`). The container image links OpenSSL statically (`deploy/Containerfile`).

## Checks to run before every push

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs each of these as its own job, and a PR is not reviewed until they pass. This is also the list CLAUDE.md gives AI coding agents as "Before any push":

```sh
cargo fmt --all -- --check
cargo lint                          # alias: clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked     # CI runs this on Linux, macOS and Windows
cargo check-wasm                    # alias: check -p rizzy-core -p rizzy-sync -p rizzy-proto -p rizzy-client -p rizzy-import -p rizzy-wasm -p rizzy-match --target wasm32-unknown-unknown --locked
cargo deny check                    # advisories, licenses, bans, sources (deny.toml)
cargo xtask check-deps              # crate-boundary and dependency rules (ADR 0016 §5, R1–R8; ADR 0009 feature sets, crypto crates with default-features = false); no unsafe keyword in first-party .rs files (ADR 0019 §4.1)
cargo xtask check-clippy            # clippy.toml entries clippy ignores ("found a module", ADR 0016 §5)
cargo xtask generate-tokens --check # every declared design-token pair meets WCAG AA contrast in both themes (no pair may ask for less than 3:1); the motion tokens stay within their limits (nothing over 5 s, docs/design/README.md §7); the generated CSS and native-toolkit token files (Swift, Kotlin, XAML, QML) match packages/ui/tokens/tokens.json (ADR 0014 §5, ADR 0019 §13)
cargo xtask check-tables            # not in CI yet: every table name after FROM/JOIN/INTO/UPDATE/TABLE/REFERENCES in the domain crates' queries/ and the migrations carries its owner's prefix (auth_, vault_), apart from the one foreign key to auth_accounts (id) ON DELETE CASCADE (ADR 0011 points 5–7, ADR 0016 R4); storage_ tables and backup queries are not checked yet
cargo xtask check-spdx              # every first-party .rs/.ts/.tsx/.js/.mjs/.sh/.css/.html file starts with the SPDX header (ADR 0017 Decision 6); `--fix` inserts or corrects it
cargo check --manifest-path fuzz/Cargo.toml --locked --bins               # fuzz targets still build
cargo deny --manifest-path fuzz/Cargo.toml check                          # fuzz/Cargo.lock
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo xtask check-signoff origin/main..HEAD                                # every commit signed off by its author (ADR 0017 §4)
```

CI also runs two more jobs that the list above does not cover, for the web vault and browser-extension-facing code (ADR 0013 §4, ADR 0014; ci.yml jobs `web` and `bindings-baseline`):

```sh
cargo xtask build-wasm                                     # needs wasm-bindgen-cli at the exact version Cargo.lock pins
pnpm install --frozen-lockfile
cargo xtask check-js                                        # exact versions, pinned pnpm, empty install-script allow-list, deny.toml licences, pnpm audit
pnpm run lint
pnpm run build
cargo xtask check-manifest                                  # not in CI yet: built extension manifests (Chromium, Firefox) against INV-40, ADR 0036 §4/§5, ADR 0040: no externally_connectable, allow-listed permissions/host_permissions/web_accessible_resources, all_frames: false, extension-pages CSP
cargo build --locked -p rizzy-server --bin rizzy-vault     # so the end-to-end test below has a server binary
pnpm run test
pnpm run e2e                                                 # Playwright against rizzy-vault built with embed-web, including the accessibility audit (e2e/a11y.spec.ts) and the keyboard-only walk (e2e/keyboard-nav.spec.ts)
pnpm --filter @rizzy-vault/extension exec playwright test e2e/a11y.spec.ts   # the extension's accessibility audit only (popup, options page, inline menu); the rest of its Playwright suite is not in CI yet
cargo xtask expand-bindings                                 # regenerates crates/rizzy-wasm/generated/; CI fails on any diff from the committed baseline (ADR 0019 §4.1)
```

`cargo xtask check-manifest` is not yet a CI job: [`docs/HANDOFF.md`](docs/HANDOFF.md) lists wiring it (and `check-tables`) into `.github/workflows/` as blocked on the owner. Run it locally, right after `pnpm run build`, until that's wired.

### What the accessibility checks cover

ROADMAP §4.5 asks for keyboard-only use, screen-reader labels and WCAG AA contrast; ADR 0014 §5
sets the checks. The automated ones:

- **Token contrast** (`cargo xtask generate-tokens --check`, `crates/xtask/src/tokens.rs`): the
  WCAG contrast ratio of every token pair `tokens.json` declares for text and controls, in both
  themes, at 4.5:1 for text or 3:1 for large text and UI components; below AA fails. It covers the
  declared pairs only.
- **Rendered pages** (`apps/web/e2e/a11y.ts`, `apps/extension/e2e/a11y.ts`): axe-core's WCAG
  2.0/2.1/2.2 A and AA rules and its best-practice rules on every screen and dialog of the web
  vault and on the extension's popup, options page and inline menu, plus Chromium's own
  accessibility tree (every focusable element exposed and named) and a Tab/Shift+Tab focus trap
  check on every modal dialog. The web vault is also audited in the dark theme, under forced
  colours (Windows High Contrast emulation) and at phone width.
- **Keyboard only** (`apps/web/e2e/keyboard-nav.spec.ts`): every audited web vault screen reached
  with Tab and operated with Enter, Space, Escape, the arrow keys or typing.

What they do not cover: real screen readers (NVDA, JAWS, VoiceOver, TalkBack, Orca) — automated
rules catch missing names, labels and structure, not whether the result is pleasant to use, so a
UI change still needs a manual pass with one; Firefox (the Playwright suites run Chromium only);
keyboard use of the extension (the popup and inline menu are audited, not walked by keyboard);
undeclared token pairs; and the native clients. This repository's share of "native
toolkits" is the generated token files under `packages/ui/tokens/generated/` staying in sync
with the checked source; each native app's own contrast, high-contrast/increased-contrast mode and
screen-reader checks live in that app's repository (ADR 0019 §6), set by its own ADR (ADR 0014
§5).

CI also builds the server image, [`deploy/Containerfile`](deploy/Containerfile), for `linux/amd64` and `linux/arm64` on every PR, each natively on its own runner. It pushes nothing. Locally: `docker build -f deploy/Containerfile .` (or `podman build`).

Notes:

- `cargo xtask check-signoff <base>..<head>` fails when any commit in the range lacks a `Signed-off-by:` trailer with its author's exact name and email (the email ignores case). Merge commits are checked too, so update a branch by rebasing. CI runs it on the PR's commits (`base.sha..head.sha`). On each push to `main` CI runs `cargo xtask check-signoff --squash <before>..<after>` instead: GitHub writes the squash commit, with the merger as author and the PR's `Signed-off-by:` lines in its body, so that mode only requires each pushed commit to keep at least one well-formed `Signed-off-by:` line anywhere in its message. See [Sign-off](#sign-off).
- `cargo xtask check-spdx` covers the files ADR 0017 Decision 6 names — Rust, TypeScript/JavaScript, shell, CSS and HTML templates — listed with `git ls-files`, the same way `check-deps` does, minus `.claude/`, `.github/` and `crates/rizzy-wasm/generated/`. It does not cover `Cargo.toml` or other TOML/JSON/YAML config: Decision 6 does not name them, and a manifest's license is already `license.workspace = true`. `--fix` inserts a header line (plus a blank line, so a `//!` module doc's first paragraph never shares a line with it) or corrects a wrong one in place, and is idempotent. This check is not yet wired into CI (`.github/workflows/ci.yml`); that is a separate ask for the owner.
- `cargo lint`, `cargo check-wasm` and `cargo xtask` are aliases defined in [`.cargo/config.toml`](.cargo/config.toml). `cargo xtask` runs the workspace's `xtask` crate.
- `fuzz/` is its own workspace with its own `Cargo.lock` (ADR 0016 §7), so the workspace commands do not see it. A change to `rizzy-core`'s dependencies refreshes `fuzz/Cargo.lock` in the same change. `libfuzzer-sys` is `(MIT OR Apache-2.0) AND NCSA`. `deny.toml` allows NCSA for that crate alone, because it is reachable only from `fuzz/`, which never ships. Running the fuzz targets needs nightly and `cargo-fuzz`; CI does that in a weekly job ([`.github/workflows/fuzz.yml`](.github/workflows/fuzz.yml)) that never blocks a PR.
- On Windows PowerShell, set the rustdoc flag with `$env:RUSTDOCFLAGS="-D warnings"` before the last command.
- CI runs cargo-deny with `--all-features`. `deny.toml` sets `[graph] all-features = true`, so a plain `cargo deny check` checks the same graph.
- `cargo deny check` also covers the RustSec advisory checks that `cargo audit` would run.
- `--locked` everywhere means `Cargo.lock` must be committed and up to date. If a check fails with "lock file needs to be updated", run the matching command without `--locked`, review the lockfile diff, and commit it.
- To auto-format: `cargo fmt --all`.

### Lints

The workspace lints in [`Cargo.toml`](Cargo.toml) apply to every crate:

- `unsafe_code = "forbid"`. `unsafe` is not accepted in our code, in any crate, for any reason, and `cargo xtask check-deps` rejects the `unsafe` keyword in first-party `.rs` files. The one accepted case is `unsafe` that an admitted binding generator emits into generated glue, audited as third-party code ([ADR 0019](docs/adr/0019-native-clients.md) §4.1).
- `clippy::all` is `deny`.
- `clippy::pedantic`, `unwrap_used`, `expect_used`, `panic`, `print_stdout` and `print_stderr` are `warn`. **`cargo lint` passes `-D warnings`, so every one of them fails CI.**
- `dbg_macro`, `todo` and `unimplemented` are `deny`.
- [`clippy.toml`](clippy.toml) allows `unwrap`, `expect` and printing inside tests.
- `rizzy-core` also raises `clippy::indexing_slicing` and `clippy::unreachable` to `warn` with a crate-level `#![warn]` in `src/lib.rs`: ADR 0016 R7 rules out per-crate `[lints]` tables, and raising a level in source is allowed. Non-test code uses `.get()`, `split_at_checked` or iterators instead of `[]`, or justifies a provably safe index with a narrow `#[expect(clippy::indexing_slicing, reason = "...")]`; test modules carry one reasoned `#[expect]` each.
- `missing_docs` (workspace lint table) and `clippy::missing_docs_in_private_items` (raised with `#![cfg_attr(not(test), warn(...))]` in each crate root) are `warn`, so every undocumented public or private non-test item fails `cargo lint`; see [Documentation](#documentation).

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

Contribution terms are set by [ADR 0017](docs/adr/0017-licensing.md) Decision 4:

- Sign off every commit with `git commit -s`. The `Signed-off-by:` line certifies the Developer Certificate of Origin 1.1 for that commit. There is no CLA.
- The sign-off must name the commit's author: the same name and email as the author line (`git commit -s` uses `user.name` and `user.email`, which is what the author line has unless you set it otherwise). A sign-off by someone else, such as a maintainer who amended the commit, does not replace the author's own. CI's `DCO sign-off` job (`cargo xtask check-signoff`) fails the PR otherwise. To fix it: `git commit --amend -s` for the last commit, or `git rebase --signoff origin/main` for all of them, then force-push.
- Contributions are licensed under the project license, `AGPL-3.0-only`, inbound = outbound.

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
  - [ ] None in our source: `forbid` workspace-wide, and `cargo xtask check-deps` rejects the `unsafe` keyword in first-party `.rs` files. A PR that needs it is redesigned. A generator or toolchain bump shows the reviewed diff of generated `unsafe` counts (ADR 0019 §4.1).
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

## Documentation

A change is not done until its documentation is. [docs/README.md](docs/README.md) is the index of where each topic is documented. The rules:

- **Every item is documented.** Every public and private item outside test code has a doc comment: modules, types, traits, fields, variants, functions, methods, constants and statics. `missing_docs` and `clippy::missing_docs_in_private_items` enforce this under `cargo lint` (see [Lints](#lints)). Clippy's pedantic group also requires an `# Errors` section on every public function that returns a `Result`, and a `# Panics` section on any that can panic. The rustdoc step of the gate fails on broken intra-doc links in the public documentation.
- **Module docs explain the logic.** A module's `//!` comment says what the module does, which rules it enforces and why, and which specification sections it implements. Cite them by number: `CRYPTO.md §8.3`, `ADR 0012 §4`, `INV-12`. Link the specification instead of restating it. Where the code resolves an ambiguous point of the specification, the comment says so and cites the section.
- **Normative documents change with the behaviour.** A change to behaviour that [CRYPTO.md](docs/CRYPTO.md), [THREAT_MODEL.md](docs/THREAT_MODEL.md), an ADR or [ROADMAP.md](docs/ROADMAP.md) describes updates that document in the same change. The limits still apply: an Accepted ADR changes only as its [lifecycle](docs/adr/README.md#lifecycle) allows, and otherwise through a new ADR ([ADR first](#adr-first)); a scope change is a ROADMAP edit the owner approves.
- **Descriptive documents stay current.** The README files, this file, the [vector README](crates/rizzy-core/tests/vectors/README.md) and the crate docs change in the same change as the code they describe. A new document, ADR or crate is added to [docs/README.md](docs/README.md), a new crate also to the layout in [README.md](README.md#repository-layout), and a new ADR also to the index in [docs/adr/README.md](docs/adr/README.md).
- **The server ships with operator documentation.** When the server lands (M1 step 3), the same change documents self-hosting, the compose files for Docker and Podman, configuration, and backup and restore. The backup and restore procedure is tested, not just written ([ROADMAP §4.9](docs/ROADMAP.md#49-server-self-hosting--ops-m1-onward)).
- **Clients ship with user documentation.** Each client (`rv`, the web vault, the extensions, and later the desktop and mobile apps) ships with user documentation in the change that makes it usable.
- **A CHANGELOG starts with the first tagged release.** From then on, every PR with a user-visible or security-relevant change adds an entry to `CHANGELOG.md`. Security fixes keep neutral wording until the advisory is public, as in [commit messages](#commit-messages).

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

## Equivalence list contributions

The global equivalence list ([ADR 0038](docs/adr/0038-equivalent-domain-list.md)) is data
every client trusts for autofill, so adding or changing a group has its own path on top of the
general [workflow](#workflow) above:

1. **Propose the group as a GitHub issue first**, from the
   [`equivalence-group`](.github/ISSUE_TEMPLATE/equivalence-group.yml) issue template, under
   [ADR 0038 §4](docs/adr/0038-equivalent-domain-list.md#4-review-rules-for-list-entries)'s
   rules. What it needs:
   - **evidence of shared ownership** for every domain, and separately for every ccTLD
     pairing (`brand.com` and `brand.co.uk` each need their own proof, not an assumption from
     the base domain): a shared WHOIS registrant/organisation, or a public
     cross-referencing statement on both domains (a `security.txt`, a support article).
     "Looks plausible next to a big brand" is not proof;
   - whether any domain is third-party-hostable, and the Public Suffix List entry that
     splits it by registrant if so (`third_party_hostable = 1` in
     `data/equivalence/groups.txt` is the explicit, reviewed exception, never silently
     assumed);
   - a note of the next scheduled re-check (at minimum every release cycle).

   The project owner creates an `equivalence-list` label in the repository's Settings →
   Labels; the template applies it automatically once that label exists, and it is the
   review queue for both the issue and the PR that follows.
2. **Open the PR** that edits [`data/equivalence/groups.txt`](data/equivalence/groups.txt)
   once the issue's evidence stands up to review, using the
   [`equivalence-list`](.github/PULL_REQUEST_TEMPLATE/equivalence-list.md) pull request
   template and linking the issue, following
   [docs/equivalence-list.md §2](docs/equivalence-list.md#2-editing-the-source-file).
3. **An entry without ownership proof, or without proof for every ccTLD variant, is
   rejected.** A domain a scheduled re-check finds lapsed is removed, not kept on the benefit
   of the doubt (ADR 0038 §4, points 1, 4 and 5).
4. **Review is the owner's own act; so is signing and shipping a new list version.** With
   one maintainer, the owner reviews the PR and records the evidence cited in it; the
   two-maintainer rule in [ADR 0038 §4](docs/adr/0038-equivalent-domain-list.md#4-review-rules-for-list-entries)
   becomes real review the moment a second maintainer exists. No community PR ships a signed
   list on its own: merging a PR only changes the human-editable
   `data/equivalence/groups.txt`. Separately, and only the owner does this
   ([docs/equivalence-list.md](docs/equivalence-list.md)), the reviewed source is signed
   offline with a dedicated Ed25519 keypair kept apart from every release-signing credential
   (ADR 0038 §3), under a `list_version` strictly greater than every version published
   before it (clients reject an equal or lower version, ADR 0038 §2). The signed
   bytes and the pinned public key are then committed together into
   `crates/rizzy-match/src/compiled.rs`'s `GLOBAL_LIST` and `LIST_SIGNING_PUBLIC_KEY`, so a
   new or updated list always ships inside a client release — there is no out-of-band list
   update in M2.

## AI coding agents

AI-assisted contributions follow the same rules. [CLAUDE.md](CLAUDE.md) states them in the form agents read. The human who opens the PR is responsible for every line in it.

- The human who opens the PR adds the `Signed-off-by` line after reviewing the change (`git commit --amend -s` or `git rebase --signoff`). Agents never add it: the sign-off is a human certification.
- Mark AI assistance with a `Co-Authored-By:` trailer.
