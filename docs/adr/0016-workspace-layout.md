# ADR 0016: Workspace layout and crate boundaries

- Status: Proposed
- Date: 2026-09-25
- Deciders: project owner
- Milestone: M0 (rules and current crates) / M1–M9 (planned crates)

## Context

[ROADMAP §4.1](../ROADMAP.md#41-foundations--project-hygiene-m0), Must, M0, asked for a Cargo workspace with core, sync, domain crates, storage, bus, server and cli. The row now names the crates this ADR defines. The M0 scaffold already exists:
- **Workspace:** resolver 3, edition 2024, `rust-version = "1.94"`, toolchain pinned to 1.94.1 with the `wasm32-unknown-unknown` target.
- **Workspace lints:** `unsafe_code = "forbid"`, `clippy::all = "deny"`, `clippy::pedantic = "warn"`; `unwrap`, `expect`, `panic` and print macros warn.
- **Aliases:** `cargo lint` (clippy, deny warnings) and `cargo check-wasm` (checks `rizzy-core` and `rizzy-sync` for wasm32).
- **CI:** rustfmt, clippy, tests on Linux, macOS and Windows, the wasm check, rustdoc with warnings denied, and cargo-deny.

The boundaries are security boundaries, not tidiness:
- **`rizzy-core` and `rizzy-sync` do no I/O and build for wasm32** ([INV-58](../THREAT_MODEL.md#8-security-invariants), [CRYPTO.md §12.1](../CRYPTO.md#121-randomness), the RNG rules in [ADR 0009](0009-crypto-dependency-policy.md)).
- **`smtp` and `icons` have no route to the database** ([THREAT_MODEL](../THREAT_MODEL.md#13-security-goals) G-11, INV-44, INV-51; [ADR 0010](0010-server-shape.md)).
- **Each domain owns its tables** ([ADR 0011](0011-storage.md)).

Two dependency facts shape the rules (V unless marked):
- **opaque-ke 4.0.1**, which `rizzy-core` needs for OPAQUE ([ADR 0003](0003-authentication-opaque.md)), depends on `rand = { version = "0.8", default-features = false }` non-optionally (its `Cargo.toml`). With default features off, `rand` 0.8 pulls no getrandom.
- **Server-side third-party crates pull getrandom themselves.** In the M0 server lockfile, sqlx-postgres 0.9.0 → rand 0.10.3 → getrandom 0.4.3, and mail-auth 0.13.3 depends on getrandom 0.2 and 0.4 and on hickory-resolver → rand 0.10.

A rule that CI does not check erodes. This ADR states each rule and the check that enforces it.

## Decision

### 1. Naming

- Every crate is named `rizzy-<name>`. No crate is called plain `core`, `sync`, `storage` and so on. The directory name equals the crate name: `crates/rizzy-core`.
- **Why the prefix.** `core` is a built-in crate. A dependency named `core` enters the extern prelude and shadows it. Paths like `::core::fmt`, which derive macros and standard macros expand to, would then resolve to our crate and break the build. The prefix removes that whole class of collisions (`core`, `alloc`, `std`, `test`, `proc_macro`). It also keeps names unambiguous in `Cargo.lock`, in cargo-deny output and in compiler errors.

### 2. Current crates (M0)

| Crate | Kind | Purpose | wasm32, no I/O | Internal dependencies |
|---|---|---|---|---|
| `rizzy-core` | lib | Crypto, envelopes, key hierarchy, item models ([CRYPTO.md](../CRYPTO.md)) | yes | – |
| `rizzy-sync` | lib | Op log, HLC, version vectors, merge ([ADR 0012](0012-sync-engine.md)) | yes | `rizzy-core` |
| `rizzy-server` | bin `rizzy-vault` | Server binary; role wiring ([ADR 0010](0010-server-shape.md)) | no | – |
| `rizzy-cli` | bin `rv` | Command-line client | no | `rizzy-core` |

### 3. Planned crates

Each crate is created only when it gets real code (§6). The milestone column says when it first exists.

| Crate | Kind | From | Purpose | May depend on (internal) | wasm32, no I/O |
|---|---|---|---|---|---|
| `rizzy-proto` | lib | M1 | `/api/v1` request and response types ([ADR 0002](0002-own-protocol.md)); serde. The schema derive for the OpenAPI file sits behind a non-default `openapi` feature that only `xtask` enables, so it never ships in a client or the wasm bundle | – | yes |
| `rizzy-import` | lib | M1 | Importers ([ADR 0002](0002-own-protocol.md)); fuzz targets | core | yes |
| `rizzy-client` | lib | M1 | Sans-I/O client flows, sync driver, cache policy ([ADR 0013](0013-shared-client-core.md)) | core, sync, proto, import, match | yes |
| `rizzy-wasm` | lib (cdylib) | M1 | wasm-bindgen bindings over `rizzy-client`. A leaf: the only crate that enables getrandom's `wasm_js` | client | runs only on wasm32, but must also compile (not run) for the host (below); a leaf |
| `rizzy-storage` | lib | M1 | sqlx pools, migrations, per-account lock, backup and restore ([ADR 0011](0011-storage.md)) | – | no |
| `rizzy-bus` | lib | M1 | Typed domain events. In-process from M1; PostgreSQL `LISTEN/NOTIFY` backend in M3 | – | no |
| `rizzy-domain-auth` | lib | M1 | OPAQUE server side, sessions, 2FA, devices, key bundles, account state, short-lived auth state ([ADR 0010](0010-server-shape.md) §5) | core, proto, storage, bus | no |
| `rizzy-domain-vault` | lib | M1 | Server-mode op records and retained headers, snapshots, cursors | sync, proto, storage, bus | no |
| `rizzy-match` | lib | M2 | URL normalisation, PSL (the `psl` crate), signed equivalence lists | core | yes |
| `rizzy-icon-proxy` | lib | M3 | Favicon fetch, SSRF guard, re-encoding, cache | proto | no |
| `rizzy-desktop` | bin | M3 | Tauri shell, in `apps/desktop/src-tauri` ([ADR 0015](0015-desktop-tauri.md)) | client | no; a leaf |
| `rizzy-domain-relay` | lib | M4 | Relay batches, ack sets, TTL, pairing sessions | sync, proto, storage, bus | no |
| `rizzy-domain-share` | lib | M5 | Share envelopes, token hashes, expiry, view counts | proto, storage, bus | no |
| `rizzy-domain-mail` | lib | M6 | Aliases, mailbox envelopes, retention, internal ingress endpoints | proto, storage, bus | no |
| `rizzy-smtp-ingress` | lib | M6 | SMTP listener, MIME limits, rspamd client, HPKE sealing, hand-off to `api` | core, proto | no |
| `rizzy-ffi` | lib | M7 | UniFFI bindings over `rizzy-client` | client | no; a leaf |
| `rizzy-domain-org` | lib | M9 | Organisations and members; policies in M10 | core, proto, storage, bus | no |
| `xtask` | bin | M1 | Repository checks (§5). Never shipped | – | no |

Notes:
- **Four crates were not in the ROADMAP's original list:** `rizzy-proto`, `rizzy-client`, `rizzy-import` and `rizzy-match`. They keep wire types, client flows, importers and URL matching shared across platforms, and keep them out of `rizzy-core`'s audit scope.
- **`rizzy-sync` is shared, but only clients merge.** The server uses its header and version-vector types for sequence checks and compaction bookkeeping. It never decrypts or merges.
- **What the binaries depend on.** `rizzy-server` depends on the domain crates, `rizzy-storage`, `rizzy-bus`, `rizzy-smtp-ingress` and `rizzy-icon-proxy`. `rizzy-cli` moves from `rizzy-core` to `rizzy-client` in M1.
- **`rizzy-wasm` on the host.** CI runs `cargo lint`, `cargo test --workspace` and `cargo doc --workspace` for the host on three OSes, and those build every member. So `rizzy-wasm` must compile, though not run, on host targets. Code that only works on wasm32 sits behind `cfg(target_arch = "wasm32")`. wasm-bindgen 0.2.129 compiles for the host (checked in M0).
- **`rizzy-proto` and OpenAPI.** [ADR 0002](0002-own-protocol.md) generates a checked-in OpenAPI 3.1 file from `rizzy-proto`'s types. That needs a schema-derive crate on those types. Behind the `openapi` feature it stays out of every client build and the wasm bundle, while `xtask` enables it to regenerate and check the file. That crate is on `rizzy-proto`'s R1 allow-list, marked as feature-gated.

### 4. Dependency rules

| Rule | Statement |
|---|---|
| **R1** No I/O | `rizzy-core`, `rizzy-sync`, `rizzy-proto`, `rizzy-client`, `rizzy-import` and `rizzy-match` use no network, filesystem, clock, environment, process or thread APIs. They do not depend on tokio, sqlx or any HTTP client. Randomness and time are injected. They build for `wasm32-unknown-unknown`. **Randomness crates:** no direct dependency on `rand` or getrandom. `rand` 0.8 with `default-features = false` is allowed only as a transitive dependency of opaque-ke. getrandom never appears in these crates' dependency closure, for any target ([ADR 0009](0009-crypto-dependency-policy.md)). |
| **R2** OS access and randomness | (a) The R1 crates never touch the OS, and never have getrandom in their closure. (b) Server-side libraries (`rizzy-storage`, `rizzy-bus`, `rizzy-domain-*`, `rizzy-icon-proxy`, `rizzy-smtp-ingress`) may do I/O, and may pull getrandom in through third-party dependencies (Context). No first-party library depends on getrandom directly; libraries take an injected RNG. (c) Only the leaf crates depend on getrandom directly: `rizzy-server`, `rizzy-cli`, `rizzy-desktop`, `rizzy-wasm` and `rizzy-ffi` (plus `xtask`). Only `rizzy-wasm` enables `wasm_js`. |
| **R3** Isolated ingress | `rizzy-smtp-ingress` and `rizzy-icon-proxy` do not depend, directly or transitively, on `rizzy-storage`, sqlx, any `rizzy-domain-*` crate or `rizzy-bus`. `rizzy-icon-proxy` also does not depend on `rizzy-core`, because it handles no keys. |
| **R4** Domains are separate | No `rizzy-domain-*` crate depends on another. A domain that needs something from another defines a trait for it. `rizzy-server` implements the trait by wiring in the other domain's public API, or the domains exchange `rizzy-bus` events. Each domain queries only its own tables ([ADR 0011](0011-storage.md)). |
| **R5** Who holds what | Only `rizzy-storage` and the `rizzy-domain-*` crates depend on sqlx. Only `rizzy-server` depends on the domain crates, `rizzy-smtp-ingress` and `rizzy-icon-proxy`. |
| **R6** Client and server are separate | Client-side crates (`rizzy-client`, `rizzy-import`, `rizzy-match`, `rizzy-wasm`, `rizzy-ffi`, `rizzy-cli`, `rizzy-desktop`) never depend on server-side crates (`rizzy-storage`, `rizzy-bus`, `rizzy-domain-*`, `rizzy-smtp-ingress`, `rizzy-icon-proxy`, `rizzy-server`), and the reverse holds too. The shared crates are `rizzy-core`, `rizzy-sync` and `rizzy-proto`. |
| **R7** Lints | Every crate sets `[lints] workspace = true`, including `unsafe_code = "forbid"`. There is no exception, and the binding crates do not need one: generated wasm-bindgen and UniFFI glue compiles under `forbid` ([ADR 0013](0013-shared-client-core.md), Risks). If an exception is ever needed, it takes a new ADR. The crate then copies the whole workspace lint table, with only `unsafe_code` changed, instead of `workspace = true`. That is the only mechanism that works: Cargo rejects local overrides next to `workspace = true`, and in-source attributes cannot lower a command-line `forbid` (both checked on 1.94.1). `xtask` compares the copy with the workspace table. |
| **R8** Manifest | Every crate inherits `publish`, `license` and `rust-version` from the workspace ([ADR 0017](0017-licensing.md)). |

- **Dev-dependencies.**
  - R3, R5 and R6 forbid their edges for dev-dependencies too. A test-only edge still grows helpers in the wrong crate, and cargo-deny reports dev edges anyway (§5).
  - One exception: `rizzy-server` may dev-depend on `rizzy-client`. End-to-end tests of real flows against the real server need both, such as INV-1's request-capture test.
  - R1's allow-list covers normal and build dependencies only, so tests may use proptest and a seeded test RNG.
- **Known conflict ahead.** The passkey-rs crates (M7) depend on getrandom 0.2 non-optionally (fact sheet, V). They cannot enter an R1 crate as they are. The M7 passkey ADR resolves this before they are added.

### 5. How CI enforces each rule

| Rule | Check | Status |
|---|---|---|
| R1, build side | `cargo check-wasm`. The alias is extended to each no-I/O crate in the PR that creates it, and to `rizzy-wasm`. A binding-generator upgrade that brings in `unsafe` or breaks the wasm build then fails in its own PR. | exists, for core and sync |
| R1, API side | A `clippy.toml` in each no-I/O crate, with the lists below | M1 |
| R1, R2, R3, R5, R6 | `cargo xtask check-deps`, below. It runs in the clippy job | M1, with the first new crate |
| R3, R5, second layer | cargo-deny `[bans]` entries with `wrappers`, below | M1 |
| R4, tables | `cargo xtask check-tables` ([ADR 0011](0011-storage.md)) | M1 |
| R7, R8 | `cargo xtask check-deps` also reads each manifest: `lints.workspace = true` (or, for a crate with an accepted exception, a lint table identical to the workspace's except `unsafe_code`), `publish` and `license` inherited | M1 |
| Server image | Linux only: `pnpm install --frozen-lockfile` and `pnpm build` for `apps/web`, then `cargo build --locked -p rizzy-server --features embed-web`, the container image build, and the rootless Podman smoke test on high ports ([ADR 0010](0010-server-shape.md) §4). The only job that needs the JavaScript toolchain for the server | M1 |
| Existing | `cargo fmt --check`, `cargo lint`, `cargo test --workspace --locked` on three OSes, rustdoc with `-D warnings`, `cargo deny check` | exists |

**R1, API side: the clippy lists.** `wasm32-unknown-unknown` compiles `std::fs` and `std::net` and fails only at run time, so `check-wasm` alone does not prove "no I/O".
- **Entries must name items, not modules.** Clippy 1.94.1 rejects a module path such as `std::fs` or `std::net` with the config warning "expected a function, found a module" and then flags nothing from it: `std::fs::read_to_string` and `std::net::TcpStream::connect` pass. Item paths are flagged (checked in M0).
- `disallowed-types`:
  - `std::fs::{File, OpenOptions, DirBuilder, ReadDir}`
  - `std::net::{TcpStream, TcpListener, UdpSocket}`
  - `std::process::{Command, Child}`
  - `std::thread::Builder`
- `disallowed-methods`:
  - the `std::fs` free functions: `read`, `read_to_string`, `write`, `read_dir`, `create_dir`, `create_dir_all`, `remove_file`, `remove_dir`, `remove_dir_all`, `rename`, `copy`, `metadata`
  - `std::net::ToSocketAddrs::to_socket_addrs`
  - `std::env::{var, var_os, vars, args, current_dir, temp_dir}`
  - `std::process::exit`
  - `std::thread::spawn`
  - `std::time::SystemTime::now`, `std::time::Instant::now`
- **A crate-level `clippy.toml` replaces the root one; it does not merge with it** (checked with clippy 1.94.1: the root file's `std::env::var` ban did not apply in a crate that had its own file). So each such file repeats the root settings.
- `xtask` checks that the files match, and fails when clippy's output contains "found a module".

**`cargo xtask check-deps`.**
- It reads `cargo metadata --format-version 1 --all-features --locked` and walks the resolved graph.
- It applies a rules table:
  - **Forbidden edges** (R3, R5, R6), checked transitively over normal, build and dev dependencies, with R6's one named exception.
  - **An allow-list of external crates for the R1 crates,** over normal and build dependencies. `rand` 0.8 appears on it only as a dependency of opaque-ke, and only with default features off.
  - **getrandom:** never in an R1 crate's closure; never a direct dependency of a first-party library; `wasm_js` only in `rizzy-wasm`.
- **Features for the getrandom rule.** `cargo metadata` reports features unified across the whole workspace (U, confirm in M1). The getrandom rule is therefore evaluated per R1 crate, with the features cargo resolves when that crate is built alone for wasm32, e.g. `cargo tree -p <crate> --target wasm32-unknown-unknown -e normal,build`. Otherwise a server crate that turns on `rand`'s `std` feature would put getrandom into every crate that uses `rand` 0.8.

**cargo-deny, second layer.** `[bans]` entries with `wrappers`, for example:
- `sqlx` with wrappers = `rizzy-storage` and the domain crates;
- `rizzy-storage` with wrappers = the domain crates and `rizzy-server`;
- each domain crate with wrappers = `rizzy-server`.

`wrappers` restricts only direct dependents, but chaining the entries covers transitive paths, because every path must pass through an allowed wrapper. cargo-deny applies these entries to workspace path crates (checked with cargo-deny 0.20.2, V). A path crate that is not a listed wrapper and depends on a banned path crate is reported as `error[banned]` plus an `unmatched-wrapper` warning, and that includes a dev-dependency edge. That is why R3, R5 and R6 cover dev-dependencies too, so the two layers agree. `xtask` stays the authoritative check.

`xtask` lives in `crates/xtask`, so the existing `crates/*` members glob picks it up, and it runs through a `cargo xtask` alias added in M1. It needs no new external tools. It parses the `cargo metadata` JSON with serde_json and stays small, on the order of a few hundred lines.

### 6. No placeholder crates

A crate is created in the PR that adds its first real code, with tests. There are no empty crates "for later":
- they cost CI time;
- they invite code into the wrong place;
- they make the layout look more finished than it is.

Until a crate exists, the table in §3 is the map. The same rule applies to `apps/` and `packages/` ([ADR 0014](0014-ui-stack.md)).

### 7. Repository layout

```
crates/     Rust workspace members: libraries, rizzy-server, rizzy-cli, xtask
apps/       user-facing apps (ADR 0014): web, extension, desktop (its src-tauri/ joins
            the Cargo workspace in M3), share (M5), android and ios (M7)
packages/   shared TypeScript packages: core, ui, i18n, config
docs/       ROADMAP, THREAT_MODEL, CRYPTO, adr/
deploy/     Containerfile, compose.yaml per profile, Quadlet units (M1/M3; ADR 0010)
fuzz/       cargo-fuzz targets. Its own workspace on the nightly toolchain, outside the
            main workspace (ADR 0009, open question 4)
```

In M3, the workspace `members` list gains `apps/desktop/src-tauri`. `fuzz/` stays excluded.

## Consequences

### Positive

- The two security-critical boundaries, no I/O in the shared core and no DB route from ingress, are machine-checked on every PR.
- Splitting a role out of the server later ([ADR 0010](0010-server-shape.md)) is mechanical, because the crate graph already isolates it.
- The audit scope for M8 is visible from the crate graph.
- No empty crates: the layout on disk always matches reality.

### Negative

- More crates mean more manifests and longer cold builds, and each boundary needs a trait or an event where a direct call would be shorter.
- `xtask` is code we maintain. Its rules table has to be updated whenever a crate is added.
- Per-crate `clippy.toml` files duplicate the root settings. `xtask` checks they stay in sync, but it is still duplication.
- The R1 API-side lists name items one by one. A new I/O function in `std` is not covered until someone adds it.
- R1 carries one named exception, `rand` 0.8 under opaque-ke, which the allow-list has to encode exactly.

### Risks

- The dependency rules can be bypassed by moving code into a shared crate (for example, putting SQL helpers in `rizzy-proto`). The external-crate allow-list for no-I/O crates is what catches it. Review must treat changes to the rules table as security changes, like `deny.toml`.
- A future opaque-ke release could turn on `rand` features that pull getrandom. The per-crate getrandom check fails in that upgrade's PR.
- The Tauri crate brings GUI system dependencies into workspace CI ([ADR 0015](0015-desktop-tauri.md), open question 3).

## Alternatives considered

- **One crate with modules.** The compiler cannot enforce "no I/O" or "no storage" between modules. The wasm build would pull in server dependencies unless we used feature flags, and feature unification makes those fragile.
- **Fewer, larger crates** (one `rizzy-server-lib` with every domain). Domain isolation could not be checked with `cargo metadata`, and table ownership would rest on review alone.
- **Separate repositories per component.** A protocol change that touches server and clients becomes a multi-repo change, and there is no shared lockfile or single cargo-deny run.
- **Enforcement by review only.** It works until the first busy week.
- **cargo-deny `wrappers` alone.** It covers direct edges between named crates, path crates included. It cannot express "no I/O APIs", "only allow-listed external crates" or the getrandom rules.
- **A third-party architecture-lint tool.** One more dependency and one more tool to trust, for what a few hundred lines of `xtask` do.
- **"getrandom only in leaf crates", read literally.** It fails on the first server library, because sqlx-postgres and mail-auth pull getrandom themselves (Context). R2 restricts what we control: direct dependencies of first-party crates, and the R1 closures.

## Open questions for the owner

1. **Accept the four crates that were not in the ROADMAP's original list** (`rizzy-proto`, `rizzy-client`, `rizzy-import`, `rizzy-match`). *Recommendation:* yes.
2. **Name the domain crates `rizzy-domain-*`** rather than `rizzy-auth`, `rizzy-vault` and so on. *Recommendation:* `rizzy-domain-*`. The prefix makes the rules in §4 easy to express, and `rizzy-vault` is already the server binary's name.
3. **An `xtask` binary, or a test in a dedicated crate, for the graph checks?** *Recommendation:* `xtask`. It runs as its own CI step with a clear error message, and `cargo test` stays about product code.
4. **Dev-dependencies under R3, R5 and R6, with the single exception `rizzy-server` → `rizzy-client`.** The alternative is a separate test-only crate that depends on both sides. *Recommendation:* the exception. It is one edge, and it never reaches a shipped binary.

[CLAUDE.md](../../CLAUDE.md) and [ADR 0009](0009-crypto-dependency-policy.md)'s RNG rules use R1 and R2's wording: only leaf crates depend on getrandom *directly*, server-side libraries may pull it in transitively, and it never appears in an R1 crate's closure.

## References

- [ROADMAP](../ROADMAP.md) §4.1, §5
- [THREAT_MODEL](../THREAT_MODEL.md) G-11, INV-1, INV-44, INV-51, INV-57, INV-58
- [CRYPTO.md §12.1](../CRYPTO.md#121-randomness)
- [ADR 0002](0002-own-protocol.md), [ADR 0003](0003-authentication-opaque.md), [ADR 0009](0009-crypto-dependency-policy.md), [ADR 0010](0010-server-shape.md), [ADR 0011](0011-storage.md), [ADR 0012](0012-sync-engine.md), [ADR 0013](0013-shared-client-core.md), [ADR 0014](0014-ui-stack.md), [ADR 0015](0015-desktop-tauri.md), [ADR 0017](0017-licensing.md)
- The workspace `Cargo.toml`, `.cargo/config.toml` (aliases), `.github/workflows/ci.yml`, `deny.toml`, and the crate contracts in `crates/rizzy-core/src/lib.rs` and `crates/rizzy-sync/src/lib.rs`
- getrandom README: enable the wasm backend only in the final crate (V, fact sheet)
- M0 checks on 1.94.1 and cargo-deny 0.20.2 in scratch crates (V): opaque-ke 4.0.1 `Cargo.toml` (`rand` 0.8 non-optional); the fact-sheet server lockfile (sqlx-postgres and mail-auth → getrandom); clippy `disallowed-*` module paths versus item paths, and `clippy.toml` precedence; cargo-deny `wrappers` on path crates, including dev edges; Cargo's lint-override rejection and E0453; wasm-bindgen 0.2.129 on the host
