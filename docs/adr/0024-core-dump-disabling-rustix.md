# ADR 0024: Disabling core dumps through rustix

- Status: Accepted
- Date: 2026-09-29
- Deciders: project owner
- Milestone: M1 (server, `rv`) / M3 (desktop bindings) / M7 (mobile bindings)

## Context

[THREAT_MODEL INV-60](../THREAT_MODEL.md#8-security-invariants) requires every native process (all server roles, `rv`, and each native client) to disable core dumps at startup: on Linux `PR_SET_DUMPABLE = 0` and `RLIMIT_CORE = 0`. Release builds use `panic = "abort"`, so a panic raises SIGABRT, and a core dump would write keys and plaintext to disk (in a container, onto the host). INV-60 names rustix 1.1.5's safe wrappers and says adding the crate "goes through ADR 0009". `unsafe_code = forbid` rules out calling `prctl`/`setrlimit` ourselves, and today's `rizzy-vault` does not disable core dumps (`crates/rizzy-server/src/server.rs`, V at 1387df9).

ADR 0009's own route, "Approving a new crypto crate", covers crates that implement a CRYPTO.md construction, and its `## Amendments` section is only for changes the ADR provides for ([ADR 0020](0020-partial-supersession.md) point 4; [docs/adr/README.md](README.md)): its crate table and pins. `rustix` implements no construction and belongs in neither the crypto table nor [CRYPTO.md §3](../CRYPTO.md#3-primitives). Admitting it therefore widens ADR 0009's Decision ([Memory hygiene](0009-crypto-dependency-policy.md#memory-hygiene)), which is a new ADR. This ADR uses ADR 0009's approval checklist anyway, since the crate runs in every process that holds secrets.

## Decision

1. **Admitted:** `rustix` `=1.1.5` in `[workspace.dependencies]`, `default-features = false`, `features = ["process"]` only. `setrlimit`, `getrlimit`, `set_dumpable_behavior` and `dumpable_behavior` need only `process` (V, rustix 1.1.5 `lib.rs`, `process/mod.rs`); `std` is not enabled.
2. **Scope: leaf crates only, never a non-leaf library.** Allowed direct dependents: `rizzy-server` and `rizzy-cli` (M1), and later the binding leaves `rizzy-ffi` and `rizzy-ffi-cpp` ([ADR 0019](0019-native-clients.md) §1.4, §5), which are libraries but leaves. It never enters the closure of `rizzy-core`, `rizzy-sync`, `rizzy-client` or any server library. The implementing PR adds an xtask rule, like the `OPENSSL` rule in `crates/xtask/src/rules.rs`, that fails `cargo xtask check-deps` when any other workspace crate reaches `rustix` directly.
3. **Use, and nothing else:** at process start, before any secret is loaded, `setrlimit(Resource::Core, 0, 0)` on every Unix; on Linux and Android also `set_dumpable_behavior(NotDumpable)`. Each is read back (`getrlimit`, `dumpable_behavior`), and the process refuses to start (the binding leaf: refuses a session handle) on failure. macOS has no dumpable flag, and its crash reports are [AR-28](../THREAT_MODEL.md#9-accepted-risks-and-out-of-scope). Windows has neither call in rustix; its dumps stay AR-28 until M3 confirms a mechanism (U).

**Checklist record ([ADR 0009](0009-crypto-dependency-policy.md#approving-a-new-crypto-crate) items), `rustix` 1.1.5:**

1. **Need.** No construction; INV-60 only.
2. **Provenance.** Bytecode Alliance, `github.com/bytecodealliance/rustix`; 1.1.5 is the newest release on crates.io (V, `cargo search`, 2026-09-29). Cadence, downloads, bus factor: U.
3. **Audit history.** None found (U).
4. **Advisories.** None in the local RustSec advisory-db checkout of 2026-09-29 (V). A 2023 advisory on `fs::Dir` iteration in older majors (U) does not touch `process`.
5. **`unsafe`.** Pervasive by design: raw syscalls and inline assembly in the `linux_raw` backend, `libc` calls elsewhere (V, source). The API we call is safe (V, `process/prctl.rs`, `process/rlimit.rs`).
6. **Constant time.** Not applicable: no secret passes through it.
7. **Builds and hygiene.** License `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`, MSRV 1.65 (V, manifest); all on the `deny.toml` allow-list (V). Dependencies: `bitflags` 2; `linux-raw-sys` 0.12 on Linux (`process` enables its `prctl`); `libc` and `errno` on other Unix; `windows-sys` on Windows (V, manifest). `bitflags`, `libc`, `errno` and `windows-sys` already resolve in `Cargo.lock`; new packages expected are `rustix` and `linux-raw-sys` (U until the implementing PR). Not in any wasm32 closure, so `cargo check-wasm` is unaffected. The implementing PR runs the full gate, `cargo deny check` included, with no `deny.toml` edit.
8. **Test vectors.** None apply. Instead each binary asserts after start that `RLIMIT_CORE` is 0 and, on Linux, that the dumpable flag is off (INV-60's test column).

## Consequences

### Positive
- INV-60 becomes implementable in M1 with no `unsafe` of our own.

### Negative
- A crate with pervasive `unsafe` and inline assembly enters every server and CLI process.

### Risks
- A rustix bug in these two calls could leave dumps enabled; the read-back and refusal to start catch that.
- A future major may move the API; the exact pin and the xtask rule keep changes reviewed.

## Alternatives considered

- **`libc` directly.** Every call is `unsafe`; forbidden.
- **`nix`.** Safe wrappers too, but a larger API and `libc`-only backend; rustix is what INV-60 names.
- **Container or systemd settings only** (`ulimit -c 0`, `LimitCORE=0`). Kept as defence in depth in the operator guide, but they do not cover `rv` or native clients, and nothing in the process checks them.
- **An `## Amendments` entry in ADR 0009.** Not allowed by ADR 0020 point 4 (see Context).

## Open questions for the owner

1. **Does INV-60's "goes through ADR 0009" mean this separate ADR** (the reading taken here), or should ADR 0009 be superseded in part to list non-crypto hygiene crates? Recommendation: this ADR.

## References

- [THREAT_MODEL](../THREAT_MODEL.md) INV-60, AR-28; [CRYPTO.md §12.2](../CRYPTO.md#122-memory-hygiene)
- [ADR 0009](0009-crypto-dependency-policy.md); [ADR 0016](0016-workspace-layout.md) R1–R2; [ADR 0019](0019-native-clients.md) §1.4, §5; [ADR 0020](0020-partial-supersession.md) point 4
