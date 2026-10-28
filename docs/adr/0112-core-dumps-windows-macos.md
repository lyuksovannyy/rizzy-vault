# ADR 0112: Core dumps and crash reports for `rv` on Windows and macOS: a panic-exit hook on every OS, `RLIMIT_CORE` on macOS, no Win32 call, and accepted risk AR-31

- Status: Accepted
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M1 (`rv`, `crates/rizzy-cli`)
- Supersedes: on acceptance, in part: [ADR 0024](0024-core-dump-disabling-rustix.md) (Decision point 3, its last two sentences). §6 gives the replacement text ([ADR 0020](0020-partial-supersession.md) point 9).

## Context

**Trigger.** On 2026-10-25 a ten-reviewer gap review of every ADR was committed ([docs/reviews/2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md); raw findings in [2026-10-25-raw/](../reviews/2026-10-25-raw/)). The same day the owner told the team to "start" fixing the gaps. This ADR answers theme **S6**: "Core dumps: `rv` on Windows disables nothing, against INV-60; AR-28 covers only native apps, and the macOS mechanism is unconfirmed." It covers raw finding **G03-8** [major]. Route: "erratum/residual + code".

**The finding** (G03-8, quoted): "INV-60 says every native process, `rv` included, disables core dumps at startup, and `rv` is supported on Windows today (docs/rv.md lists `%LOCALAPPDATA%\rizzy-vault`), but on Windows it does nothing and reports success. AR-28 covers only "a native client" (M3/M7), so the M1 `rv` on Windows (WER, LocalDumps) is neither mitigated nor an accepted risk. For macOS, which ships in M3, the crash-report opt-out is still "mechanism to confirm in M3, U" (INV-60), and no ADR has confirmed it. INV-60's "Verified by" has no Windows or macOS test." Suggested resolution: "Choose the Windows mechanism (for example `WerAddExcludedApplication` / `SetErrorMode` through a vetted safe wrapper, or an explicit accepted risk) and the macOS one."

**What the binding text says today** (all V, read in this worktree at `f3492b2`):

- [ADR 0024](0024-core-dump-disabling-rustix.md) Decision 3: "at process start, before any secret is loaded, `setrlimit(Resource::Core, 0, 0)` on every Unix; on Linux and Android also `set_dumpable_behavior(NotDumpable)`. [...] macOS has no dumpable flag, and its crash reports are [AR-28]. Windows has neither call in rustix; its dumps stay AR-28 until M3 confirms a mechanism (U)."
- [THREAT_MODEL](../THREAT_MODEL.md#8-security-invariants) INV-60: "Every native process (all server roles, `rv`, and each native client's host executable and AutoFill extensions) disables core dumps at startup. [...] On macOS and Windows: opt out of local dumps and crash-report upload where the platform allows it (mechanism to confirm in M3, U)." Its "Verified by" column: "Each binary asserts its own dumpable flag and core limit after start."
- [THREAT_MODEL](../THREAT_MODEL.md#9-accepted-risks-and-out-of-scope) AR-28: "OS crash capture that a native client cannot fully disable [...] iOS and macOS: system crash reports and Xcode Organizer. Windows: Windows Error Reporting, LocalDumps and Partner Center crash data. With `panic = "abort"`, every core panic becomes such a crash." Milestone: "M3 (desktop) and M7 (mobile), when each mechanism is confirmed". `rv` is not a native client in this sense, so AR-28 does not cover it.
- THREAT_MODEL §7.5 (CLI `rv`), row I: "Core dumps of the unlocked process" is a threat; the mitigation column says "Core dumps disabled at startup."
- [docs/rv.md](../rv.md) lines 19–20 list state directories for macOS (`~/Library/Application Support/rizzy-vault`) and Windows (`%LOCALAPPDATA%\rizzy-vault`); CI's `test` job runs on `[ubuntu-latest, macos-latest, windows-latest]` (`.github/workflows/ci.yml` line 65).

**What the code does** (V, `crates/rizzy-cli/src/coredump.rs`):

- `#[cfg(unix)] disable()` (lines 97–112): `rustix::process::setrlimit(Resource::Core, {0, 0})`, on Linux and Android also `set_dumpable_behavior(NotDumpable)`, then `check()` reads both back. `cfg(unix)` includes macOS, so **on macOS `RLIMIT_CORE = 0` (soft and hard) is already set and read back**. rustix 1.1.5's `setrlimit`, `getrlimit` and `Resource::Core` are not gated off on Apple targets (V, `src/process/rlimit.rs` and `src/backend/libc/process/types.rs` in the registry copy: `Core` is `cfg(not(target_os = "haiku"))` only). The unit test `limits_are_in_effect_after_disable` is `#[cfg(unix)]` and so runs on the macOS CI runner (V, by `cfg` and the CI matrix; that it passes there is U: no CI run was inspected).
- `#[cfg(not(unix))] disable()` (lines 152–155): `Ok(())`. On Windows nothing is called and `rv` starts as if dumps were off.
- `crates/rizzy-cli/src/lib.rs` lines 90–94: `disable()` runs first in `main`; on error `rv` prints `rv: {e}` and exits 1. No panic hook is installed anywhere in the workspace (V, grep for `set_hook` and `take_hook` over `crates/`: no hit). Release builds use `panic = "abort"` (V, `Cargo.toml` line 252).
- `rustix` is already a dependency of `rizzy-cli` (V, `crates/rizzy-cli/Cargo.toml` line 65). `windows-sys` 0.61.2 is already in `Cargo.lock`, pulled on Windows by rustix, mio, errno and others (V, `cargo tree -i windows-sys@0.61.2 --target x86_64-pc-windows-msvc`).

**The constraint.** `unsafe` is forbidden in every crate, with "no workarounds through FFI crates" ([CLAUDE.md](../../CLAUDE.md), Code rules). Every Windows mechanism the review names is a Win32 function: `SetErrorMode` (kernel32); `WerAddExcludedApplication`, `WerSetFlags`, `WerRegisterExcludedMemoryBlock` (wer.dll). `windows-sys` exposes them only as `unsafe` `extern` declarations (L), and the `windows` crate generates `unsafe fn` wrappers for Win32 APIs (L). A crates.io search on 2026-10-25 (`cargo search`) for `SetErrorMode`, `WerAddExcludedApplication` and `wer-sys` returned no crate that wraps any of them (V for those three queries; that no safe wrapper exists anywhere is U). The macOS crash reporter (ReportCrash) is reached through Mach exception ports (`task_set_exception_ports`), for which no safe wrapper is known either (U).

**What the mechanisms would buy even if we could call them** (each L or U: Microsoft and Apple documentation as remembered, not re-read for this ADR):

- `SetErrorMode(SEM_NOGPFAULTERRORBOX)` suppresses the WER fault dialog; it is not documented to stop report collection or LocalDumps (L). Rust's `std::process::abort`, which `panic = "abort"` reaches, is implemented on Windows with `__fastfail` (L), and `__fastfail` bypasses exception handlers and the error mode and goes straight to WER (L). So for panics, the main crash source in `rv`, `SetErrorMode` would do nothing.
- `WerAddExcludedApplication` writes a persistent per-user (or, with `bAllUsers`, machine-wide) registry exclusion keyed by executable name (L). It outlives `rv`, changes the user's system without asking, matches any other program named `rv.exe` (L), and whether it suppresses LocalDumps, which an administrator configures under `HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps`, is U.
- LocalDumps, Task Manager's "Create dump file", ProcDump and any debugger are under the control of the machine's user or administrator, and a process cannot refuse them (L). A same-user process can read `rv`'s memory at any time anyway; that is [NG-1](../THREAT_MODEL.md#1-scope-goals-and-non-goals).
- macOS writes core files only when `RLIMIT_CORE` is non-zero and `/cores` is writable (L); `RLIMIT_CORE = 0` therefore stops them. ReportCrash `.ips` reports hold thread backtraces, register state and the list of loaded images, not a full memory image (L), and are uploaded to Apple only if the user enabled analytics sharing (L).

**What we can do safely on every OS.** `std::panic::set_hook` is safe std API. The std documentation says the hook "is invoked when a thread panics, but before the panic runtime is invoked" (L, quoted from memory). A hook that ends the process with `std::process::exit` therefore never reaches `abort`, so under `panic = "abort"` a panic produces no `SIGABRT`, no `__fastfail`, no core file and no WER or ReportCrash report. Probe on this machine (V, Linux, rustc 1.99.1, `-C panic=abort -O`): a hook that writes one line and calls `std::process::exit(101)`, with a panic on a spawned thread whose message held a canary string, exited with status 101, printed only the hook's line, and never printed the canary. The same probe on Windows and macOS is U. The probe used a newer rustc than `rust-toolchain.toml`'s 1.94.1; the hook-before-runtime order has been std behaviour for many releases (L).

A panic is not the only crash: stack overflow, allocation failure, a second panic while the hook runs, and a memory fault in a dependency's `unsafe` code all abort without the hook completing (L). Those, and external dump requests, are what remains.

**`rizzy-vault` (the server) on Windows and macOS** is not supported: the self-hosting guide requires "a Linux host (amd64 or arm64)" (V, [docs/self-hosting.md](../self-hosting.md) line 61), and CI builds images for `linux/amd64` and `linux/arm64` only (same file, line 71). Its `#[cfg(not(unix))]` no-op (`crates/rizzy-server/src/coredump.rs` lines 149–162) is therefore not a shipped gap; this ADR names it in AR-31 and changes nothing there.

Native clients (M3, M7) keep their own route: ADR 0019 §5, INV-60's native-client sentences and AR-28 are unchanged.

## Decision

### 1. Scope

This ADR binds `rv` (`crates/rizzy-cli`) on Windows, macOS and Linux. It does not change `rizzy-vault`, the binding leaves, native clients, AR-28 or ADR 0019 §5. No crate is added, no feature is enabled, no new invariant applies to another crate, and no Win32 or Mach API is called.

### 2. Every OS: a panic becomes exit status 101 before the panic runtime runs

1. `crates/rizzy-cli/src/coredump.rs` gains `pub(crate) fn exit_on_panic()`. It calls `std::panic::set_hook` once with a closure that does exactly this and nothing else:
   1. Takes `std::io::stderr().lock()` and writes one line with `writeln!`, ignoring the result (`let _ = ...`): `rv: internal error (panic at {file}:{line}:{column})`, with the three values from `PanicHookInfo::location()`; if `location()` is `None`, the line is `rv: internal error (panic)`. It never reads `payload()`, never formats the `PanicHookInfo` itself (its `Display` includes the message), and never calls the previous or the default hook (which print the message and honour `RUST_BACKTRACE`). A panic message can carry secret bytes from any dependency; a source location cannot ([INV-48](../THREAT_MODEL.md#8-security-invariants)).
   2. Calls `std::process::exit(101)`.
2. `main` in `crates/rizzy-cli/src/lib.rs` calls `coredump::exit_on_panic()` as its first statement, before `coredump::disable()`. Order: hook, then `disable()` (unchanged), then argument parsing.
3. **Exit status 101** means "internal error; `rv` stopped without a crash dump". 101 is the status Rust itself uses for a panicking `main` under unwinding (L), and `rv` uses 1 and 2 for its other errors (V, `crates/rizzy-cli/src/error.rs` lines 132–136), so it collides with nothing. `docs/rv.md` documents it (On acceptance item 4).
4. `RUST_BACKTRACE` has no effect on `rv`. No environment variable or flag re-enables the default hook; a developer who needs a backtrace uses a debugger or a local, uncommitted change.
5. `std::process::exit` runs no destructors, so secrets in memory are not zeroized on this path; the pages go back to the OS with the process (that every supported OS clears them before reuse is L). This writes nothing to disk.
6. Only `rv`'s `main` installs the hook. Library code never calls `set_hook` or `take_hook`.

### 3. Windows: no OS call; the remainder is AR-31

1. `#[cfg(not(unix))] disable()` keeps returning `Ok(())` and makes no call. Its doc comment and the module docs say so and name this ADR and AR-31, replacing "until M3 confirms a mechanism (U)" and "(the crate is compiled there but not called)".
2. No Windows mechanism is admitted: `SetErrorMode`, `WerAddExcludedApplication`, `WerSetFlags` and `WerRegisterExcludedMemoryBlock` are reachable only through `unsafe` (Context), and none would stop LocalDumps or an external dump (L). If a safe, maintained wrapper appears later, admitting it is a new ADR with the ADR 0009 checklist record, as ADR 0024 did for rustix.
3. On Windows `rv` relies on §2 for panics, on short-lived zeroized secrets ([CRYPTO.md §12.2](../CRYPTO.md#122-memory-hygiene)) and on linking no crash-reporting SDK (INV-60). Everything else is AR-31.

### 4. macOS: `RLIMIT_CORE = 0`, as today, plus §2

1. The existing `#[cfg(unix)]` path is the macOS mechanism for `rv`: `setrlimit(RLIMIT_CORE, 0, 0)` through rustix 1.1.5 and the `getrlimit` read-back, refusing to start (exit 1) on failure. No macOS-specific code is added beyond §2. This settles, for `rv`, what INV-60 left as "mechanism to confirm".
2. No attempt is made to disable ReportCrash; non-panic crashes that reach it are AR-31.

### 5. Accepted risk AR-31 (number provisional)

The row added to THREAT_MODEL §9 on acceptance, in full:

> | AR-31 | `rv` on Windows and macOS: OS crash capture that `rv` cannot disable without `unsafe` ([ADR 0112](adr/0112-core-dumps-windows-macos.md)). A crash that is not a Rust panic (stack overflow, allocation failure, a second panic inside the panic hook, a memory fault in a dependency's `unsafe` code) aborts the process. On Windows it then reaches Windows Error Reporting, which can write a dump under an administrator's LocalDumps setting and send report data to Microsoft; on macOS ReportCrash writes a crash report with backtraces and register state and uploads it only if the user shares analytics (each U). An external dump (Task Manager, ProcDump, a debugger) works on either OS at any time and is [NG-1](#1-scope-goals-and-non-goals). `rizzy-vault` built for Windows or macOS is unsupported ([self-hosting guide](self-hosting.md)) and has no dump protection beyond `RLIMIT_CORE = 0` on macOS. | Every Rust panic in `rv` exits with status 101 before the panic runtime runs, so it never reaches these paths ([INV-125](#8-security-invariants)). macOS: `RLIMIT_CORE = 0`, soft and hard, read back ([INV-60](#8-security-invariants)). Secrets stay short-lived and zeroized; no crash-reporting SDK is linked. | M1 |

### 6. Superseded text: ADR 0024 Decision point 3, last two sentences

**Superseded** (ADR 0024 Decision 3, verbatim): "macOS has no dumpable flag, and its crash reports are [AR-28](../THREAT_MODEL.md#9-accepted-risks-and-out-of-scope). Windows has neither call in rustix; its dumps stay AR-28 until M3 confirms a mechanism (U)."

**Replacement**, in full:

"macOS has no dumpable flag; there `RLIMIT_CORE = 0` (soft and hard, read back) is the whole OS-level mechanism, and system crash reports are [AR-28](../THREAT_MODEL.md#9-accepted-risks-and-out-of-scope) for a native client and AR-31 for `rv`. Windows has neither call in rustix, and no Win32 API is called for dumps, because each one needs `unsafe` ([ADR 0112](0112-core-dumps-windows-macos.md) §3): `disable` makes no call there, and Windows Error Reporting and LocalDumps are AR-28 for a native client and AR-31 for `rv`. On every OS `rv` also installs a panic hook that exits with status 101 before the panic runtime runs (ADR 0112 §2, INV-125)."

Everything else in Decision 3 (its first sentence, the read-back and the refusal to start), points 1 and 2, the checklist record and every other part of ADR 0024 stay binding.

### 7. Invariant INV-125 (number provisional)

The row added to THREAT_MODEL §8 on acceptance, in full:

> | INV-125 | `rv` installs a panic hook as the first statement of `main`, on every OS. The hook writes one line to stderr, `rv: internal error (panic at <file>:<line>:<column>)` (or `rv: internal error (panic)` without a location), and calls `std::process::exit(101)`. It never reads or prints the panic payload, never calls the default hook, and ignores `RUST_BACKTRACE`. So no Rust panic in `rv` reaches `abort`, a core file, Windows Error Reporting or ReportCrash ([ADR 0112](adr/0112-core-dumps-windows-macos.md)). | M1 | A unit test in `crates/rizzy-cli/src/coredump.rs`, run on Linux, macOS and Windows in CI, re-runs its own test binary as a child that installs the hook and panics with a canary message, on the main test thread and, in a second case, on a spawned thread: the child exits with status 101, its stderr holds the one hook line, and the canary appears nowhere. |

### 8. Tests

All in `crates/rizzy-cli/src/coredump.rs` `#[cfg(test)]`, so the existing CI `test` matrix (Linux, macOS, Windows) runs them. Test code may read an environment variable; production code gains none.

1. **`panic_exits_101_without_payload`** (every OS). Spawns `std::env::current_exe()` with arguments `["--exact", "coredump::tests::panic_child_main", "--nocapture", "--test-threads=1"]` and the environment variable `RIZZY_CLI_PANIC_CHILD=1`, and asserts: `status.code() == Some(101)`; stderr contains exactly one line that starts with `rv: internal error (panic at ` and contains `coredump.rs:`; neither stdout nor stderr contains the canary `RV-PANIC-CANARY-8c1f`. (On Windows this also rules out `0xC0000409`, the `__fastfail` status, L.)
2. **`panic_on_thread_exits_101_without_payload`** (every OS). The same, for the child `panic_child_thread`.
3. **`panic_child_main`, `panic_child_thread`**: return at once unless `RIZZY_CLI_PANIC_CHILD` is set; otherwise call `exit_on_panic()` and `panic!("RV-PANIC-CANARY-8c1f")`, on the test thread or on a `std::thread::spawn`ed thread that is then joined. They pass trivially in a normal run.
4. **`limits_are_in_effect_after_disable`** (every Unix, macOS included): unchanged; its doc comment adds that on macOS it is INV-60's check for `rv` (ADR 0112 §4).
5. **`disable_makes_no_call_on_windows`** (`#[cfg(windows)]`): `assert_eq!(disable(), Ok(()))`, so the Windows behaviour is a named, documented test rather than an untested `cfg` branch.
6. **Not covered by CI, stated plainly:** Cargo builds tests with unwinding whatever the profile's `panic` setting (L), so `cargo test` never exercises the `panic = "abort"` path. The guarantee there rests on std's documented order (hook before panic runtime, L) and the Linux probe in Context (V). On acceptance item 6 adds a one-time manual probe on Windows and macOS.

## Consequences

**Positive**

- INV-60's "`rv` included" becomes true where it can be and honest where it cannot: macOS's mechanism is confirmed, the Windows absence is a named accepted risk, and both have CI tests.
- Panics, the main crash source under `panic = "abort"`, leave no dump on any OS, Linux included, with no `unsafe` and no new crate.
- Panic messages no longer reach stderr from `rv`, which closes a path around INV-48 for secret-bearing messages from dependencies.

**Negative**

- No backtraces from `rv`, even with `RUST_BACKTRACE`; bug reports carry only a source location.
- Destructors do not run after a panic, so zeroize-on-drop does not happen on that path (§2.5).
- Non-panic crashes on Windows and macOS, and administrator LocalDumps, stay uncovered (AR-31).

**Neutral**

- The server, the binding leaves and native clients are unchanged; AR-28 keeps its scope.

## Alternatives considered

- **Call `SetErrorMode` or `WerAddExcludedApplication` through `windows-sys`.** Needs `unsafe` in our code: forbidden. `SetErrorMode` would also not stop `__fastfail` reports (L), and `WerAddExcludedApplication` leaves a persistent registry change (L).
- **Admit the `windows` crate.** Its Win32 functions are `unsafe fn` (L); calling them is still our `unsafe`.
- **A small safe-wrapper crate of our own.** Our `unsafe` under another name; CLAUDE.md rules it out.
- **`panic = "unwind"` for `rv` and a `catch_unwind` in `main`.** Covers only the main thread unless every thread and task is wrapped, and changes a workspace-wide profile decision for one binary. The hook gives the same result for every thread.
- **Run the default hook, then `exit`.** The default hook prints the panic message, which may contain secrets.
- **Widen AR-28 instead of adding AR-31.** AR-28 is scoped to native clients and M3/M7, and its mitigation speaks of apps; a separate M1 row keeps `rv`'s residual visible and lets AR-28 change with ADR 0019 §5 on its own.
- **Install the hook in `rizzy-vault` too.** Out of scope: the server is Linux-only with the dumpable flag off, and a server panic policy (supervisor restarts, the INV-45 canary) is its own decision.

## On acceptance (not made now)

1. ADR 0024's Status line becomes "Partially superseded by [ADR 0112](0112-core-dumps-windows-macos.md) (Decision 3 in part)", and its README row likewise: the owner's act (ADR 0020 points 3 and 9).
2. THREAT_MODEL INV-60: the sentence "On macOS and Windows: opt out of local dumps and crash-report upload where the platform allows it (mechanism to confirm in M3, U)." is replaced by "For `rv`: on macOS `RLIMIT_CORE = 0` as on every Unix; on Windows no OS call, because each Win32 mechanism needs `unsafe`; on every OS its panics exit before the panic runtime ([INV-125](#8-security-invariants)); the rest is [AR-31](#9-accepted-risks-and-out-of-scope) ([ADR 0112](adr/0112-core-dumps-windows-macos.md)). For a native client on macOS and Windows: opt out of local dumps and crash-report upload where the platform allows it (mechanism to confirm in M3, U)." Its "Verified by" column gains: "macOS: the `RLIMIT_CORE` test runs on the macOS CI runner. Windows: `disable_makes_no_call_on_windows`. Every OS: INV-125's test."
3. THREAT_MODEL: add INV-125 (this ADR's §7) and AR-31 (§5), under the final numbers the lead assigns if these are taken.
4. `docs/rv.md`, after the platform table: "`rv` exits with status 101 after an internal error (a bug). It prints only the source location and writes no crash dump. On Windows and macOS other kinds of crash can still reach the OS crash reporter ([THREAT_MODEL AR-31](THREAT_MODEL.md#9-accepted-risks-and-out-of-scope))."
5. THREAT_MODEL §7.5 row I, mitigation column: "Core dumps disabled at startup." becomes "Core dumps disabled at startup on Unix; panics exit with status 101 on every OS (INV-125); the Windows and macOS remainder is AR-31."
6. A one-time manual probe, recorded in the implementing PR: a release-profile `rv` built with a temporary local panic (not committed) exits 101 on Windows with no new WER report (Event Viewer, `%LOCALAPPDATA%\CrashDumps`) and on macOS with no new `~/Library/Logs/DiagnosticReports` entry.

## Implementation plan

Gate: this ADR Accepted. One PR, `feat(cli): exit on panic without a crash dump (ADR 0112)`.

1. `coredump.rs`: add `exit_on_panic()` (§2.1); update the module docs and the `#[cfg(not(unix))] disable()` docs (§3.1); add the tests of §8.
2. `lib.rs`: call `coredump::exit_on_panic()` first in `main` (§2.2).
3. The `docs/rv.md` and THREAT_MODEL edits of On acceptance items 2–5, in the same PR once the owner has accepted.
4. Run the full pre-push list of CLAUDE.md; CI's three-OS `test` job runs §8.

## Open questions for the owner

1. **Exit status for a panic: 101, or 70 (`EX_SOFTWARE` from BSD `sysexits.h`)?** 101 matches Rust's own panic status and what users of Rust tools expect; 70 is the Unix convention for an internal software error. Recommendation: **101**.
2. **Accept AR-31 as an M1 residual, or withdraw `rv` on Windows until a safe mechanism exists?** Withdrawing drops a platform `docs/rv.md` already documents, for a gain limited to non-panic crashes, which no safe mechanism closes anyway. Recommendation: **accept AR-31**.

## References

- Review: [2026-10-25 gap review](../reviews/2026-10-25-adr-gap-review.md) S6; [raw G03](../reviews/2026-10-25-raw/G03.md) G03-8
- [ADR 0024](0024-core-dump-disabling-rustix.md) Decision 3; [ADR 0019](0019-native-clients.md) §5; [ADR 0020](0020-partial-supersession.md) point 9; [ADR 0009](0009-crypto-dependency-policy.md) (the checklist route for any future crate)
- [THREAT_MODEL](../THREAT_MODEL.md) INV-48, INV-60, AR-28, NG-1, §7.5; [CRYPTO.md §12.2](../CRYPTO.md#122-memory-hygiene)
- Code: `crates/rizzy-cli/src/coredump.rs`; `crates/rizzy-cli/src/lib.rs` lines 89–94; `crates/rizzy-cli/src/error.rs` lines 132–136; `crates/rizzy-server/src/coredump.rs` lines 149–162; `Cargo.toml` `[profile.release]`
- Rust std documentation for `std::panic::set_hook` and `std::process::exit` (L, not re-read)
