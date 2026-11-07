// SPDX-License-Identifier: AGPL-3.0-only

//! Core dumps off at process start (threat model INV-60; [ADR 0024]), and panics that exit
//! before the panic runtime runs (threat model INV-125; [ADR 0112]).
//!
//! Release builds use `panic = "abort"`, so without a hook a panic raises `SIGABRT` (on Windows,
//! a fail-fast crash); a core dump or crash report would write the process memory (from M1 on:
//! keys, the session token, decrypted items) to disk. Two things run first in `main`, before the
//! command line is read and before any secret exists:
//!
//! 1. [`exit_on_panic`] installs a panic hook that writes one line with the source location
//!    only and exits with status 101 (ADR 0112 §2). The hook runs before the panic runtime, so a
//!    Rust panic never unwinds into the frames that hold secrets, never reaches `abort`, and so
//!    never reaches a core file, Windows Error Reporting or `ReportCrash`. It never reads the panic
//!    payload (a message can carry secret bytes from any dependency, INV-48), never calls the
//!    default hook, and ignores `RUST_BACKTRACE`. `std::process::exit` runs no destructors: the
//!    secrets are not zeroized on this path, and their pages go back to the OS with the process;
//!    nothing is written to disk.
//! 2. [`disable`] turns core dumps off; `rv` exits 1 if it fails (threat model §7 `rv` row:
//!    "Core dumps disabled at startup").
//!
//! What it does, exactly as ADR 0024 point 3 says, through rustix's safe wrappers (no `unsafe`
//! of our own):
//!
//! - **Every Unix:** `setrlimit(RLIMIT_CORE, 0, 0)`: soft and hard limit both 0, so the process
//!   cannot raise it again later without `CAP_SYS_RESOURCE`.
//! - **Linux and Android:** also `prctl(PR_SET_DUMPABLE, 0)`
//!   (`set_dumpable_behavior(NotDumpable)`). This also stops a same-user process without
//!   `CAP_SYS_PTRACE` from attaching to or reading the process's memory (`ptrace(2)`
//!   access-mode checks).
//! - **Read-back:** `getrlimit(RLIMIT_CORE)` must return 0 for both limits and, on Linux and
//!   Android, `PR_GET_DUMPABLE` must return "not dumpable" ([`check`]). Anything else is an
//!   error. A rustix bug in either call is caught here rather than trusted (ADR 0024, Risks).
//!
//! **Documented absence elsewhere** (ADR 0112 §3 and §4). macOS has no dumpable flag: there
//! `RLIMIT_CORE = 0` (soft and hard, read back) is the whole OS-level mechanism for `rv`, and
//! `ReportCrash` is not disabled. On Windows rustix offers neither call, and no Win32 API is
//! called, because each one (`SetErrorMode`, `WerAddExcludedApplication`, ...) needs `unsafe`:
//! [`disable`] makes no call there and returns `Ok`. On both, a crash that is not a Rust panic
//! (stack overflow, allocation failure, a second panic inside the hook, a memory fault in a
//! dependency's `unsafe` code) can still reach the OS crash reporter: accepted risk AR-31.
//! Error messages carry only the failing step and an OS error number, never process state.
//!
//! [ADR 0024]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0024-core-dump-disabling-rustix.md
//! [ADR 0112]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0112-core-dumps-windows-macos.md

use std::fmt;
use std::io::Write as _;

/// The exit status of a panic in `rv`: "internal error; `rv` stopped without a crash dump"
/// (ADR 0112 §2.3). `rv` uses 1 and 2 for its other errors.
const PANIC_EXIT_STATUS: i32 = 101;

/// Installs the panic hook of ADR 0112 §2 (module docs, item 1). Only `rv`'s `main` calls it,
/// as its first statement; library code never calls `set_hook` or `take_hook`.
///
/// The hook writes `rv: internal error (panic at <file>:<line>:<column>)` (or
/// `rv: internal error (panic)` without a location) to stderr, ignoring a write error, and
/// calls `std::process::exit(101)`. It does nothing else.
pub(crate) fn exit_on_panic() {
    std::panic::set_hook(Box::new(|info| {
        let mut stderr = std::io::stderr().lock();
        // Only the location: never `info.payload()` and never `info` itself, whose `Display`
        // includes the message.
        let _ = match info.location() {
            Some(at) => writeln!(
                stderr,
                "rv: internal error (panic at {}:{}:{})",
                at.file(),
                at.line(),
                at.column()
            ),
            None => writeln!(stderr, "rv: internal error (panic)"),
        };
        std::process::exit(PANIC_EXIT_STATUS);
    }));
}

/// Which step of [`disable`] or [`check`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android")),
    expect(
        dead_code,
        reason = "the dumpable steps exist only on Linux and Android"
    )
)]
pub(crate) enum Step {
    /// `setrlimit(RLIMIT_CORE, 0, 0)` returned an error.
    SetLimit,
    /// `getrlimit(RLIMIT_CORE)` did not read back 0 for both the soft and the hard limit.
    LimitNotZero,
    /// `prctl(PR_SET_DUMPABLE, 0)` returned an error (Linux and Android).
    SetDumpable,
    /// `prctl(PR_GET_DUMPABLE)` returned an error (Linux and Android).
    ReadDumpable,
    /// `prctl(PR_GET_DUMPABLE)` did not read back "not dumpable" (Linux and Android).
    StillDumpable,
}

/// Core dumps could not be disabled, or are not disabled on read-back. The process must not
/// start (module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CoreDumpError {
    /// The failing step.
    pub(crate) step: Step,
    /// The OS error number, for the steps that are system calls that failed.
    pub(crate) errno: Option<i32>,
}

impl fmt::Display for CoreDumpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.step {
            Step::SetLimit => "setting RLIMIT_CORE to 0 failed",
            Step::LimitNotZero => "RLIMIT_CORE does not read back as 0",
            Step::SetDumpable => "PR_SET_DUMPABLE 0 failed",
            Step::ReadDumpable => "PR_GET_DUMPABLE failed",
            Step::StillDumpable => "the process is still dumpable after PR_SET_DUMPABLE 0",
        };
        write!(f, "cannot disable core dumps: {what}")?;
        if let Some(errno) = self.errno {
            write!(f, " (OS error {errno})")?;
        }
        Ok(())
    }
}

impl std::error::Error for CoreDumpError {}

/// The `RLIMIT_CORE` value [`disable`] sets and [`check`] expects: soft and hard limit 0.
#[cfg(unix)]
const ZERO: rustix::process::Rlimit = rustix::process::Rlimit {
    current: Some(0),
    maximum: Some(0),
};

/// Disables core dumps for this process and reads the result back (module docs).
///
/// # Errors
///
/// [`CoreDumpError`] if a call fails or the read-back ([`check`]) does not show dumps off.
#[cfg(unix)]
pub(crate) fn disable() -> Result<(), CoreDumpError> {
    rustix::process::setrlimit(rustix::process::Resource::Core, ZERO).map_err(|e| {
        CoreDumpError {
            step: Step::SetLimit,
            errno: Some(e.raw_os_error()),
        }
    })?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|e| CoreDumpError {
            step: Step::SetDumpable,
            errno: Some(e.raw_os_error()),
        })?;
    check()
}

/// Reads back what [`disable`] set: `RLIMIT_CORE` 0 (soft and hard) and, on Linux and Android,
/// the dumpable flag off.
///
/// # Errors
///
/// [`CoreDumpError`] if either is not in effect.
#[cfg(unix)]
pub(crate) fn check() -> Result<(), CoreDumpError> {
    if rustix::process::getrlimit(rustix::process::Resource::Core) != ZERO {
        return Err(CoreDumpError {
            step: Step::LimitNotZero,
            errno: None,
        });
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    match rustix::process::dumpable_behavior() {
        Ok(rustix::process::DumpableBehavior::NotDumpable) => {}
        Ok(_) => {
            return Err(CoreDumpError {
                step: Step::StillDumpable,
                errno: None,
            });
        }
        Err(e) => {
            return Err(CoreDumpError {
                step: Step::ReadDumpable,
                errno: Some(e.raw_os_error()),
            });
        }
    }
    Ok(())
}

/// Not Unix (Windows): makes no call and returns `Ok` (module docs, "Documented absence
/// elsewhere"). Every Win32 mechanism needs `unsafe`, so none is called (ADR 0112 §3); a
/// panic exits through [`exit_on_panic`], and the remainder is accepted risk AR-31.
///
/// # Errors
///
/// Never.
#[cfg(not(unix))]
pub(crate) fn disable() -> Result<(), CoreDumpError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// INV-60's test column: after [`disable`], the limit is 0 and (on Linux and Android) the
    /// process is not dumpable, read here through rustix independently of [`check`]. On macOS
    /// this is INV-60's check for `rv` (ADR 0112 §4).
    #[test]
    #[cfg(unix)]
    fn limits_are_in_effect_after_disable() {
        assert_eq!(disable(), Ok(()));
        let limit = rustix::process::getrlimit(rustix::process::Resource::Core);
        assert_eq!(limit.current, Some(0));
        assert_eq!(limit.maximum, Some(0));
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assert_eq!(
            rustix::process::dumpable_behavior(),
            Ok(rustix::process::DumpableBehavior::NotDumpable)
        );
        // Idempotent: a second call (hard limit already 0) still succeeds.
        assert_eq!(disable(), Ok(()));
        assert_eq!(check(), Ok(()));
    }

    /// The canary the child panics with; it must appear in neither output stream.
    const CANARY: &str = "RV-PANIC-CANARY-8c1f";

    /// Set in the child's environment only: the child tests below panic when it is set.
    const CHILD_ENV: &str = "RIZZY_CLI_PANIC_CHILD";

    /// Re-runs this test binary with only the child test `name` and checks the outcome of
    /// ADR 0112 §8 item 1: status 101, exactly one hook line naming this file, no canary.
    fn assert_child_exits_101_without_payload(name: &str) {
        let exe = std::env::current_exe().expect("the test binary's own path");
        let out = std::process::Command::new(exe)
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, "1")
            .output()
            .expect("the child test binary runs");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        // On Windows this also rules out 0xC0000409, the `__fastfail` status.
        assert_eq!(
            out.status.code(),
            Some(PANIC_EXIT_STATUS),
            "status {:?}, stdout {stdout:?}, stderr {stderr:?}",
            out.status
        );
        let hook_lines: Vec<&str> = stderr
            .lines()
            .filter(|l| l.starts_with("rv: internal error (panic at "))
            .collect();
        assert_eq!(hook_lines.len(), 1, "stderr {stderr:?}");
        assert!(hook_lines[0].contains("coredump.rs:"), "{}", hook_lines[0]);
        assert!(!stdout.contains(CANARY), "stdout {stdout:?}");
        assert!(!stderr.contains(CANARY), "stderr {stderr:?}");
    }

    /// INV-125's test (ADR 0112 §8 item 1): a panic on the main test thread exits 101 with the
    /// location only.
    #[test]
    fn panic_exits_101_without_payload() {
        assert_child_exits_101_without_payload("coredump::tests::panic_child_main");
    }

    /// INV-125's test (ADR 0112 §8 item 2): the same for a panic on a spawned thread.
    #[test]
    fn panic_on_thread_exits_101_without_payload() {
        assert_child_exits_101_without_payload("coredump::tests::panic_child_thread");
    }

    /// The child of [`panic_exits_101_without_payload`]; passes at once in a normal run.
    #[test]
    fn panic_child_main() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        exit_on_panic();
        panic!("{CANARY}");
    }

    /// The child of [`panic_on_thread_exits_101_without_payload`]; passes at once in a normal
    /// run.
    #[test]
    fn panic_child_thread() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        exit_on_panic();
        let joined = std::thread::spawn(|| panic!("{CANARY}")).join();
        // Not reached: the hook exits the whole process from the spawned thread.
        assert!(joined.is_ok(), "the hook did not exit");
    }

    /// ADR 0112 §8 item 5: on Windows [`disable`] makes no call and succeeds.
    #[test]
    #[cfg(windows)]
    fn disable_makes_no_call_on_windows() {
        assert_eq!(disable(), Ok(()));
    }

    #[test]
    fn messages_name_the_step_and_errno_only() {
        let e = CoreDumpError {
            step: Step::SetLimit,
            errno: Some(1),
        };
        assert_eq!(
            e.to_string(),
            "cannot disable core dumps: setting RLIMIT_CORE to 0 failed (OS error 1)"
        );
        let e = CoreDumpError {
            step: Step::StillDumpable,
            errno: None,
        };
        assert_eq!(
            e.to_string(),
            "cannot disable core dumps: the process is still dumpable after PR_SET_DUMPABLE 0"
        );
    }
}
