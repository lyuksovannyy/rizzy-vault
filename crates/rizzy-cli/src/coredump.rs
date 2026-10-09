//! Core dumps off at process start (threat model INV-60; [ADR 0024]).
//!
//! Release builds use `panic = "abort"`, so a panic raises `SIGABRT`; a core dump would write
//! the process memory (from M1 on: keys, the session token, decrypted items) to disk. [`disable`]
//! runs first in `main`, before the command line is read and before any secret exists, and `rv`
//! exits 1 if it fails (threat model §7 `rv` row: "Core dumps disabled at startup").
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
//! **Documented absence elsewhere.** macOS has no dumpable flag; its system crash reports are
//! accepted risk AR-28, and only `RLIMIT_CORE` applies there. On Windows rustix offers neither
//! call (the crate is compiled there but not called): [`disable`] does nothing and returns
//! `Ok`, and Windows Error Reporting dumps stay AR-28 until M3 confirms a mechanism (ADR 0024
//! point 3).
//! Error messages carry only the failing step and an OS error number, never process state.
//!
//! [ADR 0024]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0024-core-dump-disabling-rustix.md

use std::fmt;

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

/// Not Unix: nothing to do or check (module docs, "Documented absence elsewhere").
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
    /// process is not dumpable, read here through rustix independently of [`check`].
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
