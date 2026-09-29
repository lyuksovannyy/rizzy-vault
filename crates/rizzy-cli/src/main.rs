//! `rv` — rizzy-vault command-line client.
//!
//! # Status
//!
//! M0 skeleton. Only `--version` and `--help` are implemented; there is no vault access, no
//! network, no storage and no cryptography in this binary yet; core dumps are already disabled
//! at startup. The crate depends on `rizzy-core` (ADR 0016 §2) but calls nothing from it.
//!
//! What the binary does today:
//!
//! - It looks at the first argument only; any further arguments are ignored.
//! - `-V` or `--version` prints `rv <version>` to stdout and exits 0.
//! - `-h` or `--help` prints the usage text to stdout and exits 0.
//! - No argument, any other argument, or an argument that is not valid UTF-8 prints the usage
//!   text to stderr and exits 2. A non-UTF-8 argument never panics (`args_os`, not `args`).
//! - Before anything else it disables core dumps (threat model INV-60, [ADR 0024]): `RLIMIT_CORE`
//!   0 on every Unix and, on Linux and Android, the dumpable flag off, both read back; if that
//!   fails it prints why to stderr and exits 1 (`coredump.rs`). The crate depends on rustix for
//!   this, as ADR 0024 point 2 allows a leaf crate.
//! - If writing to stdout fails (for example a closed pipe), it exits 1. Output goes through
//!   `write!`/`writeln!` on a locked handle, never `println!`, which would panic there instead
//!   (CLAUDE.md: no `println!` in non-test code).
//!
//! `tests/cli.rs` runs the built binary and checks the version and help output and the usage
//! errors, including the non-UTF-8 case.
//!
//! # Planned (M1)
//!
//! ROADMAP §4.2 makes `rv` an M1 Must: list, get, add, generate, copy TOTP. The accepted
//! design it will follow, none of which exists yet:
//!
//! - **A native host over `rizzy-client`** ([ADR 0013] §1, §2). `rv` moves its dependency from
//!   `rizzy-core` to the sans-I/O `rizzy-client` (ADR 0016 §3 notes) and supplies the host
//!   capabilities: a Rust HTTP client on rustls, `SQLite` through sqlx with the `sqlite` driver
//!   only (ADR 0016 R5), the std clock, and device state in the OS keyring or a 0600 file.
//! - **Randomness.** As a leaf crate it is one of the few crates allowed to depend on getrandom
//!   directly, and it passes `rand_core::UnwrapErr(getrandom::SysRng)` to the library crates
//!   (ADR 0009 "RNG rules", ADR 0016 R2).
//! - **Secret handling** (threat model INV-56, INV-60, INV-61, INV-62). Secrets are never
//!   taken from argv or environment variables, only from a TTY prompt or stdin; a secret is
//!   printed to a terminal only when asked explicitly, and copied to the clipboard by default;
//!   the docs say where the state file lives and that it must stay out of backups; no keystore
//!   (biometric) unlock is offered, because neither the OS keyring nor a file enforces user
//!   presence. (INV-60, core dumps disabled at startup, is already in; see above.)
//!
//! [ADR 0013]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0013-shared-client-core.md
//! [ADR 0024]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0024-core-dump-disabling-rustix.md

// Also set by the workspace lint table (ADR 0016 R7); repeated here so that no manifest edit
// alone admits `unsafe` in this crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

use std::ffi::OsStr;
use std::io::{self, Write};
use std::process::ExitCode;

mod coredump;

/// The help text, printed on `--help` (stdout) and on a usage error (stderr).
const USAGE: &str = "\
rv — rizzy-vault command-line client

USAGE:
    rv [OPTIONS]

OPTIONS:
    -h, --help       Print this help
    -V, --version    Print version
";

/// Handles `--version` and `--help`; everything else is a usage error (exit code 2).
fn main() -> ExitCode {
    // First, before the arguments are read (threat model INV-60, ADR 0024; `coredump`).
    if let Err(e) = coredump::disable() {
        let _ = writeln!(io::stderr().lock(), "rv: {e}");
        return ExitCode::FAILURE;
    }
    // `args_os`, not `args`: `args` panics on an argument that is not UTF-8. Such an argument
    // is no known option, so it gets the usage error.
    let arg = std::env::args_os().nth(1);
    let mut out = io::stdout().lock();
    let written = match arg.as_deref().and_then(OsStr::to_str) {
        Some("-V" | "--version") => writeln!(out, "rv {}", env!("CARGO_PKG_VERSION")),
        Some("-h" | "--help") => write!(out, "{USAGE}"),
        _ => {
            let _ = write!(io::stderr().lock(), "{USAGE}");
            return ExitCode::from(2);
        }
    };
    if written.is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
