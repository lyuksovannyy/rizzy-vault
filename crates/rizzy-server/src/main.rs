//! `rizzy-vault` — self-hosted server binary.
//!
//! # Status
//!
//! M0 skeleton. Only `--version` and `--help` are implemented; there is no listener, no role,
//! no database and no cryptography in this binary yet. The crate has no dependencies.
//!
//! What the binary does today:
//!
//! - It looks at the first argument only; any further arguments are ignored.
//! - `-V` or `--version` prints `rizzy-vault <version>` to stdout and exits 0.
//! - `-h` or `--help` prints the usage text to stdout and exits 0.
//! - No argument, any other argument, or an argument that is not valid UTF-8 prints the usage
//!   text to stderr and exits 2. A non-UTF-8 argument never panics (`args_os`, not `args`).
//! - If writing to stdout fails (for example a closed pipe), it exits 1. Output goes through
//!   `write!`/`writeln!` on a locked handle, never `println!`, which would panic there instead
//!   (CLAUDE.md: no `println!` in non-test code).
//!
//! `tests/cli.rs` runs the built binary and checks the version output and the usage errors,
//! including the non-UTF-8 case.
//!
//! # Planned
//!
//! The accepted design this binary will follow, none of which exists yet:
//!
//! - **One binary, selectable roles** ([ADR 0010] §1, ROADMAP §4.9). A process runs the roles
//!   given by `--roles` or `RIZZY_ROLES`: `api`, `web` and `worker` from M1 (the default set),
//!   `notify` and `icons` from M3, `smtp` from M6. It is built on axum, tokio and sqlx.
//! - **Isolation checked at startup** ([ADR 0010] §2, threat model Q-5 and INV-44). A process
//!   with the `smtp` or `icons` role refuses to start if the role is combined with another, or
//!   if it can see a database setting or the server-secrets file.
//! - **`SQLite` single writer** ([ADR 0010] §2, [ADR 0011]). The process takes an exclusive lock
//!   next to the database; `backup` reads without it, while `restore`, `migrate` and
//!   `secrets rotate` take it and run only while the server is stopped.
//! - **Crate wiring** (ADR 0016 §3 notes, R5). This leaf crate is the only one that depends on
//!   the `rizzy-domain-*` crates, `rizzy-smtp-ingress` and `rizzy-icon-proxy`, and it also
//!   wires `rizzy-storage` and `rizzy-bus`; it may dev-depend on `rizzy-client` for end-to-end
//!   tests (ADR 0016 owner decision 4). As a leaf it may depend on getrandom directly and passes
//!   an injected RNG to the libraries (ADR 0016 R2). openssl may reach it only through the M3
//!   `WebAuthn` library (ADR 0009 owner decision 1).
//! - **Secret handling** (threat model INV-50, INV-60; CRYPTO.md §12.2). The OPAQUE server
//!   setup and data keys live in a secrets file outside the database and its backups; core
//!   dumps are disabled at startup; logging uses an allow-list of fields and never logs the
//!   request or response bodies of the auth, key and share endpoints.
//!
//! [ADR 0010]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0010-server-shape.md
//! [ADR 0011]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0011-storage.md

// Also set by the workspace lint table (ADR 0016 R7); repeated here so that no manifest edit
// alone admits `unsafe` in this crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

use std::ffi::OsStr;
use std::io::{self, Write};
use std::process::ExitCode;

/// The help text, printed on `--help` (stdout) and on a usage error (stderr).
const USAGE: &str = "\
rizzy-vault — self-hosted end-to-end encrypted password manager server

USAGE:
    rizzy-vault [OPTIONS]

OPTIONS:
    -h, --help       Print this help
    -V, --version    Print version
";

/// Handles `--version` and `--help`; everything else is a usage error (exit code 2).
fn main() -> ExitCode {
    // `args_os`, not `args`: `args` panics on an argument that is not UTF-8. Such an argument
    // is no known option, so it gets the usage error.
    let arg = std::env::args_os().nth(1);
    let mut out = io::stdout().lock();
    let written = match arg.as_deref().and_then(OsStr::to_str) {
        Some("-V" | "--version") => writeln!(out, "rizzy-vault {}", env!("CARGO_PKG_VERSION")),
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
