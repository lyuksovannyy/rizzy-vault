//! `rv` — the rizzy-vault command-line client, as a library the binary and the end-to-end
//! tests share (ROADMAP §4.2, M1: "CLI client (`rv`)"; [ADR 0013] §1–§2; ADR 0016 §3 notes).
//!
//! `rv` is a native host over the sans-I/O client core. It supplies the capabilities of ADR
//! 0013 §2 and nothing else; every check, key and format decision is `rizzy-client`'s.
//!
//! | Capability (ADR 0013 §2) | Module | How |
//! |---|---|---|
//! | HTTP transport | [`http`] | hyper's HTTP/1.1 client connection; the `/api/v1` conventions of ADR 0028. Loopback `http://` only: TLS awaits ADR 0009's approval |
//! | Persistent storage | [`db`], [`paths`] | `SQLite` through sqlx (`sqlite` driver only, ADR 0016 R5), running `rizzy-client`'s cache schema and changesets (ADR 0026); one file per account, mode 0600, one `rv` at a time |
//! | Randomness | [`sys`] | `rand_core::UnwrapErr(getrandom::SysRng)` (ADR 0009 "RNG rules") |
//! | Wall clock | [`sys`] | `std` |
//! | Key storage for local unlock | none | the master password, typed at each run. No session, token or unlocked key outlives the process (ADR 0026 §1: "each process run device-authenticates again") |
//!
//! | Module | Purpose |
//! |---|---|
//! | [`args`] | The command line; no argument is a secret |
//! | [`ui`] | Prompts without echo, piped secrets, output |
//! | [`device`] | An opened device: unlock, load, going online, sync, rotation, the write order of ADR 0026 §4 |
//! | [`enrol`] | Signup and login on a new device |
//! | [`recover`] | Recovery with the Emergency Kit (CRYPTO.md §11.9) |
//! | [`commands`] | The commands |
//! | [`error`] | [`CliError`], with no secret in it |
//! | `coredump` | Core dumps off at start (INV-60, ADR 0024) |
//!
//! # Contract
//!
//! - **No `unsafe`**, no `unwrap`, `expect`, `panic!` or `println!` outside tests (CLAUDE.md).
//! - **Secrets** (threat model INV-56): never read from argv or the environment, never
//!   written to a log, an error or a note; printed only by the commands whose purpose is to
//!   show one (`signup`'s Emergency Kit, `item show --reveal`, `generate`, `totp`).
//! - **The local data** must stay out of backups and sync tools (INV-61): the usage text and
//!   the operator docs say where it lives.
//! - **Untrusted input.** The cache file is verified row by row at every load
//!   (`rizzy_client::store::load`); server answers are bounded and verified by the client
//!   core; import files are bounded and parsed by `rizzy-import`.
//!
//! # Not in this build (reported)
//!
//! - Copying secrets to the clipboard instead of printing them (INV-56's default).
//! - Turning terminal echo off without the system `stty` (see [`ui`]); on platforms without
//!   it, secrets are read from standard input only.
//! - `https://` origins: the client-side TLS crates are not approved under ADR 0009 yet, so
//!   they are refused (see [`http`]). Only a loopback `http://` server can be used.
//! - A persisted pending stage for `rv login` and `rv recovery complete` (ADR 0026 defines one
//!   for signup only; see [`enrol`] and [`recover`]).
//! - Changing the master password or the Secret Key, server-side TOTP enrolment, editing URIs
//!   and custom fields of an existing item.
//!
//! [ADR 0013]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0013-shared-client-core.md

// Also set by the workspace lint table (ADR 0016 R7); repeated here so that no manifest edit
// alone admits `unsafe` in this crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

pub mod args;
pub mod commands;
mod coredump;
pub mod db;
pub mod device;
pub mod enrol;
pub mod error;
pub mod http;
pub mod paths;
pub mod recover;
pub mod sys;
pub mod ui;

pub use error::CliError;

use std::ffi::OsString;
use std::io::Write as _;
use std::process::ExitCode;

/// The `rv` process: core dumps off, the command line, one command on a current-thread
/// runtime, the exit code.
///
/// Exit codes: 0 success, 1 a failure, 2 a usage error. Messages go to stderr through
/// `write!` on a locked handle and name what failed, never a value.
#[must_use]
pub fn main() -> ExitCode {
    // First, before the arguments are read (threat model INV-60, ADR 0024; `coredump`).
    if let Err(e) = coredump::disable() {
        let _ = writeln!(std::io::stderr().lock(), "rv: {e}");
        return ExitCode::FAILURE;
    }
    // `args_os`, not `args`: `args` panics on an argument that is not UTF-8.
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let outcome = run(arguments);
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let mut err = std::io::stderr().lock();
            let _ = writeln!(err, "rv: {e}");
            if matches!(e, CliError::Usage(_)) {
                let _ = write!(err, "\n{}", args::USAGE);
            }
            ExitCode::from(e.exit_code())
        }
    }
}

/// Parses and runs one command line with the process's terminal and environment.
fn run(arguments: Vec<OsString>) -> Result<(), CliError> {
    let invocation = args::parse(arguments)?;
    let mut terminal = ui::Terminal::new();
    // Help and version need no data directory (and no `HOME`).
    let data_dir = match invocation.command {
        args::Command::Help | args::Command::Version | args::Command::Generate(_) => {
            std::path::PathBuf::new()
        }
        _ => paths::data_dir(&|name| std::env::var_os(name))?,
    };
    let mut env = device::Env {
        data_dir,
        account: None,
        ui: &mut terminal,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(error::io_error("cannot start the runtime"))?;
    runtime.block_on(commands::run(invocation, &mut env))
}
