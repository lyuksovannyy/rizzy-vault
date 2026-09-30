//! `rv` — rizzy-vault command-line client. Everything is in the library crate
//! ([`rizzy_cli`]), so the end-to-end tests drive the same code.

// Also set by the workspace lint table (ADR 0016 R7); repeated here so that no manifest edit
// alone admits `unsafe` in this crate.
#![forbid(unsafe_code)]

use std::process::ExitCode;

/// Runs [`rizzy_cli::main`].
fn main() -> ExitCode {
    rizzy_cli::main()
}
