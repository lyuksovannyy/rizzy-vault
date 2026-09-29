//! `rizzy-vault` — the self-hosted server binary. Everything it runs lives in the
//! `rizzy_server` library; see its crate docs and [`rizzy_server::cli`].

// Also set by the workspace lint table (ADR 0016 R7); repeated here so that no manifest edit
// alone admits `unsafe` in this crate.
#![forbid(unsafe_code)]

use std::process::ExitCode;

/// Parses the command line and runs it.
fn main() -> ExitCode {
    rizzy_server::cli::main()
}
