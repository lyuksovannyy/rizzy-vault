//! `rv` — rizzy-vault command-line client.
//!
//! Status: M0 skeleton. Only `--version` and `--help` are implemented.

// Also set by the workspace lint table (ADR 0016 R7); repeated here so that no manifest edit
// alone admits `unsafe` in this crate.
#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::io::{self, Write};
use std::process::ExitCode;

const USAGE: &str = "\
rv — rizzy-vault command-line client

USAGE:
    rv [OPTIONS]

OPTIONS:
    -h, --help       Print this help
    -V, --version    Print version
";

fn main() -> ExitCode {
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
