//! `rv` — rizzy-vault command-line client.
//!
//! Status: M0 skeleton. Only `--version` and `--help` are implemented.

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
    let arg = std::env::args().nth(1);
    let mut out = io::stdout().lock();
    let written = match arg.as_deref() {
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
