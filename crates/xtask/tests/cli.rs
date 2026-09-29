//! The `xtask` command line: usage errors exit with code 2 and never panic (CLAUDE.md).

use std::ffi::OsString;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_xtask");

#[test]
fn help_prints_every_command() {
    let out = Command::new(BIN).arg("--help").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("check-deps"), "{stdout}");
    assert!(stdout.contains("check-clippy"), "{stdout}");
    assert!(stdout.contains("check-signoff"), "{stdout}");
}

#[test]
fn unknown_or_missing_command_exits_with_usage_error() {
    for args in [
        &[][..],
        &["check"][..],
        &["check-deps", "extra"][..],
        &["check-signoff"][..],
        &["check-signoff", "main..HEAD", "extra"][..],
        &["check-signoff", "--output=x..HEAD"][..],
        &["check-signoff", "main...HEAD"][..],
        &["check-signoff", "HEAD"][..],
        &["check-signoff", "--squash"][..],
        &["check-signoff", "--squash", "main...HEAD"][..],
        &["check-signoff", "--squash", "main..HEAD", "extra"][..],
        &["check-signoff", "--other", "main..HEAD"][..],
    ] {
        let out = Command::new(BIN).args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "args: {args:?}");
        assert!(String::from_utf8(out.stderr).unwrap().contains("USAGE"));
    }
}

/// `std::env::args` panics on an argument that is not valid Unicode (exit code 101); xtask
/// treats it as an unknown command.
#[test]
fn a_non_utf8_argument_is_a_usage_error_not_a_panic() {
    let out = Command::new(BIN).arg(not_utf8()).output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("USAGE"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[cfg(unix)]
fn not_utf8() -> OsString {
    use std::os::unix::ffi::OsStringExt;
    OsString::from_vec(b"check-deps\xff".to_vec())
}

#[cfg(windows)]
fn not_utf8() -> OsString {
    use std::os::windows::ffi::OsStringExt;
    // An unpaired surrogate.
    OsString::from_wide(&[u16::from(b'c'), 0xD800])
}
