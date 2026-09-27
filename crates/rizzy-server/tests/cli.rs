//! The `rizzy-vault` command line: `--version` succeeds, and usage errors exit with code 2 and
//! never panic, even on an argument that is not UTF-8 (CLAUDE.md: no panics).

use std::ffi::OsString;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_rizzy-vault");

#[test]
fn version_flag_prints_name_and_version() {
    let out = Command::new(BIN).arg("--version").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout.trim(),
        format!("rizzy-vault {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn unknown_or_missing_argument_exits_with_usage_error() {
    for args in [&[][..], &["--definitely-not-a-flag"][..]] {
        let out = Command::new(BIN).args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "args: {args:?}");
        assert!(String::from_utf8(out.stderr).unwrap().contains("USAGE"));
    }
}

/// `std::env::args` panics on an argument that is not valid Unicode (exit code 101); the
/// binary treats it as an unknown option.
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
    OsString::from_vec(b"--version\xff".to_vec())
}

#[cfg(windows)]
fn not_utf8() -> OsString {
    use std::os::windows::ffi::OsStringExt;
    // An unpaired surrogate.
    OsString::from_wide(&[u16::from(b'-'), 0xD800])
}
