//! The `rv` command line: `--version` and `--help` succeed, and usage errors exit with code 2
//! and never panic, even on an argument that is not UTF-8 (CLAUDE.md: no panics). `rv generate`
//! runs offline, so its flags are tested here too.

use std::ffi::OsString;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_rv");

#[test]
fn version_flag_prints_name_and_version() {
    let out = Command::new(BIN).arg("--version").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stdout.trim(), format!("rv {}", env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_flag_prints_usage() {
    let out = Command::new(BIN).arg("--help").output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8(out.stdout).unwrap().contains("USAGE"));
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

/// `rv generate` with `--exclude`, `--symbols` and `--passphrase-number`: the output honours them,
/// and options the generator refuses exit with a usage error that names the problem.
#[test]
fn generate_honours_exclusions_symbols_and_the_passphrase_number() {
    let run = |args: &[&str]| {
        Command::new(BIN)
            .arg("generate")
            .args(args)
            .output()
            .unwrap()
    };
    for _ in 0..20 {
        let out = run(&[
            "--length",
            "40",
            "--exclude",
            "abcXYZ019",
            "--symbols",
            "#_",
        ]);
        assert!(out.status.success());
        let password = String::from_utf8(out.stdout).unwrap();
        let password = password.trim_end();
        assert_eq!(password.len(), 40);
        assert!(!password.contains(['a', 'b', 'c', 'X', 'Y', 'Z', '0', '1', '9']));
        assert!(password.contains(['#', '_']));
        assert!(
            password
                .chars()
                .filter(char::is_ascii_punctuation)
                .all(|c| c == '#' || c == '_')
        );
    }
    let out = run(&["--words", "4", "--passphrase-number"]);
    assert!(out.status.success());
    let phrase = String::from_utf8(out.stdout).unwrap();
    let words: Vec<&str> = phrase.trim_end().split('.').collect();
    assert_eq!(words.len(), 4);
    assert_eq!(
        words
            .iter()
            .filter(|w| w.ends_with(|c: char| c.is_ascii_digit()))
            .count(),
        1
    );
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("bits of entropy")
    );

    for (args, says) in [
        (&["--exclude", "0123456789"][..], "digit"),
        (&["--symbols", "!a"][..], "--symbols"),
        (&["--passphrase-number"][..], "--words"),
        (&["--length", "3"][..], "--length"),
        (&["--words", "2"][..], "--words"),
    ] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(stderr.contains(says), "{args:?}: {stderr}");
        assert!(out.stdout.is_empty());
    }
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
