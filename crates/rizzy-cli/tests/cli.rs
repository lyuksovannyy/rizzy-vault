// SPDX-License-Identifier: AGPL-3.0-only

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

/// Today's UTC civil date, as `rv` reads it.
#[expect(clippy::unwrap_used, reason = "a test helper: a panic fails the test")]
fn today_utc() -> rizzy_client::identity_gen::CivilDate {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    rizzy_client::identity_gen::CivilDate::from_days(i64::try_from(secs / 86_400).unwrap()).unwrap()
}

/// Runs `rv generate identity` with `args` and parses its `--json` object.
#[expect(clippy::unwrap_used, reason = "a test helper: a panic fails the test")]
fn identity_json(args: &[&str]) -> serde_json::Value {
    let out = Command::new(BIN)
        .args(["generate", "identity", "--json"])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

/// ADR 0079 §10, §12 "rv": `rv generate identity --json`: its shape, a valid date, the country,
/// and `--age` as a range, an exact age and a preset; the email only with `--domain`; refused
/// options exit with a usage error.
#[test]
fn generate_identity_prints_a_valid_identity() {
    use rizzy_client::identity_gen::CivilDate;

    let cases: [(&[&str], u32, u32); 4] = [
        (&["--country", "DE", "--age", "18-27"], 18, 27),
        (&["--country", "FR", "--age", "28"], 28, 28),
        (&["--country", "US", "--age", "any"], 21, 65),
        (
            &["--country", "GB", "--age", "30-44", "--sex", "female"],
            30,
            44,
        ),
    ];
    for (args, min, max) in cases {
        for _ in 0..5 {
            let v = identity_json(args);
            let fields = v["fields"].as_object().unwrap();
            let get = |k: &str| fields.get(k).and_then(serde_json::Value::as_str);
            let country = args[1];
            assert_eq!(get("identity.country"), Some(country));
            assert!(matches!(get("identity.sex"), Some("male" | "female")));
            if args.contains(&"female") {
                assert_eq!(get("identity.sex"), Some("female"));
            }
            let birthday = CivilDate::parse(get("identity.birthday").unwrap()).unwrap();
            let age = birthday.age_on(today_utc()).unwrap();
            assert!((min..=max).contains(&age), "{args:?}: {age}");
            for key in [
                "identity.first_name",
                "identity.last_name",
                "identity.username",
                "identity.address1",
                "identity.city",
                "identity.state",
                "identity.postal_code",
                "identity.title",
            ] {
                assert!(get(key).is_some_and(|s| !s.is_empty()), "{key}");
            }
            assert_eq!(get("identity.email"), None);
            for never in [
                "identity.ssn",
                "identity.passport_number",
                "identity.drivers_license",
            ] {
                assert_eq!(get(never), None);
            }
            assert_eq!(
                v["name"].as_str().unwrap(),
                format!(
                    "{} {}",
                    get("identity.first_name").unwrap(),
                    get("identity.last_name").unwrap()
                )
            );
        }
    }
    let v = identity_json(&[
        "--country",
        "SE",
        "--domain",
        "Example.COM",
        "--email-style",
        "nickname",
    ]);
    let fields = v["fields"].as_object().unwrap();
    let email = fields["identity.email"].as_str().unwrap();
    let username = fields["identity.username"].as_str().unwrap();
    assert_eq!(email, format!("{username}@example.com"));
    // Plain output: key=value lines, the item name first.
    let out = Command::new(BIN)
        .args(["generate", "identity", "--country", "AT"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.starts_with("item.name="));
    assert!(text.lines().any(|l| l == "identity.country=AT"));
    for (args, says) in [
        (&["--country", "XX"][..], "--country"),
        (&["--age", "17"][..], "--age"),
        (&["--age", "40-30"][..], "--age"),
        (&["--sex", "x"][..], "--sex"),
        (&["--domain", "nodot"][..], "--domain"),
    ] {
        let out = Command::new(BIN)
            .args(["generate", "identity"])
            .args(args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(says), "{args:?}: {stderr}");
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
