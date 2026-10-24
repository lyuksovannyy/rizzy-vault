// SPDX-License-Identifier: AGPL-3.0-only

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
    assert!(stdout.contains("check-spdx"), "{stdout}");
    assert!(stdout.contains("check-tables"), "{stdout}");
    assert!(stdout.contains("generate-tokens"), "{stdout}");
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
        &["check-spdx", "extra"][..],
        &["check-spdx", "--other"][..],
        &["check-spdx", "--fix", "extra"][..],
        &["check-tables", "extra"][..],
        &["check-tables", "--root"][..],
        &["check-tables", "--other", "x"][..],
        &["check-tables", "--root", "x", "extra"][..],
        &["generate-tokens", "extra"][..],
        &["generate-tokens", "--other"][..],
        &["generate-tokens", "--check", "extra"][..],
    ] {
        let out = Command::new(BIN).args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "args: {args:?}");
        assert!(String::from_utf8(out.stderr).unwrap().contains("USAGE"));
    }
}

/// `check-tables` passes on this repository (the positive case on the real tree).
#[test]
fn check_tables_passes_on_the_repository() {
    let out = Command::new(BIN).arg("check-tables").output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "{stderr}");
    assert!(stdout.starts_with("check-tables: ok ("), "{stdout}");
}

/// `check-tables --root` on a fixture tree: exit 0 on a clean one, exit 1 with `file:line`
/// errors once a vault query and a vault migration name `auth_` tables.
#[test]
fn check_tables_accepts_a_clean_fixture_and_rejects_a_cross_domain_one() {
    let root = std::env::temp_dir().join(format!(
        "rizzy-xtask-cli-check-tables-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let put = |rel: &str, text: &str| {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    };
    put(
        "crates/rizzy-domain-auth/queries/account.sql",
        "SELECT id FROM auth_accounts WHERE id = $1\n",
    );
    put(
        "crates/rizzy-domain-vault/queries/vault.sql",
        "SELECT id FROM vault_vaults WHERE account_id = $1\n",
    );
    for engine in ["sqlite", "postgres"] {
        let dir = format!("crates/rizzy-storage/migrations/{engine}");
        put(
            &format!("{dir}/0001_auth_initial.sql"),
            "CREATE TABLE auth_accounts (id BLOB NOT NULL PRIMARY KEY);\n",
        );
        put(
            &format!("{dir}/0002_vault_initial.sql"),
            "CREATE TABLE vault_vaults (\n    id BLOB NOT NULL PRIMARY KEY,\n    account_id BLOB \
             NOT NULL REFERENCES auth_accounts (id) ON DELETE CASCADE\n);\n",
        );
    }
    let run = || {
        Command::new(BIN)
            .args(["check-tables", "--root"])
            .arg(&root)
            .output()
            .unwrap()
    };

    let out = run();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "{stderr}");
    assert!(
        String::from_utf8(out.stdout)
            .unwrap()
            .starts_with("check-tables: ok (2 query file(s)"),
    );

    put(
        "crates/rizzy-domain-vault/queries/vault.sql",
        "SELECT v.id\nFROM vault_vaults v\nJOIN auth_sessions s ON s.account_id = v.account_id\n",
    );
    put(
        "crates/rizzy-storage/migrations/sqlite/0003_vault_devices.sql",
        "CREATE TABLE vault_x (\n    d BLOB REFERENCES auth_device_certificates (device_id)\n);\n",
    );
    let out = run();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr
            .contains("error: crates/rizzy-domain-vault/queries/vault.sql:3: JOIN auth_sessions: "),
        "{stderr}"
    );
    assert!(
        stderr.contains(
            "error: crates/rizzy-storage/migrations/sqlite/0003_vault_devices.sql:2: REFERENCES \
             auth_device_certificates: "
        ),
        "{stderr}"
    );
    assert!(stderr.contains("check-tables: 2 violation(s)"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
    let _ = std::fs::remove_dir_all(&root);
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
