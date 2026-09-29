//! The `rizzy-vault` command line, run as a process: `--version`, usage and configuration
//! errors (exit 2, never a panic, even on an argument that is not UTF-8), and the `secrets`
//! and `backup-secrets` admin commands against a temporary directory.

#![expect(
    clippy::unwrap_used,
    reason = "test code: a failure fails the test, which CLAUDE.md allows"
)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_rizzy-vault");

/// A command with an empty environment, so no `RIZZY_*` variable of the developer leaks in.
fn rizzy(args: &[&str], env: &[(&str, &Path)]) -> Output {
    let mut command = Command::new(BIN);
    command.env_clear().args(args);
    for (k, v) in env {
        command.env(k, v);
    }
    command.output().unwrap()
}

/// A fresh temporary directory.
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rizzy-server-cli-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn version_flag_prints_name_and_version() {
    let out = rizzy(&["--version"], &[]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout.trim(),
        format!("rizzy-vault {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn unknown_arguments_exit_with_usage_error() {
    for args in [
        &["--definitely-not-a-flag"][..],
        &["backup"],
        &["--version", "extra"],
        // A secret on the command line is not even a flag.
        &["--database-url", "postgres://user:hunter2@db/v"],
    ] {
        let out = rizzy(args, &[]);
        assert_eq!(out.status.code(), Some(2), "args: {args:?}");
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(stderr.contains("USAGE"));
        assert!(!stderr.contains("hunter2"));
    }
}

#[test]
fn serving_without_an_origin_is_a_configuration_error() {
    let out = rizzy(&[], &[]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("RIZZY_ORIGIN is required"), "{stderr}");
    let out = rizzy(&["--roles", "smtp"], &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("smtp role is not available")
    );
}

/// `std::env::args` panics on an argument that is not valid Unicode (exit code 101); the
/// binary treats it as an unknown option.
#[test]
fn a_non_utf8_argument_is_a_usage_error_not_a_panic() {
    let out = Command::new(BIN)
        .env_clear()
        .arg(not_utf8())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("USAGE"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[test]
fn secrets_init_rotate_and_backup() {
    let dir = temp_dir("secrets");
    let data = dir.join("data");
    let secrets_dir = dir.join("secrets");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&secrets_dir).unwrap();
    let secrets = secrets_dir.join("secrets.json");
    let env = [
        ("RIZZY_DATA_DIR", data.as_path()),
        ("RIZZY_SECRETS_FILE", secrets.as_path()),
    ];

    let out = rizzy(&["secrets", "init"], &env);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let first = std::fs::read(&secrets).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&secrets).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // Nothing secret on stdout or stderr.
    let parsed: serde_json::Value = serde_json::from_slice(&first).unwrap();
    let token = parsed["bootstrap_token"].as_str().unwrap();
    assert!(!String::from_utf8_lossy(&out.stdout).contains(token));

    // Never overwritten.
    let out = rizzy(&["secrets", "init"], &env);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(std::fs::read(&secrets).unwrap(), first);

    // Rotations add ids and keep the old entries.
    assert!(
        rizzy(&["secrets", "rotate", "--data-key"], &env)
            .status
            .success()
    );
    assert!(rizzy(&["secrets", "rotate"], &env).status.success());
    let rotated: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&secrets).unwrap()).unwrap();
    assert_eq!(rotated["current_data_key_id"], 2);
    assert_eq!(rotated["data_keys"].as_array().unwrap().len(), 2);
    assert_eq!(rotated["setups"].as_array().unwrap().len(), 2);
    assert_eq!(rotated["enum_key"], parsed["enum_key"]);

    // The encrypted backup opens with its passphrase and holds the file's bytes.
    let passphrase = dir.join("passphrase");
    std::fs::write(&passphrase, "operator passphrase\n").unwrap();
    let backup = dir.join("secrets-backup.json");
    let out = rizzy(
        &[
            "backup-secrets",
            "--out",
            backup.to_str().unwrap(),
            "--passphrase-file",
            passphrase.to_str().unwrap(),
        ],
        &env,
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let file = std::fs::read(&backup).unwrap();
    let opened = rizzy_server::secrets_backup::open(&file, "operator passphrase").unwrap();
    assert_eq!(opened.expose_secret(), std::fs::read(&secrets).unwrap());
    assert!(!String::from_utf8_lossy(&file).contains("operator passphrase"));

    // A secrets file inside the data directory is refused (ADR 0010 §4).
    let inside = data.join("secrets.json");
    let out = rizzy(
        &["secrets", "init"],
        &[
            ("RIZZY_DATA_DIR", data.as_path()),
            ("RIZZY_SECRETS_FILE", inside.as_path()),
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(!inside.exists());

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn migrate_creates_the_database() {
    let dir = temp_dir("migrate");
    let out = rizzy(&["migrate"], &[("RIZZY_DATA_DIR", dir.as_path())]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8(out.stdout)
            .unwrap()
            .contains("database created")
    );
    let again = rizzy(&["migrate"], &[("RIZZY_DATA_DIR", dir.as_path())]);
    assert!(
        String::from_utf8(again.stdout)
            .unwrap()
            .contains("nothing to migrate")
    );
    std::fs::remove_dir_all(&dir).unwrap();
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
