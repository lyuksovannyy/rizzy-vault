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
