// SPDX-License-Identifier: AGPL-3.0-only

//! `rizzy-vault secrets restore` and `rizzy-vault secrets invalidate` (ADR 0047) run as a
//! process: every refusal path, with its exit code and message and with nothing written, and
//! both commands carried out. The database states are loaded as fixtures (a logical backup
//! restored into the empty database), so each refusal is reached exactly. The same commands on
//! `PostgreSQL`: [`postgres_secrets_restore_and_invalidate`] (`#[ignore]`d, needs
//! `RIZZY_TEST_POSTGRES_URL`).

#![expect(
    clippy::unwrap_used,
    reason = "integration tests: a failure fails the test, which CLAUDE.md allows in test code"
)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng as _;
use rizzy_domain_auth::ServerSecrets;
use rizzy_domain_auth::invalidation::{LossCase, invalidate_in_database};
use rizzy_domain_auth::types::ServerSetup;
use rizzy_server::admin::{self, AdminError, InvalidateDiagnosis, SecretsInvalidated};
use rizzy_server::config::{self, Config, Settings, Sources};
use rizzy_server::server::{open_database, open_services};
use rizzy_server::{secrets_backup, secrets_file};
use rizzy_storage::tables::TABLES;
use rizzy_storage::{Dump, RestoreGeneration, TableDump, Value, WriterLock, schema_version};

const BIN: &str = env!("CARGO_BIN_EXE_rizzy-vault");

/// The operator's passphrase.
const PASSPHRASE: &str = "an operator passphrase for the secrets backup";

/// Runs `f` on a current-thread runtime.
fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

/// One instance: a data directory and, outside it, a secrets directory (ADR 0010 §4).
struct Instance {
    /// The root, removed on drop.
    root: PathBuf,
    /// The data directory.
    data: PathBuf,
    /// The secrets file.
    secrets: PathBuf,
    /// The passphrase file.
    passphrase: PathBuf,
    /// `RIZZY_DATABASE_URL`, for `PostgreSQL`.
    database_url: Option<String>,
}

impl Instance {
    /// A new instance under the temporary directory, on `SQLite`.
    fn new(tag: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("rizzy-server-secrets-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let data = root.join("data");
        let secrets_dir = root.join("secrets");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&secrets_dir).unwrap();
        let passphrase = root.join("passphrase");
        std::fs::write(&passphrase, format!("{PASSPHRASE}\n")).unwrap();
        Self {
            root,
            data,
            secrets: secrets_dir.join("secrets.json"),
            passphrase,
            database_url: None,
        }
    }

    /// `name` under the root.
    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// The instance's configuration, as the binary reads it.
    fn config(&self) -> Config {
        let mut env: BTreeMap<&'static str, String> = BTreeMap::new();
        env.insert(config::ORIGIN, "https://vault.example.com".to_owned());
        env.insert(config::DATA_DIR, self.data.to_str().unwrap().to_owned());
        env.insert(
            config::SECRETS_FILE,
            self.secrets.to_str().unwrap().to_owned(),
        );
        if let Some(url) = &self.database_url {
            env.insert(config::DATABASE_URL, url.clone());
        }
        let lookup = move |key: &str| env.get(key).map(OsString::from);
        Config::from_sources(&Sources {
            file: Settings::new(),
            env: &lookup,
            roles_flag: None,
        })
        .unwrap()
    }

    /// Runs the binary with `args` in this instance's environment only, `stdin` on its input.
    fn run_with_stdin(&self, args: &[&str], stdin: &[u8]) -> Output {
        use std::io::Write as _;
        let mut command = Command::new(BIN);
        command.env_clear();
        for name in ["SystemRoot", "PATH"] {
            if cfg!(windows)
                && let Some(value) = std::env::var_os(name)
            {
                command.env(name, value);
            }
        }
        let mut child = command
            .args(args)
            .env("RIZZY_DATA_DIR", &self.data)
            .env("RIZZY_SECRETS_FILE", &self.secrets)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        child.wait_with_output().unwrap()
    }

    /// Runs the binary with `args` and an empty standard input.
    fn run(&self, args: &[&str]) -> Output {
        self.run_with_stdin(args, b"")
    }

    /// The secrets file's bytes, or `None` when it is absent.
    fn secrets_bytes(&self) -> Option<Vec<u8>> {
        std::fs::read(&self.secrets).ok()
    }

    /// The loaded secrets file.
    fn loaded(&self) -> ServerSecrets {
        secrets_file::load(&self.secrets).unwrap()
    }

    /// Migrates the empty database and loads `dump` into it.
    async fn load(&self, dump: &Dump) {
        let db = open_database(&self.config()).await.unwrap();
        db.migrate().await.unwrap();
        db.restore(dump, RestoreGeneration([0x47; 16]), 1_000)
            .await
            .unwrap();
        db.close().await;
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A 16-byte id.
fn idv(n: u8) -> Value {
    Value::Blob(vec![n; 16])
}

/// An integer.
fn int(v: i64) -> Value {
    Value::Integer(v)
}

/// A recorded setup in a fixture.
struct SetupRow {
    /// Its id.
    id: i64,
    /// Its AKE public-key hash.
    hash: [u8; 32],
    /// Whether the database marks it retired.
    retired: bool,
}

/// A database fixture: the setups, one account with a record on setup `record_setup`, and its
/// TOTP rows naming `totp_data_keys`. Every other table empty.
fn fixture(setups: &[SetupRow], record_setup: i64, totp_data_keys: &[i64]) -> Dump {
    let rows: Vec<(&str, Vec<Vec<Value>>)> = vec![
        (
            "auth_accounts",
            vec![vec![
                idv(0xa1),
                Value::Text("alice".into()),
                int(1_000),
                Value::Null,
            ]],
        ),
        (
            "auth_opaque_setups",
            setups
                .iter()
                .map(|s| {
                    vec![
                        int(s.id),
                        Value::Blob(s.hash.to_vec()),
                        int(10),
                        if s.retired { int(20) } else { Value::Null },
                    ]
                })
                .collect(),
        ),
        (
            "auth_credentials",
            vec![vec![
                idv(0xa1),
                int(record_setup),
                Value::Blob(vec![2; 200]),
                int(1),
                int(0),
                Value::Blob(vec![3; 90]),
                int(11),
                int(0),
            ]],
        ),
        (
            "auth_totp_credentials",
            totp_data_keys
                .iter()
                .zip(1..)
                .map(|(key, seq)| {
                    vec![
                        idv(0xa1),
                        int(seq),
                        int(*key),
                        Value::Blob(vec![4; 60]),
                        Value::Null,
                        int(25),
                    ]
                })
                .collect(),
        ),
    ];
    Dump {
        schema_version: schema_version(),
        tables: TABLES
            .iter()
            .map(|spec| TableDump {
                table: spec.name.to_owned(),
                rows: rows
                    .iter()
                    .find(|(name, _)| *name == spec.name)
                    .map_or_else(Vec::new, |(_, r)| r.clone()),
            })
            .collect(),
    }
}

/// The hash of the secrets' setup `id`.
fn hash_of(secrets: &ServerSecrets, id: u32) -> [u8; 32] {
    secrets
        .setups()
        .find(|(i, _)| *i == id)
        .unwrap()
        .1
        .public_key_hash()
}

/// A fixture recording the instance's own setup 1, matching its file.
fn matching(instance: &Instance, totp_data_keys: &[i64]) -> Dump {
    let secrets = instance.loaded();
    fixture(
        &[SetupRow {
            id: 1,
            hash: hash_of(&secrets, 1),
            retired: false,
        }],
        1,
        totp_data_keys,
    )
}

/// Asserts `out` exited with `code` and its stderr holds every one of `needles`.
fn assert_failed(out: &Output, code: i32, needles: &[&str]) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(code), "{stderr}");
    for needle in needles {
        assert!(stderr.contains(needle), "{needle:?} not in {stderr}");
    }
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert!(!stderr.contains(PASSPHRASE), "{stderr}");
}

/// Asserts `out` succeeded; returns its stdout.
fn assert_ok(out: &Output) -> String {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout.clone()).unwrap()
}

/// `secrets init` for `instance`, then `backup-secrets --out <name>`; returns the backup path.
fn init_and_back_up(instance: &Instance, name: &str) -> PathBuf {
    assert_ok(&instance.run(&["secrets", "init"]));
    let out = instance.path(name);
    let passphrase = instance.passphrase.to_str().unwrap();
    assert_ok(&instance.run(&[
        "backup-secrets",
        "--out",
        out.to_str().unwrap(),
        "--passphrase-file",
        passphrase,
    ]));
    out
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one refusal after another, on one instance"
)]
fn secrets_restore_refusals_write_nothing_and_a_fitting_backup_is_installed() {
    let a = Instance::new("restore-a");
    let b = Instance::new("restore-b");
    let a_backup = init_and_back_up(&a, "a-backup.json");
    let b_backup = init_and_back_up(&b, "b-backup.json");
    let original = a.secrets_bytes().unwrap();
    block_on(a.load(&matching(&a, &[1])));
    let (backup, pass) = (a_backup.to_str().unwrap(), a.passphrase.to_str().unwrap());
    let unchanged = |a: &Instance| assert_eq!(a.secrets_bytes().unwrap(), original);

    // Usage errors (exit 2): a flag missing, both from stdin, a flag of another command.
    for args in [
        &["secrets", "restore"][..],
        &["secrets", "restore", "--in", backup],
        &["secrets", "restore", "--passphrase-file", pass],
        &["secrets", "restore", "--in", "-", "--passphrase-file", "-"],
        &[
            "secrets",
            "restore",
            "--in",
            backup,
            "--passphrase-file",
            pass,
            "--confirm",
        ],
        &[
            "secrets",
            "restore",
            "--in",
            backup,
            "--passphrase-file",
            pass,
            "--force",
        ],
    ] {
        assert_failed(&a.run(args), 2, &["USAGE"]);
        unchanged(&a);
    }

    // A wrong passphrase, from stdin and from a file: one error, nothing written.
    let wrong = a.path("wrong");
    std::fs::write(&wrong, "not the passphrase").unwrap();
    let out = a.run_with_stdin(
        &[
            "secrets",
            "restore",
            "--in",
            backup,
            "--passphrase-file",
            "-",
        ],
        b"not the passphrase\n",
    );
    assert_failed(
        &out,
        1,
        &["wrong passphrase, or the backup file was changed"],
    );
    let out = a.run(&[
        "secrets",
        "restore",
        "--in",
        backup,
        "--passphrase-file",
        wrong.to_str().unwrap(),
    ]);
    assert_failed(
        &out,
        1,
        &["wrong passphrase, or the backup file was changed"],
    );
    unchanged(&a);
    // A changed backup: the same error.
    let mut tampered: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&a_backup).unwrap()).unwrap();
    let data = tampered["data"].as_str().unwrap().to_owned();
    let flipped = if data.ends_with('A') { "B" } else { "A" };
    tampered["data"] = serde_json::Value::from(format!("{}{flipped}", &data[..data.len() - 1]));
    let tampered_path = a.path("tampered.json");
    std::fs::write(&tampered_path, tampered.to_string()).unwrap();
    let out = a.run(&[
        "secrets",
        "restore",
        "--in",
        tampered_path.to_str().unwrap(),
        "--passphrase-file",
        pass,
    ]);
    assert_failed(
        &out,
        1,
        &["wrong passphrase, or the backup file was changed"],
    );
    unchanged(&a);
    // Not a backup file (the secrets file itself), an empty passphrase, a missing file.
    let out = a.run(&[
        "secrets",
        "restore",
        "--in",
        a.secrets.to_str().unwrap(),
        "--passphrase-file",
        pass,
    ]);
    assert_failed(&out, 1, &["not a rizzy-vault secrets backup file"]);
    let out = a.run_with_stdin(
        &[
            "secrets",
            "restore",
            "--in",
            backup,
            "--passphrase-file",
            "-",
        ],
        b"\n",
    );
    assert_failed(&out, 1, &["the passphrase is empty"]);
    let out = a.run(&[
        "secrets",
        "restore",
        "--in",
        a.path("absent.json").to_str().unwrap(),
        "--passphrase-file",
        pass,
    ]);
    assert_failed(&out, 1, &["cannot read the backup file"]);
    unchanged(&a);
    // A backup that decrypts but holds no valid secrets file: refused before any write.
    let damaged = secrets_backup::seal(
        &mut ChaCha20Rng::seed_from_u64(47),
        PASSPHRASE,
        br#"{"format":1}"#,
        1_000,
    )
    .unwrap();
    let damaged_path = a.path("damaged.json");
    std::fs::write(&damaged_path, &damaged).unwrap();
    let out = a.run(&[
        "secrets",
        "restore",
        "--in",
        damaged_path.to_str().unwrap(),
        "--passphrase-file",
        pass,
    ]);
    assert_failed(&out, 1, &["the backup does not hold a valid secrets file"]);
    unchanged(&a);

    // Another instance's backup: it does not belong to this database, over the file and into
    // an absent one alike.
    let b_path = b_backup.to_str().unwrap();
    let out = a.run(&[
        "secrets",
        "restore",
        "--in",
        b_path,
        "--passphrase-file",
        pass,
    ]);
    assert_failed(
        &out,
        1,
        &[
            "this secrets backup does not belong to this database",
            "setup 1 does not match",
        ],
    );
    unchanged(&a);
    std::fs::remove_file(&a.secrets).unwrap();
    let out = a.run(&[
        "secrets",
        "restore",
        "--in",
        b_path,
        "--passphrase-file",
        pass,
    ]);
    assert_failed(&out, 1, &["does not belong to this database"]);
    assert!(
        a.secrets_bytes().is_none(),
        "nothing written into the absent file"
    );

    // The server running (its writer lock held): refused before anything is read.
    let config::DatabaseConfig::Sqlite(path) = &a.config().database else {
        panic!("SQLite")
    };
    let lock = WriterLock::acquire(path).unwrap();
    let out = a.run(&[
        "secrets",
        "restore",
        "--in",
        backup,
        "--passphrase-file",
        pass,
    ]);
    assert_failed(&out, 1, &["writer lock"]);
    drop(lock);
    assert!(a.secrets_bytes().is_none());

    // The fitting backup, the passphrase from stdin: created, byte for byte, mode 0600.
    let out = a.run_with_stdin(
        &[
            "secrets",
            "restore",
            "--in",
            backup,
            "--passphrase-file",
            "-",
        ],
        format!("{PASSPHRASE}\n").as_bytes(),
    );
    assert!(assert_ok(&out).contains("secrets file restored from the backup (created)"));
    unchanged(&a);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&a.secrets).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // And again, the backup from stdin, over a damaged file: replaced.
    std::fs::write(&a.secrets, b"{not json").unwrap();
    let out = a.run_with_stdin(
        &["secrets", "restore", "--in", "-", "--passphrase-file", pass],
        &std::fs::read(&a_backup).unwrap(),
    );
    assert!(assert_ok(&out).contains("(replaced)"));
    unchanged(&a);
    // The server starts on it.
    block_on(async {
        let services = open_services(&a.config()).await.unwrap();
        services.db.close().await;
    });
}

/// A database no migration was applied to holds no record: the backup is installed, and the
/// report says to restore the database next.
#[test]
fn secrets_restore_into_an_empty_database() {
    let a = Instance::new("restore-empty");
    let backup = init_and_back_up(&a, "backup.json");
    let original = a.secrets_bytes().unwrap();
    std::fs::remove_file(&a.secrets).unwrap();
    let out = a.run(&[
        "secrets",
        "restore",
        "--in",
        backup.to_str().unwrap(),
        "--passphrase-file",
        a.passphrase.to_str().unwrap(),
    ]);
    let stdout = assert_ok(&out);
    assert!(
        stdout.contains("(created)") && stdout.contains("the database is empty"),
        "{stdout}"
    );
    assert_eq!(a.secrets_bytes().unwrap(), original);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "every refusal, then both cases, on fresh instances"
)]
fn secrets_invalidate_refuses_outside_the_two_cases_and_carries_both_out() {
    // A database that was never migrated: refused, nothing written.
    let fresh = Instance::new("invalidate-fresh");
    assert_failed(
        &fresh.run(&["secrets", "invalidate", "--confirm"]),
        1,
        &["not at this release's schema"],
    );
    assert!(fresh.secrets_bytes().is_none());
    // Unknown flags and arguments: usage errors.
    for args in [
        &["secrets", "invalidate", "--yes"][..],
        &["secrets", "invalidate", "confirm"],
        &["secrets", "invalidate", "--confirm", "--confirm"],
    ] {
        assert_failed(&fresh.run(args), 2, &["USAGE"]);
    }

    // The file matches: nothing to invalidate, with or without --confirm.
    let ok = Instance::new("invalidate-ok");
    assert_ok(&ok.run(&["secrets", "init"]));
    block_on(ok.load(&matching(&ok, &[1])));
    let before = ok.secrets_bytes().unwrap();
    for args in [
        &["secrets", "invalidate"][..],
        &["secrets", "invalidate", "--confirm"],
    ] {
        assert_failed(&ok.run(args), 1, &["there is nothing to invalidate"]);
    }
    assert_eq!(ok.secrets_bytes().unwrap(), before);

    // A TOTP row names a data key the file lacks: the break is a data key, never touched here.
    let key = Instance::new("invalidate-key");
    assert_ok(&key.run(&["secrets", "init"]));
    block_on(key.load(&matching(&key, &[7])));
    let before = key.secrets_bytes().unwrap();
    assert_failed(
        &key.run(&["secrets", "invalidate", "--confirm"]),
        1,
        &["data key 7", "never discards data keys", "secrets restore"],
    );
    assert_eq!(key.secrets_bytes().unwrap(), before);

    // A setup the database marks retired is still in the file: retire-setups fits.
    let retired = Instance::new("invalidate-retired");
    assert_ok(&retired.run(&["secrets", "init"]));
    let secrets = retired.loaded();
    block_on(retired.load(&fixture(
        &[SetupRow {
            id: 1,
            hash: hash_of(&secrets, 1),
            retired: true,
        }],
        1,
        &[],
    )));
    let before = retired.secrets_bytes().unwrap();
    assert_failed(
        &retired.run(&["secrets", "invalidate", "--confirm"]),
        1,
        &["marks retired", "retire-setups", "only handles"],
    );
    assert_eq!(retired.secrets_bytes().unwrap(), before);

    // A file that exists but cannot be read (not absent, not unparsable): refused.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&retired.secrets, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&retired.secrets).is_err() {
            assert_failed(
                &retired.run(&["secrets", "invalidate", "--confirm"]),
                1,
                &["secrets file cannot be read"],
            );
        }
        std::fs::set_permissions(&retired.secrets, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(retired.secrets_bytes().unwrap(), before);
    }

    // A setup-only loss: the database's setup 1 is another one. Without --confirm, the
    // diagnosis and the cost, nothing written; with it, a new setup 2 and the log line.
    let setup = Instance::new("invalidate-setup");
    assert_ok(&setup.run(&["secrets", "init"]));
    let other = ServerSetup::generate(&mut ChaCha20Rng::seed_from_u64(9));
    block_on(setup.load(&fixture(
        &[SetupRow {
            id: 1,
            hash: other.public_key_hash(),
            retired: false,
        }],
        1,
        &[1],
    )));
    let before = setup.secrets_bytes().unwrap();
    let old = setup.loaded();
    assert_failed(
        &setup.run(&["secrets", "invalidate"]),
        2,
        &[
            "needs --confirm",
            "setup-only loss",
            "1 account(s) must re-register",
            "0 TOTP enrolment(s)",
            "secrets restore",
        ],
    );
    assert_eq!(setup.secrets_bytes().unwrap(), before);
    let out = setup.run(&["secrets", "invalidate", "--confirm"]);
    let stdout = assert_ok(&out);
    assert!(
        stdout.contains("setup-only loss")
            && stdout.contains("new OPAQUE setup 2")
            && stdout.contains("1 account(s) need to re-register")
            && stdout.contains("0 TOTP enrolment(s) to redo"),
        "{stdout}"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    let line: serde_json::Value = serde_json::from_str(
        stderr
            .lines()
            .find(|l| l.contains("secrets_invalidated"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(line["level"], "warn");
    assert_eq!(line["case"], "setup_only");
    assert_eq!(line["setup_id"], 2);
    assert_eq!(line["setup_count"], 1);
    assert_eq!(line["totp_rows_deleted"], 0);
    let renewed = setup.loaded();
    assert_eq!(renewed.setups().map(|(id, _)| id).collect::<Vec<_>>(), [2]);
    assert_eq!(
        renewed.enum_key().expose_secret(),
        old.enum_key().expose_secret()
    );
    assert_eq!(renewed.bootstrap_token(), old.bootstrap_token());
    // Done: the next run finds nothing to invalidate, and the server starts.
    assert_failed(
        &setup.run(&["secrets", "invalidate", "--confirm"]),
        1,
        &["nothing to invalidate"],
    );
    block_on(async {
        let services = open_services(&setup.config()).await.unwrap();
        services.db.close().await;
    });

    // A whole loss: an unparsable file. The TOTP row goes, and so does the bootstrap token.
    let whole = Instance::new("invalidate-whole");
    assert_ok(&whole.run(&["secrets", "init"]));
    block_on(whole.load(&matching(&whole, &[1])));
    std::fs::write(&whole.secrets, b"{}").unwrap();
    assert_failed(
        &whole.run(&["secrets", "invalidate"]),
        2,
        &["whole loss", "1 TOTP enrolment(s) are deleted"],
    );
    assert_eq!(whole.secrets_bytes().unwrap(), b"{}");
    let out = whole.run(&["secrets", "invalidate", "--confirm"]);
    let stdout = assert_ok(&out);
    assert!(
        stdout.contains("whole loss")
            && stdout.contains("1 TOTP enrolment(s) to redo")
            && stdout.contains("no bootstrap token was made"),
        "{stdout}"
    );
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains(r#""case":"whole_loss""#)
    );
    assert!(whole.loaded().bootstrap_token().is_none());
    block_on(async {
        let services = open_services(&whole.config()).await.unwrap();
        services.db.close().await;
    });
}

/// Both commands on `PostgreSQL` (ADR 0011: `SQLite` and `PostgreSQL` alike): a mismatched backup
/// refused and a fitting one installed, a setup-only loss crashed after step 4 and resumed
/// from the marker, a whole loss; the server starts after each.
///
/// `#[ignore]`d by default: run with `RIZZY_TEST_POSTGRES_URL` naming an **empty** database
/// (it is migrated and filled), e.g. `RIZZY_TEST_POSTGRES_URL=postgres://rizzy:rizzy@127.0.0.1:
/// 55432/rizzy_m1_secrets_ops_srv cargo test -p rizzy-server --test secrets_ops -- --ignored`.
#[test]
#[ignore = "needs RIZZY_TEST_POSTGRES_URL: an empty PostgreSQL database"]
fn postgres_secrets_restore_and_invalidate() {
    let url = std::env::var("RIZZY_TEST_POSTGRES_URL").unwrap();
    let mut pg = Instance::new("pg");
    pg.database_url = Some(url);
    let other = Instance::new("pg-other");
    let backup = init_and_back_up(&pg, "backup.json");
    let other_backup = init_and_back_up(&other, "other.json");
    let original = pg.secrets_bytes().unwrap();
    let config = pg.config();
    block_on(async {
        pg.load(&matching(&pg, &[1])).await;
        std::fs::remove_file(&pg.secrets).unwrap();
        assert!(matches!(
            admin::secrets_restore(&config, &other_backup, &pg.passphrase).await,
            Err(AdminError::SecretsBackupMismatch(_))
        ));
        assert!(pg.secrets_bytes().is_none());
        let restored = admin::secrets_restore(&config, &backup, &pg.passphrase)
            .await
            .unwrap();
        assert!(restored.created && !restored.database_empty);
        assert_eq!(pg.secrets_bytes().unwrap(), original);
        open_services(&config).await.unwrap().db.close().await;

        // A setup-only loss (the file's setup 1 replaced), step 4 done by hand as by a run
        // that died before writing the file, then the re-run.
        let broken = ServerSecrets::generate_after_loss(
            &mut ChaCha20Rng::seed_from_u64(3),
            1,
            ServerSetup::generate(&mut ChaCha20Rng::seed_from_u64(4)),
            Some(pg.loaded()),
        );
        std::fs::write(&pg.secrets, secrets_file::serialize(&broken).unwrap()).unwrap();
        let db = open_database(&config).await.unwrap();
        let minted = invalidate_in_database(
            &db,
            LossCase::SetupOnly,
            &ServerSetup::generate(&mut ChaCha20Rng::seed_from_u64(5)).public_key_hash(),
            30,
            30,
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!(minted.setup_id, 2);
        db.close().await;
        match admin::secrets_invalidate(&config, false).await {
            Err(AdminError::ConfirmRequired(InvalidateDiagnosis::Loss {
                case: LossCase::SetupOnly,
                resumed: Some(p),
                ..
            })) if p.setup_id == 2 => {}
            other => panic!("{other:?}"),
        }
        match admin::secrets_invalidate(&config, true).await.unwrap() {
            SecretsInvalidated::Invalidated { outcome, resumed } => {
                assert!(resumed);
                assert_eq!((outcome.setup_id, outcome.totp_rows_deleted), (3, 0));
            }
            other @ SecretsInvalidated::MarkerCleared { .. } => panic!("{other:?}"),
        }
        open_services(&config).await.unwrap().db.close().await;

        // A whole loss.
        std::fs::remove_file(&pg.secrets).unwrap();
        match admin::secrets_invalidate(&config, true).await.unwrap() {
            SecretsInvalidated::Invalidated { outcome, resumed } => {
                assert!(!resumed);
                assert_eq!(
                    (outcome.case, outcome.setup_id, outcome.totp_rows_deleted),
                    (LossCase::Whole, 4, 1)
                );
            }
            other @ SecretsInvalidated::MarkerCleared { .. } => panic!("{other:?}"),
        }
        assert!(pg.loaded().bootstrap_token().is_none());
        open_services(&config).await.unwrap().db.close().await;
    });
}
