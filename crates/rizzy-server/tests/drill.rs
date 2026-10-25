// SPDX-License-Identifier: AGPL-3.0-only

//! The operator's backup → wipe → restore drill, in its fast form ([docs/self-hosting.md] §8–§10;
//! ADR 0011 "Backups"; the threat model §5.8, INV-50, INV-59; ADR 0021 §2).
//!
//! It runs by default (`cargo test`), on real `SQLite` files in a temporary directory, through the
//! same functions the `rizzy-vault` binary runs: `secrets init`, `backup-secrets`, the startup
//! of the `api`/`worker` roles ([`open_services`]), and `backup` and `restore` with the backup
//! file of ADR 0023 ([`admin::backup`], [`admin::restore`]).
//!
//! 1. **Populate.** `secrets init` writes the secrets file; a populated instance is loaded (two
//!    accounts with credentials, TOTP, devices, a revocation, a vault with ops and a
//!    snapshot), and its reconciliation epochs are closed, as on a settled instance. The
//!    server starts on it: the startup checks pass.
//! 2. **Back up**, next to the running server: `rizzy-vault backup --out <file>` on a read-only
//!    reader (ADR 0010 §2: the backup reader takes no writer lock), and `backup-secrets` to an
//!    encrypted file. The backup file holds none of the secrets file's secrets, decoded or as
//!    text (INV-50). `restore` refuses to run next to the running server (writer lock).
//! 3. **Stop** the server and take the native backup: a copy of the data directory.
//! 4. **Wipe** the data directory and the secrets file.
//! 5. **Restore** the secrets from the encrypted backup with `rizzy-vault secrets restore`
//!    (ADR 0047; byte for byte, into the empty database), then the database with
//!    `rizzy-vault restore --in <file>` into an empty database.
//! 6. **Start again.** The startup checks pass; the database reads back exactly as backed up;
//!    the restore generation is new (ADR 0021 §2) and every account is in a reconciliation
//!    epoch of that generation (INV-59). The storage counter, seeded at the first start, comes
//!    back with the rows and matches them (ADR 0048 §4).
//! 7. **Refusals.** A second `restore` into the restored (non-empty) database; a fresh secrets
//!    file next to the restored database (CRYPTO.md §5.8), both at startup and by `restore`
//!    into an empty database, which it leaves empty (ADR 0023 §5 step 4); a damaged backup
//!    file; and a wrong backup passphrase.
//! 8. **The native copy**, restored in place, starts, but keeps the old restore generation and
//!    opens no reconciliation epoch. This pins the warning of the operator docs: a native
//!    restore does not give INV-59's protections, `rizzy-vault restore` does.
//!
//! **Not in this fast form**: the clients. ADR 0011's full drill, with clients that change a
//! password and the Secret Key, enrol and revoke devices and rotate keys after the backup, then
//! reconnect and heal the server (ADR 0032), runs in `rizzy-cli`'s end-to-end tests against the
//! built binary (`tests/healing.rs`, `tests/e2e.rs`); `rizzy-domain-vault` and
//! `rizzy-domain-auth` test the healing requests and the lag rule themselves.
//!
//! [docs/self-hosting.md]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/self-hosting.md

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests: a failure fails the test, which CLAUDE.md allows in test code"
)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rizzy_domain_auth::StartupCheckError;
use rizzy_server::config::{self, Config, Settings, Sources};
use rizzy_server::server::{ServeError, Services, open_services};
use rizzy_server::{admin, db_backup, secrets_backup, secrets_file};
use rizzy_storage::backup::file;
use rizzy_storage::meta::{end_reconciliation_epoch, reconciliation_epochs, restore_generation};
use rizzy_storage::tables::TABLES;
use rizzy_storage::{
    Database, Dump, RestoreError, RestoreGeneration, SqliteOptions, TableDump, Value, WriterLock,
    lock_account, schema_version,
};

/// The canonical origin of the drill's server.
const ORIGIN: &str = "https://vault.example.com";

/// The operator's backup passphrase, as the passphrase file holds it.
const PASSPHRASE: &str = "correct horse battery staple, drill edition\n";

/// The two accounts of the populated instance.
const ACCOUNTS: [u8; 2] = [0xa1, 0xa2];

/// Runs `f` on a current-thread runtime.
fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

/// A temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    /// A new, empty directory.
    fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rizzy-server-drill-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    /// `name` inside it.
    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The configuration of a server with its data directory and secrets file under `root`, the
/// layout of the container image: two directories, the secrets outside the data (ADR 0010 §4).
fn server_config(data: &Path, secrets: &Path) -> Config {
    let mut env: BTreeMap<&'static str, String> = BTreeMap::new();
    env.insert(config::ORIGIN, ORIGIN.to_owned());
    env.insert(config::DATA_DIR, data.to_str().unwrap().to_owned());
    env.insert(config::SECRETS_FILE, secrets.to_str().unwrap().to_owned());
    let lookup = move |key: &str| env.get(key).map(OsString::from);
    Config::from_sources(&Sources {
        file: Settings::new(),
        env: &lookup,
        roles_flag: None,
    })
    .unwrap()
}

/// The `SQLite` file of `config`.
fn sqlite_path(config: &Config) -> PathBuf {
    match &config.database {
        config::DatabaseConfig::Sqlite(path) => path.clone(),
        config::DatabaseConfig::Postgres(_) => panic!("the drill runs on SQLite"),
    }
}

/// A 16-byte id value filled with `n`.
fn idv(n: u8) -> Value {
    Value::Blob(vec![n; 16])
}

/// A blob of `len` bytes filled with `n`.
fn blob(n: u8, len: usize) -> Value {
    Value::Blob(vec![n; len])
}

/// An integer value.
fn int(v: i64) -> Value {
    Value::Integer(v)
}

/// The populated instance: rows in every backed-up table, whose OPAQUE setup and TOTP data key
/// are the ones of `secrets_path`, so the server's startup checks accept it.
#[expect(
    clippy::too_many_lines,
    reason = "one literal row per table, in one place"
)]
fn populated(secrets_path: &Path) -> Dump {
    let secrets = secrets_file::load(secrets_path).unwrap();
    let (setup_id, setup) = secrets.setups().next().unwrap();
    let setup_id = i64::from(setup_id);
    let data_key_id = i64::from(secrets.current_data_key_id());
    let (a1, a2, v1) = (|| idv(ACCOUNTS[0]), || idv(ACCOUNTS[1]), || idv(0xb1));
    let (d1, d2, d3) = (|| idv(0xd1), || idv(0xd2), || idv(0xd3));
    let item = || idv(0xe1);
    let rows: Vec<(&str, Vec<Vec<Value>>)> = vec![
        (
            "auth_accounts",
            vec![
                vec![a1(), Value::Text("alice".into()), int(1_000), Value::Null],
                vec![a2(), Value::Text("bob".into()), int(2_000), Value::Null],
            ],
        ),
        (
            "auth_opaque_setups",
            vec![vec![
                int(setup_id),
                Value::Blob(setup.public_key_hash().to_vec()),
                int(10),
                Value::Null,
            ]],
        ),
        (
            "auth_credentials",
            vec![
                vec![
                    a1(),
                    int(setup_id),
                    blob(2, 200),
                    int(1),
                    int(0),
                    blob(3, 90),
                    int(11),
                    int(0),
                ],
                vec![
                    a2(),
                    int(setup_id),
                    blob(4, 200),
                    int(1),
                    int(2),
                    blob(5, 90),
                    int(12),
                    Value::Null,
                ],
            ],
        ),
        (
            "auth_identity_keys",
            vec![vec![a1(), int(0), blob(6, 100), int(13)]],
        ),
        (
            "auth_recovery",
            vec![vec![
                a1(),
                int(1),
                blob(7, 90),
                blob(8, 32),
                int(14),
                Value::Null,
            ]],
        ),
        (
            "auth_bundles",
            vec![
                vec![a1(), int(1), blob(9, 150), int(15)],
                vec![a1(), int(2), blob(10, 150), int(16)],
            ],
        ),
        (
            "auth_account_states",
            vec![vec![a1(), int(3), blob(11, 250), int(17)]],
        ),
        (
            "auth_account_settings",
            vec![vec![a1(), int(1), blob(12, 80), int(18)]],
        ),
        (
            "auth_retired_secret_keys",
            vec![vec![a1(), idv(0x77), blob(13, 70), int(19)]],
        ),
        (
            "auth_device_certificates",
            vec![
                vec![
                    a1(),
                    d1(),
                    int(0),
                    int(1),
                    int(0),
                    blob(14, 180),
                    Value::Null,
                    int(20),
                ],
                vec![
                    a1(),
                    d2(),
                    int(0),
                    int(4),
                    int(99_999),
                    blob(15, 180),
                    int(21),
                    int(22),
                ],
            ],
        ),
        (
            "auth_device_revocations",
            vec![vec![a1(), d2(), int(7), blob(16, 120), int(23)]],
        ),
        (
            "auth_key_grants",
            vec![vec![a1(), d1(), int(1), d3(), blob(17, 160), int(24)]],
        ),
        // ADR 0077 §4: one security key; its SecurityKey JSON is opaque to the backup.
        (
            "auth_webauthn_credentials",
            vec![vec![
                a1(),
                blob(40, 64),
                int(1),
                Value::Text("{\"cred\":{}}".to_owned()),
                int(1),
                int(9),
                Value::Text("Desk key".to_owned()),
                int(41),
            ]],
        ),
        (
            "auth_totp_credentials",
            vec![vec![
                a1(),
                int(1),
                int(data_key_id),
                blob(18, 60),
                Value::Null,
                int(25),
            ]],
        ),
        (
            "auth_rate_limits",
            vec![vec![blob(19, 20), int(3), int(26), int(0), int(27)]],
        ),
        (
            "auth_pending_recoveries",
            vec![vec![a2(), int(1), int(100), int(200)]],
        ),
        (
            "vault_vaults",
            vec![vec![v1(), a1(), int(0), int(2), int(28), int(1)]],
        ),
        (
            "vault_self_grants",
            vec![vec![v1(), int(0), int(0), blob(20, 90), int(29)]],
        ),
        (
            "vault_item_key_wraps",
            vec![vec![v1(), item(), idv(0x55), int(0), blob(21, 90), int(30)]],
        ),
        (
            "vault_ops",
            vec![
                vec![
                    v1(),
                    d1(),
                    int(1),
                    item(),
                    idv(0x61),
                    int(0),
                    int(1 << 57),
                    int(1),
                    int(0),
                    blob(22, 97),
                    blob(23, 32),
                    blob(24, 32),
                    blob(25, 66),
                    blob(26, 300),
                    blob(27, 90),
                    int(31),
                ],
                vec![
                    v1(),
                    d1(),
                    int(2),
                    item(),
                    idv(0x62),
                    int(1),
                    int((1 << 57) + 1),
                    int(1),
                    int(0),
                    blob(28, 97),
                    blob(29, 32),
                    blob(0, 32),
                    blob(30, 66),
                    Value::Null,
                    Value::Null,
                    int(32),
                ],
            ],
        ),
        (
            "vault_snapshots",
            vec![vec![
                v1(),
                idv(0x71),
                item(),
                d1(),
                int(1),
                int(0),
                blob(31, 100),
                blob(32, 400),
                blob(0, 32),
                blob(33, 66),
                Value::Null,
                blob(34, 26),
                int(5),
                int(33),
            ]],
        ),
        ("vault_compaction_queue", vec![vec![v1(), item(), int(34)]]),
        // ADR 0054 §5: one attachment of 100 bytes, its one chunk stored.
        (
            "vault_attachments",
            vec![vec![
                idv(36),
                v1(),
                item(),
                blob(37, 122),
                int(100),
                int(1),
                int(38),
            ]],
        ),
        (
            "vault_attachment_chunks",
            vec![vec![idv(36), int(0), blob(39, 190)]],
        ),
        (
            "vault_device_cursors",
            vec![vec![v1(), d1(), blob(35, 26), int(35)]],
        ),
        // No counter row: the first start's backfill seeds it from the vault rows (ADR 0048 §4).
        ("storage_account_usage", Vec::new()),
    ];
    let tables: Vec<TableDump> = TABLES
        .iter()
        .map(|spec| TableDump {
            table: spec.name.to_owned(),
            rows: rows
                .iter()
                .find(|(name, _)| *name == spec.name)
                .unwrap_or_else(|| panic!("the drill has no rows for {}", spec.name))
                .1
                .clone(),
        })
        .collect();
    assert_eq!(tables.len(), rows.len(), "a table named twice or unknown");
    Dump {
        schema_version: schema_version(),
        tables,
    }
}

/// Opens the `SQLite` database of `config` with its writer lock, as `restore` would: the
/// server must be stopped.
async fn open_writer(config: &Config) -> Database {
    let path = sqlite_path(config);
    let lock = WriterLock::acquire(&path).unwrap();
    Database::open_sqlite(&SqliteOptions::new(&path), lock)
        .await
        .unwrap()
}

/// The restore generation in force and the accounts in a reconciliation epoch, with the
/// generation each epoch was opened under.
async fn restore_state(db: &Database) -> (RestoreGeneration, Vec<([u8; 16], RestoreGeneration)>) {
    let mut tx = db.begin_read().await.unwrap();
    let generation = restore_generation(tx.conn()).await.unwrap().unwrap();
    let epochs = reconciliation_epochs(tx.conn())
        .await
        .unwrap()
        .into_iter()
        .map(|(account, epoch)| (account, epoch.restore_generation))
        .collect();
    tx.finish().await.unwrap();
    (generation, epochs)
}

/// The first account's storage counter, asserted equal to the true sum of its vault rows (ADR
/// 0048 §4).
async fn usage(db: &Database) -> u64 {
    let account = [ACCOUNTS[0]; 16];
    let mut tx = db.begin_read().await.unwrap();
    let counter = rizzy_storage::quota::bytes_used(tx.conn(), &account)
        .await
        .unwrap();
    let truth = rizzy_domain_vault::usage::counted_bytes(
        tx.conn(),
        rizzy_domain_auth::types::AccountId::from_bytes(account),
    )
    .await
    .unwrap();
    tx.finish().await.unwrap();
    assert_eq!(
        counter, truth,
        "the storage counter does not match the rows"
    );
    counter
}

/// Stops a started server: closes the pools, which releases the writer lock.
async fn stop(services: Services) {
    services.db.close().await;
    drop(services);
}

/// Copies every file of `from` into `to` (a flat directory: the data volume holds files only).
fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        assert!(
            entry.file_type().unwrap().is_file(),
            "a flat data directory"
        );
        std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
    }
}

/// Every secret in a secrets file's bytes, twice: its base64url text as stored, and the
/// decoded bytes. Every string in the file's layout holds a secret (`secrets_file` module
/// docs); the numbers are `format` and the ids.
fn secret_needles(file: &[u8]) -> Vec<Vec<u8>> {
    use base64ct::{Base64UrlUnpadded, Encoding as _};

    /// Collects every string leaf of `value`.
    fn strings(value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::String(s) => out.push(s.clone()),
            serde_json::Value::Array(items) => items.iter().for_each(|v| strings(v, out)),
            serde_json::Value::Object(map) => map.values().for_each(|v| strings(v, out)),
            serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            }
        }
    }

    let parsed: serde_json::Value = serde_json::from_slice(file).unwrap();
    let mut texts = Vec::new();
    strings(&parsed, &mut texts);
    let mut needles = Vec::new();
    for text in texts {
        let decoded = Base64UrlUnpadded::decode_vec(&text).unwrap();
        assert!(decoded.len() >= 32, "a secret, not a label");
        needles.push(text.into_bytes());
        needles.push(decoded);
    }
    needles
}

/// Whether `haystack` contains `needle`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the drill reads top to bottom as the operator runs it"
)]
fn backup_wipe_restore_drill() {
    block_on(async {
        let root = TempDir::new();
        let data = root.join("data");
        let secrets_dir = root.join("secrets");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&secrets_dir).unwrap();
        let secrets_path = secrets_dir.join("secrets.json");
        let config = server_config(&data, &secrets_path);

        // 1. Populate: `secrets init`, a populated instance with its epochs closed, a start.
        admin::secrets_init(&config).unwrap();
        let original_secrets = std::fs::read(&secrets_path).unwrap();
        let instance = populated(&secrets_path);
        let before = RestoreGeneration([0x11; 16]);
        {
            let db = open_writer(&config).await;
            db.restore(&instance, before, 1_000).await.unwrap();
            for account in ACCOUNTS {
                let mut tx = db.begin_write().await.unwrap();
                lock_account(&mut tx, &[account; 16]).await.unwrap();
                assert!(
                    end_reconciliation_epoch(&mut tx, &[account; 16])
                        .await
                        .unwrap()
                );
                tx.commit().await.unwrap();
            }
            db.close().await;
        }
        let services = open_services(&config).await.unwrap();
        assert_eq!(restore_state(&services.db).await, (before, Vec::new()));
        // ADR 0048 §4: the start seeded the account's storage counter from its vault rows.
        let seeded = usage(&services.db).await;
        assert!(seeded > 0);

        // 2. Back up next to the running server: `backup` on a read-only reader, and the
        //    encrypted secrets backup. `restore` cannot run next to it.
        let backup_path = root.join("db.rvbackup");
        let summary = admin::backup(&config, &backup_path, false).await.unwrap();
        let backup_file = std::fs::read(&backup_path).unwrap();
        assert_eq!(summary.len, backup_file.len());
        assert_eq!(
            summary.digest.as_slice(),
            &backup_file[backup_file.len() - file::DIGEST_LEN..]
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&backup_path)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the database backup is private");
        }
        let backup = file::parse(&backup_file).unwrap().dump;
        assert_eq!(backup.schema_version, schema_version());
        assert!(matches!(
            admin::restore(&config, &backup_path).await,
            Err(admin::AdminError::Lock(_))
        ));
        let backed_up_rows: usize = backup.tables.iter().map(|t| t.rows.len()).sum();
        assert!(backed_up_rows > 20, "the populated instance is backed up");
        let passphrase_file = root.join("passphrase");
        std::fs::write(&passphrase_file, PASSPHRASE).unwrap();
        let secrets_backup_path = root.join("secrets-backup.json");
        admin::backup_secrets(&config, &secrets_backup_path, &passphrase_file).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&secrets_backup_path)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the secrets backup is private");
        }
        // INV-50: nothing of the secrets file is in the database backup. Every secret the file
        // holds is searched for, both decoded and in its base64url text form: each
        // `server_setup` (OPRF seed and server keypair), `enum_key`, each data key and the
        // bootstrap token.
        let needles = secret_needles(&original_secrets);
        let loaded = secrets_file::load(&secrets_path).unwrap();
        let expected_secrets = loaded.setups().count() + loaded.data_keys().count() + 2;
        assert_eq!(
            needles.len(),
            2 * expected_secrets,
            "every secret of the file is searched for"
        );
        for table in &backup.tables {
            for value in table.rows.iter().flatten() {
                let bytes = match value {
                    Value::Blob(b) => b.as_slice(),
                    Value::Text(t) => t.as_bytes(),
                    Value::Null | Value::Integer(_) => continue,
                };
                for needle in &needles {
                    assert!(!contains(bytes, needle), "{}", table.table);
                }
            }
        }
        // And in the file's bytes as a whole, across value boundaries.
        for needle in &needles {
            assert!(!contains(&backup_file, needle), "the backup file");
        }

        // 3. Stop, and take the native backup: the whole data directory, server stopped.
        stop(services).await;
        let native = root.join("native-backup");
        copy_dir(&data, &native);

        // 4. Wipe the data directory and the secrets file.
        std::fs::remove_dir_all(&data).unwrap();
        std::fs::remove_file(&secrets_path).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        assert!(matches!(
            open_services(&config).await,
            Err(ServeError::Secrets(_))
        ));

        // 5. Restore: the secrets from their encrypted backup with `secrets restore` (ADR 0047;
        //    the empty database has nothing to check it against), byte for byte, then the
        //    database, which checks the secrets against the backup.
        let file = std::fs::read(&secrets_backup_path).unwrap();
        let opened = secrets_backup::open(&file, PASSPHRASE.trim_end()).unwrap();
        assert_eq!(opened.expose_secret(), original_secrets.as_slice());
        let restored = admin::secrets_restore(&config, &secrets_backup_path, &passphrase_file)
            .await
            .unwrap();
        assert!(restored.created && restored.database_empty);
        assert!(restored.missing_setups.is_empty());
        assert_eq!(std::fs::read(&secrets_path).unwrap(), original_secrets);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&secrets_path)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the restored secrets file is private");
        }
        let report = admin::restore(&config, &backup_path).await.unwrap();
        assert_eq!(report.rows, u64::try_from(backed_up_rows).unwrap());
        assert_eq!(report.accounts_in_reconciliation, ACCOUNTS.len() as u64);

        // 6. Start again: the checks pass, the data is back, a new generation, every account
        //    in a reconciliation epoch of that generation.
        let services = open_services(&config).await.unwrap();
        let (after, epochs) = restore_state(&services.db).await;
        assert_ne!(after, before);
        let mut accounts: Vec<[u8; 16]> = epochs.iter().map(|(a, _)| *a).collect();
        accounts.sort_unstable();
        assert_eq!(accounts, ACCOUNTS.map(|a| [a; 16]).to_vec());
        assert!(epochs.iter().all(|(_, g)| *g == after));
        assert_eq!(services.db.dump().await.unwrap(), backup);
        // ADR 0048 §4: the restored counter matches the restored rows.
        assert_eq!(usage(&services.db).await, seeded);
        stop(services).await;

        // 7. Refusals.
        assert!(matches!(
            admin::restore(&config, &backup_path).await,
            Err(admin::AdminError::Storage(rizzy_storage::Error::Restore(
                RestoreError::TargetNotEmpty
            )))
        ));
        let fresh_dir = root.join("fresh-secrets");
        std::fs::create_dir_all(&fresh_dir).unwrap();
        let fresh = server_config(&data, &fresh_dir.join("secrets.json"));
        admin::secrets_init(&fresh).unwrap();
        assert!(matches!(
            open_services(&fresh).await,
            Err(ServeError::SecretsMismatch(_))
        ));
        // `restore` checks the secrets before it loads anything, and leaves the target empty.
        let empty_dir = root.join("empty-data");
        std::fs::create_dir_all(&empty_dir).unwrap();
        let fresh_empty = server_config(&empty_dir, &fresh_dir.join("secrets.json"));
        assert!(matches!(
            admin::restore(&fresh_empty, &backup_path).await,
            Err(admin::AdminError::SecretsMismatch(
                StartupCheckError::SetupMismatch { .. }
            ))
        ));
        {
            let db = open_writer(&fresh_empty).await;
            db.check_restore_target().await.unwrap();
            db.close().await;
        }
        // A damaged file is refused by its digest, before the secrets or the database.
        let damaged_path = root.join("damaged.rvbackup");
        let mut damaged = backup_file.clone();
        let middle = damaged.len() / 2;
        damaged[middle] ^= 0x40;
        std::fs::write(&damaged_path, &damaged).unwrap();
        let empty = server_config(&empty_dir, &secrets_path);
        assert!(matches!(
            admin::restore(&empty, &damaged_path).await,
            Err(admin::AdminError::BackupFile(
                file::FileError::DigestMismatch
            ))
        ));
        assert!(matches!(
            secrets_backup::open(&file, "not the passphrase"),
            Err(secrets_backup::BackupError::Decrypt)
        ));

        // 8. The native copy, restored in place: it starts, but with the old generation and no
        //    reconciliation epoch (the operator docs' warning).
        std::fs::remove_dir_all(&data).unwrap();
        copy_dir(&native, &data);
        let services = open_services(&config).await.unwrap();
        assert_eq!(restore_state(&services.db).await, (before, Vec::new()));
        assert_eq!(services.db.dump().await.unwrap(), backup);
        stop(services).await;
    });
}

/// The configuration of [`server_config`] on the `PostgreSQL` database at `url`.
fn postgres_config(data: &Path, secrets: &Path, url: &str) -> Config {
    let mut env: BTreeMap<&'static str, String> = BTreeMap::new();
    env.insert(config::ORIGIN, ORIGIN.to_owned());
    env.insert(config::DATA_DIR, data.to_str().unwrap().to_owned());
    env.insert(config::SECRETS_FILE, secrets.to_str().unwrap().to_owned());
    env.insert(config::DATABASE_URL, url.to_owned());
    let lookup = move |key: &str| env.get(key).map(OsString::from);
    Config::from_sources(&Sources {
        file: Settings::new(),
        env: &lookup,
        roles_flag: None,
    })
    .unwrap()
}

/// The format version 1 file inside a format version 2 backup, opened with `secrets_path`.
fn opened_backup(secrets_path: &Path, encrypted: &[u8]) -> file::BackupFile {
    let secrets = secrets_file::load(secrets_path).unwrap();
    let plain = db_backup::open(|id| secrets.backup_key(id), encrypted).unwrap();
    file::parse(&plain).unwrap()
}

/// The encrypted variant of the drill (ADR 0071; docs/self-hosting.md, "Encrypted backups"):
/// `secrets rotate --backup-key`, `backup --encrypt` next to the running server, a second
/// rotation (the backup stays restorable under its older key), wipe, `restore` from the
/// encrypted file, and the refusals: no backup key, a tampered file, another instance's
/// secrets file.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the drill reads top to bottom as the operator runs it"
)]
fn encrypted_backup_wipe_restore_drill() {
    block_on(async {
        let root = TempDir::new();
        let data = root.join("data");
        let secrets_dir = root.join("secrets");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&secrets_dir).unwrap();
        let secrets_path = secrets_dir.join("secrets.json");
        let config = server_config(&data, &secrets_path);
        admin::secrets_init(&config).unwrap();
        let instance = populated(&secrets_path);
        let before = RestoreGeneration([0x22; 16]);
        {
            let db = open_writer(&config).await;
            db.restore(&instance, before, 1_000).await.unwrap();
            db.close().await;
        }

        // No backup key yet: --encrypt is a usage error, and nothing is written.
        let backup_path = root.join("db.rvbackup");
        let refused = admin::backup(&config, &backup_path, true)
            .await
            .unwrap_err();
        assert!(matches!(refused, admin::AdminError::NoBackupKey));
        assert!(refused.is_usage());
        assert!(!backup_path.exists());

        // 1. The operator adds a backup key (server stopped), and keeps a secrets backup.
        let rotated = admin::secrets_rotate(&config, admin::Rotate::BackupKey)
            .await
            .unwrap();
        assert_eq!(rotated.id, 1);
        let secrets_with_key = std::fs::read(&secrets_path).unwrap();

        // 2. Back up, encrypted, next to the running server.
        let services = open_services(&config).await.unwrap();
        let summary = admin::backup(&config, &backup_path, true).await.unwrap();
        let encrypted = std::fs::read(&backup_path).unwrap();
        assert_eq!(summary.len, encrypted.len());
        assert_eq!(
            summary.encrypted,
            Some(admin::EncryptedSummary {
                backup_key_id: 1,
                chunk_count: 1
            })
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&backup_path)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the encrypted backup is private");
        }
        assert_eq!(db_backup::format_version(&encrypted), Some(2));
        let header = db_backup::parse_header(&encrypted).unwrap();
        assert_eq!(header.backup_key_id, 1);
        let inner = opened_backup(&secrets_path, &encrypted);
        assert_eq!(inner.created_at_ms, header.created_at_ms);
        let backup = inner.dump;
        assert_eq!(backup.schema_version, schema_version());
        // The payload's digest is the plain file's; it is not in the encrypted file.
        let plain = file::write(&backup, header.created_at_ms).unwrap();
        assert_eq!(
            summary.digest,
            file::digest(&plain[..plain.len() - file::DIGEST_LEN])
        );
        // Confidentiality (ADR 0071, superseding ADR 0023 §2 for version 2): no table name, no
        // row value, no secret of the secrets file appears in the encrypted file.
        for spec in TABLES {
            assert!(!contains(&encrypted, spec.name.as_bytes()), "{}", spec.name);
        }
        for table in &backup.tables {
            for value in table.rows.iter().flatten() {
                let bytes: &[u8] = match value {
                    Value::Blob(b) => b,
                    Value::Text(t) => t.as_bytes(),
                    Value::Null | Value::Integer(_) => continue,
                };
                if bytes.len() >= 16 {
                    assert!(!contains(&encrypted, bytes), "{}", table.table);
                }
            }
        }
        for needle in secret_needles(&secrets_with_key) {
            assert!(!contains(&encrypted, &needle), "a secret in the backup");
        }
        stop(services).await;

        // 3. A later rotation: new backups use key 2, and this one still restores with key 1.
        let rotated = admin::secrets_rotate(&config, admin::Rotate::BackupKey)
            .await
            .unwrap();
        assert_eq!(rotated.id, 2);
        let secrets = secrets_file::load(&secrets_path).unwrap();
        assert_eq!(secrets.current_backup_key_id(), Some(2));
        drop(secrets);

        // 4. Refusals into an empty database, each leaving it empty.
        let empty_dir = root.join("empty-data");
        std::fs::create_dir_all(&empty_dir).unwrap();
        let empty = server_config(&empty_dir, &secrets_path);
        let mut damaged = encrypted.clone();
        let last = damaged.len() - 20;
        damaged[last] ^= 0x01;
        let damaged_path = root.join("damaged.rvbackup");
        std::fs::write(&damaged_path, &damaged).unwrap();
        assert!(matches!(
            admin::restore(&empty, &damaged_path).await,
            Err(admin::AdminError::DbBackup(
                db_backup::DbBackupError::Authentication { chunk_index: 0 }
            ))
        ));
        let mut truncated = encrypted.clone();
        truncated.truncate(truncated.len() - 1);
        let truncated_path = root.join("truncated.rvbackup");
        std::fs::write(&truncated_path, &truncated).unwrap();
        assert!(matches!(
            admin::restore(&empty, &truncated_path).await,
            Err(admin::AdminError::DbBackup(
                db_backup::DbBackupError::Malformed(_)
            ))
        ));
        // Another instance's secrets file: without a backup key 1, then with its own key 1 (the
        // key-id check fails).
        let other_dir = root.join("other-secrets");
        std::fs::create_dir_all(&other_dir).unwrap();
        let other = server_config(&empty_dir, &other_dir.join("secrets.json"));
        admin::secrets_init(&other).unwrap();
        assert!(matches!(
            admin::restore(&other, &backup_path).await,
            Err(admin::AdminError::DbBackup(
                db_backup::DbBackupError::UnknownBackupKey { backup_key_id: 1 }
            ))
        ));
        admin::secrets_rotate(&other, admin::Rotate::BackupKey)
            .await
            .unwrap();
        assert!(matches!(
            admin::restore(&other, &backup_path).await,
            Err(admin::AdminError::DbBackup(
                db_backup::DbBackupError::Authentication { chunk_index: 0 }
            ))
        ));
        {
            let db = open_writer(&empty).await;
            db.check_restore_target().await.unwrap();
            db.close().await;
        }

        // 5. Wipe the data directory (the secrets file stays: it holds the backup keys) and
        //    restore from the encrypted file.
        std::fs::remove_dir_all(&data).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let report = admin::restore(&config, &backup_path).await.unwrap();
        let backed_up_rows: usize = backup.tables.iter().map(|t| t.rows.len()).sum();
        assert_eq!(report.rows, u64::try_from(backed_up_rows).unwrap());

        // 6. Start again: the checks pass, the data is back, a new restore generation.
        let services = open_services(&config).await.unwrap();
        let (after, epochs) = restore_state(&services.db).await;
        assert_ne!(after, before);
        assert_eq!(epochs.len(), ACCOUNTS.len());
        assert_eq!(services.db.dump().await.unwrap(), backup);
        stop(services).await;
    });
}

/// The encrypted backup on `PostgreSQL` (ADR 0071; ADR 0023 §5 step 1, §6): a format version 2
/// file from the `SQLite` drill instance is refused into the empty `PostgreSQL` database when
/// tampered, then restored into it; `backup --encrypt` from `PostgreSQL` (its `REPEATABLE READ`
/// reader) gives the same dump back, which restores into a fresh `SQLite` database.
///
/// `#[ignore]`d by default: run with `RIZZY_TEST_POSTGRES_URL` naming an **empty** database
/// (it is migrated and filled), e.g. `RIZZY_TEST_POSTGRES_URL=postgres://rizzy:rizzy@127.0.0.1:
/// 55432/rizzy_m8_db_backup cargo test -p rizzy-server --test drill -- --ignored`.
#[test]
#[ignore = "needs RIZZY_TEST_POSTGRES_URL: an empty PostgreSQL database"]
fn postgres_encrypted_backup_restore_drill() {
    let url = std::env::var("RIZZY_TEST_POSTGRES_URL").unwrap();
    block_on(async {
        let root = TempDir::new();
        let sqlite_data = root.join("sqlite-data");
        let pg_data = root.join("pg-data");
        let back_data = root.join("back-data");
        let secrets_dir = root.join("secrets");
        for dir in [&sqlite_data, &pg_data, &back_data, &secrets_dir] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let secrets_path = secrets_dir.join("secrets.json");
        let sqlite = server_config(&sqlite_data, &secrets_path);
        let pg = postgres_config(&pg_data, &secrets_path, &url);
        admin::secrets_init(&sqlite).unwrap();
        admin::secrets_rotate(&sqlite, admin::Rotate::BackupKey)
            .await
            .unwrap();
        let instance = populated(&secrets_path);
        {
            let db = open_writer(&sqlite).await;
            db.restore(&instance, RestoreGeneration([0x33; 16]), 1_000)
                .await
                .unwrap();
            db.close().await;
        }
        // One start, as on a running instance: it seeds the storage counter (ADR 0048 §4),
        // which a restore rebuilds.
        stop(open_services(&sqlite).await.unwrap()).await;
        let from_sqlite = root.join("from-sqlite.rvbackup");
        admin::backup(&sqlite, &from_sqlite, true).await.unwrap();
        let encrypted = std::fs::read(&from_sqlite).unwrap();
        let backup = opened_backup(&secrets_path, &encrypted).dump;

        // The PostgreSQL target: migrated explicitly (ADR 0011 point 9), then a tampered file is
        // refused and leaves it empty, so the real restore below still runs.
        admin::migrate(&pg).await.unwrap();
        let mut damaged = encrypted.clone();
        damaged[db_backup::HEADER_LEN + 50] ^= 0x80;
        let damaged_path = root.join("damaged.rvbackup");
        std::fs::write(&damaged_path, &damaged).unwrap();
        assert!(matches!(
            admin::restore(&pg, &damaged_path).await,
            Err(admin::AdminError::DbBackup(
                db_backup::DbBackupError::Authentication { chunk_index: 0 }
            ))
        ));
        admin::restore(&pg, &from_sqlite).await.unwrap();

        // An encrypted backup from PostgreSQL holds the same dump, and the server starts on it
        // (its startup checks pass; the first start then seeds the storage counter, ADR 0048).
        let from_pg = root.join("from-pg.rvbackup");
        let summary = admin::backup(&pg, &from_pg, true).await.unwrap();
        assert_eq!(summary.encrypted.unwrap().backup_key_id, 1);
        let encrypted_pg = std::fs::read(&from_pg).unwrap();
        assert_eq!(opened_backup(&secrets_path, &encrypted_pg).dump, backup);
        let services = open_services(&pg).await.unwrap();
        services.db.close().await;
        drop(services);

        // And back into a fresh SQLite database.
        let back = server_config(&back_data, &secrets_path);
        admin::restore(&back, &from_pg).await.unwrap();
        let services = open_services(&back).await.unwrap();
        assert_eq!(services.db.dump().await.unwrap(), backup);
        stop(services).await;
    });
}
