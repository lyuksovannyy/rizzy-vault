// SPDX-License-Identifier: AGPL-3.0-only

//! Shared helpers of the integration tests: a tokio runtime, temporary directories, and a
//! fixture dump that fills every backed-up table.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rizzy_storage::tables::TABLES;
use rizzy_storage::{Dump, TableDump, Value, on_engine, schema_version};

/// Runs `f` to completion on a current-thread tokio runtime.
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
)]
pub(crate) fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

/// A temporary directory, removed on drop.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    /// A new, empty directory under the system temporary directory.
    #[expect(
        clippy::unwrap_used,
        reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
    )]
    pub(crate) fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rizzy-storage-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    /// `name` inside the directory.
    pub(crate) fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A 16-byte id filled with `n`.
pub(crate) fn id(n: u8) -> [u8; 16] {
    [n; 16]
}

/// A blob value of `len` bytes filled with `n`.
pub(crate) fn blob(n: u8, len: usize) -> Value {
    Value::Blob(vec![n; len])
}

/// A 16-byte id value.
pub(crate) fn idv(n: u8) -> Value {
    blob(n, 16)
}

/// An integer value.
pub(crate) fn int(v: i64) -> Value {
    Value::Integer(v)
}

/// The first account of the fixture.
pub(crate) const ACCOUNT_1: u8 = 0xa1;
/// The second account of the fixture.
pub(crate) const ACCOUNT_2: u8 = 0xa2;
/// The fixture's vault.
pub(crate) const VAULT_1: u8 = 0xb1;

/// A dump with rows in every backed-up table, including NULLs, 32-byte hashes, a bodiless op
/// and a vault whose store-sequence counter (2) is below its highest snapshot `store_seq` (5).
#[expect(
    clippy::too_many_lines,
    reason = "one literal row per table, in one place"
)]
#[expect(
    clippy::panic,
    reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
)]
pub(crate) fn fixture() -> Dump {
    let a1 = || idv(ACCOUNT_1);
    let a2 = || idv(ACCOUNT_2);
    let v1 = || idv(VAULT_1);
    let (d1, d2, d3) = (|| idv(0xd1), || idv(0xd2), || idv(0xd3));
    let item = || idv(0xe1);
    let rows: Vec<(&str, Vec<Vec<Value>>)> = vec![
        (
            "auth_accounts",
            vec![
                vec![a1(), Value::Text("alice".into()), int(1_000), Value::Null],
                vec![a2(), Value::Text("bob".into()), int(2_000), int(2_500)],
            ],
        ),
        (
            "auth_opaque_setups",
            vec![vec![int(1), blob(1, 32), int(10), Value::Null]],
        ),
        (
            "auth_credentials",
            vec![vec![
                a1(),
                int(1),
                blob(2, 200),
                int(1),
                int(0),
                blob(3, 90),
                int(11),
                int(2),
            ]],
        ),
        (
            "auth_identity_keys",
            vec![vec![a1(), int(0), blob(4, 100), int(12)]],
        ),
        (
            "auth_recovery",
            vec![vec![
                a1(),
                int(1),
                blob(5, 90),
                blob(6, 32),
                int(13),
                Value::Null,
            ]],
        ),
        (
            "auth_bundles",
            vec![
                vec![a1(), int(1), blob(7, 150), int(14)],
                vec![a1(), int(2), blob(8, 150), int(15)],
            ],
        ),
        (
            "auth_account_states",
            vec![vec![a1(), int(3), blob(9, 250), int(16)]],
        ),
        (
            "auth_account_settings",
            vec![vec![a1(), int(1), blob(10, 80), int(17)]],
        ),
        (
            "auth_retired_secret_keys",
            vec![vec![a1(), idv(0x77), blob(11, 70), int(18)]],
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
                    blob(12, 180),
                    Value::Null,
                    int(19),
                ],
                vec![
                    a1(),
                    d2(),
                    int(0),
                    int(4),
                    int(99_999),
                    blob(13, 180),
                    int(20),
                    int(21),
                ],
            ],
        ),
        (
            "auth_device_revocations",
            vec![vec![a1(), d2(), int(7), blob(14, 120), int(22)]],
        ),
        (
            "auth_key_grants",
            vec![vec![a1(), d1(), int(1), d3(), blob(15, 160), int(23)]],
        ),
        // ADR 0077 §4: one ES256 security key, its SecurityKey JSON opaque to storage.
        (
            "auth_webauthn_credentials",
            vec![vec![
                a1(),
                blob(46, 64),
                int(1),
                Value::Text("{\"cred\":{}}".to_owned()),
                int(1),
                int(7),
                Value::Text("YubiKey".to_owned()),
                int(47),
            ]],
        ),
        (
            "auth_totp_credentials",
            vec![vec![
                a1(),
                int(1),
                int(0),
                blob(16, 60),
                Value::Null,
                int(24),
            ]],
        ),
        (
            "auth_rate_limits",
            vec![vec![blob(17, 20), int(3), int(25), int(0), int(26)]],
        ),
        (
            "auth_pending_recoveries",
            vec![vec![a2(), int(1), int(100), int(200)]],
        ),
        (
            "vault_vaults",
            vec![vec![v1(), a1(), int(0), int(2), int(27), int(1)]],
        ),
        (
            "vault_self_grants",
            vec![vec![v1(), int(0), int(0), blob(18, 90), int(28)]],
        ),
        (
            "vault_item_key_wraps",
            vec![vec![v1(), item(), idv(0x55), int(0), blob(19, 90), int(29)]],
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
                    blob(20, 97),
                    blob(21, 32),
                    blob(22, 32),
                    blob(23, 66),
                    blob(24, 300),
                    blob(25, 90),
                    int(30),
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
                    blob(26, 97),
                    blob(27, 32),
                    blob(0, 32),
                    blob(28, 66),
                    Value::Null,
                    Value::Null,
                    int(31),
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
                blob(29, 100),
                blob(30, 400),
                blob(0, 32),
                blob(31, 66),
                Value::Null,
                blob(32, 26),
                int(5),
                int(32),
            ]],
        ),
        ("vault_compaction_queue", vec![vec![v1(), item(), int(33)]]),
        (
            "vault_device_cursors",
            vec![vec![v1(), d1(), blob(33, 26), int(34)]],
        ),
        // ADR 0054 §5: one attachment of 524 289 bytes (two chunks), both chunks stored.
        (
            "vault_attachments",
            vec![vec![
                idv(40),
                v1(),
                idv(41),
                blob(42, 122),
                int(524_289),
                int(2),
                int(43),
            ]],
        ),
        (
            "vault_attachment_chunks",
            vec![
                vec![idv(40), int(0), blob(44, 524_378)],
                vec![idv(40), int(1), blob(45, 91)],
            ],
        ),
        (
            "storage_account_usage",
            vec![vec![a1(), int(1_234), int(35)]],
        ),
    ];
    // Keep the fixture in TABLES order, and make sure it covers every table.
    let tables: Vec<TableDump> = TABLES
        .iter()
        .map(|spec| {
            let rows = rows
                .iter()
                .find(|(name, _)| *name == spec.name)
                .unwrap_or_else(|| panic!("the fixture has no rows for {}", spec.name))
                .1
                .clone();
            TableDump {
                table: spec.name.to_owned(),
                rows,
            }
        })
        .collect();
    assert_eq!(
        tables.len(),
        rows.len(),
        "the fixture names a table twice or an unknown one"
    );
    Dump {
        schema_version: schema_version(),
        tables,
    }
}

/// The fixture as a restore leaves it: the vault's store-sequence counter raised to 6.
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
)]
pub(crate) fn fixture_after_restore() -> Dump {
    let mut d = fixture();
    let vaults = d
        .tables
        .iter_mut()
        .find(|t| t.table == "vault_vaults")
        .unwrap();
    vaults.rows[0][3] = int(6);
    d
}

/// The per-account counter of ADR 0048 §3–§4, on either engine. Needs `fixture()` restored:
/// `ACCOUNT_1` has a row of 1 234 bytes, `ACCOUNT_2` none.
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
)]
pub(crate) async fn exercise_quota(db: &rizzy_storage::Database) {
    use rizzy_storage::lock_account;
    use rizzy_storage::quota::{Drift, accounts, adjust, bytes_used, reconcile};
    let (a1, a2) = (id(ACCOUNT_1), id(ACCOUNT_2));
    let mut r = db.begin_read().await.unwrap();
    assert_eq!(bytes_used(r.conn(), &a1).await.unwrap(), 1_234);
    assert_eq!(
        bytes_used(r.conn(), &a2).await.unwrap(),
        0,
        "no row reads as 0"
    );
    assert_eq!(accounts(r.conn()).await.unwrap(), vec![a1]);
    r.finish().await.unwrap();

    let mut w = db.begin_write().await.unwrap();
    lock_account(&mut w, &a1).await.unwrap();
    assert_eq!(adjust(&mut w, &a1, 766, 40).await.unwrap(), 2_000);
    assert_eq!(adjust(&mut w, &a1, -500, 41).await.unwrap(), 1_500);
    // A credit larger than the value stops at 0 (drift; the next pass corrects it).
    assert_eq!(adjust(&mut w, &a1, -9_999, 42).await.unwrap(), 0);
    lock_account(&mut w, &a2).await.unwrap();
    // The upsert: an account with no row starts from 0.
    assert_eq!(adjust(&mut w, &a2, 10, 43).await.unwrap(), 10);
    w.commit().await.unwrap();

    let mut w = db.begin_write().await.unwrap();
    lock_account(&mut w, &a1).await.unwrap();
    assert_eq!(
        reconcile(&mut w, &a1, 700, false, 44).await.unwrap(),
        Some(Drift { was: 0, now: 700 })
    );
    assert_eq!(reconcile(&mut w, &a1, 700, false, 45).await.unwrap(), None);
    w.commit().await.unwrap();
    let mut r = db.begin_read().await.unwrap();
    assert_eq!(bytes_used(r.conn(), &a1).await.unwrap(), 700);
    assert_eq!(bytes_used(r.conn(), &a2).await.unwrap(), 10);
    assert_eq!(accounts(r.conn()).await.unwrap(), vec![a1, a2]);
    r.finish().await.unwrap();

    // Seeding writes a row of 0 for an account without one; without `seed`, 0 writes nothing.
    let mut w = db.begin_write().await.unwrap();
    on_engine!(w.conn(), |c| sqlx::query(
        "DELETE FROM storage_account_usage WHERE account_id = $1"
    )
    .bind(&a2[..])
    .execute(&mut *c)
    .await
    .unwrap()
    .rows_affected());
    lock_account(&mut w, &a2).await.unwrap();
    assert_eq!(reconcile(&mut w, &a2, 0, false, 46).await.unwrap(), None);
    w.commit().await.unwrap();
    let mut r = db.begin_read().await.unwrap();
    assert_eq!(accounts(r.conn()).await.unwrap(), vec![a1]);
    r.finish().await.unwrap();
    let mut w = db.begin_write().await.unwrap();
    lock_account(&mut w, &a2).await.unwrap();
    assert_eq!(reconcile(&mut w, &a2, 0, true, 47).await.unwrap(), None);
    w.commit().await.unwrap();
    let mut r = db.begin_read().await.unwrap();
    assert_eq!(accounts(r.conn()).await.unwrap(), vec![a1, a2]);
    r.finish().await.unwrap();
}

/// Runs one statement in its own write transaction; `Err` when the engine refuses it.
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
)]
async fn try_exec(
    db: &rizzy_storage::Database,
    statement: &'static str,
    bytes: &[[u8; 16]],
) -> bool {
    let mut w = db.begin_write().await.unwrap();
    let ok = on_engine!(w.conn(), |c| {
        let mut q = sqlx::query(statement);
        for b in bytes {
            q = q.bind(&b[..]);
        }
        q.execute(&mut *c).await.is_ok()
    });
    if ok {
        w.commit().await.unwrap();
    } else {
        w.rollback().await.unwrap();
    }
    ok
}

/// The vault kinds of migration 0009 (ADR 0081 §A10), on either engine: the partial unique
/// index keeps one Personal vault per account and allows any number of owned ones, the CHECK
/// refuses another kind, and the migration itself fails loudly on an account that already has
/// two vaults. Needs `fixture()` restored (`ACCOUNT_1` owns vault `0xb1…` as kind 1) and every
/// migration applied. Leaves migration 9 pending and the second vault in place: the caller
/// closes this handle (sqlx keeps PostgreSQL's migration advisory lock on the connection of a
/// failed run) and calls [`finish_vault_kinds`] on a new one.
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
)]
pub(crate) async fn exercise_vault_kinds(db: &rizzy_storage::Database) {
    let (a1, a2) = (id(ACCOUNT_1), id(ACCOUNT_2));
    let insert = "INSERT INTO vault_vaults (id, account_id, vault_key_epoch, created_at_ms) \
                  VALUES ($1, $2, 0, 1)";
    let insert_kind = |kind: u8| match kind {
        0 => {
            "INSERT INTO vault_vaults (id, account_id, vault_key_epoch, created_at_ms, kind) \
              VALUES ($1, $2, 0, 1, 0)"
        }
        2 => {
            "INSERT INTO vault_vaults (id, account_id, vault_key_epoch, created_at_ms, kind) \
              VALUES ($1, $2, 0, 1, 2)"
        }
        _ => {
            "INSERT INTO vault_vaults (id, account_id, vault_key_epoch, created_at_ms, kind) \
              VALUES ($1, $2, 0, 1, 3)"
        }
    };
    // A second Personal vault (the default kind) for the same account is refused.
    assert!(!try_exec(db, insert, &[id(0xc1), a1]).await);
    // Owned vaults: any number.
    assert!(try_exec(db, insert_kind(2), &[id(0xc2), a1]).await);
    assert!(try_exec(db, insert_kind(2), &[id(0xc3), a1]).await);
    // Another account's Personal vault is its own.
    assert!(try_exec(db, insert, &[id(0xc4), a2]).await);
    // Kind 3 (joined) is Part B's and has no row; 0 is invalid.
    assert!(!try_exec(db, insert_kind(3), &[id(0xc5), a1]).await);
    assert!(!try_exec(db, insert_kind(0), &[id(0xc6), a1]).await);
    // An owned vault cannot become a second Personal vault.
    assert!(
        !try_exec(
            db,
            "UPDATE vault_vaults SET kind = 1 WHERE id = $1",
            &[id(0xc2)]
        )
        .await
    );
    for v in [0xc2, 0xc3, 0xc4] {
        assert!(try_exec(db, "DELETE FROM vault_vaults WHERE id = $1", &[id(v)]).await);
    }

    // The migration on a database where one account has two vaults fails and changes nothing.
    // Migration 10 (ADR 0045's `last_recovery_at_ms`) came after it; undo both, newest first.
    let last = crate::common::last_migration();
    assert_eq!(last, 10, "the last-recovery migration is the last one");
    for undo in [
        "ALTER TABLE auth_accounts DROP COLUMN last_recovery_at_ms",
        "DELETE FROM _sqlx_migrations WHERE version = 10",
        "DROP INDEX vault_vaults_personal",
        "ALTER TABLE vault_vaults DROP COLUMN kind",
        "DELETE FROM _sqlx_migrations WHERE version = 9",
    ] {
        assert!(try_exec(db, undo, &[]).await, "{undo}");
    }
    assert!(try_exec(db, insert, &[id(0xc1), a1]).await);
    assert!(db.migrate().await.is_err());
    assert_eq!(db.pending_migrations().await.unwrap(), vec![9, 10]);
}

/// The second half of [`exercise_vault_kinds`], on a fresh handle: without the second vault
/// the migration applies, and the existing vault becomes the Personal vault.
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
)]
pub(crate) async fn finish_vault_kinds(db: &rizzy_storage::Database) {
    let a1 = id(ACCOUNT_1);
    assert_eq!(db.pending_migrations().await.unwrap(), vec![9, 10]);
    assert!(try_exec(db, "DELETE FROM vault_vaults WHERE id = $1", &[id(0xc1)]).await);
    db.migrate().await.unwrap();
    assert!(db.pending_migrations().await.unwrap().is_empty());
    let mut r = db.begin_read().await.unwrap();
    let kind: i64 = on_engine!(r.conn(), |c| sqlx::query_scalar(
        "SELECT kind FROM vault_vaults WHERE account_id = $1"
    )
    .bind(&a1[..])
    .fetch_one(&mut *c)
    .await
    .unwrap());
    r.finish().await.unwrap();
    assert_eq!(kind, 1, "an existing vault becomes the Personal vault");
}

/// The version of the last embedded migration.
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
)]
pub(crate) fn last_migration() -> i64 {
    rizzy_storage::migrate::MIGRATIONS.last().unwrap().version
}
