//! Shared helpers of the integration tests: a tokio runtime, temporary directories, and a
//! fixture dump that fills every backed-up table.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rizzy_storage::tables::TABLES;
use rizzy_storage::{Dump, TableDump, Value, schema_version};

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
                vec![a1(), Value::Text("alice".into()), int(1_000)],
                vec![a2(), Value::Text("bob".into()), int(2_000)],
            ],
        ),
        (
            "auth_opaque_setups",
            vec![vec![int(1), blob(1, 32), int(10)]],
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
            ]],
        ),
        (
            "auth_identity_keys",
            vec![vec![a1(), int(0), blob(4, 100), int(12)]],
        ),
        (
            "auth_recovery",
            vec![vec![a1(), int(1), blob(5, 90), blob(6, 32), int(13)]],
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
            vec![vec![v1(), a1(), int(0), int(2), int(27)]],
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
