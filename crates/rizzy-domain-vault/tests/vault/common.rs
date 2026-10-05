//! The test harness: a migrated SQLite database with one account and one vault, an in-memory
//! device directory, devices that sign real `op` and `snapshot` statements, and Fetch helpers
//! that check what a client checks.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers: a failure fails the test, which CLAUDE.md allows in test code"
)]

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use chacha20::ChaCha20Rng;
use rand_core::SeedableRng;
use rizzy_bus::Bus;
use rizzy_core::ids::{AccountId, DeviceId, ItemId, OpId, SnapshotId, VaultId};
use rizzy_core::sign::statements::DeviceKind;
use rizzy_core::sign::{DeviceSigningKey, OpStatement, SnapshotStatement};
use rizzy_domain_vault::{
    AccountKeyState, AuthorCertificate, AuthorStatus, Authors, DeviceDirectory, DirectoryError,
    FetchOutcome, VaultDomain, create_vault,
};
use rizzy_proto::objects::{self, Envelope, KeyEnvelope, VaultSelfGrant};
use rizzy_proto::vault::{
    FetchRequest, OpRecord, Record, RecordKeyWrap, SeqEntry, SeqVector, SnapshotRecord,
    UploadRequest, UploadResult,
};
use rizzy_proto::wire::{Id, List};
use rizzy_storage::tables::TABLES;
use rizzy_storage::{
    Conn, Database, Dump, PostgresOptions, SqliteOptions, TableDump, Value, WriterLock,
    lock_account, on_engine, schema_version,
};
use rizzy_sync::dot::Dot;
use rizzy_sync::header::{ItemSchemaVersion, OpHeader, SnapshotHeader};
use rizzy_sync::hlc::Hlc;
use rizzy_sync::vv::VersionVector;

/// The server clock of every test, in milliseconds.
pub(crate) const NOW: u64 = 1_800_000_000_000;

/// The account every test uses.
pub(crate) const ACCOUNT: AccountId = AccountId::from_bytes([0xa1; 16]);

/// A second account, which owns no vault.
pub(crate) const OTHER_ACCOUNT: AccountId = AccountId::from_bytes([0xa2; 16]);

/// The vault every test creates.
pub(crate) const VAULT: VaultId = VaultId::from_bytes([0xb1; 16]);

/// Runs `f` to completion on a current-thread tokio runtime.
pub(crate) fn block_on<F: Future>(f: F) -> F::Output {
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
    pub(crate) fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rizzy-domain-vault-test-{}-{}",
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

/// An item id filled with `n`.
pub(crate) const fn item(n: u8) -> ItemId {
    ItemId::from_bytes([n; 16])
}

/// The in-memory certificate source: what `rizzy-server` wires in from `rizzy-domain-auth`.
/// Clones share the certificates and the account key, so a test can revoke a device or move the
/// held state's account key while the domain holds one.
#[derive(Clone, Debug, Default)]
pub(crate) struct Directory(
    Arc<Mutex<BTreeMap<DeviceId, AuthorCertificate>>>,
    Arc<Mutex<Option<AccountKeyState>>>,
);

impl Directory {
    /// Sets the account key of the held signed state ([`DeviceDirectory::account_key`]).
    pub(crate) fn set_account_key(&self, key: AccountKeyState) {
        *self.1.lock().unwrap() = Some(key);
    }

    /// Registers or replaces `device`'s certificate with `status`.
    pub(crate) fn set(&self, device: &Device, status: AuthorStatus) {
        self.0
            .lock()
            .unwrap()
            .insert(device.id, device.cert(status));
    }
}

impl DeviceDirectory for Directory {
    fn authors<'a>(
        &'a self,
        _conn: Conn<'a>,
        account_id: AccountId,
    ) -> impl Future<Output = Result<Authors, DirectoryError>> + Send + 'a {
        let certs: Vec<AuthorCertificate> = if account_id == ACCOUNT {
            self.0.lock().unwrap().values().cloned().collect()
        } else {
            Vec::new()
        };
        async move {
            Authors::new(certs).map_err(|_| DirectoryError {
                what: "duplicate certificate",
            })
        }
    }

    fn account_key<'a>(
        &'a self,
        _conn: Conn<'a>,
        account_id: AccountId,
    ) -> impl Future<Output = Result<Option<AccountKeyState>, DirectoryError>> + Send + 'a {
        let key = if account_id == ACCOUNT {
            *self.1.lock().unwrap()
        } else {
            None
        };
        async move { Ok(key) }
    }
}

/// A device of the account: an id and a real Ed25519 device key.
pub(crate) struct Device {
    /// The device id.
    pub(crate) id: DeviceId,
    /// Its signing key.
    pub(crate) key: DeviceSigningKey,
    /// Its kind.
    pub(crate) kind: DeviceKind,
    /// Its certificate's expiry, 0 for none.
    pub(crate) expires_at_ms: u64,
}

impl Device {
    /// A durable device with id `[n; 16]` and a key drawn from a seeded test RNG.
    pub(crate) fn new(n: u8) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(u64::from(n));
        Self {
            id: DeviceId::from_bytes([n; 16]),
            key: DeviceSigningKey::generate(&mut rng),
            kind: DeviceKind::DesktopCli,
            expires_at_ms: 0,
        }
    }

    /// A kind-4 web-vault device whose certificate expires at `expires_at_ms`.
    pub(crate) fn web(n: u8, expires_at_ms: u64) -> Self {
        Self {
            kind: DeviceKind::WebEphemeral,
            expires_at_ms,
            ..Self::new(n)
        }
    }

    /// Its certificate as the directory supplies it.
    pub(crate) fn cert(&self, status: AuthorStatus) -> AuthorCertificate {
        AuthorCertificate {
            device_id: self.id,
            verifying_key: *self.key.verifying_key(),
            device_kind: self.kind,
            expires_at_ms: self.expires_at_ms,
            status,
        }
    }
}

/// What to sign into one op.
#[derive(Clone, Debug)]
pub(crate) struct OpSpec {
    /// The item.
    pub(crate) item: ItemId,
    /// `device_seq`.
    pub(crate) seq: u64,
    /// `vault_prev_seq`.
    pub(crate) prev: u64,
    /// `vault_key_epoch`.
    pub(crate) epoch: u32,
    /// The HLC's milliseconds.
    pub(crate) hlc_ms: u64,
    /// Varies the body (and so the statement) of an op at the same dot.
    pub(crate) tag: u8,
    /// The carried `ITEM_KEY_WRAP` envelope, if any.
    pub(crate) wrap: Option<Vec<u8>>,
}

impl OpSpec {
    /// Op `seq` on `item`, chained after `prev`, at epoch 0, the current time, no wrap.
    pub(crate) const fn new(item: ItemId, seq: u64, prev: u64) -> Self {
        Self {
            item,
            seq,
            prev,
            epoch: 0,
            hlc_ms: NOW,
            tag: 0,
            wrap: None,
        }
    }
}

/// The item key id every carried test wrap names.
pub(crate) const ITEM_KEY_ID: [u8; 16] = [0x4b; 16];

/// A test body: 48 bytes that differ per device, dot and tag. The server never opens it.
fn body_bytes(device: DeviceId, seq: u64, tag: u8) -> Vec<u8> {
    let mut body = Vec::with_capacity(48);
    body.extend_from_slice(device.as_bytes());
    body.extend_from_slice(&seq.to_be_bytes());
    body.push(tag);
    body.resize(48, 0xee);
    body
}

/// Signs op `spec` of `device` in `vault`: a real canonical header from `rizzy-sync`, a real
/// `op` statement from `rizzy-core`, the body, and the wrap if any.
pub(crate) fn sign_op(device: &Device, vault: VaultId, spec: &OpSpec) -> OpRecord {
    let mut op_id = [0u8; 16];
    op_id[..8].copy_from_slice(&spec.seq.to_be_bytes());
    op_id[8] = device.id.as_bytes()[0];
    op_id[9] = spec.tag;
    let header = OpHeader {
        vault_id: vault,
        item_id: spec.item,
        op_id: OpId::from_bytes(op_id),
        dot: Dot::new(device.id, spec.seq).unwrap(),
        vault_prev_seq: spec.prev,
        hlc: Hlc::from_parts(spec.hlc_ms, 0).unwrap(),
        item_schema_version: ItemSchemaVersion::V1,
        vault_key_epoch: spec.epoch,
        causal_context: VersionVector::new(),
    };
    let canonical = header.to_vec().unwrap();
    let body = body_bytes(device.id, spec.seq, spec.tag);
    let statement = OpStatement::new(&canonical, &body, spec.wrap.as_deref()).unwrap();
    let wire = statement.sign(&device.key).unwrap();
    OpRecord {
        statement: objects::OpStatement::new(wire).unwrap(),
        body: Some(Envelope::new(body).unwrap()),
        key_wrap: spec.wrap.as_ref().map(|w| RecordKeyWrap {
            item_key_id: Id::from_bytes(ITEM_KEY_ID),
            envelope: KeyEnvelope::from_slice(w).unwrap(),
        }),
    }
}

/// `device`'s ops `1..=n` on `item`, chained, starting after `prev`.
pub(crate) fn chain(device: &Device, item: ItemId, from: u64, to: u64) -> Vec<Record> {
    (from..=to)
        .map(|seq| Record::Op(sign_op(device, VAULT, &OpSpec::new(item, seq, seq - 1))))
        .collect()
}

/// Signs a snapshot of `item` by `device` with snapshot id `[id; 16]`, covered VV `covered`, at
/// `epoch`. Its envelope is opaque test bytes.
pub(crate) fn sign_snapshot(
    device: &Device,
    item: ItemId,
    id: u8,
    covered: &[(&Device, u64)],
    epoch: u32,
) -> SnapshotRecord {
    sign_snapshot_id(device, item, [id; 16], covered, epoch)
}

/// As [`sign_snapshot`], with a full 16-byte snapshot id.
pub(crate) fn sign_snapshot_id(
    device: &Device,
    item: ItemId,
    id: [u8; 16],
    covered: &[(&Device, u64)],
    epoch: u32,
) -> SnapshotRecord {
    let header = SnapshotHeader {
        vault_id: VAULT,
        item_id: item,
        snapshot_id: SnapshotId::from_bytes(id),
        author: device.id,
        item_schema_version: ItemSchemaVersion::V1,
        vault_key_epoch: epoch,
        covered: covered
            .iter()
            .map(|(d, seq)| Dot::new(d.id, *seq).unwrap())
            .collect(),
    };
    let canonical = header.to_vec().unwrap();
    let mut envelope = id.to_vec();
    envelope.resize(64, 0x5e);
    let statement = SnapshotStatement::new(&canonical, &envelope, None).unwrap();
    SnapshotRecord {
        statement: objects::SnapshotStatement::new(statement.sign(&device.key).unwrap()).unwrap(),
        envelope: Envelope::new(envelope).unwrap(),
        key_wrap: None,
    }
}

/// The canonical header inside a statement's wire form (CRYPTO.md §9.6):
/// `u32 len ‖ u16 version ‖ u32 header_len ‖ header ‖ …`. A client verifies the signature
/// first; the tests already know the signer and only need the header.
pub(crate) fn header_bytes(wire: &[u8]) -> &[u8] {
    let len = u32::from_be_bytes(wire[6..10].try_into().unwrap());
    &wire[10..10 + usize::try_from(len).unwrap()]
}

/// The dot and item of a served op.
pub(crate) fn op_dot(record: &OpRecord) -> (ItemId, Dot) {
    let h = OpHeader::parse(header_bytes(record.statement.as_slice())).unwrap();
    (h.item_id, h.dot)
}

/// The header of a served snapshot.
pub(crate) fn snapshot_header(record: &SnapshotRecord) -> SnapshotHeader {
    SnapshotHeader::parse(header_bytes(record.statement.as_slice())).unwrap()
}

/// The PostgreSQL database every test uses instead of SQLite when set: see [`Slot`].
const POSTGRES_URL_VAR: &str = "RIZZY_TEST_POSTGRES_URL";

/// Serialises the tests on PostgreSQL: they share the one database the URL names.
static POSTGRES_LOCK: Mutex<()> = Mutex::new(());

/// Where a test's databases live (ADR 0021 §8 "Storage" and ADR 0011 point 3: the suite runs on
/// both engines).
///
/// - **SQLite** (the default): fresh files in a temporary directory.
/// - **PostgreSQL**, when `RIZZY_TEST_POSTGRES_URL` names a database the tests may **wipe**
///   (owned by the connecting role): the tests take turns on it, and every fresh database drops
///   and re-creates its `public` schema. For example
///   `RIZZY_TEST_POSTGRES_URL=postgres://rizzy:rizzy@localhost/rizzy_test cargo test -p
///   rizzy-domain-vault`.
pub(crate) enum Slot {
    /// SQLite files under a temporary directory, numbered.
    Sqlite(TempDir, u32),
    /// The PostgreSQL database at the URL, held for this test.
    Postgres {
        /// The database URL.
        url: String,
        /// This test's turn on the shared database, released on drop.
        _turn: MutexGuard<'static, ()>,
    },
}

impl Slot {
    /// The slot for one test, by `RIZZY_TEST_POSTGRES_URL`.
    pub(crate) fn new() -> Self {
        match std::env::var(POSTGRES_URL_VAR) {
            Ok(url) if !url.is_empty() => Self::Postgres {
                url,
                _turn: POSTGRES_LOCK.lock().unwrap_or_else(PoisonError::into_inner),
            },
            _ => Self::Sqlite(TempDir::new(), 0),
        }
    }

    /// A new, empty database. On PostgreSQL this wipes the database the previous call of this
    /// test returned.
    pub(crate) async fn fresh_db(&mut self) -> Database {
        match self {
            Self::Sqlite(dir, n) => {
                *n += 1;
                open_db(dir, &format!("vault-{n}.db")).await
            }
            Self::Postgres { url, .. } => {
                let db = Database::open_postgres(&PostgresOptions::from_url(url).unwrap())
                    .await
                    .unwrap();
                let mut tx = db.begin_write().await.unwrap();
                for statement in [
                    "DROP SCHEMA IF EXISTS public CASCADE",
                    "CREATE SCHEMA public",
                ] {
                    on_engine!(tx.conn(), |c| sqlx::query(statement)
                        .execute(&mut *c)
                        .await
                        .map(|_| ())
                        .unwrap());
                }
                tx.commit().await.unwrap();
                db
            }
        }
    }
}

/// A test environment: a database with the account and its vault, and the domain over it.
pub(crate) struct Env {
    /// The database.
    pub(crate) db: Database,
    /// The certificates.
    pub(crate) directory: Directory,
    /// The domain.
    pub(crate) domain: Arc<VaultDomain<Directory>>,
    /// Keeps the database alive, and the PostgreSQL database this test's, until the environment
    /// is dropped. Last, so it is dropped after the handles above.
    pub(crate) slot: Slot,
}

/// A dump holding only the two accounts: `rizzy-storage` writes the `auth_accounts` rows through
/// its restore, so this domain's tests never touch another domain's table.
pub(crate) fn accounts_dump() -> Dump {
    let tables = TABLES
        .iter()
        .map(|spec| TableDump {
            table: spec.name.to_owned(),
            rows: if spec.name == "auth_accounts" {
                vec![
                    vec![
                        Value::Blob(ACCOUNT.as_bytes().to_vec()),
                        Value::Text("alice".into()),
                        Value::Integer(1),
                    ],
                    vec![
                        Value::Blob(OTHER_ACCOUNT.as_bytes().to_vec()),
                        Value::Text("bob".into()),
                        Value::Integer(1),
                    ],
                ]
            } else {
                Vec::new()
            },
        })
        .collect();
    Dump {
        schema_version: schema_version(),
        tables,
    }
}

/// Opens (creating) the SQLite database `name` in `dir`.
pub(crate) async fn open_db(dir: &TempDir, name: &str) -> Database {
    let path = dir.join(name);
    let lock = WriterLock::acquire(&path).unwrap();
    Database::open_sqlite(&SqliteOptions::new(&path), lock)
        .await
        .unwrap()
}

impl Env {
    /// A fresh database restored from [`accounts_dump`] with restore generation
    /// `[generation; 16]` (so the account is in its reconciliation epoch), and the vault created
    /// with its first self-grant.
    pub(crate) async fn new(generation: u8) -> Self {
        let mut slot = Slot::new();
        let db = slot.fresh_db().await;
        db.restore(
            &accounts_dump(),
            rizzy_storage::RestoreGeneration([generation; 16]),
            1,
        )
        .await
        .unwrap();
        let mut tx = db.begin_write().await.unwrap();
        lock_account(&mut tx, ACCOUNT.as_bytes()).await.unwrap();
        let grant = VaultSelfGrant {
            vault_id: Id::from_bytes(VAULT.to_bytes()),
            account_key_epoch: 0,
            vault_key_epoch: 0,
            envelope: KeyEnvelope::new(vec![0x5a; 98]).unwrap(),
        };
        create_vault(&mut tx, ACCOUNT, &grant, NOW).await.unwrap();
        tx.commit().await.unwrap();
        Self::over(slot, db)
    }

    /// The domain over an existing database of `slot`.
    pub(crate) fn over(slot: Slot, db: Database) -> Self {
        let directory = Directory::default();
        let domain = Arc::new(VaultDomain::new(
            db.clone(),
            directory.clone(),
            Bus::default(),
        ));
        Self {
            db,
            directory,
            domain,
            slot,
        }
    }

    /// A second domain over the same database and certificates, with a Fetch page budget of
    /// `page_bytes`.
    pub(crate) fn domain_with_page_bytes(&self, page_bytes: usize) -> VaultDomain<Directory> {
        VaultDomain::new(self.db.clone(), self.directory.clone(), Bus::default())
            .with_page_bytes(page_bytes)
    }

    /// Takes the database slot out of this environment, dropping its handles.
    pub(crate) fn into_slot(self) -> Slot {
        self.slot
    }

    /// Registers active devices.
    pub(crate) fn enrol(&self, devices: &[&Device]) {
        for d in devices {
            self.directory.set(d, AuthorStatus::Active);
        }
    }

    /// Uploads `records` to the vault; returns the results.
    pub(crate) async fn upload(&self, records: Vec<Record>) -> Vec<UploadResult> {
        let request = UploadRequest {
            vault_id: Id::from_bytes(VAULT.to_bytes()),
            records: List::new(records).unwrap(),
        };
        self.domain
            .upload(ACCOUNT, &request, NOW)
            .await
            .unwrap()
            .results
            .into_vec()
    }

    /// Uploads `records` and asserts every one was stored.
    pub(crate) async fn store(&self, records: Vec<Record>) {
        let n = records.len();
        assert_eq!(self.upload(records).await, vec![UploadResult::Stored; n]);
    }

    /// One Fetch page from `cursor`.
    pub(crate) async fn fetch_page(&self, cursor: &SeqVector) -> FetchOutcome {
        fetch_page_with(&self.domain, cursor).await
    }

    /// A complete Fetch from `cursor`, page by page, advancing the cursor as a client does.
    /// Every page is checked with [`check_page`].
    pub(crate) async fn fetch_all(&self, cursor: &[(&Device, u64)]) -> Vec<FetchOutcome> {
        fetch_all_with(&self.domain, cursor).await
    }
}

/// One Fetch page from `cursor`, served by `domain`.
pub(crate) async fn fetch_page_with(
    domain: &VaultDomain<Directory>,
    cursor: &SeqVector,
) -> FetchOutcome {
    let request = FetchRequest {
        vault_id: Id::from_bytes(VAULT.to_bytes()),
        cursor: cursor.clone(),
        wraps_after_epoch: None,
    };
    domain.fetch(ACCOUNT, &request).await.unwrap()
}

/// As [`Env::fetch_all`], served by `domain`.
pub(crate) async fn fetch_all_with(
    domain: &VaultDomain<Directory>,
    cursor: &[(&Device, u64)],
) -> Vec<FetchOutcome> {
    let mut cursor: BTreeMap<[u8; 16], u64> = cursor
        .iter()
        .map(|(d, seq)| (d.id.to_bytes(), *seq))
        .collect();
    let mut pages = Vec::new();
    loop {
        let vector = SeqVector::new(
            cursor
                .iter()
                .filter(|(_, seq)| **seq > 0)
                .map(|(id, seq)| SeqEntry {
                    device_id: Id::from_bytes(*id),
                    seq: *seq,
                })
                .collect(),
        )
        .unwrap();
        let page = fetch_page_with(domain, &vector).await;
        check_page(&page);
        for op in &page.response.ops {
            let (_, dot) = op_dot(op);
            let entry = cursor.entry(dot.device_id().to_bytes()).or_insert(0);
            assert_eq!(*entry + 1, dot.seq(), "a page skipped part of a chain");
            *entry = dot.seq();
        }
        let complete = page.response.complete;
        pages.push(page);
        if complete {
            return pages;
        }
        assert!(pages.len() < 10_000, "Fetch never completes");
    }
}

/// What a client checks on every page (ADR 0012 §7 "Chain check after compaction", ADR 0021 §8
/// server property 3): every bodiless header comes with a cover in the same page, and the
/// server reports no integrity error.
pub(crate) fn check_page(page: &FetchOutcome) {
    assert!(
        page.integrity_errors.is_empty(),
        "{:?}",
        page.integrity_errors
    );
    let covers: Vec<SnapshotHeader> = page.response.covers.iter().map(snapshot_header).collect();
    for op in page.response.ops.iter().filter(|op| op.body.is_none()) {
        let (item_id, dot) = op_dot(op);
        assert!(
            covers
                .iter()
                .any(|c| c.item_id == item_id && c.covered.covers(dot)),
            "a bodiless header without a cover in its page"
        );
    }
}

/// Every op of a complete Fetch, in response order.
pub(crate) fn ops_of(pages: &[FetchOutcome]) -> Vec<&OpRecord> {
    pages.iter().flat_map(|p| p.response.ops.iter()).collect()
}

/// Every cover of a complete Fetch.
pub(crate) fn covers_of(pages: &[FetchOutcome]) -> Vec<&SnapshotRecord> {
    pages
        .iter()
        .flat_map(|p| p.response.covers.iter())
        .collect()
}
