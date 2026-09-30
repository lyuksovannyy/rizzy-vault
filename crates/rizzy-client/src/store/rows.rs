//! The cache schema (cache format 1), its row model, and the changeset a step returns
//! ([ADR 0026] §3, §4).
//!
//! # Who does what
//!
//! This crate does no I/O. It owns the schema text ([`SCHEMA`], [`PRAGMAS`]), the row model
//! ([`CacheRows`]) and every decision about what is written ([`Write`], [`Changeset`]); a leaf
//! (`rv` with sqlx in M1, `rizzy-ffi` in M3, `IndexedDB` through `rizzy-wasm` in M2) only runs
//! them: it executes [`SCHEMA`] once, runs each [`Changeset`] as **one** `BEGIN IMMEDIATE`
//! transaction, and reads the tables back into a [`CacheRows`] for
//! [`load`](crate::store::load::load). [`CacheRows::apply`] is the reference executor: what a
//! write means is defined there, and a leaf's SQL is tested against it.
//!
//! # Encodings the schema leaves to the columns
//!
//! - Every `u64` is its 8-byte big-endian `BLOB`, ids are 16-byte `BLOB`s (ADR 0026 §3).
//! - `cache_meta`: `format` is `u16` big-endian; `server_origin` is UTF-8; `account_id` and
//!   `device_id` are 16 bytes; `next_device_seq` and `hlc` are `u64` big-endian.
//! - `vaults.self_grant` is held here as the typed [`VaultSelfGrant`]. ADR 0026 §3 says "as
//!   served" and gives the table no epoch column, and a `VAULT_KEY_SELF_GRANT` envelope does
//!   not carry the epochs of its context, so the blob must: the leaf stores the served JSON
//!   object of the grant and parses it back through `rizzy-proto`. This reading is reported,
//!   not frozen by an ADR.
//! - `account_objects.bytes` of an alarm (kind 7) is `bytes(a) ‖ bytes(b) ‖ …`, the
//!   conflicting signed statements in the `bytes()` framing of CRYPTO.md §2 ([`alarm_bytes`]);
//!   ADR 0026 names the content, not the framing (reported).
//! - `vaults.wraps_after_epoch` is always `NULL` in M1: the driver sends no
//!   `wraps_after_epoch` and holds the whole wrap set.
//!
//! # Columns are indexes, never facts
//!
//! Nothing in a row is trusted: [`load`](crate::store::load::load) parses and verifies every
//! statement and refuses a row whose columns disagree with it (ADR 0026 §3).
//!
//! [ADR 0026]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0026-client-device-state-and-cache.md

use std::collections::BTreeMap;

use core::fmt;

use rizzy_core::encoding::put_bytes;
use rizzy_proto::objects::VaultSelfGrant;
use zeroize::Zeroizing;

use crate::error::{ClientError, internal};

/// `cache_meta.format` of this build (ADR 0026 §5).
pub const CACHE_FORMAT: u16 = 1;

/// The statements that create cache format 1, in order (ADR 0026 §3). Run once, in one
/// transaction with the `format` row (`SQLite` DDL is transactional, ADR 0026 §5). The column
/// lists are the ADR's; primary-key columns are also `NOT NULL`, which `SQLite` does not imply
/// for a non-integer key.
pub const SCHEMA: &[&str] = &[
    "CREATE TABLE cache_meta(k TEXT PRIMARY KEY NOT NULL, v BLOB NOT NULL)",
    "CREATE TABLE device_state(id INTEGER PRIMARY KEY CHECK (id = 1), record BLOB NOT NULL)",
    "CREATE TABLE pending_commit(id INTEGER PRIMARY KEY CHECK (id = 1), request BLOB NOT NULL)",
    "CREATE TABLE account_objects(kind INTEGER NOT NULL, key BLOB NOT NULL, bytes BLOB NOT NULL, \
     PRIMARY KEY (kind, key))",
    "CREATE TABLE vaults(vault_id BLOB PRIMARY KEY NOT NULL, self_grant BLOB NOT NULL, \
     wraps_after_epoch INTEGER, restore_generation BLOB)",
    "CREATE TABLE wraps(vault_id BLOB NOT NULL, item_id BLOB NOT NULL, item_key_id BLOB NOT NULL, \
     vault_key_epoch INTEGER NOT NULL, envelope BLOB NOT NULL, \
     PRIMARY KEY (vault_id, item_id, item_key_id))",
    "CREATE TABLE ops(vault_id BLOB NOT NULL, device_id BLOB NOT NULL, device_seq BLOB NOT NULL, \
     item_id BLOB NOT NULL, statement BLOB NOT NULL, body BLOB, key_wrap BLOB, \
     own INTEGER NOT NULL, sent_generation BLOB, \
     PRIMARY KEY (vault_id, device_id, device_seq))",
    "CREATE TABLE snapshots(vault_id BLOB NOT NULL, snapshot_id BLOB NOT NULL, \
     item_id BLOB NOT NULL, statement BLOB NOT NULL, envelope BLOB NOT NULL, key_wrap BLOB, \
     own INTEGER NOT NULL, sent_generation BLOB, PRIMARY KEY (vault_id, snapshot_id))",
];

/// The connection settings of ADR 0026 §3 "Settings", run on every connection before anything
/// else. `secure_delete` is best-effort hygiene only; nothing relies on it (ADR 0026, Risks).
pub const PRAGMAS: &[&str] = &[
    "PRAGMA journal_mode=DELETE",
    "PRAGMA synchronous=FULL",
    "PRAGMA secure_delete=ON",
    "PRAGMA foreign_keys=ON",
    "PRAGMA busy_timeout=5000",
];

/// The keys of `cache_meta` (ADR 0026 §3).
pub mod meta {
    /// `u16` cache format.
    pub const FORMAT: &str = "format";
    /// The canonical origin, UTF-8.
    pub const SERVER_ORIGIN: &str = "server_origin";
    /// The account id, 16 bytes.
    pub const ACCOUNT_ID: &str = "account_id";
    /// The device id, 16 bytes.
    pub const DEVICE_ID: &str = "device_id";
    /// The next own `device_seq`, `u64` big-endian.
    pub const NEXT_DEVICE_SEQ: &str = "next_device_seq";
    /// The hybrid logical clock, `u64` big-endian.
    pub const HLC: &str = "hlc";
    /// Every key, in the order above.
    pub const ALL: [&str; 6] = [
        FORMAT,
        SERVER_ORIGIN,
        ACCOUNT_ID,
        DEVICE_ID,
        NEXT_DEVICE_SEQ,
        HLC,
    ];
}

/// `account_objects.kind` (ADR 0026 §3).
pub mod kind {
    /// A public-key bundle; key `u64 bundle_seq`.
    pub const BUNDLE: i64 = 1;
    /// The newest verified `account-state`; key empty.
    pub const ACCOUNT_STATE: i64 = 2;
    /// `ACCOUNT_SETTINGS`; key `u64 settings_seq`.
    pub const SETTINGS: i64 = 3;
    /// A device certificate; key `device_id`.
    pub const CERTIFICATE: i64 = 4;
    /// A device revocation; key `device_id`.
    pub const REVOCATION: i64 = 5;
    /// `E_id`; key `u32 identity_epoch`.
    pub const IDENTITY_KEYS: i64 = 6;
    /// An alarm; key `u8 kind` ([`super::Alarm`]).
    pub const ALARM: i64 = 7;
}

/// The `own` column of `ops` and `snapshots` (ADR 0026 §3). It moves only 1 → 3 → 2.
pub mod own {
    /// Served by the server.
    pub const SERVED: i64 = 0;
    /// Own and never sent.
    pub const UNSENT: i64 = 1;
    /// Own and acknowledged.
    pub const ACKNOWLEDGED: i64 = 2;
    /// Own, sent and unanswered.
    pub const SENT: i64 = 3;
}

/// An alarm that keeps the device read-only until the flow that resolves it (ADR 0026 §3 kind
/// 7, §4 step 4; kind 4 by the owner's decision on open question 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Alarm {
    /// "Possible rollback by the server" (CRYPTO.md §11.3 step 2.5).
    Rollback,
    /// "The server has shown two versions of this account".
    Fork,
    /// An identity change the user has not confirmed on this device.
    UnconfirmedIdentityChange,
    /// The device state is older than this device's own history (ADR 0026 §4 step 7).
    /// Resolved only by removal and a new enrolment.
    DeviceStateOutdated,
}

impl Alarm {
    /// The alarm's key byte.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Rollback => 1,
            Self::Fork => 2,
            Self::UnconfirmedIdentityChange => 3,
            Self::DeviceStateOutdated => 4,
        }
    }

    /// The alarm of a key byte.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Rollback),
            2 => Some(Self::Fork),
            3 => Some(Self::UnconfirmedIdentityChange),
            4 => Some(Self::DeviceStateOutdated),
            _ => None,
        }
    }
}

/// The bytes of an alarm row: the conflicting signed statements, each as `bytes(x)` (CRYPTO.md
/// §2), in the order given.
///
/// # Errors
/// [`ClientError::Internal`] for a statement longer than `u32::MAX` bytes.
pub fn alarm_bytes(statements: &[&[u8]]) -> Result<Vec<u8>, ClientError> {
    let mut out = Vec::new();
    for statement in statements {
        put_bytes(&mut out, statement).map_err(internal)?;
    }
    Ok(out)
}

/// One row of `account_objects`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectRow {
    /// [`kind`].
    pub kind: i64,
    /// The key within the kind.
    pub key: Vec<u8>,
    /// The signed or enveloped bytes, as served.
    pub bytes: Vec<u8>,
}

/// One row of `vaults`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultRow {
    /// The vault id (16 bytes).
    pub vault_id: Vec<u8>,
    /// The `VAULT_KEY_SELF_GRANT` with the epochs of its context (module docs).
    pub self_grant: VaultSelfGrant,
    /// Always `None` in M1 (module docs).
    pub wraps_after_epoch: Option<i64>,
    /// The restore generation of the last response (16 bytes), if any arrived.
    pub restore_generation: Option<Vec<u8>>,
}

/// One row of `wraps`: an `ITEM_KEY_WRAP` of the vault's wrap set, as served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrapRow {
    /// The vault id (16 bytes).
    pub vault_id: Vec<u8>,
    /// The item id (16 bytes).
    pub item_id: Vec<u8>,
    /// The locator (16 bytes); never trusted (CRYPTO.md §4.2).
    pub item_key_id: Vec<u8>,
    /// The epoch of the vault key the row is wrapped under.
    pub vault_key_epoch: i64,
    /// The envelope.
    pub envelope: Vec<u8>,
}

/// One row of `ops`: an accepted op statement and what came with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpRow {
    /// The vault id (16 bytes).
    pub vault_id: Vec<u8>,
    /// The author (16 bytes).
    pub device_id: Vec<u8>,
    /// The author's `device_seq`, 8 bytes big-endian.
    pub device_seq: Vec<u8>,
    /// The item (16 bytes).
    pub item_id: Vec<u8>,
    /// The signed `op` statement (kept forever, ADR 0021 §9 "Headers kept").
    pub statement: Vec<u8>,
    /// The `ITEM_OP` envelope, if held.
    pub body: Option<Vec<u8>>,
    /// The carried `ITEM_KEY_WRAP` envelope, if any.
    pub key_wrap: Option<Vec<u8>>,
    /// [`own`].
    pub own: i64,
    /// The restore generation of the last response before the first send (16 bytes); own rows
    /// only (ADR 0021 §2).
    pub sent_generation: Option<Vec<u8>>,
}

/// One row of `snapshots`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotRow {
    /// The vault id (16 bytes).
    pub vault_id: Vec<u8>,
    /// The snapshot id (16 bytes).
    pub snapshot_id: Vec<u8>,
    /// The item (16 bytes).
    pub item_id: Vec<u8>,
    /// The signed `snapshot` statement.
    pub statement: Vec<u8>,
    /// The `ITEM_SNAPSHOT` envelope.
    pub envelope: Vec<u8>,
    /// The carried `ITEM_KEY_WRAP` envelope, if any.
    pub key_wrap: Option<Vec<u8>>,
    /// [`own`].
    pub own: i64,
    /// As [`OpRow::sent_generation`].
    pub sent_generation: Option<Vec<u8>>,
}

/// One write of a [`Changeset`]. [`CacheRows::apply`] defines what each one does.
pub enum Write {
    /// Sets one `cache_meta` row.
    Meta {
        /// One of [`meta::ALL`].
        key: &'static str,
        /// The value (module docs, "Encodings").
        value: Vec<u8>,
    },
    /// Replaces the device-state record, always as a whole (ADR 0026 §2 "`E_local`
    /// lifecycle"). The bytes hold the Secret Key.
    DeviceState(Zeroizing<Vec<u8>>),
    /// Sets (`Some`) or removes (`None`) `pending_commit.request`.
    PendingCommit(Option<Vec<u8>>),
    /// Replaces the `account-state` row (kind 2) by a state that verified. The sequence
    /// numbers are the verified statement's; the floors check reads them.
    AccountState {
        /// The signed wire form.
        wire: Vec<u8>,
        /// Its `state_seq`.
        state_seq: u64,
        /// Its `settings_seq`.
        settings_seq: u64,
    },
    /// Inserts or replaces one `account_objects` row of kind 1 (bundle), 3 (settings), 6
    /// (`E_id`) or 7 (alarm). The state (kind 2) and the device set (kinds 4 and 5) have their
    /// own writes.
    PutObject(ObjectRow),
    /// Removes the [`Alarm::UnconfirmedIdentityChange`] row: the one alarm a flow of this
    /// build resolves, when the user confirms the new identity fingerprint on this device
    /// (CRYPTO.md §11.3 step 3.2) and the answer then verifies in full. The floors refuse this
    /// write for every other alarm: a rollback, a fork and an outdated device state are never
    /// cleared (ADR 0026 §4 step 4, §5).
    ClearAlarm(Alarm),
    /// Replaces every certificate and revocation row (kinds 4 and 5) by the device set the
    /// verified `account-state` commits to (`device_set_hash`): the rows are exactly that set,
    /// so a load can check the hash over them.
    DeviceSet {
        /// The certificates: `device_id` and signed wire form.
        certificates: Vec<([u8; 16], Vec<u8>)>,
        /// The revocations: `device_id` and signed wire form.
        revocations: Vec<([u8; 16], Vec<u8>)>,
    },
    /// Inserts a vault, or replaces its self-grant (the restore generation stays).
    VaultGrant {
        /// The grant, which names the vault.
        grant: VaultSelfGrant,
        /// The id of the vault key the grant opened to, for the fork floor (ADR 0025 §4).
        vault_key_id: [u8; 16],
    },
    /// Sets a vault's restore generation: the last response's value (ADR 0021 §2).
    VaultGeneration {
        /// The vault.
        vault_id: [u8; 16],
        /// The generation.
        generation: [u8; 16],
    },
    /// Stores the served wrap-set rows of the vault key epoch this device holds: each row is
    /// inserted or replaces the row at its locator, and every row of the vault below `epoch`
    /// is deleted (no held key opens it any more).
    ///
    /// A row at `epoch` that the server stops serving is **kept**: the item key it holds
    /// still opens the bodies this device holds, and a server that withholds a wrap must not
    /// be able to make the next load fail (ADR 0026 §5 (d)). After a rotation the wrap set
    /// moves to the new epoch in the same transaction as the new self-grant, so the rows on
    /// disk always open under the vault key on disk.
    Wraps {
        /// The vault.
        vault_id: [u8; 16],
        /// The epoch of the held vault key, and of every row.
        epoch: u32,
        /// The rows, each of this vault and at `epoch`.
        wraps: Vec<WrapRow>,
    },
    /// Inserts an op row. If a row with the same key and the same statement exists, only a
    /// missing `body` or `key_wrap` is filled; `own` and `sent_generation` stay.
    PutOp(OpRow),
    /// Replaces the statement, body and carried wrap of an unsent own op by its re-issue under
    /// the same `device_seq`, sets `own = 1` and clears `sent_generation` (ADR 0026 §4 step 6).
    ReissueOp {
        /// The re-issued row.
        row: OpRow,
        /// The restore generation of the stale answer that called for it.
        stale_generation: Option<[u8; 16]>,
    },
    /// Moves an own op row along 1 → 3 → 2. `sent_generation` is stored only if the row has
    /// none (the first send).
    OpOwn {
        /// The vault.
        vault_id: [u8; 16],
        /// The own device.
        device_id: [u8; 16],
        /// The op's `device_seq`.
        device_seq: u64,
        /// The new [`own`] value: [`own::SENT`] or [`own::ACKNOWLEDGED`].
        own: i64,
        /// With [`own::SENT`]: the restore generation of the last response before the send.
        sent_generation: Option<[u8; 16]>,
    },
    /// Inserts a snapshot row; an existing row with the same key stays as it is.
    PutSnapshot(SnapshotRow),
    /// Moves an own snapshot row along 1 → 3 → 2, as [`Write::OpOwn`].
    SnapshotOwn {
        /// The vault.
        vault_id: [u8; 16],
        /// The snapshot.
        snapshot_id: [u8; 16],
        /// The new [`own`] value.
        own: i64,
        /// As [`Write::OpOwn`].
        sent_generation: Option<[u8; 16]>,
    },
    /// Deletes an own snapshot the server refused or a re-issue discarded (ADR 0018 §3); never
    /// a served or acknowledged one.
    DeleteSnapshot {
        /// The vault.
        vault_id: [u8; 16],
        /// The snapshot.
        snapshot_id: [u8; 16],
    },
}

impl fmt::Debug for Write {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Table names only: a device-state write holds the Secret Key, and nothing else here is
        // worth a log line.
        f.write_str(match self {
            Self::Meta { .. } => "Write::Meta",
            Self::DeviceState(_) => "Write::DeviceState([REDACTED])",
            Self::PendingCommit(_) => "Write::PendingCommit",
            Self::AccountState { .. } => "Write::AccountState",
            Self::PutObject(_) => "Write::PutObject",
            Self::ClearAlarm(_) => "Write::ClearAlarm",
            Self::DeviceSet { .. } => "Write::DeviceSet",
            Self::VaultGrant { .. } => "Write::VaultGrant",
            Self::VaultGeneration { .. } => "Write::VaultGeneration",
            Self::Wraps { .. } => "Write::Wraps",
            Self::PutOp(_) => "Write::PutOp",
            Self::ReissueOp { .. } => "Write::ReissueOp",
            Self::OpOwn { .. } => "Write::OpOwn",
            Self::PutSnapshot(_) => "Write::PutSnapshot",
            Self::SnapshotOwn { .. } => "Write::SnapshotOwn",
            Self::DeleteSnapshot { .. } => "Write::DeleteSnapshot",
        })
    }
}

/// The writes of one step, to run as one `BEGIN IMMEDIATE` transaction (ADR 0026 §4: "a crash
/// leaves the file before or after a step, never inside one"). The host passes it to
/// [`Floors::admit`](crate::store::floors::Floors::admit) first and writes it only if that
/// accepts it.
#[derive(Debug, Default)]
pub struct Changeset {
    /// The writes, in order.
    writes: Vec<Write>,
}

impl Changeset {
    /// An empty changeset.
    #[must_use]
    pub const fn new() -> Self {
        Self { writes: Vec::new() }
    }

    /// Whether there is nothing to write.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }

    /// The writes, in order.
    #[must_use]
    pub fn writes(&self) -> &[Write] {
        &self.writes
    }

    /// Appends one write.
    pub fn push(&mut self, write: Write) {
        self.writes.push(write);
    }

    /// Appends every write of `other`, in order: two steps that must land together become one
    /// transaction.
    pub fn append(&mut self, mut other: Self) {
        self.writes.append(&mut other.writes);
    }
}

impl FromIterator<Write> for Changeset {
    fn from_iter<I: IntoIterator<Item = Write>>(iter: I) -> Self {
        Self {
            writes: iter.into_iter().collect(),
        }
    }
}

/// Everything a cache file holds, read back by the leaf table by table (module docs). Every
/// field is untrusted input to [`load`](crate::store::load::load).
#[derive(Default)]
pub struct CacheRows {
    /// `cache_meta`.
    pub meta: BTreeMap<String, Vec<u8>>,
    /// `device_state.record`. Holds the Secret Key; wiped on drop.
    pub device_state: Option<Zeroizing<Vec<u8>>>,
    /// `pending_commit.request`.
    pub pending_commit: Option<Vec<u8>>,
    /// `account_objects`.
    pub objects: Vec<ObjectRow>,
    /// `vaults`.
    pub vaults: Vec<VaultRow>,
    /// `wraps`.
    pub wraps: Vec<WrapRow>,
    /// `ops`.
    pub ops: Vec<OpRow>,
    /// `snapshots`.
    pub snapshots: Vec<SnapshotRow>,
}

impl fmt::Debug for CacheRows {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CacheRows")
            .field("objects", &self.objects.len())
            .field("vaults", &self.vaults.len())
            .field("wraps", &self.wraps.len())
            .field("ops", &self.ops.len())
            .field("snapshots", &self.snapshots.len())
            .finish_non_exhaustive()
    }
}

impl CacheRows {
    /// Applies `changeset` to these rows: the reference executor (module docs). It assumes
    /// [`Floors::admit`](crate::store::floors::Floors::admit) accepted the changeset, and
    /// checks nothing itself; a write that names a row that does not exist changes nothing.
    pub fn apply(&mut self, changeset: &Changeset) {
        for write in changeset.writes() {
            self.apply_one(write);
        }
    }

    /// Applies one write.
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per write kind, the table the SQL executors are checked against"
    )]
    fn apply_one(&mut self, write: &Write) {
        match write {
            Write::Meta { key, value } => {
                self.meta.insert((*key).to_owned(), value.clone());
            }
            Write::DeviceState(record) => self.device_state = Some(record.clone()),
            Write::PendingCommit(request) => self.pending_commit.clone_from(request),
            Write::AccountState { wire, .. } => self.put_object(&ObjectRow {
                kind: kind::ACCOUNT_STATE,
                key: Vec::new(),
                bytes: wire.clone(),
            }),
            Write::PutObject(row) => self.put_object(row),
            Write::ClearAlarm(alarm) => {
                let key = [alarm.to_u8()];
                self.objects
                    .retain(|o| o.kind != kind::ALARM || o.key != key);
            }
            Write::DeviceSet {
                certificates,
                revocations,
            } => {
                self.objects
                    .retain(|o| o.kind != kind::CERTIFICATE && o.kind != kind::REVOCATION);
                for (kind, rows) in [
                    (kind::CERTIFICATE, certificates),
                    (kind::REVOCATION, revocations),
                ] {
                    for (device_id, wire) in rows {
                        self.put_object(&ObjectRow {
                            kind,
                            key: device_id.to_vec(),
                            bytes: wire.clone(),
                        });
                    }
                }
            }
            Write::VaultGrant { grant, .. } => {
                let vault_id = grant.vault_id.to_bytes();
                match self.vaults.iter_mut().find(|v| v.vault_id == vault_id) {
                    Some(row) => row.self_grant = grant.clone(),
                    None => self.vaults.push(VaultRow {
                        vault_id: vault_id.to_vec(),
                        self_grant: grant.clone(),
                        wraps_after_epoch: None,
                        restore_generation: None,
                    }),
                }
            }
            Write::VaultGeneration {
                vault_id,
                generation,
            } => {
                if let Some(row) = self.vaults.iter_mut().find(|v| v.vault_id == *vault_id) {
                    row.restore_generation = Some(generation.to_vec());
                }
            }
            Write::Wraps {
                vault_id,
                epoch,
                wraps,
            } => {
                self.wraps.retain(|w| {
                    w.vault_id != *vault_id
                        || (w.vault_key_epoch >= i64::from(*epoch)
                            && !wraps
                                .iter()
                                .any(|n| n.item_id == w.item_id && n.item_key_id == w.item_key_id))
                });
                self.wraps.extend(wraps.iter().cloned());
            }
            Write::PutOp(row) => self.put_op(row),
            Write::ReissueOp { row, .. } => {
                if let Some(held) = self.ops.iter_mut().find(|o| same_op(o, row)) {
                    held.statement.clone_from(&row.statement);
                    held.body.clone_from(&row.body);
                    held.key_wrap.clone_from(&row.key_wrap);
                    held.own = own::UNSENT;
                    held.sent_generation = None;
                }
            }
            Write::OpOwn {
                vault_id,
                device_id,
                device_seq,
                own,
                sent_generation,
            } => {
                let seq = device_seq.to_be_bytes();
                if let Some(held) = self.ops.iter_mut().find(|o| {
                    o.vault_id == *vault_id && o.device_id == *device_id && o.device_seq == seq
                }) {
                    held.own = *own;
                    if held.sent_generation.is_none() {
                        held.sent_generation = sent_generation.map(|g| g.to_vec());
                    }
                }
            }
            Write::PutSnapshot(row) => {
                let held = self
                    .snapshots
                    .iter()
                    .any(|s| s.vault_id == row.vault_id && s.snapshot_id == row.snapshot_id);
                if !held {
                    self.snapshots.push(row.clone());
                }
            }
            Write::SnapshotOwn {
                vault_id,
                snapshot_id,
                own,
                sent_generation,
            } => {
                if let Some(held) = self
                    .snapshots
                    .iter_mut()
                    .find(|s| s.vault_id == *vault_id && s.snapshot_id == *snapshot_id)
                {
                    held.own = *own;
                    if held.sent_generation.is_none() {
                        held.sent_generation = sent_generation.map(|g| g.to_vec());
                    }
                }
            }
            Write::DeleteSnapshot {
                vault_id,
                snapshot_id,
            } => self
                .snapshots
                .retain(|s| s.vault_id != *vault_id || s.snapshot_id != *snapshot_id),
        }
    }

    /// Inserts or replaces one `account_objects` row.
    fn put_object(&mut self, row: &ObjectRow) {
        match self
            .objects
            .iter_mut()
            .find(|o| o.kind == row.kind && o.key == row.key)
        {
            Some(held) => held.bytes.clone_from(&row.bytes),
            None => self.objects.push(row.clone()),
        }
    }

    /// [`Write::PutOp`].
    fn put_op(&mut self, row: &OpRow) {
        match self.ops.iter_mut().find(|o| same_op(o, row)) {
            Some(held) => {
                if held.statement == row.statement {
                    if held.body.is_none() {
                        held.body.clone_from(&row.body);
                    }
                    if held.key_wrap.is_none() {
                        held.key_wrap.clone_from(&row.key_wrap);
                    }
                }
            }
            None => self.ops.push(row.clone()),
        }
    }

    /// The rows in primary-key order, as a leaf's `SELECT … ORDER BY` returns them: two caches
    /// with the same content compare equal after this.
    pub fn sort(&mut self) {
        self.objects
            .sort_by(|a, b| (a.kind, &a.key).cmp(&(b.kind, &b.key)));
        self.vaults.sort_by(|a, b| a.vault_id.cmp(&b.vault_id));
        self.wraps.sort_by(|a, b| {
            (&a.vault_id, &a.item_id, &a.item_key_id).cmp(&(
                &b.vault_id,
                &b.item_id,
                &b.item_key_id,
            ))
        });
        self.ops.sort_by(|a, b| {
            (&a.vault_id, &a.device_id, &a.device_seq).cmp(&(
                &b.vault_id,
                &b.device_id,
                &b.device_seq,
            ))
        });
        self.snapshots
            .sort_by(|a, b| (&a.vault_id, &a.snapshot_id).cmp(&(&b.vault_id, &b.snapshot_id)));
    }
}

/// Whether two op rows have the same primary key.
fn same_op(a: &OpRow, b: &OpRow) -> bool {
    a.vault_id == b.vault_id && a.device_id == b.device_id && a.device_seq == b.device_seq
}
