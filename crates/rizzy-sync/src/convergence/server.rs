// SPDX-License-Identifier: AGPL-3.0-only

//! The simulated server of the harness: ADR 0012 §7 "Upload" and "Fetch" as ADR 0021 §4 and §9
//! replace them, `worker` through [`crate::compaction`], backups and restores, and a
//! withholding mode for property 7.
//!
//! It stores and forwards: it never parses a body, and it reads only what an honest server
//! reads, the op and snapshot statements (header bytes and the signed envelope hash), their
//! parsed headers, and its own rows (store sequences, clamped VVs, body flags, heads, cut-offs).
//! Every compaction decision goes through the public functions of
//! [`compaction`](crate::compaction): [`clamp`] and [`check_snapshot`] when it stores a
//! snapshot, [`check_healing_request`] for a healing request, [`plan_worker`] for `worker` and
//! [`select_covers`] for each page of a Fetch.
//!
//! **Server properties** (ADR 0021 §8). The server exposes its rows as plain data
//! ([`Server::check_stored`], [`Server::check_after_worker`]) and checks each page it builds
//! ([`Server::fetch`]) through [`super::checker`], which is written from §2–§4 and never calls
//! [`crate::compaction`]: properties 1 and 2 after every step, 3 and the §4 selection rule on
//! every page, 4 and 5 after every `worker` run. What it finds goes into
//! [`Server::violations`].
//!
//! **Signatures and envelopes.** A record is its signed [`OpStatement`] or
//! [`SnapshotStatement`] in the wire form (the device signature over the canonical header and
//! `SHA-256` of the envelope) and the sealed `ITEM_OP` or `ITEM_SNAPSHOT` envelope
//! ([`super::crypto`]). Before it stores a record the server verifies the signature under the
//! key of the device the record names, requires the header parsed from the verified statement
//! to be the record's and to name that device, and checks the envelope against the signed hash
//! ([`OpRecord::verify`], [`SnapRecord::verify`]); a record that fails is never stored. It
//! holds no item key and never opens an envelope.
//!
//! **What is modelled of ADR 0021 §9.** "Already stored" (checked first, byte-identical by
//! statement and body), a conflict at a stored dot, the `vault_prev_seq` check, revocation
//! cut-offs for ops and snapshots, a kind-4 author's expiry ("Revoked and kind-4 authors":
//! uploads from an expired certificate refused, its new snapshots refused, retained ones kept
//! as covers), the snapshot acceptance checks, the healing request, atomic, with bodiless
//! headers only behind the request's snapshots, and "Stale epoch": an op or snapshot whose
//! `vault_key_epoch` is below the vault's is refused ([`OpAnswer::StaleEpoch`]), except a
//! bodiless header or any record of a healing request (the server cannot tell a record
//! re-published verbatim from a fresh one, so the client keeps that rule:
//! [`crate::causal::VaultLog::stale_plan`]) and a revoked device's op at or below its
//! cut-off.
//!
//! **Epochs and wraps.** The vault's epoch and its wrap-set rows, one per (`item_id`, item
//! `key_id`), each an `ITEM_KEY_WRAP` under the vault key of its epoch, are part of the
//! database a restore rolls back. A record that carries a wrap adds its row when it is stored.
//! A rotation ([`Server::rotate`], ADR 0025 §3) is checked and applied atomically with the
//! revocation it may carry: a higher epoch, the rotator's cursor equal to every head
//! ("Rotation cut-off"), and every stored row either re-wrapped at the new epoch or dropped.
//! The ADR 0032 §3 self-grant lag repair after a restore is [`Server::heal_epoch`]. Not
//! modelled: the signed `account-state`, self-grants, device grants and certificates (the
//! world hands vault keys to the devices a rotation keeps).

use std::collections::{BTreeMap, BTreeSet};

use rizzy_core::ids::{DeviceId, ItemId, SymmetricKeyId};
use rizzy_core::sign::{OpStatement, SnapshotStatement, Verified};

use super::{checker, crypto};
use crate::causal::RestoreGeneration;
use crate::compaction::{
    Body, CertificateExpiry, OpDot, RetainedSnapshot, SnapshotRefusal, VaultChains,
    check_healing_request, check_snapshot, clamp, plan_worker, select_covers,
};
use crate::dot::Dot;
use crate::header::{OpHeader, SnapshotHeader};
use crate::vv::{VersionVector, VvOrdering};

/// An `ITEM_KEY_WRAP` envelope and the vault epoch of the key it is sealed under (CRYPTO.md
/// §4.4, §11.6). Server-visible: the epoch and the envelope bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Wrap {
    /// The `vault_key_epoch` of the wrapping vault key.
    pub(super) epoch: u32,
    /// The sealed `ITEM_KEY_WRAP`.
    pub(super) envelope: Vec<u8>,
}

/// One wrap-set row: the item, the id of the item key it wraps (the `key_id` of the envelopes
/// sealed under it), and the wrap (CRYPTO.md §4.2, ADR 0025 §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WrapRow {
    /// The item.
    pub(super) item: ItemId,
    /// The item key's id.
    pub(super) key: SymmetricKeyId,
    /// The wrap.
    pub(super) wrap: Wrap,
}

/// The wrap-set rows by `(item, key id bytes)`.
type Rows = BTreeMap<(ItemId, [u8; 16]), Wrap>;

/// An op record as it travels: the statement its author signed, its parsed header (the server
/// parses the canonical header before storing, ADR 0012 §7), and its body when one goes with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct OpRecord {
    /// The signed `op` statement in its wire form (CRYPTO.md §9.6, §10.2): the canonical
    /// header, the envelope hash and the author's signature container.
    pub(super) signed: Vec<u8>,
    /// The header the record claims. Nothing trusts it before [`OpRecord::verify`] has found
    /// it equal to the header of the verified statement.
    pub(super) header: OpHeader,
    /// The body, the sealed `ITEM_OP` envelope, or `None` for a bodiless header.
    pub(super) body: Option<Vec<u8>>,
    /// The `ITEM_KEY_WRAP` of the item key the body is sealed under, when its author created
    /// that key (CRYPTO.md §11.6 writer rule): it travels beside the record, unsigned (see
    /// [`super::crypto`] "What is not modelled"), and the server keeps it as a wrap-set row.
    pub(super) wrap: Option<Wrap>,
}

impl OpRecord {
    /// Verifies the record's signature (CRYPTO.md §10.2): the statement under the key of the
    /// device the claimed header names, and the header parsed from the verified statement,
    /// which must be the claimed one (so it names that device, INV-22). Returns the verified
    /// statement, against whose signed hash the caller checks the body.
    pub(super) fn verify(&self) -> Option<Verified<OpStatement>> {
        let (statement, header) = crypto::verify_op(&self.signed, self.header.dot.device_id())?;
        (header == self.header).then_some(statement)
    }
}

/// A snapshot record as it travels: signed statement, parsed header and `data`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SnapRecord {
    /// The signed `snapshot` statement in its wire form.
    pub(super) signed: Vec<u8>,
    /// The header the record claims; as [`OpRecord::header`], trusted only after
    /// [`SnapRecord::verify`].
    pub(super) header: SnapshotHeader,
    /// The snapshot `data`, sealed: the `ITEM_SNAPSHOT` envelope.
    pub(super) data: Vec<u8>,
    /// The wrap of the item key `data` is sealed under, as [`OpRecord::wrap`].
    pub(super) wrap: Option<Wrap>,
    /// The simulation's ground truth, never sent and never read by the server or a device's
    /// sync code: whether the snapshot may lie, because a faulty device wrote it dishonestly
    /// or its author had absorbed such a snapshot before writing it (the merge spike's
    /// `honest` and `tainted`). Only the property checks read it.
    pub(super) tainted: bool,
}

impl SnapRecord {
    /// Verifies the record's signature, as [`OpRecord::verify`]: under the key of the claimed
    /// author, with the verified statement's header equal to the claimed one.
    pub(super) fn verify(&self) -> Option<Verified<SnapshotStatement>> {
        let (statement, header) = crypto::verify_snapshot(&self.signed, self.header.author)?;
        (header == self.header).then_some(statement)
    }

    /// Whether the record's signature verifies and its `data` is the envelope the statement
    /// signed.
    fn verifies_with_data(&self) -> bool {
        self.verify()
            .is_some_and(|statement| statement.matches_envelope(&self.data))
    }
}

/// A retained snapshot: the record, its store sequence and its clamped VV (ADR 0021 §2).
#[derive(Clone, Debug)]
struct Stored {
    /// The record as uploaded.
    record: SnapRecord,
    /// Its store sequence.
    store_seq: u64,
    /// Its clamped VV, computed once when stored.
    clamped: VersionVector,
}

impl Stored {
    /// The row [`crate::compaction`] reads.
    fn row(&self) -> RetainedSnapshot {
        RetainedSnapshot {
            store_seq: self.store_seq,
            clamped: self.clamped.clone(),
            author: self.record.header.author,
        }
    }
}

/// Everything a restore rolls back: the database of one vault.
#[derive(Clone, Debug)]
struct Db {
    /// The op records per chain, by `device_seq`; `body` is `None` once bodiless.
    chains: BTreeMap<DeviceId, BTreeMap<u64, OpRecord>>,
    /// The retained snapshots per item.
    snapshots: BTreeMap<ItemId, Vec<Stored>>,
    /// The last store sequence assigned.
    store_seq: u64,
    /// The revocation cut-offs: `last_accepted_device_seq` per revoked device.
    cutoffs: BTreeMap<DeviceId, u64>,
    /// The restore generation (ADR 0021 §2).
    generation: RestoreGeneration,
    /// For the checker: the store sequence counter when each op was stored.
    stored_at: BTreeMap<Dot, u64>,
    /// For the checker: the ops a healing request stored without their body, while bodiless.
    healed: BTreeSet<Dot>,
    /// For the checker: each item's covered VV of the snapshot stored last.
    last_covered: BTreeMap<ItemId, VersionVector>,
    /// For the checker: the items with a snapshot whose covered VV is not at least that of the
    /// one stored before it (property 5 does not apply to them).
    nonlinear: BTreeSet<ItemId>,
    /// The vault's current `vault_key_epoch` (CRYPTO.md §4.4).
    epoch: u32,
    /// The wrap set.
    rows: Rows,
    /// For the stale-epoch check of the world: each op stored outside a healing request, with
    /// the vault epoch at the moment it was stored.
    stored_epoch: BTreeMap<Dot, u32>,
    /// For the world's writer-rule check: every op body and snapshot envelope stored through a
    /// healing request (ADR 0021 §9 "Healing request" exempts it from the stale-epoch check,
    /// so it may carry a key from before a rotation the request's author missed).
    healed_envelopes: BTreeSet<Vec<u8>>,
}

impl Db {
    /// Every head h(V, d).
    fn heads(&self) -> VersionVector {
        self.chains
            .values()
            .filter_map(|chain| chain.values().next_back().map(|r| r.header.dot))
            .collect()
    }

    /// The record stored at `dot`.
    fn record(&self, dot: Dot) -> Option<&OpRecord> {
        self.chains.get(&dot.device_id())?.get(&dot.seq())
    }

    /// Adds the row of the wrap `record` carries, if any and if the vault has no row for that
    /// item key yet. A wrap below the vault's epoch adds nothing: its key's row, if the key was
    /// ever stored, was re-wrapped by the rotation that raised the epoch.
    fn add_row(&mut self, item: ItemId, envelope: Option<&[u8]>, wrap: Option<&Wrap>) {
        let (Some(envelope), Some(wrap)) = (envelope, wrap) else {
            return;
        };
        let Some(key) = crypto::envelope_key(envelope) else {
            return;
        };
        if wrap.epoch >= self.epoch {
            self.rows
                .entry((item, *key.as_bytes()))
                .or_insert_with(|| wrap.clone());
        }
    }

    /// Stores a snapshot after the §9 checks against `heads`.
    fn store_snapshot(
        &mut self,
        record: &SnapRecord,
        heads: &VersionVector,
        expiry: CertificateExpiry,
    ) -> Result<(), SnapshotRefusal> {
        let chains = VaultChains {
            heads,
            cutoffs: &self.cutoffs,
        };
        check_snapshot(record.header.author, &record.header.covered, chains, expiry)?;
        self.add_row(
            record.header.item_id,
            Some(&record.data),
            record.wrap.as_ref(),
        );
        self.store_seq += 1;
        let stored = Stored {
            record: record.clone(),
            store_seq: self.store_seq,
            clamped: clamp(&record.header.covered, heads),
        };
        let item = record.header.item_id;
        if let Some(last) = self.last_covered.get(&item)
            && matches!(
                record.header.covered.compare(last),
                VvOrdering::Less | VvOrdering::Concurrent
            )
        {
            self.nonlinear.insert(item);
        }
        self.last_covered
            .insert(item, record.header.covered.clone());
        self.snapshots
            .entry(record.header.item_id)
            .or_default()
            .push(stored);
        Ok(())
    }

    /// Whether a snapshot with this record's id is retained, byte-identical.
    fn holds_snapshot(&self, record: &SnapRecord) -> bool {
        self.snapshots
            .get(&record.header.item_id)
            .is_some_and(|v| v.iter().any(|s| s.record == *record))
    }

    /// The op dots of `item` with their body flags, for [`plan_worker`].
    fn op_dots(&self, item: ItemId) -> Vec<OpDot> {
        self.chains
            .values()
            .flat_map(BTreeMap::values)
            .filter(|r| r.header.item_id == item)
            .map(|r| OpDot {
                dot: r.header.dot,
                body: if r.body.is_some() {
                    Body::Held
                } else {
                    Body::Absent
                },
            })
            .collect()
    }

    /// `item`'s retained snapshots as the checker reads them.
    fn checker_rows(&self, item: ItemId) -> Vec<checker::Row> {
        self.snapshots
            .get(&item)
            .map(|v| {
                v.iter()
                    .map(|s| checker::Row {
                        store_seq: s.store_seq,
                        clamped: s.clamped.clone(),
                        covered: s.record.header.covered.clone(),
                        author: s.record.header.author,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// `item`'s op headers as the checker reads them.
    fn checker_ops(&self, item: ItemId) -> Vec<checker::OpRow> {
        self.chains
            .values()
            .flat_map(BTreeMap::values)
            .filter(|r| r.header.item_id == item)
            .map(|r| checker::OpRow {
                dot: r.header.dot,
                held: r.body.is_some(),
                stored_at: self.stored_at.get(&r.header.dot).copied().unwrap_or(0),
                healed: self.healed.contains(&r.header.dot),
            })
            .collect()
    }

    /// Every item with an op or a snapshot.
    fn items(&self) -> BTreeSet<ItemId> {
        let mut items: BTreeSet<ItemId> = self.snapshots.keys().copied().collect();
        items.extend(
            self.chains
                .values()
                .flat_map(BTreeMap::values)
                .map(|r| r.header.item_id),
        );
        items
    }
}

/// The server's answer to an op upload (ADR 0012 §7 "Upload", ADR 0021 §9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OpAnswer {
    /// Stored.
    Stored,
    /// "Already stored": byte-identical to the stored record; an acknowledgement.
    AlreadyStored,
    /// A different record at a stored dot.
    Conflict,
    /// Its `vault_prev_seq` is not the head.
    NotLinked,
    /// Past its author's revocation cut-off.
    Revoked,
    /// Its `vault_key_epoch` is below the vault's (ADR 0021 §9 "Stale epoch").
    StaleEpoch,
    /// The uploading session's certificate expired (CRYPTO.md §10.2: "The server refuses
    /// uploads from an expired certificate").
    Expired,
    /// The body does not match the signed envelope hash.
    BadBody,
    /// The statement's signature does not verify under its author's key, or the statement
    /// signs another header than the record claims.
    BadSignature,
}

/// The server's answer to a snapshot upload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SnapAnswer {
    /// Stored.
    Stored,
    /// "Already stored".
    AlreadyStored,
    /// Refused under ADR 0021 §9.
    Refused(SnapshotRefusal),
    /// Its `vault_key_epoch` is below the vault's: the client only discards and rewrites it.
    StaleEpoch,
    /// The data does not match the signed envelope hash.
    BadData,
    /// The statement's signature does not verify under its author's key, or the statement
    /// signs another header than the record claims.
    BadSignature,
}

/// Why a healing request was refused as a whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HealRefusal {
    /// An op record was refused.
    Op(Dot, OpAnswer),
    /// A snapshot was refused.
    Snapshot(SnapshotRefusal),
    /// A snapshot's signature did not verify, or its data is not the envelope it signed.
    BadSnapshot,
    /// A bodiless header had no cover among the item's snapshots (§9 "Server acceptance").
    Uncovered(Dot),
}

/// A healing request (ADR 0021 §9 "Healing request"): op records in chain order, some without
/// their bodies, then snapshots.
#[derive(Clone, Debug, Default)]
pub(super) struct HealingRequest {
    /// Every item-key wrap the server lacks, first ("every item-key wrap the server lacks,
    /// then per chain ..."), wrapped at the healer's epoch.
    pub(super) wraps: Vec<WrapRow>,
    /// The op records, per chain in chain order.
    pub(super) ops: Vec<OpRecord>,
    /// The fresh snapshots and the held ones sent verbatim.
    pub(super) snapshots: Vec<SnapRecord>,
}

/// One page of a Fetch response: op records per device in chain order, and the covers the
/// server selected for the page's bodiless headers, newest first per item (ADR 0021 §4).
#[derive(Clone, Debug, Default)]
pub(super) struct Page {
    /// The op records.
    pub(super) ops: Vec<OpRecord>,
    /// The covers.
    pub(super) covers: Vec<SnapRecord>,
}

/// A Fetch response.
#[derive(Clone, Debug)]
pub(super) struct Response {
    /// Its pages.
    pub(super) pages: Vec<Page>,
    /// The revocation cut-offs the server serves (the signed revocations of the account state).
    pub(super) cutoffs: BTreeMap<DeviceId, u64>,
    /// The restore generation.
    pub(super) generation: RestoreGeneration,
    /// The vault's wrap-set rows.
    pub(super) wraps: Vec<WrapRow>,
    /// The `expires_at_ms` of every expiring certificate (kind 4), standing in for the
    /// certificates a response carries.
    pub(super) expiries: BTreeMap<DeviceId, u64>,
}

/// Why the server refused a rotation (ADR 0025 §3); nothing of it is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RotationRefusal {
    /// The new epoch is not above the stored one (check 2).
    Epoch,
    /// A wrap is not at the new epoch, or the re-wrapped and dropped rows are not exactly the
    /// stored ones (check 3).
    Wraps,
    /// The rotator's cursor is not every head (check 4, the rotation cut-off).
    Cursor,
}

/// A rotation upload's vault half (ADR 0025 §1), with the revocation it carries, if any.
#[derive(Clone, Debug)]
pub(super) struct Rotation {
    /// The new `vault_key_epoch`.
    pub(super) epoch: u32,
    /// The rotator's fetch cursor.
    pub(super) cursor: VersionVector,
    /// Every stored row the rotator could open, re-wrapped at the new epoch.
    pub(super) rewrapped: Vec<WrapRow>,
    /// The stored rows it could not open.
    pub(super) dropped: Vec<(ItemId, SymmetricKeyId)>,
    /// The device the rotation revokes, if any (CRYPTO.md §11.8: one atomic request).
    pub(super) revoke: Option<DeviceId>,
}

/// A withholding fault (property 7): Fetch responses to `victim` leave out the op at `dot`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Withhold {
    /// The device whose responses omit the op.
    pub(super) victim: DeviceId,
    /// The op left out.
    pub(super) dot: Dot,
}

/// Counters of what a run reached, for coverage.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ServerStats {
    /// Bodies `worker` deleted.
    pub(super) bodies_deleted: u64,
    /// Snapshots R3 dropped.
    pub(super) snapshots_dropped: u64,
    /// Covers served.
    pub(super) covers_served: u64,
    /// Snapshots refused.
    pub(super) snapshots_refused: u64,
    /// Snapshots refused because their author is revoked (ADR 0021 §9 "Revoked and kind-4
    /// authors").
    pub(super) revoked_refused: u64,
    /// Healing requests stored.
    pub(super) heals_stored: u64,
    /// Healing requests refused.
    pub(super) heals_refused: u64,
    /// "Already stored" answers.
    pub(super) already_stored: u64,
    /// Restores.
    pub(super) restores: u64,
    /// What the checker checked after `worker` runs (properties 4 and 5).
    pub(super) worker_checks: checker::WorkerChecks,
    /// Pages checked for property 3 and the §4 selection with at least one bodiless header.
    pub(super) pages_checked: u64,
    /// Ops refused as stale.
    pub(super) stale_ops: u64,
    /// Snapshots refused as stale.
    pub(super) stale_snapshots: u64,
    /// Rotations stored.
    pub(super) rotations: u64,
    /// Rotations refused.
    pub(super) rotations_refused: u64,
    /// Uploads refused because the session's certificate expired.
    pub(super) expired_uploads: u64,
    /// Snapshots refused because their author's certificate expired.
    pub(super) expired_snapshots: u64,
    /// Covers served by an author whose certificate expired: retained ones keep counting.
    pub(super) expired_covers: u64,
    /// Lag repairs of the vault epoch stored (ADR 0032 §3).
    pub(super) epoch_heals: u64,
}

/// The simulated server of one vault.
#[derive(Debug)]
pub(super) struct Server {
    /// The live database.
    db: Db,
    /// The last backup, if any (ADR 0011 "Backups").
    backup: Option<Db>,
    /// The number of restore generations drawn so far; the next one's bytes derive from it.
    generations: u8,
    /// The withholding fault, if on.
    pub(super) withhold: Option<Withhold>,
    /// The kind-4 devices whose certificate has expired at the server's clock. Time, not
    /// data: a restore does not bring a certificate back.
    pub(super) expired: BTreeSet<DeviceId>,
    /// The `expires_at_ms` of every expiring certificate the server holds (kind 4).
    pub(super) certificates: BTreeMap<DeviceId, u64>,
    /// Integrity errors: a bodiless header served without a cover (§4), which an honest server
    /// never produces (§8 property 1).
    pub(super) integrity_errors: Vec<Dot>,
    /// Rows `compaction` refused as inconsistent ([`crate::compaction::InputError`]); never
    /// on this server.
    pub(super) input_errors: u64,
    /// ADR 0021 §8 server property violations the checker found ([`super::checker`]), as lines
    /// of server-visible metadata; the world moves them into its own after every step.
    pub(super) violations: Vec<String>,
    /// Coverage counters.
    pub(super) stats: ServerStats,
}

impl Server {
    /// An empty server.
    pub(super) fn new() -> Self {
        Self {
            db: Db {
                chains: BTreeMap::new(),
                snapshots: BTreeMap::new(),
                store_seq: 0,
                cutoffs: BTreeMap::new(),
                generation: RestoreGeneration::from_bytes([0; RestoreGeneration::LEN]),
                stored_at: BTreeMap::new(),
                healed: BTreeSet::new(),
                last_covered: BTreeMap::new(),
                nonlinear: BTreeSet::new(),
                epoch: 0,
                rows: Rows::new(),
                stored_epoch: BTreeMap::new(),
                healed_envelopes: BTreeSet::new(),
            },
            backup: None,
            generations: 0,
            withhold: None,
            expired: BTreeSet::new(),
            certificates: BTreeMap::new(),
            integrity_errors: Vec::new(),
            input_errors: 0,
            violations: Vec::new(),
            stats: ServerStats::default(),
        }
    }

    /// Every head h(V, d).
    pub(super) fn heads(&self) -> VersionVector {
        self.db.heads()
    }

    /// The restore generation.
    pub(super) fn generation(&self) -> RestoreGeneration {
        self.db.generation
    }

    /// The vault's current `vault_key_epoch`.
    pub(super) fn epoch(&self) -> u32 {
        self.db.epoch
    }

    /// The wrap-set rows.
    pub(super) fn rows(&self) -> Vec<WrapRow> {
        self.db
            .rows
            .iter()
            .map(|(&(item, key), wrap)| WrapRow {
                item,
                key: SymmetricKeyId::from_bytes(key),
                wrap: wrap.clone(),
            })
            .collect()
    }

    /// Every op stored outside a healing request, with the vault epoch when it was stored, for
    /// the world's stale-epoch check.
    pub(super) fn stored_epochs(&self) -> impl Iterator<Item = (&OpHeader, u32)> + '_ {
        self.db
            .stored_epoch
            .iter()
            .filter_map(|(&dot, &epoch)| self.db.record(dot).map(|r| (&r.header, epoch)))
    }

    /// Every op body and snapshot envelope stored through a healing request: for the world's
    /// writer-rule check, which excuses these (ADR 0021 §9 "Healing request" exempts them from
    /// the stale-epoch check, so one may carry a key from before a rotation its author missed).
    pub(super) fn healed_envelopes(&self) -> &BTreeSet<Vec<u8>> {
        &self.db.healed_envelopes
    }

    /// The revocation cut-offs.
    pub(super) fn cutoffs(&self) -> &BTreeMap<DeviceId, u64> {
        &self.db.cutoffs
    }

    /// Every op body and snapshot envelope the server holds, with its header: what property 6
    /// reads.
    pub(super) fn envelopes(&self) -> (Vec<(&OpHeader, &[u8])>, Vec<&SnapRecord>) {
        let ops = self
            .db
            .chains
            .values()
            .flat_map(BTreeMap::values)
            .filter_map(|r| r.body.as_deref().map(|b| (&r.header, b)))
            .collect();
        (ops, self.snapshot_records().collect())
    }

    /// A fingerprint of the database for the drain's fixed point: every record's dot and body
    /// flag, every retained snapshot's store sequence, and the cut-offs.
    pub(super) fn fingerprint(&self) -> (Vec<(Dot, bool)>, Vec<u64>, usize) {
        let ops = self
            .db
            .chains
            .values()
            .flat_map(BTreeMap::values)
            .map(|r| (r.header.dot, r.body.is_some()))
            .collect();
        let snaps = self
            .db
            .snapshots
            .values()
            .flatten()
            .map(|s| s.store_seq)
            .collect();
        (
            ops,
            snaps,
            self.db.cutoffs.len() + self.db.rows.len() + self.db.epoch as usize,
        )
    }

    /// Checks one op record for storing into `db` (the upload checks of ADR 0012 §7 and
    /// ADR 0021 §9, in order: "already stored" first, then conflict, the signature,
    /// revocation, the stale epoch, link, body). `healing` is a healing request's record, which
    /// may be bodiless and is exempt from the stale-epoch check.
    fn check_op(db: &Db, record: &OpRecord, healing: bool) -> Result<bool, OpAnswer> {
        let dot = record.header.dot;
        if let Some(stored) = db.record(dot) {
            // "Byte-identical to the record the server stores": the signed statement, and the
            // body when both have one (a bodiless stored header and a re-published body of the
            // same statement are the same signed record). The stored statement was verified
            // when it was stored, so identical bytes need no second verification.
            let same = stored.signed == record.signed
                && (stored.body.is_none() || record.body.is_none() || stored.body == record.body);
            return if same {
                Ok(false)
            } else {
                Err(OpAnswer::Conflict)
            };
        }
        // Nothing of the header is used before the signature over it verified.
        let Some(statement) = record.verify() else {
            return Err(OpAnswer::BadSignature);
        };
        let cutoff = db.cutoffs.get(&dot.device_id()).copied();
        if cutoff.is_some_and(|cutoff| dot.seq() > cutoff) {
            return Err(OpAnswer::Revoked);
        }
        // "Stale epoch": a bodiless header, a healing request's record, and a revoked device's
        // op at or below its cut-off are exempt.
        let exempt = healing || record.body.is_none() || cutoff.is_some();
        if !exempt && record.header.vault_key_epoch < db.epoch {
            return Err(OpAnswer::StaleEpoch);
        }
        if record.header.vault_prev_seq != db.heads().get(dot.device_id()) {
            return Err(OpAnswer::NotLinked);
        }
        match &record.body {
            Some(body) if !statement.matches_envelope(body) => Err(OpAnswer::BadBody),
            None if !healing => Err(OpAnswer::NotLinked),
            _ => Ok(true),
        }
    }

    /// Stores `record` into `db` (after [`Server::check_op`] said it is new), with the row of
    /// the wrap it carries.
    fn insert_op(db: &mut Db, record: &OpRecord, healing: bool) {
        db.stored_at.insert(record.header.dot, db.store_seq);
        if !healing {
            db.stored_epoch.insert(record.header.dot, db.epoch);
        }
        db.add_row(
            record.header.item_id,
            record.body.as_deref(),
            record.wrap.as_ref(),
        );
        if let Some(body) = &record.body {
            if healing {
                db.healed_envelopes.insert(body.clone());
            }
        } else {
            db.healed.insert(record.header.dot);
        }
        db.chains
            .entry(record.header.dot.device_id())
            .or_default()
            .insert(record.header.dot.seq(), record.clone());
    }

    /// Whether `author`'s certificate has expired at the server's clock.
    fn expiry(&self, author: DeviceId) -> CertificateExpiry {
        if self.expired.contains(&author) {
            CertificateExpiry::Expired
        } else {
            CertificateExpiry::Unexpired
        }
    }

    /// An op upload through the normal path (a body is required), in the session of the op's
    /// author.
    pub(super) fn upload_op(&mut self, record: &OpRecord) -> OpAnswer {
        if self.expired.contains(&record.header.dot.device_id()) {
            self.stats.expired_uploads += 1;
            return OpAnswer::Expired;
        }
        if record.body.is_none() {
            return OpAnswer::NotLinked;
        }
        match Self::check_op(&self.db, record, false) {
            Ok(true) => {
                Self::insert_op(&mut self.db, record, false);
                OpAnswer::Stored
            }
            Ok(false) => {
                self.stats.already_stored += 1;
                OpAnswer::AlreadyStored
            }
            Err(answer) => {
                if answer == OpAnswer::StaleEpoch {
                    self.stats.stale_ops += 1;
                }
                answer
            }
        }
    }

    /// A snapshot upload through the normal path, in the session of its author: "already
    /// stored", the signature and data, the stale epoch (unless the author is revoked, which
    /// [`check_snapshot`] refuses), then the §9 acceptance checks with the author's expiry.
    pub(super) fn upload_snapshot(&mut self, record: &SnapRecord) -> SnapAnswer {
        if self.db.holds_snapshot(record) {
            self.stats.already_stored += 1;
            return SnapAnswer::AlreadyStored;
        }
        let Some(statement) = record.verify() else {
            self.stats.snapshots_refused += 1;
            return SnapAnswer::BadSignature;
        };
        if !statement.matches_envelope(&record.data) {
            self.stats.snapshots_refused += 1;
            return SnapAnswer::BadData;
        }
        let author = record.header.author;
        if record.header.vault_key_epoch < self.db.epoch
            && !self.db.cutoffs.contains_key(&author)
            && !self.expired.contains(&author)
        {
            self.stats.stale_snapshots += 1;
            return SnapAnswer::StaleEpoch;
        }
        let heads = self.db.heads();
        let expiry = self.expiry(author);
        match self.db.store_snapshot(record, &heads, expiry) {
            Ok(()) => SnapAnswer::Stored,
            Err(refusal) => {
                self.stats.snapshots_refused += 1;
                match refusal {
                    SnapshotRefusal::AuthorRevoked => self.stats.revoked_refused += 1,
                    SnapshotRefusal::AuthorExpired => self.stats.expired_snapshots += 1,
                    _ => {}
                }
                SnapAnswer::Refused(refusal)
            }
        }
    }

    /// A healing request, atomic: every op in chain order (bodiless ones allowed), then every
    /// snapshot against the heads after the request's headers, then the §9 cover check of the
    /// bodiless headers it stored. Any refusal rolls the whole request back.
    pub(super) fn heal(&mut self, request: &HealingRequest) -> Result<(), HealRefusal> {
        let mut db = self.db.clone();
        for row in &request.wraps {
            if row.wrap.epoch >= db.epoch {
                db.rows
                    .entry((row.item, *row.key.as_bytes()))
                    .or_insert_with(|| row.wrap.clone());
            }
        }
        let mut ops: Vec<&OpRecord> = request.ops.iter().collect();
        ops.sort_by_key(|r| r.header.dot);
        let mut stored_bodiless: BTreeMap<ItemId, Vec<Dot>> = BTreeMap::new();
        for record in ops {
            let dot = record.header.dot;
            match Self::check_op(&db, record, true) {
                Ok(true) => {
                    Self::insert_op(&mut db, record, true);
                    if record.body.is_none() {
                        stored_bodiless
                            .entry(record.header.item_id)
                            .or_default()
                            .push(dot);
                    }
                }
                Ok(false) => {
                    // Already stored: a held body re-published over a bodiless row restores it,
                    // if it is the envelope the stored statement signed.
                    if let (Some(body), Some(chain)) =
                        (&record.body, db.chains.get_mut(&dot.device_id()))
                        && let Some(stored) = chain.get_mut(&dot.seq())
                        && stored.body.is_none()
                        && record
                            .verify()
                            .is_some_and(|statement| statement.matches_envelope(body))
                    {
                        stored.body = Some(body.clone());
                        db.healed.remove(&dot);
                        db.healed_envelopes.insert(body.clone());
                        db.add_row(record.header.item_id, Some(body), record.wrap.as_ref());
                    }
                }
                Err(answer) => {
                    self.stats.heals_refused += 1;
                    return Err(HealRefusal::Op(dot, answer));
                }
            }
        }
        let heads = db.heads();
        for snap in &request.snapshots {
            if db.holds_snapshot(snap) {
                continue;
            }
            if !snap.verifies_with_data() {
                self.stats.heals_refused += 1;
                return Err(HealRefusal::BadSnapshot);
            }
            if let Err(refusal) = db.store_snapshot(snap, &heads, self.expiry(snap.header.author)) {
                self.stats.heals_refused += 1;
                return Err(HealRefusal::Snapshot(refusal));
            }
            db.healed_envelopes.insert(snap.data.clone());
        }
        for (item, dots) in &stored_bodiless {
            let rows: Vec<RetainedSnapshot> = db
                .snapshots
                .get(item)
                .map(|v| v.iter().map(Stored::row).collect())
                .unwrap_or_default();
            if let Err(uncovered) = check_healing_request(&rows, dots) {
                self.stats.heals_refused += 1;
                return Err(HealRefusal::Uncovered(uncovered.dot));
            }
        }
        self.db = db;
        self.stats.heals_stored += 1;
        Ok(())
    }

    /// Records a revocation: `last_accepted_device_seq` is the server's head for the device, so
    /// every op of it the server holds stays accepted (ADR 0012 §6).
    fn revoke(db: &mut Db, device: DeviceId) -> u64 {
        let cutoff = db.heads().get(device);
        db.cutoffs.entry(device).or_insert(cutoff);
        db.cutoffs.get(&device).copied().unwrap_or(cutoff)
    }

    /// A rotation's vault half (ADR 0025 §3), with the revocation it carries, checked and
    /// applied in one transaction: check 2, the new epoch above the stored one; check 4, the
    /// rotator's cursor equal to every head h(V, d), a missing entry being 0 ("Rotation
    /// cut-off"); check 3, every wrap at the new epoch and the re-wrapped and dropped rows
    /// exactly the stored ones. Then the epoch is set, each re-wrapped row overwritten and each
    /// dropped row deleted. Returns the revocation's cut-off, if one was carried.
    ///
    /// # Errors
    /// The first failing check; nothing is stored.
    pub(super) fn rotate(&mut self, rotation: &Rotation) -> Result<Option<u64>, RotationRefusal> {
        let refuse = |stats: &mut ServerStats, refusal| {
            stats.rotations_refused += 1;
            Err(refusal)
        };
        if rotation.epoch <= self.db.epoch {
            return refuse(&mut self.stats, RotationRefusal::Epoch);
        }
        let heads = self.db.heads();
        let devices: BTreeSet<DeviceId> = heads
            .entries()
            .chain(rotation.cursor.entries())
            .map(Dot::device_id)
            .collect();
        if devices
            .iter()
            .any(|&d| heads.get(d) != rotation.cursor.get(d))
        {
            return refuse(&mut self.stats, RotationRefusal::Cursor);
        }
        let mut named: BTreeSet<(ItemId, [u8; 16])> = BTreeSet::new();
        for row in &rotation.rewrapped {
            if row.wrap.epoch != rotation.epoch || !named.insert((row.item, *row.key.as_bytes())) {
                return refuse(&mut self.stats, RotationRefusal::Wraps);
            }
        }
        for (item, key) in &rotation.dropped {
            if !named.insert((*item, *key.as_bytes())) {
                return refuse(&mut self.stats, RotationRefusal::Wraps);
            }
        }
        if named != self.db.rows.keys().copied().collect() {
            return refuse(&mut self.stats, RotationRefusal::Wraps);
        }
        let cutoff = rotation.revoke.map(|d| Self::revoke(&mut self.db, d));
        self.db.epoch = rotation.epoch;
        for (item, key) in &rotation.dropped {
            self.db.rows.remove(&(*item, *key.as_bytes()));
        }
        for row in &rotation.rewrapped {
            self.db
                .rows
                .insert((row.item, *row.key.as_bytes()), row.wrap.clone());
        }
        self.stats.rotations += 1;
        Ok(cutoff)
    }

    /// The ADR 0032 §3 lag repair of the vault epoch after a restore (step 3b: the self-grant
    /// and the wrap-set rows the healer holds at its epoch). Stored only when the new epoch is
    /// above the stored one and no stored row or op record names an epoch above it; then the
    /// epoch is set, each sent row (at the new epoch) replaces the row of the same item key,
    /// and every stored row below the new epoch that the request does not replace is deleted.
    /// Returns whether it was stored.
    pub(super) fn heal_epoch(&mut self, epoch: u32, rows: &[WrapRow]) -> bool {
        let above = self.db.rows.values().any(|w| w.epoch > epoch)
            || self
                .db
                .chains
                .values()
                .flat_map(BTreeMap::values)
                .any(|r| r.header.vault_key_epoch > epoch);
        if epoch <= self.db.epoch || above || rows.iter().any(|r| r.wrap.epoch != epoch) {
            return false;
        }
        self.db.epoch = epoch;
        let sent: BTreeSet<(ItemId, [u8; 16])> =
            rows.iter().map(|r| (r.item, *r.key.as_bytes())).collect();
        self.db
            .rows
            .retain(|k, w| w.epoch >= epoch || sent.contains(k));
        for row in rows {
            self.db
                .rows
                .insert((row.item, *row.key.as_bytes()), row.wrap.clone());
        }
        self.stats.epoch_heals += 1;
        true
    }

    /// `worker`: R1 then R3 on every item (ADR 0021 §3), through [`plan_worker`], then the
    /// checker's properties 4 and 5 on the rows it left.
    pub(super) fn worker(&mut self) {
        let items: Vec<ItemId> = self.db.snapshots.keys().copied().collect();
        for item in items {
            let rows: Vec<RetainedSnapshot> = self
                .db
                .snapshots
                .get(&item)
                .map(|v| v.iter().map(Stored::row).collect())
                .unwrap_or_default();
            let ops = self.db.op_dots(item);
            let Ok(plan) = plan_worker(&rows, &ops) else {
                self.input_errors += 1;
                continue;
            };
            for dot in &plan.delete_bodies {
                if let Some(record) = self
                    .db
                    .chains
                    .get_mut(&dot.device_id())
                    .and_then(|c| c.get_mut(&dot.seq()))
                {
                    record.body = None;
                    self.stats.bodies_deleted += 1;
                }
            }
            let drops: BTreeSet<u64> = plan.drop_snapshots.iter().copied().collect();
            if let Some(v) = self.db.snapshots.get_mut(&item) {
                let before = v.len();
                v.retain(|s| !drops.contains(&s.store_seq));
                self.stats.snapshots_dropped += (before - v.len()) as u64;
            }
        }
        self.check_after_worker();
    }

    /// Takes a backup of the database.
    pub(super) fn backup(&mut self) {
        self.backup = Some(self.db.clone());
    }

    /// Restores the last backup, if any, with a fresh restore generation (ADR 0021 §2).
    pub(super) fn restore(&mut self) -> bool {
        let Some(backup) = self.backup.clone() else {
            return false;
        };
        self.db = backup;
        self.generations = self.generations.wrapping_add(1);
        self.db.generation =
            RestoreGeneration::from_bytes([self.generations; RestoreGeneration::LEN]);
        self.stats.restores += 1;
        true
    }

    /// A Fetch from `cursor` by `requester`, in pages of at most `page_len` records (0: one
    /// page). Every op record above the cursor, per device in chain order; per page and item,
    /// the covers [`select_covers`] picks for the page's bodiless headers, newest first. A
    /// bodiless header [`select_covers`] finds no cover for is an integrity error (§4).
    ///
    /// Each page is then checked by [`checker::page`], from the retained rows and never from
    /// [`select_covers`]' own report: ADR 0021 §8 property 3 (each bodiless header of the page
    /// comes with a served snapshot whose clamped and covered VVs both cover it), covers by two
    /// authors when the rows have them, and §4's selection rule itself.
    pub(super) fn fetch(
        &mut self,
        requester: DeviceId,
        cursor: &VersionVector,
        page_len: usize,
    ) -> Response {
        let withheld = self
            .withhold
            .filter(|w| w.victim == requester)
            .map(|w| w.dot);
        let records: Vec<OpRecord> = self
            .db
            .chains
            .iter()
            .flat_map(|(&device, chain)| {
                chain
                    .range(cursor.get(device).saturating_add(1)..)
                    .map(|(_, r)| r)
            })
            .filter(|r| Some(r.header.dot) != withheld)
            .cloned()
            .collect();
        let size = if page_len == 0 {
            records.len().max(1)
        } else {
            page_len
        };
        let chunks: Vec<&[OpRecord]> = records.chunks(size).collect();
        let mut pages = Vec::new();
        for chunk in chunks {
            let mut page = Page {
                ops: chunk.to_vec(),
                covers: Vec::new(),
            };
            let mut bodiless: BTreeMap<ItemId, Vec<Dot>> = BTreeMap::new();
            for r in chunk.iter().filter(|r| r.body.is_none()) {
                bodiless
                    .entry(r.header.item_id)
                    .or_default()
                    .push(r.header.dot);
            }
            for (item, dots) in &bodiless {
                let stored: &[Stored] = self.db.snapshots.get(item).map_or(&[], Vec::as_slice);
                let rows: Vec<RetainedSnapshot> = stored.iter().map(Stored::row).collect();
                let mut served = Vec::new();
                match select_covers(&rows, dots) {
                    Ok(selection) => {
                        self.integrity_errors
                            .extend(selection.uncovered.iter().copied());
                        for seq in selection.covers {
                            if let Some(s) = stored.iter().find(|s| s.store_seq == seq) {
                                if self.expired.contains(&s.record.header.author) {
                                    self.stats.expired_covers += 1;
                                }
                                page.covers.push(s.record.clone());
                                served.push(seq);
                                self.stats.covers_served += 1;
                            }
                        }
                    }
                    Err(_) => self.integrity_errors.extend(dots.iter().copied()),
                }
                self.stats.pages_checked += 1;
                let found = checker::page(*item, &self.db.checker_rows(*item), dots, &served);
                self.violations.extend(found);
            }
            pages.push(page);
        }
        if pages.is_empty() {
            pages.push(Page::default());
        }
        Response {
            pages,
            cutoffs: self.db.cutoffs.clone(),
            generation: self.db.generation,
            wraps: self.rows(),
            expiries: self.certificates.clone(),
        }
    }

    /// ADR 0021 §8 properties 1 and 2 on every item, through [`checker::stored`]: every
    /// bodiless header has a retained cover, and no snapshot covers an op stored after it.
    /// What it finds goes into [`Server::violations`].
    pub(super) fn check_stored(&mut self) {
        for item in self.db.items() {
            let found = checker::stored(
                item,
                &self.db.checker_rows(item),
                &self.db.checker_ops(item),
            );
            self.violations.extend(found);
        }
    }

    /// ADR 0021 §8 properties 4 and 5 on every item, through [`checker::after_worker`], right
    /// after [`Server::worker`].
    fn check_after_worker(&mut self) {
        for item in self.db.items() {
            let found = checker::after_worker(
                item,
                &self.db.checker_rows(item),
                &self.db.checker_ops(item),
                !self.db.nonlinear.contains(&item),
                &mut self.stats.worker_checks,
            );
            self.violations.extend(found);
        }
    }

    /// The header of the op record stored at `dot`.
    pub(super) fn stored_header(&self, dot: Dot) -> Option<&OpHeader> {
        self.db.record(dot).map(|r| &r.header)
    }

    /// The dots of `item`'s bodiless headers.
    pub(super) fn bodiless(&self, item: ItemId) -> Vec<Dot> {
        self.db
            .chains
            .values()
            .flat_map(BTreeMap::values)
            .filter(|r| r.header.item_id == item && r.body.is_none())
            .map(|r| r.header.dot)
            .collect()
    }

    /// Every retained snapshot record, for the order-independence check.
    pub(super) fn snapshot_records(&self) -> impl Iterator<Item = &SnapRecord> + '_ {
        self.db.snapshots.values().flatten().map(|s| &s.record)
    }
}
