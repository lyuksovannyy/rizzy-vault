//! A simulated client device: one [`VaultLog`] and one [`ItemMerge`] per item, driven through
//! the client cycle the `causal` module documents (verify, plan, absorb, commit, deliver), the
//! own-chain upload bookkeeping, "Server behind" and the healing request (ADR 0012 §4, §7;
//! ADR 0018 §3, §10; ADR 0021 §4, §9).
//!
//! # What the device keeps
//!
//! - Every accepted link's statement ("Headers kept", ADR 0021 §9), every snapshot record it
//!   wrote or absorbed, and its merges.
//! - Op bodies: those it still needs, as ADR 0018 §10 "Newest snapshot" says a client keeps
//!   them: the retained ops of each item ([`ItemMerge::retained_ops`]), the bodies that wait in
//!   the causal layer, and its own ops the server has not acknowledged. The rest is dropped, as
//!   the merge spike's `integrated` preset drops them (`keepown` = "since newest snapshot"), so
//!   that a healing request has to send headers without their bodies behind snapshots.
//!
//! # Ground truth for the checks
//!
//! A faulty device ([`Device::faulty`]) sends lies ([`super::faults`]) in the snapshots the
//! scheduler asks it for, and in the fresh snapshots of its healing requests if given
//! [`Device::heal_lie`]; its merge and ops stay honest. Each record carries whether it may lie
//! ([`SnapRecord::tainted`]), and a device that absorbs one is tainted from then on. The sync
//! code never reads either; the device only sorts what the merge reports by them: a refusal
//! of a tainted cover or by a tainted device is a report of a lie, a `PurgeAboveCut` refusal on
//! a page that is a strict prefix of its response is the paging finding, and any other
//! refusal, or a disagreement between untainted sources, is a violation ([`DeviceStats`]).
//!
//! # Readings the harness takes
//!
//! - **Snapshots on demand.** Besides the ADR 0018 §10 triggers the merge reports, the
//!   scheduler may ask a device to write a snapshot at any time, as the merge spike's `Snapshot`
//!   action does, so that compaction is reached in short histories. The merge decides whether
//!   one can be written ([`crate::merge::NoSnapshot`]).
//! - **The taken VV.** [`VaultLog::record_absorbed`] wants what the merge took of a cover;
//!   [`crate::merge::Absorbed`] does not report it, so the device passes the merge's covered VV
//!   after the absorption, the join of the item VV and the taken part, which the log cuts to
//!   the plan's cut again.
//! - **Healing order** (ADR 0021 §9 "Healing request"). The spike's `integrated` preset models
//!   one item: it first re-publishes, chain by chain, every held body the server stored before
//!   (`heal_bodies`), then sends one request with the remaining headers without their bodies
//!   behind a fresh snapshot. With several items a fresh snapshot of one item can cover own ops
//!   the server does not hold yet and be refused (`AuthorEntryAboveHead`), so the device runs
//!   the normal upload path for its unacknowledged own ops between the two phases: "An own op
//!   never acknowledged takes the normal upload path".
//! - **A refused healing request** leaves the device as it was: the fresh snapshots written for
//!   it are rolled back with the merges, as the spike restores the device.
//! - **An own op sent without an answer before a restore** ("the server may have stored and
//!   served it", ADR 0021 §9 "Stale epoch") is never re-issued: the device sends the same
//!   signed record again. With one key epoch and no stale-epoch answer, re-publishing it in a
//!   healing request and sending it through the normal upload path store the same record, so
//!   the device uses the normal path; the server compares it byte for byte ("Already stored").

use std::collections::{BTreeMap, BTreeSet};

use rizzy_core::ids::{DeviceId, ItemId, OpId, SnapshotId};
use rizzy_core::sign::{OpStatement, SnapshotStatement};

use super::faults::{self, Fault};
use super::server::{HealingRequest, OpAnswer, OpRecord, Page, Server, SnapAnswer, SnapRecord};
use super::{VAULT, item_key};
use crate::causal::{BodyStatus, Report, ServedOp, ServerView, VaultLog};
use crate::dot::Dot;
use crate::header::{ItemSchemaVersion, OpHeader, SnapshotHeader};
use crate::hlc::Hlc;
use crate::merge::{AbsorbOutcome, ItemMerge, MergeError, OpInput, OwnWrite, SnapshotInput};
use crate::record::{
    FieldKey, Lifecycle, OpData, Value, Write, encode_op, parse_op, parse_snapshot,
};

/// What a device writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Edit {
    /// A create or edit: these `(key, value)` writes, with `Active`.
    Write(Vec<(String, Vec<u8>)>),
    /// A trash: `Trashed`, no writes.
    Trash,
    /// A restore: `Active`, no writes.
    Restore,
    /// A purge: `Purge`, no writes.
    Purge,
}

/// Coverage counters of one device.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct DeviceStats {
    /// Covers absorbed.
    pub(super) absorbed: u64,
    /// Untainted covers the merge refused, other than the paging finding: a violation.
    pub(super) refused: u64,
    /// Tombstone covers refused as `PurgeAboveCut` on a page that is a strict prefix of its
    /// response: the paging finding of [`super::world::World::drain`], excused.
    pub(super) paged_refused: u64,
    /// Covers refused that could lie (a tainted record, or a tainted device): the reports of
    /// "Snapshots are claims" at work.
    pub(super) lie_refused: u64,
    /// Tainted covers absorbed.
    pub(super) lies_absorbed: u64,
    /// Covered-VV entries the merge cut and reported (`ClaimCut`).
    pub(super) claim_cuts: u64,
    /// Dishonest snapshots this device wrote (a faulty device).
    pub(super) lies_written: u64,
    /// Snapshots written.
    pub(super) snapshots: u64,
    /// Healing requests the server stored.
    pub(super) heals: u64,
    /// Healing requests the server refused.
    pub(super) heals_refused: u64,
    /// Ops delivered as covered ops.
    pub(super) covered_ops: u64,
    /// Purges the writer rules refused.
    pub(super) purges_refused: u64,
    /// Own snapshots the server refused (and the device discarded).
    pub(super) snapshots_refused: u64,
}

/// A simulated device of the one vault.
#[derive(Clone, Debug)]
pub(super) struct Device {
    /// Its id.
    pub(super) id: DeviceId,
    /// Its per-device chains.
    pub(super) log: VaultLog,
    /// Its merge of each item.
    pub(super) items: BTreeMap<ItemId, ItemMerge>,
    /// The op bodies it still holds, verified.
    bodies: BTreeMap<Dot, Vec<u8>>,
    /// The statement of every accepted link and own op.
    statements: BTreeMap<Dot, OpStatement>,
    /// Every snapshot record it wrote or absorbed.
    held_snaps: Vec<SnapRecord>,
    /// Snapshots written and not uploaded yet.
    outbox_snaps: Vec<SnapRecord>,
    /// Its HLC.
    clock: Hlc,
    /// Its wall clock, Unix milliseconds.
    pub(super) now_ms: u64,
    /// The `device_seq` of its next op.
    next_seq: u64,
    /// Snapshots it wrote, for their ids.
    snap_count: u32,
    /// Every report of every commit.
    pub(super) reports: Vec<Report>,
    /// The reports of the last complete Fetch.
    pub(super) last_complete: Vec<Report>,
    /// Disagreements the merge reported.
    pub(super) disagreements: Vec<Dot>,
    /// The items with a reported disagreement.
    pub(super) disagreement_items: BTreeSet<ItemId>,
    /// Disagreements reported between an untainted device and an untainted cover: a violation
    /// (ADR 0018 §3: honest records never disagree).
    pub(super) honest_disagreements: Vec<Dot>,
    /// The simulation's ground truth, never read by the sync code: this device writes lies
    /// ([`super::faults`]) when the scheduler asks it for a faulty snapshot.
    pub(super) faulty: bool,
    /// The lie this device tells in the fresh snapshots of its healing requests, if faulty.
    pub(super) heal_lie: Option<Fault>,
    /// The simulation's ground truth: this device absorbed a tainted snapshot, so its own
    /// snapshots may carry a lie (the merge spike's `tainted`).
    pub(super) tainted: bool,
    /// Items a revocation found holding a revoked device past its cut-off.
    pub(super) held_past_cutoff: Vec<ItemId>,
    /// Whether the server was behind at its last sync: read-only, no new writes.
    pub(super) read_only: bool,
    /// Calls the harness did not expect to fail, by what failed; the property check reports
    /// them. Metadata only.
    pub(super) errors: Vec<String>,
    /// Upload answers, healing outcomes and refused covers, as server-visible metadata, for a
    /// failure message.
    pub(super) events: Vec<String>,
    /// Coverage counters.
    pub(super) stats: DeviceStats,
}

impl Device {
    /// Device `id`, its wall clock at `now_ms`.
    pub(super) fn new(id: DeviceId, now_ms: u64) -> Self {
        Self {
            id,
            log: VaultLog::new(VAULT, id),
            items: BTreeMap::new(),
            bodies: BTreeMap::new(),
            statements: BTreeMap::new(),
            held_snaps: Vec::new(),
            outbox_snaps: Vec::new(),
            clock: Hlc::ZERO,
            now_ms,
            next_seq: 1,
            snap_count: 0,
            reports: Vec::new(),
            last_complete: Vec::new(),
            disagreements: Vec::new(),
            disagreement_items: BTreeSet::new(),
            honest_disagreements: Vec::new(),
            faulty: false,
            heal_lie: None,
            tainted: false,
            held_past_cutoff: Vec::new(),
            read_only: false,
            errors: Vec::new(),
            events: Vec::new(),
            stats: DeviceStats::default(),
        }
    }

    /// The merge of `item`, created with the item's key in its wrap set.
    fn merge_mut(items: &mut BTreeMap<ItemId, ItemMerge>, item: ItemId) -> &mut ItemMerge {
        items.entry(item).or_insert_with(|| {
            let mut merge = ItemMerge::new(item);
            merge.add_item_key(item_key(item));
            merge
        })
    }

    /// Advances the HLC by a receipt of `remote` (ADR 0012 §2, with the skew guard).
    fn receive(&mut self, remote: Hlc) {
        self.now_ms += 1;
        if let Ok(receipt) = self.clock.receive(remote, self.now_ms) {
            self.clock = receipt.clock;
        }
    }

    /// Writes `edit` on `item` (ADR 0012 §2–§4, ADR 0018 §3): its header on the own chain,
    /// applied through [`ItemMerge::apply_own_op`] with the writer rules, kept for upload. A
    /// read-only device writes nothing, and a Purge the writer rules forbid is not written.
    /// Returns the op's dot and encoded data, for the harness's ledger.
    pub(super) fn write(&mut self, item: ItemId, edit: &Edit) -> Option<(OpHeader, Vec<u8>)> {
        if self.read_only {
            return None;
        }
        let (lifecycle, writes): (Lifecycle, &[(String, Vec<u8>)]) = match edit {
            Edit::Write(w) => (Lifecycle::Active, w),
            Edit::Trash => (Lifecycle::Trashed, &[]),
            Edit::Restore => (Lifecycle::Active, &[]),
            Edit::Purge => (Lifecycle::Purge, &[]),
        };
        let mut sorted: Vec<&(String, Vec<u8>)> = writes.iter().collect();
        sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        sorted.dedup_by(|a, b| a.0 == b.0);
        let mut data_writes = Vec::new();
        for (key, value) in sorted {
            let Ok(key) = FieldKey::new(key) else {
                self.errors
                    .push("an invalid field key in the generator".to_owned());
                return None;
            };
            data_writes.push(Write::new(key, Value::new(value)));
        }
        let Ok(body) = encode_op(&OpData::new(lifecycle, data_writes)) else {
            self.errors
                .push("encode_op refused a generated op".to_owned());
            return None;
        };
        let body = body.expose_secret().to_vec();
        let now = self.now_ms + 1;
        let Ok(hlc) = self.clock.tick(now) else {
            return None;
        };
        let seq = self.next_seq;
        let mut op_id = self.id.to_bytes();
        op_id[8..].copy_from_slice(&seq.to_be_bytes());
        let holds_unapplied_record = self.log.waiting().iter().any(|w| w.item_id == item);
        let merge = Self::merge_mut(&mut self.items, item);
        let dot = Dot::new(self.id, seq)?;
        let header = OpHeader {
            vault_id: VAULT,
            item_id: item,
            op_id: OpId::from_bytes(op_id),
            dot,
            vault_prev_seq: self.log.own_vault_prev_seq(),
            hlc,
            item_schema_version: ItemSchemaVersion::V1,
            vault_key_epoch: 0,
            causal_context: merge.covered().clone(),
        };
        let Ok(parsed) = parse_op(&body) else {
            self.errors
                .push("parse_op refused encode_op's output".to_owned());
            return None;
        };
        let applied = merge.apply_own_op(
            OpInput {
                header: &header,
                key_id: item_key(item),
                data: &parsed,
            },
            OwnWrite {
                fresh_item_key: false,
                holds_unapplied_record,
            },
        );
        let applied = match applied {
            Ok(applied) => applied,
            Err(MergeError::WriterRule) => {
                self.stats.purges_refused += 1;
                return None;
            }
            Err(e) => {
                self.errors
                    .push(format!("apply_own_op failed at {:?}: {e:?}", header.dot));
                return None;
            }
        };
        self.now_ms = now;
        self.clock = hlc;
        self.next_seq += 1;
        if let Err(e) = self.log.record_own_op(header.clone()) {
            self.errors
                .push(format!("record_own_op failed at {:?}: {e:?}", header.dot));
        }
        let Ok(canonical) = header.to_vec() else {
            self.errors.push("an op header did not encode".to_owned());
            return None;
        };
        match OpStatement::new(&canonical, &body, None) {
            Ok(statement) => {
                self.statements.insert(dot, statement);
            }
            Err(_) => self
                .errors
                .push("OpStatement::new refused a header".to_owned()),
        }
        self.bodies.insert(dot, body.clone());
        if applied.snapshot_due.is_some() {
            self.snapshot(item);
        }
        Some((header, body))
    }

    /// Writes a snapshot of `item` into the outbox, if the merge can write one (ADR 0018 §10).
    /// Returns whether it did.
    pub(super) fn snapshot(&mut self, item: ItemId) -> bool {
        self.snapshot_with(item, None)
    }

    /// As [`Device::snapshot`], but a faulty device given `lie` = (kind, server heads) sends
    /// the snapshot with that lie told ([`faults::apply`]); its merge still records the honest
    /// snapshot it wrote, so its own state stays honest. A kind that does not apply leaves the
    /// honest snapshot.
    pub(super) fn snapshot_with(
        &mut self,
        item: ItemId,
        lie: Option<(Fault, &crate::vv::VersionVector)>,
    ) -> bool {
        let Some(merge) = self.items.get_mut(&item) else {
            return false;
        };
        let Ok(written) = merge.write_snapshot() else {
            return false;
        };
        let told = lie.filter(|_| self.faulty).and_then(|(fault, heads)| {
            self.lie(
                item,
                fault,
                heads,
                &written.covered,
                written.data.expose_secret(),
            )
        });
        let record = match told {
            Some((covered, data)) => {
                self.stats.lies_written += 1;
                self.snapshot_record(item, covered, &data, true)
            }
            None => self.snapshot_record(
                item,
                written.covered,
                written.data.expose_secret(),
                self.tainted,
            ),
        };
        let Some(record) = record else {
            return false;
        };
        self.outbox_snaps.push(record.clone());
        self.held_snaps.push(record);
        self.stats.snapshots += 1;
        self.prune_bodies();
        true
    }

    /// The honest snapshot (`covered`, `data`) of `item` with `fault` told, against the server
    /// `heads`; `None` if the kind does not apply.
    fn lie(
        &self,
        item: ItemId,
        fault: Fault,
        heads: &crate::vv::VersionVector,
        covered: &crate::vv::VersionVector,
        data: &[u8],
    ) -> Option<(crate::vv::VersionVector, Vec<u8>)> {
        let causal_context = |dot: Dot| self.log.header(dot).map(|h| h.causal_context.clone());
        let cx = faults::Known {
            author: self.id,
            heads,
            item_key: item_key(item),
            causal_context: &causal_context,
        };
        faults::apply(fault, covered, data, &cx)
    }

    /// The snapshot record of `item` with `covered` and `data`, under a fresh snapshot id;
    /// `tainted` is the simulation's ground truth ([`SnapRecord::tainted`]).
    fn snapshot_record(
        &mut self,
        item: ItemId,
        covered: crate::vv::VersionVector,
        data: &[u8],
        tainted: bool,
    ) -> Option<SnapRecord> {
        self.snap_count += 1;
        let mut id = self.id.to_bytes();
        id[12..].copy_from_slice(&self.snap_count.to_be_bytes());
        let header = SnapshotHeader {
            vault_id: VAULT,
            item_id: item,
            snapshot_id: SnapshotId::from_bytes(id),
            author: self.id,
            item_schema_version: ItemSchemaVersion::V1,
            vault_key_epoch: 0,
            covered,
        };
        let canonical = header.to_vec().ok()?;
        let statement = SnapshotStatement::new(&canonical, data, None).ok()?;
        Some(SnapRecord {
            statement,
            header,
            data: data.to_vec(),
            tainted,
        })
    }

    /// The highest own `device_seq` below every unacknowledged own op: every own op up to it
    /// is acknowledged.
    fn acked(&self) -> u64 {
        self.log
            .unacknowledged()
            .next()
            .map_or_else(|| self.log.head(self.id), |h| h.vault_prev_seq)
    }

    /// The own op record at `dot`, with its body if held.
    fn record(&self, dot: Dot) -> Option<OpRecord> {
        Some(OpRecord {
            statement: self.statements.get(&dot)?.clone(),
            header: self.log.header(dot)?.clone(),
            body: self.bodies.get(&dot).cloned(),
        })
    }

    /// Uploads the unacknowledged own ops in chain order (ADR 0012 §7 "Upload"; ADR 0021 §9
    /// "Already stored"). With `lose_answer`, the first answer never arrives: the op stays sent
    /// without an answer and goes again next time.
    pub(super) fn upload_ops(&mut self, server: &mut Server, lose_answer: bool) {
        // The session starts with an answer, which carries the restore generation (ADR 0021 §2).
        self.log.observe_generation(server.generation());
        let dots: Vec<Dot> = self.log.unacknowledged().map(|h| h.dot).collect();
        for dot in dots {
            let Some(record) = self.record(dot) else {
                self.errors.push(format!("no record for own op {dot:?}"));
                return;
            };
            if record.body.is_none() {
                self.errors
                    .push(format!("own unacknowledged body dropped at {dot:?}"));
                return;
            }
            if let Err(e) = self.log.record_sent(dot.seq()) {
                self.errors.push(format!("record_sent failed: {e:?}"));
            }
            let answer = server.upload_op(&record);
            self.events
                .push(format!("upload {dot:?}: {answer:?} lose {lose_answer}"));
            if lose_answer {
                return;
            }
            let generation = server.generation();
            self.log.observe_generation(generation);
            match answer {
                OpAnswer::Stored | OpAnswer::AlreadyStored => {
                    if let Err(e) = self.log.acknowledge(dot.seq()) {
                        self.errors.push(format!("acknowledge failed: {e:?}"));
                    }
                }
                _ => {
                    if let Err(e) = self.log.record_answered(dot.seq(), generation) {
                        self.errors.push(format!("record_answered failed: {e:?}"));
                    }
                    return;
                }
            }
        }
    }

    /// Uploads the unsent snapshots whose own entry is acknowledged: the server refuses a
    /// snapshot claiming its author's unstored dots (ADR 0021 §9), so one waits for the own ops
    /// it covers. Any answer to a sent snapshot ends it: a refusal "only discards" it.
    ///
    /// With `early`, every unsent snapshot goes at once, before the own ops it covers are
    /// acknowledged (ADR 0021 §8: "a snapshot uploaded before ops it covers"); the server
    /// refuses one that claims its author's unstored dots, and the device discards it.
    pub(super) fn upload_snapshots(&mut self, server: &mut Server, early: bool) {
        let acked = self.acked();
        let (ready, waiting): (Vec<SnapRecord>, Vec<SnapRecord>) = self
            .outbox_snaps
            .drain(..)
            .partition(|s| early || s.header.covered.get(self.id) <= acked);
        self.outbox_snaps = waiting;
        for record in ready {
            match server.upload_snapshot(&record) {
                SnapAnswer::Stored | SnapAnswer::AlreadyStored => {}
                SnapAnswer::Refused(_) => self.stats.snapshots_refused += 1,
                SnapAnswer::BadData => self
                    .errors
                    .push("the server refused an honest snapshot's data".to_owned()),
            }
        }
    }

    /// Whether the server is behind this device (ADR 0021 §9 "Server behind"). No
    /// `account-state` or wraps are modelled, so only the head conditions can hold.
    pub(super) fn server_behind(&self, server: &Server) -> bool {
        let heads = server.heads();
        !self
            .log
            .server_behind(
                0,
                ServerView {
                    state_seq: 0,
                    heads: &heads,
                    lacks_wrap: false,
                },
            )
            .is_empty()
    }

    /// The devices with a chain in this device's log.
    fn chains(&self) -> BTreeSet<DeviceId> {
        let mut chains: BTreeSet<DeviceId> =
            self.statements.keys().map(|d| d.device_id()).collect();
        chains.insert(self.id);
        chains
    }

    /// The highest `device_seq` of `device` this device re-publishes: its cursor entry, or for
    /// its own chain the highest op the server may have stored and served, capped at a known
    /// cut-off (ADR 0021 §9 "Healing request").
    fn heal_bound(&self, device: DeviceId) -> u64 {
        let hi = if device == self.id {
            self.log
                .chain(device)
                .map(|h| h.dot.seq())
                .filter(|&s| self.log.may_have_been_served(s))
                .max()
                .unwrap_or(0)
        } else {
            self.log.cursor().get(device)
        };
        self.log.cutoff(device).map_or(hi, |c| hi.min(c))
    }

    /// The headers of `device`'s chain above the server's head, up to [`Device::heal_bound`].
    fn heal_dots(&self, device: DeviceId, server_head: u64) -> Vec<Dot> {
        let bound = self.heal_bound(device);
        self.log
            .chain(device)
            .map(|h| h.dot)
            .filter(|d| d.seq() > server_head && d.seq() <= bound)
            .collect()
    }

    /// Heals a server that is behind (ADR 0012 §7 "Healing a server rollback" step 4 as
    /// ADR 0021 §9 "Healing request" replaces it), in the order the module docs give: held
    /// bodies chain by chain, the normal upload path for unacknowledged own ops, then one
    /// request with the remaining headers without their bodies behind fresh snapshots, or
    /// held ones sent verbatim.
    pub(super) fn heal(&mut self, server: &mut Server) {
        self.heal_bodies(server);
        self.observe_own_head(server);
        // The normal upload path for own ops never acknowledged.
        self.upload_ops(server, false);
        self.heal_headers(server);
    }

    /// Healing phase 1: every held body of a record the server stored before, chain by chain,
    /// each in its own healing request (the spike's `heal_bodies`).
    fn heal_bodies(&mut self, server: &mut Server) {
        for device in self.chains() {
            let head = server.heads().get(device);
            for dot in self.heal_dots(device, head) {
                let Some(record) = self.record(dot).filter(|r| r.body.is_some()) else {
                    break;
                };
                let request = HealingRequest {
                    ops: vec![record],
                    snapshots: Vec::new(),
                };
                if let Err(e) = server.heal(&request) {
                    self.stats.heals_refused += 1;
                    self.events.push(format!("phase 1 {dot:?}: {e:?}"));
                    break;
                }
                self.events.push(format!("phase 1 ok {dot:?}"));
                self.stats.heals += 1;
            }
        }
    }

    /// Healing phase 2: one request with the remaining headers, without their bodies behind
    /// fresh snapshots or held ones sent verbatim (the spike's `heal_headers`).
    #[expect(
        clippy::too_many_lines,
        reason = "one healing request built in order: headers, the fresh snapshots closed over the own ops, verbatim covers, the answer"
    )]
    fn heal_headers(&mut self, server: &mut Server) {
        let heads = server.heads();
        let mut request = HealingRequest::default();
        let mut need_cover: BTreeMap<ItemId, Vec<Dot>> = BTreeMap::new();
        for device in self.chains() {
            for dot in self.heal_dots(device, heads.get(device)) {
                let Some(record) = self.record(dot) else {
                    break;
                };
                if record.body.is_none() {
                    need_cover
                        .entry(record.header.item_id)
                        .or_default()
                        .push(dot);
                }
                request.ops.push(record);
            }
        }
        if need_cover.is_empty() {
            return;
        }
        let saved = self.clone();
        // Own ops never acknowledged, above what the request re-publishes of the own chain.
        let own_from = heads.get(self.id).max(self.heal_bound(self.id));
        let own_unacked: Vec<OpHeader> = self
            .log
            .chain(self.id)
            .filter(|h| h.dot.seq() > own_from)
            .cloned()
            .collect();
        // The fresh snapshots, closed over the own unacknowledged ops they cover: a fresh
        // snapshot covers every own op of its item, and "a bodiless header needs the fresh
        // snapshot, which also covers the own ops left to the normal path: those go without
        // their bodies too" (the spike's `heal_headers`). With several items, an own op on
        // another item below such an op gets its item's fresh snapshot too, so that the own
        // chain in the request links.
        let mut fresh: BTreeMap<ItemId, SnapRecord> = BTreeMap::new();
        let mut failed: BTreeSet<ItemId> = BTreeSet::new();
        let mut own_hi;
        loop {
            let pending: Vec<ItemId> = need_cover
                .keys()
                .copied()
                .filter(|i| !fresh.contains_key(i) && !failed.contains(i))
                .collect();
            for item in pending {
                let written = self
                    .items
                    .get_mut(&item)
                    .and_then(|m| m.write_snapshot().ok());
                // A faulty healer lies in its fresh snapshots too (the spike's random seed
                // 6327: a faulty device restores its own edit behind its own omitting
                // snapshot).
                let record = written.and_then(|w| {
                    let data = w.data.expose_secret();
                    let told = self
                        .heal_lie
                        .filter(|_| self.faulty)
                        .and_then(|fault| self.lie(item, fault, &heads, &w.covered, data));
                    match told {
                        Some((covered, lie)) => {
                            self.stats.lies_written += 1;
                            self.snapshot_record(item, covered, &lie, true)
                        }
                        None => self.snapshot_record(item, w.covered, data, self.tainted),
                    }
                });
                match record {
                    Some(record) => {
                        fresh.insert(item, record);
                    }
                    None => {
                        failed.insert(item);
                    }
                }
            }
            own_hi = fresh
                .values()
                .map(|s| s.header.covered.get(self.id))
                .max()
                .unwrap_or(0);
            let mut grew = false;
            for h in own_unacked.iter().filter(|h| h.dot.seq() <= own_hi) {
                if let std::collections::btree_map::Entry::Vacant(e) = need_cover.entry(h.item_id) {
                    e.insert(Vec::new());
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }
        for h in own_unacked.iter().filter(|h| h.dot.seq() <= own_hi) {
            if let Some(mut record) = self.record(h.dot) {
                record.body = None;
                if let Some(dots) = need_cover.get_mut(&h.item_id) {
                    dots.push(h.dot);
                }
                request.ops.push(record);
            }
        }
        for record in fresh.into_values() {
            request.snapshots.push(record.clone());
            self.held_snaps.push(record);
            self.stats.snapshots += 1;
        }
        for item in &failed {
            let dots = need_cover.get(item).map_or(&[][..], Vec::as_slice);
            for held in self.held_snaps.iter().filter(|s| {
                s.header.item_id == *item && dots.iter().any(|&d| s.header.covered.covers(d))
            }) {
                request.snapshots.push(held.clone());
            }
        }
        match server.heal(&request) {
            Ok(()) => {
                self.events.push(format!(
                    "phase 2 ok: ops {:?}",
                    request
                        .ops
                        .iter()
                        .map(|r| (r.header.dot, r.body.is_some()))
                        .collect::<Vec<_>>()
                ));
                self.stats.heals += 1;
                self.observe_own_head(server);
                self.prune_bodies();
            }
            Err(e) => {
                let stats = self.stats;
                let mut log = core::mem::take(&mut self.events);
                log.push(format!(
                    "phase 2: {e:?} ops {:?} snaps {:?}",
                    request
                        .ops
                        .iter()
                        .map(|r| (r.header.dot, r.body.is_some()))
                        .collect::<Vec<_>>(),
                    request
                        .snapshots
                        .iter()
                        .map(|s| s.header.covered.clone())
                        .collect::<Vec<_>>()
                ));
                *self = saved;
                self.stats = stats;
                self.events = log;
                self.stats.heals_refused += 1;
            }
        }
    }

    /// Acknowledges the own ops the server now holds (a healing request stored them, or a
    /// request of another device did: "Any client may upload any signed op").
    fn observe_own_head(&mut self, server: &Server) {
        let head = server.heads().get(self.id);
        let own: Vec<u64> = self
            .log
            .unacknowledged()
            .map(|h| h.dot.seq())
            .filter(|&s| s <= head)
            .collect();
        if let Some(&last) = own.last() {
            self.log.observe_generation(server.generation());
            if let Err(e) = self.log.acknowledge(last) {
                self.errors
                    .push(format!("acknowledge after healing failed: {e:?}"));
            }
        }
    }

    /// A Fetch (ADR 0012 §7 "Fetch"): learns the served revocations, then runs the client cycle
    /// on each page (`pages` is the response after the harness's delivery faults), then the
    /// merged-snapshot triggers and the complete-Fetch reports.
    pub(super) fn fetch(
        &mut self,
        cutoffs: &BTreeMap<DeviceId, u64>,
        generation: crate::causal::RestoreGeneration,
        pages: &[Page],
    ) {
        self.log.observe_generation(generation);
        for (&device, &cutoff) in cutoffs {
            if self.log.cutoff(device).is_none() {
                let revocation = self.log.learn_revocation(device, cutoff);
                self.held_past_cutoff.extend(revocation.held_past_cutoff);
            }
        }
        let mut touched = BTreeSet::new();
        for page in pages {
            self.process_page(page, &mut touched);
        }
        for item in touched {
            let due = self.items.get_mut(&item).and_then(ItemMerge::end_fetch);
            if due.is_some() {
                self.snapshot(item);
            }
        }
        self.last_complete = self.log.complete_fetch_reports();
        self.prune_bodies();
    }

    /// One page through the cycle of the `causal` module docs: verify, plan, absorb, commit,
    /// deliver.
    #[expect(
        clippy::too_many_lines,
        reason = "the five steps of the causal module's client cycle, kept together in their order"
    )]
    fn process_page(&mut self, page: &Page, touched: &mut BTreeSet<ItemId>) {
        // 1. Verify: the header from the statement, the body against the signed hash and the
        //    record parser (ADR 0012 §4 step 1).
        let mut served = Vec::new();
        let mut verified: BTreeMap<Dot, (&OpRecord, &[u8])> = BTreeMap::new();
        for record in &page.ops {
            let Ok(header) = OpHeader::parse_statement(&record.statement) else {
                continue;
            };
            let body = match &record.body {
                Some(b) if record.statement.matches_envelope(b) && parse_op(b).is_ok() => {
                    verified.insert(header.dot, (record, b.as_slice()));
                    BodyStatus::Verified
                }
                Some(_) => BodyStatus::Rejected,
                None => BodyStatus::Bodiless,
            };
            served.push(ServedOp { header, body });
        }
        let mut covers: Vec<(SnapshotHeader, &SnapRecord)> = Vec::new();
        for record in &page.covers {
            let Ok(header) = SnapshotHeader::parse_statement(&record.statement) else {
                continue;
            };
            if record.statement.matches_envelope(&record.data)
                && parse_snapshot(&header.covered, &record.data).is_ok()
            {
                covers.push((header, record));
            }
        }
        let cover_headers: Vec<SnapshotHeader> = covers.iter().map(|(h, _)| h.clone()).collect();
        // 2. Plan.
        let plan = self.log.plan_covers(&served, &cover_headers);
        for dot in &plan.links {
            if let Some(op) = served.iter().find(|s| s.header.dot == *dot)
                && let Err(e) =
                    Self::merge_mut(&mut self.items, op.header.item_id).record_header(&op.header)
            {
                self.errors
                    .push(format!("record_header failed at {dot:?}: {e:?}"));
            }
        }
        // 3. Absorb each named cover, with the verified bodies of this page on its item.
        for &i in &plan.absorb {
            let Some((header, record)) = covers.get(i) else {
                continue;
            };
            let item = header.item_id;
            let Ok(data) = parse_snapshot(&header.covered, &record.data) else {
                continue;
            };
            let bodies: Vec<(&OpHeader, OpData<'_>)> = served
                .iter()
                .filter(|s| s.header.item_id == item)
                .filter_map(|s| {
                    let (_, body) = verified.get(&s.header.dot)?;
                    Some((&s.header, parse_op(body).ok()?))
                })
                .collect();
            let with: Vec<OpInput<'_>> = bodies
                .iter()
                .map(|(h, d)| OpInput {
                    header: h,
                    key_id: item_key(item),
                    data: d,
                })
                .collect();
            let merge = Self::merge_mut(&mut self.items, item);
            // Whether this absorption could involve a lie (ground truth, for the checks only).
            let could_lie = record.tainted || self.tainted;
            match merge.absorb_snapshot(
                SnapshotInput {
                    header,
                    data: &data,
                },
                &with,
            ) {
                Ok(absorption) => match absorption.outcome {
                    AbsorbOutcome::Absorbed(absorbed) => {
                        let taken = merge.covered().clone();
                        self.log.record_absorbed(&plan, item, &taken);
                        self.stats.claim_cuts += absorption.claim_cuts.len() as u64;
                        if !absorbed.disagreements.is_empty() {
                            self.disagreement_items.insert(item);
                            if !could_lie {
                                self.honest_disagreements
                                    .extend(absorbed.disagreements.iter().copied());
                            }
                        }
                        self.disagreements.extend(absorbed.disagreements);
                        if let Some(hlc) = absorbed.receive_hlc {
                            self.receive(hlc);
                        }
                        if !self.held_snaps.contains(record) {
                            self.held_snaps.push((*record).clone());
                        }
                        if record.tainted {
                            self.tainted = true;
                            self.stats.lies_absorbed += 1;
                        }
                        touched.insert(item);
                        self.stats.absorbed += 1;
                    }
                    AbsorbOutcome::Refused(r) => {
                        self.stats.claim_cuts += absorption.claim_cuts.len() as u64;
                        let kind = refusal_kind(&r);
                        if could_lie {
                            self.stats.lie_refused += 1;
                        } else if kind == "PurgeAboveCut" && page.partial {
                            self.stats.paged_refused += 1;
                        } else {
                            self.stats.refused += 1;
                        }
                        // Server-visible metadata only: the cover's VV and author, the
                        // refusal's kind and the plan's cut (the purge dot of a tombstone is
                        // content, and is left out).
                        self.events.push(format!(
                            "cover {:?} by {:?} refused: {kind} partial page {} plan cut {:?}",
                            header.covered, header.author, page.partial, plan.cut
                        ));
                    }
                },
                Err(e) => self.errors.push(format!("absorb_snapshot failed: {e:?}")),
            }
        }
        // 4. Commit.
        let commit = self.log.commit(&served);
        self.reports.extend(commit.reports);
        for dot in commit.accepted {
            let Some(header) = self.log.header(dot).cloned() else {
                continue;
            };
            if let Err(e) = Self::merge_mut(&mut self.items, header.item_id).record_header(&header)
            {
                self.errors
                    .push(format!("record_header failed at {dot:?}: {e:?}"));
            }
            if let Some(record) = page.ops.iter().find(|r| r.header.dot == dot) {
                self.statements.insert(dot, record.statement.clone());
            }
            if let Some((_, body)) = verified.get(&dot) {
                self.bodies.insert(dot, body.to_vec());
            }
        }
        // 5. Deliver.
        self.deliver(touched);
    }

    /// Applies every op the causal layer releases, in its order (ADR 0012 §4 step 2).
    fn deliver(&mut self, touched: &mut BTreeSet<ItemId>) {
        for delivery in self.log.take_deliveries() {
            let (Some(header), Some(body)) = (
                self.log.header(delivery.dot),
                self.bodies.get(&delivery.dot),
            ) else {
                self.errors
                    .push(format!("a delivery without its body at {:?}", delivery.dot));
                continue;
            };
            let Ok(data) = parse_op(body) else {
                self.errors
                    .push("a delivered body did not parse".to_owned());
                continue;
            };
            let merge = Self::merge_mut(&mut self.items, delivery.item_id);
            match merge.apply_op(OpInput {
                header,
                key_id: item_key(delivery.item_id),
                data: &data,
            }) {
                Ok(applied) => {
                    if delivery.covered {
                        self.stats.covered_ops += 1;
                    }
                    touched.insert(delivery.item_id);
                    if let Some(hlc) = applied.receive_hlc {
                        self.now_ms += 1;
                        if let Ok(receipt) = self.clock.receive(hlc, self.now_ms) {
                            self.clock = receipt.clock;
                        }
                    }
                }
                Err(e) => self
                    .errors
                    .push(format!("apply_op failed at {:?}: {e:?}", delivery.dot)),
            }
        }
    }

    /// Drops the bodies the device no longer needs (see the module docs).
    fn prune_bodies(&mut self) {
        let mut keep: BTreeSet<Dot> = self
            .items
            .values()
            .flat_map(ItemMerge::retained_ops)
            .collect();
        keep.extend(self.log.waiting().iter().map(|w| w.dot));
        keep.extend(self.log.unacknowledged().map(|h| h.dot));
        self.bodies.retain(|dot, _| keep.contains(dot));
    }

    /// Every snapshot this device wrote or absorbed.
    pub(super) fn held_snapshots(&self) -> &[SnapRecord] {
        &self.held_snaps
    }

    /// Whether the device has nothing left to upload.
    pub(super) fn outbox_empty(&self) -> bool {
        self.outbox_snaps.is_empty() && self.log.unacknowledged().next().is_none()
    }
}

/// The kind of a merge refusal, for the harness's failure analysis (synthetic test data; the
/// merge's own `Debug` redacts it).
fn refusal_kind(r: &crate::merge::Refusal) -> &'static str {
    use crate::merge::Refusal;
    match r {
        Refusal::PurgeAboveCut => "PurgeAboveCut",
        Refusal::ValueNotInBody { .. } => "ValueNotInBody",
        Refusal::ValueAtPurgeDot { .. } => "ValueAtPurgeDot",
        Refusal::WriteRecordedAsPurge { .. } => "WriteRecordedAsPurge",
        Refusal::PurgeKeyContradicts { .. } => "PurgeKeyContradicts",
        Refusal::ContextNotFromPurges => "ContextNotFromPurges",
    }
}
