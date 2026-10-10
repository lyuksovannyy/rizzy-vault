// SPDX-License-Identifier: AGPL-3.0-only

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
//! # Crypto
//!
//! The device signs and seals what it writes, and verifies and opens what it is served
//! ([`super::crypto`]). An own op is sealed as its `ITEM_OP` envelope and signed; a snapshot
//! (an honest one or a lie) is sealed as its `ITEM_SNAPSHOT` envelope, whose AAD binds its
//! covered VV, and signed. A served record is used only after its signature verified under
//! the key of the device it names, its header was parsed from the verified statement, its
//! envelope matched the signed hash and opened under the context that header gives, and the
//! record parser accepted what it holds. The device keeps each accepted envelope as it
//! travelled, so a re-upload and a healing request send the same signed bytes, together with
//! the `data` it opened to.
//!
//! # Keys and epochs
//!
//! The device holds the vault keys of the epochs it was granted and the item keys it may use:
//! every initial key from enrolment, the fresh keys it created, and those it opened from the
//! wrap-set rows a Fetch serves. It writes under the CRYPTO.md §11.6 writer rule
//! ([`Device::choose_key`]): the item's current key, or a fresh one created at its current
//! epoch when that one is stale, which the merge's `FreshItemKey` trigger follows with a full
//! snapshot; the wrap of a key it created travels beside the records sealed under it. It reads
//! under the reader rule: the key the envelope's `key_id` names, among those it holds. An op
//! under a key it does not hold is rejected rather than parked (`BodyStatus::Waiting` is not
//! used): the chain then stops at it, and the next Fetch serves it again from the same
//! cursor; against an honest server every key's row is served with the records, so only a
//! restore can reach that path. The device processes a newer account state at a Fetch, or
//! after a stale-epoch answer ([`Device::on_stale`]), never on its own: between a rotation and
//! its next Fetch it writes at the old epoch, as a device that has not processed the pushed
//! change does.
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
//!   signed record again, through the normal upload path while no stale-epoch answer came
//!   (the server compares it byte for byte, "Already stored"), and in a healing request of its
//!   own once one did ([`VaultLog::stale_plan`] puts it among the ops to re-publish). That
//!   request carries every wrap the server lacks too.
//! - **Stale snapshots.** A snapshot answered "stale epoch" is dropped from what the device
//!   holds (so no healing request re-publishes it) and rewritten under the offered epoch.
//! - **Wraps the server lacks** ("Server behind": "the server lacks an item-key wrap the device
//!   got from it or had acknowledged") are read as the rows of keys it learned from the
//!   server, and of keys it created for an own op the server acknowledged. Every healing
//!   request sequence starts with one request of every wrap the server lacks, wrapped at the
//!   device's epoch.

use std::collections::{BTreeMap, BTreeSet};

use rizzy_core::ids::{DeviceId, ItemId, OpId, SnapshotId, SymmetricKeyId};
use rizzy_core::secret::SecretBytes;

use super::faults::{self, Fault};
use super::server::{
    HealingRequest, OpAnswer, OpRecord, Page, Response, Server, SnapAnswer, SnapRecord, Wrap,
    WrapRow,
};
use super::{VAULT, crypto};
use crate::causal::{
    AuthorStatus, BodyStatus, Report, ServedOp, ServerView, VaultLog, check_op_author,
    check_snapshot_author,
};
use crate::dot::Dot;
use crate::header::{ItemSchemaVersion, OpHeader, SnapshotHeader};
use crate::hlc::Hlc;
use crate::merge::{
    AbsorbOutcome, ItemMerge, MergeError, OpInput, OwnWrite, Reissue, SnapshotInput,
};
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
    /// Fresh item keys the CRYPTO.md §11.6 writer rule created.
    pub(super) fresh_keys: u64,
    /// Item keys learned by opening a wrap-set row.
    pub(super) keys_unwrapped: u64,
    /// Stale-epoch answers to own ops.
    pub(super) stale_ops: u64,
    /// Stale-epoch answers to own snapshots (each discarded and rewritten).
    pub(super) stale_snapshots: u64,
    /// Own ops re-issued with the same `device_seq` after a stale answer.
    pub(super) reissued: u64,
    /// Own ops a stale answer sent to a healing request instead (they may have been served).
    pub(super) republished: u64,
    /// Snapshots written because a re-issue called for one.
    pub(super) reissue_snapshots: u64,
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
    /// The op bodies it still holds, verified: the sealed `ITEM_OP` envelope as it travelled
    /// (a re-upload and a healing request send the same bytes again), with the op `data` it
    /// opened to under its verified header.
    bodies: BTreeMap<Dot, HeldBody>,
    /// The signed statement (wire form) of every accepted link and own op.
    signed: BTreeMap<Dot, Vec<u8>>,
    /// The generator of its envelope nonces ([`crypto::Nonces`]). It is not part of the
    /// state a refused healing request rolls back.
    rng: crypto::Nonces,
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
    /// The vault's current `vault_key_epoch` as this device knows it: the newest account state
    /// it processed (CRYPTO.md §11.6 "Current vault epoch").
    pub(super) epoch: u32,
    /// The epochs of the vault keys it holds.
    pub(super) vault_keys: BTreeSet<u32>,
    /// The item keys it holds, by key id, with their item: every initial key, the fresh keys
    /// it created, and the keys it opened from wrap-set rows.
    item_keys: BTreeMap<[u8; 16], ItemId>,
    /// The vault epoch of the account state the world offers this device at its next exchange
    /// with the server (`None`: no grant, a revoked device). It processes it at a Fetch, and
    /// after a stale-epoch answer.
    pub(super) offered: Option<u32>,
    /// The `key_id` of every op envelope it wrote or verified, by dot.
    op_keys: BTreeMap<Dot, SymmetricKeyId>,
    /// The wraps of the fresh item keys it created, sent beside the records sealed under them.
    own_wraps: BTreeMap<[u8; 16], Wrap>,
    /// The item keys it learned from the server's wrap-set rows.
    learned: BTreeSet<[u8; 16]>,
    /// Own ops a stale-epoch answer marked for a healing request, by `device_seq`.
    republish: BTreeSet<u64>,
    /// The `expires_at_ms` of every expiring certificate, as the last Fetch served them (a
    /// stand-in for the kind-4 certificates; absent: no expiry).
    expiries: BTreeMap<DeviceId, u64>,
    /// Re-issued own ops, with their new item key, for the harness's ledger. Drained by the
    /// world.
    pub(super) reissued: Vec<(OpHeader, SymmetricKeyId)>,
    /// The items this device told a lie about (ground truth, a faulty device).
    pub(super) lied_items: BTreeSet<ItemId>,
    /// Its own certificate's `expires_at_ms` (a kind-4 device; 0: none). An honest web vault
    /// writes no op whose HLC is past it (CRYPTO.md §10.2 rule (c)).
    pub(super) expires_at_ms: u64,
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
    /// Device `id` of the run scheduled from `seed`, its wall clock at `now_ms`. The seed only
    /// keys the device's nonce generator.
    pub(super) fn new(id: DeviceId, now_ms: u64, seed: u64) -> Self {
        Self {
            id,
            log: VaultLog::new(VAULT, id),
            items: BTreeMap::new(),
            bodies: BTreeMap::new(),
            signed: BTreeMap::new(),
            rng: crypto::Nonces::new(seed, id),
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
            epoch: 0,
            vault_keys: BTreeSet::from([0]),
            item_keys: crypto::initial_keys()
                .map(|(item, key)| (*key.as_bytes(), item))
                .collect(),
            offered: Some(0),
            op_keys: BTreeMap::new(),
            own_wraps: BTreeMap::new(),
            learned: BTreeSet::new(),
            republish: BTreeSet::new(),
            expiries: BTreeMap::new(),
            reissued: Vec::new(),
            lied_items: BTreeSet::new(),
            expires_at_ms: 0,
            errors: Vec::new(),
            events: Vec::new(),
            stats: DeviceStats::default(),
        }
    }

    /// The merge of `item`, created with every key of the item in `keys` in its wrap set.
    fn merge_mut<'a>(
        items: &'a mut BTreeMap<ItemId, ItemMerge>,
        keys: &BTreeMap<[u8; 16], ItemId>,
        item: ItemId,
    ) -> &'a mut ItemMerge {
        items.entry(item).or_insert_with(|| {
            let mut merge = ItemMerge::new(item);
            for (key, _) in keys.iter().filter(|(_, i)| **i == item) {
                merge.add_item_key(SymmetricKeyId::from_bytes(*key));
            }
            merge
        })
    }

    /// Whether it holds the item key with id `key`.
    fn holds(&self, key: &SymmetricKeyId) -> bool {
        self.item_keys.contains_key(key.as_bytes())
    }

    /// The ids of every item key it holds.
    pub(super) fn held_keys(&self) -> Vec<SymmetricKeyId> {
        self.item_keys
            .keys()
            .map(|k| SymmetricKeyId::from_bytes(*k))
            .collect()
    }

    /// Enrols the device with the account state of `epoch`: the current vault key only (a new
    /// device gets what a login gets; it holds the initial item keys from the start).
    pub(super) fn enrol(&mut self, epoch: u32) {
        self.epoch = epoch;
        self.vault_keys = BTreeSet::from([epoch]);
    }

    /// Processes the account state of `epoch` (CRYPTO.md §11.3 steps 3–4, standing in for the
    /// device grant and the self-grant): a newer epoch becomes current, with its vault key.
    pub(super) fn adopt(&mut self, epoch: u32) {
        if epoch > self.epoch {
            self.epoch = epoch;
            self.vault_keys.insert(epoch);
        }
    }

    /// The item key a write to `item` is sealed under, by the CRYPTO.md §11.6 writer rule: the
    /// item's current key (the held key of the highest creation epoch), unless it is stale at
    /// the current epoch ([`rizzy_core::keys::ItemKey::is_stale`]); then a fresh key created at
    /// the current epoch, and `true`. Nothing is kept until [`Device::take_key`].
    fn choose_key(&self, item: ItemId) -> (SymmetricKeyId, bool) {
        let current = self
            .item_keys
            .iter()
            .filter(|(_, i)| **i == item)
            .map(|(k, _)| SymmetricKeyId::from_bytes(*k))
            .max_by_key(|k| {
                (
                    crypto::key_info(k).map_or(0, |(_, e)| e),
                    core::cmp::Reverse(*k.as_bytes()),
                )
            })
            .unwrap_or_else(|| crypto::initial_key(item));
        if !crypto::is_stale(&current, self.epoch) {
            return (current, false);
        }
        crypto::fresh_key(item, self.epoch, self.id).map_or((current, false), |fresh| (fresh, true))
    }

    /// Keeps the fresh item key `key` of `item` the writer rule created: held, in the item's
    /// wrap set, and wrapped under the current vault key for the records sealed under it.
    fn take_key(&mut self, item: ItemId, key: SymmetricKeyId) {
        self.item_keys.insert(*key.as_bytes(), item);
        if let Some(merge) = self.items.get_mut(&item) {
            merge.add_item_key(key);
        }
        match crypto::wrap(&mut self.rng, &key, self.epoch) {
            Some(envelope) => {
                self.own_wraps.insert(
                    *key.as_bytes(),
                    Wrap {
                        epoch: self.epoch,
                        envelope,
                    },
                );
            }
            None => self.errors.push("a fresh item key did not wrap".to_owned()),
        }
        self.stats.fresh_keys += 1;
    }

    /// Opens every wrap-set row of an item key it does not hold with the vault key of the row's
    /// epoch, if it holds that one, and keeps the key when its derived id is the row's.
    fn learn_wraps(&mut self, rows: &[WrapRow]) {
        for row in rows {
            if self.holds(&row.key) || !self.vault_keys.contains(&row.wrap.epoch) {
                continue;
            }
            let Some(key) = crypto::unwrap(row.wrap.epoch, row.item, &row.wrap.envelope) else {
                continue;
            };
            if key == row.key && crypto::key_info(&key).is_some_and(|(i, _)| i == row.item) {
                self.item_keys.insert(*key.as_bytes(), row.item);
                self.learned.insert(*key.as_bytes());
                if let Some(merge) = self.items.get_mut(&row.item) {
                    merge.add_item_key(key);
                }
                self.stats.keys_unwrapped += 1;
            }
        }
    }

    /// The rotator's re-wrap (ADR 0025 §2 step 3): each row it can open with a vault key it
    /// holds, re-wrapped under the vault key of `epoch` with its creation epoch unchanged, and
    /// the rows it cannot open, to drop.
    pub(super) fn rewrap(
        &mut self,
        rows: &[WrapRow],
        epoch: u32,
    ) -> (Vec<WrapRow>, Vec<(ItemId, SymmetricKeyId)>) {
        let mut rewrapped = Vec::new();
        let mut dropped = Vec::new();
        for row in rows {
            let opened = self
                .vault_keys
                .contains(&row.wrap.epoch)
                .then(|| crypto::unwrap(row.wrap.epoch, row.item, &row.wrap.envelope))
                .flatten()
                .filter(|key| *key == row.key);
            match opened.and_then(|key| crypto::wrap(&mut self.rng, &key, epoch)) {
                Some(envelope) => rewrapped.push(WrapRow {
                    item: row.item,
                    key: row.key,
                    wrap: Wrap { epoch, envelope },
                }),
                None => dropped.push((row.item, row.key)),
            }
        }
        (rewrapped, dropped)
    }

    /// The ADR 0032 §2 step 3b rows of a device whose epoch is above the server's after a
    /// restore: every wrap-set row it holds, that is every item key it holds but the initial
    /// ones (which have no row here), wrapped under the vault key of its epoch. `None` unless
    /// it holds that vault key.
    pub(super) fn epoch_rows(&mut self) -> Option<Vec<WrapRow>> {
        if !self.vault_keys.contains(&self.epoch) {
            return None;
        }
        let keys: Vec<([u8; 16], ItemId)> = self
            .item_keys
            .iter()
            .map(|(k, i)| (*k, *i))
            .filter(|(k, _)| {
                crypto::key_info(&SymmetricKeyId::from_bytes(*k)).is_some_and(|(_, e)| e > 0)
            })
            .collect();
        let mut rows = Vec::new();
        for (key, item) in keys {
            let id = SymmetricKeyId::from_bytes(key);
            if let Some(envelope) = crypto::wrap(&mut self.rng, &id, self.epoch) {
                rows.push(WrapRow {
                    item,
                    key: id,
                    wrap: Wrap {
                        epoch: self.epoch,
                        envelope,
                    },
                });
            }
        }
        Some(rows)
    }

    /// Every envelope it holds, for property 6: its op bodies with their headers, and every
    /// snapshot record it wrote, absorbed or has not sent.
    pub(super) fn envelopes(&self) -> (Vec<(&OpHeader, &[u8])>, Vec<&SnapRecord>) {
        let ops = self
            .bodies
            .iter()
            .filter_map(|(dot, held)| self.log.header(*dot).map(|h| (h, held.envelope.as_slice())))
            .collect();
        let snaps = self.held_snaps.iter().chain(&self.outbox_snaps).collect();
        (ops, snaps)
    }

    /// Advances the HLC by a receipt of `remote` (ADR 0012 §2, with the skew guard).
    fn receive(&mut self, remote: Hlc) {
        self.now_ms += 1;
        if let Ok(receipt) = self.clock.receive(remote, self.now_ms) {
            self.clock = receipt.clock;
        }
    }

    /// Writes `edit` on `item` (ADR 0012 §2–§4, ADR 0018 §3): its header on the own chain,
    /// applied through [`ItemMerge::apply_own_op`] with the writer rules, then sealed as its
    /// `ITEM_OP` envelope, signed and kept for upload. A read-only device writes nothing, and
    /// a Purge the writer rules forbid is not written. Returns the op's header, encoded data
    /// (the plaintext, which only the harness's ledger sees) and item key id.
    pub(super) fn write(
        &mut self,
        item: ItemId,
        edit: &Edit,
    ) -> Option<(OpHeader, Vec<u8>, SymmetricKeyId)> {
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
        if self.expires_at_ms != 0 && hlc.millis() > self.expires_at_ms {
            return None;
        }
        let seq = self.next_seq;
        let mut op_id = self.id.to_bytes();
        op_id[8..].copy_from_slice(&seq.to_be_bytes());
        let holds_unapplied_record = self.log.waiting().iter().any(|w| w.item_id == item);
        // CRYPTO.md §11.6 writer rule: a stale item key gives way to a fresh one, and the
        // merge's `FreshItemKey` trigger then calls for a full snapshot under it.
        let (key, fresh) = self.choose_key(item);
        let merge = Self::merge_mut(&mut self.items, &self.item_keys, item);
        let dot = Dot::new(self.id, seq)?;
        let header = OpHeader {
            vault_id: VAULT,
            item_id: item,
            op_id: OpId::from_bytes(op_id),
            dot,
            vault_prev_seq: self.log.own_vault_prev_seq(),
            hlc,
            item_schema_version: ItemSchemaVersion::V1,
            vault_key_epoch: self.epoch,
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
                key_id: key,
                data: &parsed,
            },
            OwnWrite {
                fresh_item_key: fresh,
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
        if fresh {
            self.take_key(item, key);
        }
        if !self.seal_own_op(&header, key, &body) {
            return None;
        }
        if applied.snapshot_due.is_some() {
            self.snapshot(item);
        }
        Some((header, body, key))
    }

    /// Makes the record of an own op that travels and keeps it for upload: `data` sealed as
    /// the `ITEM_OP` envelope under the item key `key`, its AAD bound to `header`, and the `op`
    /// statement signed over the header and the envelope's hash. Returns whether it sealed.
    fn seal_own_op(&mut self, header: &OpHeader, key: SymmetricKeyId, data: &[u8]) -> bool {
        let Some(envelope) = crypto::seal_op(&mut self.rng, header, &key, data) else {
            self.errors.push("an op did not seal".to_owned());
            return false;
        };
        self.op_keys.insert(header.dot, key);
        match crypto::sign_op(header, &envelope) {
            Some(signed) => {
                self.signed.insert(header.dot, signed);
            }
            None => self.errors.push("an op statement did not sign".to_owned()),
        }
        self.bodies.insert(
            header.dot,
            HeldBody {
                envelope,
                data: data.to_vec(),
            },
        );
        true
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
            self.lie(fault, heads, &written.covered, written.data.expose_secret())
        });
        let record = match told {
            Some((covered, data)) => {
                self.stats.lies_written += 1;
                self.lied_items.insert(item);
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
        fault: Fault,
        heads: &crate::vv::VersionVector,
        covered: &crate::vv::VersionVector,
        data: &[u8],
    ) -> Option<(crate::vv::VersionVector, Vec<u8>)> {
        let causal_context = |dot: Dot| self.log.header(dot).map(|h| h.causal_context.clone());
        let key_of = |dot: Dot| self.op_keys.get(&dot).copied();
        let cx = faults::Known {
            author: self.id,
            heads,
            key_of: &key_of,
            causal_context: &causal_context,
        };
        faults::apply(fault, covered, data, &cx)
    }

    /// The snapshot record of `item` with `covered` and `data`, under a fresh snapshot id:
    /// `data` sealed as the `ITEM_SNAPSHOT` envelope of that header (so its AAD binds the
    /// covered VV) under the item key the writer rule picks, with that key's wrap if this
    /// device created it, and the `snapshot` statement signed by this device. `tainted` is the
    /// simulation's ground truth ([`SnapRecord::tainted`]).
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
            vault_key_epoch: self.epoch,
            covered,
        };
        let (key, fresh) = self.choose_key(item);
        if fresh {
            self.take_key(item, key);
        }
        let envelope = crypto::seal_snapshot(&mut self.rng, &header, &key, data)?;
        let signed = crypto::sign_snapshot(&header, &envelope)?;
        Some(SnapRecord {
            signed,
            header,
            data: envelope,
            wrap: self.own_wraps.get(key.as_bytes()).cloned(),
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

    /// The own op record at `dot`, with its body if held and the wrap of its item key if this
    /// device created that key.
    fn record(&self, dot: Dot) -> Option<OpRecord> {
        Some(OpRecord {
            signed: self.signed.get(&dot)?.clone(),
            header: self.log.header(dot)?.clone(),
            body: self.bodies.get(&dot).map(|held| held.envelope.clone()),
            wrap: self
                .op_keys
                .get(&dot)
                .and_then(|k| self.own_wraps.get(k.as_bytes()))
                .cloned(),
        })
    }

    /// Uploads the unacknowledged own ops in chain order (ADR 0012 §7 "Upload"; ADR 0021 §9
    /// "Already stored"). With `lose_answer`, the first answer never arrives: the op stays sent
    /// without an answer and goes again next time. An op a stale-epoch answer marked for
    /// re-publication goes in a healing request of its own instead ([`Device::on_stale`]).
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
            if self.republish.contains(&dot.seq()) {
                // "It re-publishes such an op in a healing request" (ADR 0021 §9).
                let request = HealingRequest {
                    wraps: self.missing_wraps(server),
                    ops: vec![record],
                    snapshots: Vec::new(),
                };
                match server.heal(&request) {
                    Ok(()) => {
                        self.events.push(format!("republished {dot:?}"));
                        self.republish.remove(&dot.seq());
                        self.observe_own_head(server);
                        continue;
                    }
                    Err(e) => {
                        self.events.push(format!("republish {dot:?}: {e:?}"));
                        return;
                    }
                }
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
                    if answer == OpAnswer::StaleEpoch {
                        self.on_stale(dot);
                    }
                    return;
                }
            }
        }
    }

    /// A stale-epoch answer to the own op at `rejected` (ADR 0021 §9 "Stale epoch"): the
    /// device processes the offered account state, then [`VaultLog::stale_plan`] splits the
    /// rejected op and the later old-epoch own ops into those it re-issues with the same
    /// `device_seq` under the current epoch ([`Device::reissue`]) and those the server may have
    /// stored and served, which it re-publishes verbatim in a healing request at its next
    /// upload. One snapshot per item follows the last re-issue that called for one.
    fn on_stale(&mut self, rejected: Dot) {
        self.stats.stale_ops += 1;
        let Some(epoch) = self.offered else {
            self.events
                .push(format!("stale answer to {rejected:?} without a grant"));
            return;
        };
        self.adopt(epoch);
        let plan = match self.log.stale_plan(rejected.seq(), self.epoch) {
            Ok(plan) => plan,
            Err(e) => {
                self.errors.push(format!("stale_plan failed: {e:?}"));
                return;
            }
        };
        let mut due = BTreeSet::new();
        for dot in plan.reissue {
            if let Some(item) = self.reissue(dot) {
                due.insert(item);
            }
        }
        for item in due {
            if self.snapshot(item) {
                self.stats.reissue_snapshots += 1;
            }
        }
        self.stats.republished += plan.republish.len() as u64;
        self.republish
            .extend(plan.republish.iter().map(|d| d.seq()));
    }

    /// Re-issues the own op at `dot` (ADR 0018 §3 "Re-issued ops", owner decision 15): the same
    /// header but for the current `vault_key_epoch`, the same op data sealed under the item key
    /// the writer rule picks, signed again, held in place of the original by the causal layer
    /// ([`VaultLog::reissue_own_op`]) and the merge ([`ItemMerge::reissue_own_op`]). Every
    /// unsent snapshot of the item that covers the op is discarded. Returns the item when the
    /// merge calls for a snapshot.
    fn reissue(&mut self, dot: Dot) -> Option<ItemId> {
        let Some(original) = self.log.header(dot).cloned() else {
            self.errors
                .push(format!("no header to re-issue at {dot:?}"));
            return None;
        };
        let Some(data) = self.bodies.get(&dot).map(|held| held.data.clone()) else {
            self.errors.push(format!("no body to re-issue at {dot:?}"));
            return None;
        };
        let item = original.item_id;
        let (key, fresh) = self.choose_key(item);
        let mut header = original;
        header.vault_key_epoch = self.epoch;
        if let Err(e) = self.log.reissue_own_op(header.clone()) {
            self.errors
                .push(format!("reissue_own_op (log) failed at {dot:?}: {e:?}"));
            return None;
        }
        let covers = |s: &SnapRecord| s.header.item_id == item && s.header.covered.covers(dot);
        let discarded: Vec<SnapRecord> = self
            .outbox_snaps
            .iter()
            .filter(|s| covers(s))
            .cloned()
            .collect();
        self.outbox_snaps.retain(|s| !covers(s));
        self.held_snaps.retain(|s| !discarded.contains(s));
        if fresh {
            self.take_key(item, key);
        }
        let merge = Self::merge_mut(&mut self.items, &self.item_keys, item);
        let trigger = match merge.reissue_own_op(
            &header,
            key,
            Reissue {
                fresh_item_key: fresh,
                discarded_unsent_snapshot: !discarded.is_empty(),
            },
        ) {
            Ok(trigger) => trigger,
            Err(e) => {
                self.errors
                    .push(format!("reissue_own_op (merge) failed at {dot:?}: {e:?}"));
                None
            }
        };
        if !self.seal_own_op(&header, key, &data) {
            return None;
        }
        self.reissued.push((header, key));
        self.stats.reissued += 1;
        trigger.map(|_| item)
    }

    /// Uploads the unsent snapshots whose own entry is acknowledged: the server refuses a
    /// snapshot claiming its author's unstored dots (ADR 0021 §9), so one waits for the own ops
    /// it covers. Any answer to a sent snapshot ends it: a refusal "only discards" it, and a
    /// stale-epoch answer "only discards and rewrites it" (the rewrite, under the offered
    /// epoch, waits in the outbox for the next upload).
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
                SnapAnswer::StaleEpoch => {
                    self.stats.stale_snapshots += 1;
                    self.held_snaps.retain(|s| *s != record);
                    if let Some(epoch) = self.offered {
                        self.adopt(epoch);
                        self.snapshot(record.header.item_id);
                    }
                }
                SnapAnswer::Refused(_) => self.stats.snapshots_refused += 1,
                SnapAnswer::BadData => self
                    .errors
                    .push("the server refused an honest snapshot's data".to_owned()),
                SnapAnswer::BadSignature => self
                    .errors
                    .push("the server refused an honest snapshot's signature".to_owned()),
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
                    lacks_wrap: self.server_lacks_wrap(server),
                },
            )
            .is_empty()
    }

    /// Every item key it holds but the initial ones (which have no row here) that the server
    /// has no wrap-set row for, wrapped under the vault key of its epoch (ADR 0021 §9 "Healing
    /// request": "every item-key wrap the server lacks").
    fn missing_wraps(&mut self, server: &Server) -> Vec<WrapRow> {
        let stored: BTreeSet<[u8; 16]> = server.rows().iter().map(|r| *r.key.as_bytes()).collect();
        let missing: Vec<([u8; 16], ItemId)> = self
            .item_keys
            .iter()
            .filter(|(k, _)| !stored.contains(*k))
            .filter(|(k, _)| {
                crypto::key_info(&SymmetricKeyId::from_bytes(**k)).is_some_and(|(_, e)| e > 0)
            })
            .map(|(k, i)| (*k, *i))
            .collect();
        let mut rows = Vec::new();
        for (key, item) in missing {
            let id = SymmetricKeyId::from_bytes(key);
            if let Some(envelope) = crypto::wrap(&mut self.rng, &id, self.epoch) {
                rows.push(WrapRow {
                    item,
                    key: id,
                    wrap: Wrap {
                        epoch: self.epoch,
                        envelope,
                    },
                });
            }
        }
        rows
    }

    /// Whether the server lacks a wrap-set row of an item key this device got from it, or
    /// created for an own op the server acknowledged (ADR 0021 §9 "Server behind").
    fn server_lacks_wrap(&self, server: &Server) -> bool {
        let stored: BTreeSet<[u8; 16]> = server.rows().iter().map(|r| *r.key.as_bytes()).collect();
        let acked = self.log.acknowledged();
        let own_acked = self
            .op_keys
            .iter()
            .filter(|(dot, _)| dot.device_id() == self.id && dot.seq() <= acked)
            .map(|(_, k)| *k.as_bytes())
            .filter(|k| self.own_wraps.contains_key(k));
        self.learned
            .iter()
            .copied()
            .chain(own_acked)
            .any(|k| !stored.contains(&k))
    }

    /// The devices with a chain in this device's log.
    fn chains(&self) -> BTreeSet<DeviceId> {
        let mut chains: BTreeSet<DeviceId> = self.signed.keys().map(|d| d.device_id()).collect();
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
    /// ADR 0021 §9 "Healing request" replaces it), in the order the module docs give: every
    /// item-key wrap the server lacks, held bodies chain by chain, the normal upload path for
    /// unacknowledged own ops, then one request with the remaining headers without their
    /// bodies behind fresh snapshots, or held ones sent verbatim.
    pub(super) fn heal(&mut self, server: &mut Server) {
        let wraps = self.missing_wraps(server);
        if !wraps.is_empty() {
            let request = HealingRequest {
                wraps,
                ..HealingRequest::default()
            };
            if let Err(e) = server.heal(&request) {
                self.events.push(format!("wraps: {e:?}"));
            }
        }
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
                    wraps: Vec::new(),
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
                        .and_then(|fault| self.lie(fault, &heads, &w.covered, data));
                    match told {
                        Some((covered, lie)) => {
                            self.stats.lies_written += 1;
                            self.lied_items.insert(item);
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
                // The nonce generator is not rolled back: the discarded fresh snapshots drew
                // nonces, and a device never draws the same nonce twice.
                let rng = self.rng.clone();
                *self = saved;
                self.rng = rng;
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

    /// A Fetch (ADR 0012 §7 "Fetch"): processes the offered account state, learns the served
    /// revocations, expiring certificates and wrap-set rows, then runs the client cycle on each
    /// page (`pages` is the response after the harness's delivery faults), then the
    /// merged-snapshot triggers and the complete-Fetch reports.
    pub(super) fn fetch(&mut self, response: &Response, pages: &[Page]) {
        if let Some(epoch) = self.offered {
            self.adopt(epoch);
        }
        self.log.observe_generation(response.generation);
        self.expiries.clone_from(&response.expiries);
        self.learn_wraps(&response.wraps);
        for (&device, &cutoff) in &response.cutoffs {
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
        // 1. Verify (ADR 0012 §4 step 1): the signature under the key of the device the record
        //    names, the header from the verified statement, the body against the signed hash,
        //    then the envelope opened under the context that header gives, and the record
        //    parser on what it holds. The claimed `record.header` only picks the key.
        let mut served = Vec::new();
        let mut verified: BTreeMap<Dot, Opened<'_>> = BTreeMap::new();
        let mut signed: BTreeMap<Dot, &[u8]> = BTreeMap::new();
        let item_keys = &self.item_keys;
        let holds = |k: &SymmetricKeyId| item_keys.contains_key(k.as_bytes());
        for record in &page.ops {
            let Some((statement, header)) =
                crypto::verify_op(&record.signed, record.header.dot.device_id())
            else {
                continue;
            };
            // The author checks that read the header: the revocation cut-off and rule (c)
            // against the author's certificate expiry (ADR 0012 §4 step 1).
            let author = AuthorStatus {
                device: header.dot.device_id(),
                last_accepted: self.log.cutoff(header.dot.device_id()),
                expires_at_ms: self
                    .expiries
                    .get(&header.dot.device_id())
                    .copied()
                    .unwrap_or(0),
            };
            if let Err(refusal) = check_op_author(&header, author) {
                self.errors.push(format!(
                    "an honest server served {:?}, refused for its author: {refusal}",
                    header.dot
                ));
                continue;
            }
            let body = match record.body.as_deref() {
                Some(envelope) => {
                    // A body served again (a duplicated record, a re-fetch) is the one the
                    // device holds when both the envelope and the verified header are the
                    // held ones: it was opened under that header and parsed when accepted.
                    let held = self.bodies.get(&header.dot).filter(|held| {
                        held.envelope == envelope && self.log.header(header.dot) == Some(&header)
                    });
                    let data = if !statement.matches_envelope(envelope) {
                        None
                    } else if let Some(held) = held {
                        self.op_keys
                            .get(&header.dot)
                            .map(|&key| (held.data.clone(), key))
                    } else {
                        // CRYPTO.md §11.6 reader rule: the key its `key_id` names, among the
                        // keys of the item this device holds.
                        crypto::open_op(&header, envelope, holds)
                            .filter(|(data, _)| parse_op(data.expose_secret()).is_ok())
                            .map(|(data, key)| (data.expose_secret().to_vec(), key))
                    };
                    match data {
                        Some((data, key)) => {
                            verified.insert(
                                header.dot,
                                Opened {
                                    envelope,
                                    data,
                                    key,
                                },
                            );
                            BodyStatus::Verified
                        }
                        None => BodyStatus::Rejected,
                    }
                }
                None => BodyStatus::Bodiless,
            };
            signed.entry(header.dot).or_insert(&record.signed);
            served.push(ServedOp { header, body });
        }
        let mut covers: Vec<(SnapshotHeader, &SnapRecord, SecretBytes)> = Vec::new();
        for record in &page.covers {
            let Some((statement, header)) =
                crypto::verify_snapshot(&record.signed, record.header.author)
            else {
                continue;
            };
            if !statement.matches_envelope(&record.data) {
                continue;
            }
            // A kind-4 author's snapshot: its covered-VV entry for its author at most the
            // highest `device_seq` of that author verified here, this page's headers included
            // (the `causal::author` module's suggested bound; CRYPTO.md §10.2 rule (c)).
            if self.expiries.contains_key(&header.author) {
                let bound = served
                    .iter()
                    .filter(|s| s.header.dot.device_id() == header.author)
                    .map(|s| s.header.dot.seq())
                    .fold(self.log.head(header.author), u64::max);
                if let Err(refusal) = check_snapshot_author(&header, Some(bound)) {
                    self.errors.push(format!(
                        "an honest server served a cover by {:?} refused for its author: {refusal}",
                        header.author
                    ));
                    continue;
                }
            }
            let Some((data, _)) = crypto::open_snapshot(&header, &record.data, holds) else {
                continue;
            };
            if parse_snapshot(&header.covered, data.expose_secret()).is_ok() {
                covers.push((header, record, data));
            }
        }
        let cover_headers: Vec<SnapshotHeader> = covers.iter().map(|(h, _, _)| h.clone()).collect();
        // 2. Plan.
        let plan = self.log.plan_covers(&served, &cover_headers);
        for dot in &plan.links {
            if let Some(op) = served.iter().find(|s| s.header.dot == *dot)
                && let Err(e) = Self::merge_mut(&mut self.items, &self.item_keys, op.header.item_id)
                    .record_header(&op.header)
            {
                self.errors
                    .push(format!("record_header failed at {dot:?}: {e:?}"));
            }
        }
        // 3. Absorb each named cover, with the verified bodies of this page on its item.
        for &i in &plan.absorb {
            let Some((header, record, opened)) = covers.get(i) else {
                continue;
            };
            let item = header.item_id;
            let Ok(data) = parse_snapshot(&header.covered, opened.expose_secret()) else {
                continue;
            };
            let bodies: Vec<(&OpHeader, SymmetricKeyId, OpData<'_>)> = served
                .iter()
                .filter(|s| s.header.item_id == item)
                .filter_map(|s| {
                    let body = verified.get(&s.header.dot)?;
                    Some((&s.header, body.key, parse_op(&body.data).ok()?))
                })
                .collect();
            let with: Vec<OpInput<'_>> = bodies
                .iter()
                .map(|(h, key, d)| OpInput {
                    header: h,
                    key_id: *key,
                    data: d,
                })
                .collect();
            let merge = Self::merge_mut(&mut self.items, &self.item_keys, item);
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
            if let Err(e) = Self::merge_mut(&mut self.items, &self.item_keys, header.item_id)
                .record_header(&header)
            {
                self.errors
                    .push(format!("record_header failed at {dot:?}: {e:?}"));
            }
            if let Some(statement) = signed.get(&dot) {
                self.signed.insert(dot, statement.to_vec());
            }
            if let Some(body) = verified.get(&dot) {
                self.op_keys.insert(dot, body.key);
                self.bodies.insert(
                    dot,
                    HeldBody {
                        envelope: body.envelope.to_vec(),
                        data: body.data.clone(),
                    },
                );
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
            // What the held envelope opened to, under the header the log accepted.
            let Ok(data) = parse_op(&body.data) else {
                self.errors
                    .push("a delivered body did not parse".to_owned());
                continue;
            };
            let key_id = self
                .op_keys
                .get(&delivery.dot)
                .copied()
                .unwrap_or_else(|| crypto::initial_key(delivery.item_id));
            let merge = Self::merge_mut(&mut self.items, &self.item_keys, delivery.item_id);
            match merge.apply_op(OpInput {
                header,
                key_id,
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

/// An op body of a page that passed every check of the verify step.
struct Opened<'a> {
    /// The `ITEM_OP` envelope as served, which the device keeps.
    envelope: &'a [u8],
    /// The op `data` it opened to.
    data: Vec<u8>,
    /// The `key_id` of the item key it opened under.
    key: SymmetricKeyId,
}

/// An op body a device holds: an envelope it sealed itself, or one that passed the verify
/// step. The device opens each envelope once, when it accepts it, and keeps the `data` for the
/// delivery (a generated history opens the same record on several devices and pages, and
/// unoptimised test builds make each open slow). Synthetic test data, so plain vectors.
#[derive(Clone, Debug)]
struct HeldBody {
    /// The `ITEM_OP` envelope, as it travels.
    envelope: Vec<u8>,
    /// The op `data`: what the author sealed, or what the envelope opened to under the
    /// verified header.
    data: Vec<u8>,
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
