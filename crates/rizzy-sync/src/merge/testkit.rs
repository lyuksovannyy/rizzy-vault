//! A test harness for the merge: simulated devices that write ops on one item through the real
//! record encoder and parser, a test-only causal delivery buffer, and builders for honest and
//! dishonest snapshots.
//!
//! Causal delivery and the chain check are the `causal` layer's in production (ADR 0012 §4
//! step 2); here [`deliver`] releases an op once its dot is covered, or once its context and
//! its device's previous op are applied, which is the merge spike's `drain_pending` for one
//! item in one vault. Every device writes only this item, so an op's `vault_prev_seq` is its
//! device's previous `seq`.

use std::collections::BTreeMap;

use rizzy_core::ids::{DeviceId, ItemId, OpId, SnapshotId, SymmetricKeyId, VaultId};

use super::{
    Absorption, Applied, ItemMerge, MergeError, OpInput, OwnWrite, SnapshotInput, WrittenSnapshot,
};
use crate::dot::Dot;
use crate::header::{ItemSchemaVersion, OpHeader, SnapshotHeader};
use crate::hlc::Hlc;
use crate::record::{
    FieldKey, Lifecycle, OpData, SnapshotData, Value, Write, encode_op, encode_snapshot, parse_op,
    parse_snapshot,
};
use crate::vv::VersionVector;

/// 2026-05-28T20:26:40Z in Unix milliseconds, the base of every test clock.
pub(super) const T0: u64 = 1_780_000_000_000;

/// A device id whose 16 bytes are all `b`.
pub(super) fn device(b: u8) -> DeviceId {
    DeviceId::from_bytes([b; 16])
}

/// The dot `(device(b), seq)`.
pub(super) fn dot(b: u8, seq: u64) -> Dot {
    Dot::new(device(b), seq).unwrap()
}

/// The version vector with entries `(device(b), seq)`.
pub(super) fn vv(entries: &[(u8, u64)]) -> VersionVector {
    entries.iter().map(|&(b, s)| dot(b, s)).collect()
}

/// An item key id whose 16 bytes are all `b`.
pub(super) fn key_id(b: u8) -> SymmetricKeyId {
    SymmetricKeyId::from_bytes([b; 16])
}

/// The one vault of the tests.
pub(super) fn vault() -> VaultId {
    VaultId::from_bytes([0xaa; 16])
}

/// The one item of the tests.
pub(super) fn item() -> ItemId {
    ItemId::from_bytes([0x17; 16])
}

/// A Text value (ADR 0018 §6): type byte `0x01`, then `text`.
pub(super) fn text(text: &str) -> Vec<u8> {
    let mut v = vec![0x01];
    v.extend_from_slice(text.as_bytes());
    v
}

/// What a device writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Edit {
    /// A create or edit: these writes, with `Active`.
    Write(Vec<(String, Vec<u8>)>),
    /// A trash: `Trashed`, no writes.
    Trash,
    /// A restore: `Active`, no writes.
    Restore,
    /// A purge: `Purge`, no writes.
    Purge,
}

impl Edit {
    /// A write of `(key, value)` pairs.
    pub(super) fn write(writes: &[(&str, &[u8])]) -> Self {
        Self::Write(
            writes
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.to_vec()))
                .collect(),
        )
    }
}

/// An op record as the tests hold it: verified header, envelope `key_id`, encoded data.
#[derive(Clone, Debug)]
pub(super) struct Op {
    /// The header.
    pub(super) header: OpHeader,
    /// The `key_id` of the envelope header.
    pub(super) key_id: SymmetricKeyId,
    /// The encoded op data (ADR 0018 §3).
    pub(super) data: Vec<u8>,
}

impl Op {
    /// The op's dot.
    pub(super) fn dot(&self) -> Dot {
        self.header.dot
    }

    /// Runs `f` on the op as the merge receives it, its data parsed by the record parser.
    pub(super) fn with<R>(&self, f: impl FnOnce(OpInput<'_>) -> R) -> R {
        let data = parse_op(&self.data).unwrap();
        f(OpInput {
            header: &self.header,
            key_id: self.key_id,
            data: &data,
        })
    }
}

/// A snapshot record as the tests hold it.
#[derive(Clone, Debug)]
pub(super) struct Snap {
    /// The header.
    pub(super) header: SnapshotHeader,
    /// The encoded snapshot data (ADR 0018 §3).
    pub(super) data: Vec<u8>,
}

impl Snap {
    /// A snapshot by `author` of `covered` with `data`, encoded by the record encoder, which
    /// refuses anything the parser would.
    pub(super) fn build(
        author: u8,
        n: u8,
        covered: VersionVector,
        data: &SnapshotData<'_>,
    ) -> Self {
        let bytes = encode_snapshot(&covered, data).unwrap();
        Self::from_bytes(author, n, covered, bytes.expose_secret().to_vec())
    }

    /// A snapshot by `author` from already encoded data.
    pub(super) fn from_bytes(author: u8, n: u8, covered: VersionVector, data: Vec<u8>) -> Self {
        let mut id = [author; 16];
        id[15] = n;
        Self {
            header: SnapshotHeader {
                vault_id: vault(),
                item_id: item(),
                snapshot_id: SnapshotId::from_bytes(id),
                author: device(author),
                item_schema_version: ItemSchemaVersion::V1,
                vault_key_epoch: 0,
                covered,
            },
            data,
        }
    }

    /// The snapshot's data, parsed against its covered VV.
    pub(super) fn parsed(&self) -> SnapshotData<'_> {
        parse_snapshot(&self.header.covered, &self.data).unwrap()
    }
}

/// Absorbs `snap` into `merge`, with the bodies `with` of the same response.
pub(super) fn absorb(merge: &mut ItemMerge, snap: &Snap, with: &[Op]) -> Absorption {
    let datas: Vec<OpData<'_>> = with.iter().map(|o| parse_op(&o.data).unwrap()).collect();
    let inputs: Vec<OpInput<'_>> = with
        .iter()
        .zip(&datas)
        .map(|(o, d)| OpInput {
            header: &o.header,
            key_id: o.key_id,
            data: d,
        })
        .collect();
    let data = snap.parsed();
    merge
        .absorb_snapshot(
            SnapshotInput {
                header: &snap.header,
                data: &data,
            },
            &inputs,
        )
        .unwrap()
}

/// Whether `op` can be applied now: its dot is covered, or its context and its device's
/// previous op are applied (test-only causal delivery).
fn ready(merge: &ItemMerge, op: &Op) -> bool {
    let covered = merge.covered();
    covered.covers(op.dot())
        || (merge.is_ready(&op.header)
            && covered.get(op.dot().device_id()) >= op.header.vault_prev_seq)
}

/// Delivers `ops` causally: repeatedly applies the lowest ready op, in dot order, until none
/// is ready. Returns the ops left waiting. Every op is applied as received.
pub(super) fn deliver(merge: &mut ItemMerge, ops: &[Op]) -> Vec<Op> {
    let mut pending: Vec<Op> = ops.to_vec();
    loop {
        pending.sort_by_key(Op::dot);
        let Some(i) = pending.iter().position(|op| ready(merge, op)) else {
            return pending;
        };
        let op = pending.remove(i);
        op.with(|input| merge.apply_op(input)).unwrap();
    }
}

/// Records the headers of `ops` in `merge`, as the chain check does for every header it
/// verifies.
pub(super) fn record_headers(merge: &mut ItemMerge, ops: &[Op]) {
    for op in ops {
        merge.record_header(&op.header).unwrap();
    }
}

/// A simulated device writing the one item.
#[derive(Clone, Debug)]
pub(super) struct Device {
    /// Its id byte.
    pub(super) id: u8,
    /// Its merge of the item.
    pub(super) merge: ItemMerge,
    /// Its HLC.
    pub(super) clock: Hlc,
    /// Its wall clock, in Unix milliseconds.
    pub(super) now_ms: u64,
    /// The `seq` of its next op.
    pub(super) next_seq: u64,
    /// The item key it writes under.
    pub(super) key: SymmetricKeyId,
    /// Every op it wrote, by `seq`.
    pub(super) log: BTreeMap<u64, Op>,
    /// Snapshots it wrote.
    pub(super) snaps: u8,
}

impl Device {
    /// Device `id`, with its wall clock `skew_ms` after [`T0`].
    pub(super) fn new(id: u8, skew_ms: u64) -> Self {
        let key = key_id(0x40);
        let mut merge = ItemMerge::new(item());
        merge.add_item_key(key);
        Self {
            id,
            merge,
            clock: Hlc::ZERO,
            now_ms: T0 + skew_ms,
            next_seq: 1,
            key,
            log: BTreeMap::new(),
            snaps: 0,
        }
    }

    /// The op this device would write for `edit` now, without applying it.
    pub(super) fn prepare(&mut self, edit: &Edit) -> Op {
        self.now_ms += 1;
        self.clock = self.clock.tick(self.now_ms).unwrap();
        let seq = self.next_seq;
        self.next_seq += 1;
        let (lifecycle, writes): (Lifecycle, &[(String, Vec<u8>)]) = match edit {
            Edit::Write(w) => (Lifecycle::Active, w),
            Edit::Trash => (Lifecycle::Trashed, &[]),
            Edit::Restore => (Lifecycle::Active, &[]),
            Edit::Purge => (Lifecycle::Purge, &[]),
        };
        let mut sorted: Vec<&(String, Vec<u8>)> = writes.iter().collect();
        sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        let data = OpData::new(
            lifecycle,
            sorted
                .iter()
                .map(|(k, v)| Write::new(FieldKey::new(k).unwrap(), Value::new(v)))
                .collect(),
        );
        let encoded = encode_op(&data).unwrap();
        let mut op_id = [self.id; 16];
        op_id[8..].copy_from_slice(&seq.to_be_bytes());
        Op {
            header: OpHeader {
                vault_id: vault(),
                item_id: item(),
                op_id: OpId::from_bytes(op_id),
                dot: dot(self.id, seq),
                vault_prev_seq: seq - 1,
                hlc: self.clock,
                item_schema_version: ItemSchemaVersion::V1,
                vault_key_epoch: 0,
                causal_context: self.merge.covered().clone(),
            },
            key_id: self.key,
            data: encoded.expose_secret().to_vec(),
        }
    }

    /// Writes `edit` with `own`, returning the op and what applying it gave.
    pub(super) fn try_write(
        &mut self,
        edit: &Edit,
        own: OwnWrite,
    ) -> Result<(Op, Applied), MergeError> {
        let op = self.prepare(edit);
        let applied = op.with(|input| self.merge.apply_own_op(input, own));
        match applied {
            Ok(applied) => {
                self.log.insert(op.dot().seq(), op.clone());
                Ok((op, applied))
            }
            Err(e) => {
                self.next_seq -= 1;
                Err(e)
            }
        }
    }

    /// Writes `edit`, which must be allowed.
    pub(super) fn write(&mut self, edit: &Edit) -> Op {
        self.try_write(edit, OwnWrite::default()).unwrap().0
    }

    /// Receives `ops` (some may be its own, or known): records their headers, delivers them
    /// causally, and advances the clock on each fresh one. Returns the ops left waiting.
    pub(super) fn receive(&mut self, ops: &[Op]) -> Vec<Op> {
        record_headers(&mut self.merge, ops);
        let mut pending: Vec<Op> = ops.to_vec();
        loop {
            pending.sort_by_key(Op::dot);
            let Some(i) = pending.iter().position(|op| ready(&self.merge, op)) else {
                return pending;
            };
            let op = pending.remove(i);
            let applied = op.with(|input| self.merge.apply_op(input)).unwrap();
            if let Some(hlc) = applied.receive_hlc {
                self.now_ms += 1;
                self.clock = self.clock.receive(hlc, self.now_ms).unwrap().clock;
            }
        }
    }

    /// Writes a snapshot of its state, if one can be written.
    pub(super) fn snapshot(&mut self) -> Option<Snap> {
        let WrittenSnapshot { covered, data } = self.merge.write_snapshot().ok()?;
        self.snaps += 1;
        Some(Snap::from_bytes(
            self.id,
            self.snaps,
            covered,
            data.expose_secret().to_vec(),
        ))
    }

    /// Absorbs `snap` with the bodies `with`, then advances the clock by the receipt.
    pub(super) fn absorb(&mut self, snap: &Snap, with: &[Op]) -> Absorption {
        let absorption = absorb(&mut self.merge, snap, with);
        if let super::AbsorbOutcome::Absorbed(a) = &absorption.outcome
            && let Some(hlc) = a.receive_hlc
        {
            self.now_ms += 1;
            self.clock = self.clock.receive(hlc, self.now_ms).unwrap().clock;
        }
        absorption
    }

    /// Every op this device wrote.
    pub(super) fn ops(&self) -> Vec<Op> {
        self.log.values().cloned().collect()
    }
}

/// The canonical state bytes of `merge` (ADR 0018 §4), empty for an absent item.
pub(super) fn state_bytes(merge: &ItemMerge) -> Vec<u8> {
    merge
        .canonical_state()
        .unwrap()
        .map(|b| b.expose_secret().to_vec())
        .unwrap_or_default()
}

/// A fresh replica fed `ops` alone, in dot order, causally.
pub(super) fn reference(ops: &[Op]) -> ItemMerge {
    let mut merge = ItemMerge::new(item());
    merge.add_item_key(key_id(0x40));
    record_headers(&mut merge, ops);
    let stuck = deliver(&mut merge, ops);
    assert!(stuck.is_empty(), "ops stuck in the reference replay");
    merge
}
