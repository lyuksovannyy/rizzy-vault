//! Fuzzes `rizzy-sync`'s per-item merge (ADR 0012 §4–§5, ADR 0018 §3, §10) with records a
//! faulty or hostile author can sign: ops and snapshots that pass every ADR 0018 §5 parse rule
//! but carry any header context, HLC, claim, value, tombstone or `item_key_id`, delivered in
//! any order, duplicated, early, or for another item. Under "Snapshots are claims" (owner
//! decision 14) the merge takes such records, refuses them or reports them; it must never
//! panic, and what it keeps must stay a state the record layer accepts.
//!
//! The input is read as up to 32 steps on one item over four devices. Each step records a
//! header, applies an op, applies an own op, absorbs a snapshot (with the ops seen so far as
//! the response's bodies), ends a Fetch, writes a snapshot, or re-issues an op under another
//! key. Headers, op data and snapshot data are built from the input and encoded by the record
//! encoder, then parsed back, so every record the merge sees is one a verified envelope could
//! carry; a snapshot the encoder refuses is skipped. Input that runs out reads as zeros.
//!
//! After every step:
//!
//! - the covered VV never goes backwards (ADR 0012 §7 "Freshness", INV-25: the join only
//!   raises it);
//! - [`ItemMerge::canonical_state`] either succeeds or reports a record-layer refusal, and
//!   every view (lifecycle, fields, times, late values) answers;
//! - a written snapshot parses against its covered VV (ADR 0018 §1: "every serializer output
//!   within the §10 limits must parse").
//!
//! Not in the CRYPTO.md §15 item 7 list by name; CLAUDE.md requires a target for untrusted
//! input, and a snapshot's content is its author's claim.
//!
//! ```text
//! cargo +nightly fuzz run sync_merge
//! ```
#![no_main]

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use rizzy_core::ids::{DeviceId, ItemId, OpId, SnapshotId, SymmetricKeyId, VaultId};
use rizzy_sync::dot::Dot;
use rizzy_sync::header::{ItemSchemaVersion, OpHeader, SnapshotHeader};
use rizzy_sync::hlc::Hlc;
use rizzy_sync::merge::{ItemMerge, MergeError, OpInput, OwnWrite, Reissue, SnapshotInput};
use rizzy_sync::record::{
    Entry, FieldKey, Lifecycle, LiveSnapshot, OpData, Register, SnapshotData, Tombstone, Value,
    Write, encode_op, encode_snapshot, parse_op, parse_snapshot,
};
use rizzy_sync::vv::{VersionVector, VvOrdering};

/// The id bytes of the four devices: device i is `[IDS[i]; 16]`.
const IDS: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];

/// The field keys the records write, in canonical order (ADR 0018 §4).
const KEYS: [&str; 4] = ["item.name", "item.notes", "login.password", "tag/61"];

/// The item every record names, unless a step names another.
const ITEM: ItemId = ItemId::from_bytes([0x17; 16]);

/// The fuzz input, read front to back; reads past the end give zeros.
struct Input<'a>(&'a [u8]);

impl Input<'_> {
    /// The next byte, 0 once the input is used up.
    fn byte(&mut self) -> u8 {
        match self.0.split_first() {
            Some((&b, rest)) => {
                self.0 = rest;
                b
            }
            None => 0,
        }
    }

    /// One of the four devices.
    fn device(&mut self) -> DeviceId {
        DeviceId::from_bytes([IDS[usize::from(self.byte() % 4)]; 16])
    }

    /// A dot with `seq` 1–8.
    fn dot(&mut self) -> Dot {
        let device = self.device();
        Dot::new(device, u64::from(self.byte() % 8) + 1).expect("seq 1-8 is a valid dot")
    }

    /// An HLC: a small counter over a fixed millisecond, or, rarely, one far ahead.
    fn hlc(&mut self) -> Hlc {
        match self.byte() {
            0xff => Hlc::from_u64(u64::MAX - u64::from(self.byte())),
            b => Hlc::from_u64((1_780_000_000_000 << 16) + u64::from(b % 32)),
        }
    }

    /// A version vector of up to four entries, `seq` 1–8.
    fn vv(&mut self) -> VersionVector {
        (0..self.byte() % 5).map(|_| self.dot()).collect()
    }

    /// A value: Cleared, or one to three bytes.
    fn value(&mut self) -> Vec<u8> {
        (0..self.byte() % 4).map(|_| self.byte()).collect()
    }

    /// A key id: one of four.
    fn key_id(&mut self) -> SymmetricKeyId {
        SymmetricKeyId::from_bytes([0x40 + self.byte() % 4; 16])
    }
}

/// An op record as the target holds it.
#[derive(Clone)]
struct Op {
    /// Its header.
    header: OpHeader,
    /// Its envelope's `key_id`.
    key_id: SymmetricKeyId,
    /// Its encoded data.
    data: Vec<u8>,
}

/// A header with the given dot, from the input: its HLC, context, item and schema version.
fn header(input: &mut Input<'_>, dot: Dot) -> OpHeader {
    let flags = input.byte();
    OpHeader {
        vault_id: VaultId::from_bytes([0xaa; 16]),
        item_id: if flags & 0x0f == 0x0f {
            ItemId::from_bytes([0x18; 16])
        } else {
            ITEM
        },
        op_id: OpId::from_bytes([flags; 16]),
        dot,
        vault_prev_seq: dot.seq() - 1,
        hlc: input.hlc(),
        item_schema_version: if flags & 0xf0 == 0xf0 {
            ItemSchemaVersion::new(2).expect("2 is a valid version")
        } else {
            ItemSchemaVersion::V1
        },
        vault_key_epoch: 0,
        causal_context: input.vv(),
    }
}

/// An op from the input, encoded and checked by the record encoder.
fn op(input: &mut Input<'_>, header: OpHeader) -> Op {
    let lifecycle = match input.byte() % 4 {
        0 => Lifecycle::Trashed,
        1 => Lifecycle::Purge,
        _ => Lifecycle::Active,
    };
    let mut values = Vec::new();
    if lifecycle == Lifecycle::Active {
        let mask = input.byte();
        for (i, key) in KEYS.iter().enumerate() {
            if mask & (1 << i) != 0 {
                values.push((*key, input.value()));
            }
        }
    }
    let writes = values
        .iter()
        .map(|(k, v)| Write::new(FieldKey::new(k).expect("a grammar key"), Value::new(v)))
        .collect();
    let data = encode_op(&OpData::new(lifecycle, writes)).expect("a valid op encodes");
    Op {
        header,
        key_id: input.key_id(),
        data: data.expose_secret().to_vec(),
    }
}

/// Entries at distinct dots from the input, ascending by dot.
fn entries<'a>(input: &mut Input<'_>, values: &'a [Vec<u8>], lifecycle: bool) -> Vec<Entry<'a>> {
    let mut by_dot: BTreeMap<Dot, Entry<'a>> = BTreeMap::new();
    for v in values {
        let dot = input.dot();
        let value = if lifecycle {
            Value::new(if v.first().is_some_and(|b| b & 1 == 0) {
                &[0x02]
            } else {
                &[0x01]
            })
        } else {
            Value::new(v)
        };
        by_dot.insert(dot, Entry::new(dot, input.hlc(), value));
    }
    by_dot.into_values().collect()
}

/// A snapshot from the input: live or a tombstone, with a covered VV that covers what it
/// holds plus the input's claims. `None` when the encoder refuses it.
fn snapshot(input: &mut Input<'_>, pool: &[Vec<u8>]) -> Option<(SnapshotHeader, Vec<u8>)> {
    let kind = input.byte();
    let mut covered = input.vv();
    let data = if kind & 1 == 0 {
        let n = 1 + usize::from(input.byte() % 2);
        let lifecycle = entries(input, pool.get(..n)?, true);
        let mut registers = vec![Register::new(FieldKey::LIFECYCLE, lifecycle)];
        let mut history = Vec::new();
        for key in KEYS {
            let n = usize::from(input.byte() % 4);
            if n == 0 {
                continue;
            }
            let all = entries(input, pool.get(..n)?, false);
            let split = usize::from(input.byte()) % all.len().max(1);
            let (hist, cur) = all.split_at(split);
            let key = FieldKey::new(key).expect("a grammar key");
            if cur.is_empty() {
                continue;
            }
            registers.push(Register::new(key, cur.to_vec()));
            if !hist.is_empty() {
                history.push(Register::new(key, hist.to_vec()));
            }
        }
        SnapshotData::Live(LiveSnapshot::new(registers, history))
    } else {
        let purge = input.dot();
        let purge_hlc = input.hlc();
        let c = input.vv();
        let mut late = Vec::new();
        for key in KEYS {
            let n = usize::from(input.byte() % 3);
            let kept: Vec<Entry<'_>> = entries(input, pool.get(..n)?, false)
                .into_iter()
                .filter(|e| !c.covers(e.dot()))
                .collect();
            if !kept.is_empty() {
                late.push(Register::new(
                    FieldKey::new(key).expect("a grammar key"),
                    kept,
                ));
            }
        }
        covered.add(purge);
        covered.join(&c);
        SnapshotData::Tombstone(Tombstone::new(purge, purge_hlc, c, input.key_id(), late))
    };
    let dots: Vec<Dot> = match &data {
        SnapshotData::Live(l) => l
            .registers()
            .iter()
            .chain(l.history())
            .flat_map(|r| r.entries().iter().map(Entry::dot))
            .collect(),
        SnapshotData::Tombstone(t) => t
            .late()
            .iter()
            .flat_map(|r| r.entries().iter().map(Entry::dot))
            .collect(),
    };
    dots.into_iter().for_each(|d| covered.add(d));
    let bytes = encode_snapshot(&covered, &data).ok()?;
    let header = SnapshotHeader {
        vault_id: VaultId::from_bytes([0xaa; 16]),
        item_id: ITEM,
        snapshot_id: SnapshotId::from_bytes([kind; 16]),
        author: input.device(),
        item_schema_version: ItemSchemaVersion::V1,
        vault_key_epoch: 0,
        covered,
    };
    Some((header, bytes.expose_secret().to_vec()))
}

/// Applies `op` as received, or as this device's own write.
fn apply(m: &mut ItemMerge, op: &Op, own: bool) -> Result<(), MergeError> {
    let data = parse_op(&op.data).expect("an encoded op parses");
    let input = OpInput {
        header: &op.header,
        key_id: op.key_id,
        data: &data,
    };
    if own {
        m.apply_own_op(input, OwnWrite::default()).map(|_| ())
    } else {
        m.apply_op(input).map(|_| ())
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let mut m = ItemMerge::new(ITEM);
    m.add_item_key(SymmetricKeyId::from_bytes([0x40; 16]));
    let pool: Vec<Vec<u8>> = (0..4).map(|_| input.value()).collect();
    let mut ops: Vec<Op> = Vec::new();
    for _ in 0..32 {
        let before = m.covered().clone();
        match input.byte() % 8 {
            0 => {
                let dot = input.dot();
                let h = header(&mut input, dot);
                let _ = m.record_header(&h);
            }
            1 | 2 => {
                let dot = input.dot();
                let h = header(&mut input, dot);
                let o = op(&mut input, h);
                let _ = m.record_header(&o.header);
                let _ = apply(&mut m, &o, false);
                ops.push(o);
            }
            3 => {
                // An own op on the current state.
                let dot = input.dot();
                let mut h = header(&mut input, dot);
                h.causal_context = m.covered().clone();
                let o = op(&mut input, h);
                if apply(&mut m, &o, true).is_ok() {
                    ops.push(o);
                }
            }
            4 => {
                let Some((header, bytes)) = snapshot(&mut input, &pool) else {
                    continue;
                };
                let parsed = parse_snapshot(&header.covered, &bytes).expect("encoded data parses");
                let datas: Vec<OpData<'_>> = ops
                    .iter()
                    .map(|o| parse_op(&o.data).expect("an encoded op parses"))
                    .collect();
                let with: Vec<OpInput<'_>> = ops
                    .iter()
                    .zip(&datas)
                    .filter(|(o, _)| o.header.item_id == ITEM)
                    .map(|(o, d)| OpInput {
                        header: &o.header,
                        key_id: o.key_id,
                        data: d,
                    })
                    .collect();
                let take = usize::from(input.byte()) % (with.len() + 1);
                let _ = m.absorb_snapshot(
                    SnapshotInput {
                        header: &header,
                        data: &parsed,
                    },
                    with.get(..take).unwrap_or_default(),
                );
            }
            5 => {
                let _ = m.end_fetch();
            }
            6 => {
                if let Ok(written) = m.write_snapshot() {
                    assert_eq!(&written.covered, m.covered());
                    parse_snapshot(&written.covered, written.data.expose_secret())
                        .expect("a written snapshot parses");
                }
            }
            _ => {
                if let Some(o) = ops.get(usize::from(input.byte()) % ops.len().max(1)) {
                    let _ = m.reissue_own_op(
                        &o.header,
                        input.key_id(),
                        Reissue {
                            fresh_item_key: input.byte() & 1 == 1,
                            discarded_unsent_snapshot: input.byte() & 1 == 1,
                        },
                    );
                }
            }
        }
        assert!(matches!(
            before.compare(m.covered()),
            VvOrdering::Less | VvOrdering::Equal
        ));
        match m.canonical_state() {
            Ok(_) | Err(MergeError::Record(_)) => {}
            Err(other) => panic!("canonical state: {other}"),
        }
        let _ = (
            m.lifecycle(),
            m.times(),
            m.late_values_to_surface(),
            m.is_oversize(),
        );
        for key in KEYS {
            let _ = m.field(key);
        }
        let _ = m.snapshot_data().expect("held keys are record keys");
        let _ = m.basis_data().expect("held keys are record keys");
    }
});
