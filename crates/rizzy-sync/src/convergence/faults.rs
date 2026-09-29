//! Dishonest snapshots of the `faulty` family: ADR 0021 §8 "snapshots that claim unheld dots,
//! up to `u64::MAX`", and the ADR 0018 §3 "Snapshots are claims" lies of the merge spike's
//! fault kinds (`spikes/merge-model/src/replica.rs` `Fault`: `ClaimNext`, `OmitValue`,
//! `FakeTombSmart`), applied to the honest snapshot a faulty device just wrote.
//!
//! Each lie passes the ADR 0018 §5 parse rules, as a verified but dishonest snapshot must: the
//! result goes through [`encode_snapshot`], which refuses anything the parser would, and a
//! kind that does not apply or does not encode gives `None` (the device then sends the honest
//! snapshot, as the spike skips a fault that does not apply). The faulty device's own state
//! and ops stay honest; only the snapshots it writes lie (spike README, "Faulty clients").

use rizzy_core::ids::{DeviceId, SymmetricKeyId};

use crate::dot::Dot;
use crate::hlc::Hlc;
use crate::record::{
    Entry, FieldKey, LIFECYCLE_KEY, LiveSnapshot, Register, SnapshotData, Tombstone, Value,
    encode_snapshot, parse_snapshot,
};
use crate::vv::VersionVector;

/// A lie a faulty device tells in a snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Fault {
    /// Claim dots the server holds and the author never saw: another device's covered-VV entry
    /// raised to the server's head for it. The server stores it (§9 accepts a claim up to the
    /// heads); the clients' cut and the evidence merge must keep it from swallowing the
    /// genuine ops.
    ClaimHeld,
    /// Claim the next dot above the server's head of another device: the server refuses it
    /// outside a healing request (ADR 0021 §9 "Server acceptance").
    ClaimAbove,
    /// Claim another device's dots up to `u64::MAX`: refused the same way.
    ClaimMax,
    /// Omit the highest-ranked non-lifecycle current (or late) value, keeping the VV.
    OmitValue,
    /// Present the item as a tombstone whose recorded purge is the oldest current field write
    /// (the spike's `FakeTombSmart`): `c` is that op's causal context, as it would be for a
    /// real purge, and the late values are the current values `c` does not cover. A replica
    /// that merged or received the write's body refuses it (`WriteRecordedAsPurge`).
    FakeTomb,
}

/// Every fault kind.
pub(super) const ALL: [Fault; 5] = [
    Fault::ClaimHeld,
    Fault::ClaimAbove,
    Fault::ClaimMax,
    Fault::OmitValue,
    Fault::FakeTomb,
];

/// One owned value: dot, HLC, bytes.
type Val = (Dot, Hlc, Vec<u8>);

/// One owned register: key and values ascending by dot.
type Reg = (String, Vec<Val>);

/// Owned registers from the record layer's.
fn owned(regs: &[Register<'_>]) -> Vec<Reg> {
    regs.iter()
        .map(|r| {
            (
                r.key().expose_secret().to_owned(),
                r.entries()
                    .iter()
                    .map(|e| (e.dot(), e.hlc(), e.value().expose_secret().to_vec()))
                    .collect(),
            )
        })
        .collect()
}

/// The record layer's registers for owned ones; `None` if a key does not parse.
fn borrowed(regs: &[Reg]) -> Option<Vec<Register<'_>>> {
    regs.iter()
        .map(|(k, vs)| {
            let key = if k == LIFECYCLE_KEY {
                FieldKey::LIFECYCLE
            } else {
                FieldKey::new(k).ok()?
            };
            Some(Register::new(
                key,
                vs.iter()
                    .map(|(d, h, v)| Entry::new(*d, *h, Value::new(v)))
                    .collect(),
            ))
        })
        .collect()
}

/// The non-lifecycle value of `regs` ranked highest (`newest`) or lowest by `(hlc, dot)`, with
/// its key.
fn pick(regs: &[Reg], newest: bool) -> Option<(String, Val)> {
    let values = regs
        .iter()
        .filter(|(k, _)| k != LIFECYCLE_KEY)
        .flat_map(|(k, vs)| vs.iter().map(move |v| (k.clone(), v.clone())));
    if newest {
        values.max_by_key(|(_, (d, h, _))| (*h, *d))
    } else {
        values.min_by_key(|(_, (d, h, _))| (*h, *d))
    }
}

/// Removes the value at `dot` from `key`'s register, and the register if it empties; returns
/// whether it emptied.
fn remove(regs: &mut Vec<Reg>, key: &str, dot: Dot) -> bool {
    let mut emptied = false;
    for (k, vs) in regs.iter_mut() {
        if k == key {
            vs.retain(|(d, _, _)| *d != dot);
            emptied = vs.is_empty();
        }
    }
    regs.retain(|(_, vs)| !vs.is_empty());
    emptied
}

/// A device other than `author` to claim dots of: the first of `heads`, else a device no one
/// enrolled.
fn other_device(heads: &VersionVector, author: DeviceId) -> DeviceId {
    heads
        .entries()
        .map(Dot::device_id)
        .find(|d| *d != author)
        .unwrap_or_else(|| DeviceId::from_bytes([0xee; 16]))
}

/// What a faulty snapshot needs to know besides its own data.
pub(super) struct Known<'a> {
    /// The snapshot's author.
    pub(super) author: DeviceId,
    /// The server's heads when the snapshot is written (the faulty device's view of the
    /// server, for the claims).
    pub(super) heads: &'a VersionVector,
    /// The item key the tombstone lie records.
    pub(super) item_key: SymmetricKeyId,
    /// The verified causal context of the op at a dot, from the author's kept headers.
    pub(super) causal_context: &'a dyn Fn(Dot) -> Option<VersionVector>,
}

/// The honest snapshot (`covered`, `data`) with `fault` applied: its covered VV and encoded
/// data, or `None` when the kind does not apply or the encoder refuses the result.
pub(super) fn apply(
    fault: Fault,
    covered: &VersionVector,
    data: &[u8],
    cx: &Known<'_>,
) -> Option<(VersionVector, Vec<u8>)> {
    let parsed = parse_snapshot(covered, data).ok()?;
    let mut covered = covered.clone();
    let rebuilt: Option<Vec<u8>> = match (fault, &parsed) {
        (Fault::ClaimHeld, _) => {
            let (device, head) = cx
                .heads
                .entries()
                .filter(|d| d.device_id() != cx.author)
                .find(|d| d.seq() > covered.get(d.device_id()))
                .map(|d| (d.device_id(), d.seq()))?;
            covered.add(Dot::new(device, head)?);
            Some(data.to_vec())
        }
        (Fault::ClaimAbove | Fault::ClaimMax, _) => {
            let device = other_device(cx.heads, cx.author);
            let seq = if fault == Fault::ClaimMax {
                u64::MAX
            } else {
                cx.heads.get(device).saturating_add(1)
            };
            covered.add(Dot::new(device, seq)?);
            Some(data.to_vec())
        }
        (Fault::OmitValue, SnapshotData::Live(live)) => {
            let (mut regs, mut hist) = (owned(live.registers()), owned(live.history()));
            let (key, (dot, _, _)) = pick(&regs, true)?;
            if remove(&mut regs, &key, dot) {
                hist.retain(|(k, _)| *k != key);
            }
            encode_live(&covered, &regs, &hist)
        }
        (Fault::OmitValue, SnapshotData::Tombstone(t)) => {
            let mut late = owned(t.late());
            let (key, (dot, _, _)) = pick(&late, true)?;
            remove(&mut late, &key, dot);
            let late_regs = borrowed(&late)?;
            let lie = SnapshotData::Tombstone(Tombstone::new(
                t.purge_dot(),
                t.purge_hlc(),
                t.context().clone(),
                t.item_key_id(),
                late_regs,
            ));
            encode_snapshot(&covered, &lie)
                .ok()
                .map(|b| b.expose_secret().to_vec())
        }
        (Fault::FakeTomb, SnapshotData::Live(live)) => {
            let regs = owned(live.registers());
            let (_, (purge_dot, purge_hlc, _)) = pick(&regs, false)?;
            let c = (cx.causal_context)(purge_dot)?;
            let late: Vec<Reg> = regs
                .into_iter()
                .filter(|(k, _)| k != LIFECYCLE_KEY)
                .map(|(k, vs)| {
                    let kept = vs
                        .into_iter()
                        .filter(|(d, _, _)| *d != purge_dot && !c.covers(*d))
                        .collect::<Vec<Val>>();
                    (k, kept)
                })
                .filter(|(_, vs)| !vs.is_empty())
                .collect();
            let late_regs = borrowed(&late)?;
            let fake = SnapshotData::Tombstone(Tombstone::new(
                purge_dot,
                purge_hlc,
                c,
                cx.item_key,
                late_regs,
            ));
            encode_snapshot(&covered, &fake)
                .ok()
                .map(|b| b.expose_secret().to_vec())
        }
        (Fault::FakeTomb, SnapshotData::Tombstone(_)) => None,
    };
    rebuilt.map(|bytes| (covered, bytes))
}

/// A live snapshot of `regs` and `hist` under `covered`, encoded.
fn encode_live(covered: &VersionVector, regs: &[Reg], hist: &[Reg]) -> Option<Vec<u8>> {
    let data = SnapshotData::Live(LiveSnapshot::new(borrowed(regs)?, borrowed(hist)?));
    encode_snapshot(covered, &data)
        .ok()
        .map(|b| b.expose_secret().to_vec())
}
