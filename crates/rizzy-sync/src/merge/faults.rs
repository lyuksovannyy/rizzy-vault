//! Dishonest snapshots for the tests: the fault kinds of the merge spike
//! (`spikes/merge-model/src/replica.rs` `Fault`, `apply_fault`), applied to an honest snapshot.
//! Each is built to pass the ADR 0018 §5 parse rules, as a "verified but dishonest" snapshot
//! must; [`faulty`] returns `None` when a kind does not apply or the record encoder refuses the
//! result.

use rizzy_core::ids::SymmetricKeyId;

use super::testkit::{Snap, key_id};
use crate::dot::Dot;
use crate::hlc::Hlc;
use crate::record::{
    Entry, FieldKey, LIFECYCLE_KEY, LiveSnapshot, Register, SnapshotData, Tombstone, Value,
};
use crate::vv::VersionVector;

/// A fault kind (the spike's names).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Fault {
    /// Drop the highest-ranked non-lifecycle current (or late) value; keep the VV.
    OmitValue,
    /// Drop the highest-ranked history entry; keep the VV.
    OmitHist,
    /// Raise the covered VV to the next dot of device `id`.
    ClaimNext(u8),
    /// Copy the highest-ranked value to key `zz.copy` at its dot, HLC + 1, other bytes.
    AltHlc,
    /// The same with the same HLC: detectable only by a replica that merged or received the op
    /// body at that dot (the spike: "undetectable when the body is compacted").
    AltKey,
    /// Replace the bytes of the highest-ranked non-lifecycle current (or late) value, same key,
    /// dot and HLC: detectable only against the op body at that dot (not a spike kind; added
    /// for ADR 0018 §3 "refuses ... a snapshot that contradicts an op body it holds").
    AltVal,
    /// Put the highest-ranked history entry back into its register.
    Resurrect,
    /// Present a live item as a tombstone whose purge is its highest-ranked current value.
    FakeTomb,
    /// Present a tombstone as live: Active at the purge dot, the late values as registers.
    FakeLive,
    /// Record the purge under a key id nobody holds.
    WrongKey,
    /// Widen `c` to the covered VV, dropping every late value.
    WidenC,
    /// Add a late value at the purge dot.
    LateAtPurge,
}

/// Every fault kind, `ClaimNext` for device 1.
pub(super) const ALL: [Fault; 12] = [
    Fault::OmitValue,
    Fault::OmitHist,
    Fault::ClaimNext(1),
    Fault::AltHlc,
    Fault::AltKey,
    Fault::AltVal,
    Fault::Resurrect,
    Fault::FakeTomb,
    Fault::FakeLive,
    Fault::WrongKey,
    Fault::WidenC,
    Fault::LateAtPurge,
];

/// One owned value: dot, HLC, bytes.
type Val = (Dot, Hlc, Vec<u8>);

/// One owned register: key and values ascending by dot.
type Reg = (String, Vec<Val>);

/// A snapshot's parts, owned.
#[derive(Clone, Debug)]
enum Parts {
    /// Current registers and history groups.
    Live(Vec<Reg>, Vec<Reg>),
    /// Purge dot, HLC, `c`, `item_key_id`, late registers.
    Tomb(Dot, Hlc, VersionVector, SymmetricKeyId, Vec<Reg>),
}

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

/// The record layer's registers for owned ones.
fn borrowed(regs: &[Reg]) -> Vec<Register<'_>> {
    regs.iter()
        .map(|(k, vs)| {
            let key = if k == LIFECYCLE_KEY {
                FieldKey::LIFECYCLE
            } else {
                FieldKey::new(k).unwrap()
            };
            Register::new(
                key,
                vs.iter()
                    .map(|(d, h, v)| Entry::new(*d, *h, Value::new(v)))
                    .collect(),
            )
        })
        .collect()
}

/// The highest-ranked `(hlc, dot)` value among `regs`, other than `@lifecycle`'s unless
/// `lifecycle`, with its key.
fn top(regs: &[Reg], lifecycle: bool) -> Option<(String, Val)> {
    regs.iter()
        .filter(|(k, _)| lifecycle || k != LIFECYCLE_KEY)
        .flat_map(|(k, vs)| vs.iter().map(move |v| (k.clone(), v.clone())))
        .max_by_key(|(_, (d, h, _))| (*h, *d))
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

/// Adds `value` to `key`'s register, creating it in key order; `false` if the dot is there.
fn insert(regs: &mut Vec<Reg>, key: &str, value: Val) -> bool {
    if let Some((_, vs)) = regs.iter_mut().find(|(k, _)| k == key) {
        if vs.iter().any(|(d, _, _)| *d == value.0) {
            return false;
        }
        vs.push(value);
        vs.sort_by_key(|(d, _, _)| *d);
    } else {
        regs.push((key.to_owned(), vec![value]));
        regs.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    }
    true
}

/// `honest` with `fault` applied, as a snapshot by `honest`'s author numbered `n`. `None`
/// when the kind does not apply to it or the encoder refuses the result.
pub(super) fn faulty(honest: &Snap, fault: Fault, n: u8) -> Option<Snap> {
    let mut covered = honest.header.covered.clone();
    let mut parts = match honest.parsed() {
        SnapshotData::Live(l) => Parts::Live(owned(l.registers()), owned(l.history())),
        SnapshotData::Tombstone(t) => Parts::Tomb(
            t.purge_dot(),
            t.purge_hlc(),
            t.context().clone(),
            t.item_key_id(),
            owned(t.late()),
        ),
    };
    match (fault, &mut parts) {
        (Fault::OmitValue, Parts::Live(regs, hist)) => {
            let (k, v) = top(regs, false)?;
            if remove(regs, &k, v.0) {
                hist.retain(|(hk, _)| *hk != k);
            }
        }
        (Fault::OmitValue, Parts::Tomb(_, _, _, _, late)) => {
            let (k, v) = top(late, false)?;
            remove(late, &k, v.0);
        }
        (Fault::OmitHist, Parts::Live(_, hist)) => {
            let (k, v) = top(hist, true)?;
            remove(hist, &k, v.0);
        }
        (Fault::ClaimNext(id), _) => {
            let device = super::testkit::device(id);
            covered.add(Dot::new(device, covered.get(device) + 1)?);
        }
        (Fault::AltHlc | Fault::AltKey, Parts::Live(regs, _) | Parts::Tomb(_, _, _, _, regs)) => {
            let (_, (d, h, mut v)) = top(regs, false)?;
            v.push(0x99);
            let bump = u64::from(fault == Fault::AltHlc);
            if !insert(regs, "zz.copy", (d, Hlc::from_u64(h.to_u64() + bump), v)) {
                return None;
            }
        }
        (Fault::AltVal, Parts::Live(regs, _) | Parts::Tomb(_, _, _, _, regs)) => {
            let (k, (d, _, _)) = top(regs, false)?;
            for (rk, vs) in regs.iter_mut() {
                if *rk == k {
                    for (vd, _, v) in vs.iter_mut() {
                        if *vd == d {
                            v.push(0x99);
                        }
                    }
                }
            }
        }
        (Fault::Resurrect, Parts::Live(regs, hist)) => {
            let (k, v) = top(hist, true)?;
            remove(hist, &k, v.0);
            insert(regs, &k, v);
        }
        (Fault::FakeTomb, Parts::Live(regs, _)) => {
            let (_, (d, h, _)) = top(regs, true)?;
            parts = Parts::Tomb(d, h, covered.clone(), key_id(0x40), Vec::new());
        }
        (Fault::FakeLive, Parts::Tomb(d, h, _, _, late)) => {
            let mut regs = vec![(LIFECYCLE_KEY.to_owned(), vec![(*d, *h, vec![0x01])])];
            regs.extend(late.iter().cloned());
            parts = Parts::Live(regs, Vec::new());
        }
        (Fault::WrongKey, Parts::Tomb(_, _, _, key, _)) => *key = key_id(0x7f),
        (Fault::WidenC, Parts::Tomb(_, _, c, _, late)) => {
            *c = covered.clone();
            late.clear();
        }
        (Fault::LateAtPurge, Parts::Tomb(d, h, c, _, late)) => {
            if c.covers(*d) || !insert(late, "zz.late", (*d, *h, vec![0x77])) {
                return None;
            }
        }
        _ => return None,
    }
    let data = match &parts {
        Parts::Live(regs, hist) => {
            SnapshotData::Live(LiveSnapshot::new(borrowed(regs), borrowed(hist)))
        }
        Parts::Tomb(d, h, c, key, late) => {
            SnapshotData::Tombstone(Tombstone::new(*d, *h, c.clone(), *key, borrowed(late)))
        }
    };
    let bytes = crate::record::encode_snapshot(&covered, &data).ok()?;
    let author = honest.header.author.as_bytes()[0];
    Some(Snap::from_bytes(
        author,
        n,
        covered,
        bytes.expose_secret().to_vec(),
    ))
}
