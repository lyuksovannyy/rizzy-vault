//! The reference state of an item, computed directly from a set of applied ops as the specs
//! define it, never through [`crate::merge`], and the order-independence replay.
//!
//! - **Registers** (ADR 0012 §4 step 4 as ADR 0018 §3 restates it): per key, the values written
//!   by the applied ops other than a Purge, each op's lifecycle marker as a write to
//!   `@lifecycle` ([`LIFECYCLE_KEY`]). A value is current when no other applied write of the
//!   same key has a causal context that covers its dot.
//! - **Live item** (ADR 0012 §5, owner decision 3): every other value is history, the newest
//!   [`HISTORY_LIMIT`] per key by `(hlc, device_id, seq)`.
//! - **Tombstone** (ADR 0018 §3 "Tombstone (c)", owner decisions 8 and 9), once any Purge is
//!   applied: the recorded purge is the applied Purge with the highest `(hlc, device_id, seq)`,
//!   `c` the join of the applied purges' contexts, and the late registers hold the current
//!   values whose key is not `@lifecycle` and whose dot `c` does not cover. No history.
//! - **No silent loss** (ADR 0018 §12, replacing ADR 0012 §12 property 2): on a live item, every
//!   value an applied op wrote is current, in history, or removed by the pruning rule (it is
//!   not current, and its key's history holds [`HISTORY_LIMIT`] values ranked above it); on a
//!   tombstone, the late registers equal the definition above.
//!
//! Values and keys are compared, never printed: a mismatch names the item and the dot.

use std::collections::{BTreeMap, BTreeSet};

use rizzy_core::ids::ItemId;

use super::item_key;
use super::server::SnapRecord;
use crate::dot::Dot;
use crate::header::OpHeader;
use crate::hlc::Hlc;
use crate::merge::{AbsorbOutcome, HISTORY_LIMIT, ItemMerge, OpInput, SnapshotInput};
use crate::record::{LIFECYCLE_KEY, Lifecycle, OpData, SnapshotData, parse_op, parse_snapshot};
use crate::vv::VersionVector;

/// One value as the oracle holds it: dot, HLC and bytes.
pub(super) type Val = (Dot, Hlc, Vec<u8>);

/// Per key, a set of values.
pub(super) type Registers = BTreeMap<String, BTreeSet<Val>>;

/// An op of the harness's ledger: its header and body, and what it wrote.
#[derive(Clone, Debug)]
pub(super) struct LedgerOp {
    /// The header.
    pub(super) header: OpHeader,
    /// The encoded op data.
    pub(super) body: Vec<u8>,
    /// Its lifecycle marker.
    pub(super) lifecycle: Lifecycle,
    /// Its field writes, `(key, value)`.
    pub(super) writes: Vec<(String, Vec<u8>)>,
}

impl LedgerOp {
    /// The ledger entry of an op with this header and encoded data; `None` if it does not
    /// parse, which the harness's own encoder never produces.
    pub(super) fn new(header: OpHeader, body: Vec<u8>) -> Option<Self> {
        let parsed = parse_op(&body).ok()?;
        let lifecycle = parsed.lifecycle();
        let writes = parsed
            .writes()
            .iter()
            .map(|w| {
                (
                    w.key().expose_secret().to_owned(),
                    w.value().expose_secret().to_vec(),
                )
            })
            .collect();
        Some(Self {
            header,
            body,
            lifecycle,
            writes,
        })
    }

    /// The `(key, value)` writes of the op as a register write: its fields, then its lifecycle
    /// marker to `@lifecycle`. A Purge writes nothing.
    fn register_writes(&self) -> Vec<(String, Vec<u8>)> {
        let Some(marker) = self.lifecycle.register_value() else {
            return Vec::new();
        };
        let mut out = self.writes.clone();
        out.push((LIFECYCLE_KEY.to_owned(), marker.expose_secret().to_vec()));
        out
    }
}

/// An item's state, as the oracle or a replica holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum State {
    /// No op applied.
    Absent,
    /// A live item: current registers and history.
    Live {
        /// Current values per key.
        current: Registers,
        /// History per key.
        history: Registers,
    },
    /// A tombstone.
    Tombstone {
        /// The recorded purge's dot.
        purge_dot: Dot,
        /// Its HLC.
        purge_hlc: Hlc,
        /// `c`.
        context: VersionVector,
        /// The late registers.
        late: Registers,
    },
}

/// The rank of a value for pruning and the recorded purge: `(hlc, device_id, seq)`.
fn rank(dot: Dot, hlc: Hlc) -> (Hlc, [u8; 16], u64) {
    (hlc, dot.device_id().to_bytes(), dot.seq())
}

/// The multi-value registers of `ops` (the module docs), with each value's writer's context:
/// per key, `(current, superseded)`.
fn registers(ops: &[&LedgerOp]) -> (Registers, Registers) {
    let mut writes: BTreeMap<String, Vec<(Val, &VersionVector)>> = BTreeMap::new();
    for op in ops {
        for (key, value) in op.register_writes() {
            writes.entry(key).or_default().push((
                (op.header.dot, op.header.hlc, value),
                &op.header.causal_context,
            ));
        }
    }
    let mut current = Registers::new();
    let mut superseded = Registers::new();
    for (key, values) in writes {
        for (val, _) in &values {
            let covered = values
                .iter()
                .any(|((dot, _, _), ctx)| *dot != val.0 && ctx.covers(val.0));
            let into = if covered {
                &mut superseded
            } else {
                &mut current
            };
            into.entry(key.clone()).or_default().insert(val.clone());
        }
    }
    (current, superseded)
}

/// The newest [`HISTORY_LIMIT`] values of each key.
fn prune(history: Registers) -> Registers {
    history
        .into_iter()
        .map(|(key, values)| {
            let mut ranked: Vec<Val> = values.into_iter().collect();
            ranked.sort_by_key(|(dot, hlc, _)| core::cmp::Reverse(rank(*dot, *hlc)));
            ranked.truncate(HISTORY_LIMIT);
            (key, ranked.into_iter().collect())
        })
        .collect()
}

/// The state `ops` define (the module docs).
pub(super) fn expected(ops: &[&LedgerOp]) -> State {
    if ops.is_empty() {
        return State::Absent;
    }
    let purges: Vec<&&LedgerOp> = ops
        .iter()
        .filter(|op| op.lifecycle == Lifecycle::Purge)
        .collect();
    let (current, superseded) = registers(ops);
    let Some(recorded) = purges
        .iter()
        .max_by_key(|op| rank(op.header.dot, op.header.hlc))
    else {
        return State::Live {
            current,
            history: prune(superseded),
        };
    };
    let mut context = VersionVector::new();
    for purge in &purges {
        context.join(&purge.header.causal_context);
    }
    let late: Registers = current
        .into_iter()
        .filter(|(key, _)| key != LIFECYCLE_KEY)
        .map(|(key, values)| {
            let kept: BTreeSet<Val> = values
                .into_iter()
                .filter(|(dot, _, _)| !context.covers(*dot))
                .collect();
            (key, kept)
        })
        .filter(|(_, values)| !values.is_empty())
        .collect();
    State::Tombstone {
        purge_dot: recorded.header.dot,
        purge_hlc: recorded.header.hlc,
        context,
        late,
    }
}

/// The state a replica holds, read through [`ItemMerge::snapshot_data`].
pub(super) fn held(merge: &ItemMerge) -> Result<State, String> {
    let data = merge
        .snapshot_data()
        .map_err(|e| format!("snapshot_data failed: {e:?}"))?;
    let Some(data) = data else {
        return Ok(State::Absent);
    };
    let collect = |regs: &[crate::record::Register<'_>]| -> Registers {
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
    };
    Ok(match &data {
        SnapshotData::Live(live) => State::Live {
            current: collect(live.registers()),
            history: collect(live.history()),
        },
        SnapshotData::Tombstone(t) => State::Tombstone {
            purge_dot: t.purge_dot(),
            purge_hlc: t.purge_hlc(),
            context: t.context().clone(),
            late: collect(t.late()),
        },
    })
}

/// ADR 0018 §12 "no silent loss" for one replica's item against the ops it applied. Returns
/// the dots of the values found lost.
pub(super) fn silent_losses(applied: &[&LedgerOp], state: &State) -> Vec<Dot> {
    let mut lost = Vec::new();
    match (state, expected(applied)) {
        (State::Live { current, history }, State::Live { current: mvr, .. }) => {
            for op in applied {
                for (key, value) in op.register_writes() {
                    let val = (op.header.dot, op.header.hlc, value);
                    let in_state = current.get(&key).is_some_and(|v| v.contains(&val))
                        || history.get(&key).is_some_and(|v| v.contains(&val));
                    if in_state {
                        continue;
                    }
                    let is_current = mvr.get(&key).is_some_and(|v| v.contains(&val));
                    let pruned = !is_current
                        && history.get(&key).is_some_and(|h| {
                            h.len() == HISTORY_LIMIT
                                && h.iter().all(|(d, t, _)| rank(*d, *t) > rank(val.0, val.1))
                        });
                    if !pruned {
                        lost.push(val.0);
                    }
                }
            }
        }
        (State::Tombstone { late, .. }, State::Tombstone { late: want, .. }) => {
            for (key, values) in &want {
                for val in values {
                    if !late.get(key).is_some_and(|v| v.contains(val)) {
                        lost.push(val.0);
                    }
                }
            }
        }
        (State::Absent, State::Absent) => {}
        _ => lost.extend(applied.iter().map(|op| op.header.dot)),
    }
    lost
}

/// A small deterministic generator (xorshift64*), for the replay orders.
#[derive(Clone, Debug)]
pub(super) struct Rng(u64);

impl Rng {
    /// A generator from `seed` (a zero seed is moved off zero).
    pub(super) fn new(seed: u64) -> Self {
        Self(seed ^ 0x9e37_79b9_7f4a_7c15 | 1)
    }

    /// The next value.
    pub(super) fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A value below `n` (`n` > 0; 0 for `n` = 0).
    pub(super) fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        usize::try_from(self.next() % (n as u64)).unwrap_or(0)
    }

    /// True with probability `num / den`.
    pub(super) fn chance(&mut self, num: u64, den: u64) -> bool {
        den > 0 && self.next() % den < num
    }
}

/// What a replay reached.
#[derive(Debug)]
pub(super) struct Replayed {
    /// The state, read as [`held`] reads a replica's.
    pub(super) state: State,
    /// The canonical state bytes (ADR 0018 §4); empty for an absent item.
    pub(super) bytes: Vec<u8>,
    /// The snapshots absorbed.
    pub(super) absorbed: u64,
}

/// ADR 0012 §12 property 3 for one item (ADR 0018 §12: "absorbing honest snapshots ...
/// interleaved with ops ... reaches the state of the ops alone"): a fresh merge that verified
/// every header of `ops` is fed `ops` in a random causal order, with duplicates, and absorbs
/// `snapshots` at random points. The caller compares what it reached.
///
/// Every header is recorded first, so every snapshot's covered VV is within the verified
/// headers and the ADR 0018 §3 cut takes all of it. With `strict` (honest, untainted
/// snapshots), a refusal ([`AbsorbOutcome::Refused`]) or a reported disagreement is itself a
/// failure: the spec gives an honest snapshot no reason for either. Without it (the merge
/// spike's P3-faulty, which includes lies), both are allowed and counted out.
pub(super) fn replay(
    item: ItemId,
    ops: &[&LedgerOp],
    snapshots: &[&SnapRecord],
    rng: &mut Rng,
    strict: bool,
) -> Result<Replayed, String> {
    let mut merge = ItemMerge::new(item);
    merge.add_item_key(item_key(item));
    for op in ops {
        merge
            .record_header(&op.header)
            .map_err(|e| format!("record_header: {e:?}"))?;
    }
    // P3-faulty: every op body is known before anything is absorbed, as the merge spike's
    // `replay_fresh_item` learns every body first (`learn_body`); an absorption takes them as
    // bodies received with it. The strict replay takes none, the harder case for an honest
    // snapshot.
    let mut evidence: Vec<(&OpHeader, OpData<'_>)> = Vec::new();
    if !strict {
        for op in ops {
            let data = parse_op(&op.body).map_err(|e| format!("parse_op: {e:?}"))?;
            evidence.push((&op.header, data));
        }
    }
    let mut pending: Vec<&LedgerOp> = ops.to_vec();
    let mut done: Vec<&LedgerOp> = Vec::new();
    let mut snaps: Vec<&SnapRecord> = snapshots.to_vec();
    let mut absorbed = 0;
    loop {
        if !snaps.is_empty() && rng.chance(1, 4) {
            let snap = snaps.swap_remove(rng.below(snaps.len()));
            absorbed += absorb(&mut merge, item, snap, &evidence, strict)?;
            continue;
        }
        if !done.is_empty() && rng.chance(1, 6) {
            if let Some(op) = done.get(rng.below(done.len())) {
                apply(&mut merge, item, op)?;
            }
            continue;
        }
        let ready: Vec<usize> = (0..pending.len())
            .filter(|&i| pending.get(i).is_some_and(|op| merge.is_ready(&op.header)))
            .collect();
        if ready.is_empty() {
            break;
        }
        let Some(&at) = ready.get(rng.below(ready.len())) else {
            break;
        };
        let op = pending.swap_remove(at);
        apply(&mut merge, item, op)?;
        done.push(op);
    }
    for snap in snaps {
        absorbed += absorb(&mut merge, item, snap, &evidence, strict)?;
    }
    if !pending.is_empty() {
        return Err(format!("{} ops never became ready", pending.len()));
    }
    let bytes = merge
        .canonical_state()
        .map_err(|e| format!("canonical_state: {e:?}"))?
        .map(|b| b.expose_secret().to_vec())
        .unwrap_or_default();
    Ok(Replayed {
        state: held(&merge)?,
        bytes,
        absorbed,
    })
}

/// Absorbs one snapshot record into `merge`; returns 1 if absorbed, 0 if refused. With
/// `strict`, a refusal or a disagreement is an error.
fn absorb(
    merge: &mut ItemMerge,
    item: ItemId,
    snap: &SnapRecord,
    evidence: &[(&OpHeader, OpData<'_>)],
    strict: bool,
) -> Result<u64, String> {
    let with: Vec<OpInput<'_>> = evidence
        .iter()
        .map(|(header, data)| OpInput {
            header,
            key_id: item_key(item),
            data,
        })
        .collect();
    let data = parse_snapshot(&snap.header.covered, &snap.data)
        .map_err(|e| format!("parse_snapshot: {e:?}"))?;
    let absorption = merge
        .absorb_snapshot(
            SnapshotInput {
                header: &snap.header,
                data: &data,
            },
            &with,
        )
        .map_err(|e| format!("absorb_snapshot: {e:?}"))?;
    match absorption.outcome {
        AbsorbOutcome::Absorbed(a) if strict && !a.disagreements.is_empty() => Err(format!(
            "an honest snapshot by {:?} of {:?} disagrees at {:?}",
            snap.header.author, snap.header.covered, a.disagreements
        )),
        AbsorbOutcome::Absorbed(_) => Ok(1),
        AbsorbOutcome::Refused(r) if strict => Err(format!(
            "an honest snapshot by {:?} of {:?} was refused: {r:?}",
            snap.header.author, snap.header.covered
        )),
        AbsorbOutcome::Refused(_) => Ok(0),
    }
}

/// Applies one ledger op to `merge`.
fn apply(merge: &mut ItemMerge, item: ItemId, op: &LedgerOp) -> Result<(), String> {
    let data = parse_op(&op.body).map_err(|e| format!("parse_op: {e:?}"))?;
    merge
        .apply_op(OpInput {
            header: &op.header,
            key_id: item_key(item),
            data: &data,
        })
        .map(|_| ())
        .map_err(|e| format!("apply_op at {:?}: {e:?}", op.header.dot))
}
