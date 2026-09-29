//! The evidence join: the one merge function behind applying an op and absorbing a snapshot
//! (ADR 0012 §4 step 4 and §5 as ADR 0018 §3 restates them; ADR 0018 §3 "Snapshots are
//! claims", owner decision 14).
//!
//! The merge is a function of the *set of values* a replica holds, from op bodies and from the
//! part of snapshots it takes, and of the verified op headers of their dots:
//!
//! - **Current values.** A key's current values are the values of that key that no other held
//!   value of the key *supersedes*, where `u` supersedes `v` when `u`'s verified header context
//!   covers `v`'s dot (ADR 0012 §2: op A happened before op B if B's context covers A's dot).
//!   Every other value of the key is history, pruned to [`HISTORY_LIMIT`] by `(hlc, device_id,
//!   seq)` ([`prune`], ADR 0012 §5 "Pruning is deterministic").
//! - **Tombstones.** When either side is a tombstone the result is one (a purge never
//!   resurrects, ADR 0018 §3 "Applying" 3): the recorded purge is the highest by
//!   `(hlc, device_id, seq)`, `c` is the join of the purge contexts, and the late registers
//!   hold, per key other than `@lifecycle`, the current values of all held values that `c`
//!   does not cover (ADR 0018 §3 "Recorded purge", "Context", "Late values"). The live side's
//!   history and `@lifecycle` are discarded.
//! - **One dot in two versions** (only a dishonest record carries one): the version whose HLC
//!   is the verified header's is kept, then the lower `(hlc, value)` ([`preferred`]); on one
//!   purge dot, the `item_key_id` in the wrap set first ([`purge_order`]).
//!
//! **Applying an op** is joining the state with the op as a one-op state ([`singleton`]). On an
//! honest state this is exactly ADR 0012 §4 step 4 and ADR 0018 §3 "Applying" 1–3: the op's
//! context covers the current values it removes, so they become history; the first Purge on a
//! live item keeps the current values `c` does not cover and discards the rest; a Purge on a
//! tombstone joins `c`, may become the recorded purge and filters the late values; any other op
//! on a tombstone replaces the late values its context covers and writes nothing through its
//! lifecycle byte. The merge spike (`spikes/merge-model`, `item.rs` `em_join`, `maximal`,
//! `singleton`) runs this function in its `integrated` configuration, and its "Results" found
//! it equal to the op-by-op merge on every honest state.
//!
//! **Absence is not evidence.** A value leaves the current values only when a present value's
//! verified header context covers it, never because a snapshot lacks it. That is what lets a
//! replica absorb a snapshot that omits a value without losing the value.
//!
//! **Why the order of arrival does not matter.** Each part of the result is a union (the values
//! per key), a join (the VV, `c`) or a maximum under a total order (the recorded purge, the
//! version of a dot), and the current values and the late filter are functions of those. So
//! the join is commutative and idempotent on every state, and associative on every state whose
//! verified contexts are causal; pruning keeps the top [`HISTORY_LIMIT`] of a set that only
//! grows, which commutes with the union. The property tests check it (ADR 0012 §12
//! properties 1–3). One exception: the order between two versions of one *purge* dot reads the
//! wrap set ([`purge_order`]), which grows as item keys are added, and the losing version is
//! discarded. Two replicas that join the same two versions, one before and one after the key
//! of the winning version joins the wrap set, can record different `item_key_id`s and do not
//! re-converge on their own. Only a dishonest record carries one purge dot two ways, and
//! absorbing it is always reported as a disagreement ([`super::evidence::disagreements`]), so
//! the item keeps its ops and gets no further snapshot; the merge spike behaves the same.
//!
//! **Normal form.** Every state this module returns is in normal form: per key, the current
//! values are exactly the values no other held value supersedes, and the history the rest,
//! pruned. The verified header of every held value is recorded before the value is joined and
//! never changes (a second header for one dot is refused), so a state stays in normal form as
//! more headers arrive. A snapshot is put in normal form once ([`normalize`]) before it is
//! joined, since a dishonest one can hold a superseded value as current.
//!
//! **Cost.** A join recomputes only the keys the incoming side holds ([`join_into`]); the keys
//! of the other side are kept as they are, which is exact for states in normal form: the
//! current values of a key are a function of that key's values alone. Supersession among the
//! `m` values of a key is decided with a per-device index of their context entries
//! ([`Supersession`]), in O(m · e) VV entry reads for contexts of `e` entries, not O(m²)
//! pairwise tests. So applying an op costs in the keys it writes, and absorbing a snapshot in
//! the values it carries, which the ADR 0018 §10 limits bound (at most
//! [`crate::record::MAX_SNAPSHOT_DATA_LEN`] bytes), plus the item's values of the same keys. A
//! transition from live to tombstone recomputes every key once.

use std::collections::{BTreeMap, BTreeSet};

use rizzy_core::ids::{DeviceId, ID_LEN};

use super::HISTORY_LIMIT;
use super::state::{Bytes, HeldOp, Live, PurgeRec, Regs, Shape, State, Tomb, Val};
use crate::dot::Dot;
use crate::hlc::Hlc;
use crate::record::Lifecycle;
use crate::vv::VersionVector;

/// What the merge needs of one verified op header: its HLC and causal context (ADR 0012 §3).
/// Kept per dot as local evidence (ADR 0018 §3 "Each dot's verified header ... are local
/// state, not frozen"); the server-visible header is metadata, so `Debug` prints it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HeaderFacts {
    /// The op's HLC.
    pub(crate) hlc: Hlc,
    /// The op's causal context.
    pub(crate) context: VersionVector,
}

/// The local evidence a join reads: the verified op headers of the item, and the item keys of
/// its wrap set.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Evidence<'a> {
    /// The verified header of each dot the replica holds one for.
    pub(crate) headers: &'a BTreeMap<Dot, HeaderFacts>,
    /// The `key_id` of every item key in the item's wrap set (CRYPTO.md §11.6 reader rule),
    /// as bytes.
    pub(crate) wrap_keys: &'a BTreeSet<[u8; ID_LEN]>,
}

impl Evidence<'_> {
    /// The verified header context of `dot`, if the replica holds its header.
    pub(crate) fn context(&self, dot: Dot) -> Option<&VersionVector> {
        self.headers.get(&dot).map(|h| &h.context)
    }

    /// The verified header HLC of `dot`, if the replica holds its header.
    pub(crate) fn hlc(&self, dot: Dot) -> Option<Hlc> {
        self.headers.get(&dot).map(|h| h.hlc)
    }
}

/// Which of a set of values supersede a given value, in one pass over their verified header
/// contexts: per device, the highest context entry among the set and the dot it came from, and
/// the highest entry among the other dots.
///
/// `u` supersedes `v` when `u.dot != v.dot` and `u`'s context covers `v.dot`, that is
/// `context(u)[v.device_id] >= v.seq` (ADR 0012 §2). Some `u` of the set other than `v.dot`
/// does so exactly when the highest entry for `v.device_id` among the dots other than `v.dot`
/// reaches `v.seq`: the highest entry overall, unless it came from `v.dot` itself, and then the
/// second highest, which comes from another dot. A value without a verified header supersedes
/// nothing.
pub(crate) struct Supersession {
    /// Per device: the highest context entry, the dot whose context holds it, and the highest
    /// entry among the other dots (0 if none).
    top: BTreeMap<DeviceId, (u64, Dot, u64)>,
}

impl Supersession {
    /// The index of `values`; values sharing a dot count once.
    pub(crate) fn new<'v>(values: impl IntoIterator<Item = &'v Val>, ev: Evidence<'_>) -> Self {
        let dots: BTreeSet<Dot> = values.into_iter().map(|v| v.dot).collect();
        let mut top: BTreeMap<DeviceId, (u64, Dot, u64)> = BTreeMap::new();
        for u in dots {
            let Some(context) = ev.context(u) else {
                continue;
            };
            for entry in context.entries() {
                let seq = entry.seq();
                match top.entry(entry.device_id()) {
                    std::collections::btree_map::Entry::Vacant(slot) => {
                        slot.insert((seq, u, 0));
                    }
                    std::collections::btree_map::Entry::Occupied(mut slot) => {
                        let (best, best_dot, second) = *slot.get();
                        // Dots are distinct, so `best_dot != u`: the old best becomes the
                        // highest entry among the other dots when `u` takes its place.
                        *slot.get_mut() = if seq > best {
                            (seq, u, best)
                        } else {
                            (best, best_dot, second.max(seq))
                        };
                    }
                }
            }
        }
        Self { top }
    }

    /// Whether some value of the set, at another dot than `v`'s, supersedes `v`.
    pub(crate) fn covers(&self, v: &Val) -> bool {
        self.top
            .get(&v.dot.device_id())
            .is_some_and(|&(best, best_dot, second)| {
                let bound = if best_dot == v.dot { second } else { best };
                bound >= v.dot.seq()
            })
    }
}

/// Whether `candidate` is preferred over `held`, two versions of one dot: the version whose
/// HLC is the verified header's first, then the lower `(hlc, value)` (ADR 0018 §3 "Snapshots
/// are claims"). Values are ordered bytewise; only a dishonest record carries one dot in two
/// versions, so only then does this compare value bytes.
fn preferred(candidate: &Val, held: &Val, ev: Evidence<'_>) -> bool {
    let header = ev.hlc(candidate.dot);
    let key = |v: &Val| (Some(v.hlc) != header, v.hlc);
    match key(candidate).cmp(&key(held)) {
        core::cmp::Ordering::Less => true,
        core::cmp::Ordering::Greater => false,
        core::cmp::Ordering::Equal => candidate.value.expose() < held.value.expose(),
    }
}

/// Splits the values of one key into its current values and the rest: one version per dot
/// ([`preferred`]), then current = the values no other value supersedes ([`Supersession`]).
/// Both come back strictly ascending by dot.
///
/// If every value is superseded, which only a cycle of verified contexts can cause (a device
/// that signs a context covering its own later op), the key has no current value; ADR 0018 §3
/// defines the current values that way, and the item then gets no snapshot (§4 rule 7 refuses
/// a history group without a register), keeping its ops.
pub(crate) fn maximal(
    candidates: impl IntoIterator<Item = Val>,
    ev: Evidence<'_>,
) -> (Vec<Val>, Vec<Val>) {
    let mut by_dot: BTreeMap<Dot, Val> = BTreeMap::new();
    for v in candidates {
        match by_dot.entry(v.dot) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(v);
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                if preferred(&v, slot.get(), ev) {
                    slot.insert(v);
                }
            }
        }
    }
    let index = Supersession::new(by_dot.values(), ev);
    let (mut current, mut rest) = (Vec::new(), Vec::new());
    for v in by_dot.into_values() {
        if index.covers(&v) {
            rest.push(v);
        } else {
            current.push(v);
        }
    }
    (current, rest)
}

/// Keeps the newest [`HISTORY_LIMIT`] entries by `(hlc, device_id, seq)` (ADR 0012 §5), then
/// restores the canonical dot order. The top N of a set is the same whatever order the set
/// arrived in.
pub(crate) fn prune(history: &mut Vec<Val>) {
    if history.len() > HISTORY_LIMIT {
        history.sort_by_key(|v| core::cmp::Reverse(v.rank()));
        history.truncate(HISTORY_LIMIT);
    }
    history.sort_by_key(|v| v.dot);
}

/// The values of `key` in each of `regs`, cloned (the bytes are shared, not copied).
fn values_of<'a>(key: &'a Bytes, regs: &'a [&'a Regs]) -> impl Iterator<Item = Val> + 'a {
    regs.iter()
        .filter_map(move |r| r.get(key))
        .flat_map(|vs| vs.iter().cloned())
}

/// Recomputes `key` of live item `out` from `values`: the current values in the register, the
/// rest, pruned, as history; an empty register or group is removed.
fn set_live_key(
    out: &mut Live,
    key: &Bytes,
    values: impl IntoIterator<Item = Val>,
    ev: Evidence<'_>,
) {
    let (current, mut history) = maximal(values, ev);
    prune(&mut history);
    if current.is_empty() {
        out.regs.remove(key);
    } else {
        out.regs.insert(key.clone(), current);
    }
    if history.is_empty() {
        out.hist.remove(key);
    } else {
        out.hist.insert(key.clone(), history);
    }
}

/// Joins live item `y` into live item `x`, both in normal form: each key `y` holds is
/// recomputed from both sides' values of it; every other key of `x` is kept.
fn join_live_into(x: &mut Live, y: &Live, ev: Evidence<'_>) {
    let keys: BTreeSet<&Bytes> = y.regs.keys().chain(y.hist.keys()).collect();
    for key in keys {
        let values: Vec<Val> = {
            let sources = [&x.regs, &x.hist, &y.regs, &y.hist];
            values_of(key, &sources).collect()
        };
        set_live_key(x, key, values, ev);
    }
}

/// The order that picks the recorded purge: `(hlc, device_id, seq)` (ADR 0018 §3 "Recorded
/// purge"), then, for one purge dot carried with two `item_key_id`s, the one in the wrap set
/// first, then the higher `key_id` bytes, so that the choice is a total order.
///
/// The wrap-set part reads the wrap set at the time of the join, so it is not a function of
/// the set of records alone: see "Why the order of arrival does not matter" in the module
/// docs. Only a dishonest record reaches it, and that case is always reported.
fn purge_order(p: &PurgeRec, ev: Evidence<'_>) -> ((Hlc, Dot), bool, [u8; ID_LEN]) {
    let key = *p.key_id.as_bytes();
    (p.rank(), ev.wrap_keys.contains(&key), key)
}

/// Recomputes the late values of `key` in tombstone `t` from `values`: their current values
/// that `t.c` does not cover. `@lifecycle` holds no late value.
fn set_late_key(
    t: &mut Tomb,
    key: &Bytes,
    values: impl IntoIterator<Item = Val>,
    ev: Evidence<'_>,
) {
    if key.is_lifecycle_key() {
        return;
    }
    let (mut current, _) = maximal(values, ev);
    current.retain(|v| !t.c.covers(v.dot));
    if current.is_empty() {
        t.late.remove(key);
    } else {
        t.late.insert(key.clone(), current);
    }
}

/// Joins `other`, live or a tombstone, into tombstone `t`, both in normal form: the recorded
/// purge is the higher, `c` the join, and the late registers the current values of every held
/// value, other than `@lifecycle`'s, that `c` does not cover. Only the keys `other` holds are
/// recomputed; the late values of the others are the current values of their own key already,
/// and are only filtered by the new `c`.
fn join_tomb_into(t: &mut Tomb, other: &Shape, ev: Evidence<'_>) {
    let sources: Vec<&Regs> = match other {
        Shape::Live(l) => vec![&l.regs, &l.hist],
        Shape::Tomb(u) => {
            if purge_order(&u.purge, ev) > purge_order(&t.purge, ev) {
                t.purge = u.purge;
            }
            t.c.join(&u.c);
            vec![&u.late]
        }
    };
    let keys: BTreeSet<&Bytes> = sources.iter().flat_map(|r| r.keys()).collect();
    for key in keys {
        let values: Vec<Val> = t
            .late
            .get(key)
            .into_iter()
            .flatten()
            .cloned()
            .chain(values_of(key, &sources))
            .collect();
        set_late_key(t, key, values, ev);
    }
    // A grown `c` also filters the late values of the keys `other` does not hold. They are
    // filtered only now, so that a recomputed key saw every value of both sides, as the
    // symmetric definition does.
    let c = &t.c;
    for values in t.late.values_mut() {
        values.retain(|v| !c.covers(v.dot));
    }
    t.late.retain(|_, values| !values.is_empty());
}

/// Joins `b` into `a` in place (the evidence join; see the module docs). Both must be in normal
/// form, and the result is. The covered VV becomes the entrywise maximum.
pub(crate) fn join_into(a: &mut State, b: &State, ev: Evidence<'_>) {
    a.vv.join(&b.vv);
    match (&mut a.shape, &b.shape) {
        (Shape::Live(mine), Shape::Live(theirs)) => join_live_into(mine, theirs, ev),
        (Shape::Tomb(tomb), other) => join_tomb_into(tomb, other, ev),
        (Shape::Live(mine), Shape::Tomb(theirs)) => {
            // A purge never resurrects: the result is `theirs`, with every value of `mine`
            // joined in.
            let live = Shape::Live(core::mem::take(mine));
            let mut tomb = theirs.clone();
            join_tomb_into(&mut tomb, &live, ev);
            a.shape = Shape::Tomb(tomb);
        }
    }
}

/// `s` in normal form: every key recomputed from its own values, as [`join_into`] requires of
/// its inputs. A state this module built is already in normal form, and normalizing it changes
/// nothing; a snapshot need not be.
pub(crate) fn normalize(s: &State, ev: Evidence<'_>) -> State {
    let shape = match &s.shape {
        Shape::Live(l) => {
            let mut out = Live::default();
            let keys: BTreeSet<&Bytes> = l.regs.keys().chain(l.hist.keys()).collect();
            for key in keys {
                let sources = [&l.regs, &l.hist];
                let values: Vec<Val> = values_of(key, &sources).collect();
                set_live_key(&mut out, key, values, ev);
            }
            Shape::Live(out)
        }
        Shape::Tomb(t) => {
            let mut out = Tomb {
                purge: t.purge,
                c: t.c.clone(),
                late: Regs::new(),
            };
            for (key, values) in &t.late {
                set_late_key(&mut out, key, values.iter().cloned(), ev);
            }
            Shape::Tomb(out)
        }
    };
    State {
        vv: s.vv.clone(),
        shape,
    }
}

/// An op as a one-op state: its dot as the covered VV; a Purge as a tombstone recording it,
/// with its context as `c` and no late value; any other op as a live item holding its writes
/// and its marker as `@lifecycle`, each tagged with the op's dot and HLC.
pub(crate) fn singleton(op: &HeldOp) -> State {
    let mut vv = VersionVector::new();
    vv.add(op.dot);
    let shape = match op.lifecycle {
        Lifecycle::Purge => Shape::Tomb(Tomb {
            purge: PurgeRec {
                dot: op.dot,
                hlc: op.hlc,
                key_id: op.key_id,
            },
            c: op.context.clone(),
            late: Regs::new(),
        }),
        Lifecycle::Active | Lifecycle::Trashed => Shape::Live(Live {
            regs: op
                .writes_with_lifecycle()
                .into_iter()
                .map(|(key, value)| {
                    (
                        key,
                        vec![Val {
                            dot: op.dot,
                            hlc: op.hlc,
                            value,
                        }],
                    )
                })
                .collect(),
            hist: Regs::new(),
        }),
    };
    State { vv, shape }
}
