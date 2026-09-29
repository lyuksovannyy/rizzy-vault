//! "Snapshots are claims" (ADR 0018 §3, owner decision 14): what a replica takes from a
//! verified snapshot, when it refuses one, and what it reports.
//!
//! A snapshot is its author's signed claim, never a substitute for the op bodies it covers.
//! Before the evidence join ([`super::join()`]) takes anything from it:
//!
//! 1. **The cut** ([`cut`]). The covered VV is cut to the op headers the replica has verified:
//!    its entrywise minimum with the replica's verified heads ([`heads`]). Values above the cut,
//!    or whose HLC is not their verified header's, are not taken. The cut is reported
//!    ([`ClaimCut`]). A tombstone whose recorded purge is above the cut, or whose `purge_hlc`
//!    is not the purge header's, rests on a purge the replica cannot vouch for, and is refused.
//!    `c` is cut to the cut VV, and a late value at the snapshot's own purge dot (a Purge
//!    writes nothing) is not taken. This is the merge spike's `restrict` (`item.rs`).
//! 2. **Contradictions** ([`contradiction`]). A snapshot that contradicts an op body the replica
//!    knows is refused: a value that the body at its dot did not write, a value at a Purge's
//!    dot, a tombstone that records a write as its purge or a known purge under another
//!    `item_key_id`, or a `c` that is not the join of the contexts of purges it covers. The
//!    bodies are every body the replica merged or received with a snapshot, kept for the life
//!    of the item, as the merge spike keeps `body_writes`, `writes_seen` and `purges_seen`
//!    (`replica.rs` `learn_body`): a body leaves the retained ops once a snapshot covers it,
//!    but what it wrote stays evidence, so a later snapshot cannot replace it silently.
//! 3. **Disagreements** ([`disagreements`]). What neither side can be shown wrong about is
//!    reported, never decided: a value one side holds that the other covers but does not
//!    account for (held, superseded by a held value's verified context, pruned below
//!    [`super::HISTORY_LIMIT`] held entries, or discarded by a purge), one dot carried in two
//!    versions (another HLC or other bytes), a `c` that discards a value no purge the other
//!    side lacks can explain, a live state that covers a purge, and one purge dot recorded two
//!    ways. The replica writes no snapshot of the item while one is unresolved.
//!
//! Every check here reads only the item's verified headers and the known bodies: never the
//! order in which records arrived. On honest records none refuses and none reports, and the
//! join equals the op-by-op merge (the merge spike's `absorb`, `snapshots` and `compaction`
//! families). Each check reads every value of both sides once, through per-key indexes, so its
//! cost is linear in the values and headers, not quadratic.

use std::collections::{BTreeMap, BTreeSet};

use rizzy_core::ids::DeviceId;

use super::HISTORY_LIMIT;
use super::join::{Evidence, Supersession};
use super::state::{BodyKind, Bytes, HeldOp, Regs, Shape, State, Val};
use super::{ClaimCut, Refusal};
use crate::dot::Dot;
use crate::hlc::Hlc;
use crate::vv::{VersionVector, VvOrdering};

/// Per device, the highest `seq` among the item's verified op headers: the "op headers it has
/// verified" a snapshot's covered VV is cut to.
///
/// The heads are the item's own: the merge spike models one item, where they are the verified
/// chain heads; with many items a covered-VV entry above the device's last verified op *on this
/// item* claims an op of the item that the replica cannot vouch for, and is cut the same way.
pub(crate) fn heads(ev: Evidence<'_>) -> VersionVector {
    ev.headers.keys().copied().collect()
}

/// The entries of `covered` above `heads`, as reports.
pub(crate) fn claim_cuts(
    covered: &VersionVector,
    heads: &VersionVector,
    author: DeviceId,
) -> Vec<ClaimCut> {
    covered
        .entries()
        .filter(|claim| !heads.covers(*claim))
        .map(|claim| ClaimCut {
            device_id: claim.device_id(),
            verified_to: heads.get(claim.device_id()),
            claimed_to: claim.seq(),
            author,
        })
        .collect()
}

/// What the cut leaves of a snapshot.
#[derive(Debug)]
pub(crate) struct Cut {
    /// The part of the snapshot the replica may take.
    pub(crate) state: State,
    /// The dots of values not taken because their HLC is not their verified header's, or no
    /// header of the item vouches for them, although the cut VV covers them.
    pub(crate) ignored: Vec<Dot>,
}

/// Cuts snapshot state `s` to the verified headers (point 1 of the module docs).
///
/// # Errors
/// [`Refusal::PurgeAboveCut`] for a tombstone whose recorded purge is above the cut or does
/// not carry its header's HLC.
pub(crate) fn cut(s: &State, heads: &VersionVector, ev: Evidence<'_>) -> Result<Cut, Refusal> {
    let mut vv = s.vv.clone();
    vv.meet(heads);
    let mut ignored = Vec::new();
    let mut take = |regs: &super::state::Regs| {
        let mut out = super::state::Regs::new();
        for (key, values) in regs {
            let kept: Vec<Val> = values
                .iter()
                .filter(|v| {
                    if !vv.covers(v.dot) {
                        return false;
                    }
                    let vouched = ev.hlc(v.dot) == Some(v.hlc);
                    if !vouched {
                        ignored.push(v.dot);
                    }
                    vouched
                })
                .cloned()
                .collect();
            if !kept.is_empty() {
                out.insert(key.clone(), kept);
            }
        }
        out
    };
    let shape = match &s.shape {
        Shape::Live(l) => Shape::Live(super::state::Live {
            regs: take(&l.regs),
            hist: take(&l.hist),
        }),
        Shape::Tomb(t) => {
            if !vv.covers(t.purge.dot) || ev.hlc(t.purge.dot) != Some(t.purge.hlc) {
                return Err(Refusal::PurgeAboveCut);
            }
            let mut c = t.c.clone();
            c.meet(&vv);
            let mut late = take(&t.late);
            for values in late.values_mut() {
                values.retain(|v| !c.covers(v.dot) && v.dot != t.purge.dot);
            }
            late.retain(|_, values| !values.is_empty());
            Shape::Tomb(super::state::Tomb {
                purge: t.purge,
                c,
                late,
            })
        }
    };
    ignored.sort_unstable();
    ignored.dedup();
    Ok(Cut {
        state: State { vv, shape },
        ignored,
    })
}

/// Whether the held op `op` wrote `value` to `key`: its marker for `@lifecycle`, a write for
/// any other key. Values are compared without an early exit ([`Bytes::ct_eq`]).
fn wrote(op: &HeldOp, key: &Bytes, value: &Bytes) -> bool {
    if key.is_lifecycle_key() {
        return op
            .lifecycle
            .register_value()
            .is_some_and(|marker| value.ct_eq(marker.expose_secret()));
    }
    op.writes
        .iter()
        .any(|(k, v)| k == key && v.ct_eq(value.expose()))
}

/// Whether the replica knows the body at `dot` to be a write.
fn known_write(bodies: &BTreeMap<Dot, HeldOp>, dot: Dot) -> bool {
    bodies.get(&dot).map(HeldOp::kind) == Some(BodyKind::Write)
}

/// The first contradiction between the cut snapshot `taken` and the op bodies the replica
/// knows (point 2 of the module docs), or `None`.
///
/// `bodies` are the op bodies the replica merged or received, the ones of this Fetch response
/// included, kept for the life of the item: a value at a dot whose body is a Purge, or that
/// the body at its dot did not write, contradicts it.
pub(crate) fn contradiction(
    taken: &State,
    bodies: &BTreeMap<Dot, HeldOp>,
    ev: Evidence<'_>,
) -> Option<Refusal> {
    for (key, v) in taken.values() {
        if let Some(op) = bodies.get(&v.dot) {
            if matches!(op.kind(), BodyKind::Purge(_)) {
                return Some(Refusal::ValueAtPurgeDot { dot: v.dot });
            }
            if !wrote(op, key, &v.value) {
                return Some(Refusal::ValueNotInBody { dot: v.dot });
            }
        }
    }
    if let Shape::Tomb(t) = &taken.shape {
        match bodies.get(&t.purge.dot).map(HeldOp::kind) {
            Some(BodyKind::Write) => {
                return Some(Refusal::WriteRecordedAsPurge { dot: t.purge.dot });
            }
            Some(BodyKind::Purge(key_id)) if key_id != t.purge.key_id => {
                return Some(Refusal::PurgeKeyContradicts { dot: t.purge.dot });
            }
            Some(BodyKind::Purge(_)) | None => {}
        }
        // c is the join of the contexts of the purges the author applied (ADR 0018 §3
        // "Context"): each entry must be reached by the context of an op the snapshot
        // covers that is not known to be a write.
        let mut bound = VersionVector::new();
        for (dot, header) in ev.headers {
            if taken.vv.covers(*dot) && !known_write(bodies, *dot) {
                bound.join(&header.context);
            }
        }
        if !matches!(t.c.compare(&bound), VvOrdering::Less | VvOrdering::Equal) {
            return Some(Refusal::ContextNotFromPurges);
        }
    }
    None
}

/// What a state holds of one key, indexed so that the disagreement checks read each value
/// once rather than scanning the key's values for every value of the other side.
struct KeyIndex<'a> {
    /// Every version the state holds of a value of the key, by dot: current values and history
    /// entries of a live item, late values of a tombstone. A cut snapshot can hold one dot in
    /// both the register and the history group of a key.
    held: BTreeMap<Dot, Vec<&'a Val>>,
    /// Supersession among the key's current (or late) values.
    current: Supersession,
    /// For a live history group of at least [`HISTORY_LIMIT`] entries, its lowest
    /// `(hlc, device_id, seq)`: an entry ranked below it may have been pruned.
    pruned_below: Option<(Hlc, Dot)>,
}

/// The [`KeyIndex`] of every key of `s`.
fn index<'a>(s: &'a State, ev: Evidence<'_>) -> BTreeMap<&'a Bytes, KeyIndex<'a>> {
    let (current, history): (&Regs, Option<&Regs>) = match &s.shape {
        Shape::Live(l) => (&l.regs, Some(&l.hist)),
        Shape::Tomb(t) => (&t.late, None),
    };
    let mut out: BTreeMap<&Bytes, KeyIndex<'a>> = BTreeMap::new();
    let keys: BTreeSet<&Bytes> = current
        .keys()
        .chain(history.into_iter().flat_map(|h| h.keys()))
        .collect();
    for key in keys {
        let cur = current.get(key).map_or(&[][..], Vec::as_slice);
        let hist = history
            .and_then(|h| h.get(key))
            .map_or(&[][..], Vec::as_slice);
        let mut held: BTreeMap<Dot, Vec<&Val>> = BTreeMap::new();
        for v in cur.iter().chain(hist) {
            held.entry(v.dot).or_default().push(v);
        }
        out.insert(
            key,
            KeyIndex {
                held,
                current: Supersession::new(cur, ev),
                pruned_below: (hist.len() >= HISTORY_LIMIT)
                    .then(|| hist.iter().map(Val::rank).min())
                    .flatten(),
            },
        );
    }
    out
}

/// Whether state `s`, indexed as `idx`, accounts for value `v` of `key`, whose dot `s` covers:
/// honest states always do. `v` is held, superseded by a held current value, pruned below
/// [`HISTORY_LIMIT`] held history entries that all rank above it, or, in a tombstone, discarded
/// by a purge (`c` covers it, it is the purge's own dot, or it is a `@lifecycle` value). Used
/// only to report.
fn accounts_for(s: &State, idx: &BTreeMap<&Bytes, KeyIndex<'_>>, key: &Bytes, v: &Val) -> bool {
    let entry = idx.get(key);
    let held = entry.is_some_and(|e| e.held.contains_key(&v.dot) || e.current.covers(v));
    match &s.shape {
        Shape::Live(_) => {
            held || entry
                .and_then(|e| e.pruned_below)
                .is_some_and(|floor| floor > v.rank())
        }
        Shape::Tomb(t) => {
            held || key.is_lifecycle_key() || t.c.covers(v.dot) || v.dot == t.purge.dot
        }
    }
}

/// Whether the state indexed as `idx` holds a version of value `v` of `key` at `v`'s dot that
/// differs from `v` in HLC or bytes: one dot in two versions, which only a dishonest record
/// carries.
fn other_version(idx: &BTreeMap<&Bytes, KeyIndex<'_>>, key: &Bytes, v: &Val) -> bool {
    idx.get(key)
        .and_then(|e| e.held.get(&v.dot))
        .is_some_and(|versions| {
            versions
                .iter()
                .any(|u| u.hlc != v.hlc || !u.value.ct_eq(v.value.expose()))
        })
}

/// `c` of a tombstone, the empty VV for a live item.
fn purge_context(s: &State) -> VersionVector {
    match &s.shape {
        Shape::Tomb(t) => t.c.clone(),
        Shape::Live(_) => VersionVector::new(),
    }
}

/// The dots on which the replica's state `local` and the cut snapshot `taken` disagree in a
/// way neither can be shown wrong about (point 3 of the module docs), ascending, each once.
///
/// `bodies` are the op bodies the replica knows, as for [`contradiction`]; only whether each is
/// a write is read here.
pub(crate) fn disagreements(
    local: &State,
    taken: &State,
    bodies: &BTreeMap<Dot, HeldOp>,
    ev: Evidence<'_>,
) -> Vec<Dot> {
    let mut out = Vec::new();
    let (local_idx, taken_idx) = (index(local, ev), index(taken, ev));
    for ((x, _), (y, y_idx)) in [
        ((local, &local_idx), (taken, &taken_idx)),
        ((taken, &taken_idx), (local, &local_idx)),
    ] {
        for (key, v) in x.values() {
            // A value of x that y covers but does not account for: one side omits or
            // fabricates it.
            if y.vv.covers(v.dot) && !accounts_for(y, y_idx, key, v) {
                out.push(v.dot);
            }
            // One dot carried in two versions: the join keeps one by a fixed rule, and the
            // disagreement is reported rather than decided silently.
            if other_version(y_idx, key, v) {
                out.push(v.dot);
            }
        }
        // A c in x that discards a value y keeps must come from a purge y has not applied: an
        // op header x covers and y does not, not known to be a write, whose context covers the
        // value. Such a header exists exactly when the join of their contexts covers the value.
        // Otherwise one of the two lies about c.
        let (cx, cy) = (purge_context(x), purge_context(y));
        let mut explain = VersionVector::new();
        for (dot, header) in ev.headers {
            if x.vv.covers(*dot) && !y.vv.covers(*dot) && !known_write(bodies, *dot) {
                explain.join(&header.context);
            }
        }
        for (key, v) in y.values() {
            if key.is_lifecycle_key() || !cx.covers(v.dot) || cy.covers(v.dot) {
                continue;
            }
            if !explain.covers(v.dot) {
                out.push(v.dot);
            }
        }
    }
    match (&local.shape, &taken.shape) {
        (Shape::Live(l), Shape::Tomb(t)) if local.vv.covers(t.purge.dot) && !l.regs.is_empty() => {
            out.push(t.purge.dot);
        }
        (Shape::Tomb(t), Shape::Live(l)) if taken.vv.covers(t.purge.dot) && !l.regs.is_empty() => {
            out.push(t.purge.dot);
        }
        (Shape::Tomb(a), Shape::Tomb(b)) if a.purge.dot == b.purge.dot && a.purge != b.purge => {
            out.push(a.purge.dot);
        }
        _ => {}
    }
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    //! The disagreement checks and the supersession index on hand-built states and headers,
    //! for cases no sequence of honest ops reaches.

    use std::collections::{BTreeMap, BTreeSet};

    use proptest::prelude::*;

    use super::{KeyIndex, Supersession, accounts_for, index};
    use crate::dot::Dot;
    use crate::hlc::Hlc;
    use crate::merge::HISTORY_LIMIT;
    use crate::merge::join::{Evidence, HeaderFacts};
    use crate::merge::state::{Bytes, Live, Shape, State, Val};
    use crate::merge::testkit::dot;
    use crate::vv::VersionVector;

    /// A value at `(device(b), seq)` with HLC `hlc`.
    fn val(b: u8, seq: u64, hlc: u64) -> Val {
        Val {
            dot: dot(b, seq),
            hlc: Hlc::from_u64(hlc),
            value: Bytes::copy_from(&[0x01, b]),
        }
    }

    /// Headers for `values`, every context `context`.
    fn headers(values: &[&Val], context: &VersionVector) -> BTreeMap<Dot, HeaderFacts> {
        values
            .iter()
            .map(|v| {
                (
                    v.dot,
                    HeaderFacts {
                        hlc: v.hlc,
                        context: context.clone(),
                    },
                )
            })
            .collect()
    }

    /// Whether a live state of one key (current `current`, history `history`) accounts for `v`.
    fn live_accounts_for(current: Vec<Val>, history: Vec<Val>, v: &Val) -> bool {
        let key = Bytes::copy_from(b"item.name");
        let mut all: Vec<Val> = current.iter().chain(&history).cloned().collect();
        all.push(v.clone());
        let refs: Vec<&Val> = all.iter().collect();
        let headers = headers(&refs, &VersionVector::new());
        let wrap = BTreeSet::new();
        let ev = Evidence {
            headers: &headers,
            wrap_keys: &wrap,
        };
        let mut live = Live::default();
        live.regs.insert(key.clone(), current);
        if !history.is_empty() {
            live.hist.insert(key.clone(), history);
        }
        let s = State {
            vv: all.iter().map(|v| v.dot).collect(),
            shape: Shape::Live(live),
        };
        let idx: BTreeMap<&Bytes, KeyIndex<'_>> = index(&s, ev);
        accounts_for(&s, &idx, &key, v)
    }

    #[test]
    fn a_value_ranked_below_a_full_history_group_is_accounted_for_as_pruned() {
        // No held value supersedes `v` (every context is empty, which only dishonest contexts
        // give), so only the pruning rule can account for it: a full group of entries that all
        // rank above it.
        let v = val(1, 1, 1);
        let current = vec![val(3, 1, 10_000)];
        let full: Vec<Val> = (1..=HISTORY_LIMIT as u64)
            .map(|s| val(2, s, 100 + s))
            .collect();
        assert!(live_accounts_for(current.clone(), full.clone(), &v));
        // One entry short of the limit: nothing was pruned, so the omission is not explained.
        let short: Vec<Val> = full.iter().skip(1).cloned().collect();
        assert!(!live_accounts_for(current.clone(), short, &v));
        // A full group with an entry ranked below `v`: `v` would have been kept over it.
        let mut low = full;
        if let Some(first) = low.first_mut() {
            *first = val(2, 1, 0);
        }
        assert!(!live_accounts_for(current, low, &v));
    }

    proptest! {
        /// The per-device index decides supersession exactly as the pairwise definition:
        /// some other dot's verified context covers the value's dot (ADR 0012 §2).
        #[test]
        fn the_supersession_index_matches_the_pairwise_definition(
            ops in prop::collection::btree_map(
                (1u8..4, 1u64..6),
                (prop::collection::vec((1u8..4, 0u64..6), 0..4), any::<bool>()),
                1..10,
            ),
        ) {
            let mut headers = BTreeMap::new();
            let mut values = Vec::new();
            for (&(b, seq), (context, has_header)) in &ops {
                let v = val(b, seq, seq);
                if *has_header {
                    let context: VersionVector = context
                        .iter()
                        .filter(|(_, s)| *s > 0)
                        .map(|&(d, s)| dot(d, s))
                        .collect();
                    headers.insert(v.dot, HeaderFacts { hlc: v.hlc, context });
                }
                values.push(v);
            }
            let wrap = BTreeSet::new();
            let ev = Evidence { headers: &headers, wrap_keys: &wrap };
            let index = Supersession::new(&values, ev);
            for v in &values {
                let pairwise = values.iter().any(|u| {
                    u.dot != v.dot && ev.context(u.dot).is_some_and(|c| c.covers(v.dot))
                });
                prop_assert_eq!(index.covers(v), pairwise, "{:?}", v.dot);
            }
            // A value outside the set is covered by any context that covers it.
            let outside = val(1, 9, 9);
            let pairwise = values
                .iter()
                .any(|u| ev.context(u.dot).is_some_and(|c| c.covers(outside.dot)));
            prop_assert_eq!(index.covers(&outside), pairwise);
        }
    }
}
