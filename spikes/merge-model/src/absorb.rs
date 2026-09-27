//! Snapshot absorption strategies (ADR 0018 "Settled by the merge spike" item 1; ADR 0021
//! "Settled by the merge spike" first bullet). The ADRs do not define absorption; this is a
//! pluggable trait so candidate rules can be compared.
//!
//! Shared rules, applied by the caller around every strategy (`Replica::absorb`):
//! - a snapshot whose covered VV is `<=` the local item VV is a no-op.
//!   AMBIGUOUS 2: ADR 0012 §7 "Freshness" / INV-25 ("a response that goes backwards is rejected")
//!   read as "a dominated snapshot changes nothing"; the ADRs never say what absorbing one does.
//! - ADR 0012 §7 "Freshness" / INV-25 (Accepted): an absorption whose resulting item VV is not
//!   `>=` the highest VV the replica accepted is "rejected and reported, never applied". The
//!   state before the absorption stays.

use std::collections::BTreeMap;

use crate::item::{Item, Live, PurgeRec, Regs, Tomb, prune};
use crate::types::{Dot, Entry, Key, LIFECYCLE, Op, VV};

pub struct AbsorbCtx<'a> {
    pub local: &'a Item,
    /// The replica's retained ops: "Clients keep each item's ops since its newest snapshot"
    /// (ADR 0012 §6).
    pub retained: &'a [Op],
    pub snap: &'a Item,
    pub n_hist: usize,
}

pub enum AbsorbOutcome {
    /// Keep the local state; the snapshot's effect is not taken.
    Ignore(&'static str),
    /// Adopt the snapshot state, then re-deliver `replay` through causal delivery.
    Replace { state: Item, replay: Vec<Op> },
    /// A state-based merge; `pruned` counts history entries dropped by pruning in the join.
    Merge { state: Item, pruned: usize },
}

pub trait AbsorbStrategy: Sync {
    fn name(&self) -> &'static str;
    fn absorb(&self, cx: AbsorbCtx<'_>) -> AbsorbOutcome;
}

/// Literal reading 1 ("literal-replace"): ADR 0012 §6 "the replica removes the op and recomputes
/// the item from its retained ops and snapshots" and "Clients keep each item's ops since its
/// newest snapshot, which makes the recomputation possible". So the state is the newest snapshot
/// plus the retained ops it does not cover, replayed.
/// AMBIGUOUS 1: the ADRs define recomputation only for the revocation case; this applies the same
/// "newest snapshot + retained ops" rule to every absorbed snapshot, concurrent or not.
pub struct LiteralReplace;

impl AbsorbStrategy for LiteralReplace {
    fn name(&self) -> &'static str {
        "literal-replace"
    }
    fn absorb(&self, cx: AbsorbCtx<'_>) -> AbsorbOutcome {
        let svv = cx.snap.vv();
        let replay = cx
            .retained
            .iter()
            .filter(|o| !svv.covers(o.dot()))
            .cloned()
            .collect();
        AbsorbOutcome::Replace {
            state: cx.snap.clone(),
            replay,
        }
    }
}

/// Literal reading 2 ("literal-dominate"): a snapshot is taken only when it covers everything the
/// replica has (its covered VV dominates the local VV, so replacing loses nothing); a snapshot
/// with a concurrent covered VV is ignored, since no ADR text says how to combine the two.
/// An ignored snapshot is not held, so the chain check (ADR 0012 §7) does not count the bodiless
/// headers only it covers: they are reported as missing data (INV-27), never skipped.
pub struct LiteralDominate;

impl AbsorbStrategy for LiteralDominate {
    fn name(&self) -> &'static str {
        "literal-dominate"
    }
    fn absorb(&self, cx: AbsorbCtx<'_>) -> AbsorbOutcome {
        if cx.local.vv().leq(cx.snap.vv()) {
            let svv = cx.snap.vv();
            let replay = cx
                .retained
                .iter()
                .filter(|o| !svv.covers(o.dot()))
                .cloned()
                .collect();
            AbsorbOutcome::Replace {
                state: cx.snap.clone(),
                replay,
            }
        } else {
            AbsorbOutcome::Ignore("concurrent snapshot ignored")
        }
    }
}

/// Candidate ("dvv-join"): a state-based join in the dotted-version-vector style. For each key,
/// keep each side's values that the other side's VV does not cover, and the values both hold.
/// A value one side holds and the other side's VV covers but does not hold was superseded (or
/// discarded by a purge) there, so it moves to history. Tombstones join by ADR 0018 §3: recorded
/// purge = max, c = join, late values = joined registers filtered by c. The VV is the join.
pub struct DvvJoin;

impl AbsorbStrategy for DvvJoin {
    fn name(&self) -> &'static str {
        "dvv-join"
    }
    fn absorb(&self, cx: AbsorbCtx<'_>) -> AbsorbOutcome {
        let (state, pruned) = join_items_counted(cx.local, cx.snap, cx.n_hist);
        AbsorbOutcome::Merge { state, pruned }
    }
}

pub static LITERAL_REPLACE: LiteralReplace = LiteralReplace;
pub static LITERAL_DOMINATE: LiteralDominate = LiteralDominate;
pub static DVV_JOIN: DvvJoin = DvvJoin;

/// Multi-value-register join of one key: returns (kept, dropped).
pub fn mvr_join(a: &[Entry], va: &VV, b: &[Entry], vb: &VV) -> (Vec<Entry>, Vec<Entry>) {
    let mut kept: BTreeMap<Dot, Entry> = BTreeMap::new();
    let mut dropped: BTreeMap<Dot, Entry> = BTreeMap::new();
    for e in a {
        let in_b = b.iter().any(|x| x.dot == e.dot);
        if !vb.covers(e.dot) || in_b {
            kept.insert(e.dot, *e);
        } else {
            dropped.insert(e.dot, *e);
        }
    }
    for e in b {
        let in_a = a.iter().any(|x| x.dot == e.dot);
        if !va.covers(e.dot) || in_a {
            // One dot with two versions is only reachable through a faulty snapshot: keep the
            // lower (hlc, val) so the join stays commutative.
            kept.entry(e.dot)
                .and_modify(|x| {
                    if (e.hlc, e.val) < (x.hlc, x.val) {
                        *x = *e;
                    }
                })
                .or_insert(*e);
        } else {
            dropped.entry(e.dot).or_insert(*e);
        }
    }
    (
        kept.into_values().collect(),
        dropped.into_values().collect(),
    )
}

fn keys_of<'a>(a: &'a Regs, b: &'a Regs) -> Vec<Key> {
    let mut ks: Vec<Key> = a.keys().chain(b.keys()).copied().collect();
    ks.sort();
    ks.dedup();
    ks
}

pub fn join_items(a: &Item, b: &Item, n_hist: usize) -> Item {
    join_items_counted(a, b, n_hist).0
}

/// `join_items`, also returning how many history entries the ADR 0012 §5 pruning dropped.
pub fn join_items_counted(a: &Item, b: &Item, n_hist: usize) -> (Item, usize) {
    let mut pruned = 0usize;
    let vv = a.vv().joined(b.vv());
    match (a, b) {
        (Item::Live(x), Item::Live(y)) => {
            let mut regs = Regs::new();
            let mut hist = Regs::new();
            let mut all_keys = keys_of(&x.regs, &y.regs);
            all_keys.extend(keys_of(&x.hist, &y.hist));
            all_keys.sort();
            all_keys.dedup();
            let empty: Vec<Entry> = Vec::new();
            for k in all_keys {
                let ra = x.regs.get(k).unwrap_or(&empty);
                let rb = y.regs.get(k).unwrap_or(&empty);
                let (kept, dropped) = mvr_join(ra, &x.vv, rb, &y.vv);
                let mut h: Vec<Entry> = Vec::new();
                for e in x
                    .hist
                    .get(k)
                    .unwrap_or(&empty)
                    .iter()
                    .chain(y.hist.get(k).unwrap_or(&empty))
                    .chain(dropped.iter())
                {
                    if !kept.iter().any(|z| z.dot == e.dot) && !h.iter().any(|z| z.dot == e.dot) {
                        h.push(*e);
                    }
                }
                let before = h.len();
                prune(&mut h, n_hist);
                pruned += before - h.len();
                if !kept.is_empty() {
                    regs.insert(k, kept);
                }
                if !h.is_empty() {
                    hist.insert(k, h);
                }
            }
            (Item::Live(Live { vv, regs, hist }), pruned)
        }
        _ => {
            // At least one side is a tombstone: the result is a tombstone (a purge never
            // resurrects, ADR 0018 §3 "Applying" 3).
            let parts = |i: &Item| -> (Option<PurgeRec>, VV, Regs) {
                match i {
                    Item::Live(l) => {
                        let mut r = l.regs.clone();
                        r.remove(LIFECYCLE);
                        (None, VV::default(), r)
                    }
                    Item::Tomb(t) => (Some(t.purge.clone()), t.c.clone(), t.late.clone()),
                }
            };
            let (pa, ca, sa) = parts(a);
            let (pb, cb, sb) = parts(b);
            let purge = match (pa, pb) {
                (Some(p), Some(q)) => {
                    if q.rank() > p.rank() {
                        q
                    } else {
                        p
                    }
                }
                (Some(p), None) | (None, Some(p)) => p,
                (None, None) => unreachable!("one side is a tombstone"),
            };
            let c = ca.joined(&cb);
            let mut late = Regs::new();
            let empty: Vec<Entry> = Vec::new();
            for k in keys_of(&sa, &sb) {
                let (mut kept, _) = mvr_join(
                    sa.get(k).unwrap_or(&empty),
                    a.vv(),
                    sb.get(k).unwrap_or(&empty),
                    b.vv(),
                );
                kept.retain(|e| !c.covers(e.dot));
                if !kept.is_empty() {
                    late.insert(k, kept);
                }
            }
            (Item::Tomb(Tomb { vv, purge, c, late }), pruned)
        }
    }
}
