//! The item state, the op merge (ADR 0012 §4-§5 as refined by ADR 0018 §3), the canonical form
//! (ADR 0018 §4) and the snapshot parse checks the merge relies on (ADR 0018 §5).

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::types::{
    ACTIVE, Dot, Entry, Headers, Hlc, Key, KeyId, LIFECYCLE, Marker, Op, Seq, TRASHED, VV,
};

pub type Regs = BTreeMap<Key, Vec<Entry>>;

/// ADR 0018 §3 "Recorded purge": dot, HLC and the `key_id` of its `ITEM_OP` envelope header.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct PurgeRec {
    pub dot: Dot,
    pub hlc: Hlc,
    pub key_id: KeyId,
}

impl PurgeRec {
    /// ADR 0018 §3 "Recorded purge": highest (`hlc`, `device_id`, `seq`).
    pub fn rank(&self) -> (Hlc, u8, Seq) {
        (self.hlc, self.dot.dev, self.dot.seq)
    }

    /// A total order extending `rank` to records that honest merges never produce (one purge dot
    /// with two HLCs or two item_key_ids), so that a join stays commutative on every state ADR 0018
    /// §5 accepts. Candidate rule (evidence merge); honest records never tie on `rank`.
    pub fn total(&self) -> (Hlc, u8, Seq, KeyId) {
        (self.hlc, self.dot.dev, self.dot.seq, self.key_id)
    }
}

/// A live item: ADR 0018 §3 live snapshot data plus the covered VV (the snapshot header's).
#[derive(Clone, PartialEq, Eq, Hash, Debug, Default)]
pub struct Live {
    pub vv: VV,
    /// Current registers, each sorted by dot (ADR 0018 §4 "Order").
    pub regs: Regs,
    /// History groups, each sorted by dot, at most N entries (ADR 0012 §5).
    pub hist: Regs,
}

/// A tombstone: ADR 0018 §3 tombstone data plus the covered VV.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Tomb {
    pub vv: VV,
    pub purge: PurgeRec,
    /// ADR 0018 §3 "Context": join of the causal contexts of all applied Purge ops.
    pub c: VV,
    /// ADR 0018 §3 "Late values": one register per key that has any late value.
    pub late: Regs,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum Item {
    Live(Live),
    Tomb(Tomb),
}

/// What the UI shows for the item.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Shown {
    Absent,
    Active,
    Trashed,
    Purged,
}

impl Default for Item {
    fn default() -> Self {
        Item::Live(Live::default())
    }
}

/// ADR 0012 §5 "Pruning is deterministic": keep the newest N entries per field by
/// `(hlc, device_id, device_seq)`; stored in canonical dot order (ADR 0018 §4).
pub fn prune(h: &mut Vec<Entry>, n: usize) {
    if h.len() > n {
        h.sort_by_key(|e| std::cmp::Reverse(e.rank()));
        h.truncate(n);
    }
    h.sort_by_key(|e| e.dot);
}

impl Item {
    pub fn vv(&self) -> &VV {
        match self {
            Item::Live(l) => &l.vv,
            Item::Tomb(t) => &t.vv,
        }
    }

    pub fn vv_mut(&mut self) -> &mut VV {
        match self {
            Item::Live(l) => &mut l.vv,
            Item::Tomb(t) => &mut t.vv,
        }
    }

    pub fn is_absent(&self) -> bool {
        matches!(self, Item::Live(l) if l.regs.is_empty())
    }

    pub fn is_tomb(&self) -> bool {
        matches!(self, Item::Tomb(_))
    }

    /// ADR 0012 §5 "Trash": when a delete and an edit are concurrent, the lifecycle register holds
    /// both values, and **Active wins** (display only; the register keeps both).
    pub fn shown(&self) -> Shown {
        match self {
            Item::Tomb(_) => Shown::Purged,
            Item::Live(l) => match l.regs.get(LIFECYCLE) {
                None => Shown::Absent,
                Some(es) if es.iter().any(|e| e.val == ACTIVE) => Shown::Active,
                Some(es) if es.iter().any(|e| e.val == TRASHED) => Shown::Trashed,
                Some(_) => Shown::Absent,
            },
        }
    }

    /// Apply one causally ready, verified op. Returns false for a duplicate.
    pub fn apply(&mut self, op: &Op, n_hist: usize) -> bool {
        let dot = op.h.dot;
        // ADR 0012 §4 step 3 "Ignore duplicates": if the item VV already covers the op's dot,
        // the op is a no-op.
        if self.vv().covers(dot) {
            return false;
        }
        match self {
            Item::Live(l) => match op.b.marker {
                Marker::Purge => {
                    // ADR 0018 §3 "Applying" 1: the first Purge applied to a live item keeps the late
                    // values of its current registers and discards everything else (the live
                    // history included, ADR 0018 §3 "History").
                    // ADR 0018 §3 "A Purge is never rejected": applied whatever @lifecycle shows.
                    let c = op.h.ctx.clone();
                    let mut late = Regs::new();
                    for (k, es) in &l.regs {
                        // ADR 0018 §3 "Late values": key is not @lifecycle and c does not cover it.
                        if *k == LIFECYCLE {
                            continue;
                        }
                        let kept: Vec<Entry> =
                            es.iter().filter(|e| !c.covers(e.dot)).copied().collect();
                        if !kept.is_empty() {
                            late.insert(*k, kept);
                        }
                    }
                    let mut vv = l.vv.clone();
                    // ADR 0018 §3 "Applying": every applied non-duplicate op adds its dot.
                    vv.add(dot);
                    *self = Item::Tomb(Tomb {
                        vv,
                        purge: PurgeRec {
                            dot,
                            hlc: op.h.hlc,
                            key_id: op.b.key_id,
                        },
                        c,
                        late,
                    });
                }
                Marker::Active | Marker::Trashed => {
                    // ADR 0012 §4 step 4, for each field written (the marker is a write to
                    // @lifecycle, ADR 0018 §3 "Lifecycle").
                    for (k, v) in op.writes_with_lifecycle() {
                        let reg = l.regs.entry(k).or_default();
                        // 4.1 remove every current value whose dot the op's context covers ...
                        let (removed, mut kept): (Vec<Entry>, Vec<Entry>) =
                            reg.iter().copied().partition(|e| op.h.ctx.covers(e.dot));
                        // 4.2 add the new value, tagged with the op's dot and HLC.
                        kept.push(Entry {
                            dot,
                            hlc: op.h.hlc,
                            val: v,
                        });
                        kept.sort_by_key(|e| e.dot);
                        *reg = kept;
                        // ADR 0012 §5 "History": every value removed from a register goes into
                        // the item's history, with its dot and HLC; pruned to N.
                        if !removed.is_empty() {
                            let h = l.hist.entry(k).or_default();
                            for e in removed {
                                if !h.iter().any(|x| x.dot == e.dot) {
                                    h.push(e);
                                }
                            }
                            prune(h, n_hist);
                        }
                    }
                    // 4.3 update the item VV.
                    l.vv.add(dot);
                }
            },
            Item::Tomb(t) => match op.b.marker {
                Marker::Purge => {
                    // ADR 0018 §3 "Applying" 2: join its context into c, become the recorded purge
                    // if now the highest, remove every late value the new c covers.
                    t.c.join(&op.h.ctx);
                    let rec = PurgeRec {
                        dot,
                        hlc: op.h.hlc,
                        key_id: op.b.key_id,
                    };
                    if rec.rank() > t.purge.rank() {
                        t.purge = rec;
                    }
                    let c = t.c.clone();
                    filter_covered(&mut t.late, &c);
                    t.vv.add(dot);
                }
                Marker::Active | Marker::Trashed => {
                    // ADR 0018 §3 "Applying" 3: never rejected, never resurrects. For each key it
                    // writes, remove the late values its context covers and add its own value.
                    // Its lifecycle byte writes nothing.
                    for (k, v) in &op.b.writes {
                        let reg = t.late.entry(*k).or_default();
                        reg.retain(|e| !op.h.ctx.covers(e.dot));
                        // ADR 0018 §3 "Why the arrival order does not matter": c never covers the
                        // value a new op adds; the filter is kept so the definition holds anyway.
                        if !t.c.covers(dot) {
                            reg.push(Entry {
                                dot,
                                hlc: op.h.hlc,
                                val: *v,
                            });
                            reg.sort_by_key(|e| e.dot);
                        }
                    }
                    t.late.retain(|_, es| !es.is_empty());
                    t.vv.add(dot);
                }
            },
        }
        true
    }

    /// ADR 0018 §10 "Oversize items": the encoding of the merged state breaks a limit. Only the
    /// values-per-register limit is modelled (scaled down to `limit`).
    pub fn oversize(&self, limit: usize) -> bool {
        let over = |r: &Regs| r.values().any(|es| es.len() > limit);
        match self {
            Item::Live(l) => over(&l.regs) || over(&l.hist),
            Item::Tomb(t) => over(&t.late),
        }
    }

    /// Canonical form (ADR 0018 §4): keys ascending bytewise, dots ascending, VV canonical. A
    /// readable string stands in for `SHA-256(u16 item_schema_version ‖ covered VV ‖ data)`: two
    /// states are equal exactly when their canonical strings are equal.
    pub fn canon(&self) -> String {
        let mut s = String::new();
        match self {
            Item::Live(l) if l.regs.is_empty() && l.hist.is_empty() && l.vv.is_empty() => {
                s.push_str("ABSENT");
            }
            Item::Live(l) => {
                let _ = write!(
                    s,
                    "LIVE vv={} regs[{}] hist[{}]",
                    l.vv,
                    regs_str(&l.regs),
                    regs_str(&l.hist)
                );
            }
            Item::Tomb(t) => {
                let _ = write!(
                    s,
                    "TOMB vv={} purge={}@{} c={} item_key_id={} late[{}]",
                    t.vv,
                    t.purge.dot,
                    crate::types::fmt_hlc(t.purge.hlc),
                    t.c,
                    t.purge.key_id,
                    regs_str(&t.late)
                );
            }
        }
        s
    }

    /// ADR 0018 §5 rejection rules that concern the merge model: rule 2 (1 <= r), rule 3 (a dot
    /// at most once per field key across register and history, §4 "Uniqueness"), rule 5 (empty
    /// register; `@lifecycle` first in a live snapshot, absent from a tombstone), rule 6 (coverage
    /// by the covered VV), rule 7 (history key without register), rule 8 (tombstone late value
    /// covered by c). Faulty snapshots in this model are built to pass them, as a "verified but
    /// dishonest" snapshot must.
    pub fn validate_snapshot(&self) -> Result<(), &'static str> {
        match self {
            Item::Live(l) => {
                if l.regs.is_empty() {
                    return Err("rule 2: live snapshot with r = 0");
                }
                for (k, es) in &l.regs {
                    if let Some(h) = l.hist.get(k)
                        && h.iter().any(|x| es.iter().any(|e| e.dot == x.dot))
                    {
                        return Err("rule 3: a dot twice under one key");
                    }
                }
                for (k, es) in l.regs.iter().chain(l.hist.iter()) {
                    if es.is_empty() {
                        return Err("rule 5: register with m = 0");
                    }
                    for e in es {
                        if !l.vv.covers(e.dot) {
                            return Err("rule 6: dot not covered by covered VV");
                        }
                    }
                    let _ = k;
                }
                for k in l.hist.keys() {
                    if !l.regs.contains_key(k) {
                        return Err("rule 7: history group without current register");
                    }
                }
                if !l.regs.is_empty() && !l.regs.contains_key(LIFECYCLE) {
                    return Err("rule 5: live snapshot does not start with @lifecycle");
                }
            }
            Item::Tomb(t) => {
                if !t.vv.covers(t.purge.dot) {
                    return Err("rule 6: purge_dot not covered");
                }
                if !t.c.leq(&t.vv) {
                    return Err("rule 6: entry of c not covered");
                }
                if t.late.contains_key(LIFECYCLE) {
                    return Err("rule 5: @lifecycle in a tombstone");
                }
                for es in t.late.values() {
                    if es.is_empty() {
                        return Err("rule 5: late register with m = 0");
                    }
                    for e in es {
                        if !t.vv.covers(e.dot) {
                            return Err("rule 6: late dot not covered");
                        }
                        if t.c.covers(e.dot) {
                            return Err("rule 8: late value covered by c");
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn filter_covered(regs: &mut Regs, c: &VV) {
    for es in regs.values_mut() {
        es.retain(|e| !c.covers(e.dot));
    }
    regs.retain(|_, es| !es.is_empty());
}

pub fn regs_str(r: &Regs) -> String {
    let parts: Vec<String> = r
        .iter()
        .map(|(k, es)| {
            let vs: Vec<String> = es.iter().map(|e| e.fmt_with(k)).collect();
            format!("{k}:[{}]", vs.join(","))
        })
        .collect();
    parts.join(" ")
}

// ---------------------------------------------------------------------------------------------
// Candidate: the evidence merge (faulty-snapshot question, ADR 0018 "Settled by the merge spike"
// item 4, ADR 0021 "Faulty-client snapshots").
//
// The state is a function of the *set of values* a replica has seen, from op bodies and from the
// part of snapshots it takes, and of the verified op headers (ADR 0012 §3; the chain check of
// ADR 0012 §7 verifies every header a replica receives, bodied or bodiless):
// - a key's current values are the values of that key that no other value of the key supersedes,
//   where u supersedes v when u's verified header context covers v's dot (ADR 0012 §2 "Op A
//   happened before op B if B's context covers A's dot"); every other value is history, pruned to
//   N (ADR 0012 §5);
// - a tombstone's recorded purge is the maximum, c the join, and its late values the current
//   values of the non-lifecycle keys that c does not cover (ADR 0018 §3, unchanged).
// For honest inputs this is exactly ADR 0012 §4 step 4 + §5 and ADR 0018 §3 (a multi-value
// register holds the maximal writes under causality). What changes is that the *absence* of a
// value from a snapshot is never evidence that it was superseded: only a present value whose
// header context covers it is.
// ---------------------------------------------------------------------------------------------

fn ctx_of(hdr: &Headers, d: Dot) -> Option<&VV> {
    hdr.get(&d).map(|h| &h.ctx)
}

/// One dot seen in two versions (only a dishonest record does that): keep the version whose HLC
/// is the verified header's, then the lower (hlc, val), so the choice is a function of the set.
fn pick(a: Entry, b: Entry, hdr: &Headers) -> Entry {
    let h = hdr.get(&a.dot).map(|x| x.hlc);
    let ka = (Some(a.hlc) != h, a.hlc, a.val);
    let kb = (Some(b.hlc) != h, b.hlc, b.val);
    if kb < ka { b } else { a }
}

/// The values of `cands` that no other value of `cands` supersedes, and the rest.
pub fn maximal(cands: &[Entry], hdr: &Headers) -> (Vec<Entry>, Vec<Entry>) {
    let mut by_dot: BTreeMap<Dot, Entry> = BTreeMap::new();
    for e in cands {
        by_dot
            .entry(e.dot)
            .and_modify(|x| *x = pick(*x, *e, hdr))
            .or_insert(*e);
    }
    let all: Vec<Entry> = by_dot.into_values().collect();
    let (mut cur, mut rest) = (Vec::new(), Vec::new());
    for v in &all {
        let dominated = all
            .iter()
            .any(|u| u.dot != v.dot && ctx_of(hdr, u.dot).is_some_and(|c| c.covers(v.dot)));
        if dominated {
            rest.push(*v);
        } else {
            cur.push(*v);
        }
    }
    (cur, rest)
}

/// The evidence join of two states. Commutative, associative and idempotent on every state
/// (honest or not): each part is a union, a join or a maximum under a total order.
/// `keys`: the item key ids in the item's wrap set (CRYPTO.md §11.6 reader rule). Two records of
/// one purge dot with different item_key_ids (only a dishonest record does that) are ordered by
/// "names a key in the wrap set" first; ADR 0018 §3 ranks by (hlc, device_id, seq) otherwise.
pub fn em_join(
    a: &Item,
    b: &Item,
    hdr: &Headers,
    keys: &std::collections::BTreeSet<KeyId>,
    n_hist: usize,
) -> (Item, usize) {
    let mut pruned = 0usize;
    let vv = a.vv().joined(b.vv());
    let empty: Vec<Entry> = Vec::new();
    match (a, b) {
        (Item::Live(x), Item::Live(y)) => {
            let mut keys: Vec<Key> = x
                .regs
                .keys()
                .chain(x.hist.keys())
                .chain(y.regs.keys())
                .chain(y.hist.keys())
                .copied()
                .collect();
            keys.sort();
            keys.dedup();
            let (mut regs, mut hist) = (Regs::new(), Regs::new());
            for k in keys {
                let c: Vec<Entry> = [&x.regs, &x.hist, &y.regs, &y.hist]
                    .iter()
                    .flat_map(|r| r.get(k).unwrap_or(&empty).iter().copied())
                    .collect();
                let (mut cur, mut h) = maximal(&c, hdr);
                cur.sort_by_key(|e| e.dot);
                let before = h.len();
                prune(&mut h, n_hist);
                pruned += before - h.len();
                if !cur.is_empty() {
                    regs.insert(k, cur);
                }
                if !h.is_empty() {
                    hist.insert(k, h);
                }
            }
            (Item::Live(Live { vv, regs, hist }), pruned)
        }
        _ => {
            let parts = |i: &Item| -> (Option<PurgeRec>, VV, Vec<(Key, Entry)>) {
                match i {
                    Item::Live(l) => (
                        None,
                        VV::default(),
                        l.regs
                            .iter()
                            .chain(l.hist.iter())
                            .filter(|(k, _)| **k != LIFECYCLE)
                            .flat_map(|(k, es)| es.iter().map(move |e| (*k, *e)))
                            .collect(),
                    ),
                    Item::Tomb(t) => (
                        Some(t.purge.clone()),
                        t.c.clone(),
                        t.late
                            .iter()
                            .flat_map(|(k, es)| es.iter().map(move |e| (*k, *e)))
                            .collect(),
                    ),
                }
            };
            let (pa, ca, sa) = parts(a);
            let (pb, cb, sb) = parts(b);
            let order = |r: &PurgeRec| (r.rank(), keys.contains(&r.key_id), r.key_id);
            let purge = match (pa, pb) {
                (Some(p), Some(q)) => {
                    if order(&q) > order(&p) {
                        q
                    } else {
                        p
                    }
                }
                (Some(p), None) | (None, Some(p)) => p,
                (None, None) => unreachable!("one side is a tombstone"),
            };
            let c = ca.joined(&cb);
            let mut per_key: BTreeMap<Key, Vec<Entry>> = BTreeMap::new();
            for (k, e) in sa.into_iter().chain(sb) {
                per_key.entry(k).or_default().push(e);
            }
            let mut late = Regs::new();
            for (k, es) in per_key {
                let (mut cur, _) = maximal(&es, hdr);
                // ADR 0018 §3 "Late values": c does not cover it. (A value at a snapshot's own
                // purge dot is dropped in `restrict`, per snapshot: dropping values at whichever
                // purge is recorded *now* would not be associative, since a higher-ranked purge
                // can replace the recorded one later.)
                cur.retain(|e| !c.covers(e.dot));
                cur.sort_by_key(|e| e.dot);
                if !cur.is_empty() {
                    late.insert(k, cur);
                }
            }
            (Item::Tomb(Tomb { vv, purge, c, late }), pruned)
        }
    }
}

/// An op as a one-op state, for the evidence merge (ADR 0012 §4 step 4 and ADR 0018 §3
/// "Applying" 1-3 are then `em_join(state, singleton)`).
pub fn singleton(op: &Op) -> Item {
    let mut vv = VV::default();
    vv.add(op.h.dot);
    match op.b.marker {
        Marker::Purge => Item::Tomb(Tomb {
            vv,
            purge: PurgeRec {
                dot: op.h.dot,
                hlc: op.h.hlc,
                key_id: op.b.key_id,
            },
            c: op.h.ctx.clone(),
            late: Regs::new(),
        }),
        _ => {
            let mut regs = Regs::new();
            for (k, v) in op.writes_with_lifecycle() {
                regs.insert(
                    k,
                    vec![Entry {
                        dot: op.h.dot,
                        hlc: op.h.hlc,
                        val: v,
                    }],
                );
            }
            Item::Live(Live {
                vv,
                regs,
                hist: Regs::new(),
            })
        }
    }
}

/// What a replica takes from a snapshot under the candidate's header clamp: the snapshot cut down
/// to the dots whose op headers the replica has verified (`heads`), without values whose HLC is
/// not their verified header's. `None` when the snapshot's tombstone rests on a purge above the
/// clamp (it claims a purge nobody holds a header for).
/// (Tested and rejected: also taking a revoked device's dots up to its signed
/// last_accepted_device_seq. After a restore such values have no verified header, so no causal
/// context places them, and replicas diverge silently; README, faulty-snapshot results.)
pub fn restrict(s: &Item, heads: &VV, hdr: &Headers) -> Option<Item> {
    let vv = s.vv().meet(heads);
    let keep = |e: &Entry| vv.covers(e.dot) && hdr.get(&e.dot).is_some_and(|h| h.hlc == e.hlc);
    let cut = |r: &Regs| -> Regs {
        let mut o = Regs::new();
        for (k, es) in r {
            let es: Vec<Entry> = es.iter().filter(|e| keep(e)).copied().collect();
            if !es.is_empty() {
                o.insert(*k, es);
            }
        }
        o
    };
    match s {
        Item::Live(l) => {
            let (regs, hist) = (cut(&l.regs), cut(&l.hist));
            Some(Item::Live(Live { vv, regs, hist }))
        }
        Item::Tomb(t) => {
            if !vv.covers(t.purge.dot) || hdr.get(&t.purge.dot).is_none_or(|h| h.hlc != t.purge.hlc)
            {
                return None;
            }
            let c = t.c.meet(&vv);
            let mut late = cut(&t.late);
            let vv = vv.clone();
            for es in late.values_mut() {
                es.retain(|e| !c.covers(e.dot) && e.dot != t.purge.dot);
            }
            late.retain(|_, es| !es.is_empty());
            Some(Item::Tomb(Tomb {
                vv,
                purge: t.purge.clone(),
                c,
                late,
            }))
        }
    }
}

/// Does state `s` account for value `v` (key `k`) whose dot `s` covers? Honest states always do:
/// `v` is held, superseded by a held value (header evidence), pruned below N held entries, or
/// discarded by a purge. Used to *report* disagreements between sources (never to decide).
pub fn accounts_for(s: &Item, k: Key, v: &Entry, hdr: &Headers, n_hist: usize) -> bool {
    let held = |r: &Regs| r.get(k).is_some_and(|es| es.iter().any(|e| e.dot == v.dot));
    let dominated = |r: &Regs| {
        r.get(k).is_some_and(|es| {
            es.iter()
                .any(|u| u.dot != v.dot && ctx_of(hdr, u.dot).is_some_and(|c| c.covers(v.dot)))
        })
    };
    match s {
        Item::Live(l) => {
            held(&l.regs)
                || held(&l.hist)
                || dominated(&l.regs)
                || l.hist
                    .get(k)
                    .is_some_and(|h| h.len() >= n_hist && h.iter().all(|e| e.rank() > v.rank()))
        }
        Item::Tomb(t) => {
            k == LIFECYCLE
                || held(&t.late)
                || dominated(&t.late)
                || t.c.covers(v.dot)
                || v.dot == t.purge.dot
        }
    }
}

/// The highest HLC a snapshot state carries: every current value and history entry of a live
/// state; the recorded purge and every late value of a tombstone (the HLC receipt on absorption).
pub fn max_hlc(it: &Item) -> Option<Hlc> {
    match it {
        Item::Live(l) => l
            .regs
            .values()
            .chain(l.hist.values())
            .flatten()
            .map(|e| e.hlc)
            .max(),
        Item::Tomb(t) => t
            .late
            .values()
            .flatten()
            .map(|e| e.hlc)
            .chain(std::iter::once(t.purge.hlc))
            .max(),
    }
}
