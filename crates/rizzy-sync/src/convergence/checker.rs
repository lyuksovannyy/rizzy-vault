//! An independent brute-force checker of the ADR 0021 §8 server properties, written from
//! ADR 0021 §2–§4 rather than from [`crate::compaction`] (§8: "An independent brute-force
//! checker, written from §2–§4 rather than from that module, checks the server properties").
//!
//! It reads the simulated server's rows as plain data ([`Row`], [`OpRow`]) and never calls
//! the module under test. "Covers" is spelled out as §2 words it: a retained snapshot S covers
//! op o of its item when `o.device_seq ≤ clamped(S)[o.device_id]`, a missing entry being 0.
//! Each rule is transcribed as the ADR words it; R3's "re-tested after each drop" is not
//! needed here, because property 4 is checked on the rows `worker` left.
//!
//! | ADR 0021 §8 server property | Function | When the harness checks it |
//! |---|---|---|
//! | 1. every bodiless header has a retained cover | [`stored`] | after every step |
//! | 2. no snapshot covers an op stored after it | [`stored`] | after every step |
//! | 3. every response carries, for each bodiless header, a snapshot whose clamped and covered VVs both cover it | [`page`] | on every page of every Fetch |
//! | 4. after `worker` runs, R3 keeps every retained snapshot outside the two newest | [`after_worker`] | after every `worker` run |
//! | 5. in a linear history, after `worker` runs, the bodiless headers are those R1 deletes behind the older of the two newest, and the headers a healing request stored without a body | [`after_worker`] | after every `worker` run on an item whose history is linear |
//!
//! [`page`] also checks §4's selection itself, from the retained rows: newest first, a
//! snapshot is added only while it covers a bodiless header of the page that the snapshots
//! added so far cover by no author, or by one author other than its own ([`literal_covers`]).
//! Properties 4 and 5 are checked in their two-author form (R1 and R3 as owner decision 1
//! states them), as the merge spike's `check_two_author_props` and `compaction`'s own
//! simulation check them.

use std::collections::BTreeSet;

use rizzy_core::ids::{DeviceId, ItemId};

use crate::dot::Dot;
use crate::vv::VersionVector;

/// One retained snapshot of an item, as the server stores it.
#[derive(Clone, Debug)]
pub(super) struct Row {
    /// Its store sequence.
    pub(super) store_seq: u64,
    /// Its clamped VV (ADR 0021 §2).
    pub(super) clamped: VersionVector,
    /// Its covered VV, from its signed header.
    pub(super) covered: VersionVector,
    /// Its author.
    pub(super) author: DeviceId,
}

/// One op header of an item, as the server stores it.
#[derive(Clone, Copy, Debug)]
pub(super) struct OpRow {
    /// Its dot.
    pub(super) dot: Dot,
    /// Whether the server holds its body.
    pub(super) held: bool,
    /// The vault's store sequence counter when the op was stored: the op was stored after
    /// every snapshot whose store sequence is at most this.
    pub(super) stored_at: u64,
    /// Whether a healing request stored it without its body, and no body came since.
    pub(super) healed: bool,
}

/// ADR 0021 §2 "Covers", spelled out: `dot.seq ≤ v[dot.device_id]`, a missing entry being 0.
fn covers(v: &VersionVector, dot: Dot) -> bool {
    dot.seq() <= v.get(dot.device_id())
}

/// The number of distinct authors among `rows` whose clamped VV covers `dot`.
fn authors_covering<'a>(rows: impl Iterator<Item = &'a Row>, dot: Dot) -> usize {
    rows.filter(|r| covers(&r.clamped, dot))
        .map(|r| r.author)
        .collect::<BTreeSet<DeviceId>>()
        .len()
}

/// ADR 0021 §4 "Covers", transcribed: "the server takes that item's retained snapshots newest
/// first. It adds each one that covers a bodiless header of the item in the response that the
/// snapshots added so far cover by no author, or by one author other than its own." Returns
/// the store sequences of the snapshots added, in order.
pub(super) fn literal_covers(rows: &[Row], bodiless: &[Dot]) -> Vec<u64> {
    let mut newest_first: Vec<&Row> = rows.iter().collect();
    newest_first.sort_by_key(|r| core::cmp::Reverse(r.store_seq));
    let mut added: Vec<&Row> = Vec::new();
    for row in newest_first {
        let adds = bodiless.iter().any(|&header| {
            let authors: BTreeSet<DeviceId> = added
                .iter()
                .filter(|s| covers(&s.clamped, header))
                .map(|s| s.author)
                .collect();
            covers(&row.clamped, header)
                && (authors.is_empty() || (authors.len() == 1 && !authors.contains(&row.author)))
        });
        if adds {
            added.push(row);
        }
    }
    added.iter().map(|r| r.store_seq).collect()
}

/// Properties 1 and 2 on one item's rows, after any step. Returns one line per violation,
/// naming the item and dot (server-visible metadata).
pub(super) fn stored(item: ItemId, rows: &[Row], ops: &[OpRow]) -> Vec<String> {
    let mut out = Vec::new();
    for op in ops {
        // 1. Every bodiless header has a retained cover.
        if !op.held && !rows.iter().any(|r| covers(&r.clamped, op.dot)) {
            out.push(format!(
                "ADR 0021 §8 property 1: {item:?}: bodiless header {:?} without a retained cover",
                op.dot
            ));
        }
        // 2. No snapshot covers an op stored after it.
        for r in rows {
            if op.stored_at >= r.store_seq && covers(&r.clamped, op.dot) {
                out.push(format!(
                    "ADR 0021 §8 property 2: {item:?}: snapshot {} covers {:?}, stored after it",
                    r.store_seq, op.dot
                ));
            }
        }
    }
    out
}

/// Property 3 and the §4 selection on one page of a response, for one item: `bodiless` are the
/// page's bodiless headers of the item, `served` the store sequences of the item's snapshots
/// the page carries, in served order, and `rows` the item's retained snapshots when the page
/// was built.
pub(super) fn page(item: ItemId, rows: &[Row], bodiless: &[Dot], served: &[u64]) -> Vec<String> {
    let mut out = Vec::new();
    let served_rows: Vec<&Row> = served
        .iter()
        .filter_map(|seq| rows.iter().find(|r| r.store_seq == *seq))
        .collect();
    if served_rows.len() != served.len() {
        out.push(format!(
            "ADR 0021 §4: {item:?}: a served cover is not a retained snapshot"
        ));
    }
    for &dot in bodiless {
        // 3. A snapshot whose clamped and covered VVs both cover it.
        if !served_rows
            .iter()
            .any(|r| covers(&r.clamped, dot) && covers(&r.covered, dot))
        {
            out.push(format!(
                "ADR 0021 §8 property 3: {item:?}: bodiless header {dot:?} served without a cover"
            ));
        }
        // §4: covers by two authors when the retained snapshots have them, else one.
        let available = authors_covering(rows.iter(), dot);
        let carried = authors_covering(served_rows.iter().copied(), dot);
        if carried < available.min(2) {
            out.push(format!(
                "ADR 0021 §4: {item:?}: {dot:?} served with covers by {carried} authors of {available}"
            ));
        }
    }
    let want = literal_covers(rows, bodiless);
    if want != served {
        out.push(format!(
            "ADR 0021 §4: {item:?}: served covers {served:?}, the selection rule picks {want:?}"
        ));
    }
    out
}

/// What [`after_worker`] checked, for coverage.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct WorkerChecks {
    /// Retained snapshots outside the two newest that property 4 checked.
    pub(super) older_kept: u64,
    /// Items on which property 5 was checked (a linear history).
    pub(super) linear: u64,
}

/// Properties 4 and 5 on one item's rows right after `worker` ran. `linear` says whether every
/// snapshot the server stored of the item has a covered VV at least that of the one stored
/// before it (the merge spike's `Server::linear`).
pub(super) fn after_worker(
    item: ItemId,
    rows: &[Row],
    ops: &[OpRow],
    linear: bool,
    checks: &mut WorkerChecks,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut ordered: Vec<&Row> = rows.iter().collect();
    ordered.sort_by_key(|r| r.store_seq);
    let n = ordered.len();
    // 4. R3 keeps a snapshot outside the two newest only while dropping it would lower the
    // number of authors that cover some bodiless header to fewer than two.
    for (i, row) in ordered.iter().enumerate().take(n.saturating_sub(2)) {
        checks.older_kept += 1;
        let without = || {
            ordered
                .iter()
                .enumerate()
                .filter(move |&(j, _)| j != i)
                .map(|(_, r)| *r)
        };
        let stays = ops.iter().filter(|op| !op.held).any(|op| {
            let after = authors_covering(without(), op.dot);
            covers(&row.clamped, op.dot)
                && after < 2
                && after < authors_covering(ordered.iter().copied(), op.dot)
        });
        if !stays {
            out.push(format!(
                "ADR 0021 §8 property 4: {item:?} keeps snapshot {}, which R3 drops",
                row.store_seq
            ));
        }
    }
    // 5. In a linear history, the bodiless headers are those R1 deletes (the older of the two
    // newest and snapshots by two authors cover it) and those a healing request stored without
    // a body.
    if linear {
        checks.linear += 1;
        let older = n.checked_sub(2).and_then(|i| ordered.get(i));
        for op in ops {
            let r1 = older.is_some_and(|r| covers(&r.clamped, op.dot))
                && authors_covering(ordered.iter().copied(), op.dot) >= 2;
            if op.held == (r1 || op.healed) {
                out.push(format!(
                    "ADR 0021 §8 property 5: {item:?}: header {:?} bodiless {}, R1 {r1}, healed {}",
                    op.dot, !op.held, op.healed
                ));
            }
        }
    }
    out
}
