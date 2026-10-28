// SPDX-License-Identifier: AGPL-3.0-only

//! Held covers across a page boundary (ADR 0050 §2, §4; INV-74): unit tests of the
//! hold, its retry and its lapse, and a property test of convergence under every split of one
//! response into pages.
//!
//! The merge is simulated by the ADR 0018 §3 rule ADR 0050 is about: a tombstone whose recorded
//! purge is above the plan's cut is refused as `PurgeAboveCut` and held; otherwise it is taken,
//! cut to the plan's cut. Everything else is the real [`VaultLog`].

use proptest::prelude::*;
use rizzy_core::ids::{OpId, SnapshotId};

use super::*;
use crate::header::ItemSchemaVersion;

/// The vault of every fixture.
const VAULT: VaultId = VaultId::from_bytes([0x77; 16]);
/// The own device.
const ME: u8 = 0xee;
/// Authors.
const A: u8 = 0xa1;
const B: u8 = 0xb2;
const C: u8 = 0xc3;
/// The tombstoned item, and another one.
const X: u8 = 0x58;
const Y: u8 = 0x59;

fn device(b: u8) -> DeviceId {
    DeviceId::from_bytes([b; 16])
}

fn item(b: u8) -> ItemId {
    ItemId::from_bytes([b; 16])
}

fn dot(b: u8, seq: u64) -> Dot {
    Dot::new(device(b), seq).unwrap()
}

fn vv(entries: &[(u8, u64)]) -> VersionVector {
    entries
        .iter()
        .filter(|&&(_, seq)| seq > 0)
        .map(|&(b, seq)| dot(b, seq))
        .collect()
}

/// An op header of device `d` at `seq`, linked to `prev`, on item `x`, with causal context
/// `ctx`.
fn op(d: u8, seq: u64, prev: u64, x: u8, ctx: &[(u8, u64)]) -> OpHeader {
    let mut op_id = [d; 16];
    op_id[8..].copy_from_slice(&seq.to_be_bytes());
    OpHeader {
        vault_id: VAULT,
        item_id: item(x),
        op_id: OpId::from_bytes(op_id),
        dot: dot(d, seq),
        vault_prev_seq: prev,
        hlc: Hlc::from_parts(seq, 0).unwrap(),
        item_schema_version: ItemSchemaVersion::V1,
        vault_key_epoch: 1,
        causal_context: vv(ctx),
    }
}

fn verified(header: OpHeader) -> ServedOp {
    ServedOp {
        header,
        body: BodyStatus::Verified,
    }
}

fn bodiless(header: OpHeader) -> ServedOp {
    ServedOp {
        header,
        body: BodyStatus::Bodiless,
    }
}

/// A tombstone header by `author` of item `x` with covered VV `covered`.
fn cover(author: u8, x: u8, covered: &[(u8, u64)]) -> SnapshotHeader {
    SnapshotHeader {
        vault_id: VAULT,
        item_id: item(x),
        snapshot_id: SnapshotId::from_bytes([author ^ x; 16]),
        author: device(author),
        item_schema_version: ItemSchemaVersion::V1,
        vault_key_epoch: 1,
        covered: vv(covered),
    }
}

fn new_log() -> VaultLog {
    VaultLog::new(VAULT, device(ME))
}

/// A served tombstone: its header and the dot of the Purge it records (inside the encrypted
/// body: the client knows it, the server does not).
#[derive(Clone, Debug)]
struct Tomb {
    header: SnapshotHeader,
    purge: Dot,
}

/// The simulated merge's verdict on a tombstone under a cut (ADR 0018 §3, "Snapshots are
/// claims"): `Some(taken)` when the recorded purge is within the cut, `None` for
/// `PurgeAboveCut`.
fn merge_takes(tomb: &Tomb, cut: &VersionVector) -> Option<VersionVector> {
    cut.covers(tomb.purge).then(|| {
        let mut taken = tomb.header.covered.clone();
        taken.meet(cut);
        taken
    })
}

/// The client of ADR 0050 §2 for one page: plan, absorb or hold, commit, retry the held covers
/// if a chain advanced (or the page is the last), end the holds on the last page, deliver.
struct Client {
    log: VaultLog,
    /// The held tombstone per item (the merge's held claim).
    held: BTreeMap<ItemId, Tomb>,
    /// Everything delivered, in order.
    delivered: Vec<Delivery>,
    /// Every report, commits and the complete-Fetch ones.
    reports: Vec<Report>,
}

impl Client {
    fn new() -> Self {
        Self {
            log: new_log(),
            held: BTreeMap::new(),
            delivered: Vec::new(),
            reports: Vec::new(),
        }
    }

    fn page(&mut self, ops: &[ServedOp], tombs: &[Tomb], last: bool) {
        let headers: Vec<SnapshotHeader> = tombs.iter().map(|t| t.header.clone()).collect();
        let plan = self.log.plan_covers(ops, &headers);
        for &i in &plan.absorb {
            let tomb = &tombs[i];
            match merge_takes(tomb, &plan.cut) {
                Some(taken) => {
                    self.log.record_absorbed(&plan, tomb.header.item_id, &taken);
                }
                None => {
                    if self.log.hold_cover(&tomb.header) {
                        self.held.insert(tomb.header.item_id, tomb.clone());
                    }
                }
            }
        }
        let commit = self.log.commit(ops);
        self.reports.extend(commit.reports.iter().copied());
        if !commit.accepted.is_empty() || last {
            self.retry();
        }
        if last {
            self.held.clear();
            self.log.end_holds();
        }
        self.check_held_unsettled();
        let deliveries = self.log.take_deliveries();
        self.delivered.extend(deliveries);
        if last {
            self.reports.extend(self.log.complete_fetch_reports());
        }
    }

    fn retry(&mut self) {
        let plan = self.log.held_plan();
        for (item_id, tomb) in core::mem::take(&mut self.held) {
            if let Some(taken) = merge_takes(&tomb, &plan.cut) {
                self.log.record_absorbed(&plan, item_id, &taken);
                assert!(self.log.release_hold(item_id));
            } else {
                self.held.insert(item_id, tomb);
            }
        }
    }

    /// INV-74: while its item's cover is still held (not taken), a held link's dot
    /// never joins the settled VV, and so nothing waiting for it is delivered.
    fn check_held_unsettled(&self) {
        for chain in self.log.chains.values() {
            for link in chain.links.values() {
                if link.state == LinkState::Held && self.held.contains_key(&link.header.item_id) {
                    assert!(
                        !self
                            .log
                            .settled(link.header.item_id)
                            .covers(link.header.dot),
                        "a held link counts as settled: {:?}",
                        link.header.dot
                    );
                }
            }
        }
    }
}

/// The boundary case of ADR 0050 §4: A's ops 1–3 (write, write, trash) bodiless behind a
/// tombstone recording A's purge at seq 4, which comes in the next page.
#[test]
fn a_held_cover_links_past_the_page_boundary_and_settles_on_the_retry() {
    let mut log = new_log();
    let tomb = cover(B, X, &[(A, 4)]);
    let page1 = [
        bodiless(op(A, 1, 0, X, &[])),
        bodiless(op(A, 2, 1, X, &[(A, 1)])),
        bodiless(op(A, 3, 2, X, &[(A, 2)])),
    ];
    let plan = log.plan_covers(&page1, core::slice::from_ref(&tomb));
    assert_eq!(plan.absorb, [0]);
    assert_eq!(plan.cut, vv(&[(A, 3)]));
    // The merge refuses it: the purge A:4 is above the cut. Before ADR 0050 this was a gap.
    assert!(log.hold_cover(&tomb));
    let commit = log.commit(&page1);
    assert_eq!(commit.accepted, [dot(A, 1), dot(A, 2), dot(A, 3)]);
    assert!(commit.reports.is_empty(), "{:?}", commit.reports);
    assert_eq!(log.head(device(A)), 3);
    assert_eq!(log.cursor(), vv(&[(A, 3)]));
    assert!(log.settled(item(X)).is_empty(), "a held dot settled");
    assert!(log.take_deliveries().is_empty());
    // Only the first held link names the gap; the rest wait behind it.
    let waiting = log.waiting();
    assert_eq!(waiting.len(), 3);
    assert_eq!(waiting[0].reason, WaitReason::Held);
    assert_eq!(
        waiting[1].reason,
        WaitReason::Chain {
            first_unsettled: dot(A, 1)
        }
    );
    // Page 2: the Purge, with its body.
    let page2 = [verified(op(A, 4, 3, X, &[(A, 3)]))];
    let plan = log.plan_covers(&page2, &[]);
    assert!(plan.absorb.is_empty());
    let commit = log.commit(&page2);
    assert_eq!(commit.accepted, [dot(A, 4)]);
    // The purge waits behind the held links (reading 1), and nothing was delivered.
    assert!(log.take_deliveries().is_empty());
    // The retry takes the same cover under the held plan.
    let retry = log.held_plan();
    assert_eq!(retry.cut, vv(&[(A, 4)]));
    assert_eq!(
        log.record_absorbed(&retry, item(X), &vv(&[(A, 4)])),
        vv(&[(A, 4)])
    );
    assert!(log.release_hold(item(X)));
    let deliveries = log.take_deliveries();
    assert_eq!(deliveries.len(), 1);
    assert_eq!(deliveries[0].dot, dot(A, 4));
    assert!(deliveries[0].covered);
    log.end_holds();
    assert!(log.waiting().is_empty());
    assert!(log.complete_fetch_reports().is_empty());
    assert_eq!(log.cursor(), vv(&[(A, 4)]));
}

/// The cross-device case of ADR 0050 §4: the recorded purge is B's, on a chain served after
/// A's. Anything whose causal context names a held dot waits until the hold resolves.
#[test]
fn a_held_cover_whose_purge_is_on_another_chain() {
    let mut c = Client::new();
    let tomb = Tomb {
        header: cover(A, X, &[(A, 2), (B, 1)]),
        purge: dot(B, 1),
    };
    let page1 = [
        bodiless(op(A, 1, 0, X, &[])),
        bodiless(op(A, 2, 1, X, &[(A, 1)])),
        // A later op of A on another item: a link, but it waits behind the held ones.
        verified(op(A, 3, 2, Y, &[])),
    ];
    c.page(&page1, core::slice::from_ref(&tomb), false);
    assert_eq!(c.log.head(device(A)), 3);
    assert!(c.delivered.is_empty(), "{:?}", c.delivered);
    assert_eq!(c.held.len(), 1);
    // Page 2: B's purge (bodiless, its own cover again) and C's op whose context names A:2.
    let page2 = [
        bodiless(op(B, 1, 0, X, &[(A, 2)])),
        verified(op(C, 1, 0, X, &[(A, 2), (B, 1)])),
    ];
    c.page(&page2, core::slice::from_ref(&tomb), true);
    assert!(c.reports.is_empty(), "{:?}", c.reports);
    assert!(c.held.is_empty());
    assert_eq!(c.log.settled(item(X)), vv(&[(A, 2), (B, 1), (C, 1)]));
    let order: Vec<Dot> = c.delivered.iter().map(|d| d.dot).collect();
    assert_eq!(order, [dot(A, 3), dot(C, 1)]);
}

/// The regression of ADR 0050 §4: the response completes without the recorded purge (here B's
/// purge is past B's revocation cut-off, so it is never accepted). The hold resolves to the
/// same final, reported gap as before ADR 0050, the cursor drops below the held links so the
/// next Fetch serves them again, and the next response holds and reports them again.
#[test]
fn a_hold_the_response_never_resolves_is_the_same_reported_gap() {
    let mut c = Client::new();
    c.log.learn_revocation(device(B), 0);
    let tomb = Tomb {
        header: cover(A, X, &[(A, 2), (B, 1)]),
        purge: dot(B, 1),
    };
    let page = [
        bodiless(op(A, 1, 0, X, &[])),
        bodiless(op(A, 2, 1, X, &[(A, 1)])),
    ];
    // A's tombstone counts for A's headers; B's purge is never served (it is past the cut-off).
    c.page(&page, core::slice::from_ref(&tomb), false);
    assert_eq!(c.log.head(device(A)), 2);
    assert_eq!(c.log.cursor(), vv(&[(A, 2)]));
    c.page(&[], &[], true);
    let gap = Report::Gap {
        device: device(A),
        after: 0,
        cause: GapCause::Uncovered { dot: dot(A, 1) },
    };
    assert_eq!(c.reports, [gap]);
    assert_eq!(
        c.log.cursor(),
        VersionVector::new(),
        "the cursor stays past the lapsed links"
    );
    assert!(c.log.settled(item(X)).is_empty());
    assert!(c.delivered.is_empty());
    // The next Fetch serves the same headers and cover again: held again, reported again.
    c.reports.clear();
    c.page(&page, core::slice::from_ref(&tomb), true);
    assert_eq!(c.reports, [gap]);
    assert!(c.log.settled(item(X)).is_empty());
}

/// A held cover the merge refuses for another reason on the retry ends the hold at once: its
/// links lapse, the cursor drops below them, and the next page serves them again.
#[test]
fn a_released_hold_lapses_at_once() {
    let mut log = new_log();
    let tomb = cover(B, X, &[(A, 3)]);
    let page = [
        bodiless(op(A, 1, 0, X, &[])),
        bodiless(op(A, 2, 1, X, &[(A, 1)])),
    ];
    let _ = log.plan_covers(&page, core::slice::from_ref(&tomb));
    assert!(log.hold_cover(&tomb));
    let _ = log.commit(&page);
    assert_eq!(log.cursor(), vv(&[(A, 2)]));
    assert!(log.release_hold(item(X)));
    assert!(!log.release_hold(item(X)));
    assert_eq!(log.cursor(), VersionVector::new());
    assert_eq!(
        log.waiting()[0].reason,
        WaitReason::Uncovered,
        "a lapsed link waits uncovered"
    );
    // Served again with a cover the merge takes, the lapsed links settle.
    let plan = log.plan_covers(&page, core::slice::from_ref(&tomb));
    assert_eq!(plan.absorb, [0]);
    let _ = log.record_absorbed(&plan, item(X), &vv(&[(A, 2)]));
    let commit = log.commit(&page);
    assert!(commit.accepted.is_empty());
    // Settled by the cover now, they are served again as duplicates.
    assert_eq!(
        commit.reports,
        [
            Report::Duplicate { dot: dot(A, 1) },
            Report::Duplicate { dot: dot(A, 2) }
        ]
    );
    assert!(log.waiting().is_empty());
    assert_eq!(log.cursor(), vv(&[(A, 2)]));
}

/// ADR 0109 §2 C1 (cursor entry per link state): the per-chain cursor rule is "head, unless
/// a link at or after the frontier is in a serve-again state (`Rejected` or `Lapsed`) and
/// its item's settled VV does not cover its dot; then the first such link's
/// `vault_prev_seq`." A held link never lowers it; a cover absorbed later settles a lapsed
/// link out; two lapsed links in one chain give the first's `vault_prev_seq`; and a held
/// link past a learned revocation cut-off counts as rejected.
#[test]
fn adr_0109_c1_cursor_entry_per_link_state() {
    // Held link does not lower the entry: it is the chain head.
    let mut log = new_log();
    let tomb = cover(B, X, &[(A, 3)]);
    let page = [
        bodiless(op(A, 1, 0, X, &[])),
        bodiless(op(A, 2, 1, X, &[(A, 1)])),
    ];
    let _ = log.plan_covers(&page, core::slice::from_ref(&tomb));
    assert!(log.hold_cover(&tomb));
    let _ = log.commit(&page);
    assert_eq!(log.cursor(), vv(&[(A, 2)]), "held link does not lower the entry");

    // release_hold lapses the links and the entry drops to the first lapsed link's prev_seq.
    assert!(log.release_hold(item(X)));
    assert_eq!(
        log.cursor(),
        VersionVector::new(),
        "the first lapsed link's vault_prev_seq is 0 (nothing in the chain before A1)",
    );

    // end_holds has the same effect (asserted here on a fresh log).
    let mut log = new_log();
    let _ = log.plan_covers(&page, core::slice::from_ref(&tomb));
    assert!(log.hold_cover(&tomb));
    let _ = log.commit(&page);
    assert_eq!(log.cursor(), vv(&[(A, 2)]));
    log.end_holds();
    assert_eq!(
        log.cursor(),
        VersionVector::new(),
        "end_holds lapses the hold and drops the entry below the first held link",
    );

    // A later absorbed cover settles the lapsed link, and the entry returns to head.
    let plan = log.plan_covers(&page, core::slice::from_ref(&tomb));
    assert_eq!(plan.absorb, [0]);
    let _ = log.record_absorbed(&plan, item(X), &vv(&[(A, 2)]));
    let _ = log.commit(&page);
    assert_eq!(
        log.cursor(),
        vv(&[(A, 2)]),
        "a settled cover covers the lapsed link's dot; the entry returns to head",
    );

    // Two lapsed links in one chain: the entry stops at the first one's vault_prev_seq.
    // Build a chain A1,A2 held; A3,A4 (also bodiless on item X, held by the same tombstone's
    // retry at the end of the sequence) also lapse. Then make a later cover that only
    // covers A1 (through the covered VV) and absorb it: the second lapsed link (A2) is now
    // the first uncovered lapsed link, so the entry is A1 (its vault_prev_seq).
    let mut log = new_log();
    let tomb = cover(B, X, &[(A, 4)]);
    let page = [
        bodiless(op(A, 1, 0, X, &[])),
        bodiless(op(A, 2, 1, X, &[(A, 1)])),
        bodiless(op(A, 3, 2, X, &[(A, 2)])),
        bodiless(op(A, 4, 3, X, &[(A, 3)])),
    ];
    let _ = log.plan_covers(&page, core::slice::from_ref(&tomb));
    assert!(log.hold_cover(&tomb));
    let _ = log.commit(&page);
    assert_eq!(log.cursor(), vv(&[(A, 4)]));
    assert!(log.release_hold(item(X)));
    assert_eq!(
        log.cursor(),
        VersionVector::new(),
        "every link is lapsed and uncovered; the entry is 0 (A1's vault_prev_seq)",
    );
    // Serve the same page with a cover that only covers A1. The second lapsed link (A2) is
    // the first uncovered one, so the entry is now A2's `vault_prev_seq` (= 1).
    let partial = cover(B, X, &[(A, 1)]);
    let plan = log.plan_covers(&page, core::slice::from_ref(&partial));
    assert_eq!(plan.absorb, [0]);
    let _ = log.record_absorbed(&plan, item(X), &vv(&[(A, 1)]));
    let _ = log.commit(&page);
    assert_eq!(
        log.cursor(),
        vv(&[(A, 1)]),
        "with A1 covered, the first uncovered lapsed link is A2; the entry is 1 (A2's prev_seq)",
    );

    // Serve-again mirrored on the `Rejected` state (ADR 0109 C1 treats `Rejected` and
    // `Lapsed` alike, both as "serves again"): a waiting header whose body is rejected
    // after waiting, with no snapshot covering it, lowers the entry to its `vault_prev_seq`.
    let mut log = new_log();
    let page = [
        ServedOp {
            header: op(A, 1, 0, X, &[]),
            body: BodyStatus::Waiting,
        },
        verified(op(A, 2, 1, X, &[(A, 1)])),
    ];
    let _ = log.commit(&page);
    assert_eq!(log.cursor(), vv(&[(A, 2)]), "a waiting link does not lower the entry");
    log.body_rejected(dot(A, 1)).unwrap();
    assert_eq!(
        log.cursor(),
        VersionVector::new(),
        "a rejected link below the frontier lowers the entry to its vault_prev_seq (0)",
    );
}

/// The hold's bounds: a cover of another vault, or past its author's cut-off, is never held,
/// and past [`MAX_HELD_ITEMS`] distinct items a refusal is final at once (ADR 0050 "Risks").
#[test]
fn the_holds_are_bounded() {
    let mut log = new_log();
    let mut foreign = cover(B, X, &[(A, 1)]);
    foreign.vault_id = VaultId::from_bytes([0x01; 16]);
    assert!(!log.hold_cover(&foreign));
    log.learn_revocation(device(C), 1);
    assert!(!log.hold_cover(&cover(C, X, &[(C, 2)])));
    for n in 0..MAX_HELD_ITEMS {
        let mut c = cover(B, X, &[(A, 1)]);
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&(n as u64).to_be_bytes());
        c.item_id = ItemId::from_bytes(id);
        assert!(log.hold_cover(&c), "{n}");
    }
    assert!(!log.hold_cover(&cover(B, X, &[(A, 1)])), "past the cap");
    let mut again = cover(B, Y, &[(A, 1)]);
    again.item_id = ItemId::from_bytes([0u8; 16]);
    assert!(
        log.hold_cover(&again),
        "replacing a held item's cover stays within the cap"
    );
    assert_eq!(log.held_items().count(), MAX_HELD_ITEMS);
    log.end_holds();
    assert_eq!(log.held_items().count(), 0);
}

/// One generated response: devices' chains on items, every op of item X behind one tombstone
/// whose recorded purge is a given op of X, the rest with bodies; the server's page split.
#[derive(Clone, Debug)]
struct Split {
    /// Per device (ascending id), the item of each of its ops, in chain order. Every op of X is
    /// bodiless behind the tombstone; every op of Y has its body.
    chains: Vec<Vec<u8>>,
    /// Which op of X is the purge: an index into X's ops in serving order.
    purge: usize,
    /// Page boundaries, as op counts per page.
    pages: Vec<usize>,
    /// Whether the purge's header is withheld (never served).
    withhold: bool,
}

fn split() -> impl Strategy<Value = Split> {
    let chains = prop::collection::vec(
        prop::collection::vec(prop::sample::select(vec![X, Y]), 1..6),
        1..4,
    );
    (
        chains,
        any::<prop::sample::Index>(),
        prop::collection::vec(1usize..5, 1..20),
        prop::bool::weighted(0.15),
    )
        .prop_map(|(chains, purge, pages, withhold)| Split {
            purge: purge.index(usize::MAX),
            chains,
            pages,
            withhold,
        })
}

/// The response of a [`Split`]: every op served in order, the tombstone, and the purge dot.
/// `None` when no op is on X.
fn response(s: &Split) -> Option<(Vec<ServedOp>, Tomb)> {
    let authors = [A, B, C];
    let mut ops = Vec::new();
    let mut x_dots = Vec::new();
    let mut x_vv = VersionVector::new();
    for (d, chain) in s.chains.iter().enumerate() {
        let author = authors[d];
        for (seq, &x) in (1u64..).zip(chain) {
            let header = op(author, seq, seq - 1, x, &[]);
            if x == X {
                x_dots.push(header.dot);
                x_vv.add(header.dot);
                ops.push(bodiless(header));
            } else {
                ops.push(verified(header));
            }
        }
    }
    let purge = *x_dots.get(s.purge % x_dots.len().max(1))?;
    let mut tomb = Tomb {
        header: cover(A, X, &[]),
        purge,
    };
    tomb.header.covered = x_vv;
    if s.withhold {
        // Withholding the purge's header withholds the rest of its chain too (the server
        // serves chains in order), so cut the response there.
        let at = ops.iter().position(|o| o.header.dot == purge)?;
        let device = purge.device_id();
        ops = ops
            .into_iter()
            .enumerate()
            .filter(|(i, o)| o.header.dot.device_id() != device || *i < at)
            .map(|(_, o)| o)
            .collect();
    }
    Some((ops, tomb))
}

/// Serves `ops` in the pages `sizes` gives (the last page takes the rest), each with the
/// tombstone when it has a bodiless header of X, as the server selects covers per page.
fn serve(c: &mut Client, ops: &[ServedOp], tomb: &Tomb, sizes: &[usize]) {
    let mut at = 0;
    let mut sizes = sizes.iter().copied();
    while at < ops.len() {
        let n = sizes.next().unwrap_or(ops.len());
        let end = (at + n).min(ops.len());
        let page = &ops[at..end];
        let covers: Vec<Tomb> = page
            .iter()
            .any(|o| o.header.item_id == item(X) && o.body == BodyStatus::Bodiless)
            .then(|| tomb.clone())
            .into_iter()
            .collect();
        c.page(page, &covers, end == ops.len());
        at = end;
    }
    if ops.is_empty() {
        c.page(&[], &[], true);
    }
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 1_000,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    /// ADR 0012 §12 property 1 (convergence) and 7 (gap detection) under ADR 0050: however the
    /// server splits one response into pages, the client ends where one page takes it: every
    /// chain at its head, the tombstone taken, every op delivered, no report; and while a cover
    /// is held its links never count as settled. With the purge withheld, the hold resolves to
    /// one reported gap at the first held link of each chain, nothing of X settles, and the
    /// cursor drops below the held links.
    #[test]
    fn every_page_split_converges_to_the_one_page_result(s in split()) {
        let Some((ops, tomb)) = response(&s) else {
            return Ok(());
        };
        let mut whole = Client::new();
        serve(&mut whole, &ops, &tomb, &[usize::MAX]);
        let mut paged = Client::new();
        serve(&mut paged, &ops, &tomb, &s.pages);
        prop_assert_eq!(paged.log.cursor(), whole.log.cursor());
        prop_assert_eq!(paged.log.settled(item(X)), whole.log.settled(item(X)));
        prop_assert_eq!(paged.log.settled(item(Y)), whole.log.settled(item(Y)));
        prop_assert_eq!(&paged.reports, &whole.reports);
        let mut a: Vec<Dot> = paged.delivered.iter().map(|d| d.dot).collect();
        let mut b: Vec<Dot> = whole.delivered.iter().map(|d| d.dot).collect();
        a.sort_unstable();
        b.sort_unstable();
        prop_assert_eq!(a, b);
        if s.withhold {
            prop_assert!(paged.log.settled(item(X)).is_empty());
        } else {
            prop_assert!(paged.reports.is_empty(), "{:?}", paged.reports);
            prop_assert_eq!(paged.log.settled(item(X)), tomb.header.covered.clone());
        }
    }
}
