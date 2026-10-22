// SPDX-License-Identifier: AGPL-3.0-only

//! ADR 0050 §4 against the real Fetch code: a tombstone cover served in a page before the
//! header of the Purge it records, over small `VaultDomain::with_page_bytes` budgets, on
//! SQLite and, with `RIZZY_TEST_POSTGRES_URL`, PostgreSQL.
//!
//! The server never sees which purge a tombstone records (G-1); the tests know it, since they
//! wrote the records, and play a client's causal layer over the served pages: the real
//! `rizzy_sync::causal::VaultLog` with the merge's ADR 0018 §3 rule for a tombstone (refused as
//! `PurgeAboveCut` while its recorded purge is above the plan's cut, otherwise taken cut to it),
//! and the hold, retry and lapse of ADR 0050 §2. This crate's own Fetch is unchanged by ADR
//! 0050 (§3): what is checked is that the pages it serves let that client converge.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "integration tests: a failure fails the test, which CLAUDE.md allows in test code"
)]

use std::collections::BTreeMap;

use rizzy_core::ids::ItemId;
use rizzy_domain_vault::FetchOutcome;
use rizzy_proto::vault::{OpRecord, Record, SeqEntry, SeqVector};
use rizzy_proto::wire::Id;
use rizzy_sync::causal::{BodyStatus, GapCause, Report, ServedOp, VaultLog};
use rizzy_sync::dot::Dot;
use rizzy_sync::header::{OpHeader, SnapshotHeader};
use rizzy_sync::vv::{VersionVector, VvOrdering};

use crate::common::{
    Device, Env, NOW, OpSpec, VAULT, block_on, check_page, fetch_page_with, header_bytes, item,
    sign_op, sign_snapshot, snapshot_header,
};

/// The own device of the client the tests play.
const ME: u8 = 0xee;

/// What the client the tests play knows of one served tombstone: the purge it records, by
/// snapshot id byte (the tests' own records).
type Purges = BTreeMap<u8, Dot>;

/// A client's causal layer over real pages (see the module docs).
struct Client {
    log: VaultLog,
    /// Whether it holds a cover refused as `PurgeAboveCut` (ADR 0050) or gives it up at once,
    /// as before ADR 0050.
    holds: bool,
    /// The held tombstone per item, and the dot of the purge it records.
    held: BTreeMap<ItemId, (SnapshotHeader, Dot)>,
    /// Every report.
    reports: Vec<Report>,
    /// Covers refused for good.
    refused: usize,
    /// Covers held, and covers taken on a retry.
    held_count: usize,
    taken_on_retry: usize,
}

impl Client {
    fn new(holds: bool) -> Self {
        Self {
            log: VaultLog::new(VAULT, rizzy_core::ids::DeviceId::from_bytes([ME; 16])),
            holds,
            held: BTreeMap::new(),
            reports: Vec::new(),
            refused: 0,
            held_count: 0,
            taken_on_retry: 0,
        }
    }

    /// The Fetch cursor, in wire form.
    fn cursor(&self) -> SeqVector {
        SeqVector::new(
            self.log
                .cursor()
                .entries()
                .map(|d| SeqEntry {
                    device_id: Id::from_bytes(d.device_id().to_bytes()),
                    seq: d.seq(),
                })
                .collect(),
        )
        .unwrap()
    }

    /// The tombstone rule of ADR 0018 §3 under `cut`: `Some(taken)` or `None` for
    /// `PurgeAboveCut`. A cover whose purge the tests did not record is a live snapshot, taken.
    fn takes(
        cover: &SnapshotHeader,
        purge: Option<Dot>,
        cut: &VersionVector,
    ) -> Option<VersionVector> {
        if purge.is_some_and(|p| !cut.covers(p)) {
            return None;
        }
        let mut taken = cover.covered.clone();
        taken.meet(cut);
        Some(taken)
    }

    /// One served page through plan, absorb or hold, commit, retry and, on the last page, the
    /// end of the holds and the complete-Fetch reports.
    fn page(&mut self, page: &FetchOutcome, purges: &Purges) {
        check_page(page);
        let served: Vec<ServedOp> = page.response.ops.iter().map(served_op).collect();
        let covers: Vec<SnapshotHeader> =
            page.response.covers.iter().map(snapshot_header).collect();
        let plan = self.log.plan_covers(&served, &covers);
        for &i in &plan.absorb {
            let cover = &covers[i];
            let purge = purges.get(&cover.snapshot_id.as_bytes()[0]).copied();
            if let Some(taken) = Self::takes(cover, purge, &plan.cut) {
                self.log.record_absorbed(&plan, cover.item_id, &taken);
            } else if self.holds && self.log.hold_cover(cover) {
                self.held_count += 1;
                self.held
                    .insert(cover.item_id, (cover.clone(), purge.unwrap()));
            } else {
                self.refused += 1;
            }
        }
        let commit = self.log.commit(&served);
        self.reports.extend(commit.reports);
        let complete = page.response.complete;
        if !commit.accepted.is_empty() || complete {
            let retry = self.log.held_plan();
            for (item_id, (cover, purge)) in core::mem::take(&mut self.held) {
                let moot = matches!(
                    self.log.settled(item_id).compare(&cover.covered),
                    VvOrdering::Equal | VvOrdering::Greater
                );
                if moot {
                    self.log.release_hold(item_id);
                } else if let Some(taken) = Self::takes(&cover, Some(purge), &retry.cut) {
                    self.log.record_absorbed(&retry, item_id, &taken);
                    self.log.release_hold(item_id);
                    self.taken_on_retry += 1;
                } else {
                    self.held.insert(item_id, (cover, purge));
                }
            }
        }
        if complete {
            self.refused += self.held.len();
            self.held.clear();
            self.log.end_holds();
        }
        let _ = self.log.take_deliveries();
        if complete {
            self.reports.extend(self.log.complete_fetch_reports());
        }
    }
}

/// The verified header and body verdict of a served op (bodies are opaque test bytes here).
fn served_op(record: &OpRecord) -> ServedOp {
    ServedOp {
        header: OpHeader::parse(header_bytes(record.statement.as_slice())).unwrap(),
        body: if record.body.is_some() {
            BodyStatus::Verified
        } else {
            BodyStatus::Bodiless
        },
    }
}

/// Op `seq` of `device` on `item` after `prev`.
fn op(device: &Device, item: ItemId, seq: u64, prev: u64) -> Record {
    Record::Op(sign_op(device, VAULT, &OpSpec::new(item, seq, prev)))
}

/// The smallest page byte budget whose first page from an empty cursor holds exactly `ops`
/// ops: the budget the real page builder needs to stop between those ops and the next.
async fn budget_for(env: &Env, ops: usize) -> usize {
    let empty = SeqVector::new(Vec::new()).unwrap();
    for budget in (64..64 * 1024).step_by(8) {
        let page = fetch_page_with(&env.domain_with_page_bytes(budget), &empty).await;
        let n = page.response.ops.len();
        if n == ops {
            return budget;
        }
        assert!(n < ops, "no budget stops the first page after {ops} ops");
    }
    panic!("no budget found");
}

/// Plays a complete paged Fetch from the client's cursor with `budget`; returns the pages.
async fn fetch(env: &Env, client: &mut Client, budget: usize, purges: &Purges) -> usize {
    let domain = env.domain_with_page_bytes(budget);
    let mut pages = 0;
    loop {
        let page = fetch_page_with(&domain, &client.cursor()).await;
        client.page(&page, purges);
        pages += 1;
        if page.response.complete {
            return pages;
        }
        assert!(pages < 100, "the Fetch never completes");
    }
}

/// ADR 0050 §4, the boundary case on the real server, across devices: A writes, writes and
/// trashes item 1, B purges it, and A and B both write the tombstone that records B's purge;
/// `worker` deletes every body. With a budget that ends the first page after A's chain, the
/// tombstones come with A's headers while B's purge header is in the next page. Before ADR 0050
/// the client stops at a gap there, its cursor stays, and the same Fetch repeats it forever;
/// with the hold, the second page resolves it.
#[test]
fn a_tombstone_cover_split_from_its_purge_on_another_chain_resolves_on_the_next_page() {
    block_on(async {
        let env = Env::new(1).await;
        let (a, b) = (Device::new(1), Device::new(2));
        env.enrol(&[&a, &b]);
        let x = item(1);
        env.store(vec![op(&a, x, 1, 0), op(&a, x, 2, 1), op(&a, x, 3, 2)])
            .await;
        env.store(vec![op(&b, x, 1, 0)]).await;
        let covered = [(&a, 3), (&b, 1)];
        env.store(vec![
            Record::Snapshot(sign_snapshot(&a, x, 1, &covered, 0)),
            Record::Snapshot(sign_snapshot(&b, x, 2, &covered, 0)),
        ])
        .await;
        let purge = Dot::new(b.id, 1).unwrap();
        let purges: Purges = [(1, purge), (2, purge)].into_iter().collect();
        let run = env.domain.run_compaction(16, NOW).await.unwrap();
        assert_eq!(run.report.bodies_deleted, 4, "{run:?}");
        let budget = budget_for(&env, 3).await;

        // Before ADR 0050: the refusal is final, the chain stops at A:1, and the next Fetch
        // from the same cursor serves the same page again.
        let mut old = Client::new(false);
        let domain = env.domain_with_page_bytes(budget);
        let first = fetch_page_with(&domain, &old.cursor()).await;
        assert!(!first.response.complete);
        old.page(&first, &purges);
        assert_eq!(old.refused, 2);
        assert_eq!(
            old.reports,
            [Report::Gap {
                device: a.id,
                after: 0,
                cause: GapCause::Uncovered {
                    dot: Dot::new(a.id, 1).unwrap()
                },
            }]
        );
        let again = fetch_page_with(&domain, &old.cursor()).await;
        assert_eq!(again.response.ops, first.response.ops, "the stall repeats");

        // ADR 0050: held across the boundary, resolved by the next page.
        let mut new = Client::new(true);
        let pages = fetch(&env, &mut new, budget, &purges).await;
        assert!(pages >= 2);
        assert!(new.held_count > 0);
        assert_eq!(new.refused, 0);
        assert!(new.reports.is_empty(), "{:?}", new.reports);
        assert_eq!(
            new.log.settled(x),
            covered
                .iter()
                .map(|(d, s)| Dot::new(d.id, *s).unwrap())
                .collect()
        );
        assert_eq!(new.log.head(a.id), 3);
        assert_eq!(new.log.head(b.id), 1);
        // Every budget converges the same way.
        for budget in [budget, budget + 8, budget * 2, usize::MAX / 4] {
            let mut c = Client::new(true);
            fetch(&env, &mut c, budget, &purges).await;
            assert!(c.reports.is_empty(), "budget {budget}: {:?}", c.reports);
            assert_eq!(c.log.settled(x), new.log.settled(x));
        }
    });
}

/// ADR 0050 §4, the same chain and the retry: A writes, trashes and purges item 1. Two live
/// snapshots of the trashed item (A's and B's) let `worker` delete the first three bodies; the
/// tombstone (A's, recording A's purge) covers the purge alone among the two authors, so its
/// body stays. The first page serves the bodiless headers with the tombstone and a live cover;
/// the purge comes with its body in the next page, after which the retry takes the tombstone.
#[test]
fn a_held_tombstone_is_taken_on_the_retry_once_its_purge_arrives() {
    block_on(async {
        let env = Env::new(1).await;
        let (a, b) = (Device::new(1), Device::new(2));
        env.enrol(&[&a, &b]);
        let x = item(1);
        env.store(vec![
            op(&a, x, 1, 0),
            op(&a, x, 2, 1),
            op(&a, x, 3, 2),
            op(&a, x, 4, 3),
        ])
        .await;
        env.store(vec![
            Record::Snapshot(sign_snapshot(&a, x, 1, &[(&a, 3)], 0)),
            Record::Snapshot(sign_snapshot(&b, x, 2, &[(&a, 3)], 0)),
            Record::Snapshot(sign_snapshot(&a, x, 3, &[(&a, 4)], 0)),
        ])
        .await;
        let purges: Purges = [(3, Dot::new(a.id, 4).unwrap())].into_iter().collect();
        let run = env.domain.run_compaction(16, NOW).await.unwrap();
        assert_eq!(run.report.bodies_deleted, 3, "{run:?}");
        let budget = budget_for(&env, 3).await;
        let mut c = Client::new(true);
        let pages = fetch(&env, &mut c, budget, &purges).await;
        assert!(pages >= 2);
        assert_eq!(c.held_count, 1);
        assert_eq!(c.taken_on_retry, 1);
        assert_eq!(c.refused, 0);
        assert!(c.reports.is_empty(), "{:?}", c.reports);
        assert_eq!(
            c.log.settled(x),
            [Dot::new(a.id, 4).unwrap()].into_iter().collect()
        );
    });
}

/// ADR 0050 §4, the regression: the recorded purge is never served (B is revoked with a
/// cut-off below its purge, so the client never accepts it). The hold resolves to the same
/// final refusal and gap as before ADR 0050 when the response completes.
#[test]
fn a_hold_whose_purge_never_comes_is_reported_when_the_response_completes() {
    block_on(async {
        let env = Env::new(1).await;
        let (a, b) = (Device::new(1), Device::new(2));
        env.enrol(&[&a, &b]);
        let x = item(1);
        env.store(vec![op(&a, x, 1, 0), op(&a, x, 2, 1), op(&a, x, 3, 2)])
            .await;
        env.store(vec![op(&b, x, 1, 0)]).await;
        let covered = [(&a, 3), (&b, 1)];
        env.store(vec![
            Record::Snapshot(sign_snapshot(&a, x, 1, &covered, 0)),
            Record::Snapshot(sign_snapshot(&b, x, 2, &covered, 0)),
        ])
        .await;
        let purge = Dot::new(b.id, 1).unwrap();
        let purges: Purges = [(1, purge), (2, purge)].into_iter().collect();
        env.domain.run_compaction(16, NOW).await.unwrap();
        let budget = budget_for(&env, 3).await;
        let mut c = Client::new(true);
        // The client learned B's revocation with nothing accepted: B's purge is past it, and
        // B's own tombstone counts for nothing.
        let _ = c.log.learn_revocation(b.id, 0);
        fetch(&env, &mut c, budget, &purges).await;
        assert_eq!(c.held_count, 1);
        assert_eq!(c.refused, 1);
        assert!(
            c.reports.contains(&Report::Gap {
                device: a.id,
                after: 0,
                cause: GapCause::Uncovered {
                    dot: Dot::new(a.id, 1).unwrap()
                },
            }),
            "{:?}",
            c.reports
        );
        assert!(c.log.settled(x).is_empty());
        assert_eq!(c.log.cursor().get(a.id), 0);
    });
}
