//! Compaction through the `worker` job and the covers Fetch serves (ADR 0021 §3–§5, §8
//! "Storage").

use rizzy_core::ids::ItemId;
use rizzy_domain_vault::{CompactionReport, FetchOutcome, VaultError};
use rizzy_proto::vault::{Record, SeqVector};
use rizzy_storage::on_engine;

use crate::common::{
    Device, Env, OpSpec, VAULT, block_on, chain, covers_of, fetch_all_with, item, op_dot, ops_of,
    sign_op, sign_snapshot, sign_snapshot_id, snapshot_header,
};

/// The dots of a complete Fetch's bodiless headers, as (device byte, seq).
fn bodiless(pages: &[rizzy_domain_vault::FetchOutcome]) -> Vec<(u8, u64)> {
    ops_of(pages)
        .into_iter()
        .filter(|op| op.body.is_none())
        .map(|op| {
            let dot = op_dot(op).1;
            (dot.device_id().as_bytes()[0], dot.seq())
        })
        .collect()
}

/// The authors of a complete Fetch's covers, as device bytes, in response order.
fn cover_authors(pages: &[rizzy_domain_vault::FetchOutcome]) -> Vec<u8> {
    covers_of(pages)
        .into_iter()
        .map(|c| snapshot_header(c).author.as_bytes()[0])
        .collect()
}

#[test]
fn an_item_snapshotted_by_one_device_is_never_compacted() {
    block_on(async {
        let env = Env::new(1).await;
        let a = Device::new(1);
        env.enrol(&[&a]);
        env.store(chain(&a, item(1), 1, 5)).await;
        env.store(vec![
            Record::Snapshot(sign_snapshot(&a, item(1), 1, &[(&a, 3)], 0)),
            Record::Snapshot(sign_snapshot(&a, item(1), 2, &[(&a, 5)], 0)),
        ])
        .await;
        let run = env.domain.run_compaction(16).await.unwrap();
        let (items, report) = (run.processed, run.report);
        assert_eq!(items, 1);
        assert_eq!(report, CompactionReport::default());
        assert!(bodiless(&env.fetch_all(&[]).await).is_empty());
    });
}

#[test]
fn two_author_covers_delete_bodies_drop_snapshots_and_are_served() {
    block_on(async {
        let env = Env::new(1).await;
        let (a, b) = (Device::new(1), Device::new(2));
        env.enrol(&[&a, &b]);
        env.store(chain(&a, item(1), 1, 5)).await;
        env.store(vec![
            Record::Snapshot(sign_snapshot(&a, item(1), 1, &[(&a, 3)], 0)),
            Record::Snapshot(sign_snapshot(&b, item(1), 2, &[(&a, 4)], 0)),
            Record::Snapshot(sign_snapshot(&a, item(1), 3, &[(&a, 5)], 0)),
        ])
        .await;
        // `api` stored and queued; nothing is deleted before `worker` runs.
        assert!(bodiless(&env.fetch_all(&[]).await).is_empty());

        // R1: the older of the two newest (B's, a ≤ 4) covers 1–4, and A's snapshots cover
        // them too. R3: A's oldest snapshot is not needed for two-author cover.
        let run = env.domain.run_compaction(16).await.unwrap();
        let (items, report) = (run.processed, run.report);
        assert_eq!(items, 1);
        assert_eq!(
            report,
            CompactionReport {
                bodies_deleted: 4,
                snapshots_dropped: 1,
            }
        );
        // The job is idempotent and the queue is empty.
        assert_eq!(env.domain.run_compaction(16).await.unwrap().processed, 0);
        assert_eq!(
            env.domain.compact_item(VAULT, item(1)).await.unwrap(),
            CompactionReport::default()
        );

        let pages = env.fetch_all(&[]).await;
        assert_eq!(bodiless(&pages), vec![(1, 1), (1, 2), (1, 3), (1, 4)]);
        // Newest first: A's (a ≤ 5), then B's for the second author.
        assert_eq!(cover_authors(&pages), vec![1, 2]);
        // A client behind by two gets the same covers for its bodiless headers.
        let pages = env.fetch_all(&[(&a, 2)]).await;
        assert_eq!(bodiless(&pages), vec![(1, 3), (1, 4)]);
        assert_eq!(cover_authors(&pages), vec![1, 2]);
        // Nothing bodiless after the cursor: no covers.
        let pages = env.fetch_all(&[(&a, 4)]).await;
        assert!(covers_of(&pages).is_empty());
        // A re-upload of an op whose body the server deleted is still "already stored": the
        // signed body hash binds the body the server no longer holds.
        assert_eq!(
            env.upload(chain(&a, item(1), 1, 5)).await,
            vec![rizzy_proto::vault::UploadResult::AlreadyStored; 5]
        );
        assert_eq!(bodiless(&env.fetch_all(&[]).await).len(), 4);
    });
}

#[test]
fn concurrent_purges_keep_their_bodies_until_two_authors_cover_them() {
    block_on(async {
        let env = Env::new(1).await;
        let (a, b) = (Device::new(1), Device::new(2));
        env.enrol(&[&a, &b]);
        // Seq 2 of each device is its purge; each purges without having seen the other's.
        env.store(chain(&a, item(1), 1, 2)).await;
        env.store(chain(&b, item(1), 1, 2)).await;
        // T_A, then T_B (ADR 0021 Context, "False gap").
        env.store(vec![
            Record::Snapshot(sign_snapshot(&a, item(1), 1, &[(&a, 2), (&b, 1)], 0)),
            Record::Snapshot(sign_snapshot(&b, item(1), 2, &[(&a, 1), (&b, 2)], 0)),
        ])
        .await;
        env.domain.run_compaction(16).await.unwrap();
        // Only the ops both authors cover lost their bodies; each purge keeps its body, and a
        // device that was behind sees no gap (every page passed `check_page`).
        let pages = env.fetch_all(&[]).await;
        assert_eq!(bodiless(&pages), vec![(1, 1), (2, 1)]);

        // Later snapshots by both authors cover both purges: the purge bodies go, and R3 drops
        // T_A and T_B (ADR 0021 §5 "Concurrent purges").
        env.store(vec![
            Record::Snapshot(sign_snapshot(&b, item(1), 3, &[(&a, 2), (&b, 2)], 0)),
            Record::Snapshot(sign_snapshot(&a, item(1), 4, &[(&a, 2), (&b, 2)], 0)),
        ])
        .await;
        let report = env.domain.run_compaction(16).await.unwrap().report;
        assert_eq!(
            report,
            CompactionReport {
                bodies_deleted: 2,
                snapshots_dropped: 2,
            }
        );
        let pages = env.fetch_all(&[]).await;
        assert_eq!(bodiless(&pages), vec![(1, 1), (1, 2), (2, 1), (2, 2)]);
        assert_eq!(cover_authors(&pages), vec![1, 2]);
    });
}

#[test]
fn each_page_carries_its_own_covers() {
    block_on(async {
        let env = Env::new(1).await;
        let (a, b) = (Device::new(1), Device::new(2));
        env.enrol(&[&a, &b]);
        let n = u64::try_from(rizzy_domain_vault::PAGE_MAX_OPS).unwrap() + 52;
        env.store(chain(&a, item(1), 1, n)).await;
        env.store(vec![
            Record::Snapshot(sign_snapshot(&a, item(1), 1, &[(&a, n)], 0)),
            Record::Snapshot(sign_snapshot(&b, item(1), 2, &[(&a, n)], 0)),
        ])
        .await;
        let report = env.domain.run_compaction(16).await.unwrap().report;
        assert_eq!(report.bodies_deleted, usize::try_from(n).unwrap());
        let pages = env.fetch_all(&[]).await;
        assert_eq!(pages.len(), 2);
        assert!(!pages[0].response.complete && pages[1].response.complete);
        for page in &pages {
            assert_eq!(page.response.covers.len(), 2);
        }
        assert_eq!(ops_of(&pages).len(), usize::try_from(n).unwrap());
    });
}

#[test]
fn a_bodiless_header_without_a_cover_is_served_alone_and_reported() {
    block_on(async {
        let env = Env::new(1).await;
        let (a, b) = (Device::new(1), Device::new(2));
        env.enrol(&[&a, &b]);
        env.store(chain(&a, item(1), 1, 2)).await;
        env.store(vec![
            Record::Snapshot(sign_snapshot(&a, item(1), 1, &[(&a, 2)], 0)),
            Record::Snapshot(sign_snapshot(&b, item(1), 2, &[(&a, 2)], 0)),
        ])
        .await;
        env.domain.run_compaction(16).await.unwrap();
        // Damage the database: the covers disappear behind the domain's back.
        let mut tx = env.db.begin_write().await.unwrap();
        on_engine!(tx.conn(), |c| sqlx::query("DELETE FROM vault_snapshots")
            .execute(&mut *c)
            .await
            .map(|_| ())
            .unwrap());
        tx.commit().await.unwrap();

        let page = env.fetch_page(&SeqVector::default()).await;
        assert!(page.response.covers.is_empty());
        assert_eq!(page.response.ops.len(), 2);
        assert!(page.response.ops.iter().all(|op| op.body.is_none()));
        assert_eq!(page.integrity_errors.len(), 2);
        let report = page.integrity_errors[0].to_string();
        // Names the vault, the item and the dot by id; nothing else.
        assert!(report.contains(&"b1".repeat(16)), "{report}");
        assert!(report.contains(&"01".repeat(16)), "{report}");
        assert!(report.contains("seq 1"), "{report}");
    });
}

/// Stores `a`'s ops `from..=to` on `item` and one snapshot each by `a` and `b` covering them
/// all, so that compaction deletes every body and both snapshots are the covers.
async fn compactable(env: &Env, a: &Device, b: &Device, item: ItemId, from: u64, to: u64) {
    env.store(chain(a, item, from, to)).await;
    let id = item.as_bytes()[0];
    env.store(vec![
        Record::Snapshot(sign_snapshot(a, item, id, &[(a, to)], 0)),
        Record::Snapshot(sign_snapshot(b, item, id.wrapping_add(0x80), &[(a, to)], 0)),
    ])
    .await;
}

/// Damages the retained snapshots of `item`: their clamped VVs no longer parse.
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
)]
async fn damage_clamped_vv(env: &Env, item: ItemId) {
    let mut tx = env.db.begin_write().await.unwrap();
    on_engine!(tx.conn(), |c| sqlx::query(
        "UPDATE vault_snapshots SET clamped_vv = $1 WHERE vault_id = $2 AND item_id = $3"
    )
    .bind(&[0xffu8; 3][..])
    .bind(&VAULT.as_bytes()[..])
    .bind(&item.as_bytes()[..])
    .execute(&mut *c)
    .await
    .map(|_| ())
    .unwrap());
    tx.commit().await.unwrap();
}

#[test]
fn a_failing_item_does_not_stop_compaction_of_the_others() {
    block_on(async {
        let env = Env::new(1).await;
        let (a, b) = (Device::new(1), Device::new(2));
        env.enrol(&[&a, &b]);
        // Item 1 is queued first, and its rows are damaged; item 2 is healthy.
        compactable(&env, &a, &b, item(1), 1, 2).await;
        compactable(&env, &a, &b, item(2), 3, 4).await;
        damage_clamped_vv(&env, item(1)).await;

        let run = env.domain.run_compaction(16).await.unwrap();
        assert_eq!(run.processed, 1);
        assert_eq!(run.report.bodies_deleted, 2);
        assert_eq!(run.failures.len(), 1);
        let failure = &run.failures[0];
        assert_eq!((failure.vault_id, failure.item_id), (VAULT, item(1)));
        assert!(matches!(failure.error, VaultError::Corrupt { .. }));
        // The log line names the ids and the column, nothing else.
        let line = failure.to_string();
        assert!(line.contains(&"01".repeat(16)), "{line}");
        assert!(line.contains("clamped_vv"), "{line}");

        // Item 1 stays queued, but behind items queued after it: a one-item run compacts
        // item 3, not item 1 again.
        compactable(&env, &a, &b, item(3), 5, 6).await;
        let run = env.domain.run_compaction(1).await.unwrap();
        assert_eq!((run.processed, run.report.bodies_deleted), (1, 2));
        assert!(run.failures.is_empty());
        let run = env.domain.run_compaction(16).await.unwrap();
        assert_eq!((run.processed, run.failures.len()), (0, 1));
    });
}

/// The bytes a page sends: every op's statement, body and wrap, and every cover's statement,
/// envelope and wrap.
fn page_bytes(page: &FetchOutcome) -> usize {
    let ops: usize = page
        .response
        .ops
        .iter()
        .map(|op| {
            op.statement.as_slice().len()
                + op.body.as_ref().map_or(0, |b| b.as_slice().len())
                + op.key_wrap
                    .as_ref()
                    .map_or(0, |w| w.envelope.as_slice().len())
        })
        .sum();
    let covers: usize = page
        .response
        .covers
        .iter()
        .map(|c| {
            c.statement.as_slice().len()
                + c.envelope.as_slice().len()
                + c.key_wrap
                    .as_ref()
                    .map_or(0, |w| w.envelope.as_slice().len())
        })
        .sum();
    ops + covers
}

#[test]
fn covers_count_in_the_page_budget() {
    block_on(async {
        let env = Env::new(1).await;
        let (a, b) = (Device::new(1), Device::new(2));
        env.enrol(&[&a, &b]);
        let items = 8u8;
        for n in 0..items {
            let first = u64::from(n) * 2 + 1;
            compactable(&env, &a, &b, item(n + 1), first, first + 1).await;
        }
        let run = env.domain.run_compaction(64).await.unwrap();
        assert_eq!(run.report.bodies_deleted, usize::from(items) * 2);
        let total_ops = usize::from(items) * 2;

        // The default budget: one page, every item's covers in it.
        let pages = env.fetch_all(&[]).await;
        assert_eq!(pages.len(), 1);
        assert_eq!(covers_of(&pages).len(), usize::from(items) * 2);
        let one_item = page_bytes(&pages[0]) / usize::from(items);

        // A budget of about two items: several pages, each within it, each bodiless header
        // with its covers (`check_page` in `fetch_all_with`), and nothing lost.
        let budget = one_item * 2 + one_item / 2;
        let domain = env.domain_with_page_bytes(budget);
        let pages = fetch_all_with(&domain, &[]).await;
        assert!(pages.len() >= 3, "{} pages", pages.len());
        for page in &pages {
            assert!(
                page_bytes(page) <= budget,
                "{} > {budget}",
                page_bytes(page)
            );
        }
        assert_eq!(ops_of(&pages).len(), total_ops);

        // A budget below one item still makes progress: one op and its covers per page.
        let domain = env.domain_with_page_bytes(1);
        let pages = fetch_all_with(&domain, &[]).await;
        assert_eq!(pages.len(), total_ops);
        assert!(pages.iter().all(|p| p.response.ops.len() == 1));
        assert!(pages.iter().all(|p| p.response.covers.len() == 2));
    });
}

/// Fetch-versus-compaction runs, `RIZZY_TEST_RACE_RUNS` or 200.
fn race_runs() -> u32 {
    std::env::var("RIZZY_TEST_RACE_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200)
}

/// The item of race run `run`.
fn race_item(run: u32) -> ItemId {
    let mut id = [0xc0; 16];
    id[12..].copy_from_slice(&run.to_be_bytes());
    ItemId::from_bytes(id)
}

/// A snapshot id unique to race run `run`, snapshot `k`.
fn race_snapshot_id(run: u32, k: u8) -> [u8; 16] {
    let mut id = [0xd0; 16];
    id[11] = k;
    id[12..].copy_from_slice(&run.to_be_bytes());
    id
}

/// ADR 0021 §8 "Storage": "a Fetch racing a compaction never returns a bodiless header without
/// a cover". Each run builds a fresh item whose compaction deletes bodies and drops a
/// snapshot, runs `worker`'s job on a spawned task while Fetches read, twice per run, and has
/// every page checked by `check_page`. Fetches repeat until the compaction has committed, after
/// a varying number of yields, so they read while its transaction is in flight and after it;
/// the test fails unless at least one Fetch read the old state while the compaction committed
/// ([`Race::spanning`]). On PostgreSQL (`RIZZY_TEST_POSTGRES_URL`, see `common::Slot`) this is
/// the `REPEATABLE READ` check of ADR 0021 §4.
#[test]
fn a_fetch_racing_compaction_always_has_its_covers() {
    block_on(async {
        let env = Env::new(1).await;
        let (a, b) = (Device::new(1), Device::new(2));
        env.enrol(&[&a, &b]);
        let mut head = 0u64;
        let mut total = Race::default();
        for run in 0..race_runs() {
            let item = race_item(run);
            let base = head;
            env.store(
                (base + 1..=base + 5)
                    .map(|seq| Record::Op(sign_op(&a, VAULT, &OpSpec::new(item, seq, seq - 1))))
                    .collect(),
            )
            .await;
            env.store(vec![
                Record::Snapshot(sign_snapshot_id(
                    &a,
                    item,
                    race_snapshot_id(run, 1),
                    &[(&a, base + 3)],
                    0,
                )),
                Record::Snapshot(sign_snapshot_id(
                    &b,
                    item,
                    race_snapshot_id(run, 2),
                    &[(&a, base + 4)],
                    0,
                )),
                Record::Snapshot(sign_snapshot_id(
                    &a,
                    item,
                    race_snapshot_id(run, 3),
                    &[(&a, base + 5)],
                    0,
                )),
            ])
            .await;
            let r1 = race_once(&env, &a, item, base, run, 0).await;

            // Phase 2: a later snapshot by B makes B's older one droppable while a Fetch reads.
            env.store(vec![
                Record::Op(sign_op(&a, VAULT, &OpSpec::new(item, base + 6, base + 5))),
                Record::Snapshot(sign_snapshot_id(
                    &b,
                    item,
                    race_snapshot_id(run, 4),
                    &[(&a, base + 6)],
                    0,
                )),
            ])
            .await;
            head = base + 6;
            let r2 = race_once(&env, &a, item, base, run.wrapping_add(1), 4).await;
            for r in [r1, r2] {
                total.before += r.before;
                total.after += r.after;
                total.spanning += r.spanning;
            }
        }
        eprintln!("race: {total:?}");
        // Some Fetch of every race ran after the compaction committed, by construction.
        assert!(total.after >= 2 * race_runs());
        // And the race is real: some Fetch read the state before a compaction while that
        // compaction committed, and still had every cover (`check_page`).
        assert!(total.spanning >= 1, "{total:?}");
    });
}

/// What the Fetches of one race saw.
#[derive(Clone, Copy, Debug, Default)]
struct Race {
    /// Fetches that read the state before the compaction.
    before: u32,
    /// Fetches that read the state after it.
    after: u32,
    /// Fetches that read the state before the compaction, although the compaction had
    /// committed by the time they returned: their read transaction was open while the
    /// compaction committed (checked on the current-thread runtime, where the compaction
    /// advances only while the Fetch awaits).
    spanning: u32,
}

/// One race: compaction of `item` on a spawned task against Fetches from `a`'s cursor `base`,
/// repeated until the compaction has committed, then once more. Every page is checked by
/// `check_page` inside `fetch_all` (`before_bodiless` bodiless headers before it).
#[expect(
    clippy::unwrap_used,
    reason = "a test helper: a failure fails the test, which CLAUDE.md allows in test code"
)]
async fn race_once(
    env: &Env,
    a: &Device,
    item: ItemId,
    base: u64,
    spin: u32,
    before_bodiless: usize,
) -> Race {
    let domain = std::sync::Arc::clone(&env.domain);
    let worker = tokio::spawn(async move { domain.compact_item(VAULT, item).await });
    for _ in 0..(spin % 5) {
        tokio::task::yield_now().await;
    }
    let mut race = Race::default();
    loop {
        let done = worker.is_finished();
        let seen = bodiless(&env.fetch_all(&[(a, base)]).await).len();
        let done_after = worker.is_finished();
        if seen == before_bodiless {
            race.before += 1;
            if !done && done_after {
                race.spanning += 1;
            }
        } else {
            race.after += 1;
        }
        if done {
            break;
        }
    }
    let report = worker.await.unwrap().unwrap();
    assert!(report.bodies_deleted >= 1);
    race
}
