//! Unit tests of the per-device-chain layer, one or more per rule.
//!
//! - Chain check (ADR 0012 §7, INV-27): chain order, links by `vault_prev_seq` across seqs of
//!   other vaults, the INV-27 test (op n withheld, n + 1 served: reported, nothing past it
//!   applied), a first header that does not link from the cursor, duplicates, equivocations,
//!   foreign-vault and own headers.
//! - Compaction (ADR 0012 §7, ADR 0021 §4): a bodiless header behind a served cover, behind a
//!   held snapshot, without a cover, behind a refused cover, behind a cover of another item;
//!   the ADR 0012 §7 example (a withheld edit on item Z while item X is compacted), in its three
//!   forms; covers by two authors; a rejected body (reading 4).
//! - Causal delivery (ADR 0012 §4 step 2, ADR 0018 §3 "Covered ops"): a causal context from
//!   another device, a chain held by a waiting body (reading 1), a rejected body released by a
//!   cover, covered ops delivered at once, each body delivered once.
//! - Revocation (ADR 0012 §6, ADR 0021 §9, CRYPTO.md §11.8 step 4): headers past the cut-off,
//!   held links past it, ops already applied past it, the chain below the cut-off after a
//!   complete Fetch, a second revocation, an op that depends on a rejected one.
//! - Author checks (CRYPTO.md §10.2 rule (c), §11.8 step 4), with `rizzy-core`'s own
//!   `permits_hlc` and `permits_device_seq` as oracles.
//! - The own chain (ADR 0012 §7 "Upload", ADR 0021 §2 and §9, ADR 0018 §3 "Re-issued ops"):
//!   writing, acknowledgements, the restore generation, stale plans, re-issues.
//! - Server behind (ADR 0021 §9): each condition, the caps, and leaving read-only.

use proptest::prelude::*;
use rizzy_core::ids::{AccountId, OpId, SnapshotId};
use rizzy_core::sign::{DeviceCertificate, DeviceKind, DeviceRevocation, DeviceVerifyingKey};

use super::*;
use crate::header::ItemSchemaVersion;
use crate::hlc::MAX_MILLIS;

/// The vault of every fixture.
const VAULT: VaultId = VaultId::from_bytes([0x11; 16]);
/// The own device.
const ME: u8 = 0xee;
/// Other devices.
const A: u8 = 0xa1;
const B: u8 = 0xb2;
const C: u8 = 0xc3;
/// Items.
const X: u8 = 0x58;
const Y: u8 = 0x59;
const Z: u8 = 0x5a;

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
/// `ctx`, HLC `seq` ms (capped at the 48-bit maximum), epoch 1.
fn op(d: u8, seq: u64, prev: u64, x: u8, ctx: &[(u8, u64)]) -> OpHeader {
    let mut op_id = [d; 16];
    op_id[8..].copy_from_slice(&seq.to_be_bytes());
    OpHeader {
        vault_id: VAULT,
        item_id: item(x),
        op_id: OpId::from_bytes(op_id),
        dot: dot(d, seq),
        vault_prev_seq: prev,
        hlc: Hlc::from_parts(seq.min(MAX_MILLIS), 0).unwrap(),
        item_schema_version: ItemSchemaVersion::V1,
        vault_key_epoch: 1,
        causal_context: vv(ctx),
    }
}

fn with(header: OpHeader, body: BodyStatus) -> ServedOp {
    ServedOp { header, body }
}

fn verified(header: OpHeader) -> ServedOp {
    with(header, BodyStatus::Verified)
}

fn bodiless(header: OpHeader) -> ServedOp {
    with(header, BodyStatus::Bodiless)
}

/// A snapshot header by `author` of item `x` with covered VV `covered`.
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

/// One response through the whole cycle, with an honest merge that accepts every cover the
/// plan names and takes all it may of it (the covered VV cut to the plan's cut). Returns the
/// plan, the commit and the deliveries.
fn sync(
    log: &mut VaultLog,
    ops: &[ServedOp],
    covers: &[SnapshotHeader],
) -> (CoverPlan, Commit, Vec<Delivery>) {
    let plan = log.plan_covers(ops, covers);
    for &i in &plan.absorb {
        log.record_absorbed(&plan, covers[i].item_id, &covers[i].covered);
    }
    let commit = log.commit(ops);
    let deliveries = log.take_deliveries();
    (plan, commit, deliveries)
}

fn dots(deliveries: &[Delivery]) -> Vec<Dot> {
    deliveries.iter().map(|d| d.dot).collect()
}

fn gap(d: u8, after: u64, cause: GapCause) -> Report {
    Report::Gap {
        device: device(d),
        after,
        cause,
    }
}

/// A's ops 1..=n on item `x`, each on top of the one before.
fn a_chain(n: u64, x: u8) -> Vec<OpHeader> {
    (1..=n).map(|s| op(A, s, s - 1, x, &[(A, s - 1)])).collect()
}

// ---------------------------------------------------------------------------------------------
// Chain check
// ---------------------------------------------------------------------------------------------

#[test]
fn a_chain_is_accepted_in_order_and_delivered_in_order() {
    let mut log = new_log();
    let chain = a_chain(3, X);
    // Served out of order: the chain check sorts by device_seq.
    let ops = [
        verified(chain[2].clone()),
        verified(chain[0].clone()),
        verified(chain[1].clone()),
    ];
    let (_, commit, deliveries) = sync(&mut log, &ops, &[]);
    assert_eq!(commit.accepted, [dot(A, 1), dot(A, 2), dot(A, 3)]);
    assert!(commit.reports.is_empty());
    assert_eq!(dots(&deliveries), [dot(A, 1), dot(A, 2), dot(A, 3)]);
    assert!(
        deliveries
            .iter()
            .all(|d| !d.covered && d.item_id == item(X))
    );
    assert_eq!(deliveries[1].hlc, Hlc::from_parts(2, 0).unwrap());
    assert_eq!(log.cursor(), vv(&[(A, 3)]));
    assert_eq!(log.settled(item(X)), vv(&[(A, 3)]));
    assert_eq!(log.header(dot(A, 2)), Some(&chain[1]));
    assert_eq!(log.chain(device(A)).count(), 3);
    assert!(log.waiting().is_empty());
    assert!(log.take_deliveries().is_empty());
}

#[test]
fn links_follow_vault_prev_seq_across_seqs_of_other_vaults() {
    // device_seq counts ops in every vault: A's ops in this vault are 2, 5 and 9.
    let mut log = new_log();
    let ops = [
        verified(op(A, 2, 0, X, &[])),
        verified(op(A, 5, 2, X, &[(A, 2)])),
        verified(op(A, 9, 5, Y, &[])),
    ];
    let (_, commit, deliveries) = sync(&mut log, &ops, &[]);
    assert_eq!(commit.accepted.len(), 3);
    assert!(commit.reports.is_empty());
    assert_eq!(dots(&deliveries), [dot(A, 2), dot(A, 5), dot(A, 9)]);
    assert_eq!(log.head(device(A)), 9);
}

/// INV-27's test: the server omits op n from a device and serves n + 1; the client reports
/// missing data and applies nothing past the gap.
#[test]
fn a_withheld_header_is_a_gap_and_nothing_past_it_is_applied() {
    let mut log = new_log();
    let chain = a_chain(4, X);
    let ops = [
        verified(chain[0].clone()),
        verified(chain[2].clone()),
        verified(chain[3].clone()),
    ];
    let (_, commit, deliveries) = sync(&mut log, &ops, &[]);
    assert_eq!(commit.accepted, [dot(A, 1)]);
    assert_eq!(
        commit.reports,
        [gap(
            A,
            1,
            GapCause::Unlinked {
                next: dot(A, 3),
                vault_prev_seq: 2
            }
        )]
    );
    assert_eq!(dots(&deliveries), [dot(A, 1)]);
    // The cursor stays before the gap, so the next Fetch asks again.
    assert_eq!(log.cursor(), vv(&[(A, 1)]));
    assert_eq!(log.header(dot(A, 3)), None);
    // The server then serves the rest.
    let rest: Vec<ServedOp> = chain[1..].iter().cloned().map(verified).collect();
    let (_, commit, deliveries) = sync(&mut log, &rest, &[]);
    assert!(commit.reports.is_empty());
    assert_eq!(dots(&deliveries), [dot(A, 2), dot(A, 3), dot(A, 4)]);
}

#[test]
fn the_first_header_must_link_from_the_cursor() {
    let mut log = new_log();
    let (_, commit, deliveries) = sync(&mut log, &[verified(op(A, 5, 4, X, &[]))], &[]);
    assert!(commit.accepted.is_empty());
    assert_eq!(
        commit.reports,
        [gap(
            A,
            0,
            GapCause::Unlinked {
                next: dot(A, 5),
                vault_prev_seq: 4
            }
        )]
    );
    assert!(deliveries.is_empty());
    assert_eq!(log.cursor(), VersionVector::new());
}

#[test]
fn a_gap_in_one_chain_does_not_stop_another() {
    let mut log = new_log();
    let ops = [verified(op(A, 2, 1, X, &[])), verified(op(B, 1, 0, Y, &[]))];
    let (_, commit, deliveries) = sync(&mut log, &ops, &[]);
    assert_eq!(commit.accepted, [dot(B, 1)]);
    assert_eq!(commit.reports.len(), 1);
    assert_eq!(dots(&deliveries), [dot(B, 1)]);
}

#[test]
fn duplicates_are_reported_and_skipped() {
    let mut log = new_log();
    let chain = a_chain(3, X);
    sync(
        &mut log,
        &[verified(chain[0].clone()), verified(chain[1].clone())],
        &[],
    );
    // Served again, with the next one, and one of them twice in the same response.
    let ops = [
        verified(chain[0].clone()),
        verified(chain[1].clone()),
        verified(chain[2].clone()),
        verified(chain[2].clone()),
    ];
    let (_, commit, deliveries) = sync(&mut log, &ops, &[]);
    assert_eq!(commit.accepted, [dot(A, 3)]);
    assert_eq!(
        commit.reports,
        [
            Report::Duplicate { dot: dot(A, 1) },
            Report::Duplicate { dot: dot(A, 2) },
            Report::Duplicate { dot: dot(A, 3) },
        ]
    );
    assert_eq!(dots(&deliveries), [dot(A, 3)]);
}

#[test]
fn a_second_version_of_a_held_dot_is_an_equivocation() {
    let mut log = new_log();
    sync(
        &mut log,
        &[
            verified(op(A, 2, 0, X, &[])),
            verified(op(A, 5, 2, X, &[(A, 2)])),
        ],
        &[],
    );
    // A different header at a held dot.
    let mut other = op(A, 2, 0, X, &[]);
    other.vault_key_epoch = 2;
    // A header at a seq the chain skipped: link 5 says A had no op here between 2 and 5.
    let skipped = op(A, 3, 2, X, &[(A, 2)]);
    let (_, commit, deliveries) = sync(&mut log, &[verified(other), verified(skipped)], &[]);
    assert!(commit.accepted.is_empty());
    assert_eq!(
        commit.reports,
        [
            Report::Equivocation { dot: dot(A, 2) },
            Report::Equivocation { dot: dot(A, 3) },
        ]
    );
    assert!(deliveries.is_empty());
    assert_eq!(log.header(dot(A, 2)).unwrap().vault_key_epoch, 1);
}

#[test]
fn foreign_vault_and_own_headers_are_not_taken() {
    let mut log = new_log();
    let own = op(ME, 1, 0, X, &[]);
    log.record_own_op(own.clone()).unwrap();
    let mut foreign = op(A, 1, 0, X, &[]);
    foreign.vault_id = VaultId::from_bytes([0x22; 16]);
    let ops = [
        verified(foreign),
        verified(own),
        verified(op(ME, 2, 1, X, &[(ME, 1)])),
    ];
    let (plan, commit, deliveries) = sync(&mut log, &ops, &[]);
    assert!(plan.links.is_empty());
    assert!(commit.accepted.is_empty());
    assert_eq!(
        commit.reports,
        [
            Report::ForeignVault { dot: dot(A, 1) },
            Report::Duplicate { dot: dot(ME, 1) },
            Report::UnknownOwnOp { dot: dot(ME, 2) },
        ]
    );
    assert!(deliveries.is_empty());
    let mut changed = op(ME, 1, 0, X, &[]);
    changed.hlc = Hlc::from_u64(7);
    let commit = log.commit(&[verified(changed)]);
    assert_eq!(commit.reports, [Report::Equivocation { dot: dot(ME, 1) }]);
}

// ---------------------------------------------------------------------------------------------
// Compaction: bodiless headers and covers
// ---------------------------------------------------------------------------------------------

#[test]
fn a_bodiless_header_counts_behind_a_served_cover() {
    let mut log = new_log();
    let chain = a_chain(2, X);
    let ops = [bodiless(chain[0].clone()), verified(chain[1].clone())];
    let covers = [cover(B, X, &[(A, 1)])];
    let (plan, commit, deliveries) = sync(&mut log, &ops, &covers);
    assert_eq!(plan.absorb, [0]);
    assert_eq!(plan.links, [dot(A, 1), dot(A, 2)]);
    assert_eq!(commit.accepted, [dot(A, 1), dot(A, 2)]);
    assert!(commit.reports.is_empty());
    // A:1 is settled by the snapshot; only A:2 has a body to deliver.
    assert_eq!(dots(&deliveries), [dot(A, 2)]);
    assert!(!deliveries[0].covered);
    assert_eq!(log.settled(item(X)), vv(&[(A, 2)]));
}

#[test]
fn a_bodiless_header_without_a_cover_is_a_gap() {
    let mut log = new_log();
    let chain = a_chain(3, X);
    let ops = [
        verified(chain[0].clone()),
        bodiless(chain[1].clone()),
        verified(chain[2].clone()),
    ];
    // A cover that stops below A:2 does not count for it.
    let covers = [cover(B, X, &[(A, 1)])];
    let (plan, commit, deliveries) = sync(&mut log, &ops, &covers);
    assert!(plan.absorb.is_empty());
    assert_eq!(commit.accepted, [dot(A, 1)]);
    assert_eq!(
        commit.reports,
        [gap(A, 1, GapCause::Uncovered { dot: dot(A, 2) })]
    );
    assert_eq!(dots(&deliveries), [dot(A, 1)]);
    assert_eq!(log.head(device(A)), 1);
}

/// Reading 7: the cut is each chain's head or last header that passed the first pass, and a
/// cover's part above it is never recorded.
#[test]
fn a_cover_is_cut_to_the_headers_that_passed() {
    let mut log = new_log();
    sync(&mut log, &[verified(op(B, 1, 0, Y, &[]))], &[]);
    // A:2 is withheld, so A:3 does not link: the first pass stops after A:1.
    let ops = [
        bodiless(op(A, 1, 0, X, &[])),
        bodiless(op(A, 3, 2, X, &[(A, 2)])),
    ];
    let covers = [cover(C, X, &[(A, 3), (B, 4), (C, 2)])];
    let plan = log.plan_covers(&ops, &covers);
    assert_eq!(plan.absorb, [0]);
    assert_eq!(plan.links, [dot(A, 1)]);
    assert_eq!(plan.cut, vv(&[(A, 1), (B, 1)]));
    assert_eq!(plan.cut_of(&covers[0].covered), vv(&[(A, 1), (B, 1)]));
    // The log records no more than the cut, whatever it is given.
    let recorded = log.record_absorbed(&plan, item(X), &covers[0].covered);
    assert_eq!(recorded, vv(&[(A, 1), (B, 1)]));
    let commit = log.commit(&ops);
    assert_eq!(commit.accepted, [dot(A, 1)]);
    assert_eq!(
        commit.reports,
        [gap(
            A,
            1,
            GapCause::Unlinked {
                next: dot(A, 3),
                vault_prev_seq: 2
            }
        )]
    );
    assert_eq!(log.settled(item(X)), vv(&[(A, 1), (B, 1)]));
}

/// Reading 7's residual case: the merge refuses the cover the first pass counted for A:1 on X
/// and accepts a cover of Y that reaches A:2. The second pass stops before A:1, so Y holds A
/// past the head: reported. On the next Fetch the held snapshot of Y counts for A:2.
#[test]
fn a_bodiless_header_counts_behind_a_held_snapshot() {
    let mut log = new_log();
    let ops = [bodiless(op(A, 1, 0, X, &[])), bodiless(op(A, 2, 1, Y, &[]))];
    let covers = [cover(B, X, &[(A, 1)]), cover(C, Y, &[(A, 2)])];
    let plan = log.plan_covers(&ops, &covers);
    assert_eq!(plan.absorb, [0, 1]);
    assert_eq!(plan.cut, vv(&[(A, 2)]));
    // The merge refuses X's cover and accepts Y's.
    log.record_absorbed(&plan, item(Y), &covers[1].covered);
    let commit = log.commit(&ops);
    assert!(commit.accepted.is_empty());
    assert_eq!(
        commit.reports,
        [
            gap(A, 0, GapCause::Uncovered { dot: dot(A, 1) }),
            Report::SettledPastHead {
                item_id: item(Y),
                device: device(A),
                settled: 2,
                head: 0
            },
        ]
    );
    assert_eq!(log.cursor(), VersionVector::default());
    // The next Fetch serves X's cover again, and none for A:2: the held snapshot counts.
    let (plan, commit, deliveries) = sync(&mut log, &ops, &covers[..1]);
    assert_eq!(plan.absorb, [0]);
    assert_eq!(commit.accepted, [dot(A, 1), dot(A, 2)]);
    assert!(commit.reports.is_empty());
    assert!(deliveries.is_empty());
    assert!(log.complete_fetch_reports().is_empty());
}

/// CRYPTO.md §11.8 step 4: a revoked author's snapshot whose covered-VV entry for it is above
/// its cut-off is refused; it counts for no header and is not absorbed.
#[test]
fn a_cover_claiming_past_its_revoked_authors_cutoff_is_refused() {
    let mut log = new_log();
    log.learn_revocation(device(B), 2);
    let ops = [bodiless(op(A, 1, 0, X, &[]))];
    // B's cover claims B:3, above its cut-off 2; C's is honest but of another item.
    let covers = [cover(B, X, &[(A, 1), (B, 3)]), cover(C, Y, &[(A, 1)])];
    let (plan, commit, _) = sync(&mut log, &ops, &covers);
    assert!(plan.absorb.is_empty());
    assert_eq!(plan.refused, [0]);
    assert!(commit.accepted.is_empty());
    assert_eq!(
        commit.reports,
        [gap(A, 0, GapCause::Uncovered { dot: dot(A, 1) })]
    );
    assert!(log.settled(item(X)).is_empty());
    // Within its cut-off, a revoked author's cover counts.
    let covers = [cover(B, X, &[(A, 1), (B, 2)])];
    let (plan, commit, _) = sync(&mut log, &ops, &covers);
    assert_eq!(plan.absorb, [0]);
    assert!(plan.refused.is_empty());
    assert_eq!(commit.accepted, [dot(A, 1)]);
}

#[test]
fn a_refused_cover_leaves_a_gap() {
    let mut log = new_log();
    let ops = [bodiless(op(A, 1, 0, X, &[]))];
    let covers = [cover(B, X, &[(A, 1)])];
    let plan = log.plan_covers(&ops, &covers);
    assert_eq!(plan.absorb, [0]);
    // The merge refuses the cover (for example, a body contradicts it): nothing recorded.
    let commit = log.commit(&ops);
    assert!(commit.accepted.is_empty());
    assert_eq!(
        commit.reports,
        [gap(A, 0, GapCause::Uncovered { dot: dot(A, 1) })]
    );
}

#[test]
fn a_cover_of_another_item_or_vault_does_not_count() {
    let mut log = new_log();
    let ops = [bodiless(op(A, 1, 0, X, &[]))];
    let mut foreign = cover(B, X, &[(A, 1)]);
    foreign.vault_id = VaultId::from_bytes([0x22; 16]);
    let covers = [cover(B, Y, &[(A, 1)]), foreign];
    let (plan, commit, _) = sync(&mut log, &ops, &covers);
    assert!(plan.absorb.is_empty());
    assert!(plan.links.is_empty());
    assert_eq!(
        commit.reports,
        [gap(A, 0, GapCause::Uncovered { dot: dot(A, 1) })]
    );
}

/// ADR 0012 §7's example: device D writes seqs 11–50 on items X and Z, and X's ops are
/// compacted behind a snapshot with VV[D] = 50. A laptop with cursor 10 for D syncs. The server
/// withholds seq 12, the only edit to Z, and sends X's snapshot. A VV check would count seq 12 as
/// covered; the chain check reports it.
#[test]
fn adr_0012_example_a_withheld_edit_on_another_item_is_reported() {
    let d = A;
    // Ops 1–10 on X, then 11–50 on X except 12 on Z.
    let header = |s: u64| {
        let x = if s == 12 { Z } else { X };
        let ctx = if s == 12 {
            0
        } else if s == 13 {
            11
        } else {
            s - 1
        };
        op(d, s, s - 1, x, &[(d, ctx)])
    };
    let laptop = || {
        let mut log = new_log();
        let first: Vec<ServedOp> = (1..=10).map(|s| verified(header(s))).collect();
        sync(&mut log, &first, &[]);
        assert_eq!(log.head(device(d)), 10);
        log
    };
    let snapshot_x = [cover(B, X, &[(d, 50)])];
    let compacted = |s: u64| {
        if s == 12 {
            verified(header(s))
        } else {
            bodiless(header(s))
        }
    };
    // 1. The server withholds seq 12's header: seq 13 does not link.
    let mut log = laptop();
    let ops: Vec<ServedOp> = (11..=50).filter(|&s| s != 12).map(compacted).collect();
    let (_, commit, deliveries) = sync(&mut log, &ops, &snapshot_x);
    assert_eq!(commit.accepted, [dot(d, 11)]);
    assert_eq!(
        commit.reports,
        [gap(
            d,
            11,
            GapCause::Unlinked {
                next: dot(d, 13),
                vault_prev_seq: 12
            }
        )]
    );
    assert!(deliveries.is_empty());
    // X's snapshot was absorbed to cover D:11, but only up to the gap: nothing of D past 11
    // is in X (INV-27).
    assert_eq!(log.settled(item(X)), vv(&[(d, 11)]));
    // 2. The server serves seq 12 without a body, and no snapshot of Z covers it.
    let mut log = laptop();
    let ops: Vec<ServedOp> = (11..=50).map(|s| bodiless(header(s))).collect();
    let (_, commit, _) = sync(&mut log, &ops, &snapshot_x);
    assert_eq!(commit.accepted, [dot(d, 11)]);
    assert_eq!(
        commit.reports,
        [gap(d, 11, GapCause::Uncovered { dot: dot(d, 12) })]
    );
    assert_eq!(log.settled(item(X)), vv(&[(d, 11)]));
    assert!(log.settled(item(Z)).is_empty());
    // 3. An honest server serves seq 12 with its body.
    let mut log = laptop();
    let ops: Vec<ServedOp> = (11..=50).map(compacted).collect();
    let (plan, commit, deliveries) = sync(&mut log, &ops, &snapshot_x);
    assert_eq!(plan.absorb, [0]);
    assert_eq!(commit.accepted.len(), 40);
    assert!(commit.reports.is_empty());
    assert_eq!(dots(&deliveries), [dot(d, 12)]);
    assert_eq!(log.settled(item(Z)), vv(&[(d, 12)]));
    assert_eq!(log.settled(item(X)), vv(&[(d, 50)]));
    assert_eq!(log.head(device(d)), 50);
}

/// ADR 0021 §4 serves each bodiless header with covers by up to two authors; each header counts
/// against any cover the replica accepted.
#[test]
fn covers_by_two_authors() {
    let chain = a_chain(4, X);
    let ops: Vec<ServedOp> = chain.iter().cloned().map(bodiless).collect();
    // Newest first: C's covers all four, B's the first three.
    let covers = [cover(C, X, &[(A, 4)]), cover(B, X, &[(A, 3)])];
    let mut log = new_log();
    let (plan, commit, deliveries) = sync(&mut log, &ops, &covers);
    assert_eq!(plan.absorb, [0, 1]);
    assert_eq!(commit.accepted.len(), 4);
    assert!(commit.reports.is_empty());
    assert!(deliveries.is_empty());
    // The merge refuses C's cover and takes B's: the fourth header has no accepted cover.
    let mut log = new_log();
    let plan = log.plan_covers(&ops, &covers);
    assert_eq!(plan.absorb, [0, 1]);
    log.record_absorbed(&plan, item(X), &covers[1].covered);
    let commit = log.commit(&ops);
    assert_eq!(commit.accepted, [dot(A, 1), dot(A, 2), dot(A, 3)]);
    assert_eq!(
        commit.reports,
        [gap(A, 3, GapCause::Uncovered { dot: dot(A, 4) })]
    );
    // A cover is absorbed only for a bodiless header before the chain's first gap: here A:2
    // is withheld, so A:3 is past the gap, and a cover of A:3 alone is not absorbed.
    let log = new_log();
    let ops = [bodiless(chain[0].clone()), bodiless(chain[2].clone())];
    let plan = log.plan_covers(&ops, &[cover(C, X, &[(A, 3)]), cover(B, Y, &[(A, 1)])]);
    assert_eq!(plan.absorb, [0]);
    let plan = log.plan_covers(&ops[1..], &[cover(C, X, &[(A, 3)])]);
    assert!(plan.absorb.is_empty());
}

#[test]
fn a_rejected_body_counts_like_a_bodiless_header() {
    // Without a cover: reported, and a gap.
    let mut log = new_log();
    let ops = [with(op(A, 1, 0, X, &[]), BodyStatus::Rejected)];
    let (_, commit, _) = sync(&mut log, &ops, &[]);
    assert_eq!(
        commit.reports,
        [
            Report::RejectedBody { dot: dot(A, 1) },
            gap(A, 0, GapCause::Uncovered { dot: dot(A, 1) }),
        ]
    );
    assert!(commit.accepted.is_empty());
    // Behind a cover: reported, accepted, never delivered.
    let mut log = new_log();
    let ops = [
        with(op(A, 1, 0, X, &[]), BodyStatus::Rejected),
        verified(op(A, 2, 1, X, &[(A, 1)])),
    ];
    let (plan, commit, deliveries) = sync(&mut log, &ops, &[cover(B, X, &[(A, 1)])]);
    assert_eq!(plan.absorb, [0]);
    assert_eq!(commit.accepted, [dot(A, 1), dot(A, 2)]);
    assert_eq!(commit.reports, [Report::RejectedBody { dot: dot(A, 1) }]);
    assert_eq!(dots(&deliveries), [dot(A, 2)]);
}

// ---------------------------------------------------------------------------------------------
// Causal delivery
// ---------------------------------------------------------------------------------------------

#[test]
fn an_op_waits_for_its_causal_context() {
    let mut log = new_log();
    // B wrote on X after applying A:1.
    let b1 = op(B, 1, 0, X, &[(A, 1)]);
    let (_, commit, deliveries) = sync(&mut log, &[verified(b1)], &[]);
    assert_eq!(commit.accepted, [dot(B, 1)]);
    assert!(deliveries.is_empty());
    assert_eq!(
        log.waiting(),
        [Waiting {
            dot: dot(B, 1),
            item_id: item(X),
            reason: WaitReason::Context { missing: dot(A, 1) },
        }]
    );
    // After a complete Fetch without A:1, the predecessor is missing.
    assert_eq!(
        log.complete_fetch_reports(),
        [Report::MissingPredecessor {
            waiting: dot(B, 1),
            missing: dot(A, 1)
        }]
    );
    let (_, _, deliveries) = sync(&mut log, &[verified(op(A, 1, 0, X, &[]))], &[]);
    assert_eq!(dots(&deliveries), [dot(A, 1), dot(B, 1)]);
    assert!(log.waiting().is_empty());
    assert!(log.complete_fetch_reports().is_empty());
}

#[test]
fn an_op_on_another_item_does_not_satisfy_a_context() {
    // A:1 is on Y; B:1's context names A:1 on X, which does not exist: B:1 waits.
    let mut log = new_log();
    let ops = [
        verified(op(A, 1, 0, Y, &[])),
        verified(op(B, 1, 0, X, &[(A, 1)])),
    ];
    let (_, _, deliveries) = sync(&mut log, &ops, &[]);
    assert_eq!(dots(&deliveries), [dot(A, 1)]);
    assert_eq!(
        log.waiting()[0].reason,
        WaitReason::Context { missing: dot(A, 1) }
    );
    // A:1 arrived, but it is no op of X: after a complete Fetch nothing can settle the entry,
    // so it is reported as missing rather than left waiting silently.
    assert_eq!(
        log.complete_fetch_reports(),
        [Report::MissingPredecessor {
            waiting: dot(B, 1),
            missing: dot(A, 1)
        }]
    );
}

/// Reading 1: every earlier link of the chain must be settled, not only the one
/// `vault_prev_seq` names.
#[test]
fn later_ops_of_a_chain_wait_for_an_earlier_waiting_body() {
    let mut log = new_log();
    let ops = [
        with(op(A, 1, 0, X, &[]), BodyStatus::Waiting),
        verified(op(A, 2, 1, Y, &[])),
        verified(op(A, 3, 2, Y, &[(A, 2)])),
    ];
    let (_, commit, deliveries) = sync(&mut log, &ops, &[]);
    assert_eq!(commit.accepted.len(), 3);
    assert!(deliveries.is_empty());
    let first = dot(A, 1);
    assert_eq!(
        log.waiting(),
        [
            Waiting {
                dot: first,
                item_id: item(X),
                reason: WaitReason::Body
            },
            Waiting {
                dot: dot(A, 2),
                item_id: item(Y),
                reason: WaitReason::Chain {
                    first_unsettled: first
                }
            },
            Waiting {
                dot: dot(A, 3),
                item_id: item(Y),
                reason: WaitReason::Chain {
                    first_unsettled: first
                }
            },
        ]
    );
    log.body_verified(first).unwrap();
    assert_eq!(
        dots(&log.take_deliveries()),
        [dot(A, 1), dot(A, 2), dot(A, 3)]
    );
}

#[test]
fn a_rejected_waiting_body_blocks_its_chain_until_a_later_fetch_covers_it() {
    let mut log = new_log();
    let a1 = op(A, 1, 0, X, &[]);
    let a2 = op(A, 2, 1, Y, &[]);
    let ops = [with(a1.clone(), BodyStatus::Waiting), verified(a2.clone())];
    sync(&mut log, &ops, &[]);
    assert_eq!(log.cursor(), vv(&[(A, 2)]));
    log.body_rejected(dot(A, 1)).unwrap();
    assert!(log.take_deliveries().is_empty());
    assert_eq!(log.waiting()[0].reason, WaitReason::Rejected);
    assert_eq!(log.body_verified(dot(A, 1)), Err(BodyError::NotWaiting));
    // Reading 8: the cursor drops below A:1, so the next Fetch serves it again.
    assert_eq!(log.cursor(), VersionVector::default());
    assert_eq!(
        log.complete_fetch_reports(),
        [gap(A, 0, GapCause::Uncovered { dot: dot(A, 1) })]
    );
    // The next Fetch serves A:1 without a cover: still a gap, and A:2 a duplicate.
    let again = [bodiless(a1.clone()), verified(a2.clone())];
    let (_, commit, deliveries) = sync(&mut log, &again, &[]);
    assert!(commit.accepted.is_empty());
    assert_eq!(
        commit.reports,
        [
            Report::Duplicate { dot: dot(A, 2) },
            gap(A, 0, GapCause::Uncovered { dot: dot(A, 1) }),
        ]
    );
    assert!(deliveries.is_empty());
    // The server compacted A:1 behind a snapshot: the cover settles it and A:2 is delivered.
    let (plan, commit, deliveries) = sync(&mut log, &again, &[cover(B, X, &[(A, 1)])]);
    assert_eq!(plan.absorb, [0]);
    assert!(commit.accepted.is_empty());
    // Covered now, A:1 is a plain duplicate in the second pass.
    assert_eq!(
        commit.reports,
        [
            Report::Duplicate { dot: dot(A, 1) },
            Report::Duplicate { dot: dot(A, 2) },
        ]
    );
    assert_eq!(dots(&deliveries), [dot(A, 2)]);
    assert!(log.waiting().is_empty());
    assert_eq!(log.cursor(), vv(&[(A, 2)]));
    assert!(log.complete_fetch_reports().is_empty());
}

#[test]
fn a_rejected_waiting_body_is_taken_again_when_a_verified_body_is_served() {
    let mut log = new_log();
    let a1 = op(A, 1, 0, X, &[]);
    let a2 = op(A, 2, 1, X, &[(A, 1)]);
    sync(
        &mut log,
        &[with(a1.clone(), BodyStatus::Waiting), verified(a2)],
        &[],
    );
    log.body_rejected(dot(A, 1)).unwrap();
    // Served again with a body that waits for its key, and verifies later.
    let (_, commit, deliveries) = sync(&mut log, &[with(a1.clone(), BodyStatus::Waiting)], &[]);
    assert!(commit.reports.is_empty());
    assert!(deliveries.is_empty());
    assert_eq!(log.waiting()[0].reason, WaitReason::Body);
    assert_eq!(log.cursor(), vv(&[(A, 2)]));
    log.body_verified(dot(A, 1)).unwrap();
    assert_eq!(dots(&log.take_deliveries()), [dot(A, 1), dot(A, 2)]);
    // Served again once more: now a plain duplicate.
    let (_, commit, _) = sync(&mut log, &[verified(a1)], &[]);
    assert_eq!(commit.reports, [Report::Duplicate { dot: dot(A, 1) }]);
}

/// ADR 0018 §3 "Covered ops": "If the item VV already covers an op's dot, the op body still
/// merges; a body already merged changes nothing."
#[test]
fn covered_op_bodies_are_delivered_at_once_and_once_only() {
    let mut log = new_log();
    // A:3 is compacted behind a cover that reaches A:3; A:1, A:2 and A:4 are served with
    // bodies. A:2's context names C:5, which is nowhere: covered, it does not wait for it.
    let ops = [
        verified(op(A, 1, 0, X, &[])),
        verified(op(A, 2, 1, X, &[(A, 1), (C, 5)])),
        bodiless(op(A, 3, 2, X, &[(A, 2)])),
        verified(op(A, 4, 3, X, &[(A, 3)])),
    ];
    let (plan, commit, deliveries) = sync(&mut log, &ops, &[cover(B, X, &[(A, 3)])]);
    assert_eq!(plan.absorb, [0]);
    assert_eq!(commit.accepted.len(), 4);
    assert_eq!(dots(&deliveries), [dot(A, 1), dot(A, 2), dot(A, 4)]);
    assert_eq!(
        deliveries.iter().map(|d| d.covered).collect::<Vec<_>>(),
        [true, true, false]
    );
    assert!(log.take_deliveries().is_empty());
    assert_eq!(log.body_verified(dot(A, 1)), Err(BodyError::NotWaiting));
    assert_eq!(log.body_verified(dot(A, 9)), Err(BodyError::UnknownOp));
    assert_eq!(log.body_rejected(dot(B, 1)), Err(BodyError::UnknownOp));
    // A later cover changes nothing for delivered bodies.
    let plan = log.plan_covers(&[], &[]);
    log.record_absorbed(&plan, item(X), &vv(&[(A, 4)]));
    assert!(log.take_deliveries().is_empty());
}

#[test]
fn a_cover_absorbed_releases_waiting_bodies_as_covered() {
    let mut log = new_log();
    let ops = [
        with(op(A, 1, 0, X, &[]), BodyStatus::Waiting),
        verified(op(A, 2, 1, X, &[(A, 1)])),
        bodiless(op(A, 3, 2, X, &[(A, 2)])),
        verified(op(A, 4, 3, X, &[(A, 3)])),
    ];
    let (_, commit, deliveries) = sync(&mut log, &ops, &[cover(B, X, &[(A, 3)])]);
    assert_eq!(commit.accepted.len(), 4);
    // A:2 is covered; A:4 is fresh, since A:1 to A:3 are settled by the cover.
    assert_eq!(dots(&deliveries), [dot(A, 2), dot(A, 4)]);
    assert_eq!(
        deliveries.iter().map(|d| d.covered).collect::<Vec<_>>(),
        [true, false]
    );
    log.body_verified(dot(A, 1)).unwrap();
    let deliveries = log.take_deliveries();
    assert_eq!(dots(&deliveries), [dot(A, 1)]);
    assert!(deliveries[0].covered);
}

/// A body that waits at the end of a complete Fetch is reported, and holds its chain.
#[test]
fn a_body_still_waiting_after_a_complete_fetch_is_reported() {
    let mut log = new_log();
    let ops = [
        with(op(A, 1, 0, X, &[]), BodyStatus::Waiting),
        verified(op(A, 2, 1, Y, &[])),
    ];
    sync(&mut log, &ops, &[]);
    assert_eq!(
        log.complete_fetch_reports(),
        [Report::Unverifiable { dot: dot(A, 1) }]
    );
    log.body_verified(dot(A, 1)).unwrap();
    assert_eq!(dots(&log.take_deliveries()), [dot(A, 1), dot(A, 2)]);
    assert!(log.complete_fetch_reports().is_empty());
}

/// A context entry at or below its device's head that no op of that item at or above it can
/// settle is missing data, not a silent wait.
#[test]
fn a_context_naming_a_seq_that_is_no_op_of_the_item_is_reported() {
    let mut log = new_log();
    // A's ops in this vault: 2 on X, 5 on Y. B:1 on X names A:3, which is no op of X.
    let ops = [
        verified(op(A, 2, 0, X, &[])),
        verified(op(A, 5, 2, Y, &[])),
        verified(op(B, 1, 0, X, &[(A, 3)])),
    ];
    let (_, _, deliveries) = sync(&mut log, &ops, &[]);
    assert_eq!(dots(&deliveries), [dot(A, 2), dot(A, 5)]);
    assert_eq!(
        log.complete_fetch_reports(),
        [Report::MissingPredecessor {
            waiting: dot(B, 1),
            missing: dot(A, 3)
        }]
    );
}

// ---------------------------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------------------------

#[test]
fn headers_past_the_cutoff_are_rejected() {
    let mut log = new_log();
    let revocation = log.learn_revocation(device(A), 2);
    assert_eq!(revocation, Revocation::default());
    let ops: Vec<ServedOp> = a_chain(4, X).into_iter().map(verified).collect();
    let (_, commit, deliveries) = sync(&mut log, &ops, &[]);
    assert_eq!(commit.accepted, [dot(A, 1), dot(A, 2)]);
    assert_eq!(
        commit.reports,
        [Report::PastCutoff {
            dot: dot(A, 3),
            last_accepted: 2
        }]
    );
    assert_eq!(dots(&deliveries), [dot(A, 1), dot(A, 2)]);
    assert_eq!(log.cutoff(device(A)), Some(2));
    assert!(log.complete_fetch_reports().is_empty());
}

#[test]
fn held_links_past_the_cutoff_are_rejected() {
    let mut log = new_log();
    let ops = [
        with(op(A, 1, 0, X, &[]), BodyStatus::Waiting),
        verified(op(A, 2, 1, X, &[(A, 1)])),
        with(op(A, 3, 2, X, &[(A, 2)]), BodyStatus::Waiting),
    ];
    sync(&mut log, &ops, &[]);
    let revocation = log.learn_revocation(device(A), 1);
    assert_eq!(revocation.rejected, [dot(A, 2), dot(A, 3)]);
    assert!(revocation.held_past_cutoff.is_empty());
    log.body_verified(dot(A, 1)).unwrap();
    assert_eq!(dots(&log.take_deliveries()), [dot(A, 1)]);
    assert!(log.waiting().is_empty());
    assert_eq!(log.body_verified(dot(A, 3)), Err(BodyError::NotWaiting));
    // Learning it again rejects nothing more.
    assert_eq!(log.learn_revocation(device(A), 1), Revocation::default());
}

/// ADR 0021 §9 "Restored-server revocation": detected and reported, not converged.
#[test]
fn ops_already_applied_past_the_cutoff_are_reported() {
    let mut log = new_log();
    let ops: Vec<ServedOp> = a_chain(3, X).into_iter().map(verified).collect();
    sync(&mut log, &ops, &[]);
    // Snapshots of Y and Z absorbed since, cut to the chains (B has none).
    let plan = log.plan_covers(&[], &[]);
    log.record_absorbed(&plan, item(Y), &vv(&[(A, 3), (B, 1)]));
    log.record_absorbed(&plan, item(Z), &vv(&[(A, 2)]));
    assert_eq!(log.settled(item(Y)), vv(&[(A, 3)]));
    let revocation = log.learn_revocation(device(A), 2);
    assert!(revocation.rejected.is_empty());
    assert_eq!(revocation.held_past_cutoff, [item(X), item(Y)]);
}

/// ADR 0021 §9 "Revoked and kind-4 authors": after a complete Fetch, a cursor for a revoked
/// device below its `last_accepted_device_seq` is missing data.
#[test]
fn a_revoked_chain_below_its_cutoff_after_a_complete_fetch_is_missing_data() {
    let mut log = new_log();
    log.learn_revocation(device(A), 5);
    let chain = a_chain(5, X);
    let first: Vec<ServedOp> = chain[..3].iter().cloned().map(verified).collect();
    sync(&mut log, &first, &[]);
    assert_eq!(
        log.complete_fetch_reports(),
        [gap(A, 3, GapCause::BelowCutoff { last_accepted: 5 })]
    );
    let rest: Vec<ServedOp> = chain[3..].iter().cloned().map(verified).collect();
    sync(&mut log, &rest, &[]);
    assert!(log.complete_fetch_reports().is_empty());
    // A revoked device with no op in the vault at all.
    log.learn_revocation(device(B), 1);
    assert_eq!(
        log.complete_fetch_reports(),
        [gap(B, 0, GapCause::BelowCutoff { last_accepted: 1 })]
    );
    // The own device is never reported this way.
    let mut log = VaultLog::new(VAULT, device(ME));
    log.learn_revocation(device(ME), 4);
    assert!(log.complete_fetch_reports().is_empty());
}

#[test]
fn a_second_revocation_keeps_the_lower_cutoff() {
    let mut log = new_log();
    log.learn_revocation(device(A), 5);
    log.learn_revocation(device(A), 3);
    assert_eq!(log.cutoff(device(A)), Some(3));
    log.learn_revocation(device(A), 9);
    assert_eq!(log.cutoff(device(A)), Some(3));
}

#[test]
fn an_op_that_depends_on_a_rejected_op_waits_and_is_reported() {
    let mut log = new_log();
    log.learn_revocation(device(A), 2);
    let a: Vec<ServedOp> = a_chain(3, X).into_iter().map(verified).collect();
    let b1 = verified(op(B, 1, 0, X, &[(A, 3)]));
    let ops: Vec<ServedOp> = a.into_iter().chain([b1]).collect();
    let (_, _, deliveries) = sync(&mut log, &ops, &[]);
    assert_eq!(dots(&deliveries), [dot(A, 1), dot(A, 2)]);
    assert_eq!(
        log.waiting()[0].reason,
        WaitReason::Context { missing: dot(A, 3) }
    );
    assert_eq!(
        log.complete_fetch_reports(),
        [Report::MissingPredecessor {
            waiting: dot(B, 1),
            missing: dot(A, 3)
        }]
    );
}

// ---------------------------------------------------------------------------------------------
// Author checks
// ---------------------------------------------------------------------------------------------

/// RFC 8032 §7.1 test 1's public key: a canonical Ed25519 point, for building certificates.
const RFC8032_PK: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

fn certificate(d: u8, kind: DeviceKind, expires_at_ms: u64) -> DeviceCertificate {
    DeviceCertificate {
        account_id: AccountId::from_bytes([0x33; 16]),
        device_id: device(d),
        identity_epoch: 1,
        device_ed25519: DeviceVerifyingKey::from_bytes(&RFC8032_PK).unwrap(),
        device_x25519: rizzy_core::hpke::HpkePublicKey::x25519([9; 32]),
        device_kind: kind,
        created_at_ms: 1,
        expires_at_ms,
    }
}

fn revocation(d: u8, last_accepted: u64) -> DeviceRevocation {
    DeviceRevocation {
        account_id: AccountId::from_bytes([0x33; 16]),
        device_id: device(d),
        last_accepted_device_seq: last_accepted,
        revoked_at_ms: 9,
    }
}

fn status(last_accepted: Option<u64>, expires_at_ms: u64) -> AuthorStatus {
    AuthorStatus {
        device: device(A),
        last_accepted,
        expires_at_ms,
    }
}

#[test]
fn revoked_authors_ops_are_accepted_up_to_the_cutoff() {
    let revoked = status(Some(3), 0);
    assert_eq!(check_op_author(&op(A, 3, 2, X, &[]), revoked), Ok(()));
    assert_eq!(
        check_op_author(&op(A, 4, 3, X, &[]), revoked),
        Err(AuthorRefusal::PastCutoff { last_accepted: 3 })
    );
    assert_eq!(
        check_op_author(&op(A, 900, 3, X, &[]), status(None, 0)),
        Ok(())
    );
    assert_eq!(
        check_op_author(&op(B, 1, 0, X, &[]), status(None, 0)),
        Err(AuthorRefusal::OtherDevice)
    );
}

/// CRYPTO.md §10.2 rule (c): the op's HLC, read as milliseconds (its top 48 bits), is at most
/// `expires_at_ms`; the logical counter does not count.
#[test]
fn rule_c_reads_the_hlc_milliseconds() {
    let expiring = status(None, 1_000);
    let mut h = op(A, 1, 0, X, &[]);
    h.hlc = Hlc::from_parts(1_000, 0xffff).unwrap();
    assert_eq!(check_op_author(&h, expiring), Ok(()));
    h.hlc = Hlc::from_parts(1_001, 0).unwrap();
    assert_eq!(
        check_op_author(&h, expiring),
        Err(AuthorRefusal::PastExpiry {
            expires_at_ms: 1_000
        })
    );
    // No expiry: any HLC.
    h.hlc = Hlc::from_u64(u64::MAX);
    assert_eq!(check_op_author(&h, status(None, 0)), Ok(()));
}

#[test]
fn author_status_from_statements() {
    let cert = certificate(A, DeviceKind::WebEphemeral, 500);
    assert_eq!(
        AuthorStatus::from_statements(&cert, None),
        Ok(status(None, 500))
    );
    assert_eq!(
        AuthorStatus::from_statements(&cert, Some(&revocation(A, 7))),
        Ok(status(Some(7), 500))
    );
    assert_eq!(
        AuthorStatus::from_statements(&cert, Some(&revocation(B, 7))),
        Err(AuthorRefusal::OtherDevice)
    );
}

#[test]
fn snapshot_author_bound() {
    let s = cover(A, X, &[(A, 4), (B, 9)]);
    assert_eq!(check_snapshot_author(&s, None), Ok(()));
    assert_eq!(check_snapshot_author(&s, Some(4)), Ok(()));
    assert_eq!(
        check_snapshot_author(&s, Some(3)),
        Err(AuthorRefusal::ClaimsPastBound { bound: 3 })
    );
    // Only the author's own entry is bounded.
    assert_eq!(
        check_snapshot_author(&cover(C, X, &[(B, 9)]), Some(0)),
        Ok(())
    );
}

#[test]
fn refusals_display_without_content() {
    for refusal in [
        AuthorRefusal::OtherDevice,
        AuthorRefusal::PastCutoff { last_accepted: 1 },
        AuthorRefusal::PastExpiry { expires_at_ms: 1 },
        AuthorRefusal::ClaimsPastBound { bound: 1 },
    ] {
        assert!(!refusal.to_string().is_empty());
    }
    for e in [BodyError::UnknownOp, BodyError::NotWaiting] {
        assert!(!e.to_string().is_empty());
    }
    for e in [
        OwnError::WrongVault,
        OwnError::NotOwnDevice,
        OwnError::BrokenChain { head: 1 },
        OwnError::ContextNotSettled,
        OwnError::UnknownOp,
        OwnError::Acknowledged,
        OwnError::MayHaveBeenServed,
        OwnError::NotAReissue,
        OwnError::NoGeneration,
        OwnError::NotStale,
    ] {
        assert!(!e.to_string().is_empty());
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1_000,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// `check_op_author` agrees with `rizzy-core`'s `DeviceCertificate::permits_hlc` and
    /// `DeviceRevocation::permits_device_seq` on every header.
    #[test]
    fn author_checks_agree_with_rizzy_core(
        seq in 1..=u64::MAX, hlc in any::<u64>(), expires in prop_oneof![Just(0u64), 1..=u64::MAX >> 16],
        cut in proptest::option::of(any::<u64>()), kind in 1u8..=4
    ) {
        let kind = DeviceKind::from_u8(kind).unwrap();
        let expires = if kind == DeviceKind::WebEphemeral { expires.clamp(2, 1 + 12 * 3_600_000) } else { expires };
        let cert = certificate(A, kind, expires);
        let revoked = cut.map(|c| revocation(A, c));
        let status = AuthorStatus::from_statements(&cert, revoked.as_ref()).unwrap();
        let mut h = op(A, seq, seq - 1, X, &[]);
        h.hlc = Hlc::from_u64(hlc);
        let expected = revoked.is_none_or(|r| r.permits_device_seq(seq)) && cert.permits_hlc(hlc);
        prop_assert_eq!(check_op_author(&h, status).is_ok(), expected);
    }
}

// ---------------------------------------------------------------------------------------------
// The own chain
// ---------------------------------------------------------------------------------------------

fn generation(b: u8) -> RestoreGeneration {
    RestoreGeneration::from_bytes([b; 16])
}

/// A log with own ops 1..=n on item X, each on top of the one before, with epoch 1.
fn own_log(n: u64) -> VaultLog {
    let mut log = new_log();
    for s in 1..=n {
        log.record_own_op(op(ME, s, s - 1, X, &[(ME, s - 1)]))
            .unwrap();
    }
    log
}

#[test]
fn own_ops_extend_the_own_chain() {
    let mut log = new_log();
    assert_eq!(log.own_vault_prev_seq(), 0);
    log.record_own_op(op(ME, 1, 0, X, &[])).unwrap();
    // The device wrote seq 2 in another vault.
    log.record_own_op(op(ME, 3, 1, X, &[(ME, 1)])).unwrap();
    assert_eq!(log.own_vault_prev_seq(), 3);
    assert_eq!(log.cursor(), vv(&[(ME, 3)]));
    assert_eq!(log.settled(item(X)), vv(&[(ME, 3)]));
    assert_eq!(
        log.record_own_op(op(ME, 5, 1, X, &[])),
        Err(OwnError::BrokenChain { head: 3 })
    );
    assert_eq!(
        log.record_own_op(op(ME, 3, 3, X, &[])),
        Err(OwnError::BrokenChain { head: 3 })
    );
    assert_eq!(
        log.record_own_op(op(A, 4, 3, X, &[])),
        Err(OwnError::NotOwnDevice)
    );
    let mut foreign = op(ME, 4, 3, X, &[]);
    foreign.vault_id = VaultId::from_bytes([0x22; 16]);
    assert_eq!(log.record_own_op(foreign), Err(OwnError::WrongVault));
    // A context naming an op this log has not settled.
    assert_eq!(
        log.record_own_op(op(ME, 4, 3, Y, &[(A, 1)])),
        Err(OwnError::ContextNotSettled)
    );
    sync(&mut log, &[verified(op(A, 1, 0, Y, &[]))], &[]);
    log.record_own_op(op(ME, 4, 3, Y, &[(A, 1)])).unwrap();
    assert_eq!(log.settled(item(Y)), vv(&[(A, 1), (ME, 4)]));
    // Own ops are applied when written, never delivered.
    assert!(log.take_deliveries().is_empty());
    // Another device's op that depends on an own op is delivered.
    sync(&mut log, &[verified(op(B, 1, 0, Y, &[(ME, 4)]))], &[]);
    assert_eq!(log.settled(item(Y)).get(device(B)), 1);
}

#[test]
fn acknowledgements_are_cumulative() {
    let mut log = own_log(3);
    assert_eq!(log.acknowledged(), 0);
    assert_eq!(log.unacknowledged().count(), 3);
    // "Already stored" is an acknowledgement too: the same call.
    log.acknowledge(2).unwrap();
    assert_eq!(log.acknowledged(), 2);
    log.acknowledge(1).unwrap();
    assert_eq!(log.acknowledged(), 2);
    assert_eq!(
        log.unacknowledged().map(|h| h.dot).collect::<Vec<_>>(),
        [dot(ME, 3)]
    );
    assert_eq!(log.acknowledge(9), Err(OwnError::UnknownOp));
    assert_eq!(log.record_sent(9), Err(OwnError::UnknownOp));
}

#[test]
fn a_send_needs_a_restore_generation() {
    let mut log = own_log(2);
    assert_eq!(log.record_sent(1), Err(OwnError::NoGeneration));
    log.observe_generation(generation(1));
    log.record_sent(1).unwrap();
    // An acknowledged op needs no entry.
    log.acknowledge(1).unwrap();
    log.record_sent(1).unwrap();
    assert!(!log.may_have_been_served(2));
}

#[test]
fn may_have_been_served() {
    let mut log = own_log(3);
    log.observe_generation(generation(1));
    // 1 acknowledged; 2 sent without an answer; 3 never sent.
    log.record_sent(1).unwrap();
    log.acknowledge(1).unwrap();
    log.record_sent(2).unwrap();
    assert!(log.may_have_been_served(1));
    assert!(!log.may_have_been_served(2));
    assert!(!log.may_have_been_served(3));
    // A resend keeps the first send's generation.
    log.observe_generation(generation(2));
    log.record_sent(2).unwrap();
    log.record_sent(3).unwrap();
    assert!(log.may_have_been_served(2));
    assert!(!log.may_have_been_served(3));
    // An acknowledgement clears the entry.
    log.acknowledge(2).unwrap();
    assert!(log.may_have_been_served(2));
    log.observe_generation(generation(3));
    assert!(log.may_have_been_served(3));
}

/// Own ops 1..=5 on epoch 1, except 5 on epoch 2.
fn stale_fixture() -> VaultLog {
    let mut log = own_log(4);
    let mut five = op(ME, 5, 4, X, &[(ME, 4)]);
    five.vault_key_epoch = 2;
    log.record_own_op(five).unwrap();
    log
}

#[test]
fn a_stale_answer_reissues_what_the_server_never_stored() {
    let mut log = stale_fixture();
    log.observe_generation(generation(1));
    log.acknowledge(1).unwrap();
    // 2 and 3 sent without an answer at generation 1; the answer for 2 is "stale", still at
    // generation 1: the server never stored 2 or 3.
    log.record_sent(2).unwrap();
    log.record_sent(3).unwrap();
    let plan = log.stale_plan(2, 2).unwrap();
    assert_eq!(plan.reissue, [dot(ME, 2), dot(ME, 3), dot(ME, 4)]);
    assert!(plan.republish.is_empty());
    assert_eq!(log.stale_plan(5, 2), Err(OwnError::NotStale));
    assert_eq!(log.stale_plan(2, 1), Err(OwnError::NotStale));
    assert_eq!(log.stale_plan(7, 2), Err(OwnError::UnknownOp));
}

#[test]
fn a_stale_answer_after_a_restore_republishes_what_may_have_been_served() {
    let mut log = stale_fixture();
    log.observe_generation(generation(1));
    log.acknowledge(1).unwrap();
    log.record_sent(2).unwrap();
    // A restore: the answer carries a new generation. 3 is first sent after it.
    log.observe_generation(generation(2));
    log.record_sent(3).unwrap();
    let plan = log.stale_plan(2, 2).unwrap();
    assert_eq!(plan.republish, [dot(ME, 2)]);
    assert_eq!(plan.reissue, [dot(ME, 3), dot(ME, 4)]);
    // An acknowledged op the restored server rejects is re-published.
    let plan = log.stale_plan(1, 2).unwrap();
    assert_eq!(plan.republish, [dot(ME, 1), dot(ME, 2)]);
}

#[test]
fn a_reissue_changes_only_the_epoch() {
    let mut log = own_log(3);
    log.observe_generation(generation(1));
    log.acknowledge(1).unwrap();
    log.record_sent(2).unwrap();
    let mut reissued = op(ME, 2, 1, X, &[(ME, 1)]);
    reissued.vault_key_epoch = 2;
    // Another field differs.
    let mut wrong = reissued.clone();
    wrong.hlc = Hlc::from_u64(1);
    assert_eq!(log.reissue_own_op(wrong), Err(OwnError::NotAReissue));
    // The epoch does not rise.
    assert_eq!(
        log.reissue_own_op(op(ME, 2, 1, X, &[(ME, 1)])),
        Err(OwnError::NotAReissue)
    );
    assert_eq!(
        log.reissue_own_op(op(ME, 1, 0, X, &[])),
        Err(OwnError::Acknowledged)
    );
    assert_eq!(
        log.reissue_own_op(op(ME, 7, 3, X, &[])),
        Err(OwnError::UnknownOp)
    );
    assert_eq!(
        log.reissue_own_op(op(A, 2, 1, X, &[])),
        Err(OwnError::NotOwnDevice)
    );
    log.reissue_own_op(reissued.clone()).unwrap();
    assert_eq!(log.header(dot(ME, 2)), Some(&reissued));
    // The re-issued op was never sent: a restore now does not make it "maybe served".
    log.observe_generation(generation(2));
    assert!(!log.may_have_been_served(2));
    // An op sent before a restore is never re-issued.
    log.record_sent(3).unwrap();
    log.observe_generation(generation(3));
    let mut three = op(ME, 3, 2, X, &[(ME, 2)]);
    three.vault_key_epoch = 2;
    assert_eq!(log.reissue_own_op(three), Err(OwnError::MayHaveBeenServed));
}

#[test]
fn restore_generation_bytes_and_debug() {
    let g = RestoreGeneration::from_bytes([0xab; 16]);
    assert_eq!(g.to_bytes(), [0xab; 16]);
    assert_eq!(
        format!("{g:?}"),
        "RestoreGeneration(abababababababababababababababab)"
    );
}

// ---------------------------------------------------------------------------------------------
// Server behind
// ---------------------------------------------------------------------------------------------

fn view(state_seq: u64, heads: &VersionVector) -> ServerView<'_> {
    ServerView {
        state_seq,
        heads,
        lacks_wrap: false,
    }
}

#[test]
fn the_server_is_behind_on_each_condition() {
    let mut log = own_log(3);
    log.acknowledge(2).unwrap();
    let ops: Vec<ServedOp> = a_chain(4, X).into_iter().map(verified).collect();
    sync(&mut log, &ops, &[]);
    let b: Vec<ServedOp> = (1..=6)
        .map(|s| verified(op(B, s, s - 1, Y, &[(B, s - 1)])))
        .collect();
    sync(&mut log, &b, &[]);
    // Caught up: own head 2 (acknowledged; 3 not uploaded), A at 4, B at 6.
    let heads = vv(&[(ME, 2), (A, 4), (B, 6)]);
    assert!(log.server_behind(7, view(7, &heads)).is_empty());
    assert!(log.server_behind(7, view(8, &heads)).is_empty());
    assert_eq!(
        log.server_behind(7, view(6, &heads)),
        [Behind::StateSeq {
            server: 6,
            accepted: 7
        }]
    );
    let heads = vv(&[(ME, 1), (A, 3), (B, 5)]);
    assert_eq!(
        log.server_behind(7, view(7, &heads)),
        [
            Behind::Head {
                device: device(A),
                server: 3,
                local: 4
            },
            Behind::Head {
                device: device(B),
                server: 5,
                local: 6
            },
            Behind::OwnHead {
                server: 1,
                acknowledged: 2
            },
        ]
    );
    let heads = vv(&[(ME, 2), (A, 4), (B, 6)]);
    let lacking = ServerView {
        lacks_wrap: true,
        ..view(7, &heads)
    };
    assert_eq!(log.server_behind(7, lacking), [Behind::Wrap]);
}

#[test]
fn every_entry_is_capped_at_the_cutoff() {
    let mut log = new_log();
    let ops: Vec<ServedOp> = a_chain(4, X).into_iter().map(verified).collect();
    sync(&mut log, &ops, &[]);
    // A revocation signed on a server that held A only up to 2.
    log.learn_revocation(device(A), 2);
    let heads = vv(&[(A, 2)]);
    assert!(log.server_behind(1, view(1, &heads)).is_empty());
    let heads = vv(&[(A, 1)]);
    assert_eq!(
        log.server_behind(1, view(1, &heads)),
        [Behind::Head {
            device: device(A),
            server: 1,
            local: 2
        }]
    );
}

#[test]
fn the_device_leaves_read_only_once_the_server_catches_up() {
    let mut log = new_log();
    let ops: Vec<ServedOp> = a_chain(2, X).into_iter().map(verified).collect();
    sync(&mut log, &ops, &[]);
    let behind = vv(&[(A, 1)]);
    assert!(!log.server_behind(1, view(1, &behind)).is_empty());
    // The healing request re-publishes A:2; the server's head moves to 2.
    let healed = vv(&[(A, 2)]);
    assert!(log.server_behind(1, view(1, &healed)).is_empty());
}

// ---------------------------------------------------------------------------------------------
// Answers and the restore generation, revocation learned late
// ---------------------------------------------------------------------------------------------

/// ADR 0021 §2: an op answered before any restore is no longer "sent without an answer", so a
/// restore observed later does not make it "maybe served": it is re-issued, not re-published.
#[test]
fn an_op_refused_before_a_restore_is_reissued_after_it() {
    let mut log = stale_fixture();
    log.observe_generation(generation(1));
    log.acknowledge(1).unwrap();
    // 2 sent at G1 and refused at G1 (not stored); 3 sent at G1 and never answered.
    log.record_sent(2).unwrap();
    log.record_sent(3).unwrap();
    log.record_answered(2, generation(1)).unwrap();
    assert!(!log.may_have_been_served(2));
    // A restore: a Fetch carries G2. 2 is sent again at G2 and rejected as stale at G2.
    log.observe_generation(generation(2));
    assert!(!log.may_have_been_served(2));
    assert!(log.may_have_been_served(3));
    log.record_sent(2).unwrap();
    log.record_answered(2, generation(2)).unwrap();
    let plan = log.stale_plan(2, 2).unwrap();
    assert_eq!(plan.reissue, [dot(ME, 2), dot(ME, 4)]);
    assert_eq!(plan.republish, [dot(ME, 3)]);
    let mut reissued = op(ME, 2, 1, X, &[(ME, 1)]);
    reissued.vault_key_epoch = 2;
    log.reissue_own_op(reissued).unwrap();
    assert_eq!(
        log.record_answered(9, generation(2)),
        Err(OwnError::UnknownOp)
    );
}

/// The stale answer arrives at G1, then a Fetch carries G2 before the client plans: the
/// answer, recorded when it arrived, keeps the op out of "maybe served".
#[test]
fn a_stale_answer_then_a_restore_still_reissues() {
    let mut log = stale_fixture();
    log.observe_generation(generation(1));
    log.acknowledge(1).unwrap();
    log.record_sent(2).unwrap();
    log.record_answered(2, generation(1)).unwrap();
    log.observe_generation(generation(2));
    let plan = log.stale_plan(2, 2).unwrap();
    assert_eq!(plan.reissue, [dot(ME, 2), dot(ME, 3), dot(ME, 4)]);
    assert!(plan.republish.is_empty());
}

/// An answer under another generation than the first send's keeps the entry: a restore came
/// between, and the op may have been stored and served before it.
#[test]
fn an_answer_after_a_restore_keeps_the_entry() {
    let mut log = stale_fixture();
    log.observe_generation(generation(1));
    log.record_sent(1).unwrap();
    log.observe_generation(generation(2));
    log.record_answered(1, generation(2)).unwrap();
    assert!(log.may_have_been_served(1));
    let plan = log.stale_plan(1, 2).unwrap();
    assert_eq!(plan.republish, [dot(ME, 1)]);
}

/// The revocation is learned after the predecessor was accepted: the waiting op is reported
/// all the same, whatever the order.
#[test]
fn a_revocation_learned_after_the_commit_reports_the_same_missing_predecessor() {
    let a: Vec<ServedOp> = a_chain(2, X)
        .into_iter()
        .map(verified)
        .chain([with(a_chain(3, X)[2].clone(), BodyStatus::Waiting)])
        .collect();
    let b1 = verified(op(B, 1, 0, X, &[(A, 3)]));
    let ops: Vec<ServedOp> = a.into_iter().chain([b1]).collect();
    let expected = [Report::MissingPredecessor {
        waiting: dot(B, 1),
        missing: dot(A, 3),
    }];
    // Revocation after the commit.
    let mut log = new_log();
    let (_, _, deliveries) = sync(&mut log, &ops, &[]);
    assert_eq!(dots(&deliveries), [dot(A, 1), dot(A, 2)]);
    let revocation = log.learn_revocation(device(A), 2);
    assert_eq!(revocation.rejected, [dot(A, 3)]);
    assert_eq!(log.complete_fetch_reports(), expected);
    // Revocation before the commit.
    let mut log = new_log();
    log.learn_revocation(device(A), 2);
    sync(&mut log, &ops, &[]);
    assert_eq!(log.complete_fetch_reports(), expected);
}
