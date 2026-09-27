//! Unit tests of the compaction rules (ADR 0021 §2–§4, §9).
//!
//! - §2: the clamp, with a known answer of the clamped VV as persisted.
//! - §3 R1: fewer than two snapshots, one author only, the older of the two newest, bodiless
//!   headers left alone. The spike's results note that in a linear history R1 reduces to "two
//!   authors cover", so `r1_requires_the_older_of_the_two_newest` pins that clause.
//! - §3 R3: the two newest always stay, drops of unneeded snapshots, a drop that would leave
//!   one author, a healed header's sole cover, the re-test after each drop, three authors cut
//!   to two, and R1's deletions counted in the same run.
//! - §4: newest first, a second author added, no third author, one author when only one
//!   covers, per-header selection, an uncovered header reported.
//! - §9: claims above the heads, for an upload and inside a healing request (against the heads
//!   after its headers, a request with no headers included), the revoked device's cap, the
//!   author's own entry, revoked and expired authors, the healing request's covers.
//! - Inconsistent rows are refused, never a panic.
//! - Properties: [`plan_worker`] equals the literal transcription of R1 and R3 (with R3's
//!   restart from the oldest after each drop), applying its plan leaves nothing to do, and
//!   [`select_covers`] equals the literal transcription of §4; arbitrary inputs (duplicates,
//!   `u64::MAX` entries) never panic.

use std::collections::BTreeMap;
use std::ops::RangeInclusive;

use proptest::prelude::*;

use super::sim::{literal_covers, literal_worker};
use super::*;

const A: u8 = 0xa1;
const B: u8 = 0xb2;
const C: u8 = 0xc3;
const R: u8 = 0x5e;

/// A device id whose 16 bytes are all `b`.
fn device(b: u8) -> DeviceId {
    DeviceId::from_bytes([b; 16])
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

fn snap(store_seq: u64, author: u8, clamped: &[(u8, u64)]) -> RetainedSnapshot {
    RetainedSnapshot {
        store_seq,
        clamped: vv(clamped),
        author: device(author),
    }
}

fn held(b: u8, seq: u64) -> OpDot {
    OpDot {
        dot: dot(b, seq),
        body: Body::Held,
    }
}

fn absent(b: u8, seq: u64) -> OpDot {
    OpDot {
        dot: dot(b, seq),
        body: Body::Absent,
    }
}

fn chain(b: u8, seqs: RangeInclusive<u64>, body: Body) -> Vec<OpDot> {
    seqs.map(|seq| OpDot {
        dot: dot(b, seq),
        body,
    })
    .collect()
}

#[test]
fn clamp_is_the_entrywise_minimum_with_the_heads() {
    let covered = vv(&[(A, 5), (B, u64::MAX), (C, 3)]);
    let heads = vv(&[(A, 7), (B, 4)]);
    let clamped = clamp(&covered, &heads);
    assert_eq!(clamped, vv(&[(A, 5), (B, 4)]));
    // Persisted in the canonical VV encoding, the zero entry for C left out (ADR 0021 §2).
    let mut expected = vec![0x00, 0x02];
    expected.extend_from_slice(&[A; 16]);
    expected.extend_from_slice(&5u64.to_be_bytes());
    expected.extend_from_slice(&[B; 16]);
    expected.extend_from_slice(&4u64.to_be_bytes());
    assert_eq!(clamped.to_vec().unwrap(), expected);
    // Nothing held: the clamp covers nothing, whatever the claim.
    assert!(clamp(&covered, &VersionVector::new()).is_empty());
    // A claim within the heads is kept as is.
    assert_eq!(clamp(&vv(&[(A, 2)]), &heads), vv(&[(A, 2)]));
}

#[test]
fn a_retained_snapshot_covers_by_its_clamped_vv() {
    let s = snap(1, A, &[(A, 3)]);
    assert!(s.covers(dot(A, 1)) && s.covers(dot(A, 3)));
    assert!(!s.covers(dot(A, 4)) && !s.covers(dot(B, 1)));
}

#[test]
fn r1_deletes_nothing_with_fewer_than_two_snapshots() {
    let ops = chain(A, 1..=3, Body::Held);
    assert!(plan_worker(&[], &ops).unwrap().is_empty());
    assert!(
        plan_worker(&[snap(1, A, &[(A, 3)])], &ops)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn r1_needs_covers_by_two_authors() {
    // An item snapshotted by one device only is never compacted (owner decision 1).
    let snaps = [
        snap(1, A, &[(A, 2)]),
        snap(2, A, &[(A, 3)]),
        snap(3, A, &[(A, 3)]),
    ];
    let plan = plan_worker(&snaps, &chain(A, 1..=3, Body::Held)).unwrap();
    assert!(plan.delete_bodies.is_empty());
    // Nothing is bodiless, so R3 drops the older snapshot.
    assert_eq!(plan.drop_snapshots, [1]);
}

#[test]
fn r1_deletes_what_the_older_of_the_two_newest_and_two_authors_cover() {
    // A linear history: S1 by A covers A1–A3 and B1–B2, S2 by B covers A1–A5 and B1–B4. As
    // under ADR 0012, the bodies the older one covers go, here because two authors cover them.
    let snaps = [snap(2, B, &[(A, 5), (B, 4)]), snap(1, A, &[(A, 3), (B, 2)])];
    let mut ops = chain(B, 1..=4, Body::Held);
    ops.extend(chain(A, 1..=5, Body::Held));
    let plan = plan_worker(&snaps, &ops).unwrap();
    assert_eq!(
        plan.delete_bodies,
        [dot(A, 1), dot(A, 2), dot(A, 3), dot(B, 1), dot(B, 2)]
    );
    assert!(plan.drop_snapshots.is_empty());
}

#[test]
fn r1_requires_the_older_of_the_two_newest() {
    // A1 is covered by two authors (S1 by A, S3 by B), but the older of the two newest, S2,
    // does not cover it: its body stays. B1 is covered by B only.
    let mut snaps = vec![
        snap(1, A, &[(A, 1)]),
        snap(2, B, &[(B, 1)]),
        snap(3, B, &[(A, 1), (B, 1)]),
    ];
    let ops = [held(A, 1), held(B, 1)];
    assert!(plan_worker(&snaps, &ops).unwrap().delete_bodies.is_empty());
    // A newer snapshot by C makes S3 the older of the two newest: both bodies go, and R3 then
    // drops S1 and S2, whose authors still cover through S3 and S4.
    snaps.push(snap(4, C, &[(A, 1), (B, 1)]));
    let plan = plan_worker(&snaps, &ops).unwrap();
    assert_eq!(plan.delete_bodies, [dot(A, 1), dot(B, 1)]);
    assert_eq!(plan.drop_snapshots, [1, 2]);
}

#[test]
fn r1_leaves_bodiless_headers_alone() {
    let snaps = [snap(1, A, &[(A, 2)]), snap(2, B, &[(A, 2)])];
    let ops = [absent(A, 1), held(A, 2)];
    assert_eq!(
        plan_worker(&snaps, &ops).unwrap().delete_bodies,
        [dot(A, 2)]
    );
}

#[test]
fn r3_always_keeps_the_two_newest() {
    let snaps = [snap(1, A, &[]), snap(2, A, &[])];
    assert!(plan_worker(&snaps, &[]).unwrap().is_empty());
}

#[test]
fn r3_drops_older_snapshots_no_bodiless_header_needs() {
    // Linear, alternating authors.
    let snaps = [
        snap(1, A, &[(A, 1)]),
        snap(2, B, &[(A, 2)]),
        snap(3, A, &[(A, 3)]),
        snap(4, B, &[(A, 4)]),
    ];
    let plan = plan_worker(&snaps, &chain(A, 1..=4, Body::Held)).unwrap();
    assert_eq!(plan.delete_bodies, [dot(A, 1), dot(A, 2), dot(A, 3)]);
    // S3 (A) and S4 (B) cover every bodiless header by two authors on their own.
    assert_eq!(plan.drop_snapshots, [1, 2]);
}

#[test]
fn r3_keeps_a_snapshot_whose_drop_would_leave_one_author() {
    // A1 is bodiless and covered by S1 (A) and S4 (B) only.
    let snaps = [
        snap(1, A, &[(A, 1)]),
        snap(2, C, &[]),
        snap(3, C, &[]),
        snap(4, B, &[(A, 1)]),
    ];
    let plan = plan_worker(&snaps, &[absent(A, 1)]).unwrap();
    assert_eq!(plan.drop_snapshots, [2]);
}

#[test]
fn r3_keeps_the_sole_cover_of_a_healed_header() {
    // A healing request stored A1–A2 without bodies behind the healer C's snapshot alone
    // (owner decision 8); B's two snapshots cover only B's ops, which keep their bodies.
    let snaps = [
        snap(1, C, &[(A, 2)]),
        snap(2, B, &[(B, 1)]),
        snap(3, B, &[(B, 2)]),
    ];
    let mut ops = chain(A, 1..=2, Body::Absent);
    ops.extend(chain(B, 1..=2, Body::Held));
    assert!(plan_worker(&snaps, &ops).unwrap().is_empty());
}

#[test]
fn r3_retests_after_each_drop() {
    // A1 is bodiless and covered by S1 and S2, both by A; the two newest do not cover it.
    // Oldest first, S1 goes (S2 still covers by A); re-tested, S2 then stays. Testing both
    // against the set before any drop would drop both and leave A1 without a cover.
    let snaps = [
        snap(1, A, &[(A, 1)]),
        snap(2, A, &[(A, 1)]),
        snap(3, B, &[(B, 1)]),
        snap(4, B, &[(B, 1)]),
    ];
    let plan = plan_worker(&snaps, &[absent(A, 1), held(B, 1)]).unwrap();
    assert!(plan.delete_bodies.is_empty());
    assert_eq!(plan.drop_snapshots, [1]);
}

#[test]
fn r3_cuts_three_authors_to_two() {
    let snaps = [
        snap(1, A, &[(A, 1)]),
        snap(2, B, &[(A, 1)]),
        snap(3, C, &[(A, 1)]),
        snap(4, B, &[]),
        snap(5, C, &[]),
    ];
    let plan = plan_worker(&snaps, &[absent(A, 1)]).unwrap();
    assert_eq!(plan.drop_snapshots, [1]);
}

#[test]
fn r3_counts_the_bodies_r1_deletes_in_the_same_run() {
    // R1 deletes A1 behind S2, the older of the two newest, with S1 as the second author. S1
    // then stays: dropping it would leave A1 with B's cover alone.
    let snaps = [
        snap(1, A, &[(A, 1)]),
        snap(2, B, &[(A, 1)]),
        snap(3, C, &[]),
    ];
    let plan = plan_worker(&snaps, &[held(A, 1)]).unwrap();
    assert_eq!(plan.delete_bodies, [dot(A, 1)]);
    assert!(plan.drop_snapshots.is_empty());
}

#[test]
fn covers_are_taken_newest_first_by_two_authors() {
    let snaps = [
        snap(1, A, &[(A, 2)]),
        snap(2, B, &[(A, 2)]),
        snap(3, B, &[(A, 2)]),
    ];
    let sel = select_covers(&snaps, &[dot(A, 1), dot(A, 2)]).unwrap();
    // S3 (B) first; S2 adds no author; S1 adds A.
    assert_eq!(sel.covers, [3, 1]);
    assert!(sel.uncovered.is_empty());
}

#[test]
fn covers_add_no_third_author() {
    let snaps = [
        snap(1, A, &[(A, 1)]),
        snap(2, B, &[(A, 1)]),
        snap(3, C, &[(A, 1)]),
    ];
    let sel = select_covers(&snaps, &[dot(A, 1)]).unwrap();
    assert_eq!(sel.covers, [3, 2]);
}

#[test]
fn covers_serve_one_author_when_only_one_covers() {
    let snaps = [
        snap(1, A, &[(A, 1)]),
        snap(2, A, &[(A, 1)]),
        snap(3, B, &[(B, 1)]),
    ];
    let sel = select_covers(&snaps, &[dot(A, 1)]).unwrap();
    assert_eq!(sel.covers, [2]);
}

#[test]
fn covers_are_chosen_per_header() {
    // S3 (A) is the only cover of B1; S2 (B) and S1 (A) cover A1.
    let snaps = [
        snap(1, A, &[(A, 1)]),
        snap(2, B, &[(A, 1)]),
        snap(3, A, &[(B, 1)]),
    ];
    let sel = select_covers(&snaps, &[dot(B, 1), dot(A, 1), dot(B, 1)]).unwrap();
    assert_eq!(sel.covers, [3, 2, 1]);
}

#[test]
fn an_uncovered_header_is_reported_never_invented() {
    let snaps = [snap(1, A, &[(A, 1)]), snap(2, B, &[(A, 1)])];
    let sel = select_covers(&snaps, &[dot(A, 1), dot(B, 1)]).unwrap();
    assert_eq!(sel.covers, [2, 1]);
    assert_eq!(sel.uncovered, [dot(B, 1)]);
    // No bodiless header, no cover.
    assert_eq!(
        select_covers(&snaps, &[]).unwrap(),
        CoverSelection::default()
    );
}

/// The chains view of the heads and cut-offs.
fn chains<'a>(heads: &'a VersionVector, cutoffs: &'a BTreeMap<DeviceId, u64>) -> VaultChains<'a> {
    VaultChains { heads, cutoffs }
}

#[test]
fn an_upload_claims_only_held_dots() {
    let heads = vv(&[(A, 5), (B, 3)]);
    let none = BTreeMap::new();
    let check = |heads: &VersionVector, covered: &[(u8, u64)]| {
        check_snapshot(
            device(A),
            &vv(covered),
            chains(heads, &none),
            CertificateExpiry::Unexpired,
        )
    };
    assert_eq!(check(&heads, &[(A, 5), (B, 3)]), Ok(()));
    assert_eq!(check(&heads, &[(B, 1)]), Ok(()));
    let unheld = |b| {
        Err(SnapshotRefusal::ClaimsUnheldDots {
            device_id: device(b),
        })
    };
    assert_eq!(check(&heads, &[(A, 5), (B, 4)]), unheld(B));
    assert_eq!(check(&heads, &[(A, 5), (C, 1)]), unheld(C));
    assert_eq!(check(&heads, &[(B, u64::MAX), (C, 1)]), unheld(B));
}

#[test]
fn a_healing_requests_snapshot_claims_only_the_heads_after_its_headers() {
    // The merge spike's reading of §9: inside a healing request, check 3 runs against the heads
    // after the request's headers. Before the request the heads are A5, B3; it stores B4–B6.
    let none = BTreeMap::new();
    let after = vv(&[(A, 5), (B, 6)]);
    let check = |heads: &VersionVector, covered: &[(u8, u64)]| {
        check_snapshot(
            device(A),
            &vv(covered),
            chains(heads, &none),
            CertificateExpiry::Unexpired,
        )
    };
    assert_eq!(check(&after, &[(A, 5), (B, 6)]), Ok(()));
    let unheld = |b| {
        Err(SnapshotRefusal::ClaimsUnheldDots {
            device_id: device(b),
        })
    };
    assert_eq!(check(&after, &[(A, 5), (B, 7)]), unheld(B));
    assert_eq!(check(&after, &[(A, 5), (B, u64::MAX), (C, 1)]), unheld(B));
    assert_eq!(check(&after, &[(A, 5), (B, 6), (C, 1)]), unheld(C));
    // A request with no headers leaves the heads as they were, so it is no way around
    // owner decision 4's refusal.
    let unchanged = vv(&[(A, 5), (B, 3)]);
    assert_eq!(check(&unchanged, &[(A, 5), (B, 4)]), unheld(B));
    assert_eq!(check(&unchanged, &[(C, u64::MAX)]), unheld(C));
}

#[test]
fn a_revoked_devices_entry_counts_up_to_its_cutoff() {
    let heads = vv(&[(A, 5), (R, 7)]);
    let cutoffs = BTreeMap::from([(device(R), 7)]);
    let check = |heads: &VersionVector, covered: &[(u8, u64)]| {
        check_snapshot(
            device(A),
            &vv(covered),
            chains(heads, &cutoffs),
            CertificateExpiry::Unexpired,
        )
    };
    assert_eq!(check(&heads, &[(A, 5), (R, 100)]), Ok(()));
    assert_eq!(check(&heads, &[(R, u64::MAX)]), Ok(()));
    // A restored server whose head for R is below the cut-off.
    let restored = vv(&[(A, 5), (R, 4)]);
    assert_eq!(check(&restored, &[(R, 4)]), Ok(()));
    assert_eq!(
        check(&restored, &[(R, 5)]),
        Err(SnapshotRefusal::ClaimsUnheldDots {
            device_id: device(R)
        })
    );
}

#[test]
fn the_authors_own_entry_never_exceeds_its_head() {
    let heads = vv(&[(A, 5)]);
    let none = BTreeMap::new();
    for (author, covered) in [
        (A, vv(&[(A, 6)])),
        (A, vv(&[(A, u64::MAX)])),
        (B, vv(&[(B, 1)])),
    ] {
        assert_eq!(
            check_snapshot(
                device(author),
                &covered,
                chains(&heads, &none),
                CertificateExpiry::Unexpired,
            ),
            Err(SnapshotRefusal::AuthorEntryAboveHead)
        );
    }
}

#[test]
fn revoked_and_expired_authors_publish_no_new_snapshots() {
    let heads = vv(&[(A, 5), (R, 7)]);
    let cutoffs = BTreeMap::from([(device(R), 7)]);
    assert_eq!(
        check_snapshot(
            device(R),
            &vv(&[(R, 7)]),
            chains(&heads, &cutoffs),
            CertificateExpiry::Unexpired,
        ),
        Err(SnapshotRefusal::AuthorRevoked)
    );
    assert_eq!(
        check_snapshot(
            device(A),
            &vv(&[(A, 5)]),
            chains(&heads, &cutoffs),
            CertificateExpiry::Expired,
        ),
        Err(SnapshotRefusal::AuthorExpired)
    );
}

#[test]
fn a_healing_request_needs_a_cover_for_each_bodiless_header() {
    // After a restore the server's head for A is 3. The request stores A4–A6 without bodies,
    // then a fresh snapshot by B, clamped after those headers.
    let heads_after = vv(&[(A, 6), (B, 2)]);
    let old = snap(1, C, &[(A, 3), (B, 2)]);
    let stored = [dot(A, 4), dot(A, 5), dot(A, 6)];
    let fresh = |covered: &[(u8, u64)]| RetainedSnapshot {
        store_seq: 9,
        clamped: clamp(&vv(covered), &heads_after),
        author: device(B),
    };
    assert_eq!(
        check_healing_request(&[old.clone(), fresh(&[(A, 6), (B, 2)])], &stored),
        Ok(())
    );
    // A fresh snapshot that stops at A5 leaves A6 without a cover: the whole request goes.
    assert_eq!(
        check_healing_request(&[old.clone(), fresh(&[(A, 5)])], &stored),
        Err(UncoveredHeader { dot: dot(A, 6) })
    );
    // Snapshots stored before the request are clamped below every header it stores.
    assert_eq!(
        check_healing_request(&[old], &stored),
        Err(UncoveredHeader { dot: dot(A, 4) })
    );
    assert_eq!(check_healing_request(&[], &[]), Ok(()));
}

#[test]
fn inconsistent_rows_are_refused() {
    let twice = [snap(1, A, &[]), snap(1, B, &[])];
    assert_eq!(
        plan_worker(&twice, &[]),
        Err(InputError::DuplicateStoreSeq(1))
    );
    assert_eq!(
        select_covers(&twice, &[dot(A, 1)]),
        Err(InputError::DuplicateStoreSeq(1))
    );
    assert_eq!(
        plan_worker(&[], &[held(A, 1), absent(A, 1)]),
        Err(InputError::DuplicateOp(dot(A, 1)))
    );
}

#[test]
fn display_texts_name_no_content() {
    assert_eq!(
        InputError::DuplicateStoreSeq(7).to_string(),
        "two retained snapshots with store sequence 7"
    );
    assert_eq!(
        InputError::DuplicateOp(dot(A, 1)).to_string(),
        "the same op dot given twice"
    );
    for refusal in [
        SnapshotRefusal::AuthorRevoked,
        SnapshotRefusal::AuthorExpired,
        SnapshotRefusal::AuthorEntryAboveHead,
        SnapshotRefusal::ClaimsUnheldDots {
            device_id: device(A),
        },
    ] {
        assert!(!refusal.to_string().is_empty());
    }
    assert!(!UncoveredHeader { dot: dot(A, 1) }.to_string().is_empty());
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 1_000,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

const DEVICES: [u8; 3] = [A, B, C];

/// Up to six snapshots with distinct store sequences, in any order, over three devices and
/// clamped entries up to 4; and each device's ops 1–4, each held or not.
fn item() -> impl Strategy<Value = (Vec<RetainedSnapshot>, Vec<OpDot>)> {
    let snapshot = (0..DEVICES.len(), prop::array::uniform3(0u64..=4));
    (
        prop::collection::vec(snapshot, 0..=6),
        Just((1..=12u64).collect::<Vec<_>>()).prop_shuffle(),
        prop::collection::vec(any::<bool>(), 12),
    )
        .prop_map(|(snapshots, store_seqs, bodies)| {
            let snapshots = snapshots
                .into_iter()
                .zip(store_seqs)
                .map(|((author, entries), store_seq)| RetainedSnapshot {
                    store_seq,
                    clamped: DEVICES
                        .iter()
                        .zip(entries)
                        .filter(|&(_, seq)| seq > 0)
                        .map(|(&b, seq)| dot(b, seq))
                        .collect(),
                    author: device(DEVICES[author]),
                })
                .collect();
            let ops = DEVICES
                .iter()
                .flat_map(|&b| (1..=4).map(move |seq| dot(b, seq)))
                .zip(bodies)
                .map(|(dot, held)| OpDot {
                    dot,
                    body: if held { Body::Held } else { Body::Absent },
                })
                .collect();
            (snapshots, ops)
        })
}

/// Applies a plan to the rows, as `worker` would.
fn apply(
    snapshots: &[RetainedSnapshot],
    ops: &[OpDot],
    plan: &WorkerPlan,
) -> (Vec<RetainedSnapshot>, Vec<OpDot>) {
    let snapshots = snapshots
        .iter()
        .filter(|s| !plan.drop_snapshots.contains(&s.store_seq))
        .cloned()
        .collect();
    let ops = ops
        .iter()
        .map(|op| OpDot {
            dot: op.dot,
            body: if plan.delete_bodies.contains(&op.dot) {
                Body::Absent
            } else {
                op.body
            },
        })
        .collect();
    (snapshots, ops)
}

proptest! {
    #![proptest_config(config())]

    /// One pass of R3 equals the rule's "re-tested after each drop" (module docs, "R3 in one
    /// pass"), and R1 equals its text.
    #[test]
    fn worker_equals_the_literal_rules((snapshots, ops) in item()) {
        let plan = plan_worker(&snapshots, &ops).unwrap();
        prop_assert_eq!(&plan, &literal_worker(&snapshots, &ops));
        // Deletions are held bodies; drops are outside the two newest.
        let mut newest: Vec<u64> = snapshots.iter().map(|s| s.store_seq).collect();
        newest.sort_unstable();
        let newest = newest.get(newest.len().saturating_sub(2)..).unwrap_or_default();
        prop_assert!(plan.drop_snapshots.iter().all(|seq| !newest.contains(seq)));
        let was_held = |dot: &Dot| ops.iter().any(|op| op.dot == *dot && op.body == Body::Held);
        prop_assert!(plan.delete_bodies.iter().all(was_held));
        // A second run over the result has nothing left to do.
        let (snapshots, ops) = apply(&snapshots, &ops, &plan);
        prop_assert!(plan_worker(&snapshots, &ops).unwrap().is_empty());
        // Every bodiless header R1 made keeps a cover.
        for dot in &plan.delete_bodies {
            prop_assert!(snapshots.iter().any(|s| s.covers(*dot)));
        }
    }

    /// The covers equal the literal §4 rule, and every header gets covers by as many authors
    /// as the retained snapshots have, up to two.
    #[test]
    fn covers_equal_the_literal_rule((snapshots, ops) in item()) {
        let bodiless: Vec<Dot> = ops.iter().filter(|op| op.body == Body::Absent).map(|op| op.dot).collect();
        let sel = select_covers(&snapshots, &bodiless).unwrap();
        prop_assert_eq!(&sel.covers, &literal_covers(&snapshots, &bodiless));
        for &dot in &bodiless {
            let authors = |seqs: Option<&[u64]>| -> usize {
                snapshots
                    .iter()
                    .filter(|s| seqs.is_none_or(|seqs| seqs.contains(&s.store_seq)) && s.covers(dot))
                    .map(|s| s.author)
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
            };
            let retained = authors(None);
            prop_assert!(authors(Some(&sel.covers)) >= retained.min(2));
            prop_assert_eq!(sel.uncovered.contains(&dot), retained == 0);
        }
    }

    /// Arbitrary rows, duplicates and `u64::MAX` entries included, give an answer or an
    /// [`InputError`], never a panic; and the snapshot check never panics either.
    #[test]
    fn arbitrary_inputs_never_panic(
        snapshots in prop::collection::vec((0u64..4, 0..DEVICES.len(), prop::collection::vec((0..DEVICES.len(), any::<u64>()), 0..4)), 0..6),
        ops in prop::collection::vec((0..DEVICES.len(), prop_oneof![1u64..4, Just(u64::MAX)], any::<bool>()), 0..10),
        heads in prop::collection::vec((0..DEVICES.len(), any::<u64>()), 0..4),
        cutoffs in prop::collection::vec((0..DEVICES.len(), any::<u64>()), 0..2),
        author in 0..DEVICES.len(),
        expired in any::<bool>(),
    ) {
        let to_vv = |entries: &[(usize, u64)]| -> VersionVector {
            entries.iter().filter(|&&(_, seq)| seq > 0).map(|&(d, seq)| dot(DEVICES[d], seq)).collect()
        };
        let snapshots: Vec<RetainedSnapshot> = snapshots
            .iter()
            .map(|(store_seq, author, entries)| RetainedSnapshot {
                store_seq: *store_seq,
                clamped: to_vv(entries),
                author: device(DEVICES[*author]),
            })
            .collect();
        let ops: Vec<OpDot> = ops
            .iter()
            .map(|&(d, seq, held)| OpDot { dot: dot(DEVICES[d], seq), body: if held { Body::Held } else { Body::Absent } })
            .collect();
        let _ = plan_worker(&snapshots, &ops);
        let bodiless: Vec<Dot> = ops.iter().map(|op| op.dot).collect();
        let _ = select_covers(&snapshots, &bodiless);
        let _ = check_healing_request(&snapshots, &bodiless);
        let heads = to_vv(&heads);
        let cutoffs: BTreeMap<DeviceId, u64> = cutoffs.iter().map(|&(d, seq)| (device(DEVICES[d]), seq)).collect();
        let covered = snapshots.first().map(|s| s.clamped.clone()).unwrap_or_default();
        let expiry = if expired { CertificateExpiry::Expired } else { CertificateExpiry::Unexpired };
        let accepted = check_snapshot(device(DEVICES[author]), &covered, chains(&heads, &cutoffs), expiry).is_ok();
        // Accepted, as an upload or inside a healing request: every entry, capped at a revoked
        // device's cut-off, is at most its head, and the author is neither revoked nor expired.
        if accepted {
            prop_assert!(!expired && !cutoffs.contains_key(&device(DEVICES[author])));
            for entry in covered.entries() {
                let cap = cutoffs.get(&entry.device_id()).copied().unwrap_or(u64::MAX);
                prop_assert!(entry.seq().min(cap) <= heads.get(entry.device_id()));
            }
        }
    }
}
