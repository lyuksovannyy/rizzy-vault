//! Fuzzes `rizzy-sync`'s compaction rules (ADR 0021 §2–§4, §9), which the server runs on a
//! client-supplied covered VV and on its own rows, which a damaged database can make
//! inconsistent. None may panic, and each answer must keep its rule's guarantee.
//!
//! The input is read as one item's rows over four devices, so that coverage between snapshots
//! and ops is common: flags, a snapshot author, the heads, a covered VV, revocation cut-offs, up
//! to 7 retained snapshots (store sequences below 16, so repeats occur) and up to 23 ops, each
//! with a body flag. A `seq` byte gives 0–7, or one of the 16 values up to `u64::MAX`. Input
//! that runs out reads as zeros.
//!
//! What runs on each input:
//!
//! - [`clamp`]: every entry is the minimum of the covered entry and the head, so the clamped
//!   VV is at most both.
//! - [`check_snapshot`], author unexpired or expired: an accepted snapshot's author is neither
//!   revoked nor expired, its own entry is at most its head, and every entry, a revoked
//!   device's capped at its cut-off, is at most its head. Each refusal names a check that
//!   fails. The heads stand for an upload's or, inside a healing request, those after the
//!   request's headers: the checks are the same.
//! - [`plan_worker`]: refuses exactly the rows with a repeated store sequence or dot.
//!   Otherwise it deletes only held bodies that the older of the two newest snapshots and two
//!   authors cover, never drops one of the two newest, never lowers a bodiless header's
//!   covering authors below two (or below what it had), and a second run over the result has
//!   nothing to do.
//! - [`select_covers`] over every op's dot: refuses exactly a repeated store sequence.
//!   Otherwise the covers are retained snapshots, newest first, with covers by as many authors
//!   as the retained snapshots have, up to two, for every header, and a header is reported
//!   uncovered exactly when no retained snapshot covers it.
//! - [`check_healing_request`] over every op's dot: accepts exactly when every header has a
//!   cover, and otherwise names the lowest header without one.
//!
//! Not in the CRYPTO.md §15 item 7 list by name; CLAUDE.md requires a target for untrusted
//! input, and the covered VV is the client's claim.
//!
//! ```text
//! cargo +nightly fuzz run sync_compaction
//! ```
#![no_main]

use std::collections::{BTreeMap, BTreeSet};

use libfuzzer_sys::fuzz_target;
use rizzy_core::ids::DeviceId;
use rizzy_sync::compaction::{
    Body, CertificateExpiry, InputError, OpDot, RetainedSnapshot, SnapshotRefusal,
    UncoveredHeader, VaultChains, check_healing_request, check_snapshot, clamp, plan_worker,
    select_covers,
};
use rizzy_sync::dot::Dot;
use rizzy_sync::vv::VersionVector;

/// The id bytes of the four devices: device i is `[IDS[i]; 16]`.
const IDS: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];

/// The fuzz input, read front to back; reads past the end give zeros.
struct Input<'a>(&'a [u8]);

impl Input<'_> {
    /// The next byte, 0 once the input is used up.
    fn byte(&mut self) -> u8 {
        match self.0.split_first() {
            Some((&b, rest)) => {
                self.0 = rest;
                b
            }
            None => 0,
        }
    }

    /// One of the four devices.
    fn device(&mut self) -> DeviceId {
        DeviceId::from_bytes([IDS[usize::from(self.byte() % 4)]; 16])
    }

    /// A sequence number: 0–7 for bytes below 0xf0, else one of the 16 values up to
    /// `u64::MAX`.
    fn seq(&mut self) -> u64 {
        match self.byte() {
            b @ 0xf0.. => u64::MAX - u64::from(0xff - b),
            b => u64::from(b % 8),
        }
    }

    /// A version vector of up to four entries; zero entries are left out.
    fn vv(&mut self) -> VersionVector {
        let mut vv = VersionVector::new();
        for _ in 0..self.byte() % 5 {
            if let Some(dot) = Dot::new(self.device(), self.seq()) {
                vv.add(dot);
            }
        }
        vv
    }
}

/// The number of distinct authors among `snapshots` that cover `dot`.
fn authors<'a>(snapshots: impl IntoIterator<Item = &'a RetainedSnapshot>, dot: Dot) -> usize {
    snapshots
        .into_iter()
        .filter(|s| s.clamped.covers(dot))
        .map(|s| s.author)
        .collect::<BTreeSet<DeviceId>>()
        .len()
}

/// Whether no value repeats.
fn distinct<T: Ord>(values: impl IntoIterator<Item = T>) -> bool {
    let mut seen = BTreeSet::new();
    values.into_iter().all(|v| seen.insert(v))
}

/// A revoked device's entry counted up to its cut-off (ADR 0021 §9 "Server acceptance").
fn counted(cutoffs: &BTreeMap<DeviceId, u64>, device: DeviceId, seq: u64) -> u64 {
    cutoffs.get(&device).map_or(seq, |&cutoff| seq.min(cutoff))
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let flags = input.byte();
    let author = input.device();
    let heads = input.vv();
    let covered = input.vv();
    let mut cutoffs = BTreeMap::new();
    for _ in 0..input.byte() % 3 {
        let device = input.device();
        cutoffs.insert(device, input.seq());
    }
    let mut snapshots = Vec::new();
    for _ in 0..input.byte() % 8 {
        let store_seq = u64::from(input.byte() % 16);
        let author = input.device();
        let clamped = input.vv();
        snapshots.push(RetainedSnapshot {
            store_seq,
            clamped,
            author,
        });
    }
    let mut ops = Vec::new();
    for _ in 0..input.byte() % 24 {
        let b = input.byte();
        let device = DeviceId::from_bytes([IDS[usize::from(b & 3)]; 16]);
        let body = if b & 4 == 0 { Body::Held } else { Body::Absent };
        if let Some(dot) = Dot::new(device, input.seq()) {
            ops.push(OpDot { dot, body });
        }
    }

    // §2: the clamped VV.
    let clamped = clamp(&covered, &heads);
    assert!(clamped <= covered && clamped <= heads);
    for dot in covered.entries() {
        let device = dot.device_id();
        assert_eq!(clamped.get(device), dot.seq().min(heads.get(device)));
    }

    // §9: acceptance of the snapshot (`author`, `covered`).
    let expiry = if flags & 1 == 0 {
        CertificateExpiry::Unexpired
    } else {
        CertificateExpiry::Expired
    };
    let chains = VaultChains {
        heads: &heads,
        cutoffs: &cutoffs,
    };
    match check_snapshot(author, &covered, chains, expiry) {
        Ok(()) => {
            assert!(!cutoffs.contains_key(&author));
            assert_eq!(expiry, CertificateExpiry::Unexpired);
            assert!(covered.get(author) <= heads.get(author));
            for dot in covered.entries() {
                let device = dot.device_id();
                assert!(counted(&cutoffs, device, dot.seq()) <= heads.get(device));
            }
        }
        Err(SnapshotRefusal::AuthorRevoked) => assert!(cutoffs.contains_key(&author)),
        Err(SnapshotRefusal::AuthorExpired) => assert_eq!(expiry, CertificateExpiry::Expired),
        Err(SnapshotRefusal::AuthorEntryAboveHead) => {
            assert!(covered.get(author) > heads.get(author));
        }
        Err(SnapshotRefusal::ClaimsUnheldDots { device_id }) => {
            let claimed = counted(&cutoffs, device_id, covered.get(device_id));
            assert!(claimed > heads.get(device_id));
        }
        Err(other) => panic!("a refusal this target does not know: {other}"),
    }

    let store_seqs_distinct = distinct(snapshots.iter().map(|s| s.store_seq));
    let mut newest: Vec<u64> = snapshots.iter().map(|s| s.store_seq).collect();
    newest.sort_unstable();
    let older_of_two_newest = newest.len().checked_sub(2).and_then(|i| newest.get(i));
    let older_clamped = snapshots
        .iter()
        .find(|s| Some(&s.store_seq) == older_of_two_newest)
        .map(|s| &s.clamped);
    let newest = newest.get(newest.len().saturating_sub(2)..).unwrap_or_default();

    // §3: R1 and R3.
    match plan_worker(&snapshots, &ops) {
        Ok(plan) => {
            assert!(store_seqs_distinct && distinct(ops.iter().map(|op| op.dot)));
            assert!(plan.drop_snapshots.iter().all(|seq| !newest.contains(seq)));
            for &dot in &plan.delete_bodies {
                assert!(ops.contains(&OpDot {
                    dot,
                    body: Body::Held
                }));
                assert!(older_clamped.is_some_and(|older| older.covers(dot)));
                assert!(authors(&snapshots, dot) >= 2);
            }
            let kept: Vec<RetainedSnapshot> = snapshots
                .iter()
                .filter(|s| !plan.drop_snapshots.contains(&s.store_seq))
                .cloned()
                .collect();
            let after: Vec<OpDot> = ops
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
            for op in after.iter().filter(|op| op.body == Body::Absent) {
                let before = authors(&snapshots, op.dot);
                assert!(authors(&kept, op.dot) >= before.min(2));
            }
            let again = plan_worker(&kept, &after).expect("the rows stay consistent");
            assert!(again.is_empty());
        }
        Err(InputError::DuplicateStoreSeq(seq)) => {
            assert!(snapshots.iter().filter(|s| s.store_seq == seq).count() > 1);
        }
        Err(InputError::DuplicateOp(dot)) => {
            assert!(store_seqs_distinct);
            assert!(ops.iter().filter(|op| op.dot == dot).count() > 1);
        }
        Err(other) => panic!("an input error this target does not know: {other}"),
    }

    // §4: covers for every op's dot as a bodiless header.
    let headers: Vec<Dot> = ops.iter().map(|op| op.dot).collect();
    match select_covers(&snapshots, &headers) {
        Ok(selection) => {
            assert!(store_seqs_distinct);
            assert!(selection.covers.windows(2).all(|w| w.first() > w.last()));
            let served: Vec<&RetainedSnapshot> = selection
                .covers
                .iter()
                .map(|seq| {
                    snapshots
                        .iter()
                        .find(|s| s.store_seq == *seq)
                        .expect("a cover is a retained snapshot")
                })
                .collect();
            for &dot in &headers {
                let available = authors(&snapshots, dot);
                assert!(authors(served.iter().copied(), dot) >= available.min(2));
                assert_eq!(selection.uncovered.contains(&dot), available == 0);
            }
        }
        Err(InputError::DuplicateStoreSeq(_)) => assert!(!store_seqs_distinct),
        Err(other) => panic!("an input error this target does not know: {other}"),
    }

    // §9: a healing request storing every op's dot without a body.
    let lowest_uncovered = headers
        .iter()
        .copied()
        .filter(|&dot| !snapshots.iter().any(|s| s.clamped.covers(dot)))
        .min();
    assert_eq!(
        check_healing_request(&snapshots, &headers).err(),
        lowest_uncovered.map(|dot| UncoveredHeader { dot })
    );
});
