//! Unit tests of the merge: every rule of ADR 0012 §4–§5 and ADR 0018 §3, §6, §9 and §10 the
//! module implements, the named cases of ADR 0018 §12 (concurrent purges in every arrival
//! order, a tombstone with a late value, a re-issued purge's `item_key_id`, a two-value
//! conflict, trash, restore and purge, absorption of a concurrent snapshot, dishonest
//! snapshots), and cases seeded from the merge spike's `absorb`, `faulty-kinds` and `reissue`
//! families (`spikes/merge-model/src/replica.rs` `Fault`, `tests/families.rs`).
//!
//! Every op goes through the real record encoder and parser ([`super::testkit`]).

use super::testkit::{
    Device, Edit, Op, Snap, absorb, deliver, device, dot, item, key_id, record_headers, reference,
    state_bytes, text, vv,
};
use super::*;
use crate::record::{Entry, LiveSnapshot, Register, Tombstone, Value};

/// Every permutation of `0..n` (Heap's algorithm), for small `n`.
fn permutations(n: usize) -> Vec<Vec<usize>> {
    fn heap(k: usize, a: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if k <= 1 {
            out.push(a.clone());
            return;
        }
        for i in 0..k {
            heap(k - 1, a, out);
            if k.is_multiple_of(2) {
                a.swap(i, k - 1);
            } else {
                a.swap(0, k - 1);
            }
        }
    }
    let mut a: Vec<usize> = (0..n).collect();
    let mut out = Vec::new();
    heap(n, &mut a, &mut out);
    out
}

/// A fresh replica that records every header of `all`, then receives `order` one op at a
/// time, each held until it is ready (test-only causal delivery).
fn replay(all: &[Op], order: &[&Op]) -> ItemMerge {
    let mut m = ItemMerge::new(item());
    m.add_item_key(key_id(0x40));
    record_headers(&mut m, all);
    let mut pending: Vec<Op> = Vec::new();
    for op in order {
        pending.push((*op).clone());
        pending = deliver(&mut m, &pending);
    }
    assert!(pending.is_empty(), "ops left waiting");
    m
}

/// The state bytes of a fresh replica fed `ops` in every order: all equal, returned once.
fn same_in_every_order(ops: &[Op]) -> Vec<u8> {
    let reference = state_bytes(&reference(ops));
    for perm in permutations(ops.len()) {
        let order: Vec<&Op> = perm.iter().map(|&i| &ops[i]).collect();
        assert_eq!(
            state_bytes(&replay(ops, &order)),
            reference,
            "order {perm:?}"
        );
    }
    reference
}

/// The current values of `key` on `m`, as `(dot, value bytes)`.
fn current(m: &ItemMerge, key: &str) -> Vec<(Dot, Vec<u8>)> {
    m.field(key).map_or_else(Vec::new, |f| {
        f.current
            .iter()
            .map(|e| (e.dot(), e.value().expose_secret().to_vec()))
            .collect()
    })
}

/// The history of `key` on `m`, as dots.
fn history(m: &ItemMerge, key: &str) -> Vec<Dot> {
    m.field(key)
        .map_or_else(Vec::new, |f| f.history.iter().map(Entry::dot).collect())
}

/// The tombstone of `m`.
fn tomb(m: &ItemMerge) -> (Dot, SymmetricKeyId, VersionVector, Vec<(String, Vec<Dot>)>) {
    match m.snapshot_data().unwrap() {
        Some(SnapshotData::Tombstone(t)) => (
            t.purge_dot(),
            t.item_key_id(),
            t.context().clone(),
            t.late()
                .iter()
                .map(|r| {
                    (
                        r.key().expose_secret().to_owned(),
                        r.entries().iter().map(Entry::dot).collect(),
                    )
                })
                .collect(),
        ),
        _ => panic!("not a tombstone"),
    }
}

/// The absorbed outcome, which the test expects.
fn absorbed(a: &Absorption) -> &Absorbed {
    match &a.outcome {
        AbsorbOutcome::Absorbed(x) => x,
        AbsorbOutcome::Refused(r) => panic!("refused: {r:?}"),
    }
}

/// The refusal, which the test expects.
fn refused(a: &Absorption) -> Refusal {
    match &a.outcome {
        AbsorbOutcome::Refused(r) => *r,
        AbsorbOutcome::Absorbed(_) => panic!("absorbed"),
    }
}

// ---------------------------------------------------------------------------------------------
// ADR 0012 §4 step 4 and §5: registers, history, display.
// ---------------------------------------------------------------------------------------------

#[test]
fn an_edit_moves_the_values_its_context_covers_to_history() {
    let mut a = Device::new(1, 0);
    let create = a.write(&Edit::write(&[
        ("login.password", &text("p1")),
        ("login.username", &text("u")),
    ]));
    let edit = a.write(&Edit::write(&[("login.password", &text("p2"))]));
    assert_eq!(
        current(&a.merge, "login.password"),
        [(edit.dot(), text("p2"))]
    );
    assert_eq!(history(&a.merge, "login.password"), [create.dot()]);
    // Every field edit writes Active; the create's @lifecycle value moved to history.
    assert_eq!(current(&a.merge, LIFECYCLE_KEY), [(edit.dot(), vec![0x01])]);
    assert_eq!(history(&a.merge, LIFECYCLE_KEY), [create.dot()]);
    assert_eq!(
        current(&a.merge, "login.username"),
        [(create.dot(), text("u"))]
    );
    assert_eq!(a.merge.lifecycle(), ItemLifecycle::Active);
    assert_eq!(a.merge.covered(), &vv(&[(1, 2)]));
    // The same state from a fresh replica, and a snapshot that the record layer accepts.
    assert_eq!(state_bytes(&reference(&a.ops())), state_bytes(&a.merge));
    let s = a.snapshot().unwrap();
    assert!(matches!(s.parsed(), SnapshotData::Live(_)));
}

#[test]
fn a_two_value_conflict_is_kept_displayed_and_resolved_by_an_edit() {
    let mut a = Device::new(1, 0);
    let mut b = Device::new(2, 5);
    a.write(&Edit::write(&[("item.name", &text("n0"))]));
    b.receive(&a.ops());
    let ea = a.write(&Edit::write(&[("item.name", &text("from a"))]));
    let eb = b.write(&Edit::write(&[("item.name", &text("from b"))]));
    a.receive(&b.ops());
    b.receive(&a.ops());
    assert_eq!(state_bytes(&a.merge), state_bytes(&b.merge));
    let f = a.merge.field("item.name").unwrap();
    assert_eq!(
        f.current.iter().map(Entry::dot).collect::<Vec<_>>(),
        [ea.dot(), eb.dot()]
    );
    let shown = f.display.unwrap();
    assert!(shown.conflict);
    // B's clock runs 5 ms ahead: its value has the higher (hlc, device_id, seq).
    assert_eq!(f.current[shown.displayed].dot(), eb.dot());
    // Picking a value writes one whose context covers both; the conflict is resolved.
    let pick = a.write(&Edit::write(&[("item.name", &text("from b"))]));
    b.receive(&a.ops());
    assert_eq!(state_bytes(&a.merge), state_bytes(&b.merge));
    assert_eq!(
        current(&b.merge, "item.name"),
        [(pick.dot(), text("from b"))]
    );
    assert_eq!(history(&b.merge, "item.name").len(), 3);
    assert!(
        !b.merge
            .field("item.name")
            .unwrap()
            .display
            .unwrap()
            .conflict
    );
}

#[test]
fn byte_identical_concurrent_values_are_not_a_conflict() {
    let mut a = Device::new(1, 0);
    let mut b = Device::new(2, 0);
    a.write(&Edit::write(&[("item.name", &text("n0"))]));
    b.receive(&a.ops());
    a.write(&Edit::write(&[("item.name", &text("same"))]));
    b.write(&Edit::write(&[("item.name", &text("same"))]));
    a.receive(&b.ops());
    let f = a.merge.field("item.name").unwrap();
    assert_eq!(f.current.len(), 2);
    assert!(!f.display.unwrap().conflict);
}

#[test]
fn a_cleared_value_never_displays_over_a_concurrent_edit() {
    let mut a = Device::new(1, 0);
    let mut b = Device::new(2, 0);
    a.write(&Edit::write(&[("item.notes", &text("n0"))]));
    b.receive(&a.ops());
    let edit = a.write(&Edit::write(&[("item.notes", &text("kept"))]));
    b.now_ms += 60_000;
    let clear = b.write(&Edit::write(&[("item.notes", &[])]));
    a.receive(&b.ops());
    let f = a.merge.field("item.notes").unwrap();
    let shown = f.display.unwrap();
    assert_eq!(f.current[shown.displayed].dot(), edit.dot());
    assert_eq!(f.current[shown.cleared_by.unwrap()].dot(), clear.dot());
}

#[test]
fn history_keeps_the_newest_fifty_per_field() {
    let mut a = Device::new(1, 0);
    let mut ops = Vec::new();
    for i in 0..60 {
        ops.push(a.write(&Edit::write(&[("login.password", &text(&format!("p{i}")))])));
    }
    let h = history(&a.merge, "login.password");
    assert_eq!(h.len(), HISTORY_LIMIT);
    // The newest 50 of the 59 superseded values: seqs 10..=59, the 60th is current.
    let expected: Vec<Dot> = (10..=59).map(|s| dot(1, s)).collect();
    assert_eq!(h, expected);
    assert_eq!(state_bytes(&reference(&ops)), state_bytes(&a.merge));
}

#[test]
fn unknown_keys_and_unsupported_values_are_carried_verbatim() {
    let mut a = Device::new(1, 0);
    let mut b = Device::new(2, 0);
    // A key this schema does not know, and a value of a reserved type.
    a.write(&Edit::write(&[
        ("future.field", &[0xee, 0x01, 0x02]),
        ("item.name", &text("n")),
    ]));
    b.receive(&a.ops());
    let s = b.snapshot().unwrap();
    let mut c = Device::new(3, 0);
    record_headers(&mut c.merge, &a.ops());
    absorbed(&c.absorb(&s, &[]));
    assert_eq!(
        current(&c.merge, "future.field")[0].1,
        vec![0xee, 0x01, 0x02]
    );
    assert_eq!(state_bytes(&c.merge), state_bytes(&a.merge));
}

// ---------------------------------------------------------------------------------------------
// ADR 0018 §3 "Covered ops"; deduplication.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_body_merged_twice_is_a_duplicate() {
    let mut a = Device::new(1, 0);
    let op = a.write(&Edit::write(&[("item.name", &text("n"))]));
    let mut r = ItemMerge::new(item());
    let first = op.with(|i| r.apply_op(i)).unwrap();
    assert_eq!(first.kind, ApplyKind::Applied);
    assert_eq!(first.receive_hlc, Some(op.header.hlc));
    let before = state_bytes(&r);
    let again = op.with(|i| r.apply_op(i)).unwrap();
    assert_eq!(again.kind, ApplyKind::Duplicate);
    assert_eq!(again.receive_hlc, None);
    assert_eq!(state_bytes(&r), before);
    assert_eq!(r.ops_since_snapshot(), 1);
}

#[test]
fn a_covered_op_body_still_merges() {
    let mut a = Device::new(1, 0);
    let o1 = a.write(&Edit::write(&[("item.name", &text("n"))]));
    let o2 = a.write(&Edit::write(&[("login.password", &text("p"))]));
    let s = a.snapshot().unwrap();
    // A fresh replica absorbs the snapshot, then receives the bodies it covers.
    let mut r = ItemMerge::new(item());
    record_headers(&mut r, &a.ops());
    absorbed(&absorb(&mut r, &s, &[]));
    let before = state_bytes(&r);
    let applied = o1.with(|i| r.apply_op(i)).unwrap();
    assert_eq!(applied.kind, ApplyKind::CoveredMerged);
    assert_eq!(applied.receive_hlc, None);
    assert_eq!(state_bytes(&r), before);
    // A snapshot that omits a value (a faulty author) does not hide the op: its body merges.
    let SnapshotData::Live(live) = s.parsed() else {
        panic!()
    };
    let omitted: Vec<Register<'_>> = live
        .registers()
        .iter()
        .filter(|reg| reg.key().expose_secret() != "login.password")
        .cloned()
        .collect();
    let history: Vec<Register<'_>> = live
        .history()
        .iter()
        .filter(|reg| reg.key().expose_secret() != "login.password")
        .cloned()
        .collect();
    let faulty = Snap::build(
        1,
        9,
        s.header.covered.clone(),
        &SnapshotData::Live(LiveSnapshot::new(omitted, history)),
    );
    let mut q = ItemMerge::new(item());
    record_headers(&mut q, &a.ops());
    absorbed(&absorb(&mut q, &faulty, &[]));
    assert!(q.field("login.password").is_none());
    assert_eq!(
        o2.with(|i| q.apply_op(i)).unwrap().kind,
        ApplyKind::CoveredMerged
    );
    assert_eq!(
        o1.with(|i| q.apply_op(i)).unwrap().kind,
        ApplyKind::CoveredMerged
    );
    assert_eq!(state_bytes(&q), state_bytes(&a.merge));
}

// ---------------------------------------------------------------------------------------------
// ADR 0012 §5 and ADR 0018 §9: trash, restore, purge, times.
// ---------------------------------------------------------------------------------------------

#[test]
fn trash_restore_and_the_purge_writer_rules() {
    let mut a = Device::new(1, 0);
    a.write(&Edit::write(&[
        ("item.type", &[0x05, 0x00, 0x01]),
        ("item.name", &text("n")),
    ]));
    // A Purge is written only on a trashed item.
    assert_eq!(
        a.try_write(&Edit::Purge, OwnWrite::default()).unwrap_err(),
        MergeError::WriterRule
    );
    let trash = a.write(&Edit::Trash);
    assert_eq!(a.merge.lifecycle(), ItemLifecycle::Trashed);
    let times = a.merge.times();
    assert_eq!(times.trashed_at_ms, Some(trash.header.hlc.millis()));
    assert!(times.created_ms.unwrap() < times.trashed_at_ms.unwrap());
    // Retention runs from the trash op's HLC.
    let at = trash.header.hlc.millis();
    assert!(
        !a.merge
            .purge_due(at + TRASH_RETENTION_MS - 1, TRASH_RETENTION_MS, false)
    );
    assert!(
        a.merge
            .purge_due(at + TRASH_RETENTION_MS, TRASH_RETENTION_MS, false)
    );
    // Never over an unapplied record (ADR 0018 §11).
    assert!(
        !a.merge
            .purge_due(at + TRASH_RETENTION_MS, TRASH_RETENTION_MS, true)
    );
    let held = OwnWrite {
        holds_unapplied_record: true,
        ..OwnWrite::default()
    };
    assert_eq!(
        a.try_write(&Edit::Purge, held).unwrap_err(),
        MergeError::WriterRule
    );
    a.write(&Edit::Restore);
    assert_eq!(a.merge.lifecycle(), ItemLifecycle::Active);
    assert_eq!(a.merge.times().trashed_at_ms, None);
    a.write(&Edit::Trash);
    let (purge, applied) = a.try_write(&Edit::Purge, OwnWrite::default()).unwrap();
    assert_eq!(applied.snapshot_due, Some(SnapshotTrigger::AfterPurge));
    assert_eq!(a.merge.lifecycle(), ItemLifecycle::Purged);
    let (purge_dot, key, c, late) = tomb(&a.merge);
    assert_eq!(purge_dot, purge.dot());
    assert_eq!(key, key_id(0x40));
    assert_eq!(c, purge.header.causal_context);
    assert!(late.is_empty());
    assert_eq!(a.merge.times().modified_ms, None);
    // A tombstone with no late value is 53 + 24·c bytes of data (ADR 0018 §3).
    let s = a.snapshot().unwrap();
    assert_eq!(s.data.len(), 53 + 24 * c.len());
    assert_eq!(same_in_every_order(&a.ops()), state_bytes(&a.merge));
}

#[test]
fn a_concurrent_trash_and_edit_keep_the_item_active() {
    let mut a = Device::new(1, 0);
    let mut b = Device::new(2, 0);
    a.write(&Edit::write(&[("item.name", &text("n"))]));
    b.receive(&a.ops());
    let trash = a.write(&Edit::Trash);
    let edit = b.write(&Edit::write(&[("item.name", &text("edited"))]));
    a.receive(&b.ops());
    b.receive(&a.ops());
    for m in [&a.merge, &b.merge] {
        assert_eq!(m.lifecycle(), ItemLifecycle::Active);
        let values = current(m, LIFECYCLE_KEY);
        assert_eq!(values.len(), 2);
        let shown = m.lifecycle_display().unwrap();
        assert_eq!(values[shown.displayed].0, edit.dot());
        assert_eq!(values[shown.trashed_by.unwrap()].0, trash.dot());
    }
    assert_eq!(state_bytes(&a.merge), state_bytes(&b.merge));
}

#[test]
fn item_times_come_from_the_hlc() {
    let mut a = Device::new(1, 0);
    let create = a.write(&Edit::write(&[("item.type", &[0x05, 0x00, 0x01])]));
    let edit = a.write(&Edit::write(&[("item.name", &text("n"))]));
    let t = a.merge.times();
    assert_eq!(t.created_ms, Some(create.header.hlc.millis()));
    assert_eq!(t.modified_ms, Some(edit.header.hlc.millis()));
    assert_eq!(t.trashed_at_ms, None);
    let mut imported = vec![0x04];
    imported.extend_from_slice(&1_000u64.to_be_bytes());
    a.write(&Edit::write(&[("import.created_ms", &imported)]));
    assert_eq!(a.merge.times().created_ms, Some(1_000));
}

// ---------------------------------------------------------------------------------------------
// ADR 0018 §3 "Tombstone (c)" and ADR 0018 §12's tombstone cases, each in every arrival order.
// ---------------------------------------------------------------------------------------------

#[test]
fn concurrent_purges_converge_and_record_the_highest() {
    let mut a = Device::new(1, 0);
    let mut b = Device::new(2, 1_000);
    let mut c = Device::new(3, 0);
    a.write(&Edit::write(&[("item.name", &text("n"))]));
    a.write(&Edit::Trash);
    b.receive(&a.ops());
    c.receive(&a.ops());
    // B, whose clock is ahead, purges under the older key; C under a newer one. ADR 0018 §12:
    // "the lower-HLC one under the newer key, so that item_key_id is the older key".
    b.key = key_id(0x41);
    c.key = key_id(0x42);
    let pb = b.write(&Edit::Purge);
    let pc = c.write(&Edit::Purge);
    assert!(pb.header.hlc > pc.header.hlc);
    let mut ops = a.ops();
    ops.extend([pb.clone(), pc.clone()]);
    let bytes = same_in_every_order(&ops);
    b.receive(&ops);
    c.receive(&ops);
    assert_eq!(state_bytes(&b.merge), bytes);
    assert_eq!(state_bytes(&c.merge), bytes);
    let (purge_dot, key, ctx, late) = tomb(&b.merge);
    assert_eq!(purge_dot, pb.dot());
    assert_eq!(key, key_id(0x41));
    let mut join = pb.header.causal_context.clone();
    join.join(&pc.header.causal_context);
    assert_eq!(ctx, join);
    assert!(late.is_empty());
    assert_eq!(b.merge.covered(), &vv(&[(1, 2), (2, 1), (3, 1)]));
}

#[test]
fn a_late_edit_chain_leaves_its_last_value_in_every_order() {
    // ADR 0018 §3: device L writes E1, then E2 over it, to login.password, both concurrent with
    // purge P. In the orders E1 E2 P, P E1 E2 and E1 P E2 the late register is {E2}.
    let mut a = Device::new(1, 0);
    let mut l = Device::new(2, 0);
    let mut p = Device::new(3, 0);
    a.write(&Edit::write(&[("login.password", &text("p0"))]));
    a.write(&Edit::Trash);
    l.receive(&a.ops());
    p.receive(&a.ops());
    let e1 = l.write(&Edit::write(&[("login.password", &text("e1"))]));
    let e2 = l.write(&Edit::write(&[("login.password", &text("e2"))]));
    let purge = p.write(&Edit::Purge);
    let mut all = a.ops();
    all.extend([e1.clone(), e2.clone(), purge.clone()]);
    let base: Vec<&Op> = a.log.values().collect();
    let mut states = Vec::new();
    for order in [[&e1, &e2, &purge], [&purge, &e1, &e2], [&e1, &purge, &e2]] {
        let mut seq = base.clone();
        seq.extend(order);
        let m = replay(&all, &seq);
        let (_, _, _, late) = tomb(&m);
        assert_eq!(late, [("login.password".to_owned(), vec![e2.dot()])]);
        states.push(state_bytes(&m));
    }
    assert!(states.windows(2).all(|w| w[0] == w[1]));
    assert_eq!(same_in_every_order(&all), states[0]);
    // Surfacing is shown once, and changes no byte.
    let mut m = replay(&all, &all.iter().collect::<Vec<_>>());
    assert_eq!(m.late_values_to_surface(), [e2.dot()]);
    m.mark_surfaced();
    assert!(m.late_values_to_surface().is_empty());
    assert_eq!(state_bytes(&m), states[0]);
}

#[test]
fn an_edit_covered_by_one_purge_context_only_is_discarded() {
    let mut a = Device::new(1, 0);
    let mut b = Device::new(2, 0);
    let mut c = Device::new(3, 0);
    a.write(&Edit::write(&[("item.name", &text("n"))]));
    a.write(&Edit::Trash);
    b.receive(&a.ops());
    c.receive(&a.ops());
    let edit = b.write(&Edit::write(&[("item.notes", &text("x"))]));
    b.write(&Edit::Trash);
    let p1 = b.write(&Edit::Purge);
    let p2 = c.write(&Edit::Purge);
    assert!(p1.header.causal_context.covers(edit.dot()));
    assert!(!p2.header.causal_context.covers(edit.dot()));
    let mut ops = a.ops();
    ops.extend(b.ops());
    ops.push(p2);
    let bytes = same_in_every_order(&ops);
    let m = reference(&ops);
    let (_, _, ctx, late) = tomb(&m);
    assert!(ctx.covers(edit.dot()));
    assert!(late.is_empty());
    assert_eq!(state_bytes(&m), bytes);
}

#[test]
fn a_concurrent_restore_and_purge_leave_a_tombstone() {
    let mut a = Device::new(1, 0);
    let mut b = Device::new(2, 0);
    let mut c = Device::new(3, 0);
    a.write(&Edit::write(&[("item.name", &text("n"))]));
    a.write(&Edit::Trash);
    b.receive(&a.ops());
    c.receive(&a.ops());
    let restore = b.write(&Edit::Restore);
    let purge = c.write(&Edit::Purge);
    let mut ops = a.ops();
    ops.extend([restore.clone(), purge.clone()]);
    same_in_every_order(&ops);
    let m = reference(&ops);
    assert_eq!(m.lifecycle(), ItemLifecycle::Purged);
    let (purge_dot, _, _, late) = tomb(&m);
    assert_eq!(purge_dot, purge.dot());
    // The restore's lifecycle byte writes nothing into a tombstone; its dot is covered.
    assert!(late.is_empty());
    assert!(m.covered().covers(restore.dot()));
}

#[test]
fn an_op_whose_context_covers_the_purge_never_resurrects() {
    let mut a = Device::new(1, 0);
    let mut b = Device::new(2, 0);
    a.write(&Edit::write(&[("item.name", &text("n"))]));
    a.write(&Edit::Trash);
    let purge = a.write(&Edit::Purge);
    b.receive(&a.ops());
    assert_eq!(b.merge.lifecycle(), ItemLifecycle::Purged);
    // An editor open when the purge arrived saves; a trash and a restore follow.
    let edit = b.write(&Edit::write(&[("item.name", &text("late"))]));
    assert!(edit.header.causal_context.covers(purge.dot()));
    b.write(&Edit::Trash);
    b.write(&Edit::Restore);
    assert_eq!(b.merge.lifecycle(), ItemLifecycle::Purged);
    let (_, _, _, late) = tomb(&b.merge);
    assert_eq!(late, [("item.name".to_owned(), vec![edit.dot()])]);
    let mut ops = a.ops();
    ops.extend(b.ops());
    assert_eq!(same_in_every_order(&ops), state_bytes(&b.merge));
    assert_eq!(b.merge.late_values_to_surface(), [edit.dot()]);
}

#[test]
fn a_purge_is_never_rejected_whatever_lifecycle_displays() {
    // A purge concurrent with a restore reaches a replica where the item displays Active.
    let mut a = Device::new(1, 0);
    let mut b = Device::new(2, 0);
    a.write(&Edit::write(&[("item.name", &text("n"))]));
    a.write(&Edit::Trash);
    b.receive(&a.ops());
    a.write(&Edit::Restore);
    let purge = b.write(&Edit::Purge);
    assert_eq!(a.merge.lifecycle(), ItemLifecycle::Active);
    let applied = purge.with(|i| a.merge.apply_op(i)).unwrap();
    assert_eq!(applied.kind, ApplyKind::Applied);
    assert_eq!(a.merge.lifecycle(), ItemLifecycle::Purged);
}

// ---------------------------------------------------------------------------------------------
// ADR 0018 §3 "Re-issued ops" (owner decision 15; the merge spike's `reissue` family).
// ---------------------------------------------------------------------------------------------

#[test]
fn a_reissued_purge_records_the_reissued_key_on_the_author_and_every_receiver() {
    let mut a = Device::new(1, 0);
    a.write(&Edit::write(&[("item.name", &text("n"))]));
    a.write(&Edit::Trash);
    let purge = a.write(&Edit::Purge);
    assert_eq!(tomb(&a.merge).1, key_id(0x40));
    // The server answers "stale epoch"; the writer rule picks a fresh key; the op is re-issued
    // with the same dot, HLC, context and data.
    let mut reissued = purge.clone();
    reissued.header.vault_key_epoch = 1;
    reissued.key_id = key_id(0x50);
    a.merge.add_item_key(key_id(0x50));
    let due = a
        .merge
        .reissue_own_op(
            &reissued.header,
            reissued.key_id,
            Reissue {
                fresh_item_key: true,
                discarded_unsent_snapshot: false,
            },
        )
        .unwrap();
    assert_eq!(due, Some(SnapshotTrigger::FreshItemKey));
    assert_eq!(tomb(&a.merge).1, key_id(0x50));
    // A receiver sees only the re-issued op (the server never stored the original).
    let mut ops: Vec<Op> = a.ops();
    ops.pop();
    ops.push(reissued.clone());
    let r = reference(&ops);
    assert_eq!(state_bytes(&r), state_bytes(&a.merge));
    // The writer rule's snapshot, written after the re-issue, carries the re-issued key.
    let s = a.snapshot().unwrap();
    let SnapshotData::Tombstone(t) = s.parsed() else {
        panic!()
    };
    assert_eq!(t.item_key_id(), key_id(0x50));
    // A re-issue must match a merged op.
    let mut other = reissued.clone();
    other.header.hlc = Hlc::from_u64(other.header.hlc.to_u64() + 1);
    assert_eq!(
        a.merge
            .reissue_own_op(&other.header, key_id(0x51), Reissue::default()),
        Err(MergeError::UnknownOp { dot: purge.dot() })
    );
}

#[test]
fn a_reissue_calls_for_the_writer_rules_snapshot_or_a_replacement() {
    let mut a = Device::new(1, 0);
    let edit = a.write(&Edit::write(&[("item.name", &text("n"))]));
    // An unsent snapshot covering the op; the merge drops the op from the retained ones.
    a.snapshot().unwrap();
    assert_eq!(a.merge.retained_ops().count(), 0);
    let mut reissued = edit.clone();
    reissued.header.vault_key_epoch = 1;
    let before = state_bytes(&a.merge);
    let mut again = |reissue| {
        a.merge
            .reissue_own_op(&reissued.header, reissued.key_id, reissue)
            .unwrap()
    };
    assert_eq!(
        again(Reissue {
            fresh_item_key: true,
            discarded_unsent_snapshot: true,
        }),
        Some(SnapshotTrigger::FreshItemKey)
    );
    assert_eq!(
        again(Reissue {
            fresh_item_key: false,
            discarded_unsent_snapshot: true,
        }),
        Some(SnapshotTrigger::ReplacesDiscarded)
    );
    assert_eq!(again(Reissue::default()), None);
    // A re-issued write changes no state byte.
    assert_eq!(state_bytes(&a.merge), before);
}

// ---------------------------------------------------------------------------------------------
// ADR 0018 §3 "Absorbing a snapshot" and §10 (the merge spike's `absorb` family).
// ---------------------------------------------------------------------------------------------

/// B absorbs A's snapshot, concurrent with its own state, as the cover of A's bodiless
/// headers; the result equals the ops alone, and the merged snapshot is due.
fn absorb_concurrent(a: &mut Device, b: &mut Device) {
    let s = a.snapshot().unwrap();
    let mut all = a.ops();
    all.extend(b.ops());
    all.sort_by_key(Op::dot);
    all.dedup_by_key(|o| o.dot());
    record_headers(&mut b.merge, &a.ops());
    let got = b.absorb(&s, &[]);
    assert!(got.claim_cuts.is_empty());
    let x = absorbed(&got);
    assert_eq!(x.relation, VvOrdering::Concurrent);
    assert!(x.disagreements.is_empty());
    assert!(x.ignored_values.is_empty());
    assert_eq!(state_bytes(&b.merge), state_bytes(&reference(&all)));
    assert_eq!(
        b.merge.end_fetch(),
        Some(SnapshotTrigger::MergedAfterConcurrentAbsorption)
    );
    assert_eq!(b.merge.end_fetch(), None);
    let merged = b.snapshot().unwrap();
    assert_eq!(b.merge.retained_ops().count(), 0);
    assert_eq!(merged.header.covered, *b.merge.covered());
}

#[test]
fn absorbing_a_concurrent_live_snapshot_into_a_live_item() {
    let mut a = Device::new(1, 0);
    let mut b = Device::new(2, 0);
    a.write(&Edit::write(&[("item.name", &text("n"))]));
    b.receive(&a.ops());
    a.write(&Edit::write(&[("item.name", &text("a"))]));
    b.write(&Edit::write(&[("item.notes", &text("b"))]));
    absorb_concurrent(&mut a, &mut b);
}

#[test]
fn absorbing_a_concurrent_tombstone_into_a_live_item() {
    let mut a = Device::new(1, 0);
    let mut b = Device::new(2, 0);
    a.write(&Edit::write(&[("item.name", &text("n"))]));
    b.receive(&a.ops());
    a.write(&Edit::Trash);
    a.write(&Edit::Purge);
    b.write(&Edit::write(&[("item.notes", &text("late"))]));
    absorb_concurrent(&mut a, &mut b);
    assert_eq!(b.merge.lifecycle(), ItemLifecycle::Purged);
}

#[test]
fn absorbing_a_concurrent_live_snapshot_into_a_tombstone() {
    let mut a = Device::new(1, 0);
    let mut b = Device::new(2, 0);
    a.write(&Edit::write(&[("item.name", &text("n"))]));
    a.write(&Edit::Trash);
    b.receive(&a.ops());
    b.write(&Edit::Purge);
    a.write(&Edit::write(&[("item.name", &text("restored"))]));
    absorb_concurrent(&mut a, &mut b);
    let (_, _, _, late) = tomb(&b.merge);
    assert_eq!(late, [("item.name".to_owned(), vec![dot(1, 3)])]);
}

#[test]
fn absorbing_a_concurrent_tombstone_into_a_tombstone() {
    let mut a = Device::new(1, 0);
    let mut b = Device::new(2, 0);
    a.write(&Edit::write(&[("item.name", &text("n"))]));
    a.write(&Edit::Trash);
    b.receive(&a.ops());
    a.write(&Edit::Purge);
    b.write(&Edit::Purge);
    absorb_concurrent(&mut a, &mut b);
}

#[test]
fn the_newest_snapshot_is_the_pair_until_the_merged_one_is_written() {
    let mut a = Device::new(1, 0);
    let mut b = Device::new(2, 0);
    a.write(&Edit::write(&[("item.name", &text("n"))]));
    b.receive(&a.ops());
    b.write(&Edit::write(&[("item.notes", &text("b"))]));
    b.snapshot().unwrap();
    let late_b = b.write(&Edit::write(&[("item.notes", &text("b2"))]));
    a.write(&Edit::write(&[("item.name", &text("a"))]));
    let s = a.snapshot().unwrap();
    record_headers(&mut b.merge, &a.ops());
    absorbed(&b.absorb(&s, &[]));
    // The pair: B's own snapshot {A:1, B:1} and A's {A:2}; B keeps the op neither covers.
    assert_eq!(b.merge.basis_covered(), &vv(&[(1, 2), (2, 1)]));
    assert_eq!(b.merge.retained_ops().collect::<Vec<_>>(), [late_b.dot()]);
    assert_eq!(
        b.merge.end_fetch(),
        Some(SnapshotTrigger::MergedAfterConcurrentAbsorption)
    );
    b.snapshot().unwrap();
    assert_eq!(b.merge.basis_covered(), b.merge.covered());
    assert_eq!(b.merge.retained_ops().count(), 0);
}

#[test]
fn a_dominated_snapshot_changes_nothing_and_a_dominating_one_is_not_concurrent() {
    let mut a = Device::new(1, 0);
    let mut b = Device::new(2, 0);
    a.write(&Edit::write(&[("item.name", &text("n"))]));
    let old = a.snapshot().unwrap();
    a.write(&Edit::write(&[("item.name", &text("n2"))]));
    b.receive(&a.ops());
    let before = state_bytes(&b.merge);
    let dominated = b.absorb(&old, &[]);
    assert_eq!(absorbed(&dominated).relation, VvOrdering::Less);
    assert_eq!(state_bytes(&b.merge), before);
    assert_eq!(b.merge.end_fetch(), None);
    // A dominating snapshot: B had only the create.
    let mut c = Device::new(3, 0);
    c.receive(&a.ops()[..1]);
    let newer = a.snapshot().unwrap();
    record_headers(&mut c.merge, &a.ops());
    let dominating = c.absorb(&newer, &[]);
    assert_eq!(absorbed(&dominating).relation, VvOrdering::Greater);
    assert_eq!(c.merge.end_fetch(), None);
    assert_eq!(state_bytes(&c.merge), state_bytes(&a.merge));
}

#[test]
fn absorbing_is_an_hlc_receipt_of_the_highest_taken_hlc() {
    let mut a = Device::new(1, 0);
    a.write(&Edit::write(&[("item.name", &text("n"))]));
    a.write(&Edit::Trash);
    let purge = a.write(&Edit::Purge);
    let tombstone = a.snapshot().unwrap();
    let mut first = ItemMerge::new(item());
    record_headers(&mut first, &a.ops());
    let got = absorb(&mut first, &tombstone, &[]);
    assert_eq!(absorbed(&got).receive_hlc, Some(purge.header.hlc));
    let mut other = Device::new(2, 0);
    let edit = other.write(&Edit::write(&[("item.name", &text("x"))]));
    let live = other.snapshot().unwrap();
    let mut second = ItemMerge::new(item());
    record_headers(&mut second, &other.ops());
    let got = absorb(&mut second, &live, &[]);
    assert_eq!(absorbed(&got).receive_hlc, Some(edit.header.hlc));
}

#[test]
fn a_replica_rebuilt_from_its_kept_records_reaches_the_same_state() {
    let mut a = Device::new(1, 0);
    let mut b = Device::new(2, 0);
    a.write(&Edit::write(&[("item.name", &text("n"))]));
    b.receive(&a.ops());
    b.write(&Edit::write(&[("item.notes", &text("x"))]));
    let s = b.snapshot().unwrap();
    a.write(&Edit::write(&[("item.name", &text("n2"))]));
    b.receive(&a.ops());
    b.write(&Edit::Trash);
    // Rebuild: every header, the newest snapshot, then the retained ops.
    let mut all = a.ops();
    all.extend(b.ops());
    let mut r = ItemMerge::new(item());
    record_headers(&mut r, &all);
    absorbed(&absorb(&mut r, &s, &[]));
    let retained: Vec<Op> = all
        .iter()
        .filter(|o| b.merge.retained_ops().any(|d| d == o.dot()))
        .cloned()
        .collect();
    assert_eq!(retained.len(), 2);
    assert!(deliver(&mut r, &retained).is_empty());
    assert_eq!(state_bytes(&r), state_bytes(&b.merge));
}

// ---------------------------------------------------------------------------------------------
// ADR 0018 §10: triggers, oversize items.
// ---------------------------------------------------------------------------------------------

#[test]
fn snapshot_triggers() {
    let mut a = Device::new(1, 0);
    for i in 0..SNAPSHOT_AFTER_OPS {
        let (_, applied) = a
            .try_write(
                &Edit::write(&[("item.name", &text(&i.to_string()))]),
                OwnWrite::default(),
            )
            .unwrap();
        assert_eq!(applied.snapshot_due, None, "op {i}");
    }
    let (_, applied) = a
        .try_write(
            &Edit::write(&[("item.name", &text("33"))]),
            OwnWrite::default(),
        )
        .unwrap();
    assert_eq!(applied.snapshot_due, Some(SnapshotTrigger::OpCount));
    a.snapshot().unwrap();
    assert_eq!(a.merge.ops_since_snapshot(), 0);
    let fresh = OwnWrite {
        fresh_item_key: true,
        ..OwnWrite::default()
    };
    let (_, applied) = a
        .try_write(&Edit::write(&[("item.name", &text("k"))]), fresh)
        .unwrap();
    assert_eq!(applied.snapshot_due, Some(SnapshotTrigger::FreshItemKey));
    // Received ops count toward the 32 but trigger nothing themselves.
    let mut b = Device::new(2, 0);
    let got: Vec<Applied> = a
        .ops()
        .iter()
        .map(|o| {
            record_headers(&mut b.merge, core::slice::from_ref(o));
            o.with(|i| b.merge.apply_op(i)).unwrap()
        })
        .collect();
    assert!(got.iter().all(|x| x.snapshot_due.is_none()));
    assert_eq!(b.merge.ops_since_snapshot(), SNAPSHOT_AFTER_OPS + 2);
}

#[test]
fn an_oversize_item_gets_no_snapshot_and_keeps_its_ops() {
    let mut a = Device::new(1, 0);
    let keys: Vec<String> = (0..1_000).map(|i| format!("f.k{i}")).collect();
    let mut ops = Vec::new();
    for batch in 0..5 {
        let writes: Vec<(String, Vec<u8>)> = keys
            .iter()
            .map(|k| (format!("{k}x{batch}"), vec![0x01]))
            .collect();
        ops.push(a.write(&Edit::Write(writes)));
    }
    assert!(a.merge.is_oversize());
    assert_eq!(a.merge.write_snapshot().unwrap_err(), NoSnapshot::Oversize);
    assert_eq!(a.merge.retained_ops().count(), 5);
    // The state hash input has no §10 limit.
    assert!(a.merge.canonical_state().unwrap().is_some());
    assert_eq!(state_bytes(&reference(&ops)), state_bytes(&a.merge));
}

#[test]
fn no_snapshot_of_an_absent_item() {
    let mut m = ItemMerge::new(item());
    assert_eq!(m.write_snapshot().unwrap_err(), NoSnapshot::Absent);
    assert_eq!(m.lifecycle(), ItemLifecycle::Absent);
    assert!(m.canonical_state().unwrap().is_none());
    assert!(m.snapshot_data().unwrap().is_none());
    assert!(!m.is_oversize());
}

// ---------------------------------------------------------------------------------------------
// ADR 0018 §3 "Snapshots are claims": dishonest snapshots (the merge spike's `faulty-kinds`).
// ---------------------------------------------------------------------------------------------

/// A replica holding A's create and B's concurrent edit, and A's snapshot of its own state.
fn two_writers() -> (Device, Device, Snap) {
    let mut a = Device::new(1, 0);
    let mut b = Device::new(2, 0);
    a.write(&Edit::write(&[
        ("item.name", &text("n")),
        ("login.password", &text("p")),
    ]));
    b.receive(&a.ops());
    b.write(&Edit::write(&[("item.notes", &text("b"))]));
    a.receive(&b.ops());
    a.write(&Edit::write(&[("login.password", &text("p2"))]));
    let s = a.snapshot().unwrap();
    (a, b, s)
}

/// The live registers and history of an honest snapshot, for building a faulty one.
fn live_parts(s: &Snap) -> (Vec<Register<'_>>, Vec<Register<'_>>) {
    match s.parsed() {
        SnapshotData::Live(l) => (l.registers().to_vec(), l.history().to_vec()),
        SnapshotData::Tombstone(_) => panic!("not live"),
    }
}

/// The state of a fresh replica that loads `m`'s newest-snapshot basis, then its retained ops
/// (the rebuild of ADR 0012 §6 from local state). `ops` holds every op of the item.
fn rebuild_from_basis(m: &ItemMerge, ops: &[Op]) -> Vec<u8> {
    let data = m.basis_data().unwrap().unwrap();
    let basis = Snap::build(9, 1, m.basis_covered().clone(), &data);
    let mut r = ItemMerge::new(item());
    record_headers(&mut r, ops);
    absorbed(&absorb(&mut r, &basis, &[]));
    let retained: Vec<Op> = ops
        .iter()
        .filter(|o| m.retained_ops().any(|d| d == o.dot()))
        .cloned()
        .collect();
    assert!(deliver(&mut r, &retained).is_empty());
    state_bytes(&r)
}

#[test]
fn a_snapshot_that_omits_a_value_loses_nothing_and_is_reported() {
    let (a, mut b, s) = two_writers();
    // A faulty author drops B's item.notes value but keeps the covered VV.
    let (regs, hist) = live_parts(&s);
    let regs: Vec<Register<'_>> = regs
        .into_iter()
        .filter(|r| r.key().expose_secret() != "item.notes")
        .collect();
    let faulty = Snap::build(
        1,
        7,
        s.header.covered.clone(),
        &SnapshotData::Live(LiveSnapshot::new(regs, hist)),
    );
    record_headers(&mut b.merge, &a.ops());
    let before = current(&b.merge, "item.notes");
    let x = b.absorb(&faulty, &[]);
    assert_eq!(absorbed(&x).disagreements, [dot(2, 1)]);
    assert_eq!(current(&b.merge, "item.notes"), before);
    assert_eq!(b.merge.unresolved().collect::<Vec<_>>(), [dot(2, 1)]);
    // No snapshot while a disagreement is unresolved.
    assert_eq!(
        b.merge.write_snapshot().unwrap_err(),
        NoSnapshot::Unresolved
    );
    // B's own op is folded into the newest-snapshot basis, which keeps its value although
    // the absorbed record lacks it: the basis and the retained ops rebuild the state.
    let mut all = a.ops();
    all.extend(b.ops());
    all.sort_by_key(Op::dot);
    all.dedup_by_key(|o| o.dot());
    assert_eq!(b.merge.retained_ops().count(), 0);
    assert_eq!(rebuild_from_basis(&b.merge, &all), state_bytes(&b.merge));
    // Everything the ops say is still there once they arrive.
    b.receive(&all);
    assert_eq!(state_bytes(&b.merge), state_bytes(&reference(&all)));
}

#[test]
fn a_history_entry_the_snapshot_omits_stays_when_a_held_value_supersedes_it() {
    let (a, mut b, s) = two_writers();
    let (regs, hist) = live_parts(&s);
    let hist: Vec<Register<'_>> = hist
        .into_iter()
        .filter(|r| r.key().expose_secret() != "login.password")
        .collect();
    let faulty = Snap::build(
        1,
        7,
        s.header.covered.clone(),
        &SnapshotData::Live(LiveSnapshot::new(regs, hist)),
    );
    record_headers(&mut b.merge, &a.ops());
    let x = b.absorb(&faulty, &[]);
    // B holds the old password in its register; A's current value supersedes it: accounted.
    assert!(absorbed(&x).disagreements.is_empty());
    let mut all = a.ops();
    all.extend(b.ops());
    all.sort_by_key(Op::dot);
    all.dedup_by_key(|o| o.dot());
    assert_eq!(state_bytes(&b.merge), state_bytes(&reference(&all)));
}

#[test]
fn claimed_unheld_dots_are_cut_and_reported() {
    let (a, mut b, s) = two_writers();
    // Claim A's next op and put a fabricated value at it (ClaimValue).
    let (mut regs, hist) = live_parts(&s);
    let fake = dot(1, 3);
    let mut covered = s.header.covered.clone();
    covered.add(fake);
    let fabricated = text("fabricated");
    regs.push(Register::new(
        FieldKey::new("zz.fake").unwrap(),
        vec![Entry::new(
            fake,
            Hlc::from_u64(u64::MAX >> 1),
            Value::new(&fabricated),
        )],
    ));
    let faulty = Snap::build(
        1,
        7,
        covered,
        &SnapshotData::Live(LiveSnapshot::new(regs, hist)),
    );
    record_headers(&mut b.merge, &a.ops());
    let x = b.absorb(&faulty, &[]);
    assert_eq!(
        x.claim_cuts,
        [ClaimCut {
            device_id: device(1),
            verified_to: 2,
            claimed_to: 3,
            author: device(1),
        }]
    );
    absorbed(&x);
    assert!(!b.merge.covered().covers(fake));
    assert!(b.merge.field("zz.fake").is_none());
    // The value is not taken, so the clock does not receive its HLC either.
    assert!(absorbed(&x).receive_hlc < Some(Hlc::from_u64(u64::MAX >> 1)));
}

#[test]
fn a_snapshot_contradicting_a_held_body_is_refused() {
    let (a, mut b, s) = two_writers();
    // A value at B's own dot that B's body did not write.
    let (regs, hist) = live_parts(&s);
    let bogus = text("not what B wrote");
    let regs: Vec<Register<'_>> = regs
        .into_iter()
        .map(|r| {
            if r.key().expose_secret() == "item.notes" {
                let e = r.entries()[0];
                Register::new(
                    r.key(),
                    vec![Entry::new(e.dot(), e.hlc(), Value::new(&bogus))],
                )
            } else {
                r
            }
        })
        .collect();
    let faulty = Snap::build(
        1,
        7,
        s.header.covered.clone(),
        &SnapshotData::Live(LiveSnapshot::new(regs, hist)),
    );
    record_headers(&mut b.merge, &a.ops());
    let before = state_bytes(&b.merge);
    let held = b.absorb(&faulty, &[]);
    assert_eq!(refused(&held), Refusal::ValueNotInBody { dot: dot(2, 1) });
    assert_eq!(state_bytes(&b.merge), before);
    // The same check holds for a body received with the snapshot rather than held.
    let mut fresh = ItemMerge::new(item());
    record_headers(&mut fresh, &a.ops());
    let with: Vec<Op> = b.ops();
    let received = absorb(&mut fresh, &faulty, &with);
    assert_eq!(
        refused(&received),
        Refusal::ValueNotInBody { dot: dot(2, 1) }
    );
    assert!(fresh.canonical_state().unwrap().is_none());
}

#[test]
fn a_value_whose_hlc_is_not_its_headers_is_ignored() {
    let (a, mut b, s) = two_writers();
    // AltHlc: a copy of A's current password at its dot under another key, HLC + 1.
    let (mut regs, hist) = live_parts(&s);
    let src = regs
        .iter()
        .find(|r| r.key().expose_secret() == "login.password")
        .unwrap()
        .entries()[0];
    regs.push(Register::new(
        FieldKey::new("zz.copy").unwrap(),
        vec![Entry::new(
            src.dot(),
            Hlc::from_u64(src.hlc().to_u64() + 1),
            src.value(),
        )],
    ));
    let faulty = Snap::build(
        1,
        7,
        s.header.covered.clone(),
        &SnapshotData::Live(LiveSnapshot::new(regs, hist)),
    );
    record_headers(&mut b.merge, &a.ops());
    let x = b.absorb(&faulty, &[]);
    assert_eq!(absorbed(&x).ignored_values, [src.dot()]);
    assert!(b.merge.field("zz.copy").is_none());
}

#[test]
fn a_resurrected_history_entry_goes_back_to_history() {
    let (a, mut b, s) = two_writers();
    // Resurrect: the superseded password put back into its register as a current value.
    let (regs, hist) = live_parts(&s);
    let old = hist
        .iter()
        .find(|r| r.key().expose_secret() == "login.password")
        .unwrap()
        .entries()[0];
    let regs: Vec<Register<'_>> = regs
        .into_iter()
        .map(|r| {
            if r.key().expose_secret() == "login.password" {
                let mut entries = vec![old];
                entries.extend(r.entries().iter().copied());
                entries.sort_by_key(Entry::dot);
                Register::new(r.key(), entries)
            } else {
                r
            }
        })
        .collect();
    let hist: Vec<Register<'_>> = hist
        .into_iter()
        .filter(|r| r.key().expose_secret() != "login.password")
        .collect();
    let faulty = Snap::build(
        1,
        7,
        s.header.covered.clone(),
        &SnapshotData::Live(LiveSnapshot::new(regs, hist)),
    );
    record_headers(&mut b.merge, &a.ops());
    absorbed(&b.absorb(&faulty, &[]));
    let mut all = a.ops();
    all.extend(b.ops());
    all.sort_by_key(Op::dot);
    all.dedup_by_key(|o| o.dot());
    assert_eq!(state_bytes(&b.merge), state_bytes(&reference(&all)));
}

/// A tombstone snapshot built from its parts.
fn tomb_snap(
    author: u8,
    covered: VersionVector,
    purge: (Dot, Hlc),
    c: VersionVector,
    key: SymmetricKeyId,
    late: Vec<Register<'_>>,
) -> Snap {
    Snap::build(
        author,
        8,
        covered,
        &SnapshotData::Tombstone(Tombstone::new(purge.0, purge.1, c, key, late)),
    )
}

#[test]
fn a_tombstone_that_records_a_write_as_its_purge_is_refused() {
    // FakeTomb: a live item presented as a tombstone whose purge is a write.
    let (a, mut b, s) = two_writers();
    let write = &a.log[&2];
    let faulty = tomb_snap(
        1,
        s.header.covered.clone(),
        (write.dot(), write.header.hlc),
        write.header.causal_context.clone(),
        key_id(0x40),
        Vec::new(),
    );
    record_headers(&mut b.merge, &a.ops());
    let with = [write.clone()];
    let x = b.absorb(&faulty, &with);
    assert_eq!(
        refused(&x),
        Refusal::WriteRecordedAsPurge { dot: write.dot() }
    );
    assert_eq!(b.merge.lifecycle(), ItemLifecycle::Active);
}

#[test]
fn a_live_snapshot_holding_a_value_at_a_purge_dot_is_refused() {
    // FakeLive: a purged item presented as live, Active at the purge's dot.
    let mut a = Device::new(1, 0);
    a.write(&Edit::write(&[("item.name", &text("n"))]));
    a.write(&Edit::Trash);
    let purge = a.write(&Edit::Purge);
    let active = [0x01u8];
    let faulty = Snap::build(
        1,
        7,
        a.merge.covered().clone(),
        &SnapshotData::Live(LiveSnapshot::new(
            vec![Register::new(
                FieldKey::LIFECYCLE,
                vec![Entry::new(
                    purge.dot(),
                    purge.header.hlc,
                    Value::new(&active),
                )],
            )],
            Vec::new(),
        )),
    );
    let mut r = ItemMerge::new(item());
    record_headers(&mut r, &a.ops());
    let x = absorb(&mut r, &faulty, core::slice::from_ref(&purge));
    assert_eq!(refused(&x), Refusal::ValueAtPurgeDot { dot: purge.dot() });
}

#[test]
fn a_widened_purge_context_is_refused() {
    // WidenC: c widened to the covered VV, which drops a late value.
    let mut a = Device::new(1, 0);
    let mut laptop = Device::new(2, 0);
    a.write(&Edit::write(&[("item.name", &text("n"))]));
    a.write(&Edit::Trash);
    laptop.receive(&a.ops());
    let late = laptop.write(&Edit::write(&[("item.name", &text("late"))]));
    let purge = a.write(&Edit::Purge);
    a.receive(&laptop.ops());
    let honest = a.snapshot().unwrap();
    let covered = honest.header.covered.clone();
    let faulty = tomb_snap(
        1,
        covered.clone(),
        (purge.dot(), purge.header.hlc),
        covered,
        key_id(0x40),
        Vec::new(),
    );
    let mut first = ItemMerge::new(item());
    let mut all = a.ops();
    all.push(late.clone());
    record_headers(&mut first, &all);
    let got = absorb(&mut first, &faulty, &all);
    assert_eq!(refused(&got), Refusal::ContextNotFromPurges);
    // The honest tombstone keeps the late value.
    let mut second = ItemMerge::new(item());
    record_headers(&mut second, &all);
    absorbed(&absorb(&mut second, &honest, &all));
    assert_eq!(
        tomb(&second).3,
        [("item.name".to_owned(), vec![late.dot()])]
    );
}

#[test]
fn a_late_value_at_the_purge_dot_is_not_taken() {
    // LateAtPurge: a Purge writes nothing, so a late value at its dot is a fabrication.
    let mut a = Device::new(1, 0);
    a.write(&Edit::write(&[("item.name", &text("n"))]));
    a.write(&Edit::Trash);
    let purge = a.write(&Edit::Purge);
    let v = text("fabricated");
    let faulty = tomb_snap(
        1,
        a.merge.covered().clone(),
        (purge.dot(), purge.header.hlc),
        purge.header.causal_context.clone(),
        key_id(0x40),
        vec![Register::new(
            FieldKey::new("zz.late").unwrap(),
            vec![Entry::new(purge.dot(), purge.header.hlc, Value::new(&v))],
        )],
    );
    let mut r = ItemMerge::new(item());
    record_headers(&mut r, &a.ops());
    absorbed(&absorb(&mut r, &faulty, &[]));
    assert!(tomb(&r).3.is_empty());
    assert_eq!(state_bytes(&r), state_bytes(&a.merge));
}

#[test]
fn a_tombstone_resting_on_an_unverified_purge_is_refused() {
    let mut a = Device::new(1, 0);
    a.write(&Edit::write(&[("item.name", &text("n"))]));
    a.write(&Edit::Trash);
    a.write(&Edit::Purge);
    let s = a.snapshot().unwrap();
    // The replica has not verified the purge's header.
    let mut r = ItemMerge::new(item());
    record_headers(&mut r, &a.ops()[..2]);
    let x = absorb(&mut r, &s, &[]);
    assert_eq!(refused(&x), Refusal::PurgeAboveCut);
    assert_eq!(x.claim_cuts.len(), 1);
}

#[test]
fn one_purge_dot_under_two_keys_prefers_the_wrap_set_and_is_reported() {
    // WrongKey: a tombstone recording a real purge under a key id nobody holds.
    let mut a = Device::new(1, 0);
    a.write(&Edit::write(&[("item.name", &text("n"))]));
    a.write(&Edit::Trash);
    let purge = a.write(&Edit::Purge);
    let honest = a.snapshot().unwrap();
    let wrong = tomb_snap(
        1,
        honest.header.covered.clone(),
        (purge.dot(), purge.header.hlc),
        purge.header.causal_context.clone(),
        key_id(0x7f),
        Vec::new(),
    );
    let mut states = Vec::new();
    for (first, second) in [(&honest, &wrong), (&wrong, &honest)] {
        let mut r = ItemMerge::new(item());
        r.add_item_key(key_id(0x40));
        record_headers(&mut r, &a.ops());
        absorbed(&absorb(&mut r, first, &[]));
        let x = absorb(&mut r, second, &[]);
        assert_eq!(absorbed(&x).disagreements, [purge.dot()]);
        assert_eq!(tomb(&r).1, key_id(0x40));
        states.push(state_bytes(&r));
    }
    assert_eq!(states[0], states[1]);
    // With the purge body at hand, the wrong key is a contradiction and is refused.
    let mut r = ItemMerge::new(item());
    record_headers(&mut r, &a.ops());
    let x = absorb(&mut r, &wrong, core::slice::from_ref(&purge));
    assert_eq!(
        refused(&x),
        Refusal::PurgeKeyContradicts { dot: purge.dot() }
    );
}

#[test]
fn one_dot_in_two_versions_keeps_the_lower_value_in_any_order() {
    // A value at a real dot with the header's HLC but other bytes, from a snapshot whose body
    // the replica does not hold: the lower (hlc, value) is kept, whatever arrives first.
    let mut a = Device::new(1, 0);
    let op = a.write(&Edit::write(&[("item.name", &text("m"))]));
    let s = a.snapshot().unwrap();
    let (regs, hist) = live_parts(&s);
    let other = text("a");
    let regs: Vec<Register<'_>> = regs
        .into_iter()
        .map(|r| {
            if r.key().expose_secret() == "item.name" {
                let e = r.entries()[0];
                Register::new(
                    r.key(),
                    vec![Entry::new(e.dot(), e.hlc(), Value::new(&other))],
                )
            } else {
                r
            }
        })
        .collect();
    let faulty = Snap::build(
        2,
        7,
        s.header.covered.clone(),
        &SnapshotData::Live(LiveSnapshot::new(regs, hist)),
    );
    let mut x = ItemMerge::new(item());
    record_headers(&mut x, &a.ops());
    absorbed(&absorb(&mut x, &s, &[]));
    let second = absorb(&mut x, &faulty, &[]);
    let mut y = ItemMerge::new(item());
    record_headers(&mut y, &a.ops());
    absorbed(&absorb(&mut y, &faulty, &[]));
    let first = absorb(&mut y, &s, &[]);
    assert_eq!(state_bytes(&x), state_bytes(&y));
    assert_eq!(current(&x, "item.name"), [(op.dot(), text("a"))]);
    // Whichever arrives second, the two versions are reported, never decided silently, and
    // the item gets no further snapshot.
    for (m, got) in [(&x, &second), (&y, &first)] {
        assert_eq!(absorbed(got).disagreements, [op.dot()]);
        assert_eq!(m.unresolved().collect::<Vec<_>>(), [op.dot()]);
        assert_eq!(
            m.clone().write_snapshot().unwrap_err(),
            NoSnapshot::Unresolved
        );
    }
    // The body itself, merged later, settles nothing either way: the lower version stays.
    op.with(|i| x.apply_op(i)).unwrap();
    assert_eq!(current(&x, "item.name"), [(op.dot(), text("a"))]);
    // Once the body is known, the faulty version contradicts it and is refused.
    assert_eq!(
        refused(&absorb(&mut x, &faulty, &[])),
        Refusal::ValueNotInBody { dot: op.dot() }
    );
}

// ---------------------------------------------------------------------------------------------
// Errors and redaction.
// ---------------------------------------------------------------------------------------------

#[test]
fn errors_leave_the_state_unchanged() {
    let mut a = Device::new(1, 0);
    let o1 = a.write(&Edit::write(&[("item.name", &text("n"))]));
    let o2 = a.write(&Edit::write(&[("item.name", &text("n2"))]));
    let mut r = ItemMerge::new(item());
    assert_eq!(
        o2.with(|i| r.apply_op(i)),
        Err(MergeError::NotReady { dot: o2.dot() })
    );
    assert!(r.canonical_state().unwrap().is_none());
    // Another item, another schema version.
    let mut wrong = o1.clone();
    wrong.header.item_id = ItemId::from_bytes([0x18; 16]);
    assert_eq!(wrong.with(|i| r.apply_op(i)), Err(MergeError::WrongItem));
    let mut v2 = o1.clone();
    v2.header.item_schema_version = ItemSchemaVersion::new(2).unwrap();
    assert_eq!(
        v2.with(|i| r.apply_op(i)),
        Err(MergeError::UnsupportedSchema)
    );
    // Two headers for one dot with different contexts: a fork.
    let mut fork = o2.clone();
    fork.header.causal_context = VersionVector::new();
    assert_eq!(
        fork.with(|i| r.apply_op(i)),
        Err(MergeError::HeaderConflict { dot: o2.dot() })
    );
    // An own op not written on the current state.
    let mut stale = a.prepare(&Edit::write(&[("item.name", &text("x"))]));
    stale.header.causal_context = VersionVector::new();
    assert_eq!(
        stale.with(|i| a.merge.apply_own_op(i, OwnWrite::default())),
        Err(MergeError::NotCurrent { dot: stale.dot() })
    );
    assert!(!MergeError::WriterRule.to_string().is_empty());
}

#[test]
fn debug_output_shows_no_content() {
    let (a, mut b, s) = two_writers();
    record_headers(&mut b.merge, &a.ops());
    let absorption = b.absorb(&s, &[]);
    let field = b.merge.field("login.password").unwrap();
    let written = b.merge.clone().write_snapshot();
    let printed = format!(
        "{:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?}",
        b.merge,
        field,
        absorption,
        b.merge.lifecycle(),
        b.merge.times(),
        SnapshotTrigger::AfterPurge,
        Refusal::WriteRecordedAsPurge { dot: dot(1, 1) },
        written,
        a.merge.snapshot_data().unwrap(),
    );
    for secret in [
        "p2", "login", "password", "notes", "Active", "Trashed", "Purge", "Tomb",
    ] {
        assert!(!printed.contains(secret), "{secret} in {printed}");
    }
}

#[test]
fn debug_output_does_not_reveal_a_tombstone() {
    let mut a = Device::new(1, 0);
    a.write(&Edit::write(&[("item.name", &text("n"))]));
    a.write(&Edit::Trash);
    a.write(&Edit::Purge);
    let s = a.snapshot().unwrap();
    let data = s.parsed();
    let input = SnapshotInput {
        header: &s.header,
        data: &data,
    };
    let printed = format!(
        "{input:?} {:?} {:?} {:?} {:?}",
        a.merge.snapshot_data().unwrap(),
        a.merge.basis_data().unwrap(),
        a.merge,
        a.merge.lifecycle(),
    );
    for secret in [
        "Tomb",
        "tomb",
        "purge",
        "Purge",
        "late",
        "Live",
        "item.name",
    ] {
        assert!(!printed.contains(secret), "{secret} in {printed}");
    }
}

/// `s` with the value of `key` at its first dot replaced by `value`, same dot and HLC: the
/// fault a replica can detect only against the op body at that dot.
fn altered(s: &Snap, key: &str, value: &[u8]) -> Snap {
    let (regs, hist) = live_parts(s);
    let regs: Vec<Register<'_>> = regs
        .into_iter()
        .map(|r| {
            if r.key().expose_secret() == key {
                let e = r.entries()[0];
                Register::new(
                    r.key(),
                    vec![Entry::new(e.dot(), e.hlc(), Value::new(value))],
                )
            } else {
                r
            }
        })
        .collect();
    Snap::build(
        s.header.author.as_bytes()[0],
        9,
        s.header.covered.clone(),
        &SnapshotData::Live(LiveSnapshot::new(regs, hist)),
    )
}

#[test]
fn a_snapshot_cannot_replace_a_value_whose_body_left_the_retained_ops() {
    // B merged its own op (item.notes = "b" at 2:1) and wrote a snapshot, which drops the op
    // from the retained ops. A cover carrying other bytes at that dot, with the header's HLC,
    // still contradicts the body B merged: refused, not taken.
    let (a, mut b, s) = two_writers();
    let faulty = altered(&s, "item.notes", &text("a"));
    record_headers(&mut b.merge, &a.ops());
    b.merge.write_snapshot().unwrap();
    assert_eq!(b.merge.retained_ops().count(), 0);
    let before = state_bytes(&b.merge);
    let got = b.absorb(&faulty, &[]);
    assert_eq!(refused(&got), Refusal::ValueNotInBody { dot: dot(2, 1) });
    assert_eq!(state_bytes(&b.merge), before);
    assert_eq!(current(&b.merge, "item.notes"), [(dot(2, 1), text("b"))]);
    assert!(b.merge.write_snapshot().is_ok());
    // A body received with an earlier snapshot, never merged, stays evidence too.
    let mut fresh = ItemMerge::new(item());
    record_headers(&mut fresh, &a.ops());
    record_headers(&mut fresh, &b.ops());
    absorbed(&absorb(&mut fresh, &s, &b.ops()));
    assert_eq!(
        refused(&absorb(&mut fresh, &faulty, &[])),
        Refusal::ValueNotInBody { dot: dot(2, 1) }
    );
}

#[test]
fn a_purge_context_no_uncovered_purge_explains_is_reported() {
    // A trashes and purges; Laptop, concurrently, edits twice. A replica that took Laptop's
    // snapshot (no bodies) then absorbs a tombstone whose c claims Laptop's first edit, which
    // A's purge context does not cover. No op the replica lacks explains that entry of c: the
    // discarded history value is reported, and no snapshot is written.
    let mut a = Device::new(1, 0);
    let mut laptop = Device::new(2, 0);
    a.write(&Edit::write(&[("item.name", &text("n"))]));
    a.write(&Edit::Trash);
    laptop.receive(&a.ops());
    let e1 = laptop.write(&Edit::write(&[("item.name", &text("e1"))]));
    let e2 = laptop.write(&Edit::write(&[("item.name", &text("e2"))]));
    let purge = a.write(&Edit::Purge);
    let covered = vv(&[(1, 3), (2, 2)]);
    let late = text("e2");
    let faulty = tomb_snap(
        1,
        covered,
        (purge.dot(), purge.header.hlc),
        vv(&[(1, 2), (2, 1)]),
        key_id(0x40),
        vec![Register::new(
            FieldKey::new("item.name").unwrap(),
            vec![Entry::new(e2.dot(), e2.header.hlc, Value::new(&late))],
        )],
    );
    let mut r = ItemMerge::new(item());
    r.add_item_key(key_id(0x40));
    record_headers(&mut r, &a.ops());
    record_headers(&mut r, &laptop.ops());
    let honest = laptop.snapshot().unwrap();
    absorbed(&absorb(&mut r, &honest, &[]));
    assert_eq!(history(&r, "item.name"), [dot(1, 1), e1.dot()]);
    let x = absorb(&mut r, &faulty, &[]);
    assert_eq!(absorbed(&x).disagreements, [e1.dot()]);
    assert_eq!(r.write_snapshot().unwrap_err(), NoSnapshot::Unresolved);
}

#[test]
fn a_purge_context_is_cut_with_the_covered_vv() {
    // A tombstone claims Laptop's second edit in its covered VV and in c, above the headers the
    // replica verified. c is cut with the covered VV, so the edit, once it arrives, is a late
    // value and not discarded on an unverified claim.
    let mut a = Device::new(1, 0);
    let mut laptop = Device::new(2, 0);
    a.write(&Edit::write(&[("item.name", &text("n"))]));
    laptop.receive(&a.ops());
    laptop.write(&Edit::write(&[("item.name", &text("e"))]));
    a.receive(&laptop.ops());
    a.write(&Edit::Trash);
    let purge = a.write(&Edit::Purge);
    let late = laptop.write(&Edit::write(&[("item.name", &text("late"))]));
    let faulty = tomb_snap(
        1,
        vv(&[(1, 3), (2, 2)]),
        (purge.dot(), purge.header.hlc),
        vv(&[(1, 2), (2, 2)]),
        key_id(0x40),
        Vec::new(),
    );
    let mut r = ItemMerge::new(item());
    r.add_item_key(key_id(0x40));
    record_headers(&mut r, &a.ops());
    record_headers(&mut r, &laptop.ops()[..1]);
    let x = absorb(&mut r, &faulty, &[]);
    assert_eq!(x.claim_cuts.len(), 1);
    absorbed(&x);
    assert_eq!(tomb(&r).2, vv(&[(1, 2), (2, 1)]));
    record_headers(&mut r, core::slice::from_ref(&late));
    late.with(|i| r.apply_op(i)).unwrap();
    assert_eq!(tomb(&r).3, [("item.name".to_owned(), vec![late.dot()])]);
    let mut all = a.ops();
    all.extend(laptop.ops());
    assert_eq!(state_bytes(&r), state_bytes(&reference(&all)));
}

#[test]
fn a_long_history_absorbed_from_a_concurrent_snapshot_is_accounted_for() {
    // Both sides hold more than HISTORY_LIMIT values of one field, pruned the same way: the
    // entries each pruned are accounted for, so the honest absorption reports nothing and the
    // merged snapshot can be written.
    let mut a = Device::new(1, 0);
    let mut b = Device::new(2, 0);
    for i in 0..60u8 {
        a.write(&Edit::write(&[("item.name", &text(&format!("v{i}")))]));
    }
    b.receive(&a.ops());
    a.write(&Edit::write(&[("item.name", &text("a"))]));
    b.write(&Edit::write(&[("item.name", &text("b"))]));
    let s = a.snapshot().unwrap();
    record_headers(&mut b.merge, &a.ops());
    let x = b.absorb(&s, &[]);
    assert_eq!(absorbed(&x).relation, VvOrdering::Concurrent);
    assert!(absorbed(&x).disagreements.is_empty());
    assert_eq!(history(&b.merge, "item.name").len(), HISTORY_LIMIT);
    assert_eq!(
        b.merge.end_fetch(),
        Some(SnapshotTrigger::MergedAfterConcurrentAbsorption)
    );
    assert!(b.merge.write_snapshot().is_ok());
    let mut all = a.ops();
    all.extend(b.ops());
    assert_eq!(state_bytes(&b.merge), state_bytes(&reference(&all)));
}

// ---------------------------------------------------------------------------------------------
// Bounded work on hostile covers.
// ---------------------------------------------------------------------------------------------

/// A verified op header of the test item at `d` with `hlc` and `context`.
fn raw_header(d: Dot, hlc: Hlc, context: VersionVector) -> OpHeader {
    let mut op_id = [d.device_id().as_bytes()[0]; 16];
    op_id[8..].copy_from_slice(&d.seq().to_be_bytes());
    OpHeader {
        vault_id: super::testkit::vault(),
        item_id: item(),
        op_id: rizzy_core::ids::OpId::from_bytes(op_id),
        dot: d,
        vault_prev_seq: d.seq() - 1,
        hlc,
        item_schema_version: ItemSchemaVersion::V1,
        vault_key_epoch: 0,
        causal_context: context,
    }
}

#[test]
fn a_large_hostile_cover_is_absorbed_and_later_ops_recompute_only_their_keys() {
    // Within the ADR 0018 §10 limits, a signed cover can hold 64 keys of 256 concurrent values
    // each, at 256 verified dots whose (hostile) contexts are empty. Absorbing it and then
    // applying ops that each write one key recompute only the keys involved, with the
    // per-device supersession index: linear work, where a pairwise test of every key at every
    // op would make about 65 x 256^2 x 32, over 10^8, context lookups here.
    let names: Vec<String> = (0..64u8)
        .map(|i| {
            format!(
                "zz.{}{}",
                char::from(b'a' + i / 26),
                char::from(b'a' + i % 26)
            )
        })
        .collect();
    let dots: Vec<(Dot, Hlc)> = (1..=4u8)
        .flat_map(|b| (1..=64u64).map(move |s| (dot(b, s), Hlc::from_u64(super::testkit::T0 + s))))
        .collect();
    let mut r = ItemMerge::new(item());
    for &(d, h) in &dots {
        r.record_header(&raw_header(d, h, VersionVector::new()))
            .unwrap();
    }
    let value = text("v");
    let active = [0x01u8];
    let lifecycle = Register::new(
        FieldKey::LIFECYCLE,
        dots.iter()
            .map(|&(d, h)| Entry::new(d, h, Value::new(&active)))
            .collect(),
    );
    let registers: Vec<Register<'_>> = core::iter::once(lifecycle)
        .chain(names.iter().map(|k| {
            Register::new(
                FieldKey::new(k).unwrap(),
                dots.iter()
                    .map(|&(d, h)| Entry::new(d, h, Value::new(&value)))
                    .collect(),
            )
        }))
        .collect();
    let covered: VersionVector = dots.iter().map(|&(d, _)| d).collect();
    let cover = Snap::build(
        1,
        1,
        covered,
        &SnapshotData::Live(LiveSnapshot::new(registers, Vec::new())),
    );
    let x = absorb(&mut r, &cover, &[]);
    assert!(absorbed(&x).disagreements.is_empty());
    assert_eq!(r.field(&names[0]).unwrap().current.len(), 256);
    // A fifth device overwrites each key in turn, its context the whole item VV.
    for (seq, name) in (1..=32u64).zip(&names) {
        let d = dot(5, seq);
        let header = raw_header(
            d,
            Hlc::from_u64(super::testkit::T0 + 1_000 + seq),
            r.covered().clone(),
        );
        let fresh = text("fresh");
        let data = OpData::new(
            Lifecycle::Active,
            vec![crate::record::Write::new(
                FieldKey::new(name).unwrap(),
                Value::new(&fresh),
            )],
        );
        let encoded = crate::record::encode_op(&data).unwrap();
        let parsed = crate::record::parse_op(encoded.expose_secret()).unwrap();
        r.apply_op(OpInput {
            header: &header,
            key_id: key_id(0x40),
            data: &parsed,
        })
        .unwrap();
    }
    let first = r.field(&names[0]).unwrap();
    assert_eq!(first.current.len(), 1);
    assert_eq!(first.history.len(), HISTORY_LIMIT);
    assert_eq!(r.field(&names[40]).unwrap().current.len(), 256);
}
