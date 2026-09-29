//! Named scenarios: the examples the ADRs name, and the merge spike's named regression cases
//! (`tests/model.rs`, `tests/families.rs`) ported to whole-system runs. Each ends with the
//! quiescent checks of [`World::check_quiescent`], so each also checks properties 1–4, 6 and 7.
//!
//! | Test | Source |
//! |---|---|
//! | [`adr0012_withheld_edit_while_another_item_is_compacted`] | ADR 0012 §7 "Chain check after compaction", the example |
//! | [`adr0021_concurrent_purges_in_both_orders`] | ADR 0021 §8 "Named scenarios": T_A then T_B, and T_B then T_A |
//! | [`adr0021_late_edits_of_a_device_that_never_returns`] | ADR 0021 §8 "Named scenarios": S_L with 33 late edits |
//! | [`adr0018_e1_e2_concurrent_with_a_purge`] | ADR 0018 §3 "Why the arrival order does not matter"; spike `adr0018_e1_e2_purge_example` |
//! | [`active_wins_over_a_concurrent_trash`] | ADR 0012 §5; spike `active_wins_over_concurrent_trash` |
//! | [`restore_then_healing_then_a_new_device`] | ADR 0021 §8 "restores followed by healing requests"; spike `healing` family |
//! | [`a_revoked_device_writing_past_its_cut_off`] | ADR 0012 §6; spike `revocation` family |
//! | [`adr0018_concurrent_purges_record_the_highest`] | ADR 0018 §3 "Tombstone (c)"; spike `adr0018_concurrent_purges_record_highest` (one item key) |
//! | [`adr0018_purge_over_active_and_ops_after_the_purge`] | ADR 0018 §3 "A Purge is never rejected", "Applying" 3; spike test of the same name |
//! | [`an_oversize_item_across_compaction_and_a_restore`] | ADR 0021 §5 "Oversize items", §8; ADR 0018 owner decision 12 |
//! | [`a_lost_answer_across_a_restore`] | ADR 0021 §2 "Restore generation", §9; spike `stale_sent_resolution` |
//! | [`finding_a_paged_tombstone_cover_split_from_its_purge_stalls`] | a finding: ADR 0021 §4 paging against ADR 0018 §3 "Snapshots are claims" |
//! | [`a_claimed_dot_never_swallows_the_genuine_op`] | ADR 0018 §3 "Snapshots are claims"; ADR 0021 §8 claims of unheld dots; spike `tests/faulty.rs` test of the same name |
//! | [`an_omitting_snapshot_never_removes_a_held_value`] | ADR 0018 §3 "The absence of a value is never evidence"; spike `tests/faulty.rs` test of the same name |
//! | [`a_tombstone_that_records_a_known_write_is_refused`] | ADR 0018 §3 "refuses ... a snapshot that contradicts an op body it holds"; spike `tests/faulty.rs` test of the same name |
//! | [`heal_prefers_bodies_against_faulty_sole_covers`] | ADR 0021 §9 "Healing request"; spike `tests/families.rs` test of the same name |

use super::KEYS;
use super::faults::{self, Fault};
use super::oracle::{State, held};
use super::world::{Faults, Step, World};
use crate::causal::Report;
use crate::merge::ItemLifecycle;

/// Uploads then fetches for device `d`.
fn sync(w: &mut World, d: usize) {
    w.step(Step::Upload { d, lose: false });
    w.step(Step::Fetch { d });
}

/// Drains and checks every quiescent property, failing the test on a violation.
fn settle(w: &mut World) {
    assert!(w.drain(), "the drain did not reach quiescence");
    w.check_quiescent(3);
    if let Err(e) = w.verdict() {
        panic!("{e}");
    }
}

/// The state device `d` holds of item `i`.
fn state(w: &World, d: usize, i: usize) -> State {
    let item = w.items[i];
    held(&w.devices[d].items[&item]).unwrap()
}

/// ADR 0012 §7: seq 12 of the example (here seq 2), the only edit of Z, is withheld while X is
/// compacted behind two authors' snapshots; the laptop reports the gap and settles nothing past it.
#[test]
fn adr0012_withheld_edit_while_another_item_is_compacted() {
    // D = 0 writes seq 1 on X, seq 2 (the only edit of Z), then seqs 3..=40 on X. E = 1 and
    // F = 2 snapshot X; the laptop (3) synced after seq 1 and was offline since.
    let mut w = World::new(4, 4, 2, 1, Faults::default());
    w.step(Step::Write { d: 0, i: 0, k: 0 });
    sync(&mut w, 0);
    w.step(Step::Fetch { d: 3 });
    w.step(Step::Toggle { d: 3 });
    w.step(Step::Write { d: 0, i: 1, k: 0 });
    for _ in 0..38 {
        w.step(Step::Write { d: 0, i: 0, k: 1 });
    }
    sync(&mut w, 0);
    for d in [1, 2] {
        w.step(Step::Fetch { d });
        w.step(Step::Snapshot { d, i: 0 });
        w.step(Step::Upload { d, lose: false });
    }
    w.step(Step::Worker);
    assert!(w.server.stats.bodies_deleted > 30, "X was not compacted");
    let d_id = w.id(0).unwrap();
    let z_edit = w.dots_of(0, 1)[0];
    assert_eq!(z_edit.seq(), 2);
    w.withhold(3, Some(z_edit));
    w.step(Step::Toggle { d: 3 });
    w.step(Step::Fetch { d: 3 });
    let laptop = &w.devices[3];
    assert!(
        laptop
            .reports
            .iter()
            .any(|r| matches!(r, Report::Gap { device, after: 1, .. } if *device == d_id)),
        "the withheld edit was not reported: {:?}",
        laptop.reports
    );
    assert_eq!(laptop.log.head(d_id), 1, "the chain went past the gap");
    let z = w.items[1];
    assert!(!laptop.log.settled(z).covers(z_edit));
    assert!(
        laptop
            .items
            .get(&z)
            .is_none_or(|m| !m.covered().covers(z_edit))
    );
    w.withhold(3, None);
    w.devices[3].reports.clear();
    settle(&mut w);
}

/// ADR 0021 §8: concurrent purges uploaded as `T_A` then `T_B` and the reverse, a device that was
/// behind fetching after each upload and `worker` run: no false gap, one tombstone.
#[test]
fn adr0021_concurrent_purges_in_both_orders() {
    for a_first in [true, false] {
        // A = 0 and B = 1 purge concurrently; C = 2 is behind and fetches after each upload.
        let mut w = World::new(4, 3, 1, 2, Faults::default());
        w.step(Step::Write { d: 0, i: 0, k: 0 });
        sync(&mut w, 0);
        w.step(Step::Fetch { d: 2 });
        w.step(Step::Trash { d: 0, i: 0 });
        sync(&mut w, 0);
        w.step(Step::Fetch { d: 1 });
        w.step(Step::Purge { d: 0, i: 0 });
        w.step(Step::Purge { d: 1, i: 0 });
        assert_eq!(w.lifecycle(0, 0), ItemLifecycle::Purged);
        assert_eq!(w.lifecycle(1, 0), ItemLifecycle::Purged);
        let order = if a_first { [0, 1] } else { [1, 0] };
        for d in order {
            w.step(Step::Upload { d, lose: false });
            w.step(Step::Fetch { d: 2 });
            w.step(Step::Worker);
            w.step(Step::Fetch { d: 2 });
        }
        w.join(3);
        w.step(Step::Fetch { d: 3 });
        let reported: Vec<&Report> = w.devices[2]
            .reports
            .iter()
            .chain(&w.devices[3].reports)
            .filter(|r| !matches!(r, Report::Duplicate { .. }))
            .collect();
        assert!(reported.is_empty(), "a false gap: {reported:?}");
        settle(&mut w);
        assert!(matches!(state(&w, 3, 0), State::Tombstone { .. }));
    }
}

/// ADR 0021 §8: `S_L` with 33 late edits, two tombstone snapshots that miss them, L never
/// returning, then a new device: the new device ends with the edits as a late value.
#[test]
fn adr0021_late_edits_of_a_device_that_never_returns() {
    // A = 0, B = 1, the laptop L = 2, a device N = 3 enrolled at the end.
    let mut w = World::new(4, 3, 1, 3, Faults::default());
    w.step(Step::Write { d: 0, i: 0, k: 0 });
    sync(&mut w, 0);
    w.step(Step::Fetch { d: 1 });
    w.step(Step::Fetch { d: 2 });
    w.step(Step::Toggle { d: 2 });
    w.step(Step::Trash { d: 0, i: 0 });
    sync(&mut w, 0);
    w.step(Step::Fetch { d: 1 });
    w.step(Step::Purge { d: 1, i: 0 });
    sync(&mut w, 1);
    w.step(Step::Fetch { d: 0 });
    // L, offline since before the trash, writes 33 late edits: the 33rd fires the snapshot
    // trigger (more than 32 ops), so L uploads the edits and a live snapshot S_L.
    for _ in 0..33 {
        w.step(Step::Write { d: 2, i: 0, k: 2 });
    }
    w.step(Step::Toggle { d: 2 });
    w.step(Step::Upload { d: 2, lose: false });
    // Two tombstone snapshots that miss the edits (written before A and B fetch them).
    w.step(Step::Snapshot { d: 0, i: 0 });
    w.step(Step::Upload { d: 0, lose: false });
    w.step(Step::Worker);
    w.step(Step::Snapshot { d: 1, i: 0 });
    w.step(Step::Upload { d: 1, lose: false });
    w.step(Step::Worker);
    // L never returns.
    w.leave(2);
    w.join(3);
    settle(&mut w);
    match state(&w, 3, 0) {
        State::Tombstone { late, .. } => assert!(
            late.get(KEYS[2]).is_some_and(|v| v.len() == 1),
            "the new device lost the late edits"
        ),
        other => panic!("not a tombstone: {:?}", matches!(other, State::Live { .. })),
    }
}

/// ADR 0018 §3: E1 then E2 by L, concurrent with purge P, in the orders E1 E2 P, P E1 E2 and
/// E1 P E2: the late register is {E2} on every device.
#[test]
fn adr0018_e1_e2_concurrent_with_a_purge() {
    // In the orders E1 E2 P, P E1 E2 and E1 P E2 the late register is {E2}.
    for order in 0..3 {
        // L = 0 edits, P = 1 purges, O = 2 observes.
        let mut w = World::new(3, 3, 1, 4, Faults::default());
        w.step(Step::Write { d: 1, i: 0, k: 0 });
        sync(&mut w, 1);
        w.step(Step::Fetch { d: 0 });
        w.step(Step::Fetch { d: 2 });
        w.step(Step::Write { d: 0, i: 0, k: 2 });
        let purge = |w: &mut World| {
            w.step(Step::Trash { d: 1, i: 0 });
            w.step(Step::Purge { d: 1, i: 0 });
            w.step(Step::Upload { d: 1, lose: false });
        };
        match order {
            0 => {
                w.step(Step::Write { d: 0, i: 0, k: 2 });
                w.step(Step::Upload { d: 0, lose: false });
                purge(&mut w);
            }
            1 => {
                purge(&mut w);
                w.step(Step::Write { d: 0, i: 0, k: 2 });
                w.step(Step::Upload { d: 0, lose: false });
            }
            _ => {
                w.step(Step::Upload { d: 0, lose: false });
                purge(&mut w);
                w.step(Step::Write { d: 0, i: 0, k: 2 });
                w.step(Step::Upload { d: 0, lose: false });
            }
        }
        let e2 = *w.dots_of(0, 0).last().unwrap();
        settle(&mut w);
        for d in 0..3 {
            match state(&w, d, 0) {
                State::Tombstone { late, .. } => {
                    let values = &late[KEYS[2]];
                    assert_eq!(values.len(), 1);
                    assert!(values.iter().all(|(dot, _, _)| *dot == e2));
                }
                State::Live { .. } | State::Absent => panic!("order {order}: not a tombstone"),
            }
        }
    }
}

/// ADR 0012 §5 "Active wins": a trash concurrent with an edit shows Active everywhere.
#[test]
fn active_wins_over_a_concurrent_trash() {
    let mut w = World::new(3, 3, 1, 5, Faults::default());
    w.step(Step::Write { d: 0, i: 0, k: 0 });
    sync(&mut w, 0);
    w.step(Step::Fetch { d: 1 });
    w.step(Step::Trash { d: 0, i: 0 });
    w.step(Step::Write { d: 1, i: 0, k: 1 });
    settle(&mut w);
    for d in 0..3 {
        assert_eq!(w.lifecycle(d, 0), ItemLifecycle::Active);
    }
}

/// A restore to a backup behind compacted ops: the devices heal the server, and a device
/// enrolled after the restore converges with them.
#[test]
fn restore_then_healing_then_a_new_device() {
    // A = 0, B = 1, C = 2 write, snapshot and compact after a backup; the server is restored;
    // the devices heal it; D = 3, enrolled after the restore, must reach the same state.
    let mut w = World::new(4, 3, 2, 6, Faults::default());
    w.step(Step::Write { d: 0, i: 0, k: 0 });
    sync(&mut w, 0);
    w.step(Step::Backup);
    for round in 0..3 {
        for d in 0..3 {
            w.step(Step::Write {
                d,
                i: round % 2,
                k: d,
            });
            sync(&mut w, d);
        }
    }
    for d in 0..2 {
        w.step(Step::Fetch { d });
        w.step(Step::Snapshot { d, i: 0 });
        w.step(Step::Upload { d, lose: false });
    }
    w.step(Step::Worker);
    assert!(w.server.stats.bodies_deleted > 0, "nothing was compacted");
    for d in 0..3 {
        w.step(Step::Fetch { d });
    }
    w.step(Step::RestoreServer);
    w.join(3);
    settle(&mut w);
    let heals: u64 = w.devices.iter().map(|d| d.stats.heals).sum();
    assert!(heals > 0, "nothing was healed");
}

/// A revoked device that does not know it writes, snapshots and uploads past its cut-off: the
/// server refuses it, and nobody holds its ops past the cut-off.
#[test]
fn a_revoked_device_writing_past_its_cut_off() {
    let mut w = World::new(4, 4, 2, 7, Faults::default());
    for d in 0..4 {
        w.step(Step::Write { d, i: d % 2, k: 0 });
        sync(&mut w, d);
    }
    w.step(Step::Snapshot { d: 3, i: 1 });
    w.step(Step::Upload { d: 3, lose: false });
    let cutoff = w.server.heads().get(w.id(3).unwrap());
    w.step(Step::Revoke { d: 3 });
    // The revoked device does not know yet: it writes on and tries to upload and snapshot.
    w.step(Step::Write { d: 3, i: 0, k: 1 });
    w.step(Step::Snapshot { d: 3, i: 0 });
    w.step(Step::Upload { d: 3, lose: false });
    assert_eq!(w.dots_of(3, 0).len(), 1, "the revoked device did not write");
    assert_eq!(
        w.server.heads().get(w.id(3).unwrap()),
        cutoff,
        "an op past the cut-off was stored"
    );
    settle(&mut w);
}

/// ADR 0018 §3 "Tombstone (c)" (spike `adr0018_concurrent_purges_record_highest`, without the
/// second item key, which the harness does not model): two concurrent purges, one of them over
/// the purger's own edit; every device records the purge with the highest
/// `(hlc, device_id, seq)`, `c` is the join of both contexts, and the edit the higher purge's
/// context covers leaves no late value.
#[test]
fn adr0018_concurrent_purges_record_the_highest() {
    for upload_first in [1, 2] {
        // A = 0 creates and trashes; B = 1 purges on A's trash; C = 2 edits, trashes, purges.
        let mut w = World::new(3, 3, 1, 8, Faults::default());
        w.step(Step::Write { d: 0, i: 0, k: 0 });
        w.step(Step::Trash { d: 0, i: 0 });
        sync(&mut w, 0);
        w.step(Step::Fetch { d: 1 });
        w.step(Step::Fetch { d: 2 });
        w.step(Step::Write { d: 2, i: 0, k: 1 });
        w.step(Step::Trash { d: 2, i: 0 });
        w.step(Step::Purge { d: 1, i: 0 });
        w.step(Step::Purge { d: 2, i: 0 });
        let p1 = *w.dots_of(1, 0).last().unwrap();
        let p2 = *w.dots_of(2, 0).last().unwrap();
        assert_eq!((p1.seq(), p2.seq()), (1, 3), "a purge was not written");
        let (h1, h2) = (w.header_of(p1).unwrap(), w.header_of(p2).unwrap());
        let rank = |h: &crate::header::OpHeader| (h.hlc, h.dot.device_id().to_bytes(), h.dot.seq());
        let highest = if rank(h1) > rank(h2) { p1 } else { p2 };
        let mut c = h1.causal_context.clone();
        c.join(&h2.causal_context);
        w.step(Step::Upload {
            d: upload_first,
            lose: false,
        });
        w.step(Step::Upload {
            d: 3 - upload_first,
            lose: false,
        });
        settle(&mut w);
        for d in 0..3 {
            match state(&w, d, 0) {
                State::Tombstone {
                    purge_dot,
                    context,
                    late,
                    ..
                } => {
                    assert_eq!(purge_dot, highest, "device {d}");
                    assert_eq!(context, c, "device {d}");
                    assert!(
                        late.values()
                            .all(|v| v.iter().all(|(dot, _, _)| !c.covers(*dot))),
                        "device {d}: a late value the purges' contexts cover"
                    );
                }
                State::Live { .. } | State::Absent => panic!("device {d}: not a tombstone"),
            }
        }
    }
}

/// ADR 0018 §3 "A Purge is never rejected" and "Applying" 3 (spike
/// `adr0018_purge_over_active_and_ops_after_the_purge`): a purge concurrent with a restore and
/// an edit makes a tombstone whose late register holds the edit; a late trash only advances the
/// VV; an edit written over the tombstone (its context covers the purge) replaces the late
/// value it covers with its own. Three upload orders.
#[test]
fn adr0018_purge_over_active_and_ops_after_the_purge() {
    for order in [[0, 1, 2], [2, 1, 0], [1, 2, 0]] {
        // A = 0 creates, trashes and purges; B = 1 restores, then trashes late; C = 2 edits.
        let mut w = World::new(3, 3, 1, 9, Faults::default());
        w.step(Step::Write { d: 0, i: 0, k: 0 });
        w.step(Step::Trash { d: 0, i: 0 });
        sync(&mut w, 0);
        w.step(Step::Fetch { d: 1 });
        w.step(Step::Fetch { d: 2 });
        w.step(Step::Restore { d: 1, i: 0 });
        w.step(Step::Write { d: 2, i: 0, k: 0 });
        w.step(Step::Purge { d: 0, i: 0 });
        w.step(Step::Trash { d: 1, i: 0 });
        let edit = *w.dots_of(2, 0).last().unwrap();
        for d in order {
            w.step(Step::Upload { d, lose: false });
        }
        settle(&mut w);
        for d in 0..3 {
            match state(&w, d, 0) {
                State::Tombstone { late, .. } => {
                    let values = &late[KEYS[0]];
                    assert!(
                        values.len() == 1 && values.iter().all(|(dot, _, _)| *dot == edit),
                        "order {order:?}, device {d}: the late register is not the edit"
                    );
                }
                State::Live { .. } | State::Absent => panic!("device {d}: not a tombstone"),
            }
        }
        // B, which now holds the tombstone, writes over it.
        w.step(Step::Write { d: 1, i: 0, k: 0 });
        let over = *w.dots_of(1, 0).last().unwrap();
        assert!(w.header_of(over).unwrap().causal_context.covers(edit));
        settle(&mut w);
        for d in 0..3 {
            match state(&w, d, 0) {
                State::Tombstone { late, .. } => {
                    let values = &late[KEYS[0]];
                    assert!(
                        values.len() == 1 && values.iter().all(|(dot, _, _)| *dot == over),
                        "order {order:?}, device {d}: the late register is not the edit over it"
                    );
                }
                State::Live { .. } | State::Absent => panic!("device {d}: not a tombstone"),
            }
        }
    }
}

/// ADR 0021 §5 "Oversize items" and ADR 0018 owner decision 12: an item whose state breaks the
/// ADR 0018 §10 group limit writes no snapshot, so the server keeps every body of it while
/// another item is compacted; after a restore the devices heal both, and a device enrolled
/// later converges on both.
#[test]
fn an_oversize_item_across_compaction_and_a_restore() {
    // A = 0 writes item 1 oversize (5,000 registers > MAX_GROUPS); B = 1 and C = 2 snapshot.
    let mut w = World::new(4, 3, 2, 10, Faults::default());
    w.step(Step::Write { d: 0, i: 0, k: 0 });
    sync(&mut w, 0);
    w.step(Step::Backup);
    for round in 0..5_u32 {
        let writes = (0..1_000_u32)
            .map(|k| (format!("tag/{:04x}", round * 1_000 + k), super::text("x")))
            .collect();
        w.write_fields(0, 1, writes);
        w.step(Step::Write { d: 0, i: 0, k: 1 });
    }
    sync(&mut w, 0);
    let oversize = w.items[1];
    for d in 1..3 {
        w.step(Step::Fetch { d });
        w.step(Step::Snapshot { d, i: 0 });
        w.step(Step::Snapshot { d, i: 1 });
        w.step(Step::Upload { d, lose: false });
    }
    assert!(w.devices[1].items[&oversize].is_oversize());
    w.step(Step::Worker);
    assert!(
        !w.server.bodiless(w.items[0]).is_empty(),
        "the other item was not compacted"
    );
    assert!(
        w.server.bodiless(oversize).is_empty(),
        "a body of the oversize item was deleted"
    );
    w.step(Step::RestoreServer);
    w.join(3);
    settle(&mut w);
    assert!(w.server.bodiless(oversize).is_empty());
    assert!(w.devices[3].items[&oversize].is_oversize());
}

/// A lost upload answer across a restore (the spike's `stale_sent_resolution`, ADR 0021 §2
/// "Restore generation", §9 "Stale epoch"): A's op reaches the server, the answer is lost,
/// B fetches it, and the server is restored to a backup without it. A may not treat it as never
/// stored: B heals the server with the same signed record, A's next upload is answered
/// "already stored", and no dot is stored in two versions.
#[test]
fn a_lost_answer_across_a_restore() {
    let mut w = World::new(3, 3, 1, 11, Faults::default());
    w.step(Step::Write { d: 0, i: 0, k: 0 });
    sync(&mut w, 0);
    w.step(Step::Fetch { d: 1 });
    w.step(Step::Backup);
    w.step(Step::Write { d: 0, i: 0, k: 1 });
    w.step(Step::Upload { d: 0, lose: true });
    let sent = *w.dots_of(0, 0).last().unwrap();
    assert_eq!(w.server.heads().get(w.id(0).unwrap()), sent.seq());
    w.step(Step::Fetch { d: 1 });
    assert!(w.devices[1].log.head(w.id(0).unwrap()) >= sent.seq());
    w.step(Step::RestoreServer);
    // B, which holds the op, finds the server behind and heals it first.
    sync(&mut w, 1);
    assert!(w.devices[1].stats.heals > 0, "B did not heal the server");
    w.step(Step::Write { d: 1, i: 0, k: 2 });
    settle(&mut w);
    assert_eq!(
        w.server.stored_header(sent),
        w.header_of(sent),
        "the server stores another version of the op"
    );
}

/// **Finding** (reported, not fixed here): a paged Fetch can put a tombstone cover in the page
/// of the bodiless headers it covers while its recorded purge, a later link of the same chain,
/// falls in the next page. The merge cuts the cover to the headers verified so far (ADR 0018 §3
/// "Snapshots are claims"), so it refuses the tombstone (`PurgeAboveCut`); the bodiless headers
/// then count against no accepted cover, the chain stops at a gap, the cursor stays, and every
/// later Fetch with the same paging repeats it: against an honest server the device never
/// converges. The server cannot page around it: the purge dot is inside the encrypted snapshot.
/// ADR 0021 §4 ("Each page of a paged response carries its own covers") and the spike (which
/// does not model paging) leave this open. This test pins the stall; when the owner settles the
/// rule and the engine changes, it fails and becomes a convergence test.
#[test]
fn finding_a_paged_tombstone_cover_split_from_its_purge_stalls() {
    let faults = Faults {
        page_len: 3,
        page_in_drain: true,
        ..Faults::default()
    };
    // A = 0 writes seqs 1..=4 (write, write, trash, purge); A and B = 1 hold tombstone
    // snapshots; C = 2 enrols after `worker` deleted every body.
    let mut w = World::new(3, 2, 1, 12, faults);
    w.step(Step::Write { d: 0, i: 0, k: 0 });
    w.step(Step::Write { d: 0, i: 0, k: 1 });
    w.step(Step::Trash { d: 0, i: 0 });
    w.step(Step::Purge { d: 0, i: 0 });
    assert_eq!(w.dots_of(0, 0).len(), 4);
    sync(&mut w, 0);
    w.step(Step::Fetch { d: 1 });
    w.step(Step::Snapshot { d: 0, i: 0 });
    w.step(Step::Snapshot { d: 1, i: 0 });
    w.step(Step::Upload { d: 0, lose: false });
    w.step(Step::Upload { d: 1, lose: false });
    w.step(Step::Worker);
    assert_eq!(w.server.bodiless(w.items[0]).len(), 4, "not compacted");
    w.join(2);
    w.drain();
    w.check_quiescent(1);
    let a = w.id(0).unwrap();
    let c = &w.devices[2];
    assert!(c.stats.paged_refused > 0, "the split cover was not refused");
    assert_eq!(c.log.head(a), 0, "the chain went past the refused cover");
    assert!(
        w.verdict().is_err(),
        "the stall no longer happens: settle the finding"
    );
}

/// Device `d` writes a snapshot of item `i` telling `fault`.
fn lie(w: &mut World, d: usize, i: usize, fault: Fault) {
    let fault = faults::ALL.iter().position(|k| *k == fault).unwrap();
    w.step(Step::Lie { d, i, fault });
}

/// The faulty-snapshot scenarios share a shape (the merge spike's `tests/faulty.rs` cases, as
/// whole-system runs): A = 0 writes, C = 3 syncs and goes offline, A writes on, the faulty
/// F = 1 tells `fault` in a snapshot that the server stores, B = 2 writes an honest snapshot,
/// `worker` deletes the bodies behind the two authors, and C comes back to bodiless headers
/// whose covers are B's and F's lie. D = 4 enrols last and takes everything from covers.
/// `first` and `then` are A's writes before and after C leaves.
fn faulty_scenario(fault: Fault, first: Step, then: &[Step]) -> World {
    let mut w = World::new(5, 4, 1, 13, Faults::default());
    w.set_faulty(1, None);
    w.step(first);
    sync(&mut w, 0);
    w.step(Step::Fetch { d: 3 });
    w.step(Step::Toggle { d: 3 });
    for &step in then {
        w.step(step);
    }
    w.step(Step::Upload { d: 0, lose: false });
    if fault != Fault::ClaimHeld {
        // Every lie but the claim is told by a device that holds the ops it lies about.
        w.step(Step::Fetch { d: 1 });
    }
    lie(&mut w, 1, 0, fault);
    w.step(Step::Upload { d: 1, lose: false });
    assert_eq!(w.devices[1].stats.lies_written, 1, "the lie was not told");
    w.step(Step::Fetch { d: 2 });
    w.step(Step::Snapshot { d: 2, i: 0 });
    w.step(Step::Upload { d: 2, lose: false });
    w.step(Step::Worker);
    let last = *w.dots_of(0, 0).last().unwrap();
    assert!(
        w.server.bodiless(w.items[0]).contains(&last),
        "not compacted behind the lie"
    );
    w.step(Step::Toggle { d: 3 });
    w.step(Step::Fetch { d: 3 });
    w
}

/// Spike `a_claimed_dot_never_swallows_the_genuine_op` (ADR 0018 §3 "Snapshots are claims",
/// owner decision 14; ADR 0021 §8 "snapshots that claim unheld dots"): F never saw A's second
/// op, yet its snapshot claims that dot; C, which absorbs the claim with B's honest cover, and
/// D, enrolled last, both end with the op's value.
#[test]
fn a_claimed_dot_never_swallows_the_genuine_op() {
    // F fetches A's first op before A writes the second.
    let mut w = World::new(5, 4, 1, 13, Faults::default());
    w.set_faulty(1, None);
    w.step(Step::Write { d: 0, i: 0, k: 0 });
    sync(&mut w, 0);
    w.step(Step::Fetch { d: 1 });
    w.step(Step::Fetch { d: 3 });
    w.step(Step::Toggle { d: 3 });
    w.step(Step::Write { d: 0, i: 0, k: 1 });
    w.step(Step::Upload { d: 0, lose: false });
    lie(&mut w, 1, 0, Fault::ClaimHeld);
    w.step(Step::Upload { d: 1, lose: false });
    assert_eq!(w.devices[1].stats.lies_written, 1, "the claim was not told");
    w.step(Step::Fetch { d: 2 });
    w.step(Step::Snapshot { d: 2, i: 0 });
    w.step(Step::Upload { d: 2, lose: false });
    w.step(Step::Worker);
    let genuine = *w.dots_of(0, 0).last().unwrap();
    assert!(w.server.bodiless(w.items[0]).contains(&genuine));
    w.step(Step::Toggle { d: 3 });
    w.step(Step::Fetch { d: 3 });
    assert!(
        w.devices[3].stats.lies_absorbed > 0,
        "C never met the claim"
    );
    w.join(4);
    settle(&mut w);
    for d in [3, 4] {
        assert_eq!(state(&w, d, 0), w.expected_state(0), "device {d}");
        assert!(w.devices[d].items[&w.items[0]].covered().covers(genuine));
    }
}

/// Spike `an_omitting_snapshot_never_removes_a_held_value`: F's snapshot omits one of the
/// values of A's first op, which C merged from its body; absorbing it never removes the value
/// from C, and D, enrolled last, gets it from B's honest cover (absence is never evidence).
#[test]
fn an_omitting_snapshot_never_removes_a_held_value() {
    // A's first op writes two keys; then a trash and a restore, which write only @lifecycle,
    // so the value F omits is one of the first op's.
    let mut w = faulty_scenario(
        Fault::OmitValue,
        Step::WriteMany {
            d: 0,
            i: 0,
            mask: 0b11,
        },
        &[Step::Trash { d: 0, i: 0 }, Step::Restore { d: 0, i: 0 }],
    );
    assert!(w.devices[3].stats.lies_absorbed > 0, "C never met the lie");
    w.join(4);
    settle(&mut w);
    for d in [3, 4] {
        assert_eq!(state(&w, d, 0), w.expected_state(0), "device {d}");
    }
}

/// Spike `a_tombstone_that_records_a_known_write_is_refused`: F presents the item as a
/// tombstone whose recorded purge is A's first op, a write C merged from its body; C refuses
/// the cover and stays live with every value. D, enrolled last, holds no body of it: to D the
/// lie is undecidable (the spike's `lifecycle_lie_about_a_compacted_op_is_undecidable`), so
/// it must report the disagreement, which excuses property 1 on the item for this run.
#[test]
fn a_tombstone_that_records_a_known_write_is_refused() {
    let mut w = faulty_scenario(
        Fault::FakeTomb,
        Step::Write { d: 0, i: 0, k: 0 },
        &[Step::Write { d: 0, i: 0, k: 1 }],
    );
    let c = &w.devices[3];
    assert!(
        c.stats.lie_refused > 0,
        "C did not refuse the fake tombstone"
    );
    assert!(
        c.events.iter().any(|e| e.contains("WriteRecordedAsPurge")),
        "{:?}",
        c.events
    );
    assert_eq!(state(&w, 3, 0), w.expected_state(0));
    w.join(4);
    settle(&mut w);
    assert_eq!(state(&w, 3, 0), w.expected_state(0));
    assert!(
        w.devices[4].disagreement_items.contains(&w.items[0]),
        "D took the undecidable lie without reporting it"
    );
}

/// Spike `heal_prefers_bodies_against_faulty_sole_covers` (random seed 6327 of
/// `random-faults-ops`): after a restore lost F's own edit, the faulty F heals the server. It
/// holds the body, so it re-publishes it with its body (ADR 0021 §9 "Healing request": "with
/// its body if it holds the body of a record the server stored before") instead of a bodiless
/// header behind its own omitting fresh snapshot, which would have been the edit's only cover.
/// A device enrolled after the restore ends with the edit.
#[test]
fn heal_prefers_bodies_against_faulty_sole_covers() {
    let mut w = World::new(3, 2, 1, 14, Faults::default());
    w.set_faulty(0, Some(Fault::OmitValue));
    w.step(Step::Write { d: 1, i: 0, k: 0 });
    sync(&mut w, 1);
    w.step(Step::Backup);
    w.step(Step::Write { d: 0, i: 0, k: 1 });
    sync(&mut w, 0);
    let edit = *w.dots_of(0, 0).last().unwrap();
    w.step(Step::Fetch { d: 1 });
    w.step(Step::RestoreServer);
    assert!(
        w.server.stored_header(edit).is_none(),
        "the restore kept it"
    );
    // F finds the server behind and heals it first.
    sync(&mut w, 0);
    assert!(w.devices[0].stats.heals > 0, "F did not heal");
    assert!(
        w.server.stored_header(edit).is_some(),
        "the edit was not healed"
    );
    assert!(
        !w.server.bodiless(w.items[0]).contains(&edit),
        "the edit was healed without its body"
    );
    w.join(2);
    settle(&mut w);
    assert_eq!(state(&w, 2, 0), w.expected_state(0));
}
