// SPDX-License-Identifier: AGPL-3.0-only

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
//! | [`a_revoked_device_decrypts_nothing_written_after_the_rotation`] | ADR 0012 §12 property 6; CRYPTO.md §11.6 (writer rule, wraps), §11.8; ADR 0021 §9 "Stale epoch" |
//! | [`property_6_reports_a_record_sealed_under_a_revoked_key`] | the property 6 check itself: a record sealed under a key the revoked device holds is reported |
//! | [`a_stale_answer_lost_across_a_restore`] | ADR 0021 §9 "Stale epoch" (re-issue, or re-publication of an op that may have been served), §2 "Restore generation"; ADR 0032 §3 lag repair |
//! | [`a_kind4_snapshot_after_expiry`] | ADR 0021 §9 "Revoked and kind-4 authors"; CRYPTO.md §10.2 "Web-vault certificates" |
//! | [`server_rotate_refuses_a_non_advancing_epoch`] | ADR 0025 §3 check 2; a negative control for `Server::rotate`'s `RotationRefusal::Epoch` |
//! | [`server_rotate_refuses_a_cursor_that_is_not_every_head`] | ADR 0025 §3 check 4 ("Rotation cut-off"); a negative control for `RotationRefusal::Cursor`, below and above a head |
//! | [`server_rotate_refuses_a_mismatched_wrap_set`] | ADR 0025 §3 check 3; a negative control for `RotationRefusal::Wraps`: a wrong epoch, a duplicated row, a row named in neither list |
//! | [`a_kind4_author_retrying_an_already_stored_snapshot_is_acknowledged`] | ADR 0021 §9 "Already stored" vs. "Revoked and kind-4 authors": a byte-identical retry from an expired author is acknowledged; a fresh one is refused |

use super::faults::{self, Fault};
use super::oracle::{State, held};
use super::server::{Rotation, RotationRefusal, SnapAnswer, SnapRecord, Wrap, WrapRow};
use super::world::{Faults, Step, World};
use super::{KEYS, crypto};
use crate::causal::Report;
use crate::dot::Dot;
use crate::merge::ItemLifecycle;
use crate::vv::VersionVector;

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

/// ADR 0012 §12 property 6 and CRYPTO.md §11.6: device 3 is revoked in one request with a
/// rotation; the others write on both items afterwards, under fresh item keys created at the
/// new epoch, and devices that had not fetched get stale-epoch answers and re-issue. No envelope
/// written after the rotation opens under any item key the revoked device holds, and no
/// wrap-set row opens under a vault key it holds, while the remaining devices open both.
#[test]
fn a_revoked_device_decrypts_nothing_written_after_the_rotation() {
    let mut w = World::new(4, 4, 2, 23, Faults::default());
    for d in 0..4 {
        w.step(Step::Write { d, i: d % 2, k: 0 });
        sync(&mut w, d);
    }
    for d in 0..4 {
        w.step(Step::Fetch { d });
    }
    // Device 2 writes before the rotation and uploads after it, without fetching first.
    w.step(Step::Write { d: 2, i: 0, k: 1 });
    w.step(Step::Revoke { d: 3 });
    assert_eq!(w.server.epoch(), 1, "the revocation did not rotate");
    w.step(Step::Upload { d: 2, lose: false });
    assert_eq!(w.devices[2].stats.stale_ops, 1, "no stale-epoch answer");
    assert_eq!(
        w.devices[2].stats.reissued, 1,
        "the stale op was not re-issued"
    );
    for d in 0..3 {
        for i in 0..2 {
            w.step(Step::Write { d, i, k: 2 });
        }
        sync(&mut w, d);
        w.step(Step::Snapshot { d, i: 0 });
        w.step(Step::Upload { d, lose: false });
    }
    // The revoked device writes on, unaware; the server refuses it.
    w.step(Step::Write { d: 3, i: 0, k: 3 });
    w.step(Step::Upload { d: 3, lose: false });
    settle(&mut w);
    assert!(
        w.p6_checked.0 > 0 && w.p6_checked.1 > 0,
        "{:?}",
        w.p6_checked
    );

    // The same checks spelled out here: every op body and snapshot of the server written at the
    // new epoch, against every key the revoked device holds.
    let revoked = w.devices[3].held_keys();
    let vault_keys = w.devices[3].vault_keys.clone();
    assert!(!vault_keys.contains(&1));
    let (ops, snaps) = w.server.envelopes();
    let mut fresh = 0;
    for (header, envelope) in ops.iter().filter(|(h, _)| h.vault_key_epoch >= 1) {
        fresh += 1;
        let key = crypto::envelope_key(envelope).unwrap();
        assert!(!revoked.contains(&key));
        assert!(
            revoked
                .iter()
                .all(|k| !crypto::op_opens_under(header, envelope, k))
        );
        assert!(crypto::op_opens_under(header, envelope, &key));
    }
    for s in snaps.iter().filter(|s| s.header.vault_key_epoch >= 1) {
        fresh += 1;
        let key = crypto::envelope_key(&s.data).unwrap();
        assert!(
            revoked
                .iter()
                .all(|k| !crypto::snapshot_opens_under(&s.header, &s.data, k))
        );
        assert!(crypto::snapshot_opens_under(&s.header, &s.data, &key));
    }
    assert!(fresh > 0, "nothing was written after the rotation");
    let rows = w.server.rows();
    assert!(!rows.is_empty(), "no fresh item key was wrapped");
    for row in &rows {
        assert_eq!(row.wrap.epoch, 1);
        assert!(
            vault_keys
                .iter()
                .all(|&v| crypto::unwrap(v, row.item, &row.wrap.envelope).is_none())
        );
        assert_eq!(
            crypto::unwrap(1, row.item, &row.wrap.envelope),
            Some(row.key)
        );
    }
}

/// The checks of property 6 can fail: a record sealed after the rotation under an item key the
/// revoked device holds (an initial key, which the writer rule forbids at the new epoch), signed
/// by a remaining device and stored by the server, which holds no key and cannot tell, is
/// reported.
#[test]
fn property_6_reports_a_record_sealed_under_a_revoked_key() {
    let mut w = World::new(4, 4, 1, 24, Faults::default());
    for d in 0..4 {
        w.step(Step::Write { d, i: 0, k: 0 });
        sync(&mut w, d);
    }
    w.step(Step::Revoke { d: 3 });
    w.step(Step::Fetch { d: 0 });
    let item = w.items[0];
    let header = crate::header::SnapshotHeader {
        vault_id: super::VAULT,
        item_id: item,
        snapshot_id: rizzy_core::ids::SnapshotId::from_bytes([0x99; 16]),
        author: w.devices[0].id,
        item_schema_version: crate::header::ItemSchemaVersion::V1,
        vault_key_epoch: 1,
        covered: w.devices[0].items[&item].covered().clone(),
    };
    let data = w.devices[0].items[&item].snapshot_data().unwrap().unwrap();
    let data = crate::record::encode_snapshot(&header.covered, &data).unwrap();
    let mut nonces = crypto::Nonces::new(24, w.devices[0].id);
    let old = crypto::initial_key(item);
    let envelope = crypto::seal_snapshot(&mut nonces, &header, &old, data.expose_secret()).unwrap();
    let record = SnapRecord {
        signed: crypto::sign_snapshot(&header, &envelope).unwrap(),
        header,
        data: envelope,
        wrap: None,
        tainted: false,
    };
    assert_eq!(w.server.upload_snapshot(&record), SnapAnswer::Stored);
    w.step(Step::Worker);
    let found: Vec<&String> = w
        .violations
        .iter()
        .filter(|v| v.contains("property 6") || v.contains("writer rule"))
        .collect();
    assert!(
        found.iter().any(|v| v.contains("property 6"))
            && found.iter().any(|v| v.contains("writer rule")),
        "{:?}",
        w.violations
    );
}

/// ADR 0021 §9 "Stale epoch" across a restore (ADR 0032): a backup, then a rotation; device B,
/// which has not fetched since, writes an op at the old epoch; the server is restored to the
/// backup, rolling its epoch back, and C, whose epoch is newer, repairs it first (ADR 0032 §3).
/// B's upload then gets a stale-epoch answer. If B's first send of the op went without an
/// answer before the restore, the server may have stored and served it: B never re-issues it,
/// and re-publishes it verbatim in a healing request. Otherwise B re-issues it with the same
/// `device_seq` under the current epoch and a fresh item key. Both converge.
#[test]
fn a_stale_answer_lost_across_a_restore() {
    for lost in [true, false] {
        let mut w = World::new(3, 3, 1, 21, Faults::default());
        w.step(Step::Write { d: 0, i: 0, k: 0 });
        sync(&mut w, 0);
        w.step(Step::Fetch { d: 1 });
        w.step(Step::Fetch { d: 2 });
        w.step(Step::Backup);
        w.step(Step::Rotate { d: 2 });
        assert_eq!(w.server.epoch(), 1, "lost {lost}: no rotation");
        w.step(Step::Write { d: 1, i: 0, k: 1 });
        let op = *w.dots_of(1, 0).last().unwrap();
        assert_eq!(w.header_of(op).unwrap().vault_key_epoch, 0);
        if lost {
            // The server answers "stale epoch"; the answer never arrives.
            w.step(Step::Upload { d: 1, lose: true });
            assert!(w.server.stored_header(op).is_none());
            assert_eq!(w.server.stats.stale_ops, 1);
        }
        w.step(Step::RestoreServer);
        assert_eq!(w.server.epoch(), 0, "the restore kept the epoch");
        sync(&mut w, 2);
        assert_eq!(
            w.server.epoch(),
            1,
            "lost {lost}: C did not repair the epoch"
        );
        assert_eq!(w.server.stats.epoch_heals, 1);
        sync(&mut w, 1);
        sync(&mut w, 1);
        let b = &w.devices[1].stats;
        assert!(b.stale_ops >= 1, "lost {lost}: {b:?}");
        let stored = w.server.stored_header(op).cloned().unwrap();
        if lost {
            assert_eq!((b.republished, b.reissued), (1, 0), "{b:?}");
            assert_eq!(stored.vault_key_epoch, 0, "a maybe-served op was re-issued");
        } else {
            assert_eq!((b.republished, b.reissued), (0, 1), "{b:?}");
            assert_eq!(stored.vault_key_epoch, 1);
            assert_eq!(stored.dot, op, "the re-issue changed the dot");
        }
        assert_eq!(Some(&stored), w.header_of(op), "the ledger disagrees");
        settle(&mut w);
    }
}

/// ADR 0021 §9 "Revoked and kind-4 authors": a web vault (kind 4) and a durable device each
/// snapshot the item, `worker` compacts behind both, then the certificate expires with an op
/// and a snapshot unsent: the server refuses both, the web vault is gone, and its retained
/// snapshot keeps counting as a cover for a device enrolled after the expiry, which converges
/// on the state of the ops the server holds.
#[test]
fn a_kind4_snapshot_after_expiry() {
    let mut w = World::new(4, 3, 1, 22, Faults::default());
    w.set_kind4(2, super::T0 + 10_000);
    for d in [2, 0, 2, 0] {
        w.step(Step::Write { d, i: 0, k: d });
        sync(&mut w, d);
    }
    for d in [2, 0] {
        sync(&mut w, d);
        w.step(Step::Snapshot { d, i: 0 });
        w.step(Step::Upload { d, lose: false });
    }
    w.step(Step::Worker);
    assert!(!w.server.bodiless(w.items[0]).is_empty(), "not compacted");
    // An op and a snapshot the web vault never sends before its certificate expires.
    w.step(Step::Write { d: 2, i: 0, k: 3 });
    let unsent = *w.dots_of(2, 0).last().unwrap();
    w.pass_time(20_000);
    assert!(w.is_expired(2));
    assert!(w.server.stored_header(unsent).is_none());
    assert!(w.server.stats.expired_uploads > 0, "{:?}", w.server.stats);
    assert!(w.server.stats.expired_snapshots > 0, "{:?}", w.server.stats);
    w.join(3);
    settle(&mut w);
    assert!(w.server.stats.expired_covers > 0, "{:?}", w.server.stats);
    assert_eq!(state(&w, 3, 0), w.expected_state(0));
}

/// ADR 0025 §3 check 2: a rotation whose epoch is not above the vault's stored one is refused
/// as `RotationRefusal::Epoch`, and changes nothing. [`World::rotate`] never builds one of
/// these (it always computes a strictly-increasing epoch), so there was no negative control on
/// [`Server::rotate`] itself.
#[test]
fn server_rotate_refuses_a_non_advancing_epoch() {
    let mut w = World::new(3, 3, 1, 101, Faults::default());
    w.step(Step::Write { d: 0, i: 0, k: 0 });
    sync(&mut w, 0);
    w.step(Step::Rotate { d: 0 });
    assert_eq!(w.server.epoch(), 1, "the rotation did not land");
    let epoch_before = w.server.epoch();
    let rows_before = w.server.rows();
    let heads = w.server.heads();

    // Equal to the stored epoch, and below it: neither advances.
    for stale_epoch in [epoch_before, 0] {
        let rotation = Rotation {
            epoch: stale_epoch,
            cursor: heads.clone(),
            rewrapped: Vec::new(),
            dropped: Vec::new(),
            revoke: None,
        };
        assert_eq!(w.server.rotate(&rotation), Err(RotationRefusal::Epoch));
        assert_eq!(
            w.server.epoch(),
            epoch_before,
            "a refused rotation moved the epoch"
        );
        assert_eq!(
            w.server.rows(),
            rows_before,
            "a refused rotation changed the rows"
        );
    }
}

/// ADR 0025 §3 check 4 ("Rotation cut-off"): a rotation whose cursor is not every head h(V, d)
/// is refused as `RotationRefusal::Cursor`, both below a head (ADR 0012 §6's refusal
/// territory) and above one ("the server is behind", ADR 0021 §9), and changes nothing.
/// [`World::rotate`] pre-validates this with the server's own predicate before ever sending a
/// `Rotation`, so there was no negative control on [`Server::rotate`] itself.
#[test]
fn server_rotate_refuses_a_cursor_that_is_not_every_head() {
    let mut w = World::new(3, 3, 1, 102, Faults::default());
    w.step(Step::Write { d: 0, i: 0, k: 0 });
    sync(&mut w, 0);
    w.step(Step::Rotate { d: 0 });
    assert_eq!(w.server.epoch(), 1, "the rotation did not land");
    let epoch_before = w.server.epoch();
    let rows_before = w.server.rows();
    let heads = w.server.heads();
    let author = w.devices[0].id;

    let below = Rotation {
        epoch: epoch_before + 1,
        cursor: VersionVector::new(),
        rewrapped: Vec::new(),
        dropped: Vec::new(),
        revoke: None,
    };
    assert_eq!(w.server.rotate(&below), Err(RotationRefusal::Cursor));
    assert_eq!(
        w.server.epoch(),
        epoch_before,
        "a refused rotation moved the epoch"
    );
    assert_eq!(
        w.server.rows(),
        rows_before,
        "a refused rotation changed the rows"
    );

    let mut above_cursor = heads.clone();
    above_cursor.add(Dot::new(author, heads.get(author) + 1).expect("a nonzero seq"));
    let above = Rotation {
        epoch: epoch_before + 1,
        cursor: above_cursor,
        rewrapped: Vec::new(),
        dropped: Vec::new(),
        revoke: None,
    };
    assert_eq!(w.server.rotate(&above), Err(RotationRefusal::Cursor));
    assert_eq!(
        w.server.epoch(),
        epoch_before,
        "a refused rotation moved the epoch"
    );
    assert_eq!(
        w.server.rows(),
        rows_before,
        "a refused rotation changed the rows"
    );
}

/// ADR 0025 §3 check 3: a rotation is refused as `RotationRefusal::Wraps` when a rewrapped row
/// is not at the new epoch, when a row is named twice across `rewrapped` and `dropped`, or when
/// a stored row is named in neither list, and each refusal changes nothing.
/// [`World::rotate`] always builds `rewrapped`/`dropped` directly from the server's own rows
/// ([`Device::rewrap`](super::device::Device::rewrap)), so there was no negative control on
/// [`Server::rotate`] itself.
#[test]
fn server_rotate_refuses_a_mismatched_wrap_set() {
    let mut w = World::new(3, 3, 1, 103, Faults::default());
    // The initial, enrolment-time item key has no wrap-set row (CRYPTO.md §11.6): one is
    // created only once the writer rule gives this item a fresh key after a rotation.
    w.step(Step::Write { d: 0, i: 0, k: 0 });
    sync(&mut w, 0);
    w.step(Step::Rotate { d: 0 });
    assert_eq!(w.server.epoch(), 1, "the rotation did not land");
    w.step(Step::Write { d: 0, i: 0, k: 1 });
    sync(&mut w, 0);
    let epoch_before = w.server.epoch();
    let rows_before = w.server.rows();
    assert_eq!(
        rows_before.len(),
        1,
        "expected exactly one post-rotation row: {rows_before:?}"
    );
    let row = rows_before[0].clone();
    let heads = w.server.heads();

    // A rewrapped row not at the new epoch.
    let wrong_epoch = Rotation {
        epoch: epoch_before + 1,
        cursor: heads.clone(),
        rewrapped: vec![WrapRow {
            item: row.item,
            key: row.key,
            wrap: Wrap {
                epoch: epoch_before,
                envelope: row.wrap.envelope.clone(),
            },
        }],
        dropped: Vec::new(),
        revoke: None,
    };
    assert_eq!(w.server.rotate(&wrong_epoch), Err(RotationRefusal::Wraps));
    assert_eq!(
        w.server.epoch(),
        epoch_before,
        "a refused rotation moved the epoch"
    );
    assert_eq!(
        w.server.rows(),
        rows_before,
        "a refused rotation changed the rows"
    );

    // The same (item, key) named twice, across rewrapped and dropped.
    let duplicate = Rotation {
        epoch: epoch_before + 1,
        cursor: heads.clone(),
        rewrapped: vec![WrapRow {
            item: row.item,
            key: row.key,
            wrap: Wrap {
                epoch: epoch_before + 1,
                envelope: row.wrap.envelope.clone(),
            },
        }],
        dropped: vec![(row.item, row.key)],
        revoke: None,
    };
    assert_eq!(w.server.rotate(&duplicate), Err(RotationRefusal::Wraps));
    assert_eq!(
        w.server.epoch(),
        epoch_before,
        "a refused rotation moved the epoch"
    );
    assert_eq!(
        w.server.rows(),
        rows_before,
        "a refused rotation changed the rows"
    );

    // A stored row named in neither list.
    let incomplete = Rotation {
        epoch: epoch_before + 1,
        cursor: heads,
        rewrapped: Vec::new(),
        dropped: Vec::new(),
        revoke: None,
    };
    assert_eq!(w.server.rotate(&incomplete), Err(RotationRefusal::Wraps));
    assert_eq!(
        w.server.epoch(),
        epoch_before,
        "a refused rotation moved the epoch"
    );
    assert_eq!(
        w.server.rows(),
        rows_before,
        "a refused rotation changed the rows"
    );
}

/// ADR 0021 §9 "Already stored" is checked before the kind-4 expiry refusal (CRYPTO.md §10.2
/// "Web-vault certificates"): a web vault retrying a byte-identical snapshot the server already
/// holds, after its certificate has expired, is acknowledged like any other "already stored"
/// upload, the client's own retry-as-acknowledgement path; a *new* snapshot from the same
/// expired author is refused ([`SnapshotRefusal::AuthorExpired`](crate::compaction::SnapshotRefusal::AuthorExpired)),
/// as the module doc's "its new snapshots refused" already distinguishes from a plain retry.
#[test]
fn a_kind4_author_retrying_an_already_stored_snapshot_is_acknowledged() {
    let mut w = World::new(3, 3, 1, 104, Faults::default());
    w.set_kind4(0, super::T0 + 10_000);
    w.step(Step::Write { d: 0, i: 0, k: 0 });
    sync(&mut w, 0);
    w.step(Step::Snapshot { d: 0, i: 0 });
    w.step(Step::Upload { d: 0, lose: false });
    let item = w.items[0];
    let stored = w
        .server
        .snapshot_records()
        .find(|s| s.header.item_id == item)
        .cloned()
        .expect("the honest snapshot was stored");
    w.pass_time(20_000);
    assert!(w.is_expired(0));

    // A byte-identical retry: "already stored" wins over the expiry refusal.
    assert_eq!(
        w.server.upload_snapshot(&stored),
        SnapAnswer::AlreadyStored,
        "a retried already-stored snapshot from an expired author must still be acknowledged"
    );

    // A fresh snapshot (same state, a new id) from the now-expired author: refused.
    let mut header = stored.header.clone();
    header.snapshot_id = rizzy_core::ids::SnapshotId::from_bytes([0x77; 16]);
    let data = w.devices[0].items[&item]
        .snapshot_data()
        .unwrap()
        .expect("the item has a snapshot");
    let data = crate::record::encode_snapshot(&header.covered, &data).unwrap();
    let mut nonces = crypto::Nonces::new(62, w.devices[0].id);
    let key = crypto::initial_key(item);
    let envelope = crypto::seal_snapshot(&mut nonces, &header, &key, data.expose_secret()).unwrap();
    let fresh = SnapRecord {
        signed: crypto::sign_snapshot(&header, &envelope).unwrap(),
        header,
        data: envelope,
        wrap: None,
        tainted: false,
    };
    assert_eq!(
        w.server.upload_snapshot(&fresh),
        SnapAnswer::Refused(crate::compaction::SnapshotRefusal::AuthorExpired)
    );
}
