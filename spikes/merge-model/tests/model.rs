//! Unit checks of the modelled rules against the worked examples in the ADRs, and of the rules
//! the five answers chose (the `integrated` configuration).
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use merge_model::absorb::join_items;
use merge_model::config::Config;
use merge_model::item::{Item, Shown};
use merge_model::replica::Replica;
use merge_model::types::{Body, Dot, Header, KeyId, Marker, Op, VV};

fn vv(e: &[(u8, u64)]) -> VV {
    VV(e.iter().copied().collect::<BTreeMap<_, _>>())
}

fn op(
    dev: u8,
    seq: u64,
    hlc: u64,
    ctx: &[(u8, u64)],
    key: KeyId,
    marker: Marker,
    writes: &[(&'static str, u32)],
) -> Op {
    Op {
        h: Header {
            dot: Dot::new(dev, seq),
            prev: seq - 1,
            hlc,
            ctx: vv(ctx),
            epoch: key.created_epoch(),
        },
        b: Body {
            key_id: key,
            wrap: Some(key),
            marker,
            writes: writes.to_vec(),
        },
    }
}

fn cfg() -> Config {
    Config::preset("literal", 2).expect("preset")
}

fn apply_all(ops: &[&Op]) -> Replica {
    let c = cfg();
    let mut r = Replica::new(9, 0);
    for o in ops {
        r.keys.insert(o.b.key_id);
        r.deliver((*o).clone(), &c);
    }
    assert!(r.pending.is_empty(), "stuck: {:?}", r.pending);
    r
}

const K0: KeyId = KeyId(0x0000_0001);
const K1: KeyId = KeyId(0x0001_0101);

/// ADR 0018 §3 "Why the arrival order does not matter": L writes E1, then E2 over it, both
/// concurrent with purge P. In the orders E1 E2 P, P E1 E2 and E1 P E2 the late register is {E2}.
#[test]
fn adr0018_e1_e2_purge_example() {
    let create = op(0, 1, 10, &[], K0, Marker::Active, &[("a", 1)]);
    let trash = op(0, 2, 20, &[(0, 1)], K0, Marker::Trashed, &[]);
    let p = op(0, 3, 30, &[(0, 2)], K0, Marker::Purge, &[]);
    let e1 = op(1, 1, 25, &[(0, 2)], K0, Marker::Active, &[("a", 21)]);
    let e2 = op(
        1,
        2,
        26,
        &[(0, 2), (1, 1)],
        K0,
        Marker::Active,
        &[("a", 22)],
    );
    let orders: Vec<Vec<&Op>> = vec![
        vec![&create, &trash, &e1, &e2, &p],
        vec![&create, &trash, &p, &e1, &e2],
        vec![&create, &trash, &e1, &p, &e2],
    ];
    let mut canons = Vec::new();
    for o in orders {
        let r = apply_all(&o);
        match &r.item {
            Item::Tomb(t) => {
                let late: Vec<u32> = t
                    .late
                    .get("a")
                    .map(|v| v.iter().map(|e| e.val).collect())
                    .unwrap_or_default();
                assert_eq!(late, vec![22]);
            }
            other => panic!("expected tombstone, got {}", other.canon()),
        }
        canons.push(r.item.canon());
    }
    assert!(canons.windows(2).all(|w| w[0] == w[1]), "{canons:?}");
}

/// ADR 0018 §12 vector: two concurrent purges under different item keys, the lower-HLC one under
/// the newer key, so that item_key_id is the older key. Also c is the join of both contexts.
#[test]
fn adr0018_concurrent_purges_record_highest() {
    let create = op(0, 1, 10, &[], K0, Marker::Active, &[("a", 1)]);
    let trash = op(0, 2, 20, &[(0, 1)], K0, Marker::Trashed, &[]);
    let e = op(2, 1, 22, &[(0, 2)], K0, Marker::Active, &[("b", 5)]);
    let t2 = op(2, 2, 23, &[(0, 2), (2, 1)], K0, Marker::Trashed, &[]);
    // Lower HLC, newer key.
    let p1 = op(1, 1, 40, &[(0, 2)], K1, Marker::Purge, &[]);
    // Higher HLC, older key; its context covers the edit.
    let p2 = op(2, 3, 50, &[(0, 2), (2, 2)], K0, Marker::Purge, &[]);
    for order in [
        vec![&create, &trash, &e, &t2, &p1, &p2],
        vec![&create, &trash, &p1, &e, &t2, &p2],
        vec![&create, &trash, &e, &t2, &p2, &p1],
    ] {
        let r = apply_all(&order);
        let Item::Tomb(t) = &r.item else {
            panic!("expected tombstone")
        };
        assert_eq!(t.purge.dot, Dot::new(2, 3));
        assert_eq!(t.purge.key_id, K0);
        assert_eq!(t.c, vv(&[(0, 2), (2, 2)]));
        assert!(t.late.is_empty(), "{}", r.item.canon());
    }
}

/// ADR 0012 §4-§5: concurrent writes are kept; a covering write moves both to history; history is
/// pruned to N by (hlc, device_id, seq) whatever the arrival order.
#[test]
fn mvr_and_pruning_are_order_independent() {
    let create = op(0, 1, 10, &[], K0, Marker::Active, &[("a", 1)]);
    let a = op(1, 1, 30, &[(0, 1)], K0, Marker::Active, &[("a", 11)]);
    let b = op(2, 1, 30, &[(0, 1)], K0, Marker::Active, &[("a", 21)]);
    let c = op(
        0,
        2,
        40,
        &[(0, 1), (1, 1), (2, 1)],
        K0,
        Marker::Active,
        &[("a", 3)],
    );
    let r1 = apply_all(&[&create, &a, &b, &c]);
    let r2 = apply_all(&[&create, &b, &a, &c]);
    assert_eq!(r1.item.canon(), r2.item.canon());
    let Item::Live(l) = &r1.item else { panic!() };
    assert_eq!(l.regs["a"].len(), 1);
    // N = 2: the create's value (lowest rank) is pruned.
    let h: Vec<u32> = l.hist["a"].iter().map(|e| e.val).collect();
    assert_eq!(h, vec![11, 21]);
}

/// ADR 0012 §5: a concurrent trash and edit keep both lifecycle values; Active wins.
#[test]
fn active_wins_over_concurrent_trash() {
    let create = op(0, 1, 10, &[], K0, Marker::Active, &[("a", 1)]);
    let t = op(0, 2, 20, &[(0, 1)], K0, Marker::Trashed, &[]);
    let e = op(1, 1, 15, &[(0, 1)], K0, Marker::Active, &[("a", 2)]);
    let r = apply_all(&[&create, &t, &e]);
    assert_eq!(r.item.shown(), Shown::Active);
    let Item::Live(l) = &r.item else { panic!() };
    assert_eq!(l.regs["@lifecycle"].len(), 2);
}

/// The DVV join of two honest states equals applying the union of their ops.
#[test]
fn join_of_honest_states_equals_op_union() {
    let create = op(0, 1, 10, &[], K0, Marker::Active, &[("a", 1)]);
    let trash = op(0, 2, 20, &[(0, 1)], K0, Marker::Trashed, &[]);
    let e1 = op(1, 1, 25, &[(0, 1)], K0, Marker::Active, &[("a", 11)]);
    let p = op(0, 3, 30, &[(0, 2)], K0, Marker::Purge, &[]);
    let e2 = op(2, 1, 26, &[(0, 1)], K0, Marker::Active, &[("b", 21)]);
    let x = apply_all(&[&create, &trash, &p]);
    let y = apply_all(&[&create, &e1, &e2]);
    let all = apply_all(&[&create, &trash, &p, &e1, &e2]);
    assert_eq!(join_items(&x.item, &y.item, 2).canon(), all.item.canon());
    assert_eq!(join_items(&y.item, &x.item, 2).canon(), all.item.canon());
}

fn snap(id: (u8, u32), state: Item) -> merge_model::replica::Snapshot {
    merge_model::replica::Snapshot {
        id,
        author: id.0,
        epoch: 0,
        key_id: K0,
        wrap: None,
        state,
        honest: true,
        fault: None,
        tainted: false,
    }
}

/// A replica (device 1) that applied the create, wrote 1.1 and then its own snapshot, which
/// pruned its retained ops (ADR 0012 §6, AMBIGUOUS 3). Returns it with a snapshot S0.2 of
/// {0.1, 0.2}, whose covered VV {0:2} is concurrent with the replica's {0:1,1:1}.
fn concurrent_snapshot_setup(cfg: &Config) -> (Replica, merge_model::replica::Snapshot) {
    let create = op(0, 1, 10, &[], K0, Marker::Active, &[("a", 1)]);
    let own = op(1, 1, 20, &[(0, 1)], K0, Marker::Active, &[("b", 21)]);
    let other = op(0, 2, 30, &[(0, 1)], K0, Marker::Active, &[("a", 11)]);
    let mut r = Replica::new(1, 0);
    r.keys.insert(K0);
    r.deliver(create.clone(), cfg);
    r.deliver(own, cfg);
    r.write_snapshot(None, cfg);
    assert!(r.retained.is_empty());
    let s = apply_all(&[&create, &other]);
    (r, snap((0, 2), s.item))
}

/// ADR 0012 §7 "Freshness" / INV-25: an absorption whose result would lower the item VV is
/// rejected and reported, never applied, and the snapshot is not "held" for the chain check.
#[test]
fn inv25_rejects_an_absorption_that_goes_backwards() {
    let lit = cfg();
    let (mut r, s) = concurrent_snapshot_setup(&lit);
    let before = r.item.canon();
    assert!(!r.absorb(&s, &lit));
    assert_eq!(r.item.canon(), before);
    assert!(!r.held_snaps.contains(s.state.vv()));
    assert_eq!(r.absorb_rejected_inv25, 1);

    let join = Config::preset("join", 2).expect("preset");
    let (mut r, s) = concurrent_snapshot_setup(&join);
    assert!(r.absorb(&s, &join));
    assert_eq!(r.item.vv(), &vv(&[(0, 2), (1, 1)]));
}

/// ADR 0012 §7 chain check / INV-27: a bodiless header whose only cover the replica rejected is
/// reported as missing data, and the cursor does not move past it.
#[test]
fn chain_check_counts_only_accepted_covers() {
    use merge_model::server::Response;
    for (name, expect_gap) in [("literal", true), ("join", false)] {
        let c = Config::preset(name, 2).expect("preset");
        let (mut r, s) = concurrent_snapshot_setup(&c);
        r.cursor = vv(&[(0, 1)]);
        let h = op(0, 2, 30, &[(0, 1)], K0, Marker::Active, &[("a", 11)]).h;
        let resp = Response {
            chains: [(0u8, vec![(h, None)])].into_iter().collect(),
            covers: vec![s],
            wraps: [K0].into_iter().collect(),
            restore_gen: 0,
        };
        r.process_response(&resp, &c, None);
        let gap = r
            .notices
            .iter()
            .any(|n| matches!(n, merge_model::replica::Notice::Gap { dev: 0, seq: 2 }));
        assert_eq!(gap, expect_gap, "{name}");
        assert_eq!(r.cursor.get(0), if expect_gap { 1 } else { 2 }, "{name}");
    }
}

/// ADR 0018 §3 "A Purge is never rejected" (applied although a concurrent restore makes the item
/// display Active) and "Applying" 3 (a late Trash only advances the covered VV; an op whose
/// context covers purge_dot removes the late values it covers and adds its own), in several
/// arrival orders.
#[test]
fn adr0018_purge_over_active_and_ops_after_the_purge() {
    let create = op(0, 1, 10, &[], K0, Marker::Active, &[("a", 1)]);
    let trash = op(0, 2, 20, &[(0, 1)], K0, Marker::Trashed, &[]);
    let restore = op(1, 1, 25, &[(0, 2)], K0, Marker::Active, &[]);
    let edit = op(2, 1, 26, &[(0, 2)], K0, Marker::Active, &[("a", 21)]);
    let purge = op(0, 3, 30, &[(0, 2)], K0, Marker::Purge, &[]);
    let late_trash = op(1, 2, 40, &[(0, 2), (1, 1)], K0, Marker::Trashed, &[]);
    let over = op(
        1,
        3,
        50,
        &[(0, 3), (1, 2), (2, 1)],
        K0,
        Marker::Active,
        &[("a", 13)],
    );
    let before_over = apply_all(&[&create, &trash, &restore, &edit, &purge, &late_trash]);
    let Item::Tomb(t) = &before_over.item else {
        panic!("a Purge applied over a displayed-Active item still makes a tombstone")
    };
    assert_eq!(t.c, vv(&[(0, 2)]));
    let late: Vec<u32> = t.late["a"].iter().map(|e| e.val).collect();
    assert_eq!(late, vec![21]);
    assert_eq!(t.vv, vv(&[(0, 3), (1, 2), (2, 1)]));
    let mut canons = Vec::new();
    for order in [
        vec![&create, &trash, &restore, &edit, &purge, &late_trash, &over],
        vec![&create, &trash, &purge, &edit, &restore, &late_trash, &over],
        vec![&create, &trash, &edit, &late_trash, &restore, &purge, &over],
    ] {
        let r = apply_all(&order);
        let Item::Tomb(t) = &r.item else {
            panic!("expected tombstone")
        };
        let late: Vec<u32> = t.late["a"].iter().map(|e| e.val).collect();
        assert_eq!(late, vec![13]);
        canons.push(r.item.canon());
    }
    assert!(canons.windows(2).all(|w| w[0] == w[1]), "{canons:?}");
}

/// A preset with knobs flipped (`Config::set`).
fn with(preset: &str, sets: &[(&str, &str)]) -> Config {
    let mut c = Config::preset(preset, 2).expect("preset");
    for (k, v) in sets {
        assert!(c.set(k, v), "{k}={v}");
    }
    c
}

fn integrated() -> Config {
    Config::preset("integrated", 2).expect("preset")
}

// ---------------------------------------------------------------------------------------------
// Answer 1: absorption (merged snapshot, HLC receipt).
// ---------------------------------------------------------------------------------------------

/// The ADR 0012 §6 recomputation after a concurrent absorption, and the merged snapshot that
/// restores it. Device 1 wrote 1.1 and its own snapshot (so 1.1 is no longer retained), then
/// absorbs device 0's snapshot of {0.1, 0.2} as the cover of the bodiless header 0.2.
#[test]
fn merged_snapshot_keeps_the_item_recomputable() {
    use merge_model::server::Response;
    for (cfg, merged) in [
        (with("join", &[]), false),
        (
            with("join", &[("merged", "yes"), ("hlc-absorb", "yes")]),
            true,
        ),
        (integrated(), true),
    ] {
        let create = op(0, 1, 10, &[], K0, Marker::Active, &[("a", 1)]);
        let own = op(1, 1, 20, &[(0, 1)], K0, Marker::Active, &[("b", 21)]);
        let other = op(0, 2, 30, &[(0, 1)], K0, Marker::Active, &[("a", 11)]);
        let mut r = Replica::new(1, 0);
        r.keys.insert(K0);
        r.deliver(create.clone(), &cfg);
        r.deliver(own, &cfg);
        r.write_snapshot(None, &cfg);
        r.outbox.clear();
        r.cursor.add(Dot::new(0, 1));
        let mut src = Replica::new(0, 0);
        src.keys.insert(K0);
        src.deliver(create, &cfg);
        src.deliver(other.clone(), &cfg);
        let s = src.write_snapshot(None, &cfg).expect("snapshot");
        let resp = Response {
            chains: [(0u8, vec![(other.h.clone(), None)])].into_iter().collect(),
            covers: vec![s],
            wraps: [K0].into_iter().collect(),
            restore_gen: 0,
        };
        let written = r.process_response(&resp, &cfg, None);
        assert_eq!(r.item.vv(), &vv(&[(0, 2), (1, 1)]));
        let rebuilt = r.recompute(&cfg).canon() == r.item.canon();
        assert_eq!(rebuilt, merged, "{}", cfg.name);
        assert_eq!(written.is_some(), merged, "{}", cfg.name);
        if let Some(m) = written {
            assert_eq!(m.state.canon(), r.item.canon());
        }
    }
}

/// Known limit of the HLC receipt: a tombstone does not carry the HLC of a late Trash or Restore
/// (ADR 0018 §3 "Applying" 3: its lifecycle byte writes nothing), so a device that learns the item
/// only from the tombstone can write an op on it whose HLC is below that late op's. Such an op
/// writes only late values, and the late Restore wrote nothing, so no order depends on the pair.
#[test]
fn tombstone_does_not_carry_the_hlc_of_late_lifecycle_ops() {
    let cfg = with("join", &[("merged", "yes"), ("hlc-absorb", "yes")]);
    let create = op(0, 1, 10 << 16, &[], K0, Marker::Active, &[("a", 1)]);
    let trash = op(0, 2, 20 << 16, &[(0, 1)], K0, Marker::Trashed, &[]);
    let purge = op(0, 3, 30 << 16, &[(0, 2)], K0, Marker::Purge, &[]);
    let restore = op(1, 1, 90 << 16, &[(0, 2)], K0, Marker::Active, &[]);
    let mut holder = Replica::new(2, 0);
    holder.keys.insert(K0);
    for o in [&create, &trash, &purge, &restore] {
        holder.deliver(o.clone(), &cfg);
    }
    let t = holder
        .write_snapshot(None, &cfg)
        .expect("tombstone snapshot");
    assert!(matches!(t.state, Item::Tomb(_)));
    let mut fresh = Replica::new(3, 0);
    fresh.keys.insert(K0);
    assert!(fresh.absorb(&t, &cfg));
    let (late_edit, _) = fresh
        .author(&merge_model::replica::Edit::Write(vec![("a", 7)]), &cfg)
        .expect("an editor open over the purge");
    assert!(late_edit.h.ctx.covers(restore.dot()));
    assert!(late_edit.h.hlc > purge.h.hlc);
    assert!(late_edit.h.hlc < restore.h.hlc);
}

// ---------------------------------------------------------------------------------------------
// Answer 2: restore healing (healing request, unheld claims).
// ---------------------------------------------------------------------------------------------

/// A healing request is atomic; a header stored without its body needs a cover in the same
/// request (ADR 0021 owner rule 3, server property 1); a bodiless header carries no ciphertext, so
/// the stale-epoch check does not apply to it.
#[test]
fn heal_request_is_atomic_and_needs_a_cover() {
    use merge_model::server::{HealRec, Server};
    let create = op(0, 1, 10, &[], K0, Marker::Active, &[("a", 1)]);
    let edit = op(0, 2, 20, &[(0, 1)], K0, Marker::Active, &[("a", 2)]);
    let mut srv = Server::default();
    srv.upload_op(&create, 0);
    srv.epoch = 1;
    let before = srv.ops.len();
    // Bodiless, no cover: refused as a whole.
    assert!(
        srv.heal_request(&[HealRec::Op(edit.h.clone(), None)], 1, true)
            .is_err()
    );
    assert_eq!(srv.ops.len(), before);
    // With a snapshot that covers it: stored, although its epoch (0) is below the current one.
    let s = apply_all(&[&create, &edit]);
    let mut sn = snap((1, 1), s.item);
    sn.epoch = 1;
    sn.key_id = K1;
    sn.wrap = Some(K1);
    assert!(
        srv.heal_request(
            &[HealRec::Op(edit.h.clone(), None), HealRec::Snap(sn)],
            1,
            false
        )
        .is_ok()
    );
    assert!(srv.ops[&Dot::new(0, 2)].b.is_none());
    srv.check_props(true);
    assert!(srv.violations.is_empty(), "{:?}", srv.violations);
}

/// A snapshot whose covered VV claims dots above the server's heads is refused under answer 2;
/// ADR 0021 §5 (literal) stores it with a clamped VV. A revoked device's entry counts only up to
/// its cut-off (the resolution of answers 2 and 5).
#[test]
fn snapshot_claiming_unheld_dots() {
    use merge_model::server::{Server, UpRes};
    let create = op(0, 1, 10, &[], K0, Marker::Active, &[("a", 1)]);
    let edit = op(0, 2, 20, &[(0, 1)], K0, Marker::Active, &[("a", 2)]);
    let s = snap((1, 1), apply_all(&[&create, &edit]).item);
    for (refuse, stored) in [(false, true), (true, false)] {
        let mut srv = Server {
            refuse_unheld_claims: refuse,
            ..Server::default()
        };
        srv.upload_op(&create, 0);
        let res = srv.upload_snap(&s, 1);
        assert_eq!(res == UpRes::Stored, stored, "refuse={refuse}");
    }
    // Device 0 revoked with last_accepted_device_seq = 1: its claim of 0.2 is past the cut-off,
    // never storable, so it no longer counts as unheld; the clamp cuts it.
    let mut srv = Server {
        refuse_unheld_claims: true,
        ..Server::default()
    };
    srv.upload_op(&create, 0);
    srv.revocations.insert(0, 1);
    assert_eq!(srv.upload_snap(&s, 1), UpRes::Stored);
    assert_eq!(srv.snaps[0].clamped.get(0), 1);
}

// ---------------------------------------------------------------------------------------------
// Answer 3: re-issued ops.
// ---------------------------------------------------------------------------------------------

/// A Purge re-issued after a stale-epoch rejection keeps its dot, HLC and context; the author's
/// tombstone then records the re-issued envelope's key id, the unsent snapshots that embed the
/// original are replaced, and the re-issued op carries its fresh key's wrap.
#[test]
fn reissued_purge_author_records_the_new_key() {
    use merge_model::replica::Out;
    let c = integrated();
    let create = op(0, 1, 10, &[], K0, Marker::Active, &[("a", 1)]);
    let trash = op(0, 2, 20, &[(0, 1)], K0, Marker::Trashed, &[]);
    let mut r = Replica::new(1, 0);
    r.keys.insert(K0);
    r.deliver(create, &c);
    r.deliver(trash, &c);
    let (p, snap) = r
        .author(&merge_model::replica::Edit::Purge, &c)
        .expect("purge");
    assert!(snap.is_some(), "a purge triggers a snapshot (ADR 0012 §7)");
    let Item::Tomb(t) = &r.item else { panic!() };
    assert_eq!(t.purge.key_id, K0);
    // The rotation happens elsewhere; the upload is answered "stale epoch".
    r.known_epoch = 1;
    let (pairs, wsnap) = r.reissue_outbox(&c, 0, Some(p.dot()), false);
    assert_eq!(pairs.len(), 1);
    let (orig, n) = &pairs[0];
    assert_eq!(
        (n.h.dot, n.h.hlc, &n.h.ctx),
        (orig.h.dot, orig.h.hlc, &orig.h.ctx)
    );
    assert_eq!((n.b.marker, &n.b.writes), (orig.b.marker, &orig.b.writes));
    assert_ne!(n.b.key_id, K0);
    assert_eq!(n.b.key_id.created_epoch(), 1);
    assert_eq!(n.b.wrap, Some(n.b.key_id));
    let Item::Tomb(t) = &r.item else { panic!() };
    assert_eq!(t.purge.key_id, n.b.key_id);
    // The writer rule's snapshot is written after the patch; the stale one is gone.
    let s = wsnap.expect("writer-rule snapshot");
    let Item::Tomb(st) = &s.state else { panic!() };
    assert_eq!(st.purge.key_id, n.b.key_id);
    let snaps: Vec<_> = r
        .outbox
        .iter()
        .filter_map(|o| {
            if let Out::Snap(s) = o {
                Some(s.epoch)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(snaps, vec![1]);
}

/// Answers 2 and 3 combined (`StaleSent::RepublishGen`): an op whose upload response was lost is
/// re-published (not re-issued) only when the server's restore generation changed since; an
/// acknowledged op always is; otherwise "not stored" is authoritative and the op is re-issued.
#[test]
fn republish_only_what_may_have_been_stored_and_served() {
    let c = integrated();
    let mut r = Replica::new(1, 0);
    r.acked_self = 2;
    r.lost_uploads.insert(3, 0);
    assert!(r.must_republish(2, &c, 0));
    assert!(!r.must_republish(3, &c, 0));
    assert!(r.must_republish(3, &c, 1));
    assert!(!r.must_republish(4, &c, 1));
    let h = with("integrated", &[("stale-sent", "republish")]);
    assert!(r.must_republish(3, &h, 0));
    let l = with("integrated", &[("stale-sent", "reissue")]);
    assert!(!r.must_republish(2, &l, 1));
}

// ---------------------------------------------------------------------------------------------
// Answer 5: revocation.
// ---------------------------------------------------------------------------------------------

/// ADR 0021 open question 5: a revoked author's snapshot is absorbed when its covered entry for
/// its author is at most last_accepted_device_seq, and rejected above it; the literal reading
/// rejects it whatever it covers.
#[test]
fn revoked_authors_snapshot_acceptance() {
    let create = op(0, 1, 10, &[], K0, Marker::Active, &[("a", 1)]);
    let own = op(1, 1, 20, &[(0, 1)], K0, Marker::Active, &[("a", 21)]);
    let state = apply_all(&[&create, &own]).item;
    for (c, cut, accepted) in [
        (with("join", &[("revoked-snap", "covered")]), 1, true),
        (with("join", &[("revoked-snap", "covered")]), 0, false),
        (with("join", &[("revoked-snap", "reject")]), 1, false),
    ] {
        let mut r = Replica::new(2, 0);
        r.keys.insert(K0);
        r.revocations.insert(1, cut);
        assert_eq!(
            r.absorb(&snap((1, 1), state.clone()), &c),
            accepted,
            "{} {cut}",
            c.name
        );
        assert_eq!(r.item.vv().get(1), if accepted { 1 } else { 0 });
    }
}

/// Server rule of answer 5: a snapshot whose covered entry for its own author is above that
/// author's head is refused; one within the head is stored. Other devices' entries may exceed
/// their heads (ADR 0021 §5) when answer 2's refusal of unheld claims is off.
#[test]
fn server_refuses_a_snapshot_claiming_its_authors_unstored_dots() {
    use merge_model::server::{Server, UpRes};
    let create = op(0, 1, 10, &[], K0, Marker::Active, &[("a", 1)]);
    let own = op(1, 1, 20, &[(0, 1)], K0, Marker::Active, &[("a", 21)]);
    let own2 = op(
        1,
        2,
        30,
        &[(0, 1), (1, 1)],
        K0,
        Marker::Active,
        &[("a", 22)],
    );
    let mut s = Server {
        author_head: true,
        ..Server::default()
    };
    assert_eq!(s.upload_op(&create, 0), UpRes::Stored);
    assert_eq!(s.upload_op(&own, 1), UpRes::Stored);
    let ahead = apply_all(&[&create, &own, &own2]).item;
    assert!(matches!(
        s.upload_snap(&snap((1, 1), ahead), 1),
        UpRes::Refused(_)
    ));
    let within = apply_all(&[&create, &own]).item;
    assert_eq!(s.upload_snap(&snap((1, 2), within), 1), UpRes::Stored);
    let other = apply_all(&[&create, &own, &own2]).item;
    assert_eq!(s.upload_snap(&snap((0, 1), other), 0), UpRes::Stored);
    assert_eq!(s.snaps.last().map(|x| x.clamped.get(1)), Some(1));
}

/// Server rule of answer 5: after a revocation, a revoked author's op at or below its cut-off is
/// not refused as stale (only its author could re-issue it); above the cut-off it is refused.
#[test]
fn stale_epoch_exemption_for_a_revoked_authors_ops() {
    use merge_model::server::{Server, UpRes};
    let create = op(0, 1, 10, &[], K0, Marker::Active, &[("a", 1)]);
    let own = op(1, 1, 20, &[(0, 1)], K0, Marker::Active, &[("a", 21)]);
    let own2 = op(
        1,
        2,
        30,
        &[(0, 1), (1, 1)],
        K0,
        Marker::Active,
        &[("a", 22)],
    );
    for (exempt, expect) in [(false, UpRes::Stale), (true, UpRes::Stored)] {
        let mut s = Server {
            stale_exempt_revoked: exempt,
            ..Server::default()
        };
        assert_eq!(s.upload_op(&create, 0), UpRes::Stored);
        s.epoch = 1;
        s.revocations.insert(1, 1);
        // Uploaded by device 0 (a healer): "Any client may upload any signed op".
        assert_eq!(s.upload_op(&own, 0), expect);
        assert!(matches!(s.upload_op(&own2, 0), UpRes::Refused(_)));
    }
}

/// ADR 0012 §6 "removes the op and recomputes the item from its retained ops and snapshots. If it
/// cannot, it flags the item": the recomputation works when the op is a retained op, is impossible
/// once the replica's newest snapshot contains it, and leaves every later op whose causal context
/// covers the removed op undeliverable. Same under the op merge and the evidence merge.
#[test]
fn recompute_after_a_cut_off_below_applied_ops() {
    for c in [with("join", &[("past-cutoff", "recompute")]), integrated()] {
        let create = op(0, 1, 10, &[], K0, Marker::Active, &[("a", 1)]);
        let r1 = op(1, 1, 20, &[(0, 1)], K0, Marker::Active, &[("a", 21)]);
        let later = op(
            2,
            1,
            30,
            &[(0, 1), (1, 1)],
            K0,
            Marker::Active,
            &[("b", 31)],
        );
        let run = |ops: &[&Op]| {
            let mut r = Replica::new(9, 0);
            for o in ops {
                r.keys.insert(o.b.key_id);
                r.deliver((*o).clone(), &c);
            }
            r
        };
        // Retained: removed, and the item is recomputed without it.
        let mut r = run(&[&create, &r1]);
        assert!(r.learn_revocation(1, 0, &c));
        assert_eq!(r.item.canon(), run(&[&create]).item.canon(), "{}", c.name);
        assert_eq!(r.recompute_base_mismatch, 0);
        // Inside the newest snapshot: cannot be removed; the item is flagged.
        let mut r = run(&[&create, &r1]);
        r.write_snapshot(None, &c);
        assert!(!r.learn_revocation(1, 0, &c));
        assert_eq!(r.item.vv().get(1), 1);
        // A later op of a non-revoked device whose context covers the removed op is stranded.
        let mut r = run(&[&create, &r1, &later]);
        assert!(r.learn_revocation(1, 0, &c));
        assert_eq!(
            r.pending.iter().map(|o| o.dot()).collect::<Vec<_>>(),
            vec![Dot::new(2, 1)]
        );
    }
}
