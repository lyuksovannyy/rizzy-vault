//! Faulty-client snapshots (answer 4: ADR 0018 "Settled by the merge spike" item 4; ADR 0021
//! "Faulty-client snapshots"): unit checks of the evidence merge and two-author covers, and the
//! impossibility result.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use merge_model::config::{Config, FaultFilter, ServerRule};
use merge_model::explore::build_world;
use merge_model::item::{Item, Live, PurgeRec, Regs, Tomb, em_join};
use merge_model::random::{Flavor, random_scenario, random_schedule};
use merge_model::replica::{Notice, Replica, Snapshot};
use merge_model::rng::XorShift;
use merge_model::server::Server;
use merge_model::types::{
    ACTIVE, Body, Dot, Entry, Header, Headers, KeyId, LIFECYCLE, Marker, Op, VV,
};

const K0: KeyId = KeyId(0x0000_0001);

fn vv(e: &[(u8, u64)]) -> VV {
    VV(e.iter().copied().collect::<BTreeMap<_, _>>())
}

fn op(dev: u8, seq: u64, hlc: u64, ctx: &[(u8, u64)], m: Marker, w: &[(&'static str, u32)]) -> Op {
    Op {
        h: Header {
            dot: Dot::new(dev, seq),
            prev: seq - 1,
            hlc,
            ctx: vv(ctx),
            epoch: 0,
        },
        b: Body {
            key_id: K0,
            wrap: Some(K0),
            marker: m,
            writes: w.to_vec(),
        },
    }
}

fn e(dev: u8, seq: u64, hlc: u64, val: u32) -> Entry {
    Entry {
        dot: Dot::new(dev, seq),
        hlc,
        val,
    }
}

fn regs(v: &[(&'static str, Vec<Entry>)]) -> Regs {
    v.iter().cloned().collect()
}

fn snap(author: u8, n: u32, state: Item, honest: bool) -> Snapshot {
    Snapshot {
        id: (author, n),
        author,
        epoch: 0,
        key_id: K0,
        wrap: None,
        state,
        honest,
        fault: None,
        tainted: false,
    }
}

/// Answer 4's client rules (the evidence merge) inside the `integrated` configuration.
fn evidence() -> Config {
    Config::preset("integrated", 2).expect("preset")
}

/// The op truth of a set of ops, by the op merge alone.
fn truth(ops: &[&Op]) -> Item {
    let c = evidence();
    let mut r = Replica::new(9, 0);
    r.keys.insert(K0);
    for o in ops {
        r.deliver((*o).clone(), &c);
    }
    assert!(r.pending.is_empty());
    r.item
}

/// A fresh replica that verified the two headers and absorbs the two covers in the given order.
fn fresh_absorbs(hdr: &Headers, covers: &[&Snapshot]) -> Replica {
    let c = evidence();
    let mut r = Replica::new(3, 0);
    r.keys.insert(K0);
    r.headers = hdr.clone();
    for s in covers {
        r.absorb(s, &c);
    }
    r
}

fn headers_of(ops: &[&Op]) -> Headers {
    ops.iter().map(|o| (o.dot(), o.h.clone())).collect()
}

/// Impossibility (lifecycle): world A has op 0.2 = a write, a faulty author presents it as a Purge
/// (FakeTombSmart); world B has op 0.2 = a Purge, a faulty author presents it as a write
/// (FakeLive). Once 0.2's body is compacted, a fresh replica receives the same two verified covers
/// and the same signed headers in both worlds (the body hash in 0.2's header reveals nothing without
/// the body), but the op truths differ. Any deterministic absorption is wrong in one world.
#[test]
fn lifecycle_lie_about_a_compacted_op_is_undecidable() {
    let create = op(0, 1, 10, &[], Marker::Active, &[("a", 1)]);
    let write = op(0, 2, 20, &[(0, 1)], Marker::Active, &[("a", 2)]);
    let purge = op(0, 2, 20, &[(0, 1)], Marker::Purge, &[]);
    let live_x = Item::Live(Live {
        vv: vv(&[(0, 2)]),
        regs: regs(&[
            (LIFECYCLE, vec![e(0, 2, 20, ACTIVE)]),
            ("a", vec![e(0, 2, 20, 2)]),
        ]),
        hist: regs(&[
            (LIFECYCLE, vec![e(0, 1, 10, ACTIVE)]),
            ("a", vec![e(0, 1, 10, 1)]),
        ]),
    });
    let tomb_y = Item::Tomb(Tomb {
        vv: vv(&[(0, 2)]),
        purge: PurgeRec {
            dot: Dot::new(0, 2),
            hlc: 20,
            key_id: K0,
        },
        c: vv(&[(0, 1)]),
        late: Regs::new(),
    });
    // Both covers pass every ADR 0018 §5 rule.
    assert!(live_x.validate_snapshot().is_ok());
    assert!(tomb_y.validate_snapshot().is_ok());
    // World A: the truth is LIVE_X (TOMB_Y is the lie); world B: the truth is TOMB_Y.
    assert_eq!(truth(&[&create, &write]).canon(), live_x.canon());
    assert_eq!(truth(&[&create, &purge]).canon(), tomb_y.canon());
    // The signed headers the fresh replica verifies are the same in both worlds.
    assert_eq!(
        headers_of(&[&create, &write]),
        headers_of(&[&create, &purge])
    );
    let hdr = headers_of(&[&create, &write]);
    let (sx, sy) = (
        snap(0, 1, live_x.clone(), true),
        snap(1, 1, tomb_y.clone(), false),
    );
    let a = fresh_absorbs(&hdr, &[&sx, &sy]);
    let b = fresh_absorbs(&hdr, &[&sy, &sx]);
    // Deterministic (P3-faulty) and reported (a dispute on 0.2): the replica's output is the same
    // in both worlds, whose truths differ, so it cannot equal both.
    assert_eq!(a.item.canon(), b.item.canon());
    assert!(
        a.notices
            .iter()
            .any(|n| matches!(n, Notice::Dispute { .. }))
    );
    assert!(
        b.notices
            .iter()
            .any(|n| matches!(n, Notice::Dispute { .. }))
    );
    assert_ne!(live_x.canon(), tomb_y.canon());
    // The candidate resolves the dispute without loss: "a purge never resurrects" (ADR 0018 §3),
    // and the disputed write's value stays as a late value (surfaced as "restore it?").
    let Item::Tomb(t) = &a.item else {
        panic!("expected a tombstone: {}", a.item.canon())
    };
    assert_eq!(t.purge.dot, Dot::new(0, 2));
    assert!(
        t.late
            .get("a")
            .is_some_and(|es| es.iter().any(|e| e.dot == Dot::new(0, 2)))
    );
}

/// Impossibility (values): world A has op 0.2 writing {a}, a faulty author adds z at 0.2
/// (AltKey); world B has op 0.2 writing {a, z}, a faulty author omits z (OmitValue). Same inputs,
/// different truths. The candidate (absence is not evidence) is right in world B.
#[test]
fn value_lie_about_a_compacted_op_is_undecidable() {
    let create = op(0, 1, 10, &[], Marker::Active, &[("a", 1)]);
    let w_a = op(0, 2, 20, &[(0, 1)], Marker::Active, &[("a", 2)]);
    let w_az = op(0, 2, 20, &[(0, 1)], Marker::Active, &[("a", 2), ("z", 5)]);
    let without_z = truth(&[&create, &w_a]);
    let with_z = truth(&[&create, &w_az]);
    assert_ne!(without_z.canon(), with_z.canon());
    assert!(without_z.validate_snapshot().is_ok() && with_z.validate_snapshot().is_ok());
    assert_eq!(headers_of(&[&create, &w_a]), headers_of(&[&create, &w_az]));
    let hdr = headers_of(&[&create, &w_a]);
    let (s1, s2) = (
        snap(0, 1, without_z.clone(), true),
        snap(1, 1, with_z.clone(), false),
    );
    let a = fresh_absorbs(&hdr, &[&s1, &s2]);
    let b = fresh_absorbs(&hdr, &[&s2, &s1]);
    assert_eq!(a.item.canon(), b.item.canon());
    assert!(
        a.notices
            .iter()
            .any(|n| matches!(n, Notice::Dispute { .. }))
    );
    assert_eq!(a.item.canon(), with_z.canon());
}

/// Claims: a snapshot that claims the next dot of device 0 never raises the replica's VV above the
/// verified op headers, so the genuine op at that dot is merged when it arrives (ADR 0012 §4 step 3
/// would otherwise skip it as a duplicate).
#[test]
fn a_claimed_dot_never_swallows_the_genuine_op() {
    let c = evidence();
    let create = op(0, 1, 10, &[], Marker::Active, &[("a", 1)]);
    let next = op(0, 2, 20, &[(0, 1)], Marker::Active, &[("a", 2)]);
    let mut claimed = truth(&[&create]);
    *claimed.vv_mut() = vv(&[(0, 2)]);
    assert!(claimed.validate_snapshot().is_ok());
    let mut r = Replica::new(3, 0);
    r.keys.insert(K0);
    r.deliver(create.clone(), &c);
    assert!(r.absorb(&snap(1, 1, claimed, false), &c));
    assert_eq!(r.item.vv(), &vv(&[(0, 1)]));
    r.deliver(next.clone(), &c);
    assert_eq!(r.item.canon(), truth(&[&create, &next]).canon());
}

/// Omission: absorbing a snapshot that omits a value the replica holds never removes it (the
/// absence of a value is not evidence that it was superseded).
#[test]
fn an_omitting_snapshot_never_removes_a_held_value() {
    let c = evidence();
    let create = op(0, 1, 10, &[], Marker::Active, &[("a", 1), ("b", 2)]);
    let full = truth(&[&create]);
    let Item::Live(mut l) = full.clone() else {
        panic!()
    };
    l.regs.remove("a");
    let omitting = Item::Live(l);
    assert!(omitting.validate_snapshot().is_ok());
    let mut r = Replica::new(3, 0);
    r.keys.insert(K0);
    r.deliver(create, &c);
    assert!(r.absorb(&snap(1, 1, omitting, false), &c));
    assert_eq!(r.item.canon(), full.canon());
}

/// Body-confirmed contradiction: a tombstone whose recorded purge is a dot whose body this replica
/// merged as a write is refused and reported.
#[test]
fn a_tombstone_that_records_a_known_write_is_refused() {
    let c = evidence();
    let create = op(0, 1, 10, &[], Marker::Active, &[("a", 1)]);
    let fake = Item::Tomb(Tomb {
        vv: vv(&[(0, 1)]),
        purge: PurgeRec {
            dot: Dot::new(0, 1),
            hlc: 10,
            key_id: K0,
        },
        c: VV::default(),
        late: Regs::new(),
    });
    let mut r = Replica::new(3, 0);
    r.keys.insert(K0);
    r.deliver(create.clone(), &c);
    let before = r.item.canon();
    assert!(!r.absorb(&snap(1, 1, fake, false), &c));
    assert_eq!(r.item.canon(), before);
    assert!(
        r.notices
            .iter()
            .any(|n| matches!(n, Notice::SnapRejected { .. }))
    );
}

/// No laundering: a replica holding an unresolved dispute writes no snapshot of the item.
#[test]
fn a_disputed_replica_writes_no_snapshot() {
    let c = evidence();
    let mut r = Replica::new(3, 0);
    r.keys.insert(K0);
    r.deliver(op(0, 1, 10, &[], Marker::Active, &[("a", 1)]), &c);
    assert!(r.write_snapshot(None, &c).is_some());
    r.notices.push(Notice::Dispute {
        dot: Dot::new(0, 1),
        author: 1,
    });
    assert!(r.write_snapshot(None, &c).is_none());
}

/// The evidence join is commutative and associative, and idempotent on its results, on every state
/// the random faulty flavor produces (honest, faulty and tainted snapshots, and device states).
#[test]
fn evidence_join_is_a_semilattice_on_faulty_states() {
    let cfg = evidence();
    let mut checked = 0u64;
    for seed in 1..=60u64 {
        let mut rng = XorShift::new(seed);
        let scn = random_scenario(&mut rng, Flavor::FaultsOnly, seed, FaultFilter::All);
        let sched = random_schedule(&mut rng, &scn);
        let mut w = build_world(&scn, &cfg);
        w.rng = Some(XorShift::new(seed ^ 0xD15C_0DE5));
        for (a, act) in &sched {
            w.exec(*a, act);
        }
        w.drain();
        let mut hdr = Headers::new();
        let mut keys = BTreeSet::new();
        for d in &w.devs {
            hdr.extend(d.headers.clone());
            keys.extend(d.keys.iter().copied());
        }
        let mut states: Vec<Item> = w.snaps.iter().map(|s| s.state.clone()).collect();
        states.extend(w.devs.iter().map(|d| d.item.clone()));
        let j = |a: &Item, b: &Item| em_join(a, b, &hdr, &keys, cfg.n_hist).0;
        for i in 0..states.len() {
            for k in 0..states.len() {
                let (a, b) = (&states[i], &states[k]);
                assert_eq!(j(a, b).canon(), j(b, a).canon(), "seed {seed}");
                let ab = j(a, b);
                assert_eq!(j(&ab, &ab).canon(), ab.canon(), "seed {seed}");
                for c in &states {
                    assert_eq!(j(&ab, c).canon(), j(a, &j(b, c)).canon(), "seed {seed}");
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 1000);
}

/// Two-author covers: the server deletes no body behind snapshots of one author, deletes once a
/// second author covers it, and Fetch then serves covers of both authors.
#[test]
fn two_author_rule_deletes_only_behind_two_authors() {
    let mut s = Server {
        rule: ServerRule::TwoAuthors,
        ..Server::default()
    };
    let create = op(0, 1, 10, &[], Marker::Active, &[("a", 1)]);
    let w2 = op(0, 2, 20, &[(0, 1)], Marker::Active, &[("a", 2)]);
    assert_eq!(s.upload_op(&create, 0), merge_model::server::UpRes::Stored);
    assert_eq!(s.upload_op(&w2, 0), merge_model::server::UpRes::Stored);
    let st = truth(&[&create, &w2]);
    s.upload_snap(&snap(0, 1, st.clone(), true), 0);
    s.upload_snap(&snap(0, 2, st.clone(), true), 0);
    s.compact();
    assert!(
        s.ops.values().all(|o| o.b.is_some()),
        "one author: nothing deleted"
    );
    s.upload_snap(&snap(1, 1, st.clone(), true), 1);
    s.compact();
    assert!(
        s.ops.values().any(|o| o.b.is_none()),
        "two authors: bodies deleted"
    );
    let resp = s.fetch(&VV::default(), 2);
    let authors: BTreeSet<u8> = resp.covers.iter().map(|c| c.author).collect();
    assert_eq!(authors.len(), 2);
    assert!(s.violations.is_empty(), "{:?}", s.violations);
}
