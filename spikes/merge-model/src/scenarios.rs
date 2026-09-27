//! Scenario-family enumerators. Each family generates scenarios from small option menus (one
//! option per device); the explorer then runs every interleaving of each scenario.
//!
//! Conventions: device 0 creates the item with `a=1, b=2`; values written in scenarios are
//! unique (device d writes 10·(d+1)+k style values) so traces are readable. The server actor is
//! index `n_dev`.

use crate::explore::Scenario;
use crate::replica::Fault;
use crate::world::Act::{self, *};

fn w(k: &'static str, v: u32) -> Act {
    Write(vec![(k, v)])
}

/// Device 0 creates and uploads; devices `1..n_share` fetch. Optionally device 0 then trashes the
/// item and everyone fetches again. Devices `n_share..n_dev` start fresh (never synced).
fn shared(n_share: usize, trashed: bool) -> Vec<(usize, Act)> {
    let mut s = vec![(0, Write(vec![("a", 1), ("b", 2)])), (0, Sync)];
    for d in 1..n_share {
        s.push((d, Sync));
    }
    if trashed {
        s.push((0, Trash));
        s.push((0, Sync));
        for d in 1..n_share {
            s.push((d, Sync));
        }
    }
    s
}

fn scn(
    family: &'static str,
    name: String,
    n_dev: usize,
    setup: Vec<(usize, Act)>,
    devs: Vec<Vec<Act>>,
    server: Vec<Act>,
) -> Scenario {
    let mut programs = devs;
    programs.resize(n_dev, Vec::new());
    programs.push(server);
    Scenario {
        family,
        name,
        n_dev,
        skew: vec![0; n_dev],
        setup,
        programs,
        max_values: None,
    }
}

type Menu = Vec<(&'static str, Vec<Act>)>;

/// Every assignment of one menu option per device (in order), filtered.
fn product(menus: &[Menu], keep: impl Fn(&[&str]) -> bool) -> Vec<(String, Vec<Vec<Act>>)> {
    let mut out = Vec::new();
    let mut idx = vec![0usize; menus.len()];
    loop {
        let labels: Vec<&str> = idx
            .iter()
            .enumerate()
            .map(|(d, &i)| menus[d][i].0)
            .collect();
        if keep(&labels) {
            let progs = idx
                .iter()
                .enumerate()
                .map(|(d, &i)| menus[d][i].1.clone())
                .collect();
            let name = labels
                .iter()
                .enumerate()
                .map(|(d, l)| format!("D{d}:{l}"))
                .collect::<Vec<_>>()
                .join(" ");
            out.push((name, progs));
        }
        let mut d = 0;
        loop {
            if d == menus.len() {
                return out;
            }
            idx[d] += 1;
            if idx[d] < menus[d].len() {
                break;
            }
            idx[d] = 0;
            d += 1;
        }
    }
}

fn edit_menu(d: u32) -> Menu {
    let v = 10 * (d + 1);
    vec![
        ("W", vec![w("a", v + 1), Upload, Fetch]),
        (
            "WW",
            vec![w("a", v + 1), Upload, Fetch, w("a", v + 2), Upload, Fetch],
        ),
        (
            "FWb",
            vec![Fetch, w("a", v + 1), w("b", v + 2), Upload, Fetch],
        ),
        ("bW", vec![w("b", v + 1), w("a", v + 2), Sync]),
        (
            "WWW",
            vec![w("a", v + 1), w("a", v + 2), Upload, w("a", v + 3), Sync],
        ),
    ]
}

/// Concurrent edits of one and two fields, with history N small so pruning is exercised.
pub fn concurrent_edits(quick: bool) -> Vec<Scenario> {
    let menus: Vec<Menu> = (0..3).map(edit_menu).collect();
    product(&menus, |l| {
        // Multisets only (devices are distinguished by id anyway), and a quick subset.
        let ok = l[0] <= l[1] && l[1] <= l[2];
        ok && (!quick || (l.contains(&"WW") && l.contains(&"W")) || l == ["WWW", "WWW", "bW"])
    })
    .into_iter()
    .map(|(name, progs)| scn("concurrent-edits", name, 3, shared(3, false), progs, vec![]))
    .chain(std::iter::once({
        // ADR 0012 §2 "Skew guard": D2's wall clock is 25 h ahead; its HLCs are applied but not
        // adopted by the others, and they win display ties and history ranks.
        let mut s = scn(
            "concurrent-edits",
            "skewed D2 clock".into(),
            3,
            shared(3, false),
            vec![
                vec![w("a", 11), Upload, Fetch, w("a", 12), Upload, Fetch],
                vec![w("a", 21), Upload, Fetch],
                vec![Fetch, w("a", 31), Upload, Fetch],
            ],
            vec![],
        );
        s.skew = vec![0, 0, 25 * 3600 * 1000];
        s
    }))
    .collect()
}

fn purge_menu(d: u32) -> Menu {
    let v = 10 * (d + 1);
    vec![
        ("P", vec![Purge, Upload, Fetch]),
        // Disjoint contexts: an own edit (writes Active), trash, then purge.
        ("EP", vec![w("a", v + 1), Trash, Purge, Sync]),
        // Nested contexts: purge after fetching what the others did.
        ("FP", vec![Fetch, Purge, Upload, Fetch]),
        ("E", vec![w("a", v + 1), Upload, Fetch]),
        ("R", vec![Restore, Upload, Fetch]),
    ]
}

/// Concurrent purges with nested and disjoint contexts, with concurrent edits and restores.
pub fn purges(quick: bool) -> Vec<Scenario> {
    let menus: Vec<Menu> = (0..3).map(purge_menu).collect();
    product(&menus, |l| {
        let purgers = l.iter().filter(|x| x.contains('P')).count();
        purgers >= 2
            && (!quick || l == ["P", "FP", "E"] || l == ["EP", "P", "R"] || l == ["FP", "EP", "E"])
    })
    .into_iter()
    .map(|(name, progs)| scn("purges", name, 3, shared(3, true), progs, vec![]))
    .collect()
}

/// Edits before and after a purge (ADR 0018 §3's E1 → E2 example, an editor open over a purge).
pub fn edit_purge(quick: bool) -> Vec<Scenario> {
    let menus: Vec<Menu> = vec![
        vec![("P", vec![Purge, Upload, Fetch])],
        vec![
            (
                "E1E2",
                vec![w("a", 21), Upload, Fetch, w("a", 22), Upload, Fetch],
            ),
            ("E1E2local", vec![w("a", 21), w("a", 22), Upload, Fetch]),
            ("afterP", vec![Fetch, w("a", 21), Sync]),
            ("E1Eb", vec![w("a", 21), Sync, w("b", 23), Sync]),
        ],
        vec![
            ("FEb", vec![Fetch, w("b", 31), Upload, Fetch]),
            ("E", vec![w("a", 31), Upload, Fetch]),
            ("F", vec![Fetch]),
        ],
    ];
    product(&menus, |l| !quick || l[2] != "F")
        .into_iter()
        .map(|(name, progs)| scn("edit-purge", name, 3, shared(3, true), progs, vec![]))
        .collect()
}

/// Trash / restore / edit races (Active wins), and trash → purge against a restore.
pub fn trash_restore(quick: bool) -> Vec<Scenario> {
    let menus: Vec<Menu> = vec![
        vec![
            ("TP", vec![Trash, Upload, Fetch, Purge, Upload, Fetch]),
            ("T", vec![Trash, Sync]),
        ],
        vec![
            ("FR", vec![Fetch, Restore, Upload, Fetch]),
            ("E", vec![w("a", 21), Upload, Fetch]),
            ("TR", vec![Trash, Upload, Fetch, Restore, Sync]),
        ],
        vec![
            ("E", vec![w("a", 31), Upload, Fetch]),
            ("FT", vec![Fetch, Trash, Upload, Fetch]),
            ("F", vec![Fetch]),
        ],
    ];
    product(&menus, |l| !quick || l[0] == "TP")
        .into_iter()
        .map(|(name, progs)| scn("trash-restore", name, 3, shared(3, false), progs, vec![]))
        .collect()
}

/// Snapshot writes and absorption at various points. Compaction (two snapshots, then `worker`)
/// makes the server serve covers; D2 absorbs with local unsent state (concurrent VVs); D3 is a
/// fresh device that learns everything through bodiless headers and covers.
pub fn snapshots(quick: bool) -> Vec<Scenario> {
    let mut out = Vec::new();
    let live: Vec<Menu> = vec![
        vec![
            ("WS", vec![w("a", 11), Snapshot, Upload, Fetch]),
            ("WuS", vec![w("a", 11), Upload, Fetch, Snapshot, Upload]),
        ],
        vec![
            ("WS", vec![w("a", 21), Snapshot, Upload, Fetch]),
            ("FWbS", vec![Fetch, w("b", 21), Snapshot, Upload]),
        ],
        vec![
            ("W-F", vec![w("a", 31), Fetch, Upload]),
            ("WS-F", vec![w("a", 31), Snapshot, Fetch, Upload]),
            ("FS", vec![Fetch, Snapshot, Upload]),
        ],
        vec![("F", vec![Fetch])],
    ];
    for (name, progs) in product(&live, |l| !quick || (l[2] == "WS-F" && l[0] == "WS")) {
        out.push(scn(
            "snapshots",
            format!("live {name}"),
            4,
            shared(3, false),
            progs,
            vec![Worker],
        ));
    }
    let tomb: Vec<Menu> = vec![
        vec![
            ("P", vec![Purge, Upload, Fetch]),
            ("FP", vec![Fetch, Purge, Upload]),
        ],
        vec![
            ("WS", vec![w("a", 21), Snapshot, Upload, Fetch]),
            ("S", vec![Snapshot, Upload, Fetch]),
        ],
        vec![
            ("WS-F", vec![w("a", 31), Snapshot, Fetch, Upload]),
            ("P-F", vec![Purge, Fetch, Upload]),
        ],
        vec![("F", vec![Fetch])],
    ];
    for (name, progs) in product(&tomb, |l| !quick || (l[1] == "WS" && l[0] == "P")) {
        out.push(scn(
            "snapshots",
            format!("tomb {name}"),
            4,
            shared(3, true),
            progs,
            vec![Worker],
        ));
    }
    out
}

/// Absorption with concurrent covered VVs (ADR 0018 "Settled by the merge spike" item 1; ADR 0021
/// first bullet). The item starts trashed, so purges are possible. D0 and D1 each upload a
/// snapshot (live, with history to prune at small N, or a tombstone from a purge with its own
/// context); two `worker` runs delete the bodies the older covers. D2 holds local unsent state
/// (a live edit, its own purge, or an edit and its own snapshot) and absorbs the covers of the
/// bodiless headers it fetches: live<-live, live<-tomb, tomb<-live and tomb<-tomb, concurrent. D3
/// is a fresh device that learns the item only through bodiless headers and covers.
pub fn absorb(quick: bool) -> Vec<Scenario> {
    let menus: Vec<Menu> = vec![
        vec![
            ("WWS", vec![w("a", 11), w("a", 12), Snapshot, Upload]),
            // The purge trigger writes the tombstone snapshot.
            ("P", vec![Purge, Upload]),
        ],
        vec![
            ("WbS", vec![w("b", 21), Snapshot, Upload]),
            // An edit, trash and purge: a tombstone whose c differs from D0's.
            ("WTP", vec![w("a", 21), Trash, Purge, Upload]),
            ("FWS", vec![Fetch, w("a", 22), Snapshot, Upload]),
        ],
        vec![
            ("W-F", vec![w("a", 31), Fetch, Upload]),
            ("P-F", vec![Purge, Fetch, Upload]),
            ("WS-F", vec![w("b", 32), Snapshot, Fetch, Upload]),
        ],
        vec![("F", vec![Fetch])],
    ];
    product(&menus, |l| {
        !quick || (l[1] != "FWS" && (l[0] == "P" || l[2] != "W-F"))
    })
    .into_iter()
    .map(|(name, progs)| {
        scn(
            "absorb",
            name,
            4,
            shared(3, true),
            progs,
            vec![Worker, Worker],
        )
    })
    .collect()
}

/// ADR 0021's named scenarios and a three-snapshot race.
pub fn compaction(quick: bool) -> Vec<Scenario> {
    // The full S_L program has 207,900 block interleavings; quick mode drops one fetch.
    let d1_sl = if quick {
        vec![Fetch, Snapshot, Upload, Snapshot, Upload]
    } else {
        vec![Fetch, Snapshot, Upload, Fetch, Snapshot, Upload]
    };
    vec![
        // "T_A then T_B, and T_B then T_A, with a device that was behind fetching after each upload."
        scn(
            "compaction",
            "concurrent purges T_A/T_B".into(),
            4,
            shared(3, true),
            vec![
                vec![Purge, Upload],
                vec![Purge, Upload],
                vec![Fetch, Fetch],
                vec![Fetch],
            ],
            vec![Worker, Worker],
        ),
        // "S_L with late edits, two tombstone snapshots that miss them, L never returning, then a
        // new device. The new device ends with the edits."
        scn(
            "compaction",
            "late edits S_L, L lost".into(),
            4,
            shared(3, true),
            vec![
                vec![Purge, Upload, Fetch],
                d1_sl,
                vec![w("a", 31), w("a", 32), Snapshot, Upload, Lose],
                vec![Fetch],
            ],
            vec![Worker, Worker],
        ),
        scn(
            "compaction",
            "three concurrent snapshots".into(),
            4,
            shared(3, false),
            vec![
                vec![w("a", 11), Snapshot, Upload],
                vec![w("a", 21), Snapshot, Upload],
                vec![w("b", 31), Snapshot, Upload],
                vec![Fetch],
            ],
            vec![Worker, Worker],
        ),
    ]
}

/// Rotation between purges; stale-epoch re-issue of writes and purges; a lost response.
pub fn rotation(_quick: bool) -> Vec<Scenario> {
    vec![
        scn(
            "rotation",
            "two purges, rotation between".into(),
            3,
            shared(3, true),
            vec![
                vec![Purge, Upload, Fetch],
                vec![Purge, Upload, Fetch],
                vec![Rotate],
            ],
            vec![],
        ),
        scn(
            "rotation",
            "edit re-issued after rotation".into(),
            3,
            shared(3, false),
            vec![
                vec![w("a", 11), Upload, Fetch],
                vec![Rotate],
                vec![Fetch, w("a", 31), Upload, Fetch],
            ],
            vec![],
        ),
        scn(
            "rotation",
            "purge with lost response, rotation".into(),
            3,
            shared(3, true),
            vec![
                vec![Purge, SyncLost, Upload, Fetch],
                vec![Rotate],
                vec![Fetch],
            ],
            vec![],
        ),
        scn(
            "rotation",
            "purge before and after rotation".into(),
            3,
            shared(3, true),
            vec![
                vec![Purge, Upload, Fetch],
                vec![Rotate, Fetch],
                vec![Fetch, Purge, Upload, Fetch],
            ],
            vec![],
        ),
        scn(
            "rotation",
            "two rotations, one purge".into(),
            3,
            shared(3, true),
            vec![vec![Purge, Upload, Fetch], vec![Rotate], vec![Rotate]],
            vec![],
        ),
    ]
}

/// A server restore from a backup taken right after the setup (ADR 0012 §7 healing).
pub fn restore(_quick: bool) -> Vec<Scenario> {
    let cp = |mut s: Vec<(usize, Act)>, n_dev: usize| {
        s.push((n_dev, Checkpoint(0)));
        s
    };
    vec![
        scn(
            "restore",
            "edits after the backup".into(),
            3,
            cp(shared(3, false), 3),
            vec![
                vec![w("a", 11), Sync, w("a", 12), Sync],
                vec![Fetch, w("b", 21), Sync],
                vec![Fetch],
            ],
            vec![RestoreServer(0)],
        ),
        scn(
            "restore",
            "own ops pruned by own snapshot".into(),
            3,
            cp(shared(3, false), 3),
            vec![
                vec![w("a", 11), Sync, Snapshot, Upload],
                vec![Fetch],
                vec![Fetch],
            ],
            vec![RestoreServer(0)],
        ),
        scn(
            "restore",
            "lost device, healer holds its ops".into(),
            3,
            cp(shared(3, false), 3),
            vec![
                vec![w("a", 11), Sync, Lose],
                vec![Fetch, Fetch],
                vec![Fetch],
            ],
            vec![RestoreServer(0)],
        ),
        scn(
            "restore",
            "restore rolls back a rotation".into(),
            3,
            cp(shared(3, false), 3),
            vec![vec![w("a", 11), Sync], vec![Rotate], vec![Fetch]],
            vec![RestoreServer(0)],
        ),
        scn(
            "restore",
            "restore after a purge".into(),
            3,
            cp(shared(3, true), 3),
            vec![vec![Purge, Sync], vec![Fetch], vec![w("a", 31), Sync]],
            vec![RestoreServer(0)],
        ),
        {
            // ADR 0021 §8 "the restore drill checks server property 1" and open question 4: the
            // backup already holds a bodiless header behind two snapshots; D3 is a fresh device
            // that learns the item through bodiless headers and covers, before or after the
            // restore and the healing snapshots.
            let mut setup = shared(3, false);
            setup.extend([
                (0, Snapshot),
                (0, Upload),
                (1, Fetch),
                (1, w("b", 7)),
                (1, Snapshot),
                (1, Upload),
                (4, Worker),
                (4, Checkpoint(0)),
            ]);
            scn(
                "restore",
                "restore after compaction, fresh device".into(),
                4,
                setup,
                vec![
                    vec![w("a", 11), Snapshot, Sync],
                    vec![Fetch, w("a", 21), Sync],
                    vec![Fetch],
                    vec![Fetch],
                ],
                vec![Worker, RestoreServer(0)],
            )
        },
    ]
}

/// Restore healing (ADR 0012 §7 "Healing a server rollback"; ADR 0018 "Settled by the merge spike"
/// item 2; ADR 0021 "Settled by the merge spike" bullet 2 and open question 4). The backup is taken
/// right after the setup unless the setup says otherwise. Device 3, where present, is fresh: it
/// never synced before the restore, so it learns the item only from the healed server.
pub fn healing(quick: bool) -> Vec<Scenario> {
    let cp = |mut s: Vec<(usize, Act)>, n_dev: usize| {
        s.push((n_dev, Checkpoint(0)));
        s
    };
    let all = vec![
        // Own ops after the backup, the second pruned by the author's own snapshot (ADR 0012 §6).
        scn(
            "healing",
            "own edits, own snapshot".into(),
            3,
            cp(shared(3, false), 3),
            vec![
                vec![w("a", 11), Sync, Snapshot, Upload],
                vec![Fetch, w("b", 21), Sync],
                vec![Fetch],
            ],
            vec![RestoreServer(0)],
        ),
        // The author is lost; D1 wrote a snapshot after fetching, which pruned the lost device's
        // op from its retained ops: D1's fresh snapshot is the only record of it.
        scn(
            "healing",
            "lost author, only in the healer's snapshot".into(),
            4,
            cp(shared(3, false), 4),
            vec![
                vec![w("a", 11), Sync, Lose],
                vec![Fetch, Snapshot, Upload],
                vec![Fetch],
                vec![Fetch],
            ],
            vec![RestoreServer(0)],
        ),
        // The lost author's ops reached D1 only as bodiless headers and a cover (compaction), so
        // D1 never held their bodies.
        scn(
            "healing",
            "lost author, only in an absorbed cover".into(),
            4,
            cp(shared(3, false), 4),
            vec![
                vec![w("a", 11), Snapshot, Sync, w("a", 12), Snapshot, Sync, Lose],
                vec![Fetch, Fetch],
                vec![Fetch],
                vec![],
            ],
            vec![Worker, RestoreServer(0)],
        ),
        // Two healers that saw different prefixes of the lost author's chain.
        scn(
            "healing",
            "lost author, two healers, different prefixes".into(),
            3,
            cp(shared(3, false), 3),
            vec![
                vec![w("a", 11), Sync, w("b", 12), Sync, Lose],
                vec![Fetch, Snapshot, Upload],
                vec![Fetch, Fetch],
            ],
            vec![RestoreServer(0)],
        ),
        // A healer with an unsent edit and an unsent snapshot that claims the lost author's op.
        scn(
            "healing",
            "healer with unsent edit and snapshot".into(),
            4,
            cp(shared(3, false), 4),
            vec![
                vec![w("a", 11), Sync, Lose],
                vec![Fetch, w("b", 21), Snapshot, Upload],
                vec![Fetch],
                vec![Fetch],
            ],
            vec![RestoreServer(0)],
        ),
        // The restore rolls back a rotation and a purge made before it (stale-epoch check on the
        // re-published purge, ADR 0018 §3 item_key_id).
        scn(
            "healing",
            "restore rolls back a rotation after a purge".into(),
            4,
            cp(shared(3, true), 4),
            vec![vec![Purge, Sync], vec![Rotate], vec![Fetch], vec![Fetch]],
            vec![RestoreServer(0)],
        ),
        scn(
            "healing",
            "restore rolls back a rotation, edits".into(),
            3,
            cp(shared(3, false), 3),
            vec![
                vec![w("a", 11), Sync],
                vec![Rotate],
                vec![Fetch, w("b", 31), Sync],
            ],
            vec![RestoreServer(0)],
        ),
        // An op stored whose response was lost, then a rotation and a restore that rolls both back.
        scn(
            "healing",
            "lost response, rotation, restore".into(),
            3,
            cp(shared(3, true), 3),
            vec![
                vec![Purge, SyncLost, Upload],
                vec![Fetch, Rotate],
                vec![Fetch],
            ],
            vec![RestoreServer(0)],
        ),
        // The restore rolls back a revocation; the revoked device's ops up to its cut-off survive
        // only on the healer.
        scn(
            "healing",
            "restore rolls back a revocation".into(),
            3,
            cp(shared(3, false), 3),
            vec![
                vec![w("a", 11), Sync],
                vec![Revoke(0)],
                vec![Fetch, w("b", 31), Sync],
            ],
            vec![RestoreServer(0)],
        ),
        // A purge by a device that is then lost.
        scn(
            "healing",
            "lost purger".into(),
            4,
            cp(shared(3, true), 4),
            vec![
                vec![Purge, Sync, Lose],
                vec![Fetch, Snapshot, Upload],
                vec![w("a", 31), Sync],
                vec![Fetch],
            ],
            vec![RestoreServer(0)],
        ),
        // The backup is taken after a rotation. D0 then writes the writer-rule snapshot under a
        // fresh item key, whose wrap travels with that snapshot (CRYPTO.md §11.6); a restore that
        // loses the snapshot loses the wrap, and D0's next op under the key carries none. No VV
        // or cursor shows the loss.
        {
            let mut setup = shared(3, false);
            setup.extend([(1, Rotate), (3, Checkpoint(0))]);
            scn(
                "healing",
                "restore loses a fresh key's wrap".into(),
                3,
                setup,
                vec![
                    vec![Fetch, Snapshot, Upload, w("a", 11), Sync],
                    vec![Fetch],
                    vec![Fetch],
                ],
                vec![RestoreServer(0)],
            )
        },
        // ADR 0021 open question 4: D1 wrote a snapshot before the restore that claims the lost
        // author's op, uploads it after the restore without fetching (no rollback detected), and
        // is lost. The backup holds bodiless headers (compaction), so the snapshot can reach the
        // fresh device D3 as their cover, but never D2, whose cursor is past them.
        {
            let mut setup = shared(3, false);
            setup.extend([
                (0, Snapshot),
                (0, Upload),
                (1, Fetch),
                (1, w("b", 7)),
                (1, Snapshot),
                (1, Upload),
                (4, Worker),
                (2, Fetch),
                (4, Checkpoint(0)),
            ]);
            scn(
                "healing",
                "lost healer's pre-restore snapshot, fresh device".into(),
                4,
                setup,
                vec![
                    vec![w("a", 11), Sync, Lose],
                    vec![Fetch, Snapshot, Upload, Lose],
                    vec![],
                    vec![Fetch],
                ],
                vec![RestoreServer(0)],
            )
        },
        // Two restores to the same backup, the second after healing.
        scn(
            "healing",
            "restore twice".into(),
            3,
            cp(shared(3, false), 3),
            vec![
                vec![w("a", 11), Sync, Snapshot, Upload],
                vec![Fetch, Fetch],
                vec![w("b", 31), Sync],
            ],
            vec![RestoreServer(0), RestoreServer(0)],
        ),
    ];
    // Quick mode: one scenario per finding.
    let quick_set = [
        "own edits, own snapshot",
        "lost author, only in the healer's snapshot",
        "restore rolls back a rotation after a purge",
        "lost response, rotation, restore",
        "restore rolls back a revocation",
        "restore loses a fresh key's wrap",
        "lost healer's pre-restore snapshot, fresh device",
    ];
    all.into_iter()
        .filter(|s| !quick || quick_set.contains(&s.name.as_str()))
        .collect()
}

/// Verified but dishonest snapshots.
pub fn faulty(_quick: bool) -> Vec<Scenario> {
    vec![
        scn(
            "faulty",
            "omits a value".into(),
            4,
            shared(3, false),
            vec![
                vec![w("a", 11), Sync, Snapshot, Upload],
                vec![Fetch, Faulty(Fault::OmitValue), Upload],
                vec![Fetch],
                vec![Fetch],
            ],
            vec![Worker],
        ),
        scn(
            "faulty",
            "claims the author's next dot".into(),
            4,
            shared(3, false),
            vec![
                vec![w("a", 11), Snapshot, Sync, w("a", 12), Sync],
                vec![Fetch, Faulty(Fault::ClaimNext(0)), Upload],
                vec![],
                vec![Fetch],
            ],
            vec![Worker],
        ),
        scn(
            "faulty",
            "claims another device's next dot".into(),
            4,
            shared(3, false),
            vec![
                vec![w("a", 11), Snapshot, Sync],
                vec![Fetch, Faulty(Fault::ClaimNext(2)), Upload],
                vec![w("b", 31), Sync],
                vec![Fetch],
            ],
            vec![Worker],
        ),
        scn(
            "faulty",
            "omits a late value".into(),
            4,
            shared(3, true),
            vec![
                vec![Purge, Upload, Fetch],
                vec![Fetch, Faulty(Fault::OmitValue), Upload],
                vec![w("a", 31), Upload],
                vec![Fetch],
            ],
            vec![Worker],
        ),
    ]
}

/// Every fault kind (`replica::Fault`) against a live and a purged item. D1 writes the faulty
/// snapshot after fetching; D0 writes an honest snapshot and a new op (so compaction has two
/// snapshots and a claimed dot of D0 can become real); D2 is a concurrent writer, a plain fetcher,
/// or a third snapshot author; D3 is a fresh device that learns the item through bodiless headers
/// and covers. Run with `--server none` for the "without server compaction" case.
pub fn faulty_kinds(quick: bool) -> Vec<Scenario> {
    use crate::replica::ALL_FAULTS;
    let mut out = Vec::new();
    // Live item with history: create, then a second write of `a`, synced everywhere.
    let mut live_setup = shared(3, false);
    live_setup.extend([(0, w("a", 3)), (0, Sync), (1, Fetch), (2, Fetch)]);
    let d2_live: Vec<(&str, Vec<Act>)> = vec![
        ("writer", vec![w("b", 21), Sync]),
        ("fetcher", vec![Fetch]),
        ("snapshotter", vec![Fetch, Snapshot, Upload]),
    ];
    // Purged item with a late value: D2's late edit races D0's purge.
    let tomb_setup = shared(3, true);
    let tomb_menu: Vec<(&str, Vec<Act>)> = vec![
        ("late-writer", vec![w("a", 21), Upload]),
        (
            "late-writer+snapshot",
            vec![w("a", 21), Upload, Fetch, Snapshot, Upload],
        ),
        // A second late write whose context covers the first (so a widened c looks explained).
        ("late-2writes", vec![w("a", 21), w("b", 22), Upload]),
        (
            "late-2writes+snapshot",
            vec![w("a", 21), w("b", 22), Upload, Fetch, Snapshot, Upload],
        ),
    ];
    let mut faults: Vec<Fault> = ALL_FAULTS.to_vec();
    faults.push(Fault::ClaimNext(2));
    faults.push(Fault::ClaimValue(2));
    for f in faults {
        for (i, (lbl, d2)) in d2_live.iter().enumerate() {
            if quick && i > 0 {
                continue;
            }
            out.push(scn(
                "faulty-kinds",
                format!("live {f:?} D2:{lbl}"),
                4,
                live_setup.clone(),
                vec![
                    vec![w("a", 11), Snapshot, Sync],
                    vec![Fetch, Faulty(f), Upload],
                    d2.clone(),
                    vec![Fetch],
                ],
                vec![Worker],
            ));
        }
        for (i, (lbl, d2)) in tomb_menu.iter().enumerate() {
            if quick && i > 0 {
                continue;
            }
            out.push(scn(
                "faulty-kinds",
                format!("tomb {f:?} D2:{lbl}"),
                4,
                tomb_setup.clone(),
                vec![
                    vec![Purge, Upload],
                    vec![Fetch, Faulty(f), Upload],
                    d2.clone(),
                    vec![Fetch],
                ],
                vec![Worker],
            ));
        }
    }
    out
}

/// Revocation (ADR 0012 §6), including a device whose ops survive only in others' snapshots.
pub fn revocation(_quick: bool) -> Vec<Scenario> {
    vec![
        scn(
            "revocation",
            "revoke a writer".into(),
            3,
            shared(3, false),
            vec![
                vec![w("a", 11), Sync, w("a", 12), Sync],
                vec![Revoke(0)],
                vec![Fetch, w("b", 21), Sync],
            ],
            vec![],
        ),
        scn(
            "revocation",
            "revoked device's ops only in snapshots".into(),
            4,
            shared(3, false),
            vec![
                vec![w("a", 11), Snapshot, Sync],
                vec![Revoke(0)],
                vec![Fetch, Snapshot, Upload],
                vec![Fetch],
            ],
            vec![Worker],
        ),
        scn(
            "revocation",
            "revoke a purger".into(),
            3,
            shared(3, true),
            vec![
                vec![Purge, Upload, Fetch],
                vec![Revoke(0)],
                vec![w("a", 31), Sync],
            ],
            vec![],
        ),
    ]
}

// ---------------------------------------------------------------------------------------------
// Revocation of a device whose ops survive only inside another device's snapshot (ADR 0021
// "Settled by the merge spike", last bullet; ADR 0012 §6). In every family D1 is the device that
// is revoked, the revoker fetches, suspends and revokes in one step (ADR 0012 §6 phases 1-2), and
// D3 is a fresh device that learns the item only from the server after the fact.
// ---------------------------------------------------------------------------------------------

/// The revoked device's ops are compacted (ADR 0021 R1) behind its own snapshots, behind another
/// device's snapshots, or both, before or after the revocation; a device that was behind (D2) and
/// a fresh device (D3) then learn them through bodiless headers and covers.
pub fn rev_covers(quick: bool) -> Vec<Scenario> {
    let menus: Vec<Menu> = vec![
        // D0, the revoker.
        vec![
            ("R", vec![Revoke(1)]),
            // After the revocation's rotation: the writer rule writes a fresh key and a snapshot.
            ("RW", vec![Revoke(1), w("a", 12), Sync]),
        ],
        // D1, revoked.
        vec![
            ("W", vec![w("a", 21), Upload]),
            ("WS", vec![w("a", 21), Snapshot, Upload]),
            ("WSL", vec![w("a", 21), Snapshot, Upload, Lose]),
            (
                "WSWS",
                vec![w("a", 21), Snapshot, Upload, w("b", 22), Snapshot, Upload],
            ),
            ("WuFS", vec![w("a", 21), Upload, Fetch, Snapshot, Upload]),
        ],
        // D2, another writer, behind or concurrent.
        vec![
            ("WS", vec![w("b", 31), Snapshot, Upload]),
            ("FS", vec![Fetch, Snapshot, Upload]),
            ("FWS", vec![Fetch, w("b", 31), Snapshot, Upload]),
        ],
        // D3, fresh.
        vec![("F", vec![Fetch])],
    ];
    product(&menus, |l| {
        !quick || (l[0] == "R" && (l[1] == "WSWS" || l[1] == "WSL") && l[2] != "WS")
    })
    .into_iter()
    .map(|(name, progs)| {
        scn(
            "rev-covers",
            name,
            4,
            shared(3, false),
            progs,
            vec![Worker, Worker],
        )
    })
    .collect()
}

/// ADR 0021 §8's named scenarios with the snapshot author revoked: the lost laptop's late edits
/// behind its own live snapshot S_L, and concurrent purges whose tombstone snapshots are each the
/// only cover of their own purge op.
pub fn rev_named(quick: bool) -> Vec<Scenario> {
    let d1_sl = if quick {
        vec![w("a", 21), w("a", 22), Snapshot, Upload, Lose]
    } else {
        vec![w("a", 21), Upload, w("a", 22), Snapshot, Upload, Lose]
    };
    vec![
        scn(
            "rev-named",
            "late edits S_L, L lost and revoked".into(),
            4,
            shared(3, true),
            vec![
                vec![Purge, Upload, Fetch],
                d1_sl,
                vec![Fetch, Snapshot, Upload, Revoke(1)],
                vec![Fetch],
            ],
            vec![Worker, Worker],
        ),
        scn(
            "rev-named",
            "concurrent purges T_A/T_B, A revoked".into(),
            4,
            shared(3, true),
            vec![
                vec![Fetch],
                vec![Purge, Upload],
                vec![Purge, Upload, Fetch],
                vec![Fetch, Fetch],
            ],
            vec![Worker, Worker],
        )
        .with_program(0, vec![Fetch, Revoke(1)]),
        scn(
            "rev-named",
            "revoked purger, tombstone compacted, late edit".into(),
            4,
            shared(3, true),
            vec![
                vec![Fetch, Snapshot, Upload, Revoke(1)],
                vec![Purge, Upload],
                vec![w("a", 31), Upload, Fetch],
                vec![Fetch],
            ],
            vec![Worker, Worker],
        ),
    ]
}

/// The revoked device at the moment of suspension: ops it never uploaded, a snapshot uploaded
/// before the ops it covers (ADR 0021 §8 lists that history; ADR 0012 §7 orders ops only), and a
/// compromised device that uploads a snapshot claiming its own next dot before it is suspended.
pub fn rev_unsent(quick: bool) -> Vec<Scenario> {
    let menus: Vec<Menu> = vec![
        vec![("R", vec![Revoke(1)])],
        vec![
            (
                "W|WS",
                vec![w("a", 21), Upload, w("a", 22), Snapshot, Upload],
            ),
            (
                "snap-first",
                vec![
                    w("a", 21),
                    Upload,
                    w("a", 22),
                    Snapshot,
                    UploadSnaps,
                    Upload,
                ],
            ),
            (
                "claim",
                vec![w("a", 21), Upload, Faulty(Fault::ClaimNext(1)), Upload],
            ),
            (
                "claim-W",
                vec![
                    w("a", 21),
                    Faulty(Fault::ClaimNext(1)),
                    Upload,
                    w("a", 22),
                    Upload,
                ],
            ),
        ],
        vec![
            ("FS", vec![Fetch, Snapshot, Upload]),
            ("FWS", vec![Fetch, w("b", 31), Snapshot, Upload]),
        ],
        vec![("F", vec![Fetch])],
    ];
    product(&menus, |l| !quick || l[2] == "FS")
        .into_iter()
        .map(|(name, progs)| {
            scn(
                "rev-unsent",
                name,
                4,
                shared(3, false),
                progs,
                vec![Worker, Worker],
            )
        })
        .collect()
}

/// A server restore (ADR 0012 §7 "Healing a server rollback") around the revocation. The backup
/// is taken right after the setup; D1 writes after it; D2 applies D1's op and snapshots or edits
/// over it; D3 is fresh. The restore runs in D0's program so that its order with the revocation
/// is fixed per scenario:
/// - `drill`: revoke, then restore (the ADR 0011 restore drill: the restore rolls the revocation
///   back and healers re-publish it, ADR 0012 §7 healing step 2);
/// - `late`: restore, then revoke on the restored server, whose head for D1 is below what D2
///   applied.
pub fn rev_restore(quick: bool) -> Vec<Scenario> {
    let menus: Vec<Menu> = vec![
        vec![
            ("drill", vec![Revoke(1), RestoreServer(0)]),
            // The revoker also snapshots before the restore, so its retained copy of D1's op is
            // pruned (ADR 0012 §6) and, if D2 pruned it too, D1's op survives only in snapshots.
            (
                "drill-S",
                vec![Revoke(1), Snapshot, Upload, RestoreServer(0)],
            ),
            ("late", vec![RestoreServer(0), Revoke(1)]),
        ],
        vec![
            ("W", vec![w("a", 21), Sync]),
            ("WL", vec![w("a", 21), Sync, Lose]),
        ],
        vec![
            ("FS", vec![Fetch, Snapshot, Upload]),
            ("FW", vec![Fetch, w("b", 31), Sync]),
            ("FWS", vec![Fetch, w("b", 31), Snapshot, Sync]),
        ],
        vec![("F", vec![Fetch])],
    ];
    let servers: Vec<(&str, Vec<Act>)> = vec![("", vec![]), (" S:worker", vec![Worker])];
    let mut out = Vec::new();
    for (name, progs) in product(&menus, |l| !quick || l[1] == "WL") {
        for (sn, sp) in &servers {
            if quick && !sn.is_empty() {
                continue;
            }
            let mut setup = shared(3, false);
            setup.push((4, Checkpoint(0)));
            out.push(scn(
                "rev-restore",
                format!("{name}{sn}"),
                4,
                setup,
                progs.clone(),
                sp.clone(),
            ));
        }
    }
    out
}

/// ADR 0018 §10 oversize items (limit scaled to 2 values per register): no snapshot, so
/// nothing is compacted; healing must re-publish ops.
pub fn oversize(_quick: bool) -> Vec<Scenario> {
    let cp = |mut s: Vec<(usize, Act)>| {
        s.push((4, Checkpoint(0)));
        s
    };
    let mut v = vec![
        scn(
            "oversize",
            "three concurrent values, snapshots refused".into(),
            4,
            shared(3, false),
            vec![
                vec![w("a", 11), Upload, Fetch, Snapshot, Upload],
                vec![w("a", 21), Upload, Fetch],
                vec![w("a", 31), Snapshot, Upload, Fetch],
                vec![Fetch],
            ],
            vec![Worker],
        ),
        scn(
            "oversize",
            "oversize item and a server restore".into(),
            4,
            cp(shared(3, false)),
            vec![
                vec![w("a", 11), Sync, Snapshot, Upload],
                vec![w("a", 21), Sync],
                vec![w("a", 31), Sync],
                vec![],
            ],
            vec![RestoreServer(0)],
        ),
        scn(
            "oversize",
            "oversize after a rotation (writer rule)".into(),
            4,
            shared(3, false),
            vec![
                vec![w("a", 11), Sync],
                vec![w("a", 21), Sync],
                vec![w("a", 31), Sync],
                vec![Rotate, Fetch, w("b", 41), Sync],
            ],
            vec![],
        ),
    ];
    let cp4 = |mut s: Vec<(usize, Act)>| {
        s.push((4, Checkpoint(0)));
        s
    };
    // ADR 0018 open question 12: healing step 4 for an item that cannot get a fresh snapshot.
    v.push(scn(
        "oversize",
        "oversize after a snapshot, restore before it".into(),
        4,
        cp4(shared(3, false)),
        vec![
            vec![w("a", 11), Snapshot, Sync, Fetch],
            vec![w("a", 21), Sync],
            vec![w("a", 31), Sync],
            vec![Fetch],
        ],
        vec![RestoreServer(0)],
    ));
    v.push(scn(
        "oversize",
        "oversize, lost author, restore".into(),
        4,
        cp4(shared(3, false)),
        vec![
            vec![w("a", 11), Sync, Lose],
            vec![w("a", 21), Sync, Fetch],
            vec![w("a", 31), Sync],
            vec![Fetch],
        ],
        vec![RestoreServer(0)],
    ));
    v.push(scn(
        "oversize",
        "oversize, restore rolls back a rotation".into(),
        4,
        cp4(shared(3, false)),
        vec![
            vec![w("a", 11), Sync],
            vec![w("a", 21), Sync],
            vec![w("a", 31), Sync],
            vec![Rotate],
        ],
        vec![RestoreServer(0)],
    ));
    for s in &mut v {
        s.max_values = Some(2);
    }
    v
}

/// The re-issue question (ADR 0018 "Settled by the merge spike" item 3; ADR 0021 item 3): ops
/// written offline across a rotation come back "stale epoch" and are re-issued; lost responses make
/// the client re-upload; a restore can roll back a rotation after the op was stored and served.
///
/// - `purge ...`: D0 purges a trashed item offline while D1 rotates (once or twice). D0 uploads at
///   once, after fetching (it learns the rotation and D2's work first), after writing a snapshot at
///   the new epoch, after a lost response, or after losing the response to its re-issued version.
///   D2 edits (a late value), purges too, restores, or only fetches.
/// - `write ...`: the same shapes on a live item, with edits, a two-edit chain and a trash, for the
///   HLC and context variants of the re-issue.
/// - `compaction ...`: a re-issued purge, tombstone snapshots, `worker`, and a fresh device D3 that
///   learns the item through bodiless headers and covers.
/// - `restore ...`: the server's backup is taken at any point of the schedule and restored later,
///   with a purge (or an edit) stored and served before a rotation that the restore rolls back.
pub fn reissue(quick: bool) -> Vec<Scenario> {
    let mut out = Vec::new();
    let purge_menus: Vec<Menu> = vec![
        vec![
            ("P", vec![Purge, Upload, Fetch]),
            ("P-F", vec![Purge, Fetch, Upload, Fetch]),
            ("P-F-S", vec![Purge, Fetch, Snapshot, Upload, Fetch]),
            ("P-lost", vec![Purge, SyncLost, Upload, Fetch]),
            (
                "P-once-lost",
                vec![Purge, UploadOnce, SyncLost, Upload, Fetch],
            ),
        ],
        vec![("R", vec![Rotate]), ("RR", vec![Rotate, Rotate])],
        vec![
            ("E", vec![w("a", 31), Upload, Fetch]),
            ("P", vec![Purge, Upload, Fetch]),
            ("Rs", vec![Restore, Upload, Fetch]),
            ("F", vec![Fetch]),
        ],
    ];
    for (name, progs) in product(&purge_menus, |l| {
        !quick || l[1] == "R" && (l[2] == "E" || l[2] == "P")
    }) {
        out.push(scn(
            "reissue",
            format!("purge {name}"),
            3,
            shared(3, true),
            progs,
            vec![],
        ));
    }
    let write_menus: Vec<Menu> = vec![
        vec![
            ("W-F", vec![w("a", 11), Fetch, Upload, Fetch]),
            ("WW-F", vec![w("a", 11), w("a", 12), Fetch, Upload, Fetch]),
            ("T-F", vec![Trash, Fetch, Upload, Fetch]),
            ("W-lost", vec![w("a", 11), SyncLost, Upload, Fetch]),
            (
                "W-once-lost",
                vec![w("a", 11), UploadOnce, SyncLost, Upload, Fetch],
            ),
            // A lost response, then a later own edit that must still reach the others.
            (
                "W-lost-W",
                vec![w("a", 11), SyncLost, w("b", 12), Upload, Fetch],
            ),
        ],
        vec![("R", vec![Rotate]), ("RR", vec![Rotate, Rotate])],
        vec![
            ("E", vec![w("a", 31), Upload, Fetch]),
            ("Eb", vec![w("b", 32), Upload, Fetch]),
            ("T", vec![Trash, Upload, Fetch]),
            ("F", vec![Fetch]),
        ],
    ];
    for (name, progs) in product(&write_menus, |l| {
        !quick || l[1] == "R" && (l[2] == "E" || l[2] == "T")
    }) {
        out.push(scn(
            "reissue",
            format!("write {name}"),
            3,
            shared(3, false),
            progs,
            vec![],
        ));
    }
    let comp_menus: Vec<Menu> = vec![
        vec![
            ("P", vec![Purge, Upload, Fetch]),
            ("P-F", vec![Purge, Fetch, Upload]),
            // A snapshot at the new epoch, written before the re-issue, embeds the original.
            ("P-F-S", vec![Purge, Fetch, Snapshot, Upload]),
        ],
        vec![("R", vec![Rotate])],
        vec![
            ("FS", vec![Fetch, Snapshot, Upload]),
            ("ES", vec![w("a", 31), Snapshot, Upload]),
            // A snapshot that misses D0's purge: stored after D0's, it is the newest, so D0's
            // snapshot is the only cover of the purge's bodiless header.
            ("S", vec![Snapshot, Upload]),
        ],
        vec![("F", vec![Fetch])],
    ];
    for (name, progs) in product(&comp_menus, |l| !quick || l[0] == "P-F") {
        out.push(scn(
            "reissue",
            format!("compaction {name}"),
            4,
            shared(3, true),
            progs,
            vec![Worker],
        ));
    }
    // A stale-epoch answer to a *snapshot* ahead of an op whose earlier upload (response lost)
    // was stored: `worker` dropped the snapshot (R3), so its re-upload is not a duplicate. Found
    // by random-reissue seed 12438.
    out.push(scn(
        "reissue",
        "outbox: snapshot answered stale ahead of a stored op".into(),
        3,
        shared(3, true),
        vec![
            vec![Rotate],
            vec![Snapshot, Purge, Snapshot, SyncLost, Upload, Fetch],
            vec![Fetch],
        ],
        vec![Worker],
    ));
    // Two rotations: a re-issued op takes a fresh key whose wrap rides on a later op, and that
    // later op is re-issued again under a newer key. Found by random-reissue seed 20926.
    for (name, d0) in [
        (
            "wrap: re-issue under a key whose wrap is on a later op, then a second rotation",
            vec![
                w("a", 11),
                Fetch,
                w("a", 12),
                UploadOnce,
                UploadOnce,
                Upload,
                Fetch,
            ],
        ),
        (
            "wrap: the same with a purge as the later op",
            vec![Trash, Fetch, Purge, UploadOnce, UploadOnce, Upload, Fetch],
        ),
    ] {
        out.push(scn(
            "reissue",
            name.into(),
            3,
            shared(3, false),
            vec![d0, vec![Rotate, Rotate], vec![Fetch]],
            vec![],
        ));
    }
    let restore_menus: Vec<Menu> = vec![
        vec![
            ("P", vec![Purge, Sync, Fetch]),
            ("P-lost", vec![Purge, SyncLost, Fetch, Upload]),
            ("W", vec![w("a", 11), Sync, Fetch]),
        ],
        vec![("FR", vec![Fetch, Rotate])],
        vec![("F", vec![Fetch]), ("P", vec![Purge, Sync])],
    ];
    for (name, progs) in product(&restore_menus, |l| !quick || l[0] != "W") {
        out.push(scn(
            "reissue",
            format!("restore {name}"),
            3,
            shared(3, true),
            progs,
            vec![Checkpoint(0), RestoreServer(0)],
        ));
    }
    out
}

pub type FamilyFn = fn(bool) -> Vec<Scenario>;

pub const FAMILIES: &[(&str, FamilyFn)] = &[
    ("concurrent-edits", concurrent_edits),
    ("purges", purges),
    ("edit-purge", edit_purge),
    ("trash-restore", trash_restore),
    ("snapshots", snapshots),
    ("absorb", absorb),
    ("compaction", compaction),
    ("rotation", rotation),
    ("restore", restore),
    ("healing", healing),
    ("faulty", faulty),
    ("faulty-kinds", faulty_kinds),
    ("revocation", revocation),
    ("oversize", oversize),
    ("reissue", reissue),
    ("rev-covers", rev_covers),
    ("rev-named", rev_named),
    ("rev-unsent", rev_unsent),
    ("rev-restore", rev_restore),
];

pub fn family(name: &str) -> Option<FamilyFn> {
    FAMILIES.iter().find(|(n, _)| *n == name).map(|(_, f)| *f)
}
