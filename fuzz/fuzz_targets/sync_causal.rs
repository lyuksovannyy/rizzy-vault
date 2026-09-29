//! Fuzzes `rizzy-sync`'s per-device-chain layer (`causal`: ADR 0012 §4 steps 1–2, §6, §7;
//! ADR 0021 §4, §9), which a client runs on what an untrusted server serves: any sequence of
//! verified headers, covers and body verdicts may arrive, in any order, with any links, contexts
//! and claims. No call may panic, and each answer must keep its rule's guarantee.
//!
//! The input is read as a script over one vault, four devices (the last is the log's own) and
//! three items. A `seq` byte gives 0–7, or one of the 16 values up to `u64::MAX`. Input that runs
//! out reads as zeros. Each command, chosen by a byte:
//!
//! - **A response** of up to 7 op headers (sometimes of another vault, any device, link,
//!   context and body verdict) and up to 3 covers: [`VaultLog::plan_covers`], absorption of some
//!   named covers (each recorded within the plan's cut and the cover), [`VaultLog::commit`], [`VaultLog::take_deliveries`]. Checked: every cover
//!   index is in range; every accepted header is held afterwards and each chain's head is its
//!   last accepted link; an accepted bodiless header or rejected body is covered by its item's
//!   settled VV; no body is delivered twice, none of a device past a cut-off known before the
//!   batch, and every delivered op is an accepted link whose item's settled VV then covers its
//!   dot and, for a fresh delivery, its causal context.
//! - **A body verdict** for a held dot ([`VaultLog::body_verified`], [`VaultLog::body_rejected`]).
//! - **A revocation** ([`VaultLog::learn_revocation`]): every rejected link is past the
//!   cut-off; every reported item's settled VV is past it.
//! - **An own op** ([`VaultLog::record_own_op`]): on success, the head is its seq and its item's
//!   settled VV covers it.
//! - **Upload bookkeeping**: [`VaultLog::observe_generation`], [`VaultLog::record_sent`], [`VaultLog::record_answered`],
//!   [`VaultLog::acknowledge`], [`VaultLog::stale_plan`] (every planned op is an own link at or
//!   after the rejected one, in exactly one of the two lists) and [`VaultLog::reissue_own_op`].
//! - **Reports**: [`VaultLog::waiting`] (every entry an accepted, undelivered link),
//!   [`VaultLog::complete_fetch_reports`] and [`VaultLog::server_behind`] against arbitrary
//!   heads.
//!
//! Not in the CRYPTO.md §15 item 7 list by name: the layer parses no bytes. CLAUDE.md requires a
//! target for untrusted input, and every header and cover here is the server's choice.
//!
//! ```text
//! cargo +nightly fuzz run sync_causal
//! ```
#![no_main]

use std::collections::BTreeSet;

use libfuzzer_sys::fuzz_target;
use rizzy_core::ids::{DeviceId, ItemId, OpId, SnapshotId, VaultId};
use rizzy_sync::causal::{BodyStatus, RestoreGeneration, ServedOp, ServerView, VaultLog};
use rizzy_sync::dot::Dot;
use rizzy_sync::header::{ItemSchemaVersion, OpHeader, SnapshotHeader};
use rizzy_sync::hlc::Hlc;
use rizzy_sync::vv::VersionVector;

/// The id bytes of the four devices: device i is `[IDS[i]; 16]`; the last is the log's own.
const IDS: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xee];

/// The vault of the log.
const VAULT: VaultId = VaultId::from_bytes([0x11; 16]);

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

    /// One of three items.
    fn item(&mut self) -> ItemId {
        ItemId::from_bytes([0x58 + self.byte() % 3; 16])
    }

    /// A sequence number: 0–7 for bytes below 0xf0, else one of the 16 values up to
    /// `u64::MAX`.
    fn seq(&mut self) -> u64 {
        match self.byte() {
            b @ 0xf0.. => u64::MAX - u64::from(0xff - b),
            b => u64::from(b % 8),
        }
    }

    /// A version vector of up to three entries; zero entries are left out.
    fn vv(&mut self) -> VersionVector {
        let mut vv = VersionVector::new();
        for _ in 0..self.byte() % 4 {
            if let Some(dot) = Dot::new(self.device(), self.seq()) {
                vv.add(dot);
            }
        }
        vv
    }

    /// An op header; `None` when its seq is 0, which no parsed header has.
    fn header(&mut self, device: DeviceId) -> Option<OpHeader> {
        let flags = self.byte();
        let dot = Dot::new(device, self.seq())?;
        let vault_prev_seq = self.seq();
        let item_id = self.item();
        let causal_context = self.vv();
        Some(OpHeader {
            vault_id: if flags & 0x80 == 0 {
                VAULT
            } else {
                VaultId::from_bytes([0x22; 16])
            },
            item_id,
            op_id: OpId::from_bytes([flags; 16]),
            dot,
            vault_prev_seq,
            hlc: Hlc::from_u64(u64::from(self.byte())),
            item_schema_version: ItemSchemaVersion::V1,
            vault_key_epoch: u32::from(flags & 3),
            causal_context,
        })
    }

    /// A body verdict.
    fn body(&mut self) -> BodyStatus {
        match self.byte() % 4 {
            0 => BodyStatus::Verified,
            1 => BodyStatus::Waiting,
            2 => BodyStatus::Rejected,
            _ => BodyStatus::Bodiless,
        }
    }

    /// A cover: a snapshot header of this vault.
    fn cover(&mut self) -> SnapshotHeader {
        let author = self.device();
        let item_id = self.item();
        let covered = self.vv();
        SnapshotHeader {
            vault_id: VAULT,
            item_id,
            snapshot_id: SnapshotId::from_bytes([self.byte(); 16]),
            author,
            item_schema_version: ItemSchemaVersion::V1,
            vault_key_epoch: 1,
            covered,
        }
    }
}

/// One response: plan, absorb, commit, deliver, with the checks of the module docs.
fn respond(log: &mut VaultLog, input: &mut Input<'_>, delivered: &mut BTreeSet<Dot>) {
    let mut ops = Vec::new();
    for _ in 0..input.byte() % 8 {
        let device = input.device();
        if let Some(header) = input.header(device) {
            ops.push(ServedOp {
                header,
                body: input.body(),
            });
        }
    }
    let covers: Vec<SnapshotHeader> = (0..input.byte() % 4).map(|_| input.cover()).collect();
    let plan = log.plan_covers(&ops, &covers);
    assert!(plan.refused.iter().all(|&i| i < covers.len()));
    let absorb_mask = input.byte();
    for (n, &i) in plan.absorb.iter().enumerate() {
        let cover = covers.get(i).expect("a cover index is in range");
        if (absorb_mask >> (n % 8)) & 1 == 1 {
            let recorded = log.record_absorbed(&plan, cover.item_id, &cover.covered);
            assert!(
                recorded
                    .entries()
                    .all(|e| e.seq() <= plan.cut.get(e.device_id()) && cover.covered.covers(e)),
                "a cover recorded past the cut"
            );
        }
    }
    let commit = log.commit(&ops);
    let mut last: std::collections::BTreeMap<DeviceId, u64> = std::collections::BTreeMap::new();
    for &dot in &commit.accepted {
        let header = log.header(dot).expect("an accepted header is held");
        let served = ops
            .iter()
            .find(|o| o.header == *header)
            .expect("an accepted header was served");
        if matches!(served.body, BodyStatus::Bodiless | BodyStatus::Rejected) {
            assert!(log.settled(header.item_id).covers(dot));
        }
        last.insert(dot.device_id(), dot.seq());
    }
    for (device, seq) in last {
        assert_eq!(log.head(device), seq);
    }
    deliver(log, delivered);
}

/// Takes the deliveries and checks them.
fn deliver(log: &mut VaultLog, delivered: &mut BTreeSet<Dot>) {
    let cutoffs: Vec<(DeviceId, u64)> = IDS
        .iter()
        .map(|&b| DeviceId::from_bytes([b; 16]))
        .filter_map(|d| log.cutoff(d).map(|c| (d, c)))
        .collect();
    for delivery in log.take_deliveries() {
        let dot = delivery.dot;
        assert!(delivered.insert(dot), "a body delivered twice");
        assert!(
            cutoffs
                .iter()
                .all(|&(d, c)| d != dot.device_id() || dot.seq() <= c),
            "a body past a known cut-off delivered"
        );
        assert!(dot.seq() <= log.head(dot.device_id()));
        let header = log.header(dot).expect("a delivered op is an accepted link");
        assert_eq!(header.item_id, delivery.item_id);
        let settled = log.settled(header.item_id);
        assert!(settled.covers(dot));
        if !delivery.covered {
            assert!(header.causal_context.entries().all(|e| settled.covers(e)));
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let own = DeviceId::from_bytes([IDS[3]; 16]);
    let mut log = VaultLog::new(VAULT, own);
    let mut delivered: BTreeSet<Dot> = BTreeSet::new();
    for _ in 0..32 {
        if input.0.is_empty() {
            break;
        }
        match input.byte() % 8 {
            0 | 1 => respond(&mut log, &mut input, &mut delivered),
            2 => {
                if let Some(dot) = Dot::new(input.device(), input.seq()) {
                    let verified = input.byte() & 1 == 0;
                    let _ = if verified {
                        log.body_verified(dot)
                    } else {
                        log.body_rejected(dot)
                    };
                    deliver(&mut log, &mut delivered);
                }
            }
            3 => {
                let device = input.device();
                let cut = input.seq();
                let revocation = log.learn_revocation(device, cut);
                let cut = log.cutoff(device).expect("a learned cut-off is kept");
                assert!(
                    revocation
                        .rejected
                        .iter()
                        .all(|d| d.device_id() == device && d.seq() > cut)
                );
                for item in revocation.held_past_cutoff {
                    assert!(log.settled(item).get(device) > cut);
                }
            }
            4 => {
                if let Some(header) = input.header(own) {
                    let (dot, item) = (header.dot, header.item_id);
                    if log.record_own_op(header).is_ok() {
                        assert_eq!(log.own_vault_prev_seq(), dot.seq());
                        assert!(log.settled(item).covers(dot));
                    }
                }
            }
            5 => match input.byte() % 6 {
                0 => log.observe_generation(RestoreGeneration::from_bytes([input.byte(); 16])),
                1 => {
                    let _ = log.record_sent(input.seq());
                }
                5 => {
                    let seq = input.seq();
                    let _ =
                        log.record_answered(seq, RestoreGeneration::from_bytes([input.byte(); 16]));
                }
                2 => {
                    let seq = input.seq();
                    if log.acknowledge(seq).is_ok() {
                        assert!(log.acknowledged() >= seq);
                        assert!(!log.unacknowledged().any(|h| h.dot.seq() <= seq));
                    }
                }
                3 => {
                    let rejected = input.seq();
                    if let Ok(plan) = log.stale_plan(rejected, u32::from(input.byte() % 4)) {
                        let all: Vec<Dot> = plan
                            .reissue
                            .iter()
                            .chain(&plan.republish)
                            .copied()
                            .collect();
                        let distinct: BTreeSet<Dot> = all.iter().copied().collect();
                        assert_eq!(distinct.len(), all.len());
                        for dot in all {
                            assert!(dot.device_id() == own && dot.seq() >= rejected);
                            assert!(log.header(dot).is_some());
                        }
                    }
                }
                _ => {
                    if let Some(header) = input.header(own) {
                        let dot = header.dot;
                        let expected = header.clone();
                        if log.reissue_own_op(header).is_ok() {
                            assert_eq!(log.header(dot), Some(&expected));
                        }
                    }
                }
            },
            6 => {
                for w in log.waiting() {
                    assert!(w.dot.seq() <= log.head(w.dot.device_id()));
                    assert!(!delivered.contains(&w.dot));
                    assert!(log.header(w.dot).is_some());
                }
                let _ = log.complete_fetch_reports();
            }
            _ => {
                let heads = input.vv();
                let view = ServerView {
                    state_seq: input.seq(),
                    heads: &heads,
                    lacks_wrap: input.byte() & 1 == 1,
                };
                let behind = log.server_behind(input.seq(), view);
                let _ = behind.is_empty();
            }
        }
    }
});
