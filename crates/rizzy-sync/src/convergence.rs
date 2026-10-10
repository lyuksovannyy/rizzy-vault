// SPDX-License-Identifier: AGPL-3.0-only

//! The ADR 0012 §12 convergence harness: simulated devices and a simulated server running the
//! whole engine (the `causal` layer, the per-item `merge`, the record layer and the server's
//! `compaction` rules) inside one test process, driven by a seeded scheduler.
//!
//! # What ADR 0012 §12 asks, after supersession
//!
//! ADR 0022 removes the relay, On-device mode, mode switches, relay TTL, pairing and property 5
//! (staleness); ADR 0018 §12 replaces property 2 and asks the convergence property to compare
//! the §4 state hash; ADR 0021 §8 adds the client properties with compaction on and its named
//! scenarios. What is left, and where it is:
//!
//! | ADR text | Here |
//! |---|---|
//! | 3–7 simulated devices, a simulated server | [`world::World`], [`device::Device`], [`server::Server`] (which calls [`crate::compaction`]), checked by the independent [`checker`] (ADR 0021 §8) |
//! | a deterministic scheduler and a seeded RNG | [`oracle::Rng`] (xorshift64*, as the merge spike's `random.rs`); proptest draws only the seed and the family |
//! | real `rizzy-core` crypto with a test RNG | [`crypto`]: signed statements and sealed `ITEM_OP`/`ITEM_SNAPSHOT` envelopes under a seeded `ChaCha20Rng`; see "Crypto" below for what is not modelled |
//! | creates, field edits, list-element edits, trash, restore, purge, concurrent edits, offline devices | every family of [`generate`]; list elements are the `tag/<hex>` and `uri/<id>/value` keys of [`KEYS`], some ops write several keys |
//! | duplicated, delayed and reordered delivery | [`world::Faults`]: pages, shuffles, duplicate records and pages; lost upload answers and re-uploads ("Already stored") |
//! | a server rolled back to an earlier state | backups and restores with healing requests ([`generate`] family `restore`, [`named`]) |
//! | a server that withholds an op on one item while serving a compacted snapshot of another | [`generate`]'s gap-detection test and the ADR 0012 §7 example in [`named`] |
//! | device revocation | family `revocation` (every revocation rotates the keys), families `rotation` and `mixed`, [`named`] |
//! | ADR 0021 §8: snapshots from several devices, concurrent purges, late edits, a snapshot uploaded before ops it covers, snapshots that claim unheld dots up to `u64::MAX`, oversize items, `worker` paused and resumed, restores followed by healing requests, re-uploads, revocations, fetches from a cursor behind the head | families `purges`, `snapshots`, `restore`, `revocation`, `faults`, `faulty` ([`faults`]); named scenarios `T_A`/`T_B`, `S_L`, the oversize item, the lost answer across a restore and the merge spike's faulty cases |
//! | ADR 0021 §8, §9 "Stale epoch", "Revoked and kind-4 authors", "Rotation cut-off"; ADR 0025; ADR 0032 | family `rotation`: rotations with revocations, and without them in runs that restore, stale-epoch answers to ops and snapshots, re-issues with the same `device_seq`, re-publications of ops that may have been served, the rotation cut-off ([`server::Server::rotate`]), the ADR 0032 lag repair after a restore; family `kind4`: a web vault whose certificate expires; family `faulty2`: two faulty devices, "detected and reported" beyond the bound ([`world`] module docs); named scenarios `a_stale_answer_lost_across_a_restore`, `a_kind4_snapshot_after_expiry`, `a_revoked_device_decrypts_nothing_written_after_the_rotation` |
//! | not reached | revocations combined with restores (ADR 0021 §9 "Restored-server revocation", an accepted M1 limit); a full rotation's revocations of kind-4 certificates; an op under an item key whose wrap has not arrived parked as `Waiting` (it is rejected and served again) |
//! | properties 1, 2, 3, 4, 6, 7; ADR 0021 §8 server properties 1–5 | [`world`] module docs; [`checker`] |
//! | budget: a fixed number of cases per property on every PR, 100 times more nightly; failures print their seed; fixed seeds become regression tests | [`generate`] |
//!
//! # Crypto
//!
//! Records are signed and encrypted with `rizzy-core` ([`crypto`]). Every op and snapshot
//! travels as its [`OpStatement`](rizzy_core::sign::OpStatement) or
//! [`SnapshotStatement`](rizzy_core::sign::SnapshotStatement) in the signed wire form, by its
//! author's device key, with its sealed `ITEM_OP` or `ITEM_SNAPSHOT` envelope under an item
//! key of the item, its `vault_key_epoch` in the header. The server and the devices verify each signature under the key of the device
//! the record names, parse the header from the verified statement
//! ([`crate::header::OpHeader::parse_statement`]) and check the envelope against the signed
//! hash; a device then opens the envelope under the AAD context that header gives
//! ([`crate::header::OpHeader::envelope_context`]), which binds the item id, the dot, the HLC
//! and, through the header hash, the causal context or a snapshot's covered VV (ADR 0018 owner
//! decision 3), and only then runs the record parser. The server holds no item key.
//!
//! `rizzy-core` takes randomness only as an injected `rand_core` 0.10 `CryptoRng`; the harness
//! injects `chacha20`'s seeded `ChaCha20Rng`, a dev-dependency (ADR 0009 "RNG rules"), into
//! `rizzy-core`'s public key-generation and seal functions. `rizzy-core`'s API is unchanged.
//!
//! The generated histories exchange honest signatures and envelopes only (a faulty device
//! lies in what it signs and seals, not in the crypto), so what the crypto refuses is pinned
//! by the tests of [`crypto`].
//!
//! **Rotation.** Vault keys per epoch, the CRYPTO.md §11.6 writer rule's fresh item keys and
//! their `ITEM_KEY_WRAP` envelopes are real `rizzy-core` keys and envelopes: a device holds a
//! fresh item key only after opening its wrap with a vault key it holds, and a rotation
//! re-wraps every wrap-set row under the next vault key, which the world grants to every
//! device but the revoked one. Property 6 as ADR 0012 §12 words it ("cannot decrypt anything
//! written after the rotation") is checked on what the revoked device holds
//! ([`world`] module docs). Modelled as effects, not messages: the signed `account-state`,
//! self-grants and device grants (the rotation protocol is `rizzy-client`'s, ADR 0025 §2, and
//! this crate may not depend on it, ADR 0016), certificates (a directory of verifying keys
//! stands in for the verified device set, and one of `expires_at_ms` for kind-4 certificates),
//! and the wrap hash in a signed statement (a wrap travels beside its record). Every device
//! holds the initial item keys from enrolment.
//!
//! # Findings
//!
//! A paged Fetch can split a tombstone cover from its recorded purge, and the device then
//! stalls against an honest server: see [`named`]'s
//! `finding_a_paged_tombstone_cover_split_from_its_purge_stalls`. The generated histories page
//! during the history and fetch whole responses in the drain ([`world::World::drain`]).
//!
//! # Readings
//!
//! Each follows the merge spike (`spikes/merge-model`, `integrated` preset) where the specs
//! leave a choice; the modules say which: explicit snapshots ([`device`]), the healing order
//! with several items ([`device`]), what the server compares for "Already stored" ([`server`]).

mod checker;
mod crypto;
mod device;
mod faults;
mod generate;
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes the devices and items it built; a panic there fails the test, which CLAUDE.md allows"
)]
mod named;
mod oracle;
mod server;
mod world;

use rizzy_core::ids::{DeviceId, ItemId, VaultId};

/// The one vault of every run.
const VAULT: VaultId = VaultId::from_bytes([0x5a; 16]);

/// 2026-05-28T20:26:40Z in Unix milliseconds, the base of every device's wall clock.
const T0: u64 = 1_780_000_000_000;

/// The field keys the generators write (ADR 0018 §7 grammar; M1 schema keys): plain fields,
/// and list elements (ADR 0018 §7 "List elements"): a URI element's `value` under a 16-byte
/// element id, and two tags whose keys are prefix-related, which ADR 0018 §4 orders as
/// `tag/61` < `tag/6162`.
const KEYS: [&str; 7] = [
    "item.name",
    "item.notes",
    "login.password",
    "login.username",
    "tag/61",
    "tag/6162",
    "uri/00112233445566778899aabbccddeeff/value",
];

/// Device `d` of a run.
fn device_id(d: usize) -> DeviceId {
    let b = u8::try_from(d).unwrap_or(u8::MAX);
    DeviceId::from_bytes([0x10 | (b & 0x0f); 16])
}

/// Item `i` of a run.
fn item_id(i: usize) -> ItemId {
    let b = u8::try_from(i).unwrap_or(u8::MAX);
    ItemId::from_bytes([0xa0 | (b & 0x0f); 16])
}

/// The `n`th fresh value the generators write to `key` (ADR 0018 §6, §7): for a tag, Bool
/// `0x01` (add) or, every third write, Cleared (remove, the zero-length value); otherwise a
/// Text.
fn value(key: &str, n: u64) -> Vec<u8> {
    if key.starts_with("tag/") {
        if n.is_multiple_of(3) {
            Vec::new()
        } else {
            vec![0x03, 0x01]
        }
    } else {
        text(&format!("v{n}"))
    }
}

/// A Text value (ADR 0018 §6): type byte `0x01`, then the UTF-8 text.
fn text(s: &str) -> Vec<u8> {
    let mut v = vec![0x01];
    v.extend_from_slice(s.as_bytes());
    v
}
