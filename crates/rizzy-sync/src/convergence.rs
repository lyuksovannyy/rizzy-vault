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
//! | real `rizzy-core` crypto with a test RNG | partly: see "Crypto" below |
//! | creates, field edits, list-element edits, trash, restore, purge, concurrent edits, offline devices | every family of [`generate`]; list elements are the `tag/<hex>` and `uri/<id>/value` keys of [`KEYS`], some ops write several keys |
//! | duplicated, delayed and reordered delivery | [`world::Faults`]: pages, shuffles, duplicate records and pages; lost upload answers and re-uploads ("Already stored") |
//! | a server rolled back to an earlier state | backups and restores with healing requests ([`generate`] family `restore`, [`named`]) |
//! | a server that withholds an op on one item while serving a compacted snapshot of another | [`generate`]'s gap-detection test and the ADR 0012 §7 example in [`named`] |
//! | device revocation | family `revocation`, [`named`] |
//! | ADR 0021 §8: snapshots from several devices, concurrent purges, late edits, a snapshot uploaded before ops it covers, snapshots that claim unheld dots up to `u64::MAX`, oversize items, `worker` paused and resumed, restores followed by healing requests, re-uploads, revocations, fetches from a cursor behind the head | families `purges`, `snapshots`, `restore`, `revocation`, `faults`, `faulty` ([`faults`]); named scenarios `T_A`/`T_B`, `S_L`, the oversize item, the lost answer across a restore and the merge spike's faulty cases |
//! | ADR 0021 §8 not reached | stale-epoch answers and re-issued ops (no key rotation is modelled), kind-4 authors, two or more faulty devices (beyond the f + 1 bound of two-author covers) |
//! | properties 1, 2, 3, 4, 6, 7; ADR 0021 §8 server properties 1–5 | [`world`] module docs; [`checker`] |
//! | budget: a fixed number of cases per property on every PR, 100 times more nightly; failures print their seed; fixed seeds become regression tests | [`generate`] |
//!
//! # Crypto
//!
//! `rizzy-core` builds a device signing key and seals an envelope only with an injected
//! `rand_core` 0.10 `CryptoRng`, whose traits it re-exports only as `CryptoRng` (not the
//! `TryRng`/`TryCryptoRng` traits an implementation needs), and its seeded test RNG is
//! crate-private. `rizzy-sync` depends on no RNG crate, and adding one is out of this change's
//! scope (and the owner's call: a public seeded `CryptoRng` behind a `rizzy-core` test
//! feature, or `rand_core` as a `rizzy-sync` dev-dependency), so records are **not** encrypted
//! or signed here. Signature verification, the AAD binding of the item VV and item id
//! (ADR 0018 owner decision 3) and property 6's decryption half are therefore untested by this
//! harness. What the harness does run of `rizzy-core`'s verification path: every op and
//! snapshot travels as its
//! [`OpStatement`](rizzy_core::sign::OpStatement) or
//! [`SnapshotStatement`](rizzy_core::sign::SnapshotStatement), the exact bytes a signature
//! covers (canonical header, `SHA-256` of the envelope), with the record's `data` standing in
//! for the envelope; the server and the clients check the envelope hash and parse the header
//! from the statement ([`crate::header::OpHeader::parse_statement`]). Property 6 as ADR 0012
//! §12 words it ("cannot decrypt anything written after the rotation") needs rotation and real
//! envelopes and is not tested; its sync-engine half (cut-offs) is.
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

use rizzy_core::ids::{DeviceId, ItemId, SymmetricKeyId, VaultId};

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

/// The one item key of `item`: every op of the item is under it (no rotation is modelled).
fn item_key(item: ItemId) -> SymmetricKeyId {
    SymmetricKeyId::from_bytes(item.to_bytes())
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
