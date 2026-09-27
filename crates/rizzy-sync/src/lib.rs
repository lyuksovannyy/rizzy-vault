//! `rizzy-sync` — the sync engine of rizzy-vault's Server mode (roadmap M1, [ADR 0012]).
//!
//! ADR 0012 is binding as partially superseded by ADR 0018 (item-record encoding), ADR 0021
//! (server compaction) and ADR 0022 (Server mode only). Server mode is the only sync mode: the
//! server stores and forwards signed, encrypted op records and per-item snapshots, keeps every
//! signed op header for the life of the vault, and deletes op bodies only behind
//! client-signed snapshots; only clients merge. On-device mode, with its relay, ack sets, TTL,
//! stale devices and peer re-sync, is parked (ADR 0022), and nothing here models it.
//!
//! # Plaintext audit scope
//!
//! Everything the server uses from this crate (header, version-vector and cursor types, the
//! compaction rules) is ciphertext metadata only. The field merge, however, receives decrypted
//! field writes from `rizzy-client` as opaque bytes in zeroizing types, so this crate is in the
//! plaintext audit scope (ADR 0012 §13, owner decision 6). The merge stores and compares field
//! keys and values and never interprets them; the record layer reads no value byte other than
//! `@lifecycle`, and keys and values never appear in logs, errors or `Debug` output (ADR 0018
//! §2). Encryption, signatures and the item schema stay in `rizzy-core`.
//!
//! # Contract
//!
//! - **No I/O** ([ADR 0016] R1, threat model INV-58): no filesystem, network, clock,
//!   environment, process, thread or randomness source. Time is injected (the HLC rules take
//!   `now_ms`). `cargo check-wasm` builds the crate for `wasm32-unknown-unknown`, and its
//!   `clippy.toml` carries the R1 disallowed-types and disallowed-methods lists.
//!   `cargo xtask check-deps` keeps `rizzy-core` its only internal dependency, bars a direct
//!   dependency on `rand` or getrandom, keeps getrandom out of its normal and build dependency
//!   closure, and limits that closure to allow-listed external crates: its own list is empty,
//!   so it may reach only what `rizzy-core`'s list allows, `zeroize` for one ([ADR 0016]
//!   R1–R2, §3).
//! - **No `unsafe`** (workspace lint and `#![forbid(unsafe_code)]` below).
//! - **Errors, never panics.** Fallible functions return a typed error and document it; the
//!   workspace lints warn on `unwrap`, `expect` and `panic!`, this crate adds
//!   `clippy::indexing_slicing` and `clippy::unreachable`, and `cargo lint` makes every warning
//!   an error.
//! - **Untrusted input is bounded.** Decoders read through `rizzy-core`'s bounded
//!   [`Reader`](rizzy_core::encoding::Reader), check a count against the remaining input before
//!   reading what it counts, never panic, and leave the reader untouched on error. The fuzz
//!   targets `sync_types` (the core types), `sync_header` (the op and snapshot headers),
//!   `record_op`, `record_snapshot`, `record_tombstone` and `record_key` (the item record and
//!   its key grammar) and `sync_compaction` (the compaction rules on a client's covered VV and
//!   on damaged rows) cover them.
//! - **Canonical bytes.** Every encoding here has exactly one valid byte string per value:
//!   the fixed big-endian layouts of CRYPTO.md §2, never serde.
//!
//! # Module map
//!
//! The core types every later module builds on:
//!
//! | Module | Spec | Purpose | Key invariants |
//! |---|---|---|---|
//! | [`hlc`] | ADR 0012 §2 "HLC", "Skew guard"; CRYPTO.md §10.2 rule (c); ADR 0018 §9 | [`Hlc`](hlc::Hlc): the `u64` hybrid logical clock, its encoding, its milliseconds reading, and the local-event and receive rules as pure functions of the injected wall clock | Orders history and breaks ties, never decides causality; a received HLC more than 24 h ahead is not adopted; the clock never wraps |
//! | [`dot`] | ADR 0012 §2 "Dot"; ADR 0018 §3 `dot`, §4 "Order" | [`Dot`](dot::Dot): `(device_id, device_seq)`, the identity of an op and of every value it wrote | `seq` ≥ 1, refused at construction and decoding; ordered by `device_id` bytewise, then `seq` |
//! | [`vv`] | ADR 0012 §2 "Per-item version vector", "Causal context", §3 "Canonical VV encoding"; ADR 0021 §2 | [`VersionVector`](vv::VersionVector) and [`CausalContext`](vv::CausalContext): coverage, join, meet, entrywise comparison, the canonical encoding | No zero entry is stored; one encoding per vector, entries strictly ascending by `device_id` with `seq` ≥ 1, at most 65,535 |
//! | [`error`] | ADR 0018 §2 (error form) | [`DecodeError`](error::DecodeError) and [`EncodeError`](error::EncodeError) of those encodings | An error carries only a kind and a byte offset |
//!
//! The formats and rules built on them:
//!
//! | Module | Spec | Purpose | Key invariants |
//! |---|---|---|---|
//! | [`header`] | ADR 0012 §3; CRYPTO.md §8.4, §10.2; ADR 0018 §11 | [`OpHeader`](header::OpHeader) and [`SnapshotHeader`](header::SnapshotHeader): the canonical headers the `op` and `snapshot` statements sign, their strict parsing, and the `ITEM_OP` and `ITEM_SNAPSHOT` AAD contexts built from the same bytes | `header_version` 1, `device_seq` ≥ 1, `item_schema_version` neither 0 nor `0xFFFF`, canonical version vectors, no trailing bytes; parsed before any field of a verified statement is trusted |
//! | [`record`] | ADR 0018 §2–§5, §7, §10; CRYPTO.md §8.5, §9.5 rule 5 | [`OpData`](record::OpData) and [`SnapshotData`](record::SnapshotData) (live snapshot or tombstone): the `ITEM_OP` and `ITEM_SNAPSHOT` `data` of `item_schema_version` 1, their strict parsers, writers and the §4 state-hash input | Exactly the eight §5 rejection rules and nothing else; the §10 limits; keys and values borrowed from the decrypted buffer, redacted in `Debug`, never in errors |
//! | [`compaction`] | ADR 0021 §2–§4, §7, §9 "Server acceptance" and "Revoked and kind-4 authors" | Pure functions over one item's retained snapshots (store sequence, clamped VV, author) and op dots with a body flag: the clamped VV, R1's body deletions and R3's snapshot drops, the covers of a Fetch response, and the snapshot and healing-request acceptance checks | A body is deleted only when the older of the two newest snapshots covers it and snapshots by two authors do; dropping a snapshot never leaves a bodiless header without a cover, nor lowers its covering authors below two; a response serves each bodiless header with covers by up to two authors, or reports it uncovered |
//!
//! The rest of ADR 0012 §13's list builds on these: causal delivery, deduplication and the
//! chain check (ADR 0012 §4, §7), and the multi-value-register merge with history, tombstones
//! and snapshot absorption (ADR 0012 §4–§5, ADR 0018 §3).
//!
//! # Invariants the engine keeps (threat model INV-23 to INV-27)
//!
//! Merge is idempotent and order-independent; conflicting edits become history instead of
//! being dropped; a client never accepts a state that goes backwards; the server compacts only
//! behind snapshots that clients made and signed; each device's sequence is gap-free. The HLC
//! orders history and breaks ties, but never decides causality; the version vectors do.
//!
//! # Tests
//!
//! Each module carries known-answer tests of its encoding and property tests (proptest) of its
//! algebra: the HLC rules against the textbook rules, the join and meet lattice laws,
//! encode → parse identity, and rejection of every non-canonical encoding. The engine as a
//! whole is a pure state machine, so ADR 0012 §12 tests it inside one process: 3 to 7
//! simulated devices, a simulated server, a seeded scheduler and real `rizzy-core` crypto,
//! with properties for convergence, no silent loss, idempotence, monotonicity, revocation and
//! gap detection.
//!
//! [ADR 0012]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0012-sync-engine.md
//! [ADR 0016]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0016-workspace-layout.md

// Also set by the workspace lint table (ADR 0016 R7); repeated here so that no manifest edit
// alone admits `unsafe` in this crate.
#![forbid(unsafe_code)]
#![warn(clippy::indexing_slicing, clippy::unreachable)]
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

pub mod compaction;
mod cursor;
pub mod dot;
pub mod error;
pub mod header;
pub mod hlc;
pub mod record;
pub mod vv;
