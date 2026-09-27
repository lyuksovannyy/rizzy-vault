//! `rizzy-sync` — the sync engine (Server mode, roadmap M1).
//!
//! Everything the server uses from this crate is ciphertext only. The field merge, however,
//! receives decrypted field writes from `rizzy-client` as opaque bytes in zeroizing types, so
//! this crate is in the plaintext audit scope (ADR 0012 section 13, owner decision 6).
//! Same portability contract as `rizzy-core`: no I/O, no `unsafe`, builds for
//! `wasm32-unknown-unknown`.
//!
//! # Status
//!
//! Skeleton: this crate has no items yet. ADR 0012 is accepted; code lands in M1 after the item
//! record ADR (ADR 0018, still Proposed), because the op and snapshot bodies carry field writes
//! and register values in that encoding (ADR 0012 §3). Until then nothing here merges, orders
//! or verifies anything. The manifest already declares `rizzy-core`, its one allowed internal
//! dependency (ADR 0016 §2), and nothing else.
//!
//! # Planned contents (ADR 0012 §13)
//!
//! - the op and snapshot record formats: one op is one save of one item, identified by its dot
//!   `(device_id, device_seq)`, with a hybrid logical clock and the item's causal context;
//! - hybrid logical clocks and per-item version vectors;
//! - causal delivery, deduplication and gap detection;
//! - cursor and ack arithmetic, and the compaction rules;
//! - the multi-value-register field merge, generic over field keys and values: it stores and
//!   compares them and never interprets them.
//!
//! Encryption, signatures and the item schema stay in `rizzy-core`; `rizzy-client` drives the
//! cycle (fetch, verify and decrypt through `rizzy-core`, apply here, persist ciphertext). Only
//! clients merge; the server uses the header, version-vector and cursor types for sequence
//! checks and compaction bookkeeping, and never decrypts.
//!
//! # Invariants the code must keep (threat model INV-23 to INV-27)
//!
//! Merge is idempotent and order-independent; conflicting edits become history instead of
//! being dropped; a client never accepts a state that goes backwards; the server compacts only
//! behind snapshots that clients made and signed; each device's sequence is gap-free. The HLC
//! orders history and breaks ties, but never decides causality; the version vectors do.
//!
//! # Boundaries and tests
//!
//! The crate is a no-I/O crate (ADR 0016 R1): time and randomness are injected,
//! `cargo check-wasm` builds it for wasm32, its `clippy.toml` carries the R1 disallowed-types
//! and disallowed-methods lists, and `cargo xtask check-deps` keeps its dependency closure free
//! of getrandom and limited to allow-listed external crates (its own list is empty, so it may
//! reach only what `rizzy-core`'s list allows).
//!
//! Because it is a pure state machine, ADR 0012 §12 tests it inside one process: 3 to 7
//! simulated devices, a simulated server, a seeded scheduler and real `rizzy-core` crypto, with
//! proptest properties for convergence, no silent loss, idempotence, monotonicity, revocation
//! and gap detection.

// Also set by the workspace lint table (ADR 0016 R7); repeated here so that no manifest edit
// alone admits `unsafe` in this crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]
