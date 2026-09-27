//! Fuzzes the strict parsers of the canonical op and snapshot headers (ADR 0012 §3), which
//! read the header bytes of every `op` and `snapshot` statement the server stores and every
//! client fetches. They run before any field of a verified statement is trusted, so they must
//! never panic, never allocate in proportion to a count, and accept only canonical bytes.
//!
//! What runs on each input:
//!
//! - [`OpHeader::parse`] and [`SnapshotHeader::parse`] on the whole input. When one accepts,
//!   re-encoding must give back exactly the input and its [`encoded_len`](OpHeader::encoded_len):
//!   one encoding per header. The parsed header must hold what the layout promises:
//!   `device_seq` ≥ 1 and an `item_schema_version` neither 0 nor `0xFFFF`.
//! - The accepted bytes wrapped in `rizzy-core`'s [`OpStatement`] or [`SnapshotStatement`], the
//!   way a verifier receives them: the statement takes them (its length bounds hold for every
//!   header this module accepts), [`OpHeader::parse_statement`] gives back the same header, and
//!   the `ITEM_OP` or `ITEM_SNAPSHOT` AAD context built from the header binds the hash of
//!   exactly the signed bytes (CRYPTO.md §8.4).
//!
//! Not in the CRYPTO.md §15 item 7 list by name (ADR 0012 §3 headers); CLAUDE.md requires a
//! target for every parser of untrusted input.
//!
//! ```text
//! cargo +nightly fuzz run sync_header
//! ```
#![no_main]

use libfuzzer_sys::fuzz_target;
use rizzy_core::envelope::purpose::{ItemOpCtx, ItemSnapshotCtx};
use rizzy_core::sign::{OpStatement, SnapshotStatement};
use rizzy_sync::header::{OpHeader, SnapshotHeader};

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = OpHeader::parse(data) {
        assert_eq!(header.to_vec().as_deref(), Ok(data));
        assert_eq!(header.encoded_len(), data.len());
        assert!(header.dot.seq() >= 1);
        assert!(!matches!(header.item_schema_version.get(), 0 | 0xFFFF));
        let statement =
            OpStatement::new(data, b"envelope", None).expect("a canonical header fits the bounds");
        assert_eq!(OpHeader::parse_statement(&statement).as_ref(), Ok(&header));
        let ctx = header.envelope_context().expect("an accepted header encodes");
        assert_eq!(ctx.op_header_hash, ItemOpCtx::header_hash(data));
        assert_eq!(ctx.op_header_hash, statement.header_hash());
        assert_eq!(ctx.device_seq, header.dot.seq());
    }
    if let Ok(header) = SnapshotHeader::parse(data) {
        assert_eq!(header.to_vec().as_deref(), Ok(data));
        assert_eq!(header.encoded_len(), data.len());
        assert!(!matches!(header.item_schema_version.get(), 0 | 0xFFFF));
        let statement = SnapshotStatement::new(data, b"envelope", Some(b"wrap"))
            .expect("a canonical header fits the bounds");
        assert_eq!(SnapshotHeader::parse_statement(&statement).as_ref(), Ok(&header));
        let ctx = header.envelope_context().expect("an accepted header encodes");
        assert_eq!(ctx.snapshot_header_hash, ItemSnapshotCtx::header_hash(data));
        assert_eq!(ctx.snapshot_header_hash, statement.header_hash());
    }
});
