//! `rizzy-core`'s committed known-answer vectors (CRYPTO.md §15 item 1), read by this crate's
//! header parser.
//!
//! The tier A files `statements.json` and `envelopes.json` under
//! `crates/rizzy-core/tests/vectors/` carry canonical ADR 0012 §3 headers: the `op` and
//! `snapshot` statement vectors sign one, and the `ITEM_OP` and `ITEM_SNAPSHOT` envelope
//! vectors bind one in their AAD context. `rizzy-core` cannot depend on this crate (ADR 0016),
//! so its generator writes those headers by hand from the ADR text. These tests close the
//! loop from the other side, on the committed bytes:
//!
//! - every such header parses with [`OpHeader::parse`] or [`SnapshotHeader::parse`] and
//!   re-encodes to exactly the committed bytes;
//! - each statement vector's wire form verifies under the vector's signer key, and the
//!   verified statement gives back the same header ([`OpHeader::parse_statement`]) and matches
//!   the vector's envelope;
//! - each envelope vector's context is exactly what [`OpHeader::envelope_context`] or
//!   [`SnapshotHeader::envelope_context`] builds from the parsed header, and the committed
//!   envelope opens under that rebuilt context to the vector's plaintext.
//!
//! The counts are asserted, so a vector that loses its header, or a file that loses the
//! vectors, fails here instead of passing with nothing checked.

use rizzy_core::envelope::{Context as _, open};
use rizzy_core::secret::Key32;
use rizzy_core::sign::DeviceVerifyingKey;
use serde_json::Value;

use super::*;

/// The committed statement vectors.
const STATEMENTS: &str = include_str!("../../../rizzy-core/tests/vectors/statements.json");

/// The committed envelope vectors.
const ENVELOPES: &str = include_str!("../../../rizzy-core/tests/vectors/envelopes.json");

/// The vectors of `file` named `name`.
fn vectors(file: &str, name: &str) -> Vec<Value> {
    let doc: Value = serde_json::from_str(file).expect("a vector file is JSON");
    doc.get("vectors")
        .and_then(Value::as_array)
        .expect("a `vectors` array")
        .iter()
        .filter(|v| v.get("name").and_then(Value::as_str) == Some(name))
        .cloned()
        .collect()
}

/// The hex byte string at `v[group][key]` (the vector files write bytes as lowercase hex).
fn bytes(v: &Value, group: &str, key: &str) -> Vec<u8> {
    let text = v
        .get(group)
        .and_then(|g| g.get(key))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no hex string `{group}.{key}`"));
    let digits: Vec<u8> = text
        .bytes()
        .map(|b| match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => panic!("`{group}.{key}` is not lowercase hex"),
        })
        .collect();
    assert!(
        digits.len().is_multiple_of(2),
        "`{group}.{key}`: odd length"
    );
    digits
        .chunks_exact(2)
        .map(|pair| pair.iter().fold(0, |byte, digit| (byte << 4) | digit))
        .collect()
}

/// The verifying key of the device that signed statement vector `v`.
fn signer(v: &Value) -> DeviceVerifyingKey {
    let key: [u8; 32] = bytes(v, "outputs", "signer_public_key")
        .try_into()
        .expect("a 32-byte public key");
    DeviceVerifyingKey::from_bytes(&key).expect("an Ed25519 public key")
}

/// The vector's raw 32-byte wrapping key.
fn key(v: &Value) -> Key32 {
    Key32::from_slice(&bytes(v, "inputs", "key")).expect("a 32-byte key")
}

#[test]
fn op_statement_vectors_sign_canonical_op_headers() {
    let ops = vectors(STATEMENTS, "op");
    assert_eq!(ops.len(), 2, "statement/op/0 and statement/op/1");
    let mut headers = Vec::new();
    for v in &ops {
        let canonical = bytes(v, "inputs", "canonical_header");
        let header = OpHeader::parse(&canonical).expect("a canonical op header");
        assert_eq!(
            header.to_vec().unwrap(),
            canonical,
            "re-encodes identically"
        );
        assert_eq!(header.encoded_len(), canonical.len());

        let verified = OpStatement::verify(&bytes(v, "outputs", "wire"), &signer(v))
            .expect("the vector's signature verifies");
        assert_eq!(verified.header(), canonical);
        assert_eq!(OpHeader::parse_statement(&verified), Ok(header.clone()));
        assert!(verified.matches_envelope(&bytes(v, "inputs", "envelope")));
        // The AAD context binds the hash of exactly the signed header bytes.
        assert_eq!(
            header.envelope_context().unwrap().op_header_hash,
            verified.header_hash()
        );
        headers.push(header);
    }
    // The story the generator tells (`rizzy-core`, `test_vectors::statements`): a create, then
    // an edit of the same item whose context names two devices and covers the create.
    let [create, edit] = headers.as_slice() else {
        panic!("two op headers");
    };
    assert!(create.causal_context.is_empty());
    assert_eq!(create.item_schema_version, ItemSchemaVersion::V1);
    assert_eq!((create.dot.seq(), create.vault_prev_seq), (41, 40));
    assert_eq!(
        (edit.vault_id, edit.item_id),
        (create.vault_id, create.item_id)
    );
    assert_eq!(edit.dot.device_id(), create.dot.device_id());
    assert_eq!((edit.dot.seq(), edit.vault_prev_seq), (43, 41));
    assert_eq!(edit.causal_context.len(), 2);
    assert!(edit.causal_context.covers(create.dot));
    assert!(edit.hlc > create.hlc);
}

#[test]
fn snapshot_statement_vectors_sign_canonical_snapshot_headers() {
    let snapshots = vectors(STATEMENTS, "snapshot");
    assert_eq!(snapshots.len(), 1, "statement/snapshot/0");
    let create = OpHeader::parse(&bytes(
        vectors(STATEMENTS, "op").first().expect("statement/op/0"),
        "inputs",
        "canonical_header",
    ))
    .expect("a canonical op header");
    for v in &snapshots {
        let canonical = bytes(v, "inputs", "canonical_header");
        let header = SnapshotHeader::parse(&canonical).expect("a canonical snapshot header");
        assert_eq!(
            header.to_vec().unwrap(),
            canonical,
            "re-encodes identically"
        );
        assert_eq!(header.encoded_len(), canonical.len());

        let verified = SnapshotStatement::verify(&bytes(v, "outputs", "wire"), &signer(v))
            .expect("the vector's signature verifies");
        assert_eq!(verified.header(), canonical);
        assert_eq!(
            SnapshotHeader::parse_statement(&verified),
            Ok(header.clone())
        );
        assert!(verified.matches_envelope(&bytes(v, "inputs", "envelope")));
        assert_eq!(
            header.envelope_context().unwrap().snapshot_header_hash,
            verified.header_hash()
        );
        // The snapshot is of the item `statement/op/0` creates, by the same device, and
        // covers that op.
        assert_eq!(
            (header.vault_id, header.item_id, header.author),
            (create.vault_id, create.item_id, create.dot.device_id())
        );
        assert!(header.covered.covers(create.dot));
    }
}

#[test]
fn item_op_envelope_vectors_bind_canonical_op_headers() {
    let ops = vectors(ENVELOPES, "ITEM_OP");
    assert_eq!(ops.len(), 2, "envelope/ITEM_OP/0 and envelope/ITEM_OP/1");
    let mut contexts = Vec::new();
    for v in &ops {
        let canonical = bytes(v, "inputs", "canonical_header");
        let header = OpHeader::parse(&canonical).expect("a canonical op header");
        assert_eq!(
            header.to_vec().unwrap(),
            canonical,
            "re-encodes identically"
        );

        // The context this crate builds from the header is the vector's, byte for byte, and
        // the committed envelope opens under it.
        let ctx = header.envelope_context().unwrap();
        assert_eq!(ctx.ctx_bytes(), bytes(v, "outputs", "ctx"));
        let opened =
            open(&key(v), &ctx, &bytes(v, "outputs", "envelope")).expect("the envelope opens");
        assert_eq!(opened.expose_secret(), bytes(v, "inputs", "plaintext"));
        contexts.push(header.causal_context.len());
    }
    // One header without a causal context and one with several entries.
    assert_eq!(contexts, [0, 2]);
}

#[test]
fn item_snapshot_envelope_vectors_bind_canonical_snapshot_headers() {
    let snapshots = vectors(ENVELOPES, "ITEM_SNAPSHOT");
    assert_eq!(
        snapshots.len(),
        2,
        "envelope/ITEM_SNAPSHOT/0 and envelope/ITEM_SNAPSHOT/1"
    );
    let mut covered = Vec::new();
    for v in &snapshots {
        let canonical = bytes(v, "inputs", "canonical_header");
        let header = SnapshotHeader::parse(&canonical).expect("a canonical snapshot header");
        assert_eq!(
            header.to_vec().unwrap(),
            canonical,
            "re-encodes identically"
        );

        let ctx = header.envelope_context().unwrap();
        assert_eq!(ctx.ctx_bytes(), bytes(v, "outputs", "ctx"));
        let opened =
            open(&key(v), &ctx, &bytes(v, "outputs", "envelope")).expect("the envelope opens");
        assert_eq!(opened.expose_secret(), bytes(v, "inputs", "plaintext"));
        // The author's own ops are in the covered VV.
        assert!(header.covered.get(header.author) >= 1);
        covered.push(header.covered.len());
    }
    assert_eq!(covered, [1, 2]);
}

/// A header of the wrong kind never parses as the other: an op header is not a snapshot
/// header and the reverse, for every header the vector files carry.
#[test]
fn vector_headers_do_not_parse_as_the_other_kind() {
    for v in vectors(STATEMENTS, "op")
        .iter()
        .chain(&vectors(ENVELOPES, "ITEM_OP"))
    {
        let canonical = bytes(v, "inputs", "canonical_header");
        assert!(SnapshotHeader::parse(&canonical).is_err());
    }
    for v in vectors(STATEMENTS, "snapshot")
        .iter()
        .chain(&vectors(ENVELOPES, "ITEM_SNAPSHOT"))
    {
        let canonical = bytes(v, "inputs", "canonical_header");
        assert!(OpHeader::parse(&canonical).is_err());
    }
}
