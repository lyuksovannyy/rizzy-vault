//! Verifying one uploaded op or snapshot record before anything about it is trusted (ADR 0012
//! §3, §7 "Upload"; CRYPTO.md §10.2). Pure: no I/O, no clock.
//!
//! **Steps, for an op** (a snapshot is the same with its own statement and header):
//! 1. The signature container is the statement's last 82 bytes; `rizzy-core` parses it
//!    ([`SignatureContainer::from_bytes`]) only to read the signer key id, which picks the
//!    author's certificate among the account's ([`Authors::by_key_id`]). No certificate: refused.
//! 2. `rizzy-core` verifies the whole statement with `verify_strict` under that certificate's
//!    key ([`OpStatement::verify`]).
//! 3. `rizzy-sync` parses the signed header strictly ([`OpHeader::parse_statement`]). The
//!    header must name the certificate's device and the request's vault.
//! 4. A carried body must match the signed body hash, and a carried key wrap the signed wrap
//!    hash, before either is stored (ADR 0012 §3: "the receiver checks it against the signed hash
//!    before anything else").
//! 5. Every integer the server stores in an SQL column must be at most `i64::MAX`
//!    (`rizzy_storage::convert`); a forged value above it is refused here.
//! 6. The statement is rebuilt from the parts the server stores ([`Signed::wire`]) and must
//!    equal the uploaded bytes, so what the server serves later is exactly what was signed.
//!
//! **No new parser.** Every byte string of a record is read by a fuzzed parser of `rizzy-core`
//! (`signed_statements`) or `rizzy-sync` (`sync_header`); this module only slices the last
//! 82 bytes off a bounded buffer with checked arithmetic, and compares.
//!
//! The rules that need the database (the chain, "Already stored", stale epoch, heads) and the
//! author's revocation state are the caller's.

use rizzy_core::encoding::{put_bytes, put_u16};
use rizzy_core::error::EncodeError;
use rizzy_core::ids::VaultId;
use rizzy_core::sign::{
    CONTAINER_LEN, OpStatement, STATEMENT_VERSION, SignatureContainer, SnapshotStatement,
};
use rizzy_proto::vault::{OpRecord, RecordKeyWrap, SnapshotRecord};
use rizzy_sync::header::{OpHeader, SnapshotHeader};

use crate::authors::{AuthorCertificate, Authors};

/// Length of a SHA-256 value.
pub(crate) const HASH_LEN: usize = 32;

/// The signed parts of an op or snapshot statement, as the server stores them: the canonical
/// header, the two signed hashes (32 zero bytes for "no wrap") and the one signature container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Signed {
    /// The canonical header bytes, as signed.
    pub(crate) header: Vec<u8>,
    /// The signed SHA-256 of the body envelope (op) or snapshot envelope.
    pub(crate) envelope_hash: [u8; HASH_LEN],
    /// The signed SHA-256 of the carried `ITEM_KEY_WRAP`, or 32 zero bytes.
    pub(crate) wrap_hash: [u8; HASH_LEN],
    /// The 82-byte signature container.
    pub(crate) container: [u8; CONTAINER_LEN],
}

impl Signed {
    /// The statement's wire form (CRYPTO.md §9.6):
    /// `bytes(u16(statement_version) ‖ bytes(header) ‖ envelope_hash ‖ wrap_hash) ‖ container`,
    /// the layout `rizzy-core` signs and verifies for `op` and `snapshot` (§10.2).
    ///
    /// # Errors
    /// [`EncodeError::TooLong`] if a length does not fit its `u32` prefix, which a header the
    /// parser accepted never reaches.
    pub(crate) fn wire(&self) -> Result<Vec<u8>, EncodeError> {
        let mut versioned = Vec::with_capacity(2 + 4 + self.header.len() + 2 * HASH_LEN);
        put_u16(&mut versioned, STATEMENT_VERSION);
        put_bytes(&mut versioned, &self.header)?;
        versioned.extend_from_slice(&self.envelope_hash);
        versioned.extend_from_slice(&self.wrap_hash);
        let mut out = Vec::with_capacity(4 + versioned.len() + CONTAINER_LEN);
        put_bytes(&mut out, &versioned)?;
        out.extend_from_slice(&self.container);
        Ok(out)
    }
}

/// Why a record was refused before any database rule ran. Every variant answers
/// `invalid_request`; the variants exist for the tests and never leave the process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IntakeError {
    /// No certificate of the account has the container's signer key, or the container is not
    /// one well-formed 82-byte container.
    UnknownSigner,
    /// The statement does not verify, or its header does not parse.
    BadStatement,
    /// The header names another device than the certificate, or another vault than the request.
    WrongOwner,
    /// A carried envelope or wrap does not match its signed hash, or a required one is missing.
    BadAttachment,
    /// An integer field is above `i64::MAX`.
    OutOfRange,
}

/// A carried `ITEM_KEY_WRAP` with its item key id locator (CRYPTO.md §4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CarriedWrap {
    /// The wrapped item key's id, a locator the server never trusts.
    pub(crate) item_key_id: [u8; 16],
    /// The envelope, matching the signed wrap hash.
    pub(crate) envelope: Vec<u8>,
}

/// A verified op record.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedOp {
    /// The parsed signed header.
    pub(crate) header: OpHeader,
    /// The signed parts.
    pub(crate) signed: Signed,
    /// The body, matching the signed hash; `None` for a bodiless header.
    pub(crate) body: Option<Vec<u8>>,
    /// The carried wrap, matching the signed hash.
    pub(crate) key_wrap: Option<CarriedWrap>,
    /// The author's certificate.
    pub(crate) author: AuthorCertificate,
}

/// A verified snapshot record.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedSnapshot {
    /// The parsed signed header.
    pub(crate) header: SnapshotHeader,
    /// The signed parts.
    pub(crate) signed: Signed,
    /// The envelope, matching the signed hash.
    pub(crate) envelope: Vec<u8>,
    /// The carried wrap, matching the signed hash.
    pub(crate) key_wrap: Option<CarriedWrap>,
    /// The author's certificate.
    pub(crate) author: AuthorCertificate,
}

/// Whether a record's carried wrap is required when its statement signed one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WrapRule {
    /// A normal upload: a signed wrap must be carried, so the wrap set receives it
    /// (CRYPTO.md §4.2: "A wrap that arrives inside an op or snapshot record fills that row").
    Required,
    /// A healing request re-publishes records the server may have served without their wraps
    /// after a rotation (CRYPTO.md §4.2), so a signed wrap may be absent.
    Optional,
}

/// The container at the end of `wire` and the certificate its signer key names.
fn signer<'a>(
    wire: &[u8],
    authors: &'a Authors,
) -> Result<(&'a AuthorCertificate, [u8; CONTAINER_LEN]), IntakeError> {
    let tail = wire
        .len()
        .checked_sub(CONTAINER_LEN)
        .and_then(|at| wire.get(at..))
        .ok_or(IntakeError::UnknownSigner)?;
    let container = SignatureContainer::from_bytes(tail).map_err(|_| IntakeError::UnknownSigner)?;
    let author = authors
        .by_key_id(container.signer_key_id())
        .ok_or(IntakeError::UnknownSigner)?;
    Ok((author, container.to_bytes()))
}

/// Checks a carried wrap against the signed hash.
fn carried_wrap(
    wrap: Option<&RecordKeyWrap>,
    signed_wrap: bool,
    matches: impl Fn(&[u8]) -> bool,
    rule: WrapRule,
) -> Result<Option<CarriedWrap>, IntakeError> {
    match wrap {
        Some(w) if matches(w.envelope.as_slice()) => Ok(Some(CarriedWrap {
            item_key_id: w.item_key_id.to_bytes(),
            envelope: w.envelope.as_slice().to_vec(),
        })),
        Some(_) => Err(IntakeError::BadAttachment),
        None if signed_wrap && rule == WrapRule::Required => Err(IntakeError::BadAttachment),
        None => Ok(None),
    }
}

/// Refuses a `u64` the SQL columns cannot hold.
fn fits_sql(values: &[u64]) -> Result<(), IntakeError> {
    if values.iter().all(|&v| i64::try_from(v).is_ok()) {
        Ok(())
    } else {
        Err(IntakeError::OutOfRange)
    }
}

/// Verifies one op record of `vault_id` against the account's certificates (module docs).
/// `body_required` is false only inside a healing request, the one place a bodiless header may
/// be stored (ADR 0021 §9 "Server acceptance").
pub(crate) fn verify_op(
    record: &OpRecord,
    vault_id: VaultId,
    authors: &Authors,
    body_required: bool,
    wrap_rule: WrapRule,
) -> Result<VerifiedOp, IntakeError> {
    let wire = record.statement.as_slice();
    let (author, container) = signer(wire, authors)?;
    let verified =
        OpStatement::verify(wire, &author.verifying_key).map_err(|_| IntakeError::BadStatement)?;
    let header = OpHeader::parse_statement(&verified).map_err(|_| IntakeError::BadStatement)?;
    if header.dot.device_id() != author.device_id {
        return Err(IntakeError::WrongOwner);
    }
    if header.vault_id != vault_id {
        return Err(IntakeError::WrongOwner);
    }
    fits_sql(&[header.dot.seq(), header.vault_prev_seq, header.hlc.to_u64()])?;
    let body = match &record.body {
        Some(body) if verified.matches_envelope(body.as_slice()) => Some(body.as_slice().to_vec()),
        Some(_) => return Err(IntakeError::BadAttachment),
        None if body_required => return Err(IntakeError::BadAttachment),
        None => None,
    };
    let key_wrap = carried_wrap(
        record.key_wrap.as_ref(),
        verified.wrap_hash().is_some(),
        |w| verified.matches_wrap(w),
        wrap_rule,
    )?;
    let signed = Signed {
        header: verified.header().to_vec(),
        envelope_hash: *verified.envelope_hash(),
        wrap_hash: verified.wrap_hash().copied().unwrap_or([0u8; HASH_LEN]),
        container,
    };
    if signed.wire().map_err(|_| IntakeError::BadStatement)? != wire {
        return Err(IntakeError::BadStatement);
    }
    Ok(VerifiedOp {
        header,
        signed,
        body,
        key_wrap,
        author: author.clone(),
    })
}

/// Verifies one snapshot record of `vault_id` against the account's certificates (module
/// docs). A snapshot always carries its envelope.
pub(crate) fn verify_snapshot(
    record: &SnapshotRecord,
    vault_id: VaultId,
    authors: &Authors,
    wrap_rule: WrapRule,
) -> Result<VerifiedSnapshot, IntakeError> {
    let wire = record.statement.as_slice();
    let (author, container) = signer(wire, authors)?;
    let verified = SnapshotStatement::verify(wire, &author.verifying_key)
        .map_err(|_| IntakeError::BadStatement)?;
    let header =
        SnapshotHeader::parse_statement(&verified).map_err(|_| IntakeError::BadStatement)?;
    if header.author != author.device_id {
        return Err(IntakeError::WrongOwner);
    }
    if header.vault_id != vault_id {
        return Err(IntakeError::WrongOwner);
    }
    if !verified.matches_envelope(record.envelope.as_slice()) {
        return Err(IntakeError::BadAttachment);
    }
    let key_wrap = carried_wrap(
        record.key_wrap.as_ref(),
        verified.wrap_hash().is_some(),
        |w| verified.matches_wrap(w),
        wrap_rule,
    )?;
    let signed = Signed {
        header: verified.header().to_vec(),
        envelope_hash: *verified.envelope_hash(),
        wrap_hash: verified.wrap_hash().copied().unwrap_or([0u8; HASH_LEN]),
        container,
    };
    if signed.wire().map_err(|_| IntakeError::BadStatement)? != wire {
        return Err(IntakeError::BadStatement);
    }
    Ok(VerifiedSnapshot {
        header,
        signed,
        envelope: record.envelope.as_slice().to_vec(),
        key_wrap,
        author: author.clone(),
    })
}

/// SHA-256 of a snapshot envelope, which `vault_snapshots` does not store: computed through
/// `rizzy-core`'s statement constructor, the one place that hashes it for signing.
///
/// # Errors
/// [`EncodeError`] if `header` is outside the snapshot-header length bounds (a damaged row).
pub(crate) fn snapshot_envelope_hash(
    header: &[u8],
    envelope: &[u8],
) -> Result<[u8; HASH_LEN], EncodeError> {
    Ok(*SnapshotStatement::new(header, envelope, None)?.envelope_hash())
}
