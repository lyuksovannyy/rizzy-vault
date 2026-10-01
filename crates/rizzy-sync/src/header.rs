//! The canonical op and snapshot headers (ADR 0012 §3), the bytes the `op` and `snapshot`
//! statements sign (CRYPTO.md §10.2).
//!
//! # Layouts
//!
//! ```text
//! op header        u8 header_version = 1 ‖ vault_id ‖ item_id ‖ op_id ‖ device_id ‖
//!                  u64 device_seq ‖ u64 vault_prev_seq ‖ u64 hlc ‖ u16 item_schema_version ‖
//!                  u32 vault_key_epoch ‖ causal context (u16 n ‖ n × (device_id ‖ u64 seq))
//!
//! snapshot header  u8 header_version = 1 ‖ vault_id ‖ item_id ‖ snapshot_id ‖
//!                  author device_id ‖ u16 item_schema_version ‖ u32 vault_key_epoch ‖
//!                  covered VV (u16 n ‖ n × (device_id ‖ u64 seq))
//! ```
//!
//! Ids are 16 bytes (CRYPTO.md §2). `device_id ‖ u64 device_seq` is the op's [`Dot`]
//! (ADR 0012 §2), and both version vectors use the canonical VV encoding of
//! [`vv`](crate::vv). The fixed parts are 97 and 73 bytes, the minimum lengths `rizzy-core`'s
//! [`OpStatement`] and [`SnapshotStatement`] accept
//! ([`OP_HEADER_MIN_LEN`](rizzy_core::sign::statements::OP_HEADER_MIN_LEN),
//! [`SNAPSHOT_HEADER_MIN_LEN`](rizzy_core::sign::statements::SNAPSHOT_HEADER_MIN_LEN)); with at
//! most 65,535 entries a header never exceeds their maximum.
//!
//! # Where the bytes go
//!
//! `rizzy-core` takes each header as an opaque byte string: the `op` statement signs
//! `bytes(canonical op header) ‖ SHA-256(op envelope) ‖ SHA-256(wrap or 32 zero bytes)`, the
//! `snapshot` statement the same over the snapshot header (CRYPTO.md §10.2), and the
//! `ITEM_OP` and `ITEM_SNAPSHOT` AAD contexts end with `SHA-256(canonical header)`
//! (CRYPTO.md §8.4). This module owns the layout (ADR 0012 §13): [`OpHeader::to_vec`] makes
//! the bytes a writer signs, [`OpHeader::parse_statement`] reads them back out of a verified
//! statement, and [`OpHeader::envelope_context`] builds the AAD context from the same bytes,
//! so the header the signature covers and the header the envelope binds cannot differ. The
//! snapshot header has the same three.
//!
//! # Strict parsing
//!
//! A verified statement proves only that its signer signed these bytes. Before any field is
//! trusted (to pick the certificate the header names, to run the chain check, to decrypt),
//! the bytes are parsed strictly, and every other byte string is rejected:
//!
//! - `header_version` is 1 (the only version ADR 0012 §3 defines);
//! - `device_seq` is at least 1, since a device's sequence starts at 1 (ADR 0012 §2), so the
//!   op's dot is a [`Dot`];
//! - `item_schema_version` is neither 0 nor `0xFFFF`, which ADR 0018 §11 rejects. Any other
//!   value parses: a client parks a record of a version it does not know rather than
//!   rejecting it (ADR 0018 §11 "Reader rule"), and needs its header to do so;
//! - the version vector is canonical: entries strictly ascending by `device_id`, every `seq`
//!   ≥ 1 (ADR 0012 §3);
//! - nothing follows the last field.
//!
//! Relations between fields and with other records (`vault_prev_seq` against the device's
//! chain, the context against the item VV, the covered VV against the held headers) are not
//! layout rules: the chain check, causal delivery and snapshot absorption decide them
//! (ADR 0012 §4, §7; ADR 0018 §3).
//!
//! Every header field is server-visible metadata (ADR 0012 §11 as replaced by ADR 0022 §2), so
//! the types here derive `Debug`, and a [`HeaderError`] names a byte offset and a kind.

use core::fmt;

use rizzy_core::encoding::{put_u8, put_u16, put_u32, put_u64};
use rizzy_core::envelope::purpose::{ItemOpCtx, ItemSnapshotCtx};
use rizzy_core::ids::{DeviceId, ID_LEN, ItemId, OpId, SnapshotId, VaultId};
use rizzy_core::sign::{OpStatement, SnapshotStatement};

use crate::cursor::Cursor;
use crate::dot::Dot;
use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::hlc::Hlc;
use crate::vv::{CausalContext, VersionVector};

/// `header_version` of both headers (ADR 0012 §3). No other version exists.
pub const HEADER_VERSION: u8 = 1;

/// Length of an op header with an empty causal context (ADR 0012 §3): 97 bytes.
pub const OP_HEADER_FIXED_LEN: usize = 1 + 4 * ID_LEN + 8 + 8 + 8 + 2 + 4 + 2;

/// Length of a snapshot header with an empty covered VV (ADR 0012 §3): 73 bytes.
pub const SNAPSHOT_HEADER_FIXED_LEN: usize = 1 + 4 * ID_LEN + 2 + 4 + 2;

/// An `item_schema_version` (ADR 0018 §11): the version of the item-record encoding, in both
/// headers and in the `ITEM_OP` and `ITEM_SNAPSHOT` AAD (CRYPTO.md §8.4).
///
/// 0 is invalid and `0xFFFF` reserved; both are rejected, so this type never holds them.
/// 1 is the M1 model ([`ItemSchemaVersion::V1`]), the only one the [`record`](crate::record)
/// parser reads. 2–`0xFFFE` are unassigned: a client keeps such a record unapplied ("parked",
/// ADR 0018 §11) until it is updated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ItemSchemaVersion(u16);

impl ItemSchemaVersion {
    /// The M1 item model, ADR 0018.
    pub const V1: Self = Self(1);

    /// The version `value`; `None` for 0 and `0xFFFF`, which ADR 0018 §11 rejects.
    #[must_use]
    pub const fn new(value: u16) -> Option<Self> {
        match value {
            0 | 0xFFFF => None,
            v => Some(Self(v)),
        }
    }

    /// The `u16` value.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Whether this build's record layer reads the version: only [`ItemSchemaVersion::V1`].
    /// A record of any other version is parked, neither applied nor dropped (ADR 0018 §11).
    #[must_use]
    pub const fn is_known(self) -> bool {
        self.0 == Self::V1.0
    }
}

/// Why a header was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HeaderErrorKind {
    /// The input ended before a field was complete, or a count claims more entries than the
    /// remaining input holds.
    Truncated,
    /// Bytes remained after the last field.
    TrailingBytes,
    /// `header_version` is not 1.
    UnknownHeaderVersion,
    /// `device_seq` or a version-vector `seq` is 0.
    ZeroSeq,
    /// Version-vector entries are not strictly ascending by `device_id`.
    NotAscending,
    /// `item_schema_version` is 0 or `0xFFFF` (ADR 0018 §11).
    InvalidSchemaVersion,
}

impl fmt::Display for HeaderErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "header truncated",
            Self::TrailingBytes => "trailing bytes after the header",
            Self::UnknownHeaderVersion => "unknown header version",
            Self::ZeroSeq => "sequence number 0",
            Self::NotAscending => "version-vector entries not strictly ascending",
            Self::InvalidSchemaVersion => "invalid item schema version",
        })
    }
}

/// A rejected header: the kind of failure and the offset of the field that failed, from the
/// first header byte. Kinds and offsets are local diagnostics, not format (see
/// [`crate::error`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HeaderError {
    /// What was wrong.
    kind: HeaderErrorKind,
    /// Where the failing field starts.
    offset: usize,
}

impl HeaderError {
    /// An error of `kind` at `offset`.
    const fn new(kind: HeaderErrorKind, offset: usize) -> Self {
        Self { kind, offset }
    }

    /// What was wrong.
    #[must_use]
    pub const fn kind(&self) -> HeaderErrorKind {
        self.kind
    }

    /// The byte offset of the failing field.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }
}

impl From<DecodeError> for HeaderError {
    /// The same failure, as a header error.
    fn from(e: DecodeError) -> Self {
        let kind = match e.kind() {
            DecodeErrorKind::Truncated => HeaderErrorKind::Truncated,
            DecodeErrorKind::TrailingBytes => HeaderErrorKind::TrailingBytes,
            DecodeErrorKind::ZeroSeq => HeaderErrorKind::ZeroSeq,
            DecodeErrorKind::NotAscending => HeaderErrorKind::NotAscending,
        };
        Self::new(kind, e.offset())
    }
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.kind, self.offset)
    }
}

impl core::error::Error for HeaderError {}

/// Reads `header_version` and checks that it is [`HEADER_VERSION`].
fn read_version(c: &mut Cursor<'_>) -> Result<(), HeaderError> {
    if c.u8()? == HEADER_VERSION {
        Ok(())
    } else {
        Err(HeaderError::new(HeaderErrorKind::UnknownHeaderVersion, 0))
    }
}

/// Reads a 16-byte id.
fn read_id(c: &mut Cursor<'_>) -> Result<[u8; ID_LEN], HeaderError> {
    Ok(*c.array::<ID_LEN>()?)
}

/// Reads `u16 item_schema_version` and refuses 0 and `0xFFFF`.
fn read_schema(c: &mut Cursor<'_>) -> Result<ItemSchemaVersion, HeaderError> {
    let at = c.offset();
    ItemSchemaVersion::new(c.u16()?)
        .ok_or(HeaderError::new(HeaderErrorKind::InvalidSchemaVersion, at))
}

/// The header of one op: one save of one item (ADR 0012 §3). The server sees it and keeps it,
/// signed, for the life of the vault (ADR 0012 §7).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OpHeader {
    /// The vault the op belongs to.
    pub vault_id: VaultId,
    /// The item the op saves.
    pub item_id: ItemId,
    /// The op's random 16-byte id.
    pub op_id: OpId,
    /// `(device_id, device_seq)`: the authoring device and its sequence number, the op's
    /// identity (ADR 0012 §2).
    pub dot: Dot,
    /// The same device's previous `device_seq` in this vault, or 0 for its first op there
    /// (ADR 0012 §2).
    pub vault_prev_seq: u64,
    /// The op's hybrid logical clock (ADR 0012 §2).
    pub hlc: Hlc,
    /// The version of the op's `data` encoding (ADR 0018 §11).
    pub item_schema_version: ItemSchemaVersion,
    /// The vault key epoch the author believed current (ADR 0012 §3, CRYPTO.md §11.6).
    pub vault_key_epoch: u32,
    /// The item VV the author had when it wrote the op (ADR 0012 §2 "Causal context").
    pub causal_context: CausalContext,
}

impl OpHeader {
    /// The length of the canonical encoding: 97 bytes plus 24 per context entry.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        OP_HEADER_FIXED_LEN.saturating_add(
            self.causal_context
                .len()
                .saturating_mul(VersionVector::ENTRY_LEN),
        )
    }

    /// Appends the canonical encoding (ADR 0012 §3) to `out`.
    ///
    /// # Errors
    /// [`EncodeError::TooManyEntries`] if the causal context has more than 65,535 entries.
    /// Nothing is appended then.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        if self.causal_context.len() > VersionVector::MAX_ENTRIES {
            return Err(EncodeError::TooManyEntries);
        }
        out.reserve(self.encoded_len());
        put_u8(out, HEADER_VERSION);
        out.extend_from_slice(self.vault_id.as_bytes());
        out.extend_from_slice(self.item_id.as_bytes());
        out.extend_from_slice(self.op_id.as_bytes());
        self.dot.encode(out);
        put_u64(out, self.vault_prev_seq);
        self.hlc.encode(out);
        put_u16(out, self.item_schema_version.get());
        put_u32(out, self.vault_key_epoch);
        self.causal_context.encode(out)
    }

    /// The canonical encoding as a new vector: the bytes the author passes to
    /// [`OpStatement::new`] as the canonical op header.
    ///
    /// # Errors
    /// [`EncodeError::TooManyEntries`], as [`OpHeader::encode`].
    pub fn to_vec(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Parses a canonical op header that fills all of `bytes`.
    ///
    /// # Errors
    /// A [`HeaderError`] for every byte string other than the canonical encoding of an op
    /// header (see the module docs).
    pub fn parse(bytes: &[u8]) -> Result<Self, HeaderError> {
        let mut c = Cursor::new(bytes);
        read_version(&mut c)?;
        let vault_id = VaultId::from_bytes(read_id(&mut c)?);
        let item_id = ItemId::from_bytes(read_id(&mut c)?);
        let op_id = OpId::from_bytes(read_id(&mut c)?);
        let dot = c.dot()?;
        let vault_prev_seq = c.u64()?;
        let hlc = c.hlc()?;
        let item_schema_version = read_schema(&mut c)?;
        let vault_key_epoch = c.u32()?;
        let causal_context = c.vv()?;
        c.finish()?;
        Ok(Self {
            vault_id,
            item_id,
            op_id,
            dot,
            vault_prev_seq,
            hlc,
            item_schema_version,
            vault_key_epoch,
            causal_context,
        })
    }

    /// Parses the header an `op` statement signed. Call it on a verified statement
    /// (`rizzy_core::sign::Verified<OpStatement>` dereferences to one) before trusting any of
    /// the header's fields, then check that the header's `device_id` is the device whose
    /// certificate supplied the verifying key (CRYPTO.md §10.2, INV-22).
    ///
    /// # Errors
    /// As [`OpHeader::parse`].
    pub fn parse_statement(statement: &OpStatement) -> Result<Self, HeaderError> {
        Self::parse(statement.header())
    }

    /// The `ITEM_OP` AAD context of the op's envelope (CRYPTO.md §8.4): the header's vault,
    /// item, schema version, op id, dot and HLC, and `SHA-256` of its canonical encoding.
    ///
    /// # Errors
    /// [`EncodeError::TooManyEntries`], as [`OpHeader::encode`].
    pub fn envelope_context(&self) -> Result<ItemOpCtx, EncodeError> {
        let canonical = self.to_vec()?;
        Ok(ItemOpCtx {
            vault_id: self.vault_id,
            item_id: self.item_id,
            item_schema_version: self.item_schema_version.get(),
            op_id: self.op_id,
            device_id: self.dot.device_id(),
            device_seq: self.dot.seq(),
            hlc: self.hlc.to_u64(),
            op_header_hash: ItemOpCtx::header_hash(&canonical),
        })
    }
}

/// The header of one item snapshot (ADR 0012 §3). The covered VV is the item VV of the
/// snapshot's state, which the `data` does not repeat (ADR 0018 §3, owner decision 3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SnapshotHeader {
    /// The vault the snapshot belongs to.
    pub vault_id: VaultId,
    /// The item it snapshots.
    pub item_id: ItemId,
    /// The snapshot's random 16-byte id.
    pub snapshot_id: SnapshotId,
    /// The device that wrote and signed it.
    pub author: DeviceId,
    /// The version of the snapshot's `data` encoding (ADR 0018 §11).
    pub item_schema_version: ItemSchemaVersion,
    /// The vault key epoch the author believed current (ADR 0012 §3, CRYPTO.md §11.6).
    pub vault_key_epoch: u32,
    /// The covered VV: every op the snapshot's state includes (ADR 0012 §3).
    pub covered: VersionVector,
}

impl SnapshotHeader {
    /// The length of the canonical encoding: 73 bytes plus 24 per covered-VV entry.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        SNAPSHOT_HEADER_FIXED_LEN
            .saturating_add(self.covered.len().saturating_mul(VersionVector::ENTRY_LEN))
    }

    /// Appends the canonical encoding (ADR 0012 §3) to `out`.
    ///
    /// # Errors
    /// [`EncodeError::TooManyEntries`] if the covered VV has more than 65,535 entries.
    /// Nothing is appended then.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        if self.covered.len() > VersionVector::MAX_ENTRIES {
            return Err(EncodeError::TooManyEntries);
        }
        out.reserve(self.encoded_len());
        put_u8(out, HEADER_VERSION);
        out.extend_from_slice(self.vault_id.as_bytes());
        out.extend_from_slice(self.item_id.as_bytes());
        out.extend_from_slice(self.snapshot_id.as_bytes());
        out.extend_from_slice(self.author.as_bytes());
        put_u16(out, self.item_schema_version.get());
        put_u32(out, self.vault_key_epoch);
        self.covered.encode(out)
    }

    /// The canonical encoding as a new vector: the bytes the author passes to
    /// [`SnapshotStatement::new`] as the canonical snapshot header.
    ///
    /// # Errors
    /// [`EncodeError::TooManyEntries`], as [`SnapshotHeader::encode`].
    pub fn to_vec(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Parses a canonical snapshot header that fills all of `bytes`.
    ///
    /// # Errors
    /// A [`HeaderError`] for every byte string other than the canonical encoding of a
    /// snapshot header (see the module docs).
    pub fn parse(bytes: &[u8]) -> Result<Self, HeaderError> {
        let mut c = Cursor::new(bytes);
        read_version(&mut c)?;
        let vault_id = VaultId::from_bytes(read_id(&mut c)?);
        let item_id = ItemId::from_bytes(read_id(&mut c)?);
        let snapshot_id = SnapshotId::from_bytes(read_id(&mut c)?);
        let author = DeviceId::from_bytes(read_id(&mut c)?);
        let item_schema_version = read_schema(&mut c)?;
        let vault_key_epoch = c.u32()?;
        let covered = c.vv()?;
        c.finish()?;
        Ok(Self {
            vault_id,
            item_id,
            snapshot_id,
            author,
            item_schema_version,
            vault_key_epoch,
            covered,
        })
    }

    /// Parses the header a `snapshot` statement signed. As for ops, call it on a verified
    /// statement before trusting any field, then check that `author` is the device whose
    /// certificate supplied the verifying key (CRYPTO.md §10.2).
    ///
    /// # Errors
    /// As [`SnapshotHeader::parse`].
    pub fn parse_statement(statement: &SnapshotStatement) -> Result<Self, HeaderError> {
        Self::parse(statement.header())
    }

    /// The `ITEM_SNAPSHOT` AAD context of the snapshot's envelope (CRYPTO.md §8.4): the
    /// header's vault, item, schema version and snapshot id, and `SHA-256` of its canonical
    /// encoding, which binds the author and the covered VV (ADR 0012 §3).
    ///
    /// # Errors
    /// [`EncodeError::TooManyEntries`], as [`SnapshotHeader::encode`].
    pub fn envelope_context(&self) -> Result<ItemSnapshotCtx, EncodeError> {
        let canonical = self.to_vec()?;
        Ok(ItemSnapshotCtx {
            vault_id: self.vault_id,
            item_id: self.item_id,
            item_schema_version: self.item_schema_version.get(),
            snapshot_id: self.snapshot_id,
            snapshot_header_hash: ItemSnapshotCtx::header_hash(&canonical),
        })
    }
}

#[cfg(test)]
mod core_vectors;
#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code edits fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests;
