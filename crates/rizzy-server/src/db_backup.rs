// SPDX-License-Identifier: AGPL-3.0-only

//! The encrypted database backup, format version 2 ([ADR 0071]; CRYPTO.md §9.8, audit target
//! 12 of §1 rule 2): the container `rizzy-vault backup --encrypt` writes and `rizzy-vault
//! restore` opens.
//!
//! The payload is a complete format version 1 file ([ADR 0023], written and parsed by the
//! unchanged [`rizzy_storage::backup::file`]), split into chunks of [`CHUNK_LEN`] bytes, each
//! sealed as its own algorithm-`0x01` envelope under purpose `SERVER_DB_BACKUP` (0x0105) with
//! the secrets file's backup key ([`ServerDbBackupKey`], CRYPTO.md §4.3 "Server DB-backup
//! subkey"). This module owns only the framing; every chunk uses the unmodified `0x01`
//! construction through `rizzy-core`.
//!
//! # Layout (CRYPTO.md §9.8)
//!
//! Notation of CRYPTO.md §2: big-endian fixed-width integers.
//!
//! ```text
//! file   = magic ‖ u16(format_version) = 2 ‖ backup_id (16) ‖ u64(created_at_ms)
//!          ‖ u32(backup_key_id) ‖ u64(plaintext_len) ‖ u32(chunk_count) ‖ chunk{chunk_count}
//! magic  = "rizzy-vault-db-backup" ‖ 0x00                      (ADR 0023 §1, 22 bytes)
//! chunk  = one 0x01 envelope (CRYPTO.md §9.1), 90 bytes longer than its plaintext
//! ctx(i) = backup_id ‖ u64(created_at_ms) ‖ u32(backup_key_id) ‖ u32(i) ‖ u32(chunk_count)
//! ```
//!
//! - The header is [`HEADER_LEN`] = 64 bytes. `backup_id` is 16 fresh random bytes per run.
//! - `plaintext_len` is the exact length of the format version 1 file; `chunk_count =
//!   ceil(plaintext_len / CHUNK_LEN)`. Chunk *i* holds bytes `[i × CHUNK_LEN, (i + 1) ×
//!   CHUNK_LEN)` of it, the last chunk the shorter rest. Opening every chunk in order, each
//!   at the exact envelope length [`parse_header`]/[`open`] derive from `plaintext_len`, and
//!   concatenating them gives the format version 1 file byte for byte; the concatenation is
//!   exactly `plaintext_len` bytes and there is no truncation step (ADR 0083).
//! - No outer digest: the per-chunk AEAD tags cover every byte (ADR 0071 "Size").
//!
//! # What binds what
//!
//! - **Order, completeness, origin.** Chunk *i* is sealed and opened under `ctx(i)`. Because
//!   `i` and `chunk_count` are in every chunk's AAD, a reordered, duplicated or dropped chunk,
//!   an edited clear `chunk_count`, or a chunk spliced in from another backup (another
//!   `backup_id`) fails the commitment of a chunk the reader opens. An edited `backup_id`,
//!   `created_at_ms` or `backup_key_id` fails it too, or names a key the secrets file lacks.
//! - **`plaintext_len` is in no AAD.** No commitment binds it: the 0x01 commitment covers
//!   only the key, the nonce and the AAD, and `plaintext_len` is in no chunk's ctx. What
//!   refuses such an edit here is the framing (ADR 0083): the reader derives every chunk's
//!   exact length from `plaintext_len` and requires the file to end exactly after the last
//!   chunk, so an edit that keeps `chunk_count` consistent either misframes the file (refused
//!   before any crypto) or, with the last chunk cut to fit, fails that chunk's Poly1305 tag.
//!   The format version 1 digest behind it would also catch a shortened payload.
//!
//! # Reading (strict, canonical)
//!
//! [`parse_header`] checks, before any crypto and before any allocation sized by a declared
//! length: the input is at most [`MAX_BACKUP_FILE_LEN`] and at least [`HEADER_LEN`] bytes; the
//! magic; `format_version` = 2; `plaintext_len` > 0 (a format version 1 file is never empty,
//! and a container without chunks would authenticate nothing); `chunk_count =
//! ceil(plaintext_len / CHUNK_LEN)` (ADR 0071: "before opening any chunk"); and the input's
//! length is exactly `HEADER_LEN + plaintext_len + 90 × chunk_count`. [`open`] then looks up
//! the header's `backup_key_id` in the secrets file, which may no longer be the current one,
//! and opens the chunks in order, stopping at the first failure. Every file [`open`] accepts
//! is one [`seal`] can produce. The parser never panics, and its errors name a rule or a
//! chunk index, never a byte of the payload (fuzz target `db_backup_container`).
//!
//! # Writing
//!
//! [`seal`] refuses an empty payload and an output past [`MAX_BACKUP_FILE_LEN`] (ADR 0071
//! "Size": the cap is on the format version 2 file, so a format version 1 file close to the
//! cap may not fit once encrypted), then draws `backup_id`, then each chunk's nonce, from the
//! injected CSPRNG.
//!
//! [ADR 0071]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0071-encrypted-db-backup-format.md
//! [ADR 0023]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0023-logical-backup-format.md

use core::fmt;

use rizzy_domain_auth::types::{BackupId, CryptoRng, ServerDbBackupCtx, ServerDbBackupKey};
use rizzy_storage::backup::file::{MAGIC, MAX_BACKUP_FILE_LEN};
use zeroize::Zeroizing;

/// The container's `format_version` (ADR 0071; format version 1 is ADR 0023's plain file).
pub const FORMAT_VERSION: u16 = 2;

/// The plaintext length of every chunk but the last: 8 MiB, fixed (ADR 0071 owner answer 5).
pub const CHUNK_LEN: usize = 8 * 1024 * 1024;

/// What one algorithm-`0x01` envelope adds to its plaintext (CRYPTO.md §9.1): 90 bytes.
pub const CHUNK_OVERHEAD: usize = 90;

/// The header's length: magic (22), `format_version` (2), `backup_id` (16),
/// `created_at_ms` (8), `backup_key_id` (4), `plaintext_len` (8), `chunk_count` (4).
pub const HEADER_LEN: usize = MAGIC.len() + 2 + 16 + 8 + 4 + 8 + 4;

/// The framing rule a file whose length disagrees with its header breaks.
const LENGTH_MISMATCH: &str = "the file length does not match plaintext_len and chunk_count";

/// The clear header of a format version 2 file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// 16 random bytes per run.
    pub backup_id: BackupId,
    /// Creation time, milliseconds since the Unix epoch; also the format version 1 file's.
    pub created_at_ms: u64,
    /// The secrets file's backup key the chunks are sealed under.
    pub backup_key_id: u32,
    /// The exact length of the format version 1 file inside.
    pub plaintext_len: u64,
    /// `ceil(plaintext_len / CHUNK_LEN)`.
    pub chunk_count: u32,
}

impl Header {
    /// The context chunk `index` is sealed and opened under (CRYPTO.md §8.4, §9.8).
    #[must_use]
    pub const fn chunk_ctx(&self, index: u32) -> ServerDbBackupCtx {
        ServerDbBackupCtx {
            backup_id: self.backup_id,
            created_at_ms: self.created_at_ms,
            backup_key_id: self.backup_key_id,
            chunk_index: index,
            chunk_count: self.chunk_count,
        }
    }

    /// The header's [`HEADER_LEN`] bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        out.extend_from_slice(self.backup_id.as_bytes());
        out.extend_from_slice(&self.created_at_ms.to_be_bytes());
        out.extend_from_slice(&self.backup_key_id.to_be_bytes());
        out.extend_from_slice(&self.plaintext_len.to_be_bytes());
        out.extend_from_slice(&self.chunk_count.to_be_bytes());
        out
    }
}

/// Why a format version 2 file could not be written or opened. `Display` names a rule or a
/// chunk index, never a byte of the payload or a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DbBackupError {
    /// The payload to seal is empty.
    Empty,
    /// The file would be, or is, longer than [`MAX_BACKUP_FILE_LEN`] (ADR 0071 "Size").
    TooLarge,
    /// The file breaks a framing rule (module docs), checked before any crypto.
    Malformed(&'static str),
    /// The header names a backup key the secrets file does not hold.
    UnknownBackupKey {
        /// The header's `backup_key_id`.
        backup_key_id: u32,
    },
    /// A chunk failed its key-id check, its commitment or its AEAD: the file was damaged or
    /// tampered with, or does not belong to this backup key.
    Authentication {
        /// The 0-based position of the first chunk that failed.
        chunk_index: u32,
    },
    /// Sealing a chunk failed (not expected for a payload within the limits).
    Seal,
}

impl fmt::Display for DbBackupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("encrypted backup: nothing to encrypt"),
            Self::TooLarge => f.write_str("encrypted backup exceeds the 2 GiB file limit"),
            Self::Malformed(rule) => write!(f, "encrypted backup is malformed: {rule}"),
            Self::UnknownBackupKey { backup_key_id } => write!(
                f,
                "encrypted backup is sealed under backup key {backup_key_id}, which the secrets \
                 file does not hold"
            ),
            Self::Authentication { chunk_index } => write!(
                f,
                "encrypted backup chunk {chunk_index} failed authentication: the file is \
                 damaged or tampered with, or belongs to other secrets"
            ),
            Self::Seal => f.write_str("encrypted backup: a chunk could not be sealed"),
        }
    }
}

impl std::error::Error for DbBackupError {}

/// The `format_version` of a backup file that starts with ADR 0023's magic, or `None`.
/// `rizzy-vault restore` dispatches on it (ADR 0071 "Commands and restore").
#[must_use]
pub fn format_version(bytes: &[u8]) -> Option<u16> {
    let rest = bytes.strip_prefix(MAGIC.as_slice())?;
    Reader(rest).u16()
}

/// The length of the format version 2 file for a payload of `plaintext_len` bytes in
/// `chunk_len`-byte chunks: header, payload and 90 bytes per chunk (ADR 0071 "Size"); `None`
/// on overflow.
fn sealed_len_with(plaintext_len: usize, chunk_len: usize) -> Option<usize> {
    plaintext_len
        .div_ceil(chunk_len)
        .checked_mul(CHUNK_OVERHEAD)?
        .checked_add(plaintext_len)?
        .checked_add(HEADER_LEN)
}

/// The length of the format version 2 file for a payload of `plaintext_len` bytes: header,
/// payload and 90 bytes per chunk; `None` on overflow.
#[must_use]
pub fn sealed_len(plaintext_len: usize) -> Option<usize> {
    sealed_len_with(plaintext_len, CHUNK_LEN)
}

/// Seals `plaintext`, a complete format version 1 file, as a format version 2 file under
/// `key` (the secrets file's current backup key). `backup_id`, then each chunk's nonce, come
/// from `rng`.
///
/// # Errors
/// [`DbBackupError::Empty`] and [`DbBackupError::TooLarge`], checked before anything is drawn
/// or sealed; [`DbBackupError::Seal`].
pub fn seal<R: CryptoRng + ?Sized>(
    rng: &mut R,
    key: &ServerDbBackupKey,
    plaintext: &[u8],
    created_at_ms: u64,
) -> Result<Vec<u8>, DbBackupError> {
    seal_with(rng, key, plaintext, created_at_ms, CHUNK_LEN)
}

/// [`seal`] with `chunk_len`-byte chunks. Only the unit tests pass another length than
/// [`CHUNK_LEN`], to reach many chunks with small payloads.
fn seal_with<R: CryptoRng + ?Sized>(
    rng: &mut R,
    key: &ServerDbBackupKey,
    plaintext: &[u8],
    created_at_ms: u64,
    chunk_len: usize,
) -> Result<Vec<u8>, DbBackupError> {
    if plaintext.is_empty() {
        return Err(DbBackupError::Empty);
    }
    let total = sealed_len_with(plaintext.len(), chunk_len).ok_or(DbBackupError::TooLarge)?;
    if total > MAX_BACKUP_FILE_LEN {
        return Err(DbBackupError::TooLarge);
    }
    let chunk_count =
        u32::try_from(plaintext.len().div_ceil(chunk_len)).map_err(|_| DbBackupError::TooLarge)?;
    let plaintext_len = u64::try_from(plaintext.len()).map_err(|_| DbBackupError::TooLarge)?;
    let header = Header {
        backup_id: BackupId::generate(rng),
        created_at_ms,
        backup_key_id: key.backup_key_id(),
        plaintext_len,
        chunk_count,
    };
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&header.encode());
    for (index, chunk) in (0..chunk_count).zip(plaintext.chunks(chunk_len)) {
        let envelope = key
            .seal_chunk(rng, &header.chunk_ctx(index), chunk)
            .map_err(|_| DbBackupError::Seal)?;
        out.extend_from_slice(&envelope);
    }
    if out.len() != total {
        return Err(DbBackupError::Seal);
    }
    Ok(out)
}

/// Reads a format version 2 header and checks the file's framing against it (module docs,
/// "Reading"), before any crypto.
///
/// # Errors
/// [`DbBackupError::TooLarge`] or [`DbBackupError::Malformed`].
pub fn parse_header(bytes: &[u8]) -> Result<Header, DbBackupError> {
    parse_header_with(bytes, CHUNK_LEN)
}

/// [`parse_header`] with `chunk_len`-byte chunks (only the unit tests pass another length).
fn parse_header_with(bytes: &[u8], chunk_len: usize) -> Result<Header, DbBackupError> {
    const SHORT: DbBackupError = DbBackupError::Malformed("shorter than the header");
    if bytes.len() > MAX_BACKUP_FILE_LEN {
        return Err(DbBackupError::TooLarge);
    }
    let mut r = Reader(bytes);
    if r.take(MAGIC.len()).ok_or(SHORT)? != MAGIC.as_slice() {
        return Err(DbBackupError::Malformed(
            "not a rizzy-vault database backup",
        ));
    }
    if r.u16().ok_or(SHORT)? != FORMAT_VERSION {
        return Err(DbBackupError::Malformed("format_version is not 2"));
    }
    let backup_id = BackupId::from_bytes(r.array().ok_or(SHORT)?);
    let created_at_ms = r.u64().ok_or(SHORT)?;
    let backup_key_id = r.u32().ok_or(SHORT)?;
    let plaintext_len = r.u64().ok_or(SHORT)?;
    let chunk_count = r.u32().ok_or(SHORT)?;
    if plaintext_len == 0 {
        return Err(DbBackupError::Malformed("plaintext_len is 0"));
    }
    // A plaintext_len longer than any file this reader accepts is refused before the
    // arithmetic, so nothing below can overflow.
    let payload = usize::try_from(plaintext_len)
        .ok()
        .filter(|&n| n <= MAX_BACKUP_FILE_LEN)
        .ok_or(DbBackupError::Malformed(LENGTH_MISMATCH))?;
    if usize::try_from(chunk_count).ok() != Some(payload.div_ceil(chunk_len)) {
        return Err(DbBackupError::Malformed(
            "chunk_count is not ceil(plaintext_len / CHUNK_LEN)",
        ));
    }
    if sealed_len_with(payload, chunk_len) != Some(bytes.len()) {
        return Err(DbBackupError::Malformed(LENGTH_MISMATCH));
    }
    Ok(Header {
        backup_id,
        created_at_ms,
        backup_key_id,
        plaintext_len,
        chunk_count,
    })
}

/// Opens a format version 2 file: checks the header and framing ([`parse_header`]), takes the
/// header's backup key from `backup_key` (the secrets file's
/// [`ServerSecrets::backup_key`](rizzy_domain_auth::ServerSecrets::backup_key), which may give
/// a key that is no longer current), opens every chunk in order, and returns the format
/// version 1 file, which the caller then parses as ADR 0023 §5 step 2 does.
///
/// # Errors
/// [`DbBackupError`]: the framing (before any crypto), an unknown backup key, or the first
/// chunk that fails authentication.
pub fn open<'k>(
    backup_key: impl FnOnce(u32) -> Option<&'k ServerDbBackupKey>,
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, DbBackupError> {
    open_with(backup_key, bytes, CHUNK_LEN)
}

/// [`open`] with `chunk_len`-byte chunks (only the unit tests pass another length).
fn open_with<'k>(
    backup_key: impl FnOnce(u32) -> Option<&'k ServerDbBackupKey>,
    bytes: &[u8],
    chunk_len: usize,
) -> Result<Zeroizing<Vec<u8>>, DbBackupError> {
    let header = parse_header_with(bytes, chunk_len)?;
    let key = backup_key(header.backup_key_id).ok_or(DbBackupError::UnknownBackupKey {
        backup_key_id: header.backup_key_id,
    })?;
    // parse_header_with checked that the file holds exactly this many plaintext bytes, so the
    // allocation is bounded by the input.
    let payload = usize::try_from(header.plaintext_len)
        .map_err(|_| DbBackupError::Malformed(LENGTH_MISMATCH))?;
    let mut out = Zeroizing::new(Vec::with_capacity(payload));
    let mut rest = bytes.get(HEADER_LEN..).unwrap_or_default();
    for index in 0..header.chunk_count {
        let failed = DbBackupError::Authentication { chunk_index: index };
        let len = chunk_len.min(payload.saturating_sub(out.len()));
        let (envelope, tail) = rest
            .split_at_checked(len.saturating_add(CHUNK_OVERHEAD))
            .ok_or(DbBackupError::Malformed(LENGTH_MISMATCH))?;
        let chunk = key
            .open_chunk(&header.chunk_ctx(index), envelope)
            .map_err(|_| failed)?;
        // The AEAD covers the ciphertext length, so this holds; checked anyway.
        if chunk.len() != len {
            return Err(failed);
        }
        out.extend_from_slice(chunk.expose_secret());
        rest = tail;
    }
    if out.len() != payload || !rest.is_empty() {
        return Err(DbBackupError::Malformed(LENGTH_MISMATCH));
    }
    Ok(out)
}

/// A cursor over the header bytes; every read is bounds-checked.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    /// The next `n` bytes, or `None` past the end.
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(n)?;
        self.0 = tail;
        Some(head)
    }

    /// The next `N` bytes as an array.
    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    /// A big-endian `u16`.
    fn u16(&mut self) -> Option<u16> {
        self.array().map(u16::from_be_bytes)
    }

    /// A big-endian `u32`.
    fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_be_bytes)
    }

    /// A big-endian `u64`.
    fn u64(&mut self) -> Option<u64> {
        self.array().map(u64::from_be_bytes)
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic fails the test, which CLAUDE.md allows"
)]
mod tests {
    //! The framing rules on small chunks (the real [`CHUNK_LEN`] runs in
    //! `tests/db_backup.rs` and the known-answer vectors): round trips, every truncation and
    //! every bit flip refused, the named attacks of ADR 0071 "Ordering and completeness", and
    //! the `plaintext_len` edit, which the framing refuses, not the commitment (module docs).

    use chacha20::ChaCha20Rng;
    use chacha20::rand_core::SeedableRng as _;
    use proptest::prelude::*;

    use super::*;

    /// The chunk length of these tests.
    const SMALL: usize = 64;

    fn key(id: u32) -> ServerDbBackupKey {
        ServerDbBackupKey::from_slice(&[0x42; 32], id).unwrap()
    }

    /// `len` payload bytes, byte `i` = `i mod 251`.
    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    fn seal_small(len: usize, seed: u64) -> Vec<u8> {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        seal_with(&mut rng, &key(3), &payload(len), 1_780_000_000_000, SMALL).unwrap()
    }

    fn open_small(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, DbBackupError> {
        let k = key(3);
        open_with(|id| (id == 3).then_some(&k), bytes, SMALL)
    }

    /// The byte range of chunk `i` in a small file with a `len`-byte payload.
    fn chunk_range(len: usize, i: usize) -> core::ops::Range<usize> {
        let start = HEADER_LEN + i * (SMALL + CHUNK_OVERHEAD);
        let plain = SMALL.min(len - i * SMALL);
        start..start + plain + CHUNK_OVERHEAD
    }

    /// Rewrites the header of `bytes` with `edit` applied to its fields, read without the
    /// framing checks.
    fn with_header(bytes: &[u8], edit: impl FnOnce(&mut Header)) -> Vec<u8> {
        let mut r = Reader(&bytes[MAGIC.len() + 2..HEADER_LEN]);
        let mut header = Header {
            backup_id: BackupId::from_bytes(r.array().unwrap()),
            created_at_ms: r.u64().unwrap(),
            backup_key_id: r.u32().unwrap(),
            plaintext_len: r.u64().unwrap(),
            chunk_count: r.u32().unwrap(),
        };
        edit(&mut header);
        let mut out = header.encode();
        out.extend_from_slice(&bytes[HEADER_LEN..]);
        out
    }

    fn auth(chunk_index: u32) -> DbBackupError {
        DbBackupError::Authentication { chunk_index }
    }

    #[test]
    fn header_layout() {
        assert_eq!(HEADER_LEN, 64);
        let header = Header {
            backup_id: BackupId::from_bytes([0xb1; 16]),
            created_at_ms: 0x0102_0304_0506_0708,
            backup_key_id: 0x0a0b_0c0d,
            plaintext_len: 0x1122_3344_5566_7788,
            chunk_count: 0x99aa_bbcc,
        };
        let bytes = header.encode();
        let expected = [
            b"rizzy-vault-db-backup\0".as_slice(),
            &[0x00, 0x02],
            &[0xb1; 16],
            &[1, 2, 3, 4, 5, 6, 7, 8],
            &[0x0a, 0x0b, 0x0c, 0x0d],
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            &[0x99, 0xaa, 0xbb, 0xcc],
        ]
        .concat();
        assert_eq!(bytes, expected);
        assert_eq!(format_version(&bytes), Some(2));
        assert_eq!(
            format_version(b"rizzy-vault-db-backup\0\x00\x01rest"),
            Some(1)
        );
        assert_eq!(format_version(b"rizzy-vault-db-backup\0\x00"), None);
        assert_eq!(format_version(b"something else"), None);
        let ctx = header.chunk_ctx(7);
        assert_eq!(
            (
                ctx.backup_id,
                ctx.created_at_ms,
                ctx.backup_key_id,
                ctx.chunk_index,
                ctx.chunk_count
            ),
            (
                header.backup_id,
                header.created_at_ms,
                header.backup_key_id,
                7,
                header.chunk_count
            )
        );
    }

    #[test]
    fn round_trips_at_every_chunk_boundary() {
        for len in [
            1,
            2,
            SMALL - 1,
            SMALL,
            SMALL + 1,
            2 * SMALL,
            2 * SMALL + 1,
            5 * SMALL + 7,
        ] {
            let file = seal_small(len, len as u64);
            assert_eq!(Some(file.len()), sealed_len_with(len, SMALL), "{len}");
            let header = parse_header_with(&file, SMALL).unwrap();
            assert_eq!(header.plaintext_len, len as u64);
            assert_eq!(header.chunk_count as usize, len.div_ceil(SMALL));
            assert_eq!(header.backup_key_id, 3);
            assert_eq!(header.created_at_ms, 1_780_000_000_000);
            assert_eq!(
                open_small(&file).unwrap().as_slice(),
                payload(len).as_slice()
            );
        }
        // The real chunk length: one chunk for a small payload.
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let file = seal(&mut rng, &key(3), &payload(1000), 5).unwrap();
        assert_eq!(file.len(), HEADER_LEN + 1000 + CHUNK_OVERHEAD);
        assert_eq!(parse_header(&file).unwrap().chunk_count, 1);
        let k = key(3);
        assert_eq!(
            open(|_| Some(&k), &file).unwrap().as_slice(),
            payload(1000).as_slice()
        );
        // Two runs never share a backup_id.
        let again = seal(&mut rng, &key(3), &payload(1000), 5).unwrap();
        assert_ne!(
            parse_header(&file).unwrap().backup_id,
            parse_header(&again).unwrap().backup_id
        );
    }

    #[test]
    fn seal_refusals() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        assert_eq!(seal(&mut rng, &key(1), &[], 0), Err(DbBackupError::Empty));
        // The cap is on the format version 2 file: a format version 1 file at the cap does not
        // fit once encrypted (ADR 0071 "Size").
        assert!(sealed_len(MAX_BACKUP_FILE_LEN).unwrap() > MAX_BACKUP_FILE_LEN);
        assert_eq!(
            sealed_len(CHUNK_LEN + 1),
            Some(HEADER_LEN + CHUNK_LEN + 1 + 2 * CHUNK_OVERHEAD)
        );
        assert_eq!(sealed_len(usize::MAX), None);
    }

    #[test]
    fn every_truncation_and_every_bit_flip_is_refused() {
        let len = 2 * SMALL + 10;
        let file = seal_small(len, 3);
        for cut in 0..file.len() {
            assert!(open_small(&file[..cut]).is_err(), "cut {cut}");
        }
        for byte in 0..file.len() {
            for bit in 0..8 {
                let mut bad = file.clone();
                bad[byte] ^= 1 << bit;
                assert!(open_small(&bad).is_err(), "byte {byte} bit {bit}");
            }
        }
        // One extra byte anywhere is refused too.
        let mut longer = file.clone();
        longer.push(0);
        assert_eq!(
            open_small(&longer),
            Err(DbBackupError::Malformed(LENGTH_MISMATCH))
        );
    }

    #[test]
    fn reordered_duplicated_and_dropped_chunks_fail_the_commitment() {
        let len = 3 * SMALL + 10;
        let file = seal_small(len, 4);
        let chunk = |i| file[chunk_range(len, i)].to_vec();
        let header = file[..HEADER_LEN].to_vec();
        let build = |chunks: &[Vec<u8>]| [std::slice::from_ref(&header), chunks].concat().concat();

        // Swap chunks 0 and 1 (same length).
        let swapped = build(&[chunk(1), chunk(0), chunk(2), chunk(3)]);
        assert_eq!(open_small(&swapped), Err(auth(0)));
        // Chunk 1 duplicated over chunk 2.
        let duplicated = build(&[chunk(0), chunk(1), chunk(1), chunk(3)]);
        assert_eq!(open_small(&duplicated), Err(auth(2)));
        // A full chunk dropped, the header left alone: the framing refuses it.
        let dropped = build(&[chunk(0), chunk(1), chunk(3)]);
        assert_eq!(
            open_small(&dropped),
            Err(DbBackupError::Malformed(LENGTH_MISMATCH))
        );
        // The last chunk dropped and the clear chunk_count and plaintext_len edited to match:
        // the framing is consistent, and chunk_count in every ctx fails the first chunk.
        let truncated = with_header(&build(&[chunk(0), chunk(1), chunk(2)]), |h| {
            h.chunk_count = 3;
            h.plaintext_len = 3 * SMALL as u64;
        });
        assert_eq!(open_small(&truncated), Err(auth(0)));
        // An edited chunk_count alone breaks ceil(plaintext_len / CHUNK_LEN): before any crypto.
        let count = with_header(&file, |h| h.chunk_count = 5);
        assert_eq!(
            open_small(&count),
            Err(DbBackupError::Malformed(
                "chunk_count is not ceil(plaintext_len / CHUNK_LEN)"
            ))
        );
    }

    #[test]
    fn a_chunk_from_another_backup_fails() {
        // Same key, same length, same time: only backup_id differs.
        let len = 2 * SMALL;
        let a = seal_small(len, 5);
        let b = seal_small(len, 6);
        assert_ne!(a[..HEADER_LEN], b[..HEADER_LEN]);
        for i in 0..2 {
            let mut spliced = a.clone();
            spliced[chunk_range(len, i)].copy_from_slice(&b[chunk_range(len, i)]);
            assert_eq!(open_small(&spliced), Err(auth(u32::try_from(i).unwrap())));
        }
        // B's header over A's chunks.
        let mut spliced = a.clone();
        spliced[..HEADER_LEN].copy_from_slice(&b[..HEADER_LEN]);
        assert_eq!(open_small(&spliced), Err(auth(0)));
    }

    #[test]
    fn header_edits_are_refused() {
        let len = 2 * SMALL + 5;
        let file = seal_small(len, 7);
        let mut magic = file.clone();
        magic[0] ^= 1;
        assert_eq!(
            open_small(&magic),
            Err(DbBackupError::Malformed(
                "not a rizzy-vault database backup"
            ))
        );
        let mut version = file.clone();
        version[MAGIC.len() + 1] = 3;
        assert_eq!(
            open_small(&version),
            Err(DbBackupError::Malformed("format_version is not 2"))
        );
        let id = with_header(&file, |h| h.backup_id = BackupId::from_bytes([0; 16]));
        assert_eq!(open_small(&id), Err(auth(0)));
        let time = with_header(&file, |h| h.created_at_ms += 1);
        assert_eq!(open_small(&time), Err(auth(0)));
        // Another backup_key_id: unknown to the secrets, or another key's (key-id check).
        let other = with_header(&file, |h| h.backup_key_id = 4);
        assert_eq!(
            open_small(&other),
            Err(DbBackupError::UnknownBackupKey { backup_key_id: 4 })
        );
        let k4 = key(4);
        assert_eq!(
            open_with(|id| (id == 4).then_some(&k4), &other, SMALL),
            Err(auth(0))
        );
        // The right id, but other key bytes under it.
        let wrong = ServerDbBackupKey::from_slice(&[0x43; 32], 3).unwrap();
        assert_eq!(open_with(|_| Some(&wrong), &file, SMALL), Err(auth(0)));
        let zero = with_header(&file, |h| {
            h.plaintext_len = 0;
            h.chunk_count = 0;
        });
        assert_eq!(
            open_small(&zero[..HEADER_LEN]),
            Err(DbBackupError::Malformed("plaintext_len is 0"))
        );
        let huge = with_header(&file, |h| h.plaintext_len = u64::MAX);
        assert_eq!(
            open_small(&huge),
            Err(DbBackupError::Malformed(LENGTH_MISMATCH))
        );
        assert_eq!(
            open_small(&file[..HEADER_LEN - 1]),
            Err(DbBackupError::Malformed("shorter than the header"))
        );
    }

    /// The open point of ADR 0071: `plaintext_len` is in no chunk's AAD, so an edit to it does
    /// not fail any commitment. The strict framing refuses it instead: as a length mismatch
    /// before any crypto, or, with the last chunk cut to fit, by that chunk's Poly1305 tag.
    #[test]
    fn a_plaintext_len_edit_is_refused_by_the_framing_not_the_commitment() {
        let len = 2 * SMALL + 10;
        let file = seal_small(len, 8);
        // Within the same ceil() bucket, so chunk_count stays consistent.
        let shorter = with_header(&file, |h| h.plaintext_len -= 1);
        assert_eq!(
            open_small(&shorter),
            Err(DbBackupError::Malformed(LENGTH_MISMATCH))
        );
        let longer = with_header(&file, |h| h.plaintext_len += 1);
        assert_eq!(
            open_small(&longer),
            Err(DbBackupError::Malformed(LENGTH_MISMATCH))
        );
        // Shorter by one, and the last envelope shortened by one byte to fit the framing: the
        // last chunk's ciphertext is cut, which its tag catches. Every earlier chunk opens.
        let mut cut = shorter;
        // The last envelope: 74 bytes of header, nonce and commitment, then its 10 ciphertext
        // bytes, then the tag (CRYPTO.md §9.1). One ciphertext byte goes.
        let last = chunk_range(len, 2).start;
        cut.remove(last + 74);
        assert_eq!(open_small(&cut), Err(auth(2)));
    }

    #[test]
    fn errors_name_no_payload_byte() {
        for e in [
            DbBackupError::Empty,
            DbBackupError::TooLarge,
            DbBackupError::Malformed(LENGTH_MISMATCH),
            DbBackupError::UnknownBackupKey { backup_key_id: 9 },
            auth(3),
            DbBackupError::Seal,
        ] {
            let text = e.to_string();
            assert!(text.starts_with("encrypted backup"), "{text}");
            assert!(text.len() < 200);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn prop_round_trip(len in 1usize..600, seed in any::<u64>()) {
            let file = seal_small(len, seed);
            let opened = open_small(&file).unwrap();
            let expected = payload(len);
            prop_assert_eq!(opened.as_slice(), expected.as_slice());
        }

        #[test]
        fn prop_any_single_bit_flip_fails(len in 1usize..600, seed in any::<u64>(), at in any::<prop::sample::Index>(), bit in 0u8..8) {
            let mut file = seal_small(len, seed);
            let i = at.index(file.len());
            file[i] ^= 1 << bit;
            prop_assert!(open_small(&file).is_err());
        }

        #[test]
        fn prop_any_truncation_fails(len in 1usize..600, seed in any::<u64>(), at in any::<prop::sample::Index>()) {
            let file = seal_small(len, seed);
            let cut = at.index(file.len());
            prop_assert!(open_small(&file[..cut]).is_err());
        }

        #[test]
        fn prop_arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..400), header in any::<bool>()) {
            // With the magic and version in front, the parser behind them is reached.
            let input = if header {
                [MAGIC.as_slice(), &[0, 2], &bytes].concat()
            } else {
                bytes
            };
            let _ = open_small(&input);
            let _ = parse_header(&input);
        }
    }
}
