//! Strict envelope parsing (CRYPTO.md §9.1, §9.2, §9.5).
//!
//! Envelope bytes come from the server, a file or the local cache, so they are untrusted
//! input. This module turns them into borrowed, typed views ([`EnvelopeRef`]) or rejects them.
//! It never decrypts and never sees a key.
//!
//! Two entry points:
//! - [`parse`] is the pure, purpose-agnostic layout parser `&[u8] -> Result<EnvelopeRef<'_>,
//!   ParseError>` (§9.5 rule 5). It is the fuzzing target
//!   (`fuzz/fuzz_targets/envelope_parse.rs`) and serves tooling and the `key-grant` statement,
//!   which checks the layout of the HPKE envelope it signs ([`crate::sign`]).
//! - [`parse_for_purpose`] is the decryption path. It runs the §9.5 checks in their fixed
//!   order (length, `format_version`, algorithm allow-list) and returns the one
//!   [`DecryptError`] on any failure. The fourth check, the key id, needs the key and is done
//!   by the caller before any crypto runs.
//!
//! Both never panic, never copy, and never allocate: every field of an [`EnvelopeRef`] borrows
//! from the input.
//!
//! # Layouts
//!
//! ```text
//! [0]        format_version (0x01)
//! [1]        alg_id
//! [2, 18)    key_id
//! 0x01:      [18, 42) nonce ‖ [42, 74) commitment ‖ [74, len − 16) ct ‖ [len − 16, len) tag
//! 0x10/0x12: [18, 50) enc   ‖ [50, len − 16) ct   ‖ [len − 16, len) tag
//! ```
//!
//! An envelope has no length field. The ciphertext is whatever lies between the fixed-size
//! prefix and the 16-byte tag at the end, so a hostile length value cannot exist, and nothing
//! is allocated in proportion to one. `n = 0` is a valid layout (an empty plaintext); whether a
//! purpose accepts it is decided later by its plaintext rule.
//!
//! # Limits
//!
//! A symmetric (`0x01`) envelope is at most [`MAX_SYMMETRIC_ENVELOPE_LEN`] bytes, checked
//! before any field after the header is read (and by [`parse_for_purpose`] before the header
//! too). HPKE envelopes have no limit at this layer: the HPKE open path checks the 16 MiB
//! plaintext bound after parsing and before any crypto ([`crate::hpke`]), and the `key-grant`
//! statement bounds the envelopes it accepts itself.
//!
//! # What the parser does not decide
//!
//! A successful parse says only that the bytes have the shape of an envelope of an implemented
//! algorithm. It does not say the envelope is authentic, that it belongs to any purpose, or
//! that the caller holds its key.

use super::symmetric::{COMMITMENT_LEN, MAX_PLAINTEXT_LEN, NONCE_LEN, OVERHEAD, TAG_LEN};
use super::{AlgFamily, AlgId, FORMAT_VERSION, HEADER_LEN};
use crate::encoding::Reader;
use crate::error::{DecryptError, ParseError};
use crate::ids::ID_LEN;

/// Length of the HPKE encapsulated key (`enc`, an X25519 public key): envelope bytes
/// `[18, 50)` (§9.2).
pub const ENC_LEN: usize = 32;

/// HPKE envelope overhead: header (18) + `enc` (32) + tag (16) = 66 bytes (§9.2). It is also
/// the minimum length of an HPKE envelope (§9.5 rule 1.1).
pub const HPKE_OVERHEAD: usize = HEADER_LEN + ENC_LEN + TAG_LEN;

/// Longest accepted `0x01` envelope: the 16 MiB M1 plaintext limit plus the overhead (§9.1).
/// Longer input is rejected before any crypto, and by [`parse_for_purpose`] before the header
/// is even read.
pub const MAX_SYMMETRIC_ENVELOPE_LEN: usize = MAX_PLAINTEXT_LEN + OVERHEAD;

/// A parsed envelope, borrowing from the input.
///
/// Obtained from [`parse`] or [`parse_for_purpose`]. The variant is fixed by the header's
/// `alg_id`: `0x01` gives [`EnvelopeRef::Symmetric`], `0x10` and `0x12` give
/// [`EnvelopeRef::Hpke`]. Nothing in it has been authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeRef<'a> {
    /// Algorithm `0x01`.
    Symmetric(SymmetricEnvelopeRef<'a>),
    /// Algorithms `0x10` and `0x12`.
    Hpke(HpkeEnvelopeRef<'a>),
}

impl<'a> EnvelopeRef<'a> {
    /// The algorithm.
    #[must_use]
    pub const fn alg_id(&self) -> AlgId {
        match self {
            Self::Symmetric(_) => AlgId::XChaCha20Poly1305Committed,
            Self::Hpke(e) => e.alg,
        }
    }

    /// The 18-byte header, `format_version ‖ alg_id ‖ key_id`.
    #[must_use]
    pub const fn header(&self) -> &'a [u8; HEADER_LEN] {
        match self {
            Self::Symmetric(e) => e.header,
            Self::Hpke(e) => e.header,
        }
    }

    /// The key id in the header: the symmetric key id (§4.4) for `0x01`, the recipient public
    /// key id for HPKE.
    #[must_use]
    pub const fn key_id(&self) -> &'a [u8; ID_LEN] {
        match self {
            Self::Symmetric(e) => e.key_id,
            Self::Hpke(e) => e.key_id,
        }
    }

    /// Total encoded length: the algorithm's overhead plus the ciphertext length. Equal to the
    /// length of the input it was parsed from.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        match self {
            Self::Symmetric(e) => OVERHEAD + e.ciphertext.len(),
            Self::Hpke(e) => HPKE_OVERHEAD + e.ciphertext.len(),
        }
    }

    /// Serialises the envelope. `parse` then `to_vec` is the identity (§15 item 4), so the
    /// layout is canonical: one byte string per parsed envelope. Allocates once, at the final
    /// size.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        match self {
            Self::Symmetric(e) => {
                out.extend_from_slice(e.header);
                out.extend_from_slice(e.nonce);
                out.extend_from_slice(e.commitment);
                out.extend_from_slice(e.ciphertext);
                out.extend_from_slice(e.tag);
            }
            Self::Hpke(e) => {
                out.extend_from_slice(e.header);
                out.extend_from_slice(e.enc);
                out.extend_from_slice(e.ciphertext);
                out.extend_from_slice(e.tag);
            }
        }
        out
    }
}

/// A symmetric envelope (§9.1):
/// `header[18] ‖ nonce[24] ‖ commitment[32] ‖ ciphertext[n] ‖ tag[16]`.
///
/// Fields are private and read through accessors, so a value can only come from the parser
/// and always describes a well-formed layout. `Debug` prints the bytes; they are ciphertext
/// and public header values, not secrets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SymmetricEnvelopeRef<'a> {
    /// Bytes `[0, 18)`: the whole header, as bound into the AAD.
    header: &'a [u8; HEADER_LEN],
    /// Bytes `[2, 18)`: the key id of `K`, a sub-slice of `header`.
    key_id: &'a [u8; ID_LEN],
    /// Bytes `[18, 42)`: the random `XChaCha20` nonce, also the HKDF salt of the commitment.
    nonce: &'a [u8; NONCE_LEN],
    /// Bytes `[42, 74)`: the key commitment, `okm[32..64]` (§8.3).
    commitment: &'a [u8; COMMITMENT_LEN],
    /// Bytes `[74, len − 16)`: the ciphertext, as long as the AEAD plaintext.
    ciphertext: &'a [u8],
    /// The last 16 bytes: the Poly1305 tag.
    tag: &'a [u8; TAG_LEN],
}

impl<'a> SymmetricEnvelopeRef<'a> {
    /// The 18-byte header.
    #[must_use]
    pub const fn header(&self) -> &'a [u8; HEADER_LEN] {
        self.header
    }

    /// The key id of the key `K` (§4.4). The reader compares it with the id of the key it
    /// holds (§9.5 rule 1.4); it only helps find the key and proves nothing by itself.
    #[must_use]
    pub const fn key_id(&self) -> &'a [u8; ID_LEN] {
        self.key_id
    }

    /// The 24-byte nonce.
    #[must_use]
    pub const fn nonce(&self) -> &'a [u8; NONCE_LEN] {
        self.nonce
    }

    /// The 32-byte key commitment. Compare it only in constant time, against the value
    /// recomputed from the key, nonce and rebuilt AAD (§8.3, §12.3).
    #[must_use]
    pub const fn commitment(&self) -> &'a [u8; COMMITMENT_LEN] {
        self.commitment
    }

    /// The ciphertext, as long as the plaintext.
    #[must_use]
    pub const fn ciphertext(&self) -> &'a [u8] {
        self.ciphertext
    }

    /// The 16-byte Poly1305 tag.
    #[must_use]
    pub const fn tag(&self) -> &'a [u8; TAG_LEN] {
        self.tag
    }
}

/// An HPKE envelope (§9.2): `header[18] ‖ enc[32] ‖ ciphertext[n] ‖ tag[16]`.
///
/// Base mode (`0x10`) and PSK mode (`0x12`) share this layout; only the header's `alg_id`
/// tells them apart, and the purpose decides which one is allowed (§9.5 rule 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HpkeEnvelopeRef<'a> {
    /// The header's `alg_id`: `0x10` or `0x12`.
    alg: AlgId,
    /// Bytes `[0, 18)`: the whole header, as bound into the AAD.
    header: &'a [u8; HEADER_LEN],
    /// Bytes `[2, 18)`: the recipient public key id, a sub-slice of `header`.
    key_id: &'a [u8; ID_LEN],
    /// Bytes `[18, 50)`: the encapsulated key, the sender's ephemeral X25519 public key.
    enc: &'a [u8; ENC_LEN],
    /// Bytes `[50, len − 16)`: the ciphertext, as long as the AEAD plaintext.
    ciphertext: &'a [u8],
    /// The last 16 bytes: the `ChaCha20Poly1305` tag.
    tag: &'a [u8; TAG_LEN],
}

impl<'a> HpkeEnvelopeRef<'a> {
    /// `0x10` (Base mode) or `0x12` (PSK mode).
    #[must_use]
    pub const fn alg_id(&self) -> AlgId {
        self.alg
    }

    /// The 18-byte header.
    #[must_use]
    pub const fn header(&self) -> &'a [u8; HEADER_LEN] {
        self.header
    }

    /// The recipient public key id: `SHA-256(LABEL("key-id") ‖ 0x00 ‖ u8(key_type) ‖ pk)[0..16]`
    /// for the recipient's X25519 key, with the key type the purpose's recipient has (§4.3,
    /// §9.2).
    #[must_use]
    pub const fn key_id(&self) -> &'a [u8; ID_LEN] {
        self.key_id
    }

    /// The encapsulated key (`enc`), the sender's ephemeral X25519 public key. It is not
    /// validated here; decapsulation rejects an unusable value.
    #[must_use]
    pub const fn enc(&self) -> &'a [u8; ENC_LEN] {
        self.enc
    }

    /// The ciphertext, as long as the plaintext.
    #[must_use]
    pub const fn ciphertext(&self) -> &'a [u8] {
        self.ciphertext
    }

    /// The 16-byte tag.
    #[must_use]
    pub const fn tag(&self) -> &'a [u8; TAG_LEN] {
        self.tag
    }
}

/// Splits `input` into its header fields and the rest.
///
/// The version and algorithm are raw bytes here; the callers check them.
struct Header<'a> {
    /// The 18 header bytes, as bound into the AAD.
    bytes: &'a [u8; HEADER_LEN],
    /// Byte 0: `format_version`, not checked yet.
    version: u8,
    /// Byte 1: `alg_id`, not checked yet.
    alg: u8,
    /// Bytes `[2, 18)`: the key id.
    key_id: &'a [u8; ID_LEN],
    /// Everything after the header.
    rest: &'a [u8],
}

/// Reads the 18-byte header from the front of `input` without judging its values.
///
/// # Errors
/// [`ParseError::Truncated`] if `input` is shorter than [`HEADER_LEN`]. The inner
/// `finish` cannot fail: the header reader consumes all of its 18 bytes (1 + 1 + 16).
fn split_header(input: &[u8]) -> Result<Header<'_>, ParseError> {
    let mut r = Reader::new(input);
    let bytes = r.array::<HEADER_LEN>()?;
    let rest = r.rest();
    let mut h = Reader::new(bytes);
    let version = h.u8()?;
    let alg = h.u8()?;
    let key_id = h.array::<ID_LEN>()?;
    h.finish()?;
    Ok(Header {
        bytes,
        version,
        alg,
        key_id,
        rest,
    })
}

/// Splits `ct ‖ tag`: the tag is the last [`TAG_LEN`] bytes, the ciphertext is everything
/// before it (possibly empty).
///
/// # Errors
/// [`ParseError::Truncated`] if `body` is shorter than a tag. Unreachable from
/// [`parse_layout`], which checks the minimum length first.
fn split_tag(body: &[u8]) -> Result<(&[u8], &[u8; TAG_LEN]), ParseError> {
    body.split_last_chunk::<TAG_LEN>()
        .ok_or(ParseError::Truncated)
}

/// Parses the layout of an envelope of a known, implemented algorithm. The header's version
/// and algorithm have already been checked by the caller.
///
/// Length is checked first (the algorithm's minimum, and the 16 MiB maximum for `0x01`), then
/// the fixed-size fields are read from the front and the tag from the back.
///
/// # Errors
/// [`ParseError::Truncated`] below the algorithm's overhead, [`ParseError::TooLong`] above the
/// symmetric limit, [`ParseError::InvalidValue`] for a registered but unimplemented algorithm.
fn parse_layout(alg: AlgId, input: &[u8]) -> Result<EnvelopeRef<'_>, ParseError> {
    match alg {
        AlgId::XChaCha20Poly1305Committed => {
            // 90-byte minimum: header, nonce, commitment and tag, with an empty ciphertext.
            if input.len() < OVERHEAD {
                return Err(ParseError::Truncated);
            }
            if input.len() > MAX_SYMMETRIC_ENVELOPE_LEN {
                return Err(ParseError::TooLong);
            }
            let header = split_header(input)?;
            let mut r = Reader::new(header.rest);
            let nonce = r.array::<NONCE_LEN>()?;
            let commitment = r.array::<COMMITMENT_LEN>()?;
            let (ciphertext, tag) = split_tag(r.rest())?;
            Ok(EnvelopeRef::Symmetric(SymmetricEnvelopeRef {
                header: header.bytes,
                key_id: header.key_id,
                nonce,
                commitment,
                ciphertext,
                tag,
            }))
        }
        AlgId::HpkeBaseX25519 | AlgId::HpkePskX25519 => {
            // 66-byte minimum: header, `enc` and tag, with an empty ciphertext. No maximum here;
            // the HPKE open path applies the 16 MiB bound (§9.2).
            if input.len() < HPKE_OVERHEAD {
                return Err(ParseError::Truncated);
            }
            let header = split_header(input)?;
            let mut r = Reader::new(header.rest);
            let enc = r.array::<ENC_LEN>()?;
            let (ciphertext, tag) = split_tag(r.rest())?;
            Ok(EnvelopeRef::Hpke(HpkeEnvelopeRef {
                alg,
                header: header.bytes,
                key_id: header.key_id,
                enc,
                ciphertext,
                tag,
            }))
        }
        // Reserved algorithms have no layout yet.
        _ => Err(ParseError::InvalidValue),
    }
}

/// Parses any envelope of an implemented algorithm, without a purpose.
///
/// Checks: at least a header, `format_version = 0x01`, a registered and implemented `alg_id`
/// (`0x01`, `0x10`, `0x12`; reserved, test-only and invalid ids are rejected), the algorithm's
/// minimum length, and for `0x01` the 16 MiB M1 limit.
///
/// This does not decide whether the envelope is acceptable for any purpose; decryption uses
/// [`parse_for_purpose`]. The order of checks differs from §9.5 (the header is read before the
/// algorithm's minimum length is known), which is harmless here because this function runs no
/// crypto and reports distinct [`ParseError`]s for tooling and fuzzing.
///
/// # Errors
/// - [`ParseError::Truncated`]: shorter than the header, or than the algorithm's overhead;
/// - [`ParseError::TooLong`]: a `0x01` envelope over [`MAX_SYMMETRIC_ENVELOPE_LEN`];
/// - [`ParseError::InvalidValue`]: a wrong `format_version`, or an `alg_id` that is not
///   registered and implemented.
pub fn parse(input: &[u8]) -> Result<EnvelopeRef<'_>, ParseError> {
    let header = split_header(input)?;
    if header.version != FORMAT_VERSION {
        return Err(ParseError::InvalidValue);
    }
    let alg = AlgId::from_u8(header.alg)
        .filter(|a| a.is_implemented())
        .ok_or(ParseError::InvalidValue)?;
    parse_layout(alg, input)
}

/// The §9.5 decryption-path checks, in their fixed order, against a purpose's decrypt
/// allow-list:
///
/// 1. length: at least the smallest overhead among the allowed algorithms (90 bytes for
///    `0x01`, 66 for `0x10` and `0x12`), and at most the M1 limit for a symmetric purpose;
/// 2. `format_version` must be `0x01`;
/// 3. `alg_id` must be on `allow_list`;
///
/// then the layout of that algorithm. The key id check (step 4) needs the key and is the
/// caller's, before any crypto runs.
///
/// Pass the allow-list of the purpose the object was expected under
/// ([`Purpose::client_decrypt_allow_list`](super::Purpose::client_decrypt_allow_list) or, on
/// the server, [`Purpose::server_decrypt_allow_list`](super::Purpose::server_decrypt_allow_list)),
/// never a list derived from the envelope. For an HPKE purpose the 16 MiB plaintext bound is
/// not checked here; the HPKE open path checks it next.
///
/// # Errors
/// [`DecryptError`] for every failure, including an empty allow-list and an allow-list that
/// holds only algorithms with no implemented layout (such as `ATTACHMENT_CHUNK`'s `0x03`).
pub fn parse_for_purpose<'a>(
    input: &'a [u8],
    allow_list: &[AlgId],
) -> Result<EnvelopeRef<'a>, DecryptError> {
    // 1. Length first. The minimum is the smallest overhead of an implemented algorithm on the
    //    list; reserved algorithms have no overhead, so a list of only those rejects everything.
    let min_len = allow_list
        .iter()
        .filter_map(|alg| alg.overhead())
        .min()
        .ok_or(DecryptError)?;
    if input.len() < min_len {
        return Err(DecryptError);
    }
    // The maximum applies when every allowed algorithm is symmetric, which is the case for
    // every symmetric purpose (their lists are `{0x01}`).
    let symmetric_only = allow_list
        .iter()
        .all(|alg| alg.family() == AlgFamily::Symmetric);
    if symmetric_only && input.len() > MAX_SYMMETRIC_ENVELOPE_LEN {
        return Err(DecryptError);
    }
    // Cannot be truncated: every implemented overhead is longer than the header.
    let header = split_header(input)?;
    // 2. Format version.
    if header.version != FORMAT_VERSION {
        return Err(DecryptError);
    }
    // 3. Algorithm on this purpose's allow-list.
    let alg = AlgId::from_u8(header.alg)
        .filter(|alg| allow_list.contains(alg))
        .ok_or(DecryptError)?;
    // Then that algorithm's own minimum length and fields. Any `ParseError` becomes the one
    // `DecryptError`.
    Ok(parse_layout(alg, input)?)
}
