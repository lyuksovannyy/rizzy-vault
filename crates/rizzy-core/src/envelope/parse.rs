//! Strict envelope parsing (CRYPTO.md §9.1, §9.2, §9.5).
//!
//! Two entry points:
//! - [`parse`] is the pure, purpose-agnostic layout parser `&[u8] -> Result<EnvelopeRef<'_>,
//!   ParseError>` (§9.5 rule 5). It is the fuzzing target and serves tooling.
//! - [`parse_for_purpose`] is the decryption path. It runs the §9.5 checks in their fixed
//!   order (length, `format_version`, algorithm allow-list) and returns the one
//!   [`DecryptError`] on any failure. The fourth check, the key id, needs the key and is done
//!   by the caller before any crypto runs.
//!
//! Both never panic, never copy, and never allocate: every field of an [`EnvelopeRef`] borrows
//! from the input.

use super::symmetric::{COMMITMENT_LEN, MAX_PLAINTEXT_LEN, NONCE_LEN, OVERHEAD, TAG_LEN};
use super::{AlgFamily, AlgId, FORMAT_VERSION, HEADER_LEN};
use crate::encoding::Reader;
use crate::error::{DecryptError, ParseError};
use crate::ids::ID_LEN;

/// Length of the HPKE encapsulated key (`enc`, an X25519 public key).
pub const ENC_LEN: usize = 32;

/// HPKE envelope overhead: header (18) + `enc` (32) + tag (16) = 66 bytes (§9.2).
pub const HPKE_OVERHEAD: usize = HEADER_LEN + ENC_LEN + TAG_LEN;

/// Longest accepted `0x01` envelope: the 16 MiB M1 plaintext limit plus the overhead (§9.1).
pub const MAX_SYMMETRIC_ENVELOPE_LEN: usize = MAX_PLAINTEXT_LEN + OVERHEAD;

/// A parsed envelope, borrowing from the input.
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

    /// Total encoded length.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        match self {
            Self::Symmetric(e) => OVERHEAD + e.ciphertext.len(),
            Self::Hpke(e) => HPKE_OVERHEAD + e.ciphertext.len(),
        }
    }

    /// Serialises the envelope. `parse` then `to_vec` is the identity.
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SymmetricEnvelopeRef<'a> {
    header: &'a [u8; HEADER_LEN],
    key_id: &'a [u8; ID_LEN],
    nonce: &'a [u8; NONCE_LEN],
    commitment: &'a [u8; COMMITMENT_LEN],
    ciphertext: &'a [u8],
    tag: &'a [u8; TAG_LEN],
}

impl<'a> SymmetricEnvelopeRef<'a> {
    /// The 18-byte header.
    #[must_use]
    pub const fn header(&self) -> &'a [u8; HEADER_LEN] {
        self.header
    }

    /// The key id of the key `K` (§4.4).
    #[must_use]
    pub const fn key_id(&self) -> &'a [u8; ID_LEN] {
        self.key_id
    }

    /// The 24-byte nonce.
    #[must_use]
    pub const fn nonce(&self) -> &'a [u8; NONCE_LEN] {
        self.nonce
    }

    /// The 32-byte key commitment.
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HpkeEnvelopeRef<'a> {
    alg: AlgId,
    header: &'a [u8; HEADER_LEN],
    key_id: &'a [u8; ID_LEN],
    enc: &'a [u8; ENC_LEN],
    ciphertext: &'a [u8],
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

    /// The recipient public key id.
    #[must_use]
    pub const fn key_id(&self) -> &'a [u8; ID_LEN] {
        self.key_id
    }

    /// The encapsulated key.
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
struct Header<'a> {
    bytes: &'a [u8; HEADER_LEN],
    version: u8,
    alg: u8,
    key_id: &'a [u8; ID_LEN],
    rest: &'a [u8],
}

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

/// Splits `ct ‖ tag`.
fn split_tag(body: &[u8]) -> Result<(&[u8], &[u8; TAG_LEN]), ParseError> {
    body.split_last_chunk::<TAG_LEN>()
        .ok_or(ParseError::Truncated)
}

/// Parses the layout of an envelope of a known, implemented algorithm. The header's version
/// and algorithm have already been checked by the caller.
fn parse_layout(alg: AlgId, input: &[u8]) -> Result<EnvelopeRef<'_>, ParseError> {
    match alg {
        AlgId::XChaCha20Poly1305Committed => {
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
/// [`parse_for_purpose`].
///
/// # Errors
/// [`ParseError::Truncated`], [`ParseError::TooLong`] or [`ParseError::InvalidValue`].
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
/// # Errors
/// [`DecryptError`] for every failure, including an empty allow-list.
pub fn parse_for_purpose<'a>(
    input: &'a [u8],
    allow_list: &[AlgId],
) -> Result<EnvelopeRef<'a>, DecryptError> {
    // 1. Length first.
    let min_len = allow_list
        .iter()
        .filter_map(|alg| alg.overhead())
        .min()
        .ok_or(DecryptError)?;
    if input.len() < min_len {
        return Err(DecryptError);
    }
    let symmetric_only = allow_list
        .iter()
        .all(|alg| alg.family() == AlgFamily::Symmetric);
    if symmetric_only && input.len() > MAX_SYMMETRIC_ENVELOPE_LEN {
        return Err(DecryptError);
    }
    let header = split_header(input)?;
    // 2. Format version.
    if header.version != FORMAT_VERSION {
        return Err(DecryptError);
    }
    // 3. Algorithm on this purpose's allow-list.
    let alg = AlgId::from_u8(header.alg)
        .filter(|alg| allow_list.contains(alg))
        .ok_or(DecryptError)?;
    Ok(parse_layout(alg, input)?)
}
