//! Ciphertext envelopes (CRYPTO.md §8, §9; ADR 0005, ADR 0007).
//!
//! Every ciphertext `rizzy-core` produces is a versioned envelope: a fixed binary layout whose
//! 18-byte header names the format version, the algorithm and the key (threat model INV-9).
//! This module owns the registries and the parser that every envelope shares, and the
//! symmetric algorithm itself.
//!
//! - [`purpose`]: the purpose registry for every purpose in §8.4 (ids, encrypt algorithm,
//!   decrypt allow-lists, plaintext rules) and the typed contexts (`ctx`) of the M1 purposes.
//! - [`parse`]: the strict, non-panicking, non-allocating envelope parser and the §9.5 check
//!   order.
//! - [`symmetric`]: algorithm `0x01`, XChaCha20-Poly1305 with the `UtC` + `HtE` key commitment
//!   (§8.3, §9.1).
//! - The HPKE algorithms `0x10` and `0x12` (§9.2) live in [`crate::hpke`], next to the X25519
//!   key types and the PSK derivations, and share [`parse`] and the AAD builder with this
//!   module.
//! - Plaintext framing and Padmé padding (§8.5) live in [`crate::padding`]; the envelope
//!   applies them itself for the purposes that need them.
//!
//! # Layouts (§9.1, §9.2)
//!
//! ```text
//! header    = u8(format_version = 0x01) ‖ u8(alg_id) ‖ key_id[16]          (18 bytes)
//! symmetric = header ‖ nonce[24] ‖ commitment[32] ‖ ct[n] ‖ tag[16]        (alg 0x01, 90 B overhead)
//! HPKE      = header ‖ enc[32] ‖ ct[n] ‖ tag[16]                            (alg 0x10/0x12, 66 B overhead)
//! ```
//!
//! There is no length field: the ciphertext length is the envelope length minus the fixed
//! overhead, and `n` is always the length of the plaintext the AEAD saw (for a padded purpose,
//! the whole frame).
//!
//! # Binding
//!
//! Every envelope binds its 18-byte header, a `u16` purpose and a context:
//! `aad = header ‖ u16(purpose) ‖ ctx`. The purpose and context are **not transmitted**: the
//! reader rebuilds them from where it expected the object, so ciphertext moved anywhere else
//! fails the commitment (symmetric) or the AEAD (HPKE). A context type fixes its purpose at
//! compile time ([`Context::PURPOSE`]), so the two can never be paired wrongly.
//!
//! # Opening (§9.5)
//!
//! Every open runs the same checks in the same order before any crypto: length, then
//! `format_version`, then the algorithm against the purpose's decrypt allow-list, then the key
//! id against the caller's key. Each purpose has exactly one encrypt algorithm and a
//! compiled-in decrypt allow-list; the server never chooses an algorithm, and there is no
//! fallback or legacy path (INV-10). Every failure, from a short input to a bad tag, is the one
//! [`DecryptError`](crate::error::DecryptError), so the error never says which check failed
//! (§12.3).
//!
//! # What this defends against, and what it does not
//!
//! - **Moving or swapping ciphertext** (another item, vault, account, epoch or purpose): the
//!   rebuilt AAD differs, so the open fails (INV-13 for items).
//! - **Algorithm downgrade**: only allow-listed algorithms open, and the header is inside the
//!   AAD, so rewriting `alg_id` or `key_id` fails too (INV-9, INV-10).
//! - **Partitioning oracles and multi-key ciphertexts**: every symmetric envelope is
//!   key-committing (INV-11, §8.3). HPKE envelopes need no commitment (§9.2).
//! - **Nonce misuse**: no public function accepts a nonce (INV-12). Nonces are drawn inside this
//!   crate from the injected CSPRNG.
//! - **Not covered here: freshness.** An older envelope with the same context still opens under
//!   the same key. Rollback is only partly addressed elsewhere: by epochs in the context and by
//!   the signed `account-state` (for example `settings_seq` for `ACCOUNT_SETTINGS`, §8.4).
//!   CRYPTO.md §14 lists what remains, such as op withholding and rolling a fresh device back
//!   to an older, validly signed state.
//! - **Not covered here: authorship.** Whoever holds a symmetric key, or a recipient's public
//!   key, can seal a valid envelope. Where authorship matters, a signature covers the envelope
//!   (§10.1, [`crate::sign`]).
//! - **Not hidden: metadata.** The header (version, algorithm, key id) and the envelope length
//!   are in clear. Envelopes under the same key share a key id. Padded purposes leak only the
//!   Padmé bucket of their length, fixed-size purposes leak nothing beyond that size, and
//!   unpadded purposes leak the exact plaintext length (§8.5, §14).
//!
//! The raw AEAD and HKDF calls stay private to this crate (ADR 0005 "Risks", ADR 0009): the only
//! public way to encrypt is an envelope function, so the commitment cannot be skipped by
//! calling the AEAD directly.

pub mod parse;
pub mod purpose;
pub mod symmetric;

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod proptests;
#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    clippy::unreachable,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests;

pub use parse::{EnvelopeRef, HpkeEnvelopeRef, SymmetricEnvelopeRef};
pub use purpose::{
    Context, HpkeBaseContext, HpkeContext, HpkePskContext, PlaintextRule, Purpose, ServerContext,
    SymmetricContext,
};
pub use symmetric::{open, seal};

/// `format_version` of every envelope (§9.1, §9.2). It is the first header byte; any other
/// value is rejected before any crypto (§9.5 rule 1.2).
pub const FORMAT_VERSION: u8 = 0x01;

/// Header length: `format_version ‖ alg_id ‖ key_id[16]`. The whole header is the first part
/// of the AAD of every envelope (INV-9).
pub const HEADER_LEN: usize = 18;

/// Algorithm ids (CRYPTO.md §9.4). Only registered ids exist as values; `0x00`, `0x14`–`0x1F`,
/// the test-only `0xF0`–`0xFE` and `0xFF` are rejected by [`AlgId::from_u8`].
///
/// Registered is not the same as usable: only `0x01`, `0x10` and `0x12` are implemented in M1
/// ([`AlgId::is_implemented`]). The reserved ids exist so that the registry, the purpose table
/// and the parser can name them. No purpose can seal or open with them yet (`ATTACHMENT_CHUNK`
/// names `0x03` but has no context type), and no layout parses them.
/// Whether an algorithm is acceptable for a given object is decided by the purpose's decrypt
/// allow-list ([`Purpose`]), never by this enum alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum AlgId {
    /// `0x01`: XChaCha20-Poly1305 with the HKDF-SHA-256 `UtC` + `HtE` commitment (§8.3). M1.
    XChaCha20Poly1305Committed = 0x01,
    /// `0x02`: AES-256-GCM-SIV with the same commitment. Reserved, not implemented.
    Aes256GcmSivCommitted = 0x02,
    /// `0x03`: chunked/streaming variant of `0x01` for attachments. Reserved for the M3 ADR.
    ChunkedXChaCha20Poly1305 = 0x03,
    /// `0x10`: HPKE Base mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / `ChaCha20Poly1305`. M1.
    HpkeBaseX25519 = 0x10,
    /// `0x11`: HPKE Base mode with X-Wing. Reserved, post-1.0.
    HpkeBaseXWing = 0x11,
    /// `0x12`: HPKE PSK mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / `ChaCha20Poly1305`. M1.
    HpkePskX25519 = 0x12,
    /// `0x13`: HPKE PSK mode with X-Wing. Reserved, post-1.0.
    HpkePskXWing = 0x13,
}

/// The family an algorithm belongs to. A purpose's encrypt algorithm and every algorithm on
/// its decrypt allow-list share one family (§9.5 rule 2: a symmetric purpose never accepts
/// HPKE, a PSK-mode purpose never accepts Base mode, and vice versa).
///
/// The parser also uses the family to decide whether the 16 MiB symmetric size limit applies
/// before the header is read ([`parse::parse_for_purpose`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AlgFamily {
    /// Symmetric committing AEAD.
    Symmetric,
    /// Chunked symmetric (M3).
    Chunked,
    /// HPKE Base mode.
    HpkeBase,
    /// HPKE PSK mode.
    HpkePsk,
}

impl AlgId {
    /// Every registered algorithm id, implemented or reserved, in id order.
    pub const ALL: [Self; 7] = [
        Self::XChaCha20Poly1305Committed,
        Self::Aes256GcmSivCommitted,
        Self::ChunkedXChaCha20Poly1305,
        Self::HpkeBaseX25519,
        Self::HpkeBaseXWing,
        Self::HpkePskX25519,
        Self::HpkePskXWing,
    ];

    /// The `u8` on the wire: header byte 1.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Looks up a registered id. Unregistered, reserved-range, test-only and invalid ids give
    /// `None`.
    ///
    /// A `Some` here only means the id is registered. A reader must still check it against
    /// the purpose's allow-list; [`parse::parse_for_purpose`] does both.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::XChaCha20Poly1305Committed),
            0x02 => Some(Self::Aes256GcmSivCommitted),
            0x03 => Some(Self::ChunkedXChaCha20Poly1305),
            0x10 => Some(Self::HpkeBaseX25519),
            0x11 => Some(Self::HpkeBaseXWing),
            0x12 => Some(Self::HpkePskX25519),
            0x13 => Some(Self::HpkePskXWing),
            _ => None,
        }
    }

    /// The algorithm's family: symmetric (`0x01`, `0x02`), chunked (`0x03`), HPKE Base
    /// (`0x10`, `0x11`) or HPKE PSK (`0x12`, `0x13`).
    #[must_use]
    pub const fn family(self) -> AlgFamily {
        match self {
            Self::XChaCha20Poly1305Committed | Self::Aes256GcmSivCommitted => AlgFamily::Symmetric,
            Self::ChunkedXChaCha20Poly1305 => AlgFamily::Chunked,
            Self::HpkeBaseX25519 | Self::HpkeBaseXWing => AlgFamily::HpkeBase,
            Self::HpkePskX25519 | Self::HpkePskXWing => AlgFamily::HpkePsk,
        }
    }

    /// `true` for the algorithms M1 implements: `0x01`, `0x10` and `0x12` (§9.4).
    #[must_use]
    pub const fn is_implemented(self) -> bool {
        matches!(
            self,
            Self::XChaCha20Poly1305Committed | Self::HpkeBaseX25519 | Self::HpkePskX25519
        )
    }

    /// Envelope overhead in bytes for an implemented algorithm: 90 for `0x01`, 66 for `0x10`
    /// and `0x12`. It is also the minimum envelope length (§9.5 rule 1.1). `None` for reserved
    /// algorithms, whose layouts are not defined yet.
    #[must_use]
    pub const fn overhead(self) -> Option<usize> {
        match self {
            Self::XChaCha20Poly1305Committed => Some(symmetric::OVERHEAD),
            Self::HpkeBaseX25519 | Self::HpkePskX25519 => Some(parse::HPKE_OVERHEAD),
            _ => None,
        }
    }
}

/// Builds `aad = header ‖ u16(purpose) ‖ ctx` (§8.4, §9.1, §9.2), allocated at its final size.
///
/// Shared by the symmetric envelope and the HPKE envelope, so both bind exactly the same bytes.
/// The purpose id comes from the context's type (`C::PURPOSE`), not from a parameter, and the
/// `ctx` bytes are fixed-width fields with no length prefixes ([`Context::write_ctx`]). On
/// open, `header` is the header read from the envelope; any change to it therefore changes
/// the AAD.
pub(crate) fn build_aad<C: Context>(header: &[u8; HEADER_LEN], ctx: &C) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_LEN + 2 + ctx.ctx_len());
    aad.extend_from_slice(header);
    aad.extend_from_slice(&C::PURPOSE.id().to_be_bytes());
    ctx.write_ctx(&mut aad);
    aad
}
