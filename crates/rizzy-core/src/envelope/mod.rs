//! Ciphertext envelopes (CRYPTO.md §8, §9; ADR 0005, ADR 0007).
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
//!
//! Every envelope binds its 18-byte header, a `u16` purpose and a context:
//! `aad = header ‖ u16(purpose) ‖ ctx`. The purpose and context are **not transmitted**: the
//! reader rebuilds them from where it expected the object, so ciphertext moved anywhere else
//! fails the commitment (symmetric) or the AEAD (HPKE).
//!
//! No public function accepts a nonce (threat model INV-12): nonces are drawn inside this crate
//! from the injected CSPRNG.

pub mod parse;
pub mod purpose;
pub mod symmetric;

#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;

pub use parse::{EnvelopeRef, HpkeEnvelopeRef, SymmetricEnvelopeRef};
pub use purpose::{
    Context, HpkeBaseContext, HpkeContext, HpkePskContext, PlaintextRule, Purpose, ServerContext,
    SymmetricContext,
};
pub use symmetric::{open, seal};

/// `format_version` of every envelope (§9.1, §9.2).
pub const FORMAT_VERSION: u8 = 0x01;

/// Header length: `format_version ‖ alg_id ‖ key_id[16]`.
pub const HEADER_LEN: usize = 18;

/// Algorithm ids (CRYPTO.md §9.4). Only registered ids exist as values; `0x00`, `0x14`–`0x1F`,
/// the test-only `0xF0`–`0xFE` and `0xFF` are rejected by [`AlgId::from_u8`].
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
    /// Every registered algorithm id.
    pub const ALL: [Self; 7] = [
        Self::XChaCha20Poly1305Committed,
        Self::Aes256GcmSivCommitted,
        Self::ChunkedXChaCha20Poly1305,
        Self::HpkeBaseX25519,
        Self::HpkeBaseXWing,
        Self::HpkePskX25519,
        Self::HpkePskXWing,
    ];

    /// The `u8` on the wire.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// Looks up a registered id. Unregistered, reserved-range, test-only and invalid ids give
    /// `None`.
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

    /// The algorithm's family.
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
pub(crate) fn build_aad<C: Context>(header: &[u8; HEADER_LEN], ctx: &C) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_LEN + 2 + ctx.ctx_len());
    aad.extend_from_slice(header);
    aad.extend_from_slice(&C::PURPOSE.id().to_be_bytes());
    ctx.write_ctx(&mut aad);
    aad
}
