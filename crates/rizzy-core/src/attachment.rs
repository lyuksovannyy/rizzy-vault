// SPDX-License-Identifier: AGPL-3.0-only

//! Encrypted attachments: the chunk layout, the attachment key and its wrap ([ADR 0054];
//! CRYPTO.md §4.2, §8.4, §9.1).
//!
//! [ADR 0054]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0054-attachments-envelope-and-api.md
//!
//! **No new construction (ADR 0054 §1).** Every chunk is an ordinary algorithm-`0x01`
//! envelope ([`crate::envelope::seal`], §9.1 layout and §8.3 commitment unchanged) under the
//! attachment key, purpose `ATTACHMENT_CHUNK` (`0x0033`), unpadded, with
//! `ctx = vault_id ‖ item_id ‖ attachment_id ‖ u32 chunk_index ‖ u32 chunk_count`
//! ([`AttachmentChunkCtx`]). The attachment key itself is wrapped under the item key as
//! `ATTACHMENT_KEY_WRAP` (`0x0034`, ctx `vault_id ‖ item_id ‖ attachment_id`), and never
//! re-wrapped when the item key rotates (ADR 0054 §3).
//!
//! **Where the numbers come from.** [`AttachmentLayout`] is built from the plaintext size the
//! item's `attachment/<id>/size` field records (ADR 0054 §4), never from a server value:
//! `chunk_count = ceil(size / CHUNK_SIZE)`, and every chunk but the last holds exactly
//! [`CHUNK_SIZE`] bytes. [`AttachmentKey::seal_chunk`] and [`AttachmentKey::open_chunk`] build
//! the context from the layout themselves, so no caller can put a server-supplied count into an
//! AAD. A chunk served at another index, for another attachment, or opened against a count
//! derived from another size fails the commitment before the AEAD runs (INV-78).
//!
//! **What is not here.** The upload and download loops, and the completeness check that
//! assembles an attachment only from exactly `chunk_count` opened chunks (INV-79), live in
//! `rizzy-client` (ADR 0054 §2: "Streaming encrypt/decrypt loops live in `rizzy-client`/leaves,
//! never in `rizzy-core`"). This module has no I/O, no clock and no OS randomness: every nonce
//! and key comes from the injected CSPRNG.
//!
//! [`AttachmentChunkCtx`]: crate::envelope::purpose::AttachmentChunkCtx

use core::fmt;

use rand_core::CryptoRng;

use crate::envelope::purpose::{AttachmentChunkCtx, AttachmentKeyWrapCtx};
use crate::envelope::symmetric::OVERHEAD;
use crate::envelope::{open, seal};
use crate::error::{DecryptError, DerivationError, EncryptError};
use crate::ids::{AttachmentId, ItemId, SymmetricKeyId, VaultId};
use crate::keys::ItemKey;
use crate::secret::{KEY_LEN, Key32, SecretBytes};

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "test code indexes fixtures at known offsets; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests;

/// Plaintext bytes per chunk: 512 KiB (ADR 0054 §2). Every chunk but the last holds exactly
/// this many; compiled in, never configured.
pub const CHUNK_SIZE: usize = 524_288;

/// [`CHUNK_SIZE`] as a `u64`, for the layout arithmetic.
const CHUNK_SIZE_U64: u64 = 524_288;

/// The largest attachment, in plaintext bytes: 25 MiB (ADR 0054 §2). Compiled in.
pub const MAX_ATTACHMENT_LEN: u64 = 26_214_400;

/// The most chunks an attachment can have: `MAX_ATTACHMENT_LEN / CHUNK_SIZE` = 50.
pub const MAX_CHUNK_COUNT: u32 = 50;

/// Bytes a chunk envelope adds to its plaintext: the §9.1 symmetric overhead (90).
pub const CHUNK_OVERHEAD: usize = OVERHEAD;

/// The longest chunk envelope: `CHUNK_SIZE + 90` (ADR 0054 §6).
pub const MAX_CHUNK_ENVELOPE_LEN: usize = CHUNK_SIZE + CHUNK_OVERHEAD;

/// Length of an `ATTACHMENT_KEY_WRAP` envelope: the 32-byte key plus the §9.1 overhead.
pub const ATTACHMENT_KEY_WRAP_LEN: usize = KEY_LEN + OVERHEAD;

/// A declared size over [`MAX_ATTACHMENT_LEN`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TooLarge;

impl fmt::Display for TooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("attachment exceeds the 25 MiB limit")
    }
}

impl core::error::Error for TooLarge {}

/// Where an attachment belongs: the three ids every attachment context starts with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AttachmentRef {
    /// The vault holding the item.
    pub vault_id: VaultId,
    /// The item the attachment belongs to.
    pub item_id: ItemId,
    /// The attachment's own id, which also names its `attachment/<id>/…` fields.
    pub attachment_id: AttachmentId,
}

impl AttachmentRef {
    /// The `ATTACHMENT_KEY_WRAP` context of this attachment.
    #[must_use]
    pub const fn key_wrap_ctx(&self) -> AttachmentKeyWrapCtx {
        AttachmentKeyWrapCtx {
            vault_id: self.vault_id,
            item_id: self.item_id,
            attachment_id: self.attachment_id,
        }
    }

    /// The `ATTACHMENT_CHUNK` context of chunk `chunk_index` under `layout`, or `None` when the
    /// index is not below the layout's chunk count.
    #[must_use]
    pub const fn chunk_ctx(
        &self,
        layout: AttachmentLayout,
        chunk_index: u32,
    ) -> Option<AttachmentChunkCtx> {
        if chunk_index >= layout.chunk_count {
            return None;
        }
        Some(AttachmentChunkCtx {
            vault_id: self.vault_id,
            item_id: self.item_id,
            attachment_id: self.attachment_id,
            chunk_index,
            chunk_count: layout.chunk_count,
        })
    }
}

/// The chunk layout of one attachment, derived from its plaintext size alone (ADR 0054 §1,
/// §2, §4).
///
/// The client builds it from the `attachment/<id>/size` value it wrote (on upload) or reads
/// from the item (on download); the server builds the same layout from the
/// `total_plaintext_len` the client declared at `create`, which the client sets equal to that
/// field, so both sides count the same chunks by construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AttachmentLayout {
    /// Plaintext byte length.
    size: u64,
    /// `ceil(size / CHUNK_SIZE)`; zero for an empty attachment.
    chunk_count: u32,
}

impl AttachmentLayout {
    /// The layout of a `size`-byte attachment.
    ///
    /// # Errors
    /// [`TooLarge`] when `size` exceeds [`MAX_ATTACHMENT_LEN`].
    pub const fn new(size: u64) -> Result<Self, TooLarge> {
        if size > MAX_ATTACHMENT_LEN {
            return Err(TooLarge);
        }
        let chunks = size.div_ceil(CHUNK_SIZE_U64);
        if chunks > MAX_CHUNK_COUNT as u64 {
            return Err(TooLarge);
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "chunks <= MAX_CHUNK_COUNT (50) was checked just above"
        )]
        let chunk_count = chunks as u32;
        Ok(Self { size, chunk_count })
    }

    /// Plaintext byte length.
    #[must_use]
    pub const fn size(self) -> u64 {
        self.size
    }

    /// Number of chunks, `ceil(size / CHUNK_SIZE)`.
    #[must_use]
    pub const fn chunk_count(self) -> u32 {
        self.chunk_count
    }

    /// Offset of chunk `index` in the plaintext, or `None` past the last chunk.
    #[must_use]
    pub const fn chunk_offset(self, index: u32) -> Option<u64> {
        if index >= self.chunk_count {
            return None;
        }
        // index < 50, so the product is at most 49 × 512 KiB.
        Some(index as u64 * CHUNK_SIZE_U64)
    }

    /// Plaintext length of chunk `index`: [`CHUNK_SIZE`] for every chunk but the last, which
    /// holds the remainder (`1..=CHUNK_SIZE` bytes). `None` past the last chunk.
    #[must_use]
    pub const fn chunk_len(self, index: u32) -> Option<usize> {
        let Some(offset) = self.chunk_offset(index) else {
            return None;
        };
        // offset < size for every index below chunk_count.
        let rest = self.size - offset;
        let len = if rest < CHUNK_SIZE_U64 {
            rest
        } else {
            CHUNK_SIZE_U64
        };
        #[expect(
            clippy::cast_possible_truncation,
            reason = "len <= CHUNK_SIZE (512 KiB), which fits every usize this crate builds for"
        )]
        Some(len as usize)
    }

    /// Exact envelope length of chunk `index`: its plaintext length plus [`CHUNK_OVERHEAD`].
    /// `None` past the last chunk. The server checks every uploaded chunk against this.
    #[must_use]
    pub const fn chunk_envelope_len(self, index: u32) -> Option<usize> {
        match self.chunk_len(index) {
            Some(len) => Some(len + CHUNK_OVERHEAD),
            None => None,
        }
    }

    /// Sum of every chunk envelope's length: `size + chunk_count × 90`.
    #[must_use]
    pub const fn envelopes_len(self) -> u64 {
        self.size + self.chunk_count as u64 * CHUNK_OVERHEAD as u64
    }
}

/// An attachment key (CRYPTO.md §4.2): 32 bytes from the injected CSPRNG, one per attachment,
/// never rotated — a changed attachment is a new attachment with a new key.
///
/// It seals and opens the attachment's `ATTACHMENT_CHUNK` envelopes and travels only inside an
/// `ATTACHMENT_KEY_WRAP` under the item key. Not `Clone`; wiped on drop; `Debug` is redacted.
pub struct AttachmentKey {
    /// The 32 key bytes, heap-allocated and wiped on drop.
    key: Key32,
}

impl fmt::Debug for AttachmentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AttachmentKey([REDACTED])")
    }
}

impl AttachmentKey {
    /// A fresh attachment key from the injected CSPRNG.
    #[must_use]
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self {
            key: Key32::generate(rng),
        }
    }

    /// The key id, `HKDF(K, "key-id/symmetric")[0..16]` (§4.4): the `key_id` in the header of
    /// every chunk envelope under this key.
    ///
    /// # Errors
    /// [`DerivationError`] if HKDF fails, which it cannot for a 16-byte output.
    pub fn key_id(&self) -> Result<SymmetricKeyId, DerivationError> {
        self.key.key_id()
    }

    /// Seals chunk `index` of the attachment `at` laid out as `layout`: an `ATTACHMENT_CHUNK`
    /// envelope with a fresh nonce from `rng` and the context built from `at`, `index` and
    /// `layout.chunk_count()`.
    ///
    /// # Errors
    /// [`EncryptError::ContextMismatch`] if `index` is not below the chunk count;
    /// [`EncryptError::InvalidPlaintextLength`] if `plaintext` is not exactly
    /// [`AttachmentLayout::chunk_len`] bytes; any error of [`seal`].
    pub fn seal_chunk<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        at: &AttachmentRef,
        layout: AttachmentLayout,
        index: u32,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, EncryptError> {
        let (Some(ctx), Some(len)) = (at.chunk_ctx(layout, index), layout.chunk_len(index)) else {
            return Err(EncryptError::ContextMismatch);
        };
        if plaintext.len() != len {
            return Err(EncryptError::InvalidPlaintextLength);
        }
        seal(rng, &self.key, &ctx, plaintext)
    }

    /// Opens chunk `index` of the attachment `at` laid out as `layout`.
    ///
    /// The index and the envelope's exact length are checked against the layout before any
    /// crypto; then [`open`] runs the §9.5 checks and the commitment, which fails for a chunk of
    /// another index, attachment, item, vault or chunk count; then the plaintext length is
    /// checked again.
    ///
    /// # Errors
    /// [`DecryptError`] for every failure, which never says which check failed.
    pub fn open_chunk(
        &self,
        at: &AttachmentRef,
        layout: AttachmentLayout,
        index: u32,
        envelope: &[u8],
    ) -> Result<SecretBytes, DecryptError> {
        let (Some(ctx), Some(len)) = (at.chunk_ctx(layout, index), layout.chunk_len(index)) else {
            return Err(DecryptError);
        };
        if envelope.len() != len + CHUNK_OVERHEAD {
            return Err(DecryptError);
        }
        let plaintext = open(&self.key, &ctx, envelope)?;
        if plaintext.len() != len {
            return Err(DecryptError);
        }
        Ok(plaintext)
    }
}

impl ItemKey {
    /// Builds an `ATTACHMENT_KEY_WRAP`: the 32-byte attachment key under this item key, ctx
    /// `vault_id ‖ item_id ‖ attachment_id` (CRYPTO.md §8.4, ADR 0054 §3).
    ///
    /// Creating an attachment is a write under the item key, so the caller applies the writer
    /// rule first ([`ItemKey::is_stale`], §11.6): a stale item key is rotated before it wraps
    /// anything new.
    ///
    /// # Errors
    /// Any error of [`seal`].
    pub fn wrap_attachment_key<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        ctx: &AttachmentKeyWrapCtx,
        attachment_key: &AttachmentKey,
    ) -> Result<Vec<u8>, EncryptError> {
        seal(
            rng,
            self.key(),
            ctx,
            attachment_key.key.expose_secret().as_slice(),
        )
    }

    /// Opens an `ATTACHMENT_KEY_WRAP` with the ctx of the attachment it was fetched for. The
    /// caller picks this item key by the envelope's `key_id` (§11.6 reader rule): wraps are never
    /// re-wrapped, so an old item key may be the one that opens it.
    ///
    /// # Errors
    /// [`DecryptError`] for every failure.
    pub fn unwrap_attachment_key(
        &self,
        ctx: &AttachmentKeyWrapCtx,
        envelope: &[u8],
    ) -> Result<AttachmentKey, DecryptError> {
        let plaintext = open(self.key(), ctx, envelope)?;
        let key = Key32::from_slice(plaintext.expose_secret())?;
        Ok(AttachmentKey { key })
    }
}

#[cfg(test)]
impl AttachmentKey {
    /// The raw key bytes, for the vector generator and tests only.
    pub(crate) fn expose_for_tests(&self) -> &[u8; KEY_LEN] {
        self.key.expose_secret()
    }
}
