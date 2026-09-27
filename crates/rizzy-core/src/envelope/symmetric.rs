//! Symmetric envelope, algorithm `0x01` (CRYPTO.md §8.3, §9.1; ADR 0005, ADR 0007).
//!
//! XChaCha20-Poly1305 inside Bellare–Hoang's `UtC` transform with the AAD folded into the
//! committing PRF (`UtC` + `HtE`), instantiated with HKDF-SHA-256:
//!
//! ```text
//! header     = u8(0x01) ‖ u8(0x01) ‖ key_id(K)                     (18 bytes)
//! aad        = header ‖ u16(purpose) ‖ ctx
//! okm        = HKDF(ikm = K, salt = nonce,
//!                   info = LABEL("envelope/xchacha20poly1305") ‖ 0x00 ‖ aad, 64)
//! k_enc      = okm[0..32]
//! commitment = okm[32..64]
//! ct ‖ tag   = XChaCha20-Poly1305.Encrypt(key = k_enc, nonce, aad, plaintext)
//! envelope   = header ‖ nonce ‖ commitment ‖ ct ‖ tag              (90 bytes overhead)
//! ```
//!
//! Decryption parses strictly and runs the §9.5 checks (length, version, allow-list, key id),
//! recomputes `okm`, compares the commitment with `ct_eq` and returns [`DecryptError`]
//! **without running the AEAD** if it differs, then opens the AEAD. Every failure is the same
//! [`DecryptError`].
//!
//! The 24-byte nonce is drawn here from the injected CSPRNG; no function accepts a nonce
//! (INV-12). Plaintext rules (§8.5) are applied here too: padded purposes are framed on seal
//! and unframed on open, and fixed-size purposes (key wraps) must have exactly their size.
//!
//! # Sealing, step by step
//!
//! 1. Check that the purpose encrypts with `0x01` and belongs to the caller's side (client or
//!    server-only), and work out the AEAD plaintext length from the plaintext rule: exact for
//!    fixed-size purposes, `padded_len` for padded ones. Refuse anything over 16 MiB.
//! 2. Build the header from the key's own id, and `aad` from the header and the context.
//! 3. Draw the nonce, derive `okm`, split it into `k_enc` and `commitment`.
//! 4. Write `header ‖ nonce ‖ commitment ‖ plaintext` (or its frame) into one buffer of the
//!    final size, encrypt the plaintext part in place, and append the tag.
//!
//! # Opening, step by step
//!
//! 1. [`parse::parse_for_purpose`]: length, `format_version`, and `alg_id` against the
//!    purpose's allow-list for the caller's side.
//! 2. The header's key id must equal the id of the caller's key (compared with `ct_eq`).
//! 3. Rebuild `aad` from the envelope's header and the caller's context, recompute `okm`, and
//!    compare the commitment with `ct_eq`. A mismatch ends here, before the AEAD.
//! 4. Open the AEAD in place in a zeroizing copy of the ciphertext.
//! 5. Apply the plaintext rule: check the exact size of a fixed-size purpose, or unframe a
//!    padded one strictly.
//!
//! # Properties
//!
//! - **Commitment** (§8.3): the commitment covers `(K, nonce, aad)`. A second key, or another
//!   AAD under the same key, gives the same 256-bit value only through an HMAC-SHA-256
//!   collision (about 128-bit commitment security). Short of such a collision, and because
//!   decryption is deterministic, an envelope opens under at most one key and context, to at
//!   most one plaintext (INV-11; CMT-4 reached through CMT-3 in Bellare–Hoang's terms, a claim
//!   the M8 audit is to confirm). This removes partitioning oracles on password-derived keys
//!   such as `local_unlock_key` and the export file key.
//! - **Nonce collisions** (§8.2): the AEAD key `k_enc` is derived from `(K, nonce, aad)`, so a
//!   repeated nonce under the same key repeats the AEAD key and nonce only for that pair of
//!   envelopes, and only when their AAD is equal too.
//! - **One error**: the key-id mismatch, the commitment mismatch and the tag failure all return
//!   the same [`DecryptError`], and the comparisons are constant-time (§12.3).
//! - **Memory**: every buffer this module writes plaintext into is zeroizing and allocated at
//!   its final size, and `okm` (holding `k_enc`) is wiped on drop, as is the AEAD instance's
//!   copy of `k_enc` (`chacha20poly1305`'s `zeroize` feature). The caller's own plaintext
//!   input is the caller's to wipe. Limit: hkdf 0.13 does not wipe its own internal state
//!   (CRYPTO.md §12.2).
//! - **Not provided**: authorship and freshness. Anyone with `K` can seal, and an older envelope
//!   with the same context opens again ([`crate::envelope`] module docs).
//!
//! The construction is our composition and an M8 audit target (CRYPTO.md §1 rule 2.1).

use chacha20poly1305::{AeadInOut as _, KeyInit as _, Tag, XChaCha20Poly1305, XNonce};
use rand_core::CryptoRng;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use super::parse::{self, EnvelopeRef};
use super::purpose::{Context, PlaintextRule, ServerContext, Side, SymmetricContext};
use super::{AlgId, FORMAT_VERSION, HEADER_LEN, build_aad};
use crate::error::{DecryptError, EncryptError};
use crate::ids::ID_LEN;
use crate::secret::{KEY_LEN, Key32, SecretBytes};
use crate::{kdf, labels, padding};

/// `XChaCha20` nonce length: 192 bits, random per envelope (§8.2).
pub const NONCE_LEN: usize = 24;
/// Key commitment length: `okm[32..64]` (§8.3).
pub const COMMITMENT_LEN: usize = 32;
/// Poly1305 tag length. The HPKE envelope's `ChaCha20Poly1305` tag has the same length and
/// shares this constant.
pub const TAG_LEN: usize = 16;
/// Envelope overhead: header (18) + nonce (24) + commitment (32) + tag (16) = 90 bytes.
pub const OVERHEAD: usize = HEADER_LEN + NONCE_LEN + COMMITMENT_LEN + TAG_LEN;
/// M1 limit on the encrypted plaintext (after framing, for padded purposes): 16 MiB (§9.1).
/// Larger objects use the chunked algorithm `0x03` from M3. The HPKE envelope applies the same
/// limit (§9.2).
pub const MAX_PLAINTEXT_LEN: usize = 16 * 1024 * 1024;

/// HKDF output length: `k_enc` (32) followed by `commitment` (32).
const OKM_LEN: usize = KEY_LEN + COMMITMENT_LEN;

/// Encrypts `plaintext` for a client purpose under `key`, with a fresh random nonce.
///
/// For a [`PlaintextRule::Padded`] purpose the plaintext is framed and padded first (§8.5); for
/// a [`PlaintextRule::Fixed`] purpose it must have exactly that length.
///
/// The context type fixes the purpose, and its fields must be the values the reader will
/// rebuild from where it expects the object; any other value makes the envelope unopenable
/// there. `key` must be the key §8.4 names for that purpose; its id goes into the header. The
/// plaintext is encrypted in place in the output buffer, which is wiped if sealing fails part
/// way; on success it holds only ciphertext and public header values and is returned.
///
/// # Errors
/// [`EncryptError::InvalidPlaintextLength`], [`EncryptError::PlaintextTooLong`],
/// [`EncryptError::UnsupportedPurpose`] (unreachable for the context types that exist: all of
/// them are `0x01` client purposes with a defined plaintext rule), or
/// [`EncryptError::Internal`] (unreachable).
pub fn seal<C: SymmetricContext, R: CryptoRng + ?Sized>(
    rng: &mut R,
    key: &Key32,
    ctx: &C,
    plaintext: &[u8],
) -> Result<Vec<u8>, EncryptError> {
    seal_with(rng, key, Side::Client, ctx, plaintext)
}

/// Decrypts a client-purpose envelope under `key`, rebuilding the AAD from `ctx`.
///
/// Returns the plaintext (unframed for padded purposes) in a zeroizing buffer.
///
/// Build `ctx` from where the object was expected (the ids, epochs and hashes the caller
/// already trusts), never from fields that travelled with the envelope. Only the client
/// allow-list of the purpose is consulted, so a server-only envelope never opens here. A
/// successful open proves that the envelope was sealed under `key` for exactly this purpose
/// and context; it does not prove who sealed it or that it is the latest version.
///
/// # Errors
/// [`DecryptError`] for every failure, without saying which check failed.
pub fn open<C: SymmetricContext>(
    key: &Key32,
    ctx: &C,
    envelope: &[u8],
) -> Result<SecretBytes, DecryptError> {
    open_with(key, C::PURPOSE.client_decrypt_allow_list(), ctx, envelope)
}

/// Encrypts a server-only purpose (§5.11) under a server data subkey or the server-secrets
/// backup key. Server code only.
///
/// Same construction as [`seal`]; only the purpose range differs (`0x0100`–`0x01FF`). This is
/// not zero-knowledge encryption: it protects rows from a reader of the database alone, not
/// from someone who also holds the server secrets file (§5.11). [`crate::server_seal`] wraps
/// it with the key derivations.
///
/// # Errors
/// As [`seal`].
pub fn server_seal<C: ServerContext, R: CryptoRng + ?Sized>(
    rng: &mut R,
    key: &Key32,
    ctx: &C,
    plaintext: &[u8],
) -> Result<Vec<u8>, EncryptError> {
    seal_with(rng, key, Side::Server, ctx, plaintext)
}

/// Decrypts a server-only purpose (§5.11) against the server's allow-list table. Server code
/// only.
///
/// The server's table is non-empty only for server-only purposes, so the server cannot open a
/// client purpose through this function even with the right key.
///
/// # Errors
/// [`DecryptError`] for every failure.
pub fn server_open<C: ServerContext>(
    key: &Key32,
    ctx: &C,
    envelope: &[u8],
) -> Result<SecretBytes, DecryptError> {
    open_with(key, C::PURPOSE.server_decrypt_allow_list(), ctx, envelope)
}

/// Builds the `0x01` header `u8(0x01) ‖ u8(0x01) ‖ key_id(K)`, with the key id derived from
/// `key` itself (§4.4), so the header always names the key that sealed the envelope.
///
/// # Errors
/// [`EncryptError::Internal`] if the key-id HKDF fails (unreachable for its fixed length).
fn header_for(key: &Key32) -> Result<[u8; HEADER_LEN], EncryptError> {
    let key_id = key.key_id()?;
    let mut header = [0u8; HEADER_LEN];
    let (prefix, id) = header.split_at_mut(2);
    prefix.copy_from_slice(&[FORMAT_VERSION, AlgId::XChaCha20Poly1305Committed.to_u8()]);
    id.copy_from_slice(key_id.as_bytes());
    Ok(header)
}

/// `okm = HKDF(K, salt = nonce, LABEL("envelope/xchacha20poly1305") ‖ 0x00 ‖ aad, 64)`,
/// returned as a wiped-on-drop buffer.
///
/// This is the committing PRF of `UtC` + `HtE` (§8.3): the nonce is the HKDF salt and the whole
/// AAD is in `info`, so both the AEAD key and the commitment depend on `(K, nonce, aad)`.
///
/// # Errors
/// [`DerivationError`](crate::error::DerivationError), unreachable for the fixed 64-byte
/// output.
fn derive_okm(
    key: &Key32,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
) -> Result<Zeroizing<[u8; OKM_LEN]>, crate::error::DerivationError> {
    #[cfg(test)]
    test_hooks::note_okm();
    let mut okm = Zeroizing::new([0u8; OKM_LEN]);
    kdf::hkdf_sha256(
        key.expose_secret(),
        Some(nonce),
        labels::ENVELOPE_XCHACHA20POLY1305,
        aad,
        okm.as_mut_slice(),
    )?;
    Ok(okm)
}

/// `(k_enc, commitment) = (okm[0..32], okm[32..64])`. Both borrow from `okm`, so no copy of
/// `k_enc` outlives the zeroizing buffer. Never `None` for a 64-byte input; the `Option` only
/// avoids a panic path.
fn split_okm(okm: &[u8; OKM_LEN]) -> Option<(&[u8; KEY_LEN], &[u8; COMMITMENT_LEN])> {
    let (k_enc, rest) = okm.split_first_chunk::<KEY_LEN>()?;
    let commitment = rest.first_chunk::<COMMITMENT_LEN>()?;
    Some((k_enc, commitment))
}

/// The seal path shared by [`seal`] (client) and [`server_seal`] (server-only).
///
/// `side` is the caller's table: a purpose of the other side, or one that does not encrypt
/// with `0x01`, is refused. The context types already make that impossible; this check keeps
/// the rule local to the function that encrypts.
///
/// # Errors
/// [`EncryptError::UnsupportedPurpose`] for a purpose of another algorithm or side, or with an
/// unspecified plaintext rule; [`EncryptError::InvalidPlaintextLength`] for a fixed-size
/// purpose given another length; [`EncryptError::PlaintextTooLong`] when the (framed)
/// plaintext exceeds [`MAX_PLAINTEXT_LEN`]; [`EncryptError::Internal`] (unreachable).
fn seal_with<C: Context, R: CryptoRng + ?Sized>(
    rng: &mut R,
    key: &Key32,
    side: Side,
    ctx: &C,
    plaintext: &[u8],
) -> Result<Vec<u8>, EncryptError> {
    let purpose = C::PURPOSE;
    if purpose.encrypt_alg() != AlgId::XChaCha20Poly1305Committed || purpose.side() != side {
        return Err(EncryptError::UnsupportedPurpose);
    }
    let rule = purpose.plaintext_rule();
    // `body_len` is the AEAD plaintext length: the plaintext itself, or its whole frame for a
    // padded purpose. The 16 MiB limit applies to it (§8.5 "Size limit", §9.1).
    let body_len = match rule {
        PlaintextRule::Fixed(len) if plaintext.len() == len => len,
        PlaintextRule::Fixed(_) => return Err(EncryptError::InvalidPlaintextLength),
        PlaintextRule::Padded => {
            padding::padded_len(plaintext.len()).map_err(|_| EncryptError::PlaintextTooLong)?
        }
        PlaintextRule::Unpadded => plaintext.len(),
        PlaintextRule::Unspecified => return Err(EncryptError::UnsupportedPurpose),
    };
    if body_len > MAX_PLAINTEXT_LEN {
        return Err(EncryptError::PlaintextTooLong);
    }

    let header = header_for(key)?;
    let aad = build_aad(&header, ctx);
    // A fresh 192-bit nonce from the injected CSPRNG for every envelope (§8.2, INV-12).
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let okm = derive_okm(key, &nonce, &aad)?;
    let (k_enc, commitment) = split_okm(&okm).ok_or(EncryptError::Internal)?;
    let cipher = XChaCha20Poly1305::new_from_slice(k_enc).map_err(|_| EncryptError::Internal)?;

    // One allocation at the final size. The plaintext is written into it and encrypted in
    // place, and the buffer is wiped if anything fails before the ciphertext is complete.
    let mut out = Zeroizing::new(Vec::with_capacity(OVERHEAD + body_len));
    out.extend_from_slice(&header);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(commitment);
    let body_start = out.len();
    match rule {
        PlaintextRule::Padded => padding::write_frame(&mut out, plaintext, body_len)
            .map_err(|_| EncryptError::PlaintextTooLong)?,
        _ => out.extend_from_slice(plaintext),
    }
    let body = out.get_mut(body_start..).ok_or(EncryptError::Internal)?;
    let tag = cipher
        .encrypt_inout_detached(&XNonce::from(nonce), &aad, body.into())
        .map_err(|_| EncryptError::Internal)?;
    // The tag fills the last 16 bytes of the reserved capacity, so this does not reallocate.
    out.extend_from_slice(&tag);
    // The buffer now holds only ciphertext; move it out of its zeroizing wrapper.
    Ok(core::mem::take(&mut *out))
}

/// The open path shared by [`open`] (client table) and [`server_open`] (server table).
///
/// `allow_list` is the purpose's decrypt allow-list for the caller's side; an empty list (the
/// other side's purpose) rejects everything at the first check.
///
/// # Errors
/// [`DecryptError`] for every failure: parsing, the §9.5 checks, the key id, the commitment,
/// the tag and the plaintext rule.
fn open_with<C: Context>(
    key: &Key32,
    allow_list: &[AlgId],
    ctx: &C,
    envelope: &[u8],
) -> Result<SecretBytes, DecryptError> {
    // §9.5 steps 1–3: length, format version, algorithm allow-list. Every symmetric
    // allow-list is `{0x01}`, so the HPKE arm cannot occur; it is rejected all the same.
    let EnvelopeRef::Symmetric(env) = parse::parse_for_purpose(envelope, allow_list)? else {
        return Err(DecryptError);
    };
    // §9.5 step 4: the key id must be the id of the key the caller holds.
    let key_id = key.key_id()?;
    let key_id_matches: bool = key_id.as_bytes().ct_eq(env.key_id()).into();
    if !key_id_matches {
        return Err(DecryptError);
    }
    // §8.3: recompute okm over the AAD the reader rebuilt, and check the commitment in
    // constant time before the AEAD runs.
    let aad = build_aad(env.header(), ctx);
    let okm = derive_okm(key, env.nonce(), &aad)?;
    let (k_enc, commitment) = split_okm(&okm).ok_or(DecryptError)?;
    let commitment_matches: bool = env.commitment().ct_eq(commitment).into();
    if !commitment_matches {
        return Err(DecryptError);
    }

    #[cfg(test)]
    test_hooks::note_aead_open();

    let cipher = XChaCha20Poly1305::new_from_slice(k_enc).map_err(|_| DecryptError)?;
    // Decrypt in place in a zeroizing copy of exactly the ciphertext's size: the plaintext
    // never sits in an unwiped buffer, whether the tag check passes or fails.
    let mut body = Zeroizing::new(env.ciphertext().to_vec());
    cipher
        .decrypt_inout_detached(
            &XNonce::from(*env.nonce()),
            &aad,
            body.as_mut_slice().into(),
            &Tag::from(*env.tag()),
        )
        .map_err(|_| DecryptError)?;
    finish_plaintext(C::PURPOSE.plaintext_rule(), body)
}

/// Applies the purpose's plaintext rule to an authenticated plaintext. Shared with the HPKE
/// envelope ([`crate::hpke`]).
///
/// - [`PlaintextRule::Fixed`]: the length must match exactly (§8.5 "Key-wrap envelopes"). For
///   the symmetric envelope this is the first place the fixed length is checked on open; the
///   HPKE envelope also checks it before any crypto.
/// - [`PlaintextRule::Unpadded`]: returned as is.
/// - [`PlaintextRule::Padded`]: unframed strictly ([`padding::unframe`]); `data` is copied into
///   a new buffer of exactly its size, and the frame buffer is wiped when `body` drops.
/// - [`PlaintextRule::Unspecified`]: never opens.
///
/// # Errors
/// [`DecryptError`] for a wrong fixed length, a malformed frame, or an unspecified rule.
pub(crate) fn finish_plaintext(
    rule: PlaintextRule,
    body: Zeroizing<Vec<u8>>,
) -> Result<SecretBytes, DecryptError> {
    match rule {
        PlaintextRule::Fixed(len) if body.len() == len => Ok(SecretBytes::from_zeroizing(body)),
        PlaintextRule::Unpadded => Ok(SecretBytes::from_zeroizing(body)),
        PlaintextRule::Padded => Ok(SecretBytes::copy_from_slice(padding::unframe(&body)?)),
        PlaintextRule::Fixed(_) | PlaintextRule::Unspecified => Err(DecryptError),
    }
}

// Compile-time checks of the §9.1 layout: 90 bytes of overhead, and a header of the two
// one-byte fields plus a 16-byte key id.
const _: () = assert!(OVERHEAD == 90);
const _: () = assert!(HEADER_LEN == 2 + ID_LEN);

/// Test-only instrumentation: counts how often the AEAD is reached, so tests can prove the
/// commitment check fails first, and how often the envelope subkey and commitment are derived,
/// so tests can prove the §9.5 checks fail before any crypto (CRYPTO.md §15 item 4).
#[cfg(test)]
pub(crate) mod test_hooks {
    use std::cell::Cell;

    std::thread_local! {
        static AEAD_OPENS: Cell<usize> = const { Cell::new(0) };
        static OKM_DERIVATIONS: Cell<usize> = const { Cell::new(0) };
    }

    pub(crate) fn note_aead_open() {
        AEAD_OPENS.with(|c| c.set(c.get() + 1));
    }

    /// AEAD openings attempted on this thread so far.
    pub(crate) fn aead_opens() -> usize {
        AEAD_OPENS.with(Cell::get)
    }

    pub(crate) fn note_okm() {
        OKM_DERIVATIONS.with(|c| c.set(c.get() + 1));
    }

    /// `okm` derivations (the commitment HKDF) on this thread so far.
    pub(crate) fn okm_derivations() -> usize {
        OKM_DERIVATIONS.with(Cell::get)
    }
}
