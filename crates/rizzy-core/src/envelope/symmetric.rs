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

/// `XChaCha20` nonce length.
pub const NONCE_LEN: usize = 24;
/// Key commitment length.
pub const COMMITMENT_LEN: usize = 32;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// Envelope overhead: header (18) + nonce (24) + commitment (32) + tag (16) = 90 bytes.
pub const OVERHEAD: usize = HEADER_LEN + NONCE_LEN + COMMITMENT_LEN + TAG_LEN;
/// M1 limit on the encrypted plaintext (after framing, for padded purposes): 16 MiB (§9.1).
/// Larger objects use the chunked algorithm `0x03` from M3.
pub const MAX_PLAINTEXT_LEN: usize = 16 * 1024 * 1024;

const OKM_LEN: usize = KEY_LEN + COMMITMENT_LEN;

/// Encrypts `plaintext` for a client purpose under `key`, with a fresh random nonce.
///
/// For a [`PlaintextRule::Padded`] purpose the plaintext is framed and padded first (§8.5); for
/// a [`PlaintextRule::Fixed`] purpose it must have exactly that length.
///
/// # Errors
/// [`EncryptError::InvalidPlaintextLength`], [`EncryptError::PlaintextTooLong`], or
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
/// # Errors
/// [`DecryptError`] for every failure.
pub fn server_open<C: ServerContext>(
    key: &Key32,
    ctx: &C,
    envelope: &[u8],
) -> Result<SecretBytes, DecryptError> {
    open_with(key, C::PURPOSE.server_decrypt_allow_list(), ctx, envelope)
}

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

/// `(k_enc, commitment) = (okm[0..32], okm[32..64])`.
fn split_okm(okm: &[u8; OKM_LEN]) -> Option<(&[u8; KEY_LEN], &[u8; COMMITMENT_LEN])> {
    let (k_enc, rest) = okm.split_first_chunk::<KEY_LEN>()?;
    let commitment = rest.first_chunk::<COMMITMENT_LEN>()?;
    Some((k_enc, commitment))
}

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
    out.extend_from_slice(&tag);
    Ok(core::mem::take(&mut *out))
}

fn open_with<C: Context>(
    key: &Key32,
    allow_list: &[AlgId],
    ctx: &C,
    envelope: &[u8],
) -> Result<SecretBytes, DecryptError> {
    // §9.5 steps 1–3: length, format version, algorithm allow-list.
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

// Compile-time checks of the §9.1 layout.
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
