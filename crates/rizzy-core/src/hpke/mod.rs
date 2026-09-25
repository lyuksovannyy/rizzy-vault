//! HPKE envelopes: algorithms `0x10` (Base mode) and `0x12` (PSK mode) (CRYPTO.md §9.2, §10.1;
//! ADR 0006 decision 9), the HPKE key types, and the HPKE PSK derivations (§4.3).
//!
//! ```text
//! header   = u8(0x01) ‖ u8(alg_id) ‖ key_id(recipient public key)            (18 bytes)
//! info     = LABEL("hpke") ‖ 0x00 ‖ u16(purpose)
//! aad      = header ‖ u16(purpose) ‖ ctx
//! enc, ct ‖ tag = HPKE.Seal(mode, pk_R, info, aad, plaintext [, psk, psk_id])
//! envelope = header ‖ enc (32) ‖ ct ‖ tag (16)                                (66 bytes overhead)
//! ```
//!
//! Suite: KEM `0x0020` DHKEM(X25519, HKDF-SHA256), KDF `0x0001` HKDF-SHA256, AEAD `0x0003`
//! `ChaCha20Poly1305`; `mode_base` for `0x10`, `mode_psk` for `0x12`. Never Auth or `AuthPSK`
//! (§10.1). hpke 0.14.1 is built without `getrandom`: every random value (the ephemeral key,
//! generated key pairs) comes from the injected RNG through the `*_with_rng` functions.
//!
//! **The purpose fixes the mode (§9.5 rule 2).** A PSK-mode purpose ([`HpkePskContext`]) can
//! only be sealed with [`seal_psk`] and opened with [`open_psk`], which require a PSK; a
//! Base-mode purpose ([`HpkeBaseContext`]) only with [`seal_base`] and [`open_base`]. On open,
//! the purpose's decrypt allow-list rejects the other mode's algorithm before any crypto, and
//! the algorithm must also match the mode of the function called. Base mode on a PSK purpose
//! would silently drop the PSK's protection, so it can never happen.
//!
//! **Checks on open (§9.5).** Length, `format_version`, the allow-list, then the key id: the
//! header's key id must be the id of the caller's own public key, derived with the key type the
//! purpose's recipient has ([`Purpose::hpke_recipient_key_type`]). A fixed-size purpose must
//! also have exactly its envelope length. Every failure is the same [`DecryptError`].
//!
//! **No commitment.** HPKE envelopes carry no separate key commitment: the key comes from a
//! Diffie-Hellman with the recipient's static key (plus a 256-bit PSK derived from a random key
//! in PSK mode), never from a password, so there is no partitioning oracle (§9.2). Authorship
//! comes from the signed `key-grant` ([`crate::sign::KeyGrant`]) where it matters.
//!
//! **KEM agility (§13 item 4).** The code dispatches on the [`Kem`] enum, chosen from the
//! algorithm id ([`suite`]), and the key types carry their KEM. M1 has only X25519; X-Wing
//! (`0x11`, `0x13`) adds a variant post-1.0.
//!
//! **Memory.** §9.2 names `single_shot_seal_with_rng` and `single_shot_open`. This module calls
//! their in-place forms, `single_shot_seal_inout_detached_with_rng` and
//! `single_shot_open_inout_detached`: the same setup and the same AEAD, so the bytes are
//! identical (a test checks both directions against the named calls), but the plaintext is
//! encrypted and decrypted inside one zeroizing buffer instead of an unwiped `Vec`. Limit:
//! hpke's key schedule and its HKDF state are not wiped by us (CRYPTO.md §12.2); X25519 secret
//! keys are (`x25519-dalek`'s `StaticSecret` is zeroize-on-drop in hpke's build).

use core::fmt;

use hpke::aead::{AeadTag, ChaCha20Poly1305};
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable as _, HpkeError, Kem as _, OpModeR, OpModeS, PskBundle, Serializable};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::envelope::parse::{self, ENC_LEN, EnvelopeRef, HPKE_OVERHEAD};
use crate::envelope::purpose::{AccountKeyDeviceGrantCtx, Side};
use crate::envelope::symmetric::{MAX_PLAINTEXT_LEN, TAG_LEN, finish_plaintext};
use crate::envelope::{
    AlgId, FORMAT_VERSION, HEADER_LEN, HpkeBaseContext, HpkeContext, HpkePskContext, PlaintextRule,
    Purpose, build_aad,
};
use crate::error::{DecryptError, EncryptError, ParseError};
use crate::ids::{ID_LEN, KeyType, PUBLIC_KEY_LEN, PublicKeyId};
use crate::keys::AccountKey;
use crate::labels::{self, Label};
use crate::secret::{Key32, SecretBytes};
use crate::{kdf, padding};

#[cfg(test)]
mod tests;

type X25519PrivateKey = <X25519HkdfSha256 as hpke::Kem>::PrivateKey;
type X25519PublicKey = <X25519HkdfSha256 as hpke::Kem>::PublicKey;
type X25519EncappedKey = <X25519HkdfSha256 as hpke::Kem>::EncappedKey;

/// Length of an X25519 secret key.
pub const X25519_SECRET_KEY_LEN: usize = 32;

/// The HPKE KEMs (§9.4). Only DHKEM(X25519, HKDF-SHA256) exists in M1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kem {
    /// DHKEM(X25519, HKDF-SHA256), KEM id `0x0020` (RFC 9180 §7.1).
    X25519HkdfSha256,
}

impl Kem {
    /// The RFC 9180 KEM id.
    #[must_use]
    pub const fn id(self) -> u16 {
        match self {
            Self::X25519HkdfSha256 => 0x0020,
        }
    }
}

/// The HPKE modes this crate uses (§10.1). Auth and `AuthPSK` do not exist here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    /// `mode_base` (0x00).
    Base,
    /// `mode_psk` (0x01).
    Psk,
}

/// The KEM and mode of an HPKE algorithm id, or `None` for anything that is not an implemented
/// HPKE algorithm (§9.4).
#[must_use]
pub const fn suite(alg: AlgId) -> Option<(Kem, Mode)> {
    match alg {
        AlgId::HpkeBaseX25519 => Some((Kem::X25519HkdfSha256, Mode::Base)),
        AlgId::HpkePskX25519 => Some((Kem::X25519HkdfSha256, Mode::Psk)),
        _ => None,
    }
}

/// The `psk_id` of each PSK-mode purpose: the PSK's derivation label itself (§4.3). `None` for
/// every other purpose.
#[must_use]
pub const fn psk_id_label(purpose: Purpose) -> Option<Label> {
    match purpose {
        Purpose::AccountKeyDeviceGrant => Some(labels::HPKE_PSK_DEVICE_GRANT),
        Purpose::PasswordVerifierGrant => Some(labels::HPKE_PSK_PASSWORD_VERIFIER),
        Purpose::PairingTransferSealed => Some(labels::HPKE_PSK_PAIRING),
        Purpose::ResyncTransfer => Some(labels::HPKE_PSK_RESYNC),
        _ => None,
    }
}

/// An HPKE recipient public key. Public: compares with `==` and prints as hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HpkePublicKey {
    kem: Kem,
    bytes: [u8; PUBLIC_KEY_LEN],
}

impl HpkePublicKey {
    /// An X25519 public key from its 32 bytes (RFC 7748). Every 32-byte string is accepted
    /// here; a small-order point fails when sealing ([`EncryptError::InvalidPublicKey`]).
    #[must_use]
    pub const fn x25519(bytes: [u8; PUBLIC_KEY_LEN]) -> Self {
        Self {
            kem: Kem::X25519HkdfSha256,
            bytes,
        }
    }

    /// The KEM this key belongs to.
    #[must_use]
    pub const fn kem(&self) -> Kem {
        self.kem
    }

    /// The encoded key: the 32-byte X25519 u-coordinate in M1.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.bytes
    }

    /// The public key id for a key of type `key_type` (§4.3).
    #[must_use]
    pub fn key_id(&self, key_type: KeyType) -> PublicKeyId {
        PublicKeyId::derive(key_type, &self.bytes)
    }
}

impl fmt::Debug for HpkePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HpkePublicKey({:?}, ", self.kem)?;
        self.bytes.iter().try_for_each(|b| write!(f, "{b:02x}"))?;
        f.write_str(")")
    }
}

enum SecretInner {
    X25519(X25519PrivateKey),
}

/// An HPKE recipient secret key, with its public key.
///
/// The X25519 secret lives in `x25519-dalek`'s `StaticSecret`, which is wiped on drop. No
/// `Clone`, `Copy` or `Display`; `Debug` is redacted.
pub struct HpkeSecretKey {
    secret: SecretInner,
    public: HpkePublicKey,
}

impl HpkeSecretKey {
    /// Generates an X25519 key pair from the injected CSPRNG:
    /// `<X25519HkdfSha256 as hpke::Kem>::gen_keypair_with_rng` (§10.1), which is RFC 9180's
    /// `DeriveKeyPair` over 32 random bytes.
    #[must_use]
    pub fn generate_x25519<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let (secret, public) = X25519HkdfSha256::gen_keypair_with_rng(&mut &mut *rng);
        Self {
            secret: SecretInner::X25519(secret),
            public: HpkePublicKey::x25519(x25519_public_bytes(&public)),
        }
    }

    /// Rebuilds an X25519 secret key from its 32 bytes, as stored inside `E_id`, `E_dev` or a
    /// `RETIRED_SECRET_KEY`. The caller wipes `bytes`.
    ///
    /// # Errors
    /// [`ParseError::InvalidLength`] (unreachable for a 32-byte input).
    pub fn from_x25519_bytes(bytes: &[u8; X25519_SECRET_KEY_LEN]) -> Result<Self, ParseError> {
        let secret = X25519PrivateKey::from_bytes(bytes).map_err(|_| ParseError::InvalidLength)?;
        let public = X25519HkdfSha256::sk_to_pk(&secret);
        Ok(Self {
            secret: SecretInner::X25519(secret),
            public: HpkePublicKey::x25519(x25519_public_bytes(&public)),
        })
    }

    /// The KEM this key belongs to.
    #[must_use]
    pub const fn kem(&self) -> Kem {
        self.public.kem
    }

    /// The public key.
    #[must_use]
    pub const fn public_key(&self) -> &HpkePublicKey {
        &self.public
    }

    /// Writes the 32 secret-key bytes into `out`, a buffer the caller wipes (an `E_id`,
    /// `E_dev` or `RETIRED_SECRET_KEY` plaintext).
    pub(crate) fn write_secret(&self, out: &mut [u8; X25519_SECRET_KEY_LEN]) {
        match &self.secret {
            SecretInner::X25519(secret) => secret.write_exact(out),
        }
    }
}

impl fmt::Debug for HpkeSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HpkeSecretKey({:?}, [REDACTED])", self.public.kem)
    }
}

fn x25519_public_bytes(public: &X25519PublicKey) -> [u8; PUBLIC_KEY_LEN] {
    let mut bytes = [0u8; PUBLIC_KEY_LEN];
    public.write_exact(&mut bytes);
    bytes
}

/// An HPKE pre-shared key for one PSK-mode purpose (§4.3, §10.1): 32 bytes derived from a key
/// the legitimate recipient already holds, never from a password. The `psk_id` is the
/// purpose's derivation label ([`psk_id_label`]).
///
/// A PSK is bound to the purpose it was derived for; sealing or opening another purpose with it
/// fails before any crypto.
pub struct HpkePsk {
    purpose: Purpose,
    psk: Key32,
}

impl HpkePsk {
    /// The device-grant PSK (§4.3):
    /// `HKDF(ikm = previous account key, salt = empty, info = LABEL("hpke-psk/device-grant") ‖
    /// 0x00 ‖ account_id ‖ u32(new account_key_epoch) ‖ recipient device_id, 32)`, with
    /// `psk_id = LABEL("hpke-psk/device-grant")`.
    ///
    /// The fields come from the grant's own context, so the PSK always matches it.
    ///
    /// # Errors
    /// [`EncryptError::ContextMismatch`] unless `previous_account_key` is the key of the epoch
    /// just before `ctx.account_key_epoch`; [`EncryptError::Internal`] (unreachable).
    pub fn device_grant(
        previous_account_key: &AccountKey,
        ctx: &AccountKeyDeviceGrantCtx,
    ) -> Result<Self, EncryptError> {
        if previous_account_key.epoch().checked_add(1) != Some(ctx.account_key_epoch) {
            return Err(EncryptError::ContextMismatch);
        }
        let mut info = Vec::with_capacity(2 * ID_LEN + 4);
        info.extend_from_slice(ctx.account_id.as_bytes());
        info.extend_from_slice(&ctx.account_key_epoch.to_be_bytes());
        info.extend_from_slice(ctx.recipient_device_id.as_bytes());
        let psk = Key32::try_init_with(|out| {
            kdf::hkdf_sha256(
                previous_account_key.key().expose_secret(),
                None,
                labels::HPKE_PSK_DEVICE_GRANT,
                &info,
                out,
            )
        })
        .map_err(|_| EncryptError::Internal)?;
        Ok(Self {
            purpose: Purpose::AccountKeyDeviceGrant,
            psk,
        })
    }

    /// The purpose this PSK belongs to.
    #[must_use]
    pub const fn purpose(&self) -> Purpose {
        self.purpose
    }

    /// `(psk, psk_id)` for hpke's `PskBundle`.
    fn parts(&self) -> Option<(&[u8], &[u8])> {
        let psk_id = psk_id_label(self.purpose)?;
        Some((self.psk.expose_secret().as_slice(), psk_id.as_bytes()))
    }

    #[cfg(test)]
    pub(crate) const fn secret(&self) -> &Key32 {
        &self.psk
    }
}

impl fmt::Debug for HpkePsk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HpkePsk({}, [REDACTED])", self.purpose.name())
    }
}

/// `info = LABEL("hpke") ‖ 0x00 ‖ u16(purpose)` (§9.2).
fn info(purpose: Purpose) -> Vec<u8> {
    labels::HPKE.info(&purpose.id().to_be_bytes())
}

/// The recipient key id a purpose puts in its header.
fn recipient_key_id(purpose: Purpose, recipient: &HpkePublicKey) -> Option<PublicKeyId> {
    Some(recipient.key_id(purpose.hpke_recipient_key_type()?))
}

/// Seals `plaintext` for a PSK-mode purpose (`0x12`) to `recipient`, with `psk`.
///
/// For a [`PlaintextRule::Fixed`] purpose the plaintext must have exactly that length; a
/// [`PlaintextRule::Padded`] purpose (M4) is framed first (§8.5).
///
/// # Errors
/// [`EncryptError::ContextMismatch`] if `psk` belongs to another purpose;
/// [`EncryptError::InvalidPublicKey`] for a small-order recipient key; the plaintext-rule
/// errors; [`EncryptError::Internal`] (unreachable).
pub fn seal_psk<C: HpkePskContext, R: CryptoRng + ?Sized>(
    rng: &mut R,
    recipient: &HpkePublicKey,
    psk: &HpkePsk,
    ctx: &C,
    plaintext: &[u8],
) -> Result<Vec<u8>, EncryptError> {
    if psk.purpose != C::PURPOSE {
        return Err(EncryptError::ContextMismatch);
    }
    seal_with(rng, recipient, Some(psk), ctx, plaintext)
}

/// Opens a PSK-mode envelope (`0x12`) with the recipient's secret key and `psk`, rebuilding
/// the AAD from `ctx`. A Base-mode envelope is rejected before any crypto.
///
/// # Errors
/// [`DecryptError`] for every failure.
pub fn open_psk<C: HpkePskContext>(
    recipient: &HpkeSecretKey,
    psk: &HpkePsk,
    ctx: &C,
    envelope: &[u8],
) -> Result<SecretBytes, DecryptError> {
    if psk.purpose != C::PURPOSE {
        return Err(DecryptError);
    }
    open_with(recipient, Some(psk), ctx, envelope)
}

/// Seals `plaintext` for a Base-mode purpose (`0x10`) to `recipient`.
///
/// # Errors
/// As [`seal_psk`], without the PSK check.
pub fn seal_base<C: HpkeBaseContext, R: CryptoRng + ?Sized>(
    rng: &mut R,
    recipient: &HpkePublicKey,
    ctx: &C,
    plaintext: &[u8],
) -> Result<Vec<u8>, EncryptError> {
    seal_with(rng, recipient, None, ctx, plaintext)
}

/// Opens a Base-mode envelope (`0x10`). A PSK-mode envelope is rejected before any crypto.
///
/// # Errors
/// [`DecryptError`] for every failure.
pub fn open_base<C: HpkeBaseContext>(
    recipient: &HpkeSecretKey,
    ctx: &C,
    envelope: &[u8],
) -> Result<SecretBytes, DecryptError> {
    open_with(recipient, None, ctx, envelope)
}

fn mode_of(psk: Option<&HpkePsk>) -> Mode {
    if psk.is_some() { Mode::Psk } else { Mode::Base }
}

fn seal_with<C: HpkeContext, R: CryptoRng + ?Sized>(
    rng: &mut R,
    recipient: &HpkePublicKey,
    psk: Option<&HpkePsk>,
    ctx: &C,
    plaintext: &[u8],
) -> Result<Vec<u8>, EncryptError> {
    let purpose = C::PURPOSE;
    let alg = purpose.encrypt_alg();
    if purpose.side() != Side::Client || suite(alg) != Some((recipient.kem(), mode_of(psk))) {
        return Err(EncryptError::UnsupportedPurpose);
    }
    let key_id = recipient_key_id(purpose, recipient).ok_or(EncryptError::UnsupportedPurpose)?;
    let psk_parts = match psk {
        Some(p) => Some(p.parts().ok_or(EncryptError::UnsupportedPurpose)?),
        None => None,
    };
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

    let header = header(alg, &key_id);
    let aad = build_aad(&header, ctx);
    let info = info(purpose);

    // One allocation at the final size: header, a placeholder for `enc`, then the plaintext,
    // encrypted in place. Wiped if anything fails before the ciphertext is complete.
    let mut out = Zeroizing::new(Vec::with_capacity(HPKE_OVERHEAD + body_len));
    out.extend_from_slice(&header);
    out.resize(HEADER_LEN + ENC_LEN, 0);
    match rule {
        PlaintextRule::Padded => padding::write_frame(&mut out, plaintext, body_len)
            .map_err(|_| EncryptError::PlaintextTooLong)?,
        _ => out.extend_from_slice(plaintext),
    }
    let (head, body) = out.split_at_mut(HEADER_LEN + ENC_LEN);
    let (enc, tag) = raw_seal_in_place(rng, recipient, psk_parts, &info, &aad, body)?;
    head.get_mut(HEADER_LEN..)
        .ok_or(EncryptError::Internal)?
        .copy_from_slice(&enc);
    out.extend_from_slice(&tag);
    Ok(core::mem::take(&mut *out))
}

fn open_with<C: HpkeContext>(
    recipient: &HpkeSecretKey,
    psk: Option<&HpkePsk>,
    ctx: &C,
    envelope: &[u8],
) -> Result<SecretBytes, DecryptError> {
    let purpose = C::PURPOSE;
    // §9.5 steps 1–3: length, format version, the purpose's allow-list.
    let EnvelopeRef::Hpke(env) =
        parse::parse_for_purpose(envelope, purpose.client_decrypt_allow_list())?
    else {
        return Err(DecryptError);
    };
    // Length rules of the purpose: exact for fixed-size plaintexts, the M1 bound otherwise.
    let plaintext_len_ok = match purpose.plaintext_rule() {
        PlaintextRule::Fixed(len) => env.ciphertext().len() == len,
        _ => env.ciphertext().len() <= MAX_PLAINTEXT_LEN,
    };
    // The algorithm must be the mode of the function called (§9.5 rule 2), and the KEM the
    // recipient key's.
    let mode_ok = suite(env.alg_id()) == Some((recipient.kem(), mode_of(psk)));
    if !plaintext_len_ok || !mode_ok {
        return Err(DecryptError);
    }
    // §9.5 step 4: the header names the caller's own public key.
    let expected_id = recipient_key_id(purpose, recipient.public_key()).ok_or(DecryptError)?;
    if env.key_id() != expected_id.as_bytes() {
        return Err(DecryptError);
    }
    let psk_parts = match psk {
        Some(p) => Some(p.parts().ok_or(DecryptError)?),
        None => None,
    };

    let aad = build_aad(env.header(), ctx);
    let info = info(purpose);
    let mut body = Zeroizing::new(env.ciphertext().to_vec());
    raw_open_in_place(
        recipient,
        psk_parts,
        env.enc(),
        &info,
        &aad,
        body.as_mut_slice(),
        env.tag(),
    )?;
    finish_plaintext(purpose.plaintext_rule(), body)
}

/// `format_version ‖ alg_id ‖ key_id`.
fn header(alg: AlgId, key_id: &PublicKeyId) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    let (prefix, id) = header.split_at_mut(2);
    prefix.copy_from_slice(&[FORMAT_VERSION, alg.to_u8()]);
    id.copy_from_slice(key_id.as_bytes());
    header
}

/// One HPKE single-shot seal in place (RFC 9180 §6.1). Returns `enc` and the tag. Crate-private
/// so the RFC 9180 vectors can run through exactly the code the envelope uses.
pub(crate) fn raw_seal_in_place<R: CryptoRng + ?Sized>(
    rng: &mut R,
    recipient: &HpkePublicKey,
    psk: Option<(&[u8], &[u8])>,
    info: &[u8],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<([u8; ENC_LEN], [u8; TAG_LEN]), EncryptError> {
    match recipient.kem() {
        Kem::X25519HkdfSha256 => {
            let pk_r = X25519PublicKey::from_bytes(recipient.as_bytes())
                .map_err(|_| EncryptError::InvalidPublicKey)?;
            let mode = match psk {
                None => OpModeS::Base,
                Some((psk, psk_id)) => {
                    OpModeS::Psk(PskBundle::new(psk, psk_id).map_err(|_| EncryptError::Internal)?)
                }
            };
            let (encapped, tag) =
                hpke::single_shot_seal_inout_detached_with_rng::<
                    ChaCha20Poly1305,
                    HkdfSha256,
                    X25519HkdfSha256,
                >(&mode, &pk_r, info, buffer.into(), aad, &mut &mut *rng)
                .map_err(|e| match e {
                    HpkeError::EncapError => EncryptError::InvalidPublicKey,
                    _ => EncryptError::Internal,
                })?;
            let mut enc = [0u8; ENC_LEN];
            encapped.write_exact(&mut enc);
            let mut tag_bytes = [0u8; TAG_LEN];
            tag.write_exact(&mut tag_bytes);
            Ok((enc, tag_bytes))
        }
    }
}

/// One HPKE single-shot open in place (RFC 9180 §6.1).
pub(crate) fn raw_open_in_place(
    recipient: &HpkeSecretKey,
    psk: Option<(&[u8], &[u8])>,
    enc: &[u8; ENC_LEN],
    info: &[u8],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), DecryptError> {
    #[cfg(test)]
    test_hooks::note_hpke_open();

    match &recipient.secret {
        SecretInner::X25519(sk_r) => {
            let encapped = X25519EncappedKey::from_bytes(enc).map_err(|_| DecryptError)?;
            let tag = AeadTag::<ChaCha20Poly1305>::from_bytes(tag).map_err(|_| DecryptError)?;
            let mode = match psk {
                None => OpModeR::Base,
                Some((psk, psk_id)) => {
                    OpModeR::Psk(PskBundle::new(psk, psk_id).map_err(|_| DecryptError)?)
                }
            };
            hpke::single_shot_open_inout_detached::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
                &mode,
                sk_r,
                &encapped,
                info,
                buffer.into(),
                aad,
                &tag,
            )
            .map_err(|_| DecryptError)
        }
    }
}

// The hpke types this module serialises have the sizes of the §9.2 layout.
const _: () = assert!(ENC_LEN == PUBLIC_KEY_LEN && TAG_LEN == 16);

/// Test-only instrumentation: counts how often an HPKE open (decapsulation and AEAD) is
/// reached, so tests can prove that the allow-list and key-id checks fail first.
#[cfg(test)]
pub(crate) mod test_hooks {
    use std::cell::Cell;

    std::thread_local! {
        static HPKE_OPENS: Cell<usize> = const { Cell::new(0) };
    }

    pub(crate) fn note_hpke_open() {
        HPKE_OPENS.with(|c| c.set(c.get() + 1));
    }

    /// HPKE openings attempted on this thread so far.
    pub(crate) fn hpke_opens() -> usize {
        HPKE_OPENS.with(Cell::get)
    }
}
