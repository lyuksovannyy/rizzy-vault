//! `ACCOUNT_KEY_DEVICE_GRANT`: the new account key sealed to a remaining device after a
//! rotation (CRYPTO.md §8.4, §10.1, §11.3 step 4, §11.6 step 6).
//!
//! - HPKE PSK mode (`0x12`) to the recipient device's X25519 key, with the device-grant PSK
//!   derived from the **previous** account key, which every remaining device holds and a new
//!   epoch's attacker does not ([`crate::hpke::HpkePsk::device_grant`]).
//! - ctx `account_id ‖ u32 account_key_epoch (new) ‖ sender device_id ‖ recipient device_id`.
//! - Signed as a `key-grant` ([`KeyGrant`]) by the rotating device's key, or by the identity
//!   key when the rotating client is a web vault (kind 4, §10.1).
//!
//! The recipient checks that the signing key belongs to the sender the AAD names: a
//! certificate of the account for that `device_id` (it may since have been revoked), or the
//! identity key for a grant from a kind-4 client. The key the **last** grant of a chain
//! delivers must then have the id `state.account_key_id`
//! ([`crate::sign::AccountState::matches_account_key`]); that check is the caller's, because
//! it needs the verified state.
//!
//! **Sealing, step by step** ([`seal_account_key_device_grant`]).
//! 1. The context's epoch must be the new key's, and the recipient certificate must be this
//!    account's durable device named as `recipient_device_id`.
//! 2. Derive the device-grant PSK from the previous account key, which must be of the epoch
//!    just before the new one:
//!    `HKDF(previous key, LABEL("hpke-psk/device-grant") ‖ 0x00 ‖ account_id ‖ u32 new epoch ‖
//!    recipient device_id)`, `psk_id = LABEL("hpke-psk/device-grant")` (§4.3).
//! 3. HPKE-seal the 32-byte new key to the certificate's X25519 key in PSK mode, with the
//!    context in the AAD and a fresh ephemeral key from the injected CSPRNG (§9.2).
//! 4. Sign `LABEL("sig/key-grant") ‖ 0x00 ‖ u16(1) ‖ u16(purpose) ‖ sender key id ‖ recipient
//!    key id ‖ bytes(envelope)` with the rotating device's key or, from a web vault, the
//!    identity key (§10.1).
//!
//! **Opening, step by step** ([`open_account_key_device_grant`]): the epochs; the sender
//! certificate against the AAD's sender; the signature, the signer's role and the purpose; the
//! recipient key id against this device's X25519 key; only then the HPKE open with the PSK. The
//! delivered key gets the epoch the context names. A device several rotations behind opens its
//! grants in epoch order, each with the key the previous grant delivered (§10.1).
//!
//! **What this defends against.** A database snapshot plus a future quantum computer breaks the
//! X25519 half but still lacks the PSK. A revoked device knows the previous account key but not
//! the recipient's X25519 secret, which never leaves that device (`E_dev` is device-local).
//! Stripping the signature and re-signing with another key fails: the signer must match the
//! certificate for the sender the AAD names, and the AAD itself is bound into the HPKE
//! envelope. A grant cannot be redirected: the recipient key id is in the envelope header,
//! which is AAD, and in the signed message.
//!
//! **What it does not do.** Sealing does not check that the signer is the device the context
//! names as `sender_device_id`; the rotating client passes its own key and id, and a mismatch
//! makes every recipient reject the grant. For [`GrantSender::Identity`] there is no
//! certificate to compare with the AAD's sender: the caller decides that the grant comes from a
//! kind-4 client. The final `account_key_id` check, persisting the re-wrapped `E_local`, `E_ks`
//! and `E_dev`, and acknowledging the grant are the caller's (§11.3 step 4). A compromised
//! revoked device that still holds the old identity key can race its own rotation; the
//! `account_key_id` check and the user's fingerprint confirmation are the controls (§11.6
//! "Known limitation").

use core::fmt;

use rand_core::CryptoRng;

use super::{AccountKey, DeviceKeys};
use crate::envelope::Purpose;
use crate::envelope::purpose::AccountKeyDeviceGrantCtx;
use crate::error::{DecryptError, EncryptError, SignError, VerifyError};
use crate::hpke::{self, HpkePsk};
use crate::secret::Key32;
use crate::sign::{
    DeviceCertificate, DeviceSigningKey, IdentitySigningKey, IdentityVerifyingKey, KeyGrant,
    Verified,
};

/// Who signs a device grant.
///
/// `key-grant` accepts exactly these two signer roles for `ACCOUNT_KEY_DEVICE_GRANT` (§10.2);
/// the statement layer refuses any other pairing of purpose and role.
#[derive(Clone, Copy, Debug)]
pub enum GrantSigner<'a> {
    /// The rotating device's own key (kinds 1–3).
    Device(&'a DeviceSigningKey),
    /// The identity key of the current `identity_epoch`, when the rotating client is a web
    /// vault (kind 4, §10.1).
    Identity(&'a IdentitySigningKey),
}

/// Who the recipient expects to have signed a device grant.
///
/// The recipient picks this from the grant's context: the verified certificate of the account
/// for `ctx.sender_device_id`, or, for a grant from a kind-4 client, the identity key of the
/// current `identity_epoch` (§11.3 step 4).
#[derive(Clone, Copy, Debug)]
pub enum GrantSender<'a> {
    /// A verified certificate of the account for the sender `device_id` in the AAD, which may
    /// since have been revoked (§11.3 step 4.2). Must be a durable device (kinds 1–3).
    Device(&'a Verified<DeviceCertificate>),
    /// The identity key of the current `identity_epoch`: a grant from a kind-4 client.
    Identity(&'a IdentityVerifyingKey),
}

/// A device grant could not be made or accepted.
///
/// The variants are distinguished for the caller's logs and UI; none carries key material or
/// plaintext. Every failure inside the HPKE open is the single [`GrantError::Decrypt`], so the
/// opening side gives no "which check failed" oracle about the ciphertext (§9.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GrantError {
    /// The context does not fit the keys: the new key's epoch is not the context's, or the
    /// previous key is not of the epoch before it.
    EpochMismatch,
    /// Sealing: the recipient certificate is not the device the context names, or not a
    /// durable device. Opening: the grant is addressed to another X25519 key than this
    /// device's.
    WrongRecipient,
    /// The sender certificate is not the device the context names, or not a durable device.
    WrongSender,
    /// Sealing failed.
    Encrypt(EncryptError),
    /// Signing failed.
    Sign(SignError),
    /// The `key-grant` signature or statement did not verify, was made by a key other than the
    /// expected sender's or of a role not allowed for the purpose, or carries another purpose.
    Verify(VerifyError),
    /// The HPKE envelope did not open, or its plaintext is not a 32-byte key.
    Decrypt,
}

impl fmt::Display for GrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EpochMismatch => f.write_str("device grant epochs do not match the keys"),
            Self::WrongRecipient => f.write_str("device grant recipient does not match"),
            Self::WrongSender => f.write_str("device grant sender does not match"),
            Self::Encrypt(e) => write!(f, "device grant sealing failed: {e}"),
            Self::Sign(e) => write!(f, "device grant signing failed: {e}"),
            Self::Verify(e) => write!(f, "device grant signature invalid: {e}"),
            Self::Decrypt => f.write_str("device grant did not open"),
        }
    }
}

impl core::error::Error for GrantError {}

/// Seals `new_account_key` to the recipient device and signs the grant (§11.6 step 6).
///
/// `recipient` is the recipient's verified certificate: its X25519 key is the HPKE recipient,
/// and it must be the durable device `ctx.recipient_device_id` of `ctx.account_id`. Returns
/// the signed `key-grant` wire bytes, which carry the HPKE envelope.
///
/// Call it once per remaining device (every durable device in the new device set other than
/// the rotating one), with `ctx.sender_device_id` set to the rotating client's own device id and
/// `signer` to its own key (the identity key from a web vault). `previous_account_key` must be
/// the key of the epoch just before `new_account_key`'s. The ephemeral HPKE key comes from
/// `rng`.
///
/// # Errors
/// [`GrantError`].
pub fn seal_account_key_device_grant<R: CryptoRng + ?Sized>(
    rng: &mut R,
    ctx: &AccountKeyDeviceGrantCtx,
    new_account_key: &AccountKey,
    previous_account_key: &AccountKey,
    recipient: &Verified<DeviceCertificate>,
    signer: GrantSigner<'_>,
) -> Result<Vec<u8>, GrantError> {
    if ctx.account_key_epoch != new_account_key.epoch() {
        return Err(GrantError::EpochMismatch);
    }
    if recipient.account_id != ctx.account_id
        || recipient.device_id != ctx.recipient_device_id
        || !recipient.in_device_set()
    {
        return Err(GrantError::WrongRecipient);
    }
    // The PSK derivation also checks that the previous key is of the epoch before
    // `ctx.account_key_epoch`; that refusal surfaces as `EpochMismatch`.
    let psk = HpkePsk::device_grant(previous_account_key, ctx).map_err(|e| match e {
        EncryptError::ContextMismatch => GrantError::EpochMismatch,
        other => GrantError::Encrypt(other),
    })?;
    let envelope = hpke::seal_psk(
        rng,
        &recipient.device_x25519,
        &psk,
        ctx,
        new_account_key.key().expose_secret(),
    )
    .map_err(GrantError::Encrypt)?;
    // Sign the envelope as a `key-grant`; the recipient key id is read back from the envelope
    // header, and the sender key id is the signer's.
    let purpose = Purpose::AccountKeyDeviceGrant;
    match signer {
        GrantSigner::Device(key) => KeyGrant::sign(purpose, key, &envelope),
        GrantSigner::Identity(key) => KeyGrant::sign(purpose, key, &envelope),
    }
    .map_err(GrantError::Sign)
}

/// Verifies and opens a signed device grant (§11.3 step 4).
///
/// Checks, in order: the epochs; that `sender` is the sender the AAD names (for a
/// certificate: account, `device_id`, durable kind); the `key-grant` signature and purpose;
/// that the grant is addressed to this device's X25519 key; then opens the HPKE envelope with
/// the device X25519 key and the device-grant PSK from `previous_account_key`. The delivered
/// key gets the epoch `ctx` names.
///
/// `signed_grant` is untrusted server data; the statement layer parses it with size limits
/// before checking its signature. Rebuild `ctx` from this device's own `device_id` as
/// recipient, the account, the epoch being opened, and the sender id the grant's locator
/// names; a lying locator makes the sender check, the signature check or the HPKE open fail.
/// The returned key is not yet trusted: for the last grant of a chain, compare it with
/// `state.account_key_id` ([`crate::sign::AccountState::matches_account_key`]) and stay
/// read-only on a mismatch.
///
/// # Errors
/// [`GrantError`].
pub fn open_account_key_device_grant(
    signed_grant: &[u8],
    ctx: &AccountKeyDeviceGrantCtx,
    recipient: &DeviceKeys,
    previous_account_key: &AccountKey,
    sender: GrantSender<'_>,
) -> Result<AccountKey, GrantError> {
    // 1. Epochs: the previous key must be of the epoch just before the one being granted.
    if previous_account_key.epoch().checked_add(1) != Some(ctx.account_key_epoch) {
        return Err(GrantError::EpochMismatch);
    }
    // 2–3. The expected sender, then the signature under its key (the statement layer also
    // checks the sender key id and that the signer's role may sign this purpose).
    let grant = match sender {
        GrantSender::Device(cert) => {
            if cert.account_id != ctx.account_id
                || cert.device_id != ctx.sender_device_id
                || !cert.in_device_set()
            {
                return Err(GrantError::WrongSender);
            }
            KeyGrant::verify(signed_grant, &cert.device_ed25519)
        }
        GrantSender::Identity(key) => KeyGrant::verify(signed_grant, key),
    }
    .map_err(GrantError::Verify)?;
    // 4. The signed purpose: a valid grant of another purpose is not a device grant.
    if grant.purpose() != Purpose::AccountKeyDeviceGrant {
        return Err(GrantError::Verify(VerifyError::Mismatch));
    }
    // 5. Addressed to this device's X25519 key (the id in the envelope header).
    if *grant.recipient_key_id() != recipient.kem_key_id() {
        return Err(GrantError::WrongRecipient);
    }
    // 6. Only now any secret-key crypto: the PSK from the previous key, the HPKE open with the
    // AAD rebuilt from `ctx`, and the 32-byte length of the delivered key.
    let psk = HpkePsk::device_grant(previous_account_key, ctx).map_err(|_| GrantError::Decrypt)?;
    let plaintext = hpke::open_psk(recipient.kem_key(), &psk, ctx, grant.envelope())
        .map_err(|DecryptError| GrantError::Decrypt)?;
    let key = Key32::from_slice(plaintext.expose_secret()).map_err(|_| GrantError::Decrypt)?;
    Ok(AccountKey::from_key(key, ctx.account_key_epoch))
}
