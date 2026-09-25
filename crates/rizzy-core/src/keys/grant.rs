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
#[derive(Clone, Copy, Debug)]
pub enum GrantSigner<'a> {
    /// The rotating device's own key (kinds 1–3).
    Device(&'a DeviceSigningKey),
    /// The identity key of the current `identity_epoch`, when the rotating client is a web
    /// vault (kind 4, §10.1).
    Identity(&'a IdentitySigningKey),
}

/// Who the recipient expects to have signed a device grant.
#[derive(Clone, Copy, Debug)]
pub enum GrantSender<'a> {
    /// A verified certificate of the account for the sender `device_id` in the AAD, which may
    /// since have been revoked (§11.3 step 4.2). Must be a durable device (kinds 1–3).
    Device(&'a Verified<DeviceCertificate>),
    /// The identity key of the current `identity_epoch`: a grant from a kind-4 client.
    Identity(&'a IdentityVerifyingKey),
}

/// A device grant could not be made or accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GrantError {
    /// The context does not fit the keys: the new key's epoch is not the context's, or the
    /// previous key is not of the epoch before it.
    EpochMismatch,
    /// The recipient certificate is not the device the context names, or not a durable device.
    WrongRecipient,
    /// The sender certificate is not the device the context names, or not a durable device.
    WrongSender,
    /// Sealing failed.
    Encrypt(EncryptError),
    /// Signing failed.
    Sign(SignError),
    /// The `key-grant` signature or statement did not verify.
    Verify(VerifyError),
    /// The HPKE envelope did not open.
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
    let purpose = Purpose::AccountKeyDeviceGrant;
    match signer {
        GrantSigner::Device(key) => KeyGrant::sign(purpose, key, &envelope),
        GrantSigner::Identity(key) => KeyGrant::sign(purpose, key, &envelope),
    }
    .map_err(GrantError::Sign)
}

/// Verifies and opens a signed device grant (§11.3 step 4).
///
/// Checks, in order: the epochs; that `sender` is the sender the AAD names; the `key-grant`
/// signature and purpose; that the grant is addressed to this device's X25519 key; then opens
/// the HPKE envelope with the device X25519 key and the device-grant PSK from
/// `previous_account_key`. The delivered key gets the epoch `ctx` names.
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
    if previous_account_key.epoch().checked_add(1) != Some(ctx.account_key_epoch) {
        return Err(GrantError::EpochMismatch);
    }
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
    if grant.purpose() != Purpose::AccountKeyDeviceGrant {
        return Err(GrantError::Verify(VerifyError::Mismatch));
    }
    if *grant.recipient_key_id() != recipient.kem_key_id() {
        return Err(GrantError::WrongRecipient);
    }
    let psk = HpkePsk::device_grant(previous_account_key, ctx).map_err(|_| GrantError::Decrypt)?;
    let plaintext = hpke::open_psk(recipient.kem_key(), &psk, ctx, grant.envelope())
        .map_err(|DecryptError| GrantError::Decrypt)?;
    let key = Key32::from_slice(plaintext.expose_secret()).map_err(|_| GrantError::Decrypt)?;
    Ok(AccountKey::from_key(key, ctx.account_key_epoch))
}
