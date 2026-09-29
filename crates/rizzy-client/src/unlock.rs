//! The online part of an unlock on an enrolled device (CRYPTO.md §11.3 step 2–5).
//!
//! The offline part is [`DeviceState::unlock`]; device authentication is
//! [`crate::session`]. Then:
//!
//! 1. [`account_state_query`]: what to fetch (bundles above the pinned one, settings if
//!    `settings_seq` changed).
//! 2. [`verify_unlock`] on the answer: the checks of [`crate::account`] against the pin,
//!    rollback and fork detection (read-only, §11.3 step 2.5), an identity change only with
//!    the user's confirmation of the new fingerprint (§11.3 step 3), then adoption of the new
//!    pin.
//! 3. On [`ClientError::AccountKeyRotated`]: fetch this device's grants and pass them to
//!    [`apply_device_grants`] (§11.3 step 4), persist, send the acknowledgement it returns, and
//!    run [`verify_unlock`] again.
//! 4. On [`ClientError::PasswordChangedElsewhere`]: the host prompts for the new password (and
//!    Secret Key) and runs an OPAQUE login (§11.3 step 5). Re-creating `E_local` on this
//!    device after that login is not implemented in this build (reported).
//!
//! # Readings
//!
//! - A rollback, a fork or an unconfirmed identity change is an error, and nothing is adopted:
//!   the host shows the matching warning and keeps the vault read-only, which
//!   [`crate::sync::VaultSync::set_read_only`] enforces for writes.
//! - A newer `password_epoch` is detected after the answer verified, and the verified pin is
//!   adopted before [`ClientError::PasswordChangedElsewhere`] is returned: the newer state is
//!   authentic, and adopting it keeps the rollback floor as high as possible.
//! - A grant for this device's epoch chain must be addressed to this device, carry exactly
//!   each epoch from the held key's + 1 to the state's, and deliver a key whose id is the
//!   state's `account_key_id`; a grant's sender is a certificate of the account (revoked ones
//!   included, §11.3 step 4.2) or, when no durable certificate names it, the current identity
//!   key (a kind-4 rotating client, §10.1).

use rizzy_core::envelope::purpose::AccountKeyDeviceGrantCtx;
use rizzy_core::ids::DeviceId;
use rizzy_core::keys::{AccountFingerprint, GrantSender, open_account_key_device_grant};
use rizzy_core::rng::CryptoRng;
use rizzy_proto::account::{
    AccountStateQuery, AccountView, AckDeviceGrantsRequest, DeviceGrantsResponse,
};

use crate::account::{Anchor, VerifiedAccount, verify_account_view, verify_public};
use crate::device::{DeviceState, UnlockedDevice};
use crate::error::ClientError;

/// What an enrolled device fetches after device authentication (§11.3 step 2.2).
///
/// `known_settings_seq` is the pinned `settings_seq` only when the pin holds those settings
/// (`rizzy-proto`: "the `settings_seq` of the settings the device holds; 0 for none"), so the
/// server leaves out only settings [`verify_unlock`] can check against the kept envelope.
#[must_use]
pub fn account_state_query(state: &DeviceState) -> AccountStateQuery {
    let pin = &state.pin;
    let held = pin
        .settings
        .as_ref()
        .filter(|s| s.settings_seq == pin.state.settings_seq);
    AccountStateQuery {
        known_bundle_seq: pin.bundle.bundle_seq,
        known_settings_seq: held.map_or(0, |s| s.settings_seq),
    }
}

/// Verifies the account answer of an unlock and adopts it (see the module docs).
///
/// `confirmed` is the fingerprint the user confirmed on this device after the host showed
/// the one [`ClientError::IdentityChangeUnconfirmed`] asked about; `None` otherwise.
///
/// # Errors
/// [`ClientError::Rollback`], [`ClientError::Fork`], [`ClientError::IdentityChangeUnconfirmed`],
/// [`ClientError::AccountKeyRotated`], [`ClientError::PasswordChangedElsewhere`],
/// [`ClientError::InvalidServerResponse`]; [`ClientError::InvalidInput`] if `unlocked` is
/// another device's.
pub fn verify_unlock(
    state: &mut DeviceState,
    unlocked: &UnlockedDevice,
    view: &AccountView,
    confirmed: Option<&AccountFingerprint>,
) -> Result<VerifiedAccount, ClientError> {
    if unlocked.account_id != state.account_id || unlocked.device_id != state.device_id {
        return Err(ClientError::InvalidInput);
    }
    let account = verify_account_view(
        view,
        state.account_id,
        &unlocked.account_key,
        &Anchor::Enrolled {
            pin: &state.pin,
            confirmed,
        },
    )?;
    // This device must still be a member of the signed set (§11.3 step 3.3), under its own
    // keys: a certificate that names this device id but other keys (one a compromised former
    // identity holder could sign, §11.6 "Known limitation") is not this device's membership.
    let own_keys = unlocked.device_keys.public_keys();
    let revoked = account
        .revocations
        .iter()
        .any(|r| r.revocation.device_id == state.device_id);
    let member = !revoked
        && account.certificates.iter().any(|c| {
            c.certificate.device_id == state.device_id
                && c.certificate.device_ed25519 == own_keys.ed25519
                && c.certificate.device_x25519 == own_keys.x25519
        });
    if !member {
        return Err(ClientError::InvalidServerResponse);
    }
    state.adopt(&account);
    if account.state().password_epoch > state.local_password_epoch() {
        return Err(ClientError::PasswordChangedElsewhere);
    }
    Ok(account)
}

/// Opens this device's account-key grants after a rotation elsewhere (§11.3 step 4), re-wraps
/// `E_local` and `E_dev` under the delivered key, and returns the acknowledgement to send once
/// the new device state is persisted (step 4.5).
///
/// `view` is the account answer [`verify_unlock`] refused with
/// [`ClientError::AccountKeyRotated`]; its public part is verified again here.
///
/// # Errors
/// [`ClientError::InvalidServerResponse`] for a missing, misaddressed or failing grant, or a
/// delivered key that is not the state's; [`ClientError::InvalidInput`] if the unlock key was
/// already dropped (a keystore unlock, which this build does not support); the errors of the
/// public verification.
pub fn apply_device_grants<R: CryptoRng + ?Sized>(
    rng: &mut R,
    state: &mut DeviceState,
    unlocked: &mut UnlockedDevice,
    view: &AccountView,
    grants: &DeviceGrantsResponse,
    confirmed: Option<&AccountFingerprint>,
) -> Result<AckDeviceGrantsRequest, ClientError> {
    let bad = ClientError::InvalidServerResponse;
    if unlocked.account_id != state.account_id || unlocked.device_id != state.device_id {
        return Err(ClientError::InvalidInput);
    }
    let public = verify_public(
        view,
        state.account_id,
        &Anchor::Enrolled {
            pin: &state.pin,
            confirmed,
        },
        None,
    )?;
    let target = public.state.account_key_epoch;
    let mut epoch = unlocked.account_key.epoch();
    if target <= epoch {
        return Err(bad);
    }
    let mut key = None;
    while epoch < target {
        let next = epoch.checked_add(1).ok_or(bad)?;
        let mut matching = grants.grants.as_slice().iter().filter(|g| {
            g.account_key_epoch == next
                && g.recipient_device_id.to_bytes() == state.device_id.to_bytes()
        });
        let grant = matching.next().ok_or(bad)?;
        if matching.next().is_some() {
            return Err(bad);
        }
        let sender_id = DeviceId::from_bytes(grant.sender_device_id.to_bytes());
        let sender_cert = public
            .certificates
            .iter()
            .find(|c| c.certificate.device_id == sender_id && c.certificate.in_device_set());
        let sender = match sender_cert {
            Some(c) => GrantSender::Device(&c.certificate),
            None => GrantSender::Identity(&public.bundle.identity_ed25519),
        };
        let ctx = AccountKeyDeviceGrantCtx {
            account_id: state.account_id,
            account_key_epoch: next,
            sender_device_id: sender_id,
            recipient_device_id: state.device_id,
        };
        let previous = key.as_ref().unwrap_or(&unlocked.account_key);
        let opened = open_account_key_device_grant(
            grant.key_grant.as_slice(),
            &ctx,
            &unlocked.device_keys,
            previous,
            sender,
        )
        .map_err(|_| bad)?;
        key = Some(opened);
        epoch = next;
    }
    let new_key = key.ok_or(bad)?;
    if !public.state.matches_account_key(&new_key) {
        return Err(bad);
    }
    let local = unlocked
        .local_unlock_key
        .as_ref()
        .ok_or(ClientError::InvalidInput)?;
    state.rewrap(rng, local, &new_key, &unlocked.device_keys)?;
    unlocked.account_key = new_key;
    Ok(AckDeviceGrantsRequest {
        account_key_epoch: target,
    })
}
