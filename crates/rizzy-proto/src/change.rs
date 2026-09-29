//! Changes of the signed account state that carry credentials, keys or devices, and the
//! suspension of revocation phase 1 (CRYPTO.md §11 "Replacing credentials", §11.3 step 5,
//! §11.5, §11.6, §11.8 steps 0–3, §11.9 steps 5–6; ADR 0012 §6; ADR 0025).
//!
//! | Flow step | Request | Response |
//! |---|---|---|
//! | OPAQUE re-registration, §11.5 step 3, §11.9 step 5, §5.8 | [`ReregisterStartRequest`] | [`ReregisterStartResponse`] |
//! | The atomic commit, §11.5 step 5, §11.6 step 9, §11.8 step 3, §11.9 step 6, §11.3 step 5, settings | [`CommitChangeRequest`] | empty success |
//! | Suspension, §11.8 step 0 | [`DeviceSuspensionRequest`] | [`SuspendDeviceResponse`] |
//! | Lifting a suspension, ADR 0012 §6 | [`DeviceSuspensionRequest`] | empty success |
//!
//! **One commit, no partial replace.** CRYPTO.md §11 "Replacing credentials": the server
//! replaces the OPAQUE record, `E_srv`, `E_rec` or `H_rec` "only in a request that also carries
//! a new `account-state`", applied by compare-and-swap. [`CommitChangeRequest`] is that request:
//! the new state and every object the step it describes needs. The server classifies the step
//! from the state it holds to the new one and refuses any object the step does not need, so a
//! field that is present but not needed fails the request like one that is missing.
//!
//! **Key rotation** ([ADR 0025] §1). A rotation (§11.6, and the revocation of §11.8 step 3 and
//! the default recovery of §11.9 step 5 that carry one) is the same commit with its optional
//! rotation fields: the auth half (`bundle`, `identity_secret_keys`, `retired_secret_keys`,
//! `device_grants`, `recovery_rewrap`), mirroring the server's `AccountChange`, and the vault
//! half, [`VaultRotationUpload`]: per vault the new self-grant, the rotating device's exact
//! fetch cursor, the re-wrapped item keys and the wrap-set rows it could not open. The fields
//! are additive: a client that does not rotate does not send them, and each is present exactly
//! when the step the new state describes needs it.
//!
//! **What never travels.** No field carries `E_dev`, `E_local`, `E_ks`, a new Secret Key, a
//! recovery code or any key in the clear (CRYPTO.md §4.2, §11 "Secrets before commit"), and
//! every request here rejects unknown fields.
//!
//! [ADR 0025]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0025-rotation-vault-half.md

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

use crate::auth::RecoveryRegistration;
use crate::limits::{
    MAX_DEVICE_GRANTS, MAX_DEVICE_STATEMENTS, MAX_ITEM_KEY_WRAPS, MAX_RETIRED_KEYS,
    MAX_VAULT_GRANTS,
};
use crate::objects::{
    AccountKeyRecoveryWrap, AccountKeyServerWrap, AccountSettings, AccountStatement, DeviceGrant,
    IdentitySecretKeys, ItemKeyWrap, KeyEnvelope, OpaqueMessage, VaultSelfGrant,
};
use crate::vault::SeqVector;
use crate::wire::{Id, List, WireError};
/// OPAQUE re-registration start (CRYPTO.md §11.5 step 3, §11.9 step 5): the registration
/// request ("M1") for a new record under `credential_identifier = account_id`, the session's
/// account. Allowed over a fresh OPAQUE session, the recovery-only session, or a device session
/// (a same-password re-registration, §5.8); the commit decides what each may replace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReregisterStartRequest {
    /// OPAQUE `RegistrationRequest`.
    pub registration_request: OpaqueMessage,
}

/// The answer to [`ReregisterStartRequest`]: OPAQUE `RegistrationResponse` ("M2").
///
/// A response type: unknown fields are ignored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReregisterStartResponse {
    /// OPAQUE `RegistrationResponse`.
    pub registration_response: OpaqueMessage,
}

/// One atomic change of the account (CRYPTO.md §11 "Replacing credentials"): the new
/// `account-state` (`state_seq + 1`) and exactly the objects its step needs.
///
/// | The new state… | …carries |
/// |---|---|
/// | `password_epoch + 1` (password or Secret Key change, §11.5; the recovery commit, §11.9 step 5) | `registration_upload` and `account_key_server_wrap` |
/// | same `password_epoch`, a new record (same-password re-registration, §5.8, §6.3) | `registration_upload` and `account_key_server_wrap` |
/// | `recovery_epoch + 1` (a new recovery code) | `recovery` |
/// | recovery switched off | nothing more; the server deletes `E_rec` and `H_rec` |
/// | `settings_seq + 1` | `account_settings` |
/// | a new durable device (§11.9 step 5, §11.3 step 5) | its certificate in `device_certificates` |
/// | a revoked device without a rotation (the self-revocation of §11.3 step 5 only) | its `device-revocation` in `device_revocations` |
/// | `account_key_epoch + 1` (standard rotation, §11.6; the revocation of §11.8 step 3; the default recovery of §11.9 step 5) | `account_key_server_wrap`, `identity_secret_keys`, `device_grants` (one per remaining durable device), `vault_rotation`, and `recovery_rewrap` (keep the code) or `recovery` (new code) while recovery is on |
/// | `identity_epoch + 1` (full rotation) | all of the above, `bundle` signed by both identity keys, `retired_secret_keys`, and a re-issue of every certificate and revocation |
///
/// A byte-identical repeat of the committed state is success (§11 "Secrets before commit").
/// The session each change needs is the server's rule, not a field here: a fresh OPAQUE
/// session, the recovery-only session for the recovery commit, or a device session for a
/// same-password re-registration or new settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitChangeRequest {
    /// The new `account-state`.
    pub account_state: AccountStatement,
    /// OPAQUE `RegistrationUpload` of the new record, after [`ReregisterStartRequest`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_upload: Option<OpaqueMessage>,
    /// `E_srv'`, with a new record; its locator equals the new state's epochs and `kdf_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_key_server_wrap: Option<AccountKeyServerWrap>,
    /// `E_rec` and `H_rec` of a new recovery code, at the new state's `recovery_epoch`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryRegistration>,
    /// The new `ACCOUNT_SETTINGS`, at the new state's `settings_seq`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_settings: Option<AccountSettings>,
    /// Certificates of devices the change enrols.
    pub device_certificates: List<AccountStatement, MAX_DEVICE_STATEMENTS>,
    /// Revocations the change adds, each with `last_accepted_device_seq` = H, the head the
    /// server still holds (§11.8 steps 1–3).
    pub device_revocations: List<AccountStatement, MAX_DEVICE_STATEMENTS>,
    /// The new bundle of a full rotation (`bundle_seq + 1`), signed by the new and the
    /// preceding identity key (CRYPTO.md §11.6 step 7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<AccountStatement>,
    /// `E_id'` under the new account key, with a rotation (§11.6 step 3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_secret_keys: Option<IdentitySecretKeys>,
    /// `RETIRED_SECRET_KEY` envelopes under the new account key, with a rotation (§11.6 step
    /// 3): the old identity X25519 key of a full rotation, and from M6 old mail keys.
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub retired_secret_keys: List<RetiredSecretKey, MAX_RETIRED_KEYS>,
    /// `ACCOUNT_KEY_DEVICE_GRANT`s at the new `account_key_epoch`, one per remaining durable
    /// device other than the rotating client's own, with a rotation (§11.6 step 6).
    #[serde(default, skip_serializing_if = "List::is_empty")]
    pub device_grants: List<DeviceGrant, MAX_DEVICE_GRANTS>,
    /// `E_rec'` under the new account key, for a rotation that keeps the current recovery code
    /// (§11.6 step 5): `recovery_epoch` and `H_rec` unchanged. Never together with `recovery`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_rewrap: Option<AccountKeyRecoveryWrap>,
    /// The vault half of a rotation (§11.6 steps 3 and 9; ADR 0025 §1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_rotation: Option<VaultRotationUpload>,
}

/// Revocation phase 1, `suspend(device_id)` (CRYPTO.md §11.8 step 0; ADR 0012 §6), and the
/// request that lifts a suspension: the target device of the session's account. Both need a
/// fresh OPAQUE re-authentication from another durable device of the set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceSuspensionRequest {
    /// The device to suspend, or whose suspension to lift.
    pub device_id: Id,
}

/// The answer to a suspension (CRYPTO.md §11.8 step 0): H, "the highest `device_seq` it holds
/// from that device", which the revoker fetches up to and signs into the `device-revocation`.
/// A repeat returns H again.
///
/// A response type: unknown fields are ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuspendDeviceResponse {
    /// H: the `last_accepted_device_seq` of the revocation; 0 when the server holds nothing
    /// from the device.
    pub last_accepted_device_seq: u64,
}

/// A `RETIRED_SECRET_KEY` envelope (CRYPTO.md §8.4, §11.6 step 3) with its locator, the retired
/// public key's id (§4.4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredSecretKey {
    /// The retired public key id, which files the envelope.
    pub retired_key_id: Id,
    /// The envelope under the new account key.
    pub envelope: KeyEnvelope,
}

/// The locator of one item-key wrap-set row (CRYPTO.md §4.2): the item and the wrapped item
/// key's id. The vault is the one the carrying [`VaultRotation`] names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrapLocator {
    /// `item_id` of the row.
    pub item_id: Id,
    /// The wrapped item key's key id.
    pub item_key_id: Id,
}

/// The vault half of a rotation for one vault (ADR 0025 §1, §3; CRYPTO.md §11.6 steps 3 and 9).
///
/// - `self_grant`: the new vault key under the new account key, at the new `account_key_epoch`
///   and a `vault_key_epoch` above the one the server holds.
/// - `cursor`: the rotating device's fetch cursor after a complete Fetch (a recovering client:
///   the heads `/recovery/complete` returned). The server requires it to equal its heads
///   exactly (ADR 0025 §3 check 4). Canonical, as every [`SeqVector`].
/// - `item_key_wraps`: every wrap-set row the rotator could open, re-wrapped under the new vault
///   key, one per `(item_id, item_key_id)`.
/// - `dropped`: the rows it could not open (an AEAD failure, or an epoch whose vault key it
///   lacks); the server deletes them.
///
/// Every stored row is in exactly one of the two lists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultRotation {
    /// The new `VAULT_KEY_SELF_GRANT`; its `vault_id` names the vault.
    pub self_grant: VaultSelfGrant,
    /// The rotating device's fetch cursor.
    pub cursor: SeqVector,
    /// The re-wrapped rows, at the new `vault_key_epoch`.
    pub item_key_wraps: List<ItemKeyWrap, MAX_ITEM_KEY_WRAPS>,
    /// The rows the rotator could not open.
    pub dropped: List<WrapLocator, MAX_ITEM_KEY_WRAPS>,
}

/// The vault half of a rotation (ADR 0025 §1): one [`VaultRotation`] per vault of the account,
/// strictly ascending by `self_grant.vault_id` bytewise (so one per vault, and one JSON form).
///
/// Deserialising rejects any other order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VaultRotationUpload {
    /// The vaults, ascending by id.
    vaults: List<VaultRotation, MAX_VAULT_GRANTS>,
}

impl VaultRotationUpload {
    /// Checks and wraps `vaults`.
    ///
    /// # Errors
    /// [`WireError::TooMany`] above [`MAX_VAULT_GRANTS`] entries; [`WireError::NotCanonical`]
    /// when the vaults are not strictly ascending by `self_grant.vault_id`.
    pub fn new(vaults: Vec<VaultRotation>) -> Result<Self, WireError> {
        Self::checked(List::new(vaults)?)
    }

    /// The order check.
    fn checked(vaults: List<VaultRotation, MAX_VAULT_GRANTS>) -> Result<Self, WireError> {
        let ascending = vaults
            .as_slice()
            .windows(2)
            .all(|w| matches!(w, [a, b] if a.self_grant.vault_id < b.self_grant.vault_id));
        if ascending {
            Ok(Self { vaults })
        } else {
            Err(WireError::NotCanonical)
        }
    }

    /// The vaults, ascending by id.
    #[must_use]
    pub fn vaults(&self) -> &[VaultRotation] {
        self.vaults.as_slice()
    }
}

/// The wire form: `{"vaults": [...]}`, unknown fields rejected.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultRotationUploadWire {
    /// The vaults, as sent.
    vaults: List<VaultRotation, MAX_VAULT_GRANTS>,
}

impl<'de> Deserialize<'de> for VaultRotationUpload {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = VaultRotationUploadWire::deserialize(deserializer)?;
        Self::checked(wire.vaults).map_err(de::Error::custom)
    }
}
