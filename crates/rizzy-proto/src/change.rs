//! Changes of the signed account state that carry credentials or devices, and the suspension
//! of revocation phase 1 (CRYPTO.md §11 "Replacing credentials", §11.3 step 5, §11.5, §11.8
//! steps 0–2, §11.9 steps 5–6; ADR 0012 §6).
//!
//! | Flow step | Request | Response |
//! |---|---|---|
//! | OPAQUE re-registration, §11.5 step 3, §11.9 step 5, §5.8 | [`ReregisterStartRequest`] | [`ReregisterStartResponse`] |
//! | The atomic commit, §11.5 step 5, §11.9 step 6, §11.3 step 5, settings | [`CommitChangeRequest`] | empty success |
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
//! **No key rotation in this build.** A rotation (§11.6, and the revocation of §11.8 step 3 and
//! the default recovery of §11.9 step 5 that carry one) also carries the vault half of step 9:
//! the rotating device's fetch cursor, the new vault self-grants and the re-wrapped item keys,
//! under the rotation cut-off of ADR 0012 §6. No Accepted ADR fixes that half's wire form, and
//! the vault domain has no rotation upload yet, so [`CommitChangeRequest`] has no rotation
//! fields (`E_id'`, the new bundle, retired keys, device grants, the vault half). A state that
//! rotates is refused as an invalid request. The rotation fields are added, as optional fields,
//! with the vault half (an additive change for the server: a client that does not send them is
//! still understood).
//!
//! **What never travels.** No field carries `E_dev`, `E_local`, `E_ks`, a new Secret Key or a
//! recovery code (CRYPTO.md §4.2, §11 "Secrets before commit"), and every request here rejects
//! unknown fields.

use serde::{Deserialize, Serialize};

use crate::auth::RecoveryRegistration;
use crate::limits::MAX_DEVICE_STATEMENTS;
use crate::objects::{AccountKeyServerWrap, AccountSettings, AccountStatement, OpaqueMessage};
use crate::wire::{Id, List};

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
