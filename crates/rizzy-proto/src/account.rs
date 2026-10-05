//! Account state, enrolment, bundles and key grants (CRYPTO.md §10.1, §10.2, §11.2 step 7,
//! §11.3, §11.4; ADR 0012 §7 "Healing a server rollback" steps 1–3).
//!
//! | Flow step | Request | Response |
//! |---|---|---|
//! | Unlock, online part, §11.3 steps 2.2 and 4.4 | [`AccountStateQuery`] | [`AccountView`] |
//! | Enrolment, §11.2 step 7 | [`EnrolDeviceRequest`] | empty success |
//! | Web-vault ephemeral certificate, §11.4 | [`UploadWebDeviceCertificateRequest`] | empty success |
//! | Pending device grants, §11.3 step 4.1 | – | [`DeviceGrantsResponse`] |
//! | Grant acknowledgement, §10.1, §11.3 step 4.5 | [`AckDeviceGrantsRequest`] | empty success |
//! | Healing step 1, the bundle chain | [`PublishBundlesRequest`] | empty success |
//! | Healing step 2, the newest `account-state` with every certificate, revocation, `E_id` and `ACCOUNT_SETTINGS` (ADR 0032 §2) | [`PublishAccountStateRequest`] | empty success |
//! | Healing step 3a, grants | [`PublishGrantsRequest`] | empty success |
//!
//! Everything signed here is verified by the client against its cached identity key and
//! persisted state (INV-25) before it is trusted; the server's copy is never the authority.
//! Every new `account-state` the server accepts is applied by compare-and-swap on `state_seq`
//! (§10.2); a lost race is answered [`ErrorCode::StateConflict`](crate::error::ErrorCode).
//!
//! Password change, revocation and recovery (§11.5, §11.8, §11.9) carry larger atomic requests,
//! in [`crate::change`] and [`crate::recovery`]; key rotation (§11.6) is the commit of
//! [`crate::change`] with its rotation fields (ADR 0025).

use serde::{Deserialize, Serialize};

use crate::limits::{MAX_BUNDLES, MAX_DEVICE_GRANTS, MAX_DEVICE_STATEMENTS, MAX_VAULT_GRANTS};
use crate::objects::{
    AccountSettings, AccountStatement, DeviceGrant, IdentitySecretKeys, VaultSelfGrant,
};
use crate::wire::List;

/// The signed account objects and account-level wraps a client verifies (CRYPTO.md §11.2
/// step 6, §11.3 step 2.4): the answer to [`AccountStateQuery`] and part of
/// [`LoginFinishResponse`](crate::auth::LoginFinishResponse).
///
/// A response type: unknown fields are ignored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountView {
    /// The current `account-state`.
    pub account_state: AccountStatement,
    /// Key bundles, oldest first: after a login the current bundle alone; after an
    /// [`AccountStateQuery`] every bundle above the cached `bundle_seq` (§11.3 step 2.2).
    pub bundles: List<AccountStatement, MAX_BUNDLES>,
    /// Every device certificate of the account.
    pub device_certificates: List<AccountStatement, MAX_DEVICE_STATEMENTS>,
    /// Every device revocation of the account.
    pub device_revocations: List<AccountStatement, MAX_DEVICE_STATEMENTS>,
    /// `ACCOUNT_SETTINGS`, absent while `settings_seq = 0`, and after an [`AccountStateQuery`]
    /// whose `known_settings_seq` is the current one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_settings: Option<AccountSettings>,
    /// `E_id` of the current `identity_epoch`.
    pub identity_secret_keys: IdentitySecretKeys,
    /// The vault self-grants under the current account key.
    pub vault_self_grants: List<VaultSelfGrant, MAX_VAULT_GRANTS>,
}

/// What an enrolled device already holds, so the server can leave out what has not changed
/// (CRYPTO.md §11.3 step 2.2: "every bundle with `bundle_seq` above the cached one, …, and
/// `ACCOUNT_SETTINGS` if `settings_seq` changed").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountStateQuery {
    /// The highest `bundle_seq` the device has accepted.
    pub known_bundle_seq: u64,
    /// The `settings_seq` of the settings the device holds; 0 for none.
    pub known_settings_seq: u64,
}

/// Enrolment of a new durable device after an OPAQUE login (CRYPTO.md §11.2 step 7): its
/// certificate and the `account-state` with `state_seq + 1` and the new `device_set_hash`, over
/// the fresh OPAQUE session. `E_dev` and `E_local` stay on the device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolDeviceRequest {
    /// The new device's certificate.
    pub device_certificate: AccountStatement,
    /// The new `account-state`.
    pub account_state: AccountStatement,
}

/// This device's pending `ACCOUNT_KEY_DEVICE_GRANT`s (CRYPTO.md §10.1, §11.3 step 4.1), in epoch
/// order. Fetching does not consume them.
///
/// A response type: unknown fields are ignored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceGrantsResponse {
    /// The grants, lowest `account_key_epoch` first.
    pub grants: List<DeviceGrant, MAX_DEVICE_GRANTS>,
}

/// The separate acknowledgement of CRYPTO.md §10.1: the device has persisted its re-wrapped
/// `E_local` (or an `ACCOUNT_KEY_FORWARD`), `E_ks` and `E_dev` up to this epoch, so the server may
/// delete its grants up to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckDeviceGrantsRequest {
    /// The highest `account_key_epoch` whose grant is persisted.
    pub account_key_epoch: u32,
}

/// Restore healing, step 1: the bundle chain, so the server holds the current identity key
/// (ADR 0012 §7), sent by a device that found the server behind its own accepted state.
///
/// This is the only bundle-only publish the specs define, and it is for restore healing only.
/// Every `account-state` commits to
/// `bundle_hash` (CRYPTO.md §10.2) and clients check it against the served bundle (§11.2 step
/// 6, §11.3 step 2.4), so outside healing a new bundle travels with its `account-state` in the
/// rotation, post-quantum or mail-key flow that causes it, never on its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishBundlesRequest {
    /// Bundles, oldest first, each chaining from the one before.
    pub bundles: List<AccountStatement, MAX_BUNDLES>,
}

/// Restore healing, step 2 ([ADR 0032] §2, replacing ADR 0012 §7 step 2): the device's newest
/// signed `account-state`, "in one request with every device certificate and `device-revocation`
/// it holds and, as last served, `E_id` and `ACCOUNT_SETTINGS`". The state is accepted as that
/// step's session rules say: during the reconciliation epoch any state that verifies with a
/// strictly higher `state_seq`, otherwise only the held state re-sent byte for byte. `E_id` and
/// `ACCOUNT_SETTINGS` repair a lagging server copy under the lag rule of ADR 0032 §3, checked
/// against the signed state the server holds, inside or outside the epoch.
///
/// [ADR 0032]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0032-healing-rotation-after-backup.md
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishAccountStateRequest {
    /// The `account-state`.
    pub account_state: AccountStatement,
    /// Every certificate the device holds: its device set's, revoked devices' and kind-4
    /// certificates re-issued by a full rotation (ADR 0032 §2).
    pub device_certificates: List<AccountStatement, MAX_DEVICE_STATEMENTS>,
    /// Every revocation the device holds.
    pub device_revocations: List<AccountStatement, MAX_DEVICE_STATEMENTS>,
    /// `E_id` of the state's `identity_epoch`, verbatim as last served and cached (ADR 0032 §2;
    /// ADR 0026 §1). Absent from a client that holds none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_secret_keys: Option<IdentitySecretKeys>,
    /// `ACCOUNT_SETTINGS` the state commits to, verbatim as last served and cached, when
    /// `settings_seq > 0` (ADR 0032 §2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_settings: Option<AccountSettings>,
}

/// Restore healing, step 3: "key grants, vault self-grants … that it holds, or can re-create
/// with the keys it has" (ADR 0012 §7). Item-key wraps travel in the vault's
/// [`HealingRequest`](crate::vault::HealingRequest).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishGrantsRequest {
    /// Vault self-grants.
    pub vault_self_grants: List<VaultSelfGrant, MAX_VAULT_GRANTS>,
    /// Device grants.
    pub device_grants: List<DeviceGrant, MAX_DEVICE_GRANTS>,
}

/// The web vault's ephemeral `device_kind = 4` certificate (CRYPTO.md §11.4: "The certificate
/// is uploaded, but it is **not** part of the signed device set and publishes no new
/// `account-state`"), over the OPAQUE session of that web login.
///
/// Without it the server holds no certificate to verify the web session's ops and snapshots
/// against (§10.2, ADR 0012 §7), so a web vault could store nothing. The server accepts it
/// only if the certificate:
/// - has `device_kind = 4`; any other kind enrols through [`EnrolDeviceRequest`] and its
///   `account-state` compare-and-swap;
/// - verifies under the identity key of the current `identity_epoch`, for the session's
///   account;
/// - has a non-zero `expires_at_ms` after `created_at_ms` and at most `created_at_ms + 12 h`
///   (§10.2 `device-certificate`), and has not expired.
///
/// It carries exactly one certificate and nothing else: no `account-state`, bundle or grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadWebDeviceCertificateRequest {
    /// The kind-4 certificate.
    pub device_certificate: AccountStatement,
}
