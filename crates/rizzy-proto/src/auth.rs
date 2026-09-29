//! Signup, login and sessions: OPAQUE registration and login, device authentication, and the
//! values of a signed request (CRYPTO.md §5.3, §5.9, §5.10, §11.1, §11.2; ADR 0002 owner
//! decision 2; ADR 0003).
//!
//! | Flow step | Request | Response |
//! |---|---|---|
//! | Signup, §11.1 step 4.2 | [`RegisterStartRequest`] | [`RegisterStartResponse`] |
//! | Signup commit, §11.1 step 8 | [`RegisterFinishRequest`] | empty success |
//! | Login, §11.2 step 2 | [`LoginStartRequest`] | [`LoginStartResponse`] |
//! | Login, §11.2 step 5 | [`LoginFinishRequest`] | [`LoginFinishResponse`] |
//! | Device authentication, §5.10 steps 1–3 | [`DeviceAuthStartRequest`], [`DeviceAuthFinishRequest`] | [`DeviceAuthStartResponse`], [`DeviceAuthFinishResponse`] |
//! | Request signing, §5.10 | [`RequestSignature`] (headers) | – |
//!
//! Endpoint paths and HTTP methods are not fixed here: CRYPTO.md §11 calls its paths
//! "illustrative; the API specification owns them", and no Accepted ADR fixes them yet.
//!
//! **What never travels.** `E_dev`, `E_local`, `E_ks` and `ACCOUNT_KEY_FORWARD` have no field
//! in any type (CRYPTO.md §4.2), and every request type rejects unknown fields, so a client
//! cannot upload them by mistake (§11.1 step 8). The OPAQUE `session_key` and `export_key`
//! never leave their side.
//!
//! **Enumeration.** Nothing in [`LoginStartResponse`] differs between a real and an unknown
//! login name (CRYPTO.md §5.9): the fake path returns the same fields.

use serde::{Deserialize, Serialize};

use crate::account::AccountView;
use crate::limits::MAX_BUNDLES;
use crate::limits::{CHALLENGE_LEN, InviteTokenRule, LoginNameRule, OriginRule, TotpCodeRule};
use crate::objects::{
    AccountKeyRecoveryWrap, AccountKeyServerWrap, AccountStatement, IdentitySecretKeys,
    OpaqueMessage, SignatureContainer, VaultSelfGrant,
};
use crate::wire::{Fixed, Id, List, SecretText, SessionToken, Text};

/// A login name as typed ([`LoginNameRule`]); the server normalises it (CRYPTO.md §2).
pub type LoginName = Text<LoginNameRule>;
/// A server's canonical origin ([`OriginRule`], CRYPTO.md §2).
pub type ServerOrigin = Text<OriginRule>;
/// An admin-issued invite token ([`InviteTokenRule`]); a secret.
pub type InviteToken = SecretText<InviteTokenRule>;
/// A TOTP code for server-side 2FA ([`TotpCodeRule`]); a secret.
pub type TotpCode = SecretText<TotpCodeRule>;
/// A device-authentication challenge (CRYPTO.md §5.10): 32 random bytes, 60 s TTL.
pub type Challenge = Fixed<CHALLENGE_LEN>;

/// Signup, OPAQUE registration start (CRYPTO.md §11.1 step 4.2: `{invite, login_name,
/// account_id, M1}`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterStartRequest {
    /// The invite token, when the server requires one (§5.9: invite-only signup is the M1
    /// default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite: Option<InviteToken>,
    /// The login name.
    pub login_name: LoginName,
    /// The new `account_id`, which is the OPAQUE `credential_identifier` (§5.3).
    pub account_id: Id,
    /// OPAQUE `RegistrationRequest` ("M1" in §11.1).
    pub registration_request: OpaqueMessage,
}

/// The answer to [`RegisterStartRequest`]: OPAQUE `RegistrationResponse` ("M2", §11.1 step
/// 4.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterStartResponse {
    /// OPAQUE `RegistrationResponse`.
    pub registration_response: OpaqueMessage,
}

/// The signup commit (CRYPTO.md §11.1 step 8), "with exactly these objects: the OPAQUE
/// `upload`, `E_srv`, `E_id`, the bundle, `account-state`, the vault self-grant, the device
/// certificate, and `E_rec` with `H_rec`".
///
/// The `account_id` is the one inside the signed `account-state`. `recovery` is absent when the
/// user opted out of a recovery code (`recovery_epoch = 0` and `recovery_enabled = 0` in the
/// state). The server treats a byte-identical repeat as success.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterFinishRequest {
    /// OPAQUE `RegistrationUpload`.
    pub registration_upload: OpaqueMessage,
    /// `E_srv`.
    pub account_key_server_wrap: AccountKeyServerWrap,
    /// `E_id`.
    pub identity_secret_keys: IdentitySecretKeys,
    /// The first key bundle (`bundle_seq = 1`).
    pub bundle: AccountStatement,
    /// The first `account-state` (`state_seq = 1`).
    pub account_state: AccountStatement,
    /// The personal vault's self-grant.
    pub vault_self_grant: VaultSelfGrant,
    /// The first device's certificate (kind 1–3, or kind 4 for a web-vault signup).
    pub device_certificate: AccountStatement,
    /// `E_rec` with `H_rec`, unless the user opted out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryRegistration>,
}

/// `E_rec` with `H_rec` as a client uploads them (CRYPTO.md §11.1 steps 5 and 8): the
/// recovery wrap and `H_rec = SHA-256(recovery_auth_token)`, which the server stores to compare
/// the token in constant time at recovery (§11.9 step 2).
///
/// Request-only. `H_rec` sits here, beside the wrap and not inside
/// [`AccountKeyRecoveryWrap`], so that a response returning `E_rec` (§11.9 step 3) cannot
/// carry `H_rec` by reusing the wrap's type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRegistration {
    /// `E_rec` with its locator.
    pub recovery_wrap: AccountKeyRecoveryWrap,
    /// `H_rec = SHA-256(recovery_auth_token)`.
    pub recovery_token_hash: Fixed<32>,
}

/// Login start (CRYPTO.md §11.2 step 2: `{login_name, KE1}`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginStartRequest {
    /// The login name.
    pub login_name: LoginName,
    /// OPAQUE KE1.
    pub ke1: OpaqueMessage,
}

/// The answer to [`LoginStartRequest`] (CRYPTO.md §11.2 step 3: `{login_id, KE2, kdf_id,
/// server_origin}`).
///
/// `kdf_id` and `server_origin` are unauthenticated here. The client checks `kdf_id` against
/// its allow-list and `server_origin` against the origin it dialled before running the KSF
/// (§11.2 step 4); the OPAQUE context binds both, so a lie only makes the login fail (§5.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginStartResponse {
    /// The handle of the sealed server login state (60 s TTL, §5.10).
    pub login_id: Id,
    /// OPAQUE KE2.
    pub ke2: OpaqueMessage,
    /// The `kdf_id` of the record, or of the fake path (§5.9).
    pub kdf_id: u16,
    /// The server's canonical origin (§5.3).
    pub server_origin: ServerOrigin,
}

/// Login finish (CRYPTO.md §11.2 step 5: `{login_id, KE3, totp?}`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginFinishRequest {
    /// From [`LoginStartResponse`].
    pub login_id: Id,
    /// OPAQUE KE3.
    pub ke3: OpaqueMessage,
    /// The TOTP code, for an account with server-side 2FA (§11.15).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<TotpCode>,
}

/// The answer to [`LoginFinishRequest`] (CRYPTO.md §11.2 step 5): the session, then "`account_id`,
/// the epochs and `E_srv`; `E_id`, the current bundle, `account-state`, `ACCOUNT_SETTINGS`;
/// device certificates, revocations; the vault self-grants". The client verifies all of it
/// (step 6) before it trusts any of it.
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginFinishResponse {
    /// The bearer token of the new OPAQUE session (§5.10). A secret.
    pub session_token: SessionToken,
    /// The account.
    pub account_id: Id,
    /// `E_srv` with the epochs of its context.
    pub account_key_server_wrap: AccountKeyServerWrap,
    /// The signed account objects and wraps.
    pub account: AccountView,
}

/// The objects a device enrolled after a restored backup sends with its device-auth request,
/// during the reconciliation epoch only (ADR 0012 §7 "A device enrolled after the backup";
/// threat model INV-59): its certificate, the `account-state` that lists it, and the bundle
/// chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reconciliation {
    /// This device's certificate.
    pub device_certificate: AccountStatement,
    /// The `account-state` whose device set lists it.
    pub account_state: AccountStatement,
    /// The bundle chain, oldest first.
    pub bundles: List<AccountStatement, MAX_BUNDLES>,
}

/// Device authentication, step 1: ask for a challenge (CRYPTO.md §5.10). Kinds 1–3 only; the web
/// vault logs in with OPAQUE every time (§11.4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthStartRequest {
    /// The account.
    pub account_id: Id,
    /// The device.
    pub device_id: Id,
    /// Present only from a device the restored database does not know, during the
    /// reconciliation epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconciliation: Option<Reconciliation>,
}

/// The challenge (CRYPTO.md §5.10 step 1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuthStartResponse {
    /// 32 random bytes, valid for 60 s.
    pub challenge: Challenge,
}

/// Device authentication, step 2: the `device-auth` signature (CRYPTO.md §5.10 step 2), "one
/// signature container, and nothing else: not a raw 64-byte signature, and not the message".
/// The server rebuilds the message from its own origin, this account and device, and the
/// challenge it issued (step 3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthFinishRequest {
    /// The account.
    pub account_id: Id,
    /// The device.
    pub device_id: Id,
    /// The challenge being answered, which names the pending challenge row.
    pub challenge: Challenge,
    /// The `device-auth` signature container.
    pub signature: SignatureContainer,
}

/// The device-authenticated session (CRYPTO.md §5.10): its bearer token and the 16-byte
/// `session_id` that every `device-request` signature covers.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceAuthFinishResponse {
    /// The bearer token. A secret.
    pub session_token: SessionToken,
    /// The session id for request signing.
    pub session_id: Id,
}

/// The two values a native client (kinds 1–3) sends with every request over a
/// device-authenticated session (CRYPTO.md §5.10 "Request signing"; ADR 0002 owner decision 2):
/// the per-session `request_counter` and the `device-request` signature container.
///
/// The signature covers `SHA-256(request body)`, so these travel outside the body, in HTTP
/// headers. **The header names and value encoding are not fixed by any Accepted ADR**, so this
/// crate defines neither; the server and client steps that add request signing fix them in the
/// API specification. Everything else the signed message covers (origin, account, device,
/// session, method, path and query) the server takes from its own state and the request it
/// received (§9.6, "Exception").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestSignature {
    /// The per-session counter; the server accepts each value at most once, within a sliding
    /// window of 64 (§5.10).
    pub request_counter: u64,
    /// The `device-request` signature container.
    pub signature: SignatureContainer,
}
