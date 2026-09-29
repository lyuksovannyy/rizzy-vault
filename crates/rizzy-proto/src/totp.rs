//! Server-side 2FA with TOTP: enrolment and removal (CRYPTO.md §5.10 "Server-side 2FA",
//! §5.11, §11.15). The code at login travels in
//! [`LoginFinishRequest::totp`](crate::auth::LoginFinishRequest::totp).
//!
//! | Flow step | Request | Response |
//! |---|---|---|
//! | Enrolment start | – | [`TotpEnrolStartResponse`] |
//! | Enrolment confirmation | [`TotpEnrolConfirmRequest`] | empty success |
//! | Removal | [`TotpDisableRequest`] | empty success |
//!
//! Every step needs a fresh OPAQUE session. The server issues the secret (§11.15: "generated at
//! 20 bytes"), seals it as `SERVER_TOTP_SECRET` and returns it once, for the otpauth URI the
//! client renders; only a confirmed enrolment gates a login.

use serde::{Deserialize, Serialize};

use crate::auth::TotpCode;
use crate::limits::TOTP_SECRET_LEN;
use crate::wire::SecretFixed;

/// A server 2FA secret as the server hands it to the user once (CRYPTO.md §11.15): 20 bytes,
/// which the client encodes as RFC 4648 Base32 in the otpauth URI. A secret: zeroized on drop,
/// `Debug` redacted.
pub type TotpSecretBytes = SecretFixed<TOTP_SECRET_LEN>;

/// The answer to an enrolment start: the new, unconfirmed enrolment.
///
/// A response type: unknown fields are ignored.
#[derive(Debug, Serialize, Deserialize)]
pub struct TotpEnrolStartResponse {
    /// The enrolment's `totp_credential_seq` (CRYPTO.md §5.11), to name it in the
    /// confirmation.
    pub totp_credential_seq: u32,
    /// The secret. Shown to the user once; never stored by the client beyond that.
    pub secret: TotpSecretBytes,
}

/// Confirms the pending enrolment `totp_credential_seq` with a code from the user's
/// authenticator. From then on every login needs a code.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpEnrolConfirmRequest {
    /// From [`TotpEnrolStartResponse`].
    pub totp_credential_seq: u32,
    /// The current code.
    pub code: TotpCode,
}

/// Switches 2FA off with a current code (losing the authenticator is the admin's logged 2FA
/// reset, threat model INV-69, M3).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpDisableRequest {
    /// The current code.
    pub code: TotpCode,
}
