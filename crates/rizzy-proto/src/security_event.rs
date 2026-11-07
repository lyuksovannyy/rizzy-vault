// SPDX-License-Identifier: AGPL-3.0-only

//! The per-account security event log ([ADR 0090] §7): `security-events/list` and the alert
//! summary of [`AccountView`](crate::account::AccountView).
//!
//! | Endpoint | Request | Response | Caller |
//! |---|---|---|---|
//! | `security-events/list` | [`SecurityEventListRequest`] | [`SecurityEventListResponse`] | OPAQUE or device |
//!
//! - **Advisory, unsigned and server-set** (threat model INV-110): a client shows an entry and
//!   the [`SecurityAlertSummary`] as UI only, and never uses them as input to a device-set,
//!   `account-state`, recovery or trust decision. A malicious server can hide, invent or change
//!   entries.
//! - **What an entry carries** (§4): the kind, its class, who acted, and the fields §3 names. No
//!   source address, no user agent, no token or `session_id`, no secret and no admin id.
//! - **Codes.** The stored integers of §3 (kinds) and §4 (actor kinds) are fixed here, with
//!   their `snake_case` wire names; a name or code this build does not know reads as `Unknown`.
//!
//! [ADR 0090]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0090-per-account-security-event-log.md

use serde::{Deserialize, Deserializer, Serialize};

use crate::limits::MAX_SECURITY_EVENTS_LISTED;
use crate::webauthn::WebauthnLabel;
use crate::wire::{Id, List};

/// Body of `security-events/list`. A request: unknown fields are refused, and so is a `limit`
/// of 0 or above [`MAX_SECURITY_EVENTS_LISTED`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityEventListRequest {
    /// Entries strictly older than this one, in `(at_ms, event_id)` order; absent = the newest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<SecurityEventCursor>,
    /// 1 to [`MAX_SECURITY_EVENTS_LISTED`]; absent =
    /// [`DEFAULT_SECURITY_EVENTS_LISTED`](crate::limits::DEFAULT_SECURITY_EVENTS_LISTED).
    #[serde(
        default,
        deserialize_with = "bounded_limit",
        skip_serializing_if = "Option::is_none"
    )]
    pub limit: Option<u32>,
}

/// Reads a `limit`: an integer from 1 to [`MAX_SECURITY_EVENTS_LISTED`].
fn bounded_limit<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u32>, D::Error> {
    let value = u32::deserialize(deserializer)?;
    if value == 0 || usize::try_from(value).map_or(true, |v| v > MAX_SECURITY_EVENTS_LISTED) {
        return Err(serde::de::Error::custom("limit out of range"));
    }
    Ok(Some(value))
}

/// A position in the list: the `(at_ms, event_id)` of the last entry shown. Keyset paging, so a
/// cursor that names a purged entry still works.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityEventCursor {
    /// The entry's time, ms since the Unix epoch.
    pub at_ms: u64,
    /// The entry's 16-byte id.
    pub event_id: Id,
}

/// The answer to `security-events/list`: the account's entries below the cursor, newest first.
///
/// A response type: unknown fields are ignored. More than [`MAX_SECURITY_EVENTS_LISTED`]
/// entries is a parse error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityEventListResponse {
    /// Newest first, in `(at_ms, event_id)` descending order.
    pub events: List<SecurityEventView, MAX_SECURITY_EVENTS_LISTED>,
    /// True when older entries exist beyond the last one.
    pub more: bool,
}

/// One entry of the log. A response-only object: unknown fields are ignored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityEventView {
    /// The entry's 16-byte id (the paging tie-break).
    pub event_id: Id,
    /// When the action's transaction ran, ms since the Unix epoch (the server's clock).
    pub at_ms: u64,
    /// What happened.
    pub kind: SecurityEventKind,
    /// Info or alert.
    pub class: SecurityEventClass,
    /// Who acted.
    pub actor: SecurityEventActor,
    /// The device the action was about (enrolled, suspended, revoked, or bound to an ended
    /// session).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_device_id: Option<Id>,
    /// A security key's label at the time (codes 19–21). User content: shown as text only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<WebauthnLabel>,
    /// The value before (a counter for code 21, the recovery wait in ms for code 24).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_old: Option<u64>,
    /// The value after, per kind (ADR 0090 §3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_new: Option<u64>,
    /// The `state_seq` an `account-state` commit produced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_seq: Option<u64>,
}

/// Who acted. The admin's id is never sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityEventActor {
    /// The actor's kind.
    pub kind: SecurityEventActorKind,
    /// The acting durable device, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<Id>,
}

/// `AccountView.security_alerts`: alert-class entries younger than
/// [`ALERT_WINDOW_MS`](crate::limits::ALERT_WINDOW_MS). Absent when there are none. Advisory
/// (INV-110): it drives a banner, nothing else. A response type: unknown fields are ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityAlertSummary {
    /// Alert-class entries in the window (at most 500, the per-class cap).
    pub count: u32,
    /// The newest one's id (the banner's dismissal key).
    pub newest_event_id: Id,
    /// The newest one's time, ms since the Unix epoch.
    pub newest_at_ms: u64,
    /// The newest one's kind.
    pub newest_kind: SecurityEventKind,
}

/// The class of an entry (ADR 0090 §2): stored as 1 info, 2 alert.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventClass {
    /// `"info"`: an expected consequence of the user's own action.
    Info,
    /// `"alert"`: a change the user should confirm was theirs.
    Alert,
    /// A class this build does not know; shown as an alert. The server never sends it.
    #[serde(other)]
    Unknown,
}

impl SecurityEventClass {
    /// The stored code, `None` for [`Self::Unknown`].
    #[must_use]
    pub const fn code(self) -> Option<u8> {
        match self {
            Self::Info => Some(1),
            Self::Alert => Some(2),
            Self::Unknown => None,
        }
    }

    /// The class of a stored code, `None` for an unknown one.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Info),
            2 => Some(Self::Alert),
            _ => None,
        }
    }
}

/// Defines an enum of wire names with fixed stored codes and an `Unknown` catch-all.
macro_rules! coded_enum {
    (
        $(#[$doc:meta])*
        $name:ident: $repr:ty { $( $(#[$vdoc:meta])* $variant:ident = $code:literal, )+ }
    ) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $( $(#[$vdoc])* $variant, )+
            /// A value this build does not know; only ever produced by parsing a newer server's
            /// answer. The server never sends it.
            #[serde(other)]
            Unknown,
        }

        impl $name {
            /// Every known value, in code order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The stored code, `None` for `Unknown`.
            #[must_use]
            pub const fn code(self) -> Option<$repr> {
                match self {
                    $( Self::$variant => Some($code), )+
                    Self::Unknown => None,
                }
            }

            /// The value of a stored code, `None` for one this build does not know.
            #[must_use]
            pub const fn from_code(code: $repr) -> Option<Self> {
                match code {
                    $( $code => Some(Self::$variant), )+
                    _ => None,
                }
            }
        }
    };
}

coded_enum! {
    /// The kind of an entry: the codes and names of ADR 0090 §3.
    SecurityEventKind: u16 {
        /// `register_finish` created the account.
        AccountCreated = 1,
        /// A login issued an OPAQUE session.
        PasswordLogin = 2,
        /// A supplied second factor was refused after the password was proven.
        SecondFactorFailed = 3,
        /// A durable device got its first certificate.
        DeviceEnrolled = 4,
        /// A device was suspended.
        DeviceSuspended = 5,
        /// A device's suspension was lifted.
        DeviceUnsuspended = 6,
        /// A device was revoked.
        DeviceRevoked = 7,
        /// The password or the Secret Key changed (the server cannot tell which).
        CredentialsChanged = 8,
        /// The account key was rotated.
        AccountKeyRotated = 9,
        /// The identity was rotated (a full rotation).
        IdentityRotated = 10,
        /// A new recovery code was set.
        RecoveryCodeChanged = 11,
        /// Recovery was disabled.
        RecoveryDisabled = 12,
        /// A recovery was started with the recovery code.
        RecoveryStarted = 13,
        /// A pending recovery was cancelled.
        RecoveryCancelled = 14,
        /// The recovery code opened a recovery-only session.
        RecoverySessionOpened = 15,
        /// A recovery committed new credentials.
        RecoveryCompleted = 16,
        /// TOTP was enabled.
        TotpEnabled = 17,
        /// TOTP was disabled.
        TotpDisabled = 18,
        /// A security key was added.
        SecurityKeyAdded = 19,
        /// A security key was removed.
        SecurityKeyRemoved = 20,
        /// A security key's counter did not advance: a possible clone (INV-83).
        SecurityKeyPossibleClone = 21,
        /// A session was ended.
        SessionEnded = 22,
        /// Every other session was ended.
        OtherSessionsEnded = 23,
        /// The recovery waiting period in force changed.
        RecoveryWaitChanged = 24,
        /// An administrator disabled the account.
        AccountDisabled = 25,
        /// An administrator enabled the account.
        AccountEnabled = 26,
        /// An administrator reset the second factor.
        SecondFactorResetByAdmin = 27,
    }
}

coded_enum! {
    /// Who acted: the codes and names of ADR 0090 §4 `actor_kind`.
    SecurityEventActorKind: u8 {
        /// An OPAQUE session (a password login).
        OpaqueSession = 1,
        /// A device-authenticated session.
        DeviceSession = 2,
        /// The recovery-only session.
        RecoverySession = 3,
        /// An anonymous request that presented the recovery code.
        RecoveryCode = 4,
        /// The event is the sign-in itself.
        SignIn = 5,
        /// An administrator, in the admin panel.
        AdminPanel = 6,
        /// The server operator, on the command line.
        OperatorCli = 7,
        /// The server on its own.
        Server = 8,
    }
}

impl SecurityEventKind {
    /// The class an entry of this kind gets (ADR 0090 §3). Code 24 depends on its values: it is
    /// an alert when the wait got shorter.
    #[must_use]
    pub fn class(self, value_old: Option<u64>, value_new: Option<u64>) -> SecurityEventClass {
        match self {
            Self::AccountCreated
            | Self::PasswordLogin
            | Self::DeviceSuspended
            | Self::DeviceRevoked
            | Self::AccountKeyRotated
            | Self::IdentityRotated
            | Self::RecoveryCancelled
            | Self::SessionEnded
            | Self::OtherSessionsEnded => SecurityEventClass::Info,
            Self::RecoveryWaitChanged => match (value_old, value_new) {
                (Some(old), Some(new)) if new < old => SecurityEventClass::Alert,
                _ => SecurityEventClass::Info,
            },
            Self::SecondFactorFailed
            | Self::DeviceEnrolled
            | Self::DeviceUnsuspended
            | Self::CredentialsChanged
            | Self::RecoveryCodeChanged
            | Self::RecoveryDisabled
            | Self::RecoveryStarted
            | Self::RecoverySessionOpened
            | Self::RecoveryCompleted
            | Self::TotpEnabled
            | Self::TotpDisabled
            | Self::SecurityKeyAdded
            | Self::SecurityKeyRemoved
            | Self::SecurityKeyPossibleClone
            | Self::AccountDisabled
            | Self::AccountEnabled
            | Self::SecondFactorResetByAdmin
            | Self::Unknown => SecurityEventClass::Alert,
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "the tests index fixed tables by code; a panic there fails the test, which CLAUDE.md allows"
)]
mod tests;
