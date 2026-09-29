//! The one error type of the client flows (ADR 0013 §3 rule 4: "Errors are typed and carry no
//! secrets. They cross as enums with stable codes, never with key bytes, plaintext or
//! passwords"; threat model INV-21).
//!
//! Every variant is a kind, nothing more: no variant holds a byte of a key, a password, a
//! plaintext, a token or a server answer. [`ClientError::code`] is the stable string a binding
//! passes to its host.

use core::fmt;

/// Why a client flow step failed. See the module docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ClientError {
    /// A value the host passed in is not acceptable: a login name or server origin that does
    /// not normalise, an empty or unassignable new password, a text too long for its field.
    /// ADR 0013 §3 rule 8: host input is untrusted.
    InvalidInput,
    /// OPAQUE failed, or `E_local` did not open: the master password or the Secret Key is wrong.
    /// Nothing says which one (CRYPTO.md §11.2 step 4, §5.6 step 3).
    WrongPasswordOrSecretKey,
    /// The server named a `kdf_id` that is not on this client's allow-list (CRYPTO.md §6.2,
    /// threat model INV-3). Nothing was stretched.
    KdfNotAllowed,
    /// The server's canonical origin is not the origin this client dialled (CRYPTO.md §5.3).
    OriginMismatch,
    /// The user has not confirmed the Emergency Kit by re-typing the last group of the Secret
    /// Key, so the signup commit is withheld (CRYPTO.md §7, §11 "Secrets before commit").
    EmergencyKitNotConfirmed,
    /// A server answer failed a check: a signature, a commitment the signed `account-state`
    /// makes, an envelope that did not open, an id that does not match (CRYPTO.md §11.2 step 6,
    /// §11.3 step 2.4). The flow aborts; nothing from the answer was adopted.
    InvalidServerResponse,
    /// The signed `account-state` went backwards against what this device persisted: a possible
    /// rollback by the server (CRYPTO.md §11.3 step 2.5, INV-25). The device goes read-only.
    Rollback,
    /// The server showed two versions of this account at one `state_seq` (CRYPTO.md §10.2,
    /// §11.3 step 2.5). The device goes read-only.
    Fork,
    /// The identity keys changed through a verified bundle chain, and the user has not
    /// confirmed the new fingerprint on this device (CRYPTO.md §11.3 step 3.2). Read-only until
    /// then.
    IdentityChangeUnconfirmed,
    /// The account key was rotated elsewhere; the device grants must be fetched and opened
    /// first (CRYPTO.md §11.3 step 4).
    AccountKeyRotated,
    /// The password or the Secret Key was changed on another device; this device needs an
    /// OPAQUE login with the new password (CRYPTO.md §11.3 step 5).
    PasswordChangedElsewhere,
    /// The vault is read-only: a rollback, a fork, an unconfirmed identity change, or the
    /// server is behind this device (ADR 0021 §9 "Server behind"). No op is written.
    ReadOnly,
    /// The item does not exist in this vault, or is not in a state the edit applies to.
    UnknownItem,
    /// A field write breaks a rule of the item schema (ADR 0018 §6–§8, §10), or the edit is
    /// not allowed on the item now (a purge of an item that is not trashed).
    InvalidEdit,
    /// The item's key or vault key epoch is not usable for a write: the vault key was rotated
    /// and this build does not re-wrap (CRYPTO.md §11.6 writer rule).
    StaleKey,
    /// The export file is not a well-formed rizzy-vault export: too large, not the strict JSON
    /// shape of CRYPTO.md §11.14, an unsupported format or version, or a malformed field.
    InvalidExportFile,
    /// The export password is wrong, or the export file was changed (one error, CRYPTO.md
    /// §9.5).
    ExportDecryptionFailed,
    /// An upload was asked for before any Fetch response or upload answer was seen: the
    /// restore generation the own-chain bookkeeping needs is unknown (ADR 0021 §2). Fetch
    /// first.
    FetchRequired,
    /// The session's request counter is exhausted. A new device authentication is needed.
    SessionExhausted,
    /// An internal step failed that the inputs cannot cause: a sealing, signing, encoding or
    /// derivation call that is unreachable for valid state. No detail is kept on purpose.
    Internal,
}

impl ClientError {
    /// The stable code of this error, for bindings and logs (ADR 0013 §3 rule 4). Codes never
    /// change meaning; new ones are only added.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::WrongPasswordOrSecretKey => "wrong_password_or_secret_key",
            Self::KdfNotAllowed => "kdf_not_allowed",
            Self::OriginMismatch => "origin_mismatch",
            Self::EmergencyKitNotConfirmed => "emergency_kit_not_confirmed",
            Self::InvalidServerResponse => "invalid_server_response",
            Self::Rollback => "rollback",
            Self::Fork => "fork",
            Self::IdentityChangeUnconfirmed => "identity_change_unconfirmed",
            Self::AccountKeyRotated => "account_key_rotated",
            Self::PasswordChangedElsewhere => "password_changed_elsewhere",
            Self::ReadOnly => "read_only",
            Self::UnknownItem => "unknown_item",
            Self::InvalidEdit => "invalid_edit",
            Self::StaleKey => "stale_key",
            Self::InvalidExportFile => "invalid_export_file",
            Self::ExportDecryptionFailed => "export_decryption_failed",
            Self::FetchRequired => "fetch_required",
            Self::SessionExhausted => "session_exhausted",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "the input is not acceptable",
            Self::WrongPasswordOrSecretKey => "wrong master password or Secret Key",
            Self::KdfNotAllowed => {
                "the server asked for key-derivation parameters this client refuses"
            }
            Self::OriginMismatch => "this is not the server's configured address",
            Self::EmergencyKitNotConfirmed => "the Emergency Kit has not been confirmed",
            Self::InvalidServerResponse => "the server's answer failed verification",
            Self::Rollback => "possible rollback by the server",
            Self::Fork => "the server has shown two versions of this account",
            Self::IdentityChangeUnconfirmed => {
                "the account's identity key changed and is not confirmed"
            }
            Self::AccountKeyRotated => "the account key was rotated on another device",
            Self::PasswordChangedElsewhere => "the password was changed on another device",
            Self::ReadOnly => "the vault is read-only",
            Self::UnknownItem => "no such item",
            Self::InvalidEdit => "the edit is not allowed",
            Self::StaleKey => "the item's key is from an older key epoch",
            Self::InvalidExportFile => "not a valid rizzy-vault export file",
            Self::ExportDecryptionFailed => "wrong export password, or the file was changed",
            Self::FetchRequired => "fetch the vault before uploading",
            Self::SessionExhausted => "the session must be renewed",
            Self::Internal => "internal error",
        })
    }
}

impl core::error::Error for ClientError {}

/// Maps an error that valid state cannot cause to [`ClientError::Internal`], dropping its
/// detail on purpose.
pub(crate) fn internal<E>(_: E) -> ClientError {
    ClientError::Internal
}

#[cfg(test)]
mod tests {
    use super::ClientError;

    #[test]
    fn codes_are_unique() {
        let all = [
            ClientError::InvalidInput,
            ClientError::WrongPasswordOrSecretKey,
            ClientError::KdfNotAllowed,
            ClientError::OriginMismatch,
            ClientError::EmergencyKitNotConfirmed,
            ClientError::InvalidServerResponse,
            ClientError::Rollback,
            ClientError::Fork,
            ClientError::IdentityChangeUnconfirmed,
            ClientError::AccountKeyRotated,
            ClientError::PasswordChangedElsewhere,
            ClientError::ReadOnly,
            ClientError::UnknownItem,
            ClientError::InvalidEdit,
            ClientError::StaleKey,
            ClientError::InvalidExportFile,
            ClientError::ExportDecryptionFailed,
            ClientError::FetchRequired,
            ClientError::SessionExhausted,
            ClientError::Internal,
        ];
        let mut codes: Vec<&str> = all.iter().map(|e| e.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len());
    }
}
