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
    /// The account key was rotated elsewhere, and the server holds no device grant for this
    /// device's next epoch: a restore undid the grants of a rotation this device missed
    /// (ADR 0032 §4 "A device that missed the rotation"). The device stays read-only; at a
    /// password unlock, once the server's OPAQUE record no longer lags, it catches up with an
    /// OPAQUE login ([`crate::unlock::catch_up_account_key`]).
    NoDeviceGrant,
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
    /// The item's key is not usable for a write (CRYPTO.md §11.6 writer rule). Not returned by
    /// this build any more: the writer generates a fresh item key instead. Kept so the stable
    /// code keeps its meaning.
    StaleKey,
    /// The export file is not a well-formed rizzy-vault export: too large, not the strict JSON
    /// shape of CRYPTO.md §11.14, an unsupported format or version, or a malformed field.
    InvalidExportFile,
    /// The export password is wrong, or the export file was changed (one error, CRYPTO.md
    /// §9.5).
    ExportDecryptionFailed,
    /// The export was written by a newer rizzy-vault: its payload version is not one this
    /// client reads (ADR 0027 §1: "refused as update required"). Nothing was imported.
    ExportUpdateRequired,
    /// The vault is too large for one export file: the encrypted payload would exceed 16 MiB
    /// (ADR 0027 §1 "Too large", refused before any key derivation), or the plaintext JSON
    /// would exceed a cap its reader applies (ADR 0027 §6). Nothing was written.
    ExportTooLarge,
    /// The vault holds an item that cannot be encoded within the ADR 0018 §10 limits (an
    /// oversize item), so no export is written (ADR 0027 §1 "Oversize items").
    /// [`crate::sync::VaultSync::export_blockers`] names the items; the user runs "duplicate
    /// as a new item" on them first.
    ExportOversizeItems,
    /// A plaintext export was asked for without the typed acknowledgement `EXPORT PLAINTEXT`
    /// (ADR 0027 §5). Nothing was written.
    PlaintextExportNotAcknowledged,
    /// An export was asked for without a fresh, unspent re-authentication of the account
    /// (owner decision 2026-10-05; [`crate::export::gate`]): log in again with the master
    /// password (and Secret Key), then export within five minutes. Nothing was written.
    ReauthRequired,
    /// A plaintext export was asked for before the hold after its warning ended
    /// ([`crate::export::gate::PLAINTEXT_EXPORT_HOLD_MS`], owner decision 2026-10-05), or
    /// without the warning shown. Nothing was written.
    PlaintextExportHold,
    /// An upload was asked for before any Fetch response or upload answer was seen: the
    /// restore generation the own-chain bookkeeping needs is unknown (ADR 0021 §2). Fetch
    /// first.
    FetchRequired,
    /// The session's request counter is exhausted. A new device authentication is needed.
    SessionExhausted,
    /// A rotation was asked for before this device uploaded its queued ops and snapshots and
    /// ran a complete Fetch of every vault afterwards (ADR 0025 §2 step 1). Sync, then retry.
    SyncRequired,
    /// The account changed in a way a rotation cannot absorb by rebuilding (an epoch, a key or
    /// a setting moved): discard the pending rotation and start it again with new keys (ADR 0025
    /// §2 step 5).
    RotationRestart,
    /// A rotation was refused five times in a row because the vault kept changing (ADR 0025 §2
    /// step 5). The pending rotation is kept; the host reports it and may try later.
    VaultKeepsChanging,
    /// The server answered an own op `stale_epoch`: a rotation elsewhere raised the vault's
    /// `vault_key_epoch` (ADR 0021 §9 "Stale epoch"; ADR 0025 §4). Process the new signed
    /// `account-state` and adopt the new vault key
    /// ([`crate::sync::VaultSync::adopt_vault_key`]), then upload again: the op is re-issued
    /// under the new epoch with the same `device_seq`.
    VaultKeyRotated,
    /// The server answered `stale_epoch` to an own op it may have stored and served before a
    /// restore lost it (ADR 0021 §9 "Stale epoch"): such an op is never re-issued, only
    /// re-published in a healing request. The host fetches, sends
    /// [`crate::sync::VaultSync::healing_request`] and uploads again.
    HealingRequired,
    /// The server is behind this device and no complete healing request can be built (ADR 0021
    /// §9 "Healing request"): a header in a chain's range is held with neither its body nor a
    /// held snapshot that covers it, the server lacks a dot this device holds no header of, or
    /// the request would exceed the wire limits. The vault stays read-only; the host reports it.
    CannotHeal,
    /// The local cache or the device-state record was written by a newer rizzy-vault: its
    /// `cache_meta.format` or record version is above what this build knows (ADR 0026 §5:
    /// "update required"). Nothing was read and nothing is written.
    CacheUpdateRequired,
    /// The local cache does not load (ADR 0026 §5 (a), (b), (d)): a table, a meta key or the
    /// device-state record is missing or malformed, a signed statement or an account object
    /// fails its check, a column disagrees with the statement it indexes, or an own row breaks
    /// the own chain. The load fails as a whole; nothing is shown, written or uploaded, and the
    /// cache is never dropped silently. The recourse is "remove this device" and a new
    /// enrolment.
    CacheCorrupt,
    /// The device-state record is signup-pending (ADR 0026 §2, `stage = 2`): the stored
    /// `register/finish` request must be resent and acknowledged before anything else runs.
    SignupPending,
    /// The device state holds no `E_local` (ADR 0026 §2, `has_local = 0`): it cannot unlock;
    /// the one path left is CRYPTO.md §11.3 step 5, "I changed my password on another device".
    LocalUnlockUnavailable,
    /// The server refused a registration's OPAQUE setup (`setup_retired`) again after the
    /// registration was restarted once under the current setup (ADR 0031 point 8, "Risks": at
    /// most one restart per commit attempt). The pending change is kept; the host reports it.
    SetupRetired,
    /// The device state is older than this device's own history (ADR 0026 §4 step 7, owner
    /// decision on open question 5): the server holds an own `device_seq` this file lacks, or
    /// holds another record at an own dot. A restored image or a copied profile. The device is
    /// read-only; the one resolution is removal and a new enrolment.
    DeviceStateOutdated,
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
            Self::NoDeviceGrant => "no_device_grant",
            Self::PasswordChangedElsewhere => "password_changed_elsewhere",
            Self::ReadOnly => "read_only",
            Self::UnknownItem => "unknown_item",
            Self::InvalidEdit => "invalid_edit",
            Self::StaleKey => "stale_key",
            Self::InvalidExportFile => "invalid_export_file",
            Self::ExportDecryptionFailed => "export_decryption_failed",
            Self::ExportUpdateRequired => "export_update_required",
            Self::ExportTooLarge => "export_too_large",
            Self::ExportOversizeItems => "export_oversize_items",
            Self::PlaintextExportNotAcknowledged => "plaintext_export_not_acknowledged",
            Self::ReauthRequired => "reauth_required",
            Self::PlaintextExportHold => "plaintext_export_hold",
            Self::FetchRequired => "fetch_required",
            Self::SessionExhausted => "session_exhausted",
            Self::SyncRequired => "sync_required",
            Self::RotationRestart => "rotation_restart",
            Self::VaultKeepsChanging => "vault_keeps_changing",
            Self::VaultKeyRotated => "vault_key_rotated",
            Self::HealingRequired => "healing_required",
            Self::CannotHeal => "cannot_heal",
            Self::CacheUpdateRequired => "cache_update_required",
            Self::CacheCorrupt => "cache_corrupt",
            Self::SignupPending => "signup_pending",
            Self::LocalUnlockUnavailable => "local_unlock_unavailable",
            Self::DeviceStateOutdated => "device_state_outdated",
            Self::SetupRetired => "setup_retired",
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
            Self::NoDeviceGrant => {
                "the account key was rotated on another device, and the server holds no key for \
                 this device; open a device that saw the change"
            }
            Self::PasswordChangedElsewhere => "the password was changed on another device",
            Self::ReadOnly => "the vault is read-only",
            Self::UnknownItem => "no such item",
            Self::InvalidEdit => "the edit is not allowed",
            Self::StaleKey => "the item's key is from an older key epoch",
            Self::InvalidExportFile => "not a valid rizzy-vault export file",
            Self::ExportDecryptionFailed => "wrong export password, or the file was changed",
            Self::ExportUpdateRequired => {
                "the export was written by a newer rizzy-vault; update to import it"
            }
            Self::ExportTooLarge => "the vault is too large for one export file",
            Self::ExportOversizeItems => "an item is too large to export; duplicate it first",
            Self::PlaintextExportNotAcknowledged => {
                "the plaintext export was not confirmed by typing EXPORT PLAINTEXT"
            }
            Self::ReauthRequired => {
                "confirm your master password (and Secret Key) again before exporting"
            }
            Self::PlaintextExportHold => {
                "read the warning: the plaintext export waits 10 seconds after it is shown"
            }
            Self::FetchRequired => "fetch the vault before uploading",
            Self::SessionExhausted => "the session must be renewed",
            Self::SyncRequired => "upload and fetch every vault first",
            Self::RotationRestart => "the account changed; start the rotation again",
            Self::VaultKeepsChanging => "the vault keeps changing",
            Self::VaultKeyRotated => "the vault key was rotated on another device",
            Self::HealingRequired => "the server lost an own change and needs healing",
            Self::CannotHeal => {
                "the server lost changes that this device cannot send back; the vault stays read-only"
            }
            Self::CacheUpdateRequired => {
                "the local data was written by a newer rizzy-vault; update required"
            }
            Self::CacheCorrupt => {
                "the local data does not load; remove this device and enrol it again"
            }
            Self::SignupPending => "the signup has not been acknowledged yet",
            Self::LocalUnlockUnavailable => "this device can no longer unlock with a password",
            Self::DeviceStateOutdated => "the local data is older than this device's own history",
            Self::SetupRetired => {
                "the server refused the registration again after it was restarted; try later"
            }
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
            ClientError::NoDeviceGrant,
            ClientError::PasswordChangedElsewhere,
            ClientError::ReadOnly,
            ClientError::UnknownItem,
            ClientError::InvalidEdit,
            ClientError::StaleKey,
            ClientError::InvalidExportFile,
            ClientError::ExportDecryptionFailed,
            ClientError::ExportUpdateRequired,
            ClientError::ExportTooLarge,
            ClientError::ExportOversizeItems,
            ClientError::PlaintextExportNotAcknowledged,
            ClientError::ReauthRequired,
            ClientError::PlaintextExportHold,
            ClientError::FetchRequired,
            ClientError::SessionExhausted,
            ClientError::SyncRequired,
            ClientError::RotationRestart,
            ClientError::VaultKeepsChanging,
            ClientError::VaultKeyRotated,
            ClientError::HealingRequired,
            ClientError::CannotHeal,
            ClientError::CacheUpdateRequired,
            ClientError::CacheCorrupt,
            ClientError::SignupPending,
            ClientError::LocalUnlockUnavailable,
            ClientError::DeviceStateOutdated,
            ClientError::SetupRetired,
            ClientError::Internal,
        ];
        let mut codes: Vec<&str> = all.iter().map(|e| e.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len());
    }
}
