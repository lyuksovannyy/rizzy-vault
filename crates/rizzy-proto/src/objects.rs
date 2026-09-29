//! The signed statements, envelopes and wrapped-key objects the messages carry.
//!
//! None of these is parsed here. Each travels as the bytes `rizzy-core` writes and verifies:
//! - **Signed statements** in the wire form of CRYPTO.md §9.6,
//!   `bytes(u16(statement_version) ‖ body) ‖ signature container(s)`, for every statement of
//!   §10.2 except `device-auth` and `device-request`, which travel as one bare
//!   [`SignatureContainer`].
//! - **Envelopes** (§9.1, §9.2) as opaque bytes; the server never opens one (ADR 0002 point 3).
//! - **Wrapped-key objects** with the cleartext locator CRYPTO.md §4.2 requires: "ids, epochs
//!   and, for `ITEM_KEY_WRAP`, the item key's id, so that the server can file them. The locator
//!   is never trusted." Each locator here is the part of the object's §8.4 AAD context that
//!   the carrying message does not already name (the account is the session's; the vault is the
//!   request's). A reader rebuilds the context from where it expected the object and fails on a
//!   lie; the server checks locators against the signed `account-state` where the state names
//!   the same epoch.
//!
//! **Unknown fields.** These types appear in requests, so they reject unknown fields, like every
//! request type (CRYPTO.md §11.1 step 8: "the server rejects requests with unknown fields"). A
//! consequence for responses: a field added to one of these types is not an additive change
//! for old clients; add it next to the object in the response instead.

use serde::{Deserialize, Serialize};

use crate::limits::{
    MAX_ACCOUNT_STATEMENT_LEN, MAX_ENVELOPE_LEN, MAX_KEY_ENVELOPE_LEN, MAX_KEY_GRANT_STATEMENT_LEN,
    MAX_OP_STATEMENT_LEN, MAX_OPAQUE_MESSAGE_LEN, MAX_SNAPSHOT_STATEMENT_LEN,
    SIGNATURE_CONTAINER_LEN,
};
use crate::wire::{Bytes, Fixed, Id};

/// An account-level signed statement in wire form: `public-key-bundle`, `device-certificate`,
/// `device-revocation` or `account-state` (CRYPTO.md §9.6, §10.2).
pub type AccountStatement = Bytes<MAX_ACCOUNT_STATEMENT_LEN>;

/// An `op` statement in wire form (CRYPTO.md §10.2; ADR 0012 §3): the canonical op header, the
/// SHA-256 of the body envelope and of the key wrap (or 32 zero bytes), and the author device's
/// signature.
pub type OpStatement = Bytes<MAX_OP_STATEMENT_LEN>;

/// A `snapshot` statement in wire form (CRYPTO.md §10.2; ADR 0012 §3).
pub type SnapshotStatement = Bytes<MAX_SNAPSHOT_STATEMENT_LEN>;

/// A `key-grant` statement in wire form (CRYPTO.md §10.1). Its body holds the HPKE envelope
/// itself, so a grant carries no separate envelope.
pub type KeyGrantStatement = Bytes<MAX_KEY_GRANT_STATEMENT_LEN>;

/// One bare signature container (CRYPTO.md §9.3): the form of `device-auth` and
/// `device-request` (§9.6, "Exception"). Exactly 82 bytes, the only container M1 defines.
pub type SignatureContainer = Fixed<SIGNATURE_CONTAINER_LEN>;

/// An envelope of any size up to the M1 limit (CRYPTO.md §9.1): op bodies, snapshots,
/// `ACCOUNT_SETTINGS`.
pub type Envelope = Bytes<MAX_ENVELOPE_LEN>;

/// A key-wrap envelope: fixed-size, unpadded, small (CRYPTO.md §8.5).
pub type KeyEnvelope = Bytes<MAX_KEY_ENVELOPE_LEN>;

/// One OPAQUE protocol message of the M1 suite (CRYPTO.md §5.1): registration request,
/// response and upload, KE1, KE2, KE3. Never logged (threat model INV-48); `Debug` prints the
/// length only.
pub type OpaqueMessage = Bytes<MAX_OPAQUE_MESSAGE_LEN>;

/// `E_srv`, the account key wrapped under `server_unlock_key` (`ACCOUNT_KEY_SERVER_WRAP`,
/// CRYPTO.md §8.4), with its locator: the epochs and `kdf_id` of its context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountKeyServerWrap {
    /// `account_key_epoch` of the context.
    pub account_key_epoch: u32,
    /// `password_epoch` of the context.
    pub password_epoch: u32,
    /// `kdf_id` of the context.
    pub kdf_id: u16,
    /// The envelope.
    pub envelope: KeyEnvelope,
}

/// `E_id`, the identity secret keys under the account key (`IDENTITY_SECRET_KEYS`, CRYPTO.md
/// §8.4), with its locator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySecretKeys {
    /// `identity_epoch` of the context.
    pub identity_epoch: u32,
    /// The envelope.
    pub envelope: KeyEnvelope,
}

/// `E_rec` (CRYPTO.md §11.1 step 5): the account key under the recovery wrap key
/// (`ACCOUNT_KEY_RECOVERY_WRAP`, §8.4), with its locator.
///
/// It travels both ways. The client uploads it at signup and on every recovery re-registration
/// (§11.1 step 8, §11.9 step 5); the recovery-complete response of §11.9 step 3 returns it
/// with its locator. `H_rec` is deliberately not a field here: it is request-only and travels
/// beside this object in [`RecoveryRegistration`](crate::auth::RecoveryRegistration), so a
/// response that carries `E_rec` cannot carry `H_rec` by reusing this type (§11.9 step 3 does
/// not list `H_rec` among the returned objects).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountKeyRecoveryWrap {
    /// `account_key_epoch` of the context.
    pub account_key_epoch: u32,
    /// `recovery_epoch` of the context.
    pub recovery_epoch: u32,
    /// The envelope.
    pub envelope: KeyEnvelope,
}

/// A vault self-grant (`VAULT_KEY_SELF_GRANT`, CRYPTO.md §8.4) with its locator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultSelfGrant {
    /// `vault_id` of the context.
    pub vault_id: Id,
    /// `account_key_epoch` of the context.
    pub account_key_epoch: u32,
    /// `vault_key_epoch` of the context.
    pub vault_key_epoch: u32,
    /// The envelope.
    pub envelope: KeyEnvelope,
}

/// A signed `ACCOUNT_KEY_DEVICE_GRANT` (CRYPTO.md §8.4, §10.1) with its locator: the context's
/// new `account_key_epoch` and the sender and recipient device ids. The `key-grant` statement
/// carries the HPKE envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceGrant {
    /// The new `account_key_epoch` of the context.
    pub account_key_epoch: u32,
    /// The sender `device_id` of the context.
    pub sender_device_id: Id,
    /// The recipient `device_id` of the context.
    pub recipient_device_id: Id,
    /// The `key-grant` statement, envelope included.
    pub key_grant: KeyGrantStatement,
}

/// The `ACCOUNT_SETTINGS` envelope (CRYPTO.md §8.4) with its locator, `settings_seq`. The signed
/// `account-state` commits to both (§10.2 "Settings freshness").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountSettings {
    /// `settings_seq` of the context.
    pub settings_seq: u64,
    /// The envelope.
    pub envelope: Envelope,
}

/// An item-key wrap-set row (`ITEM_KEY_WRAP`, CRYPTO.md §4.2, §8.4) with its locator; the vault
/// is the one the carrying request or response names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemKeyWrap {
    /// `item_id` of the context.
    pub item_id: Id,
    /// The wrapped item key's key id (§4.4), which files the row.
    pub item_key_id: Id,
    /// `vault_key_epoch` of the context: the wrapping vault key's epoch.
    pub vault_key_epoch: u32,
    /// The envelope.
    pub envelope: KeyEnvelope,
}
