//! Account recovery with the Emergency Kit (CRYPTO.md §11.9; ADR 0008; ADR 0025 §1).
//!
//! | Flow step | Request | Response |
//! |---|---|---|
//! | Start, §11.9 step 2 | [`RecoveryRequest`] | [`RecoveryStartResponse`] |
//! | Cancel, §11.9 step 2 (a device session) | – | [`RecoveryCancelResponse`] |
//! | Complete, §11.9 step 3 | [`RecoveryRequest`] | [`RecoveryCompleteResponse`] |
//! | Commit, §11.9 steps 5–6 | [`CommitChangeRequest`](crate::change::CommitChangeRequest) over the recovery-only session | empty success |
//!
//! Start and complete carry `{login_name, recovery_auth_token}` (§11.9 steps 2 and 3). The token
//! is a secret ([`RecoveryAuthToken`]); the recovery code itself never travels. An unknown name
//! and a wrong code get the same answer (§5.9), so nothing in these responses exists before
//! the code has matched.

use serde::{Deserialize, Serialize};

use crate::account::AccountView;
use crate::auth::LoginName;
use crate::limits::{MAX_ITEM_KEY_WRAPS, MAX_VAULT_GRANTS, RECOVERY_AUTH_TOKEN_LEN};
use crate::objects::{AccountKeyRecoveryWrap, ItemKeyWrap, VaultSelfGrant};
use crate::vault::SeqVector;
use crate::wire::{Id, List, SecretFixed, SessionToken};

/// The recovery auth token (CRYPTO.md §4.3): 32 bytes derived from the recovery code, which
/// the server compares as `SHA-256(token)` with `H_rec` in constant time (§11.9 step 2). A
/// secret: zeroized on drop, `Debug` redacted.
pub type RecoveryAuthToken = SecretFixed<RECOVERY_AUTH_TOKEN_LEN>;

/// Recovery start and complete (CRYPTO.md §11.9 steps 2 and 3: `{login_name,
/// recovery_auth_token}`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRequest {
    /// The login name.
    pub login_name: LoginName,
    /// The recovery auth token.
    pub recovery_auth_token: RecoveryAuthToken,
}

/// The answer to a recovery start with a valid code (CRYPTO.md §11.9 step 2): the pending
/// recovery's end of the waiting period.
///
/// A response type: unknown fields are ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryStartResponse {
    /// When the waiting period ends and complete may succeed, ms since the Unix epoch.
    pub available_at_ms: u64,
}

/// The answer to a cancellation (CRYPTO.md §11.9 step 2: "Any enrolled device with a
/// device-authenticated session can cancel the pending recovery").
///
/// A response type: unknown fields are ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryCancelResponse {
    /// Whether a recovery was pending (and is now cancelled).
    pub cancelled: bool,
}

/// One vault of the recovering account, for the rotation of CRYPTO.md §11.9 step 5 (ADR 0025
/// §1): its current self-grant, the server's heads h(V, d) and its whole item-key wrap set,
/// read in one consistent read with the rest of [`RecoveryCompleteResponse`].
///
/// The recovering client holds no replica: it sends `heads` as its rotation cursor, re-wraps
/// the rows it can open and drops the rest. So the recovery-only session never needs a vault
/// endpoint (ADR 0025 open question 7, decided). Nothing here is trusted: the self-grant opens
/// under the recovered account key or the recovery stops, and every row is opened with the
/// context rebuilt from its locator.
///
/// A response type: unknown fields are ignored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryVault {
    /// The vault.
    pub vault_id: Id,
    /// Its current self-grant.
    pub self_grant: VaultSelfGrant,
    /// The server's head h(V, d) for every device with ops in the vault.
    pub heads: SeqVector,
    /// Every wrap-set row of the vault.
    pub item_key_wraps: List<ItemKeyWrap, MAX_ITEM_KEY_WRAPS>,
}

/// The answer to a recovery complete after the wait (CRYPTO.md §11.9 step 3): `E_rec` with its
/// epochs, the account objects, the vaults with their heads and item-key wraps, and a
/// recovery-only session with a 10-minute TTL that covers the recovery commit only.
///
/// `H_rec` is not returned: [`AccountKeyRecoveryWrap`] has no field for it.
///
/// A response type: unknown fields are ignored.
#[derive(Debug, Serialize, Deserialize)]
pub struct RecoveryCompleteResponse {
    /// The bearer token of the recovery-only session. A secret.
    pub session_token: SessionToken,
    /// The account.
    pub account_id: Id,
    /// `E_rec` with the epochs of its context.
    pub recovery_wrap: AccountKeyRecoveryWrap,
    /// The whole bundle chain, the state, the certificates and revocations, `E_id`,
    /// `ACCOUNT_SETTINGS` and the self-grants.
    pub account: AccountView,
    /// Every vault of the account, ascending by id, with its heads and wrap set (ADR 0025 §1).
    pub vaults: List<RecoveryVault, MAX_VAULT_GRANTS>,
}
