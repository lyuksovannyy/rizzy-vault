//! What the auth domain needs from the vault domain (ADR 0016 R4).
//!
//! No `rizzy-domain-*` crate depends on another: "A domain that needs something from another
//! defines a trait for it. `rizzy-server` implements the trait by wiring in the other domain's
//! public API." The auth flows touch the vault's tables in five places, and each is one
//! transaction with the auth rows, never a chain of events (ADR 0011 "Transactions and
//! concurrency": a cross-domain operation is one transaction that takes the account lock once):
//!
//! - **Signup** stores the personal vault's self-grant with the account (CRYPTO.md §11.1 step
//!   8), and a byte-identical repeat must compare it too.
//! - **Account views** (login §11.2 step 5, unlock §11.3 step 2.2, recovery §11.9 step 3) carry
//!   the vault self-grants.
//! - **Recovery complete** (§11.9 step 3; ADR 0025 §1) also carries every vault's heads and
//!   wrap set, so the recovering client can rotate without a vault endpoint.
//! - **Revocation** needs H, the highest `device_seq` the server holds from a device (§11.8
//!   step 0; ADR 0012 §6); healing step 3a compares re-sent self-grants with the stored ones
//!   and never stores one (ADR 0032 §3: only `vault/heal` repairs a self-grant).
//! - **Rotation** (§11.6 steps 3 and 9, and the revocation and recovery that carry one) hands
//!   the vault half of the upload (its fetch cursor, self-grants and re-wrapped item keys) to
//!   the vault domain in the same transaction ([`VaultPort::apply_rotation`], ADR 0025 §3–§4).
//!
//! Every method runs on the caller's transaction ([`WriteTx`] or [`Conn`]), which already
//! holds the account lock where one is needed; an implementation queries only `vault_` tables.
//! The futures are `Send`, so the auth flows stay usable from a multi-threaded runtime.

use core::future::Future;

use rizzy_core::ids::{AccountId, DeviceId};
use rizzy_proto::change::VaultRotationUpload;
use rizzy_proto::objects::VaultSelfGrant;
use rizzy_proto::recovery::RecoveryVault;
use rizzy_storage::{Conn, WriteTx};

use crate::error::AuthError;

/// The outcome of storing a signup's personal vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersonalVault {
    /// The vault and its self-grant were created.
    Created,
    /// A vault with this id already exists with byte-identical grant contents: a repeat of the
    /// same signup (CRYPTO.md §11.1 step 8).
    Identical,
    /// A vault with this id exists with other contents, or belongs to another account.
    Conflict,
}

/// The vault domain's side of the auth flows. See the module docs.
pub trait VaultPort: Send + Sync {
    /// The vault half of a rotation upload (CRYPTO.md §11.6 steps 3 and 9; ADR 0012 §6; ADR
    /// 0025 §1): the rotating device's fetch cursor, the new vault self-grants and the
    /// re-wrapped item keys. Its checks are the vault domain's; this crate only carries it into
    /// the one transaction of the change.
    type Rotation: Send + Sync;

    /// The vault half as the vault domain takes it, from its parsed wire form (the
    /// `vault_rotation` field of `CommitChangeRequest`).
    fn rotation_from_wire(upload: VaultRotationUpload) -> Self::Rotation;

    /// A rotation (§11.6 step 9), in `tx` after every auth-side check passed and before the
    /// compare-and-swap (ADR 0025 §4): checks the upload against every vault the account owns
    /// (a new self-grant under `new_account_key_epoch` whose envelope names
    /// `new_account_key_id`, at a `vault_key_epoch` above the stored one; every stored wrap-set
    /// row re-wrapped or dropped; the exact cursor of the rotation cut-off, ADR 0012 §6), then
    /// stores the grants and re-wraps, deletes the dropped rows and the superseded wraps.
    /// Refuses with [`AuthError::StateConflict`] when the server holds what the rotator has not
    /// seen and [`AuthError::InvalidRequest`] when the upload is malformed or incomplete.
    fn apply_rotation(
        &self,
        tx: &mut WriteTx,
        account_id: AccountId,
        new_account_key_epoch: u32,
        new_account_key_id: [u8; 16],
        rotation: &Self::Rotation,
        now_ms: u64,
    ) -> impl Future<Output = Result<(), AuthError>> + Send;

    /// Signup (§11.1 step 8): creates the personal vault named by `grant.vault_id` for
    /// `account_id` at `vault_key_epoch = grant.vault_key_epoch`, with `grant` as its current
    /// self-grant, in `tx`.
    fn create_personal_vault(
        &self,
        tx: &mut WriteTx,
        account_id: AccountId,
        grant: &VaultSelfGrant,
        now_ms: u64,
    ) -> impl Future<Output = Result<PersonalVault, AuthError>> + Send;

    /// The account's current vault self-grants, the ones under `account_key_epoch` (§11.2 step
    /// 5: "the vault self-grants"; §11.2 step 6 opens each with that epoch).
    fn self_grants(
        &self,
        conn: Conn<'_>,
        account_id: AccountId,
        account_key_epoch: u32,
    ) -> impl Future<Output = Result<Vec<VaultSelfGrant>, AuthError>> + Send;

    /// Recovery complete (§11.9 step 3; ADR 0025 §1): every vault of the account with its
    /// current self-grant, heads and wrap set, ascending by vault id, on the caller's
    /// connection (one consistent read with the rest of the answer).
    fn recovery_vaults(
        &self,
        conn: Conn<'_>,
        account_id: AccountId,
    ) -> impl Future<Output = Result<Vec<RecoveryVault>, AuthError>> + Send;

    /// H: the highest `device_seq` the server holds from `device_id` in any of the account's
    /// vaults, 0 for none (§11.8 step 0, ADR 0012 §6).
    fn device_head(
        &self,
        conn: Conn<'_>,
        account_id: AccountId,
        device_id: DeviceId,
    ) -> impl Future<Output = Result<u64, AuthError>> + Send;
}
