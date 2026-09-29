//! What the auth domain needs from the vault domain (ADR 0016 R4).
//!
//! No `rizzy-domain-*` crate depends on another: "A domain that needs something from another
//! defines a trait for it. `rizzy-server` implements the trait by wiring in the other domain's
//! public API." The auth flows touch the vault's tables in four places, and each is one
//! transaction with the auth rows, never a chain of events (ADR 0011 "Transactions and
//! concurrency": a cross-domain operation is one transaction that takes the account lock once):
//!
//! - **Signup** stores the personal vault's self-grant with the account (CRYPTO.md §11.1 step
//!   8), and a byte-identical repeat must compare it too.
//! - **Account views** (login §11.2 step 5, unlock §11.3 step 2.2, recovery §11.9 step 3) carry
//!   the vault self-grants.
//! - **Revocation** needs H, the highest `device_seq` the server holds from a device (§11.8
//!   step 0; ADR 0012 §6), and healing step 3 stores self-grants (ADR 0012 §7).
//! - **Rotation** (§11.6 steps 3 and 9, and the revocation and recovery that carry one) hands
//!   the vault half of the upload (its fetch cursor, self-grants and re-wrapped item keys) to
//!   the vault domain in the same transaction ([`VaultPort::apply_rotation`]).
//!
//! Every method runs on the caller's transaction ([`WriteTx`] or [`Conn`]), which already
//! holds the account lock where one is needed; an implementation queries only `vault_` tables.
//! The futures are `Send`, so the auth flows stay usable from a multi-threaded runtime.

use core::future::Future;

use rizzy_core::ids::{AccountId, DeviceId};
use rizzy_proto::objects::VaultSelfGrant;
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
    /// The vault half of a rotation upload (CRYPTO.md §11.6 steps 3 and 9; ADR 0012 §6): the
    /// rotating device's fetch cursor, the new vault self-grants and the re-wrapped item keys.
    /// Its wire form and its checks are the vault domain's; this crate only carries it into
    /// the one transaction of the change.
    type Rotation: Send + Sync;

    /// A rotation (§11.6 step 9), in `tx` after every auth-side check passed: applies the
    /// rotation cut-off of ADR 0012 §6 against the fetch cursor in `rotation`, requires a new
    /// self-grant at `vault_key_epoch + 1` under `new_account_key_epoch` for every vault the
    /// account owns, stores them and the re-wrapped item keys, and deletes the superseded
    /// wraps. Refuses with [`AuthError::StateConflict`] when the cut-off fails (the server
    /// holds records beyond the cursor) and [`AuthError::InvalidRequest`] when the upload is
    /// incomplete.
    fn apply_rotation(
        &self,
        tx: &mut WriteTx,
        account_id: AccountId,
        new_account_key_epoch: u32,
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

    /// Healing step 3 (ADR 0012 §7): stores re-uploaded self-grants of the account's vaults.
    /// An implementation keeps a stored grant whose `account_key_epoch` is newer.
    fn store_self_grants(
        &self,
        tx: &mut WriteTx,
        account_id: AccountId,
        grants: &[VaultSelfGrant],
        now_ms: u64,
    ) -> impl Future<Output = Result<(), AuthError>> + Send;

    /// H: the highest `device_seq` the server holds from `device_id` in any of the account's
    /// vaults, 0 for none (§11.8 step 0, ADR 0012 §6).
    fn device_head(
        &self,
        conn: Conn<'_>,
        account_id: AccountId,
        device_id: DeviceId,
    ) -> impl Future<Output = Result<u64, AuthError>> + Send;
}
