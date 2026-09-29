//! The vault domain's side of the `auth` domain's cross-domain flows (ADR 0016 R4).
//!
//! `rizzy-domain-auth` defines the trait (`VaultPort`) and `rizzy-server` implements it with the
//! functions here, so neither domain depends on the other. Each one runs on the caller's
//! transaction or connection, which already holds the account lock where one is needed
//! (ADR 0011 "Transactions and concurrency": a cross-domain operation is one transaction that
//! takes the lock once), and queries only `vault_` tables (ADR 0011 point 5).
//!
//! | Function | The `auth` flow it serves |
//! |---|---|
//! | [`create_personal_vault`] | Signup (CRYPTO.md §11.1 step 8), with its byte-identical repeat |
//! | [`self_grants`] | Account views (§11.2 step 5, §11.3 step 2.2) |
//! | [`store_self_grants`] | Restore healing step 3 (ADR 0012 §7) |
//! | [`device_head`] | Revocation phase 1, H (§11.8 step 0; ADR 0012 §6) |
//!
//! The key-rotation upload (§11.6 step 9) is not here: its vault half has no wire form yet (see
//! [`crate::keys`]).

use rizzy_core::ids::{AccountId, DeviceId, VaultId};
use rizzy_proto::objects::{KeyEnvelope, VaultSelfGrant};
use rizzy_proto::wire::Id;
use rizzy_storage::{Conn, WriteTx};

use crate::error::VaultError;
use crate::keys::{create_vault, republish_in};
use crate::repo;

/// The outcome of [`create_personal_vault`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersonalVaultOutcome {
    /// The vault and its self-grant were created.
    Created,
    /// The vault exists for this account at `vault_key_epoch` 0 with a byte-identical
    /// self-grant: a repeat of the same signup (CRYPTO.md §11.1 step 8).
    Identical,
    /// A vault with this id exists with other contents, or belongs to another account.
    Conflict,
}

/// Reborrows a [`Conn`] for one more query.
fn reborrow<'a>(conn: &'a mut Conn<'_>) -> Conn<'a> {
    match conn {
        Conn::Sqlite(c) => Conn::Sqlite(c),
        Conn::Postgres(c) => Conn::Postgres(c),
    }
}

/// Signup (CRYPTO.md §11.1 step 8): creates the personal vault `grant.vault_id` for
/// `account_id` with `grant` as its first self-grant ([`create_vault`]), in the caller's write
/// transaction, which has taken the account's lock. A vault that already exists is compared
/// instead: the same account, `vault_key_epoch` 0 and a byte-identical grant is
/// [`PersonalVaultOutcome::Identical`], anything else [`PersonalVaultOutcome::Conflict`].
///
/// # Errors
/// [`VaultError::Invalid`] for a grant whose `vault_key_epoch` is not 0; [`VaultError::Storage`]
/// or [`VaultError::Corrupt`].
pub async fn create_personal_vault(
    tx: &mut WriteTx,
    account_id: AccountId,
    grant: &VaultSelfGrant,
    now_ms: u64,
) -> Result<PersonalVaultOutcome, VaultError> {
    let vault_id = VaultId::from_bytes(grant.vault_id.to_bytes());
    let Some(vault) = repo::vault(tx.conn(), vault_id).await? else {
        create_vault(tx, account_id, grant, now_ms).await?;
        return Ok(PersonalVaultOutcome::Created);
    };
    let stored = repo::self_grant(tx.conn(), vault_id).await?;
    let identical = vault.account_id == account_id
        && vault.vault_key_epoch == 0
        && stored.is_some_and(|s| {
            s.account_key_epoch == grant.account_key_epoch
                && s.vault_key_epoch == grant.vault_key_epoch
                && s.envelope.as_slice() == grant.envelope.as_slice()
        });
    Ok(if identical {
        PersonalVaultOutcome::Identical
    } else {
        PersonalVaultOutcome::Conflict
    })
}

/// The account's current vault self-grants under `account_key_epoch`, ordered by vault id
/// (CRYPTO.md §11.2 step 5: "the vault self-grants"; step 6 opens each with that epoch). A
/// vault whose current self-grant is under another epoch is left out.
///
/// # Errors
/// [`VaultError::Storage`] or [`VaultError::Corrupt`].
pub async fn self_grants(
    mut conn: Conn<'_>,
    account_id: AccountId,
    account_key_epoch: u32,
) -> Result<Vec<VaultSelfGrant>, VaultError> {
    let vaults = repo::list_vaults(reborrow(&mut conn), account_id).await?;
    let mut grants = Vec::with_capacity(vaults.len());
    for vault_id in vaults {
        let Some(row) = repo::self_grant(reborrow(&mut conn), vault_id).await? else {
            continue;
        };
        if row.account_key_epoch != account_key_epoch {
            continue;
        }
        grants.push(VaultSelfGrant {
            vault_id: Id::from_bytes(vault_id.to_bytes()),
            account_key_epoch: row.account_key_epoch,
            vault_key_epoch: row.vault_key_epoch,
            envelope: KeyEnvelope::new(row.envelope).map_err(|_| VaultError::Corrupt {
                what: "vault_self_grants.envelope length",
            })?,
        });
    }
    Ok(grants)
}

/// Restore healing step 3 (ADR 0012 §7): stores re-uploaded self-grants of the account's
/// vaults, each under the rules of [`VaultDomain::republish_self_grant`](crate::VaultDomain):
/// only during the account's reconciliation epoch, only when newer in both epochs (a stored
/// grant with a newer `account_key_epoch` is kept), never above a `vault_key_epoch` the server
/// verified. In the caller's write transaction, which holds the account lock.
///
/// # Errors
/// [`VaultError::NotFound`] for a vault of another account or none; [`VaultError::Invalid`]
/// outside the reconciliation epoch or for an unverified `vault_key_epoch`;
/// [`VaultError::Storage`] or [`VaultError::Corrupt`]. The caller drops the transaction then.
pub async fn store_self_grants(
    tx: &mut WriteTx,
    account_id: AccountId,
    grants: &[VaultSelfGrant],
    now_ms: u64,
) -> Result<(), VaultError> {
    for grant in grants {
        republish_in(tx, account_id, grant, now_ms).await?;
    }
    Ok(())
}

/// H: the highest `device_seq` the server holds from `device_id` in any of the account's
/// vaults, 0 for none (CRYPTO.md §11.8 step 0, ADR 0012 §6).
///
/// # Errors
/// [`VaultError::Storage`] or [`VaultError::Corrupt`].
pub async fn device_head(
    mut conn: Conn<'_>,
    account_id: AccountId,
    device_id: DeviceId,
) -> Result<u64, VaultError> {
    let vaults = repo::list_vaults(reborrow(&mut conn), account_id).await?;
    let mut head = 0;
    for vault_id in vaults {
        let heads = repo::heads(reborrow(&mut conn), vault_id).await?;
        head = head.max(heads.get(device_id));
    }
    Ok(head)
}
