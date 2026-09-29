//! Vault rows, vault self-grants and the item-key wrap set (CRYPTO.md §4.2: "`VAULT_KEY_SELF_GRANT`
//! | Server, `vault` domain"; "`ITEM_KEY_WRAP` | Server, `vault` domain: the current wrap set").
//!
//! - **Vault creation** ([`create_vault`]) runs inside the caller's write transaction (signup,
//!   CRYPTO.md §11.1, one transaction with the `auth` domain's rows): the vault row at
//!   `vault_key_epoch` 0 ("0 when the vault is created", CRYPTO.md §4.4) and its first
//!   self-grant.
//! - **Reading** the self-grant ([`VaultDomain::self_grant`]) and the account's vaults
//!   ([`VaultDomain::vaults`]).
//! - **Re-publishing a self-grant** in restore healing step 3 (ADR 0012 §7: "Key grants, vault
//!   self-grants and item-key wraps that it holds") with [`VaultDomain::republish_self_grant`].
//!   The self-grant's epochs are an unsigned locator the server never trusts (CRYPTO.md §4.2),
//!   and no Accepted ADR says what a re-published grant does to the vault's `vault_key_epoch`.
//!   So this crate's conservative reading, pending the owner:
//!   - the grant **never changes** `vault_vaults.vault_key_epoch` (the stale-epoch check's
//!     reference). Only the rotation upload ([`crate::rotation`]) moves it. How the server heals
//!     the epoch rollback of a restore is an open question reported to the owner: until an ADR
//!     answers it, a restore that rolled the vault's epoch back leaves the stale-epoch check at
//!     the older epoch (a weaker check, never a locked vault);
//!   - it is accepted only while the account's reconciliation epoch is open (INV-59, the window
//!     in which a restore's rollback is healed);
//!   - it replaces the stored grant only when neither epoch goes down and one goes up
//!     (component-wise, not lexicographic): a grant with a lower `vault_key_epoch` or a lower
//!     `account_key_epoch` than the stored one is left out;
//!   - its `vault_key_epoch` must not exceed what the server verified: the vault's current
//!     epoch or the highest `vault_key_epoch` of a stored signed op or snapshot header, the
//!     healer's re-published records included. A higher one is refused, so an unsigned value
//!     can never raise the bar a later re-publication must pass. `account_key_epoch` is the
//!     `auth` domain's (signed `account-state`), which this crate cannot read; it bounds no
//!     rule here. Consequence, reported to the owner: a grant of a rotation after which no
//!     signed record reached the server before a restore is refused until a record at its
//!     epoch is stored (ADR 0012 §7 lists grants, step 3, before records, step 4).
//! - **The wrap set.** A wrap carried inside an op or snapshot, or sent in a healing request,
//!   fills its row (`crate::store`, `crate::upload`): inserted when missing, replacing a row at
//!   a lower `vault_key_epoch`, otherwise kept. Fetch serves the rows (`crate::fetch`).
//!
//! **The key-rotation upload** (CRYPTO.md §11.6 step 9: new self-grants, the re-wrapped wrap set
//! overwriting every row, the superseded wraps deleted, and the rotation cut-off of ADR 0012 §6 /
//! ADR 0021 §9 "Rotation cut-off") is [`crate::rotation`] (ADR 0025): one atomic request with the
//! `auth` domain's `account-state`. It is the only write that moves `vault_key_epoch`, always
//! upwards, above the stored value (ADR 0025 §3 check 2).

use rizzy_core::ids::{AccountId, VaultId};
use rizzy_proto::objects::{KeyEnvelope, VaultSelfGrant};
use rizzy_proto::wire::Id;
use rizzy_storage::WriteTx;
use rizzy_storage::lock_account;
use rizzy_storage::meta::reconciliation_epoch;

use crate::authors::DeviceDirectory;
use crate::error::VaultError;
use crate::repo::{self, SelfGrantRow};
use crate::{VaultDomain, to_sql_time};

/// Creates vault `grant.vault_id` for `account_id` with its first self-grant, in the caller's
/// write transaction, which has taken the account's lock (signup, CRYPTO.md §11.1).
///
/// # Errors
/// [`VaultError::Invalid`] when the grant's `vault_key_epoch` is not 0; [`VaultError::Storage`]
/// when the vault exists already or the account row is missing (foreign key), and on any
/// database failure. The caller drops the transaction then.
pub async fn create_vault(
    tx: &mut WriteTx,
    account_id: AccountId,
    grant: &VaultSelfGrant,
    now_ms: u64,
) -> Result<(), VaultError> {
    if grant.vault_key_epoch != 0 {
        return Err(VaultError::Invalid);
    }
    let vault_id = VaultId::from_bytes(grant.vault_id.to_bytes());
    let now = to_sql_time(now_ms)?;
    repo::insert_vault(tx.conn(), vault_id, account_id, 0, now).await?;
    let row = SelfGrantRow {
        account_key_epoch: grant.account_key_epoch,
        vault_key_epoch: 0,
        envelope: grant.envelope.as_slice().to_vec(),
    };
    repo::write_self_grant(tx.conn(), vault_id, &row, false, now).await
}

impl<D: DeviceDirectory> VaultDomain<D> {
    /// The account's vaults, by id.
    ///
    /// # Errors
    /// [`VaultError::Storage`] or [`VaultError::Corrupt`].
    pub async fn vaults(&self, account_id: AccountId) -> Result<Vec<VaultId>, VaultError> {
        let mut tx = self.database().begin_read().await?;
        let vaults = repo::list_vaults(tx.conn(), account_id).await?;
        tx.finish().await?;
        Ok(vaults)
    }

    /// The vault's current self-grant.
    ///
    /// # Errors
    /// [`VaultError::NotFound`] for a vault of another account or without a self-grant;
    /// [`VaultError::Storage`] or [`VaultError::Corrupt`].
    pub async fn self_grant(
        &self,
        account_id: AccountId,
        vault_id: VaultId,
    ) -> Result<VaultSelfGrant, VaultError> {
        let mut tx = self.database().begin_read().await?;
        repo::vault(tx.conn(), vault_id)
            .await?
            .filter(|v| v.account_id == account_id)
            .ok_or(VaultError::NotFound)?;
        let row = repo::self_grant(tx.conn(), vault_id)
            .await?
            .ok_or(VaultError::NotFound)?;
        tx.finish().await?;
        Ok(VaultSelfGrant {
            vault_id: Id::from_bytes(vault_id.to_bytes()),
            account_key_epoch: row.account_key_epoch,
            vault_key_epoch: row.vault_key_epoch,
            envelope: KeyEnvelope::new(row.envelope).map_err(|_| VaultError::Corrupt {
                what: "vault_self_grants.envelope length",
            })?,
        })
    }

    /// Restore healing step 3 for one vault self-grant (module docs for the rules). Returns
    /// whether the grant was stored; a grant that is not newer than the stored one (neither
    /// epoch lower, one higher) is left out, and answered `false`. The vault's
    /// `vault_key_epoch` is never changed here.
    ///
    /// # Errors
    /// [`VaultError::NotFound`] for a vault of another account; [`VaultError::Invalid`] outside
    /// the account's reconciliation epoch, or for a `vault_key_epoch` above both the vault's and
    /// every stored signed header's; [`VaultError::Storage`] or [`VaultError::Corrupt`].
    pub async fn republish_self_grant(
        &self,
        account_id: AccountId,
        grant: &VaultSelfGrant,
        now_ms: u64,
    ) -> Result<bool, VaultError> {
        let mut tx = self.database().begin_write().await?;
        lock_account(&mut tx, account_id.as_bytes()).await?;
        let stored = republish_in(&mut tx, account_id, grant, now_ms).await?;
        tx.commit().await?;
        Ok(stored)
    }
}

/// [`VaultDomain::republish_self_grant`] in the caller's write transaction, which has taken the
/// account's lock: the same rules, the same answer. Nothing is committed here; on an error the
/// caller drops the transaction.
///
/// # Errors
/// As [`VaultDomain::republish_self_grant`].
pub(crate) async fn republish_in(
    tx: &mut WriteTx,
    account_id: AccountId,
    grant: &VaultSelfGrant,
    now_ms: u64,
) -> Result<bool, VaultError> {
    let vault_id = VaultId::from_bytes(grant.vault_id.to_bytes());
    let now = to_sql_time(now_ms)?;
    let vault = repo::vault(tx.conn(), vault_id)
        .await?
        .filter(|v| v.account_id == account_id)
        .ok_or(VaultError::NotFound)?;
    if reconciliation_epoch(tx.conn(), account_id.as_bytes())
        .await?
        .is_none()
    {
        return Err(VaultError::Invalid);
    }
    // The highest vault epoch the server verified: its own, or a signed header's.
    let verified = repo::max_record_epoch(tx.conn(), vault_id)
        .await?
        .map_or(vault.vault_key_epoch, |e| e.max(vault.vault_key_epoch));
    if grant.vault_key_epoch > verified {
        return Err(VaultError::Invalid);
    }
    let stored = repo::self_grant(tx.conn(), vault_id).await?;
    if !stored.as_ref().is_none_or(|s| is_newer(grant, s)) {
        return Ok(false);
    }
    let row = SelfGrantRow {
        account_key_epoch: grant.account_key_epoch,
        vault_key_epoch: grant.vault_key_epoch,
        envelope: grant.envelope.as_slice().to_vec(),
    };
    repo::write_self_grant(tx.conn(), vault_id, &row, stored.is_some(), now).await?;
    Ok(true)
}

/// Whether `grant` is newer than the stored grant: neither epoch lower and one higher
/// (component-wise, module docs).
fn is_newer(grant: &VaultSelfGrant, stored: &SelfGrantRow) -> bool {
    grant.account_key_epoch >= stored.account_key_epoch
        && grant.vault_key_epoch >= stored.vault_key_epoch
        && (grant.account_key_epoch, grant.vault_key_epoch)
            != (stored.account_key_epoch, stored.vault_key_epoch)
}
