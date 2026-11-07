// SPDX-License-Identifier: AGPL-3.0-only

//! The write-time caps on wrap-set rows ([ADR 0092] §2).
//!
//! Every request that inserts a wrap-set row checks, inside its transaction under the account
//! lock and after its existing checks (for an upload after ADR 0048 §3's quota step):
//!
//! 1. the vault's row count after the request ≤ [`MAX_ITEM_KEY_WRAPS`], and
//! 2. the owning account's row count after the request ≤ [`MAX_ACCOUNT_WRAP_ROWS`].
//!
//! If either fails, the whole request is refused with `rotation_limit` and nothing is written.
//! A record inserts a row only when it carries a wrap at or above the vault's current
//! `vault_key_epoch` whose `(item_id, item_key_id)` row the server lacks; **a request that
//! inserts no row is never refused for size** (trash, purge, edits under an existing item key,
//! deletes and the rotation itself). A healing request is checked against check 1 only (§2
//! "Healing").
//!
//! The counts are `COUNT(*)` over the stored rows, read once per transaction when its first
//! row-adding record arrives and advanced by every row it adds since, so an account stored
//! before ADR 0092 needs no migration (§2 "Accounts stored before this ADR").
//!
//! [ADR 0092]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0092-rotation-size-limits.md

use rizzy_core::ids::ItemId;
use rizzy_proto::limits::{MAX_ACCOUNT_WRAP_ROWS, MAX_ITEM_KEY_WRAPS};
use rizzy_storage::WriteTx;

use crate::error::VaultError;
use crate::intake::CarriedWrap;
use crate::repo;
use crate::store::{Refusal, Session};

/// The two caps of [ADR 0092] §2. [`WrapCaps::STANDARD`] is the compiled-in pair of §1; ADR 0092
/// gives them no configuration setting, so another pair is for tests only (§8 test 3: "small
/// caps by a test-only constructor parameter").
///
/// [ADR 0092]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0092-rotation-size-limits.md
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrapCaps {
    /// The most wrap-set rows one vault may hold after a write (check 1).
    pub vault_rows: u64,
    /// The most wrap-set rows the account's vaults may hold together after a write (check 2).
    pub account_rows: u64,
}

impl WrapCaps {
    /// The compiled-in caps of ADR 0092 §1.
    pub const STANDARD: Self = Self {
        vault_rows: MAX_ITEM_KEY_WRAPS as u64,
        account_rows: MAX_ACCOUNT_WRAP_ROWS as u64,
    };
}

impl Default for WrapCaps {
    fn default() -> Self {
        Self::STANDARD
    }
}

/// The counts one store transaction checks against, read on first use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RowCounts {
    /// The session vault's wrap-set rows.
    pub(crate) vault: u64,
    /// The owning account's wrap-set rows over all its vaults.
    pub(crate) account: u64,
}

/// [`admit_row`] for a record's carried wrap, if it carries one.
pub(crate) async fn admit_carried(
    tx: &mut WriteTx,
    session: &mut Session,
    item_id: ItemId,
    epoch: u32,
    wrap: Option<&CarriedWrap>,
) -> Result<Result<(), Refusal>, VaultError> {
    match wrap {
        Some(wrap) => admit_row(tx, session, item_id, &wrap.item_key_id, epoch).await,
        None => Ok(Ok(())),
    }
}

/// Whether a record that carries a wrap for `(item_id, item_key_id)` at `epoch` may be stored
/// under the caps; called after the record's other checks and before it is stored. A wrap below
/// the vault's current epoch fills no row ([`crate::store::current_wrap`]), and a wrap whose row
/// is already stored adds none: neither is ever refused. A row the record will add is counted
/// in the session at once, so a later record of the same request sees it.
pub(crate) async fn admit_row(
    tx: &mut WriteTx,
    session: &mut Session,
    item_id: ItemId,
    item_key_id: &[u8; 16],
    epoch: u32,
) -> Result<Result<(), Refusal>, VaultError> {
    if !crate::store::current_wrap(session, epoch)
        || repo::wrap_exists(tx.conn(), session.vault_id, item_id, item_key_id).await?
    {
        return Ok(Ok(()));
    }
    let counts = match session.wrap_rows {
        Some(counts) => counts,
        None => RowCounts {
            vault: repo::vault_wrap_rows(tx.conn(), session.vault_id).await?,
            account: repo::account_wrap_rows(tx.conn(), session.account_id).await?,
        },
    };
    let after = RowCounts {
        vault: counts.vault.saturating_add(1),
        account: counts.account.saturating_add(1),
    };
    if after.vault > session.caps.vault_rows
        || (session.account_cap && after.account > session.caps.account_rows)
    {
        return Ok(Err(Refusal::RotationLimit));
    }
    session.wrap_rows = Some(after);
    Ok(Ok(()))
}
