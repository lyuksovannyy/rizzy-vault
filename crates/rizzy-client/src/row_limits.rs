// SPDX-License-Identifier: AGPL-3.0-only

//! The wrap-set row limits on the client ([ADR 0092] §6): the early warnings and the local
//! pre-checks before a row-adding action.
//!
//! - **Counts.** [`RowCounts`] holds the account's rows and each vault's: the larger of the
//!   server's unsigned figure ([`AccountView::wrap_rows`](rizzy_proto::account::AccountView))
//!   and this device's own replica (the wrap set of each vault's last Fetch). Neither is trusted
//!   for anything but display and the pre-check: the server enforces the caps itself.
//! - **Warnings.** At [`ROTATION_WARN_ROWS`] (80 %) a dismissable-per-session notice, at
//!   [`ROTATION_URGENT_ROWS`] (95 %) one that is not dismissable ([`RowNotice::text`] is the
//!   ADR's text). In a vault, the same at the same share of [`MAX_ITEM_KEY_WRAPS`].
//! - **Pre-checks.** The host gives each vault its room ([`RowCounts::room`],
//!   [`VaultSync::set_row_room`](crate::sync::VaultSync::set_row_room)); a new item key past it
//!   is [`ClientError::RotationLimit`] before anything is written, and an import checks its
//!   whole batch first and is refused whole. A `rotation_limit` from the server (another
//!   device raced the count) aborts the action the same way.
//! - **Never a blocker** for revoking a device, a credential change or recovery: those add no
//!   row and are never checked here (INV-115).
//!
//! [ADR 0092]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0092-rotation-size-limits.md

use rizzy_core::ids::VaultId;
use rizzy_proto::limits::{
    MAX_ACCOUNT_WRAP_ROWS, MAX_ITEM_KEY_WRAPS, ROTATION_URGENT_ROWS, ROTATION_WARN_ROWS,
};

use crate::ClientError;
use crate::sync::VaultSync;

// The warning thresholds are shares of the account cap; a vault's are the same numbers
// because the two caps are equal (ADR 0092 §1).
const _: () = assert!(MAX_ITEM_KEY_WRAPS == MAX_ACCOUNT_WRAP_ROWS);

/// How close to a cap a count is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoticeLevel {
    /// At or above 80 % of the cap: dismissable for the session.
    Warn,
    /// At or above 95 %: not dismissable.
    Urgent,
}

impl NoticeLevel {
    /// The level of a count of `rows`, `None` below 80 %.
    #[must_use]
    pub const fn of(rows: u64) -> Option<Self> {
        if rows >= ROTATION_URGENT_ROWS as u64 {
            Some(Self::Urgent)
        } else if rows >= ROTATION_WARN_ROWS as u64 {
            Some(Self::Warn)
        } else {
            None
        }
    }
}

/// What a notice is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoticeScope {
    /// The whole account (`MAX_ACCOUNT_WRAP_ROWS`).
    Account,
    /// One vault (`MAX_ITEM_KEY_WRAPS`).
    Vault(VaultId),
}

/// One size notice to show ([ADR 0092] §6).
///
/// [ADR 0092]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0092-rotation-size-limits.md
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowNotice {
    /// The account or a vault.
    pub scope: NoticeScope,
    /// How close to the cap.
    pub level: NoticeLevel,
    /// The count.
    pub rows: u64,
}

impl RowNotice {
    /// Whether the user may dismiss it for the session (only below 95 %).
    #[must_use]
    pub const fn dismissable(&self) -> bool {
        matches!(self.level, NoticeLevel::Warn)
    }

    /// The text to show, with the count and the cap grouped by thousands: for the account
    /// exactly ADR 0092 §6's ("This account is close to its item limit (N of 65,536). Above it
    /// you can't add items; delete or empty Trash to free space."), for a vault the same with
    /// "This vault".
    #[must_use]
    pub fn text(&self) -> String {
        let what = match self.scope {
            NoticeScope::Account => "account",
            NoticeScope::Vault(_) => "vault",
        };
        format!(
            "This {what} is close to its item limit ({} of {}). Above it you can't add items; \
             delete or empty Trash to free space.",
            grouped(self.rows),
            grouped(MAX_ACCOUNT_WRAP_ROWS as u64)
        )
    }
}

/// The account's and each vault's wrap-set rows (module docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowCounts {
    /// The account's rows.
    account: u64,
    /// Each vault's rows, in the order given.
    vaults: Vec<(VaultId, u64)>,
}

impl RowCounts {
    /// The counts of `vaults` (the vaults the account owns, each after a Fetch), taking the
    /// server's account figure when it is larger than the replica's sum.
    #[must_use]
    pub fn new(server_account_rows: Option<u64>, vaults: &[&VaultSync]) -> Self {
        let vaults: Vec<(VaultId, u64)> = vaults
            .iter()
            .map(|v| (v.vault_id(), v.wrap_row_count() as u64))
            .collect();
        Self::from_counts(server_account_rows, vaults)
    }

    /// The counts from figures the host already holds.
    #[must_use]
    pub fn from_counts(server_account_rows: Option<u64>, vaults: Vec<(VaultId, u64)>) -> Self {
        let local = vaults
            .iter()
            .fold(0u64, |sum, (_, rows)| sum.saturating_add(*rows));
        Self {
            account: server_account_rows.map_or(local, |server| server.max(local)),
            vaults,
        }
    }

    /// The account's rows.
    #[must_use]
    pub const fn account(&self) -> u64 {
        self.account
    }

    /// The notices to show now: the account's first, then each vault's.
    #[must_use]
    pub fn notices(&self) -> Vec<RowNotice> {
        let account = NoticeLevel::of(self.account).map(|level| RowNotice {
            scope: NoticeScope::Account,
            level,
            rows: self.account,
        });
        let vaults = self.vaults.iter().filter_map(|(id, rows)| {
            NoticeLevel::of(*rows).map(|level| RowNotice {
                scope: NoticeScope::Vault(*id),
                level,
                rows: *rows,
            })
        });
        account.into_iter().chain(vaults).collect()
    }

    /// The rows `vault` may still add: the smaller of its own room and the account's.
    #[must_use]
    pub fn room(&self, vault: VaultId) -> u64 {
        let own = self
            .vaults
            .iter()
            .find(|(id, _)| *id == vault)
            .map_or(0, |(_, rows)| *rows);
        (MAX_ITEM_KEY_WRAPS as u64)
            .saturating_sub(own)
            .min((MAX_ACCOUNT_WRAP_ROWS as u64).saturating_sub(self.account))
    }

    /// The pre-check of a batch adding `adding` rows to `vault` (an import, a bulk move or
    /// copy into it), before its first write: refused whole above the room.
    ///
    /// # Errors
    /// [`ClientError::RotationLimit`].
    pub fn check(&self, vault: VaultId, adding: u64) -> Result<(), ClientError> {
        if adding > self.room(vault) {
            Err(ClientError::RotationLimit)
        } else {
            Ok(())
        }
    }
}

/// `n` with a comma between thousands (`65,536`).
fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len().saturating_add(digits.len() / 3));
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault(n: u8) -> VaultId {
        VaultId::from_bytes([n; 16])
    }

    #[test]
    fn the_levels_are_at_80_and_95_percent() {
        assert_eq!(NoticeLevel::of(52_428), None);
        assert_eq!(NoticeLevel::of(52_429), Some(NoticeLevel::Warn));
        assert_eq!(NoticeLevel::of(62_258), Some(NoticeLevel::Warn));
        assert_eq!(NoticeLevel::of(62_259), Some(NoticeLevel::Urgent));
        assert_eq!(NoticeLevel::of(70_000), Some(NoticeLevel::Urgent));
    }

    #[test]
    fn the_notice_text_is_the_adr_text() {
        let counts = RowCounts::from_counts(Some(52_429), vec![(vault(1), 100)]);
        let notices = counts.notices();
        assert_eq!(notices.len(), 1);
        let notice = notices.first().unwrap();
        assert!(notice.dismissable());
        assert_eq!(
            notice.text(),
            "This account is close to its item limit (52,429 of 65,536). Above it you can't add \
             items; delete or empty Trash to free space."
        );
        let urgent = RowCounts::from_counts(None, vec![(vault(1), 62_259)]).notices();
        assert_eq!(urgent.len(), 2, "the account and the vault");
        assert!(urgent.iter().all(|n| !n.dismissable()));
        assert!(
            urgent
                .get(1)
                .unwrap()
                .text()
                .starts_with("This vault is close")
        );
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(1_000), "1,000");
        assert_eq!(grouped(1_234_567), "1,234,567");
    }

    #[test]
    fn a_batch_past_either_cap_is_refused_whole() {
        // The server's figure wins when larger than the replica's.
        let counts = RowCounts::from_counts(Some(65_000), vec![(vault(1), 10), (vault(2), 20)]);
        assert_eq!(counts.account(), 65_000);
        assert_eq!(counts.room(vault(1)), 536);
        assert!(counts.check(vault(1), 536).is_ok());
        assert_eq!(counts.check(vault(1), 537), Err(ClientError::RotationLimit));
        // The vault's own cap binds when the account has room.
        let counts = RowCounts::from_counts(None, vec![(vault(1), 65_530)]);
        assert_eq!(counts.room(vault(1)), 6);
        assert_eq!(
            counts.room(vault(9)),
            6,
            "an unknown vault has no rows of its own"
        );
        // Above a cap (an account healed past it): no room, nothing negative.
        let counts = RowCounts::from_counts(Some(70_000), vec![(vault(1), 1)]);
        assert_eq!(counts.room(vault(1)), 0);
        assert_eq!(counts.check(vault(1), 1), Err(ClientError::RotationLimit));
        assert!(counts.check(vault(1), 0).is_ok());
    }
}
