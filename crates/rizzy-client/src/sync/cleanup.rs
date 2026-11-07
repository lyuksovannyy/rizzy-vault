// SPDX-License-Identifier: AGPL-3.0-only

//! The cleanup of a purged item's attachments: the client's half of [ADR 0093] §1.
//!
//! # When a row is written
//!
//! A row of the cache's `attachment_cleanup` table ([`Write::AttachmentCleanupPut`]) is
//! written into the journal of the very step that causes it, so it lands in the same cache
//! write (§1.2):
//! 1. **Own Purge** ([`VaultSync::purge_item`], so also `auto_purge_due` and
//!    `PendingMove::finish`): `purge_seq` = the Purge op's `device_seq`, whether or not the
//!    merged state names an attachment.
//! 2. **Received Purge**: an op or a cover of another device turns an item this device held
//!    live, with at least one existing `attachment/<id>` element, into a tombstone;
//!    `purge_seq = 0`.
//! 3. **Late op on a tombstone**: an applied op of another device on a purged item writes an
//!    `attachment/…` key; `purge_seq = 0`.
//!
//! A second row for the same item keeps the larger `purge_seq`.
//!
//! # Running a row
//!
//! At the end of each sync round the host takes [`VaultSync::attachment_cleanups_due`]: every
//! row with no unacknowledged own op at or below its `purge_seq`, so no attachment goes before
//! the server holds the Purge (INV-113 (b)). For each it sends
//! [`VaultSync::attachment_cleanup_request`] to `attachments/delete-item` and hands the
//! answer to [`VaultSync::attachment_cleanup_respond`], which applies §1.2's table:
//!
//! | Answer | [`CleanupStep`] | Row |
//! |---|---|---|
//! | 200, `remaining: false` | `Done` | deleted |
//! | 200, `remaining: true` | `Again` (at most [`MAX_CALLS_PER_ROUND`] calls this round), then `Keep` | kept |
//! | 404 | `Done` | deleted (the vault is gone) |
//! | no answer (status 0), 5xx, 429, 401 | `Keep` | kept for the next round |
//! | any other 4xx | [`ClientError::AttachmentCleanupFailed`], once | deleted |
//!
//! A failed cleanup is never a sync error, and a row never blocks a round, an unlock or another
//! vault. A vault dropped from the directory drops its rows ([`Write::DropVault`]).
//!
//! [ADR 0093]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0093-attachment-lifecycle.md

use rizzy_core::ids::ItemId;
use rizzy_proto::attachments::{AttachmentItemRequest, AttachmentItemResponse};
use rizzy_proto::wire::Id;

use crate::error::ClientError;
use crate::store::rows::{AttachmentCleanupRow, Write};
use crate::sync::VaultSync;

/// The most `delete-item` calls one row makes in one sync round (ADR 0093 §1.1): 64 × 16 =
/// 1,024 attachments.
pub const MAX_CALLS_PER_ROUND: u32 = 64;

/// The prefix of every attachment field key (ADR 0054 §4).
const ATTACHMENT_PREFIX: &str = "attachment/";

/// One `attachment_cleanup` row as the driver holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Cleanup {
    /// The `device_seq` of this device's own Purge op; `0` for none.
    purge_seq: u64,
    /// The `delete-item` calls made this round.
    calls: u32,
}

impl Cleanup {
    /// A row as the cache holds it.
    pub(crate) const fn new(purge_seq: u64) -> Self {
        Self {
            purge_seq,
            calls: 0,
        }
    }
}

/// What the host does next with a cleanup row ([`VaultSync::attachment_cleanup_respond`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupStep {
    /// The row is gone: nothing is left to delete, or nothing can be.
    Done,
    /// Some attachments are left: send the request again now.
    Again,
    /// The row stays for the next sync round.
    Keep,
}

/// Whether `key` is an attachment field key.
pub(crate) fn is_attachment_key(key: &str) -> bool {
    key.starts_with(ATTACHMENT_PREFIX)
}

impl VaultSync {
    /// Writes the cleanup row of `item` (module docs), keeping the larger `purge_seq` when
    /// one exists.
    pub(crate) fn note_cleanup(&mut self, item: ItemId, purge_seq: u64) {
        let entry = self
            .cleanups
            .entry(item)
            .or_insert_with(|| Cleanup::new(purge_seq));
        entry.purge_seq = entry.purge_seq.max(purge_seq);
        let row = AttachmentCleanupRow {
            vault_id: self.vault_id.to_bytes(),
            item_id: item.to_bytes(),
            purge_seq: entry.purge_seq,
        };
        self.record(|| Write::AttachmentCleanupPut(row));
    }

    /// Whether `item` is live (Active or Trashed) and names at least one existing attachment
    /// element (ADR 0018 §6): what a received Purge must see to write a row (module docs, 2).
    pub(crate) fn live_with_attachments(&self, item: ItemId) -> bool {
        use rizzy_sync::merge::ItemLifecycle;
        matches!(
            self.item_lifecycle(item),
            ItemLifecycle::Active | ItemLifecycle::Trashed
        ) && !self.attachments(item).is_empty()
    }

    /// Writes a row for `item` when a received change made it a tombstone (`was_live`: it was
    /// live with attachments before) or when it is a tombstone and the change named an
    /// attachment key (`names_attachment`) (module docs, 2 and 3).
    pub(crate) fn note_received(&mut self, item: ItemId, was_live: bool, names_attachment: bool) {
        use rizzy_sync::merge::ItemLifecycle;
        if self.item_lifecycle(item) == ItemLifecycle::Purged && (was_live || names_attachment) {
            self.note_cleanup(item, 0);
        }
    }

    /// The items whose cleanup can run now (ADR 0093 §1.2, "Running a row"): every row with no
    /// unacknowledged own op at or below its `purge_seq`. Starts a new round: each row's call
    /// count is reset.
    pub fn attachment_cleanups_due(&mut self) -> Vec<ItemId> {
        let acked = self.acked();
        let mut due = Vec::new();
        for (item, row) in &mut self.cleanups {
            row.calls = 0;
            if row.purge_seq == 0 || row.purge_seq <= acked {
                due.push(*item);
            }
        }
        due
    }

    /// How many cleanup rows this vault holds, due or not.
    #[must_use]
    pub fn attachment_cleanups_held(&self) -> usize {
        self.cleanups.len()
    }

    /// The `attachments/delete-item` body for `item` of this vault (ADR 0093 §1.1).
    #[must_use]
    pub fn attachment_cleanup_request(&self, item: ItemId) -> AttachmentItemRequest {
        AttachmentItemRequest {
            vault_id: Id::from_bytes(self.vault_id.to_bytes()),
            item_id: Id::from_bytes(item.to_bytes()),
        }
    }

    /// Applies the answer to `attachments/delete-item` for `item` (module docs, the table):
    /// `status` `0` stands for no answer (a network error); `answer` is the 200 body as the
    /// host parsed it (`None` when it did not parse). This crate parses no JSON (the hosts own
    /// the transport), so the host hands over the parsed body instead of its bytes. Writes the
    /// row change into the journal.
    ///
    /// # Errors
    /// [`ClientError::AttachmentCleanupFailed`] for a refusal no retry can fix: the row is
    /// deleted, so this is reported once; [`ClientError::InvalidServerResponse`] for a 200
    /// whose body does not parse (the row is kept); [`ClientError::UnknownItem`] when `item`
    /// has no row.
    pub fn attachment_cleanup_respond(
        &mut self,
        item: ItemId,
        status: u16,
        answer: Option<&AttachmentItemResponse>,
    ) -> Result<CleanupStep, ClientError> {
        let Some(row) = self.cleanups.get_mut(&item) else {
            return Err(ClientError::UnknownItem);
        };
        row.calls = row.calls.saturating_add(1);
        let calls = row.calls;
        match status {
            200 => {
                let answer = answer.ok_or(ClientError::InvalidServerResponse)?;
                if !answer.remaining {
                    self.drop_cleanup(item);
                    Ok(CleanupStep::Done)
                } else if calls < MAX_CALLS_PER_ROUND {
                    Ok(CleanupStep::Again)
                } else {
                    Ok(CleanupStep::Keep)
                }
            }
            404 => {
                self.drop_cleanup(item);
                Ok(CleanupStep::Done)
            }
            401 | 429 | 0 => Ok(CleanupStep::Keep),
            s if (400..500).contains(&s) => {
                self.drop_cleanup(item);
                Err(ClientError::AttachmentCleanupFailed)
            }
            _ => Ok(CleanupStep::Keep),
        }
    }

    /// Deletes the cleanup row of `item`.
    fn drop_cleanup(&mut self, item: ItemId) {
        if self.cleanups.remove(&item).is_some() {
            let (vault_id, item_id) = (self.vault_id.to_bytes(), item.to_bytes());
            self.record(|| Write::AttachmentCleanupDelete { vault_id, item_id });
        }
    }
}
