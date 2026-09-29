//! The compaction job `worker` runs (ADR 0021 §3 "Where it runs", §7).
//!
//! `api` stores a snapshot with its clamped VV and store sequence and queues its item
//! (`vault_compaction_queue`); it never deletes or drops. `worker` calls
//! [`VaultDomain::compact_item`] per queued item: one write transaction under the account lock
//! reads the item's current retained snapshots and op dots, asks
//! `rizzy_sync::compaction::plan_worker` for R1's body deletions and R3's snapshot drops,
//! applies both, and removes the item from the queue. The plan is recomputed from the current
//! rows every time, so a lagging `worker` only delays deletion; it never breaks R1 or R3.
//! Nothing else in this crate deletes a body or drops a snapshot (§3 "Nothing else").
//!
//! [`VaultDomain::run_compaction`] drains up to a given number of queued items, oldest first,
//! isolating failures per item (a failing item is moved to the back of the queue and reported);
//! `rizzy-server` wires it into `worker` (ADR 0021 §7), waking on `rizzy-bus`'s
//! `CompactionQueued` or on a timer, since the queue, not the event, is the record of truth.

use core::fmt;

use rizzy_core::ids::{ItemId, VaultId};
use rizzy_storage::lock_account;
use rizzy_sync::compaction::plan_worker;

use crate::VaultDomain;
use crate::authors::DeviceDirectory;
use crate::error::VaultError;
use crate::repo;

/// What one compaction run did to one item.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompactionReport {
    /// Op bodies deleted (R1).
    pub bodies_deleted: usize,
    /// Snapshots dropped (R3).
    pub snapshots_dropped: usize,
}

impl<D: DeviceDirectory> VaultDomain<D> {
    /// Runs R1 then R3 on one item, in one transaction under the account lock, and dequeues it
    /// (module docs). An item of a vault that no longer exists is only dequeued.
    ///
    /// # Errors
    /// [`VaultError::Storage`] or [`VaultError::Corrupt`]; nothing is changed then, and the item
    /// stays queued.
    pub async fn compact_item(
        &self,
        vault_id: VaultId,
        item_id: ItemId,
    ) -> Result<CompactionReport, VaultError> {
        let mut tx = self.database().begin_write().await?;
        let Some(vault) = repo::vault(tx.conn(), vault_id).await? else {
            repo::dequeue(tx.conn(), vault_id, item_id).await?;
            tx.commit().await?;
            return Ok(CompactionReport::default());
        };
        lock_account(&mut tx, vault.account_id.as_bytes()).await?;
        let snapshots = repo::item_snapshots(tx.conn(), vault_id, item_id).await?;
        let ops = repo::item_op_dots(tx.conn(), vault_id, item_id).await?;
        let plan = plan_worker(&snapshots, &ops).map_err(|_| VaultError::Corrupt {
            what: "an item's retained snapshots or ops repeat a key",
        })?;
        for &dot in &plan.delete_bodies {
            repo::delete_body(tx.conn(), vault_id, item_id, dot).await?;
        }
        for &store_seq in &plan.drop_snapshots {
            repo::delete_snapshot(tx.conn(), vault_id, item_id, store_seq).await?;
        }
        repo::dequeue(tx.conn(), vault_id, item_id).await?;
        tx.commit().await?;
        Ok(CompactionReport {
            bodies_deleted: plan.delete_bodies.len(),
            snapshots_dropped: plan.drop_snapshots.len(),
        })
    }

    /// Compacts up to `max_items` queued items, oldest first, each in its own transaction.
    ///
    /// **Failures are isolated per item.** An item whose compaction fails (a damaged row, a
    /// database error) is rolled back, moved behind every other queued item in its own write
    /// transaction, and reported in [`CompactionRun::failures`]; the run goes on with the next
    /// item. So one item that keeps failing never holds the head of the queue and never stops
    /// R1 and R3 for the rest of the database (ADR 0021 §3, §7). `rizzy-server` logs each
    /// failure (ids and the error, which names a rule or column, never a value).
    ///
    /// # Errors
    /// [`VaultError::Storage`] or [`VaultError::Corrupt`] only when the queue cannot be read, or
    /// a failed item cannot be moved back; the items processed before stay compacted.
    pub async fn run_compaction(&self, max_items: usize) -> Result<CompactionRun, VaultError> {
        let mut read = self.database().begin_read().await?;
        let queued = repo::queued(read.conn(), max_items).await?;
        read.finish().await?;
        let mut run = CompactionRun::default();
        for &(vault_id, item_id) in &queued {
            match self.compact_item(vault_id, item_id).await {
                Ok(report) => {
                    run.processed = run.processed.saturating_add(1);
                    run.report.bodies_deleted = run
                        .report
                        .bodies_deleted
                        .saturating_add(report.bodies_deleted);
                    run.report.snapshots_dropped = run
                        .report
                        .snapshots_dropped
                        .saturating_add(report.snapshots_dropped);
                }
                Err(error) => {
                    let mut tx = self.database().begin_write().await?;
                    repo::defer(tx.conn(), vault_id, item_id).await?;
                    tx.commit().await?;
                    run.failures.push(CompactionFailure {
                        vault_id,
                        item_id,
                        error,
                    });
                }
            }
        }
        Ok(run)
    }
}

/// What one [`VaultDomain::run_compaction`] call did.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct CompactionRun {
    /// Items compacted (and dequeued) without error.
    pub processed: usize,
    /// The summed report of those items.
    pub report: CompactionReport,
    /// Items whose compaction failed: each was left unchanged, stays queued behind every other
    /// item, and is for `rizzy-server` to log.
    pub failures: Vec<CompactionFailure>,
}

/// One queued item whose compaction failed. Names the vault and item by id, and the error,
/// which names a rule or column; never content. `Display` gives the log line.
#[derive(Debug)]
#[non_exhaustive]
pub struct CompactionFailure {
    /// The vault.
    pub vault_id: VaultId,
    /// The item.
    pub item_id: ItemId,
    /// Why it failed.
    pub error: VaultError,
}

impl fmt::Display for CompactionFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "compaction failed: vault {:?}, item {:?}: {}",
            self.vault_id, self.item_id, self.error
        )
    }
}
