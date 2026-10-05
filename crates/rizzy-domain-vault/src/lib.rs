//! `rizzy-domain-vault` — the server's `vault` domain (roadmap M1 step 3; [ADR 0016] §3 row
//! `rizzy-domain-vault`): Server-mode op records and retained headers, snapshots, compaction,
//! restore healing, item-key wraps and vault self-grants. It verifies each uploaded op and
//! snapshot signature ([ADR 0012] §7 "Upload") and runs [ADR 0021] in full on the server side.
//! No HTTP: `rizzy-server` maps the `/api/v1` types of `rizzy-proto` onto these calls.
//!
//! # What the server sees, and does
//!
//! The server stores and forwards. It never decrypts and never merges ([ADR 0012] §7). Every
//! rule here runs on cleartext the server already holds (ADR 0012 §11, as ADR 0022 §2 replaces
//! it; THREAT_MODEL §3.4): signed headers (vault, item, dot, `vault_prev_seq`, HLC, causal
//! context, `vault_key_epoch`), snapshot headers with their covered VVs, the signed hashes, the
//! clamped VVs and store sequences it derives from them (ADR 0021 §6: "No new metadata"), and
//! envelope and wrap lengths. `rizzy-core` verifies signatures; it is never asked to decrypt.
//!
//! | Call | Spec | Module |
//! |---|---|---|
//! | [`VaultDomain::upload`] | ADR 0012 §7 "Upload" as ADR 0021 §9 supersedes it in part | [`upload`] |
//! | [`VaultDomain::heal`] | ADR 0021 §9 "Healing request", "Server acceptance"; ADR 0032 §2–§3 (step 3b, a request with a self-grant) | [`upload`], [`keys`] |
//! | [`VaultDomain::fetch`] | ADR 0012 §7 "Fetch" as ADR 0021 §4 supersedes it in part | [`fetch`] |
//! | [`VaultDomain::compact_item`], [`VaultDomain::run_compaction`] | ADR 0021 §3, §7 (the `worker` job) | [`compact`] |
//! | [`create_vault`], [`VaultDomain::self_grant`], [`VaultDomain::vaults`] | CRYPTO.md §4.2, §4.4 | [`keys`] |
//! | [`port::create_personal_vault`], [`port::self_grants`], [`port::device_head`], [`port::recovery_vaults`] | ADR 0016 R4; CRYPTO.md §11.1 step 8, §11.2 step 5, §11.8 step 0, §11.9 step 3; ADR 0025 §1; ADR 0032 §3 (healing step 3a compares re-sent self-grants) | [`port`]: the vault side of the `auth` flows, on the caller's transaction |
//! | [`rotation::apply_rotation`] | CRYPTO.md §11.6 steps 3 and 9; ADR 0012 §6; ADR 0021 §9 "Rotation cut-off"; ADR 0025 §3 | [`rotation`]: the vault half of a key rotation, in the `auth` domain's commit transaction |
//! | [`DeviceDirectory`] | ADR 0012 §7 "Certificates come from the `auth` domain through a trait"; ADR 0016 R4 | [`authors`] |
//!
//! The rule logic of ADR 0021 §2–§4 and §9 "Server acceptance" / "Revoked and kind-4 authors" is
//! `rizzy_sync::compaction` ([`clamp`](rizzy_sync::compaction::clamp),
//! [`plan_worker`](rizzy_sync::compaction::plan_worker),
//! [`select_covers`](rizzy_sync::compaction::select_covers),
//! [`check_snapshot`](rizzy_sync::compaction::check_snapshot),
//! [`check_healing_request`](rizzy_sync::compaction::check_healing_request)). This crate reads
//! the rows, calls those pure functions inside the right transaction, and writes the result.
//!
//! # Transactions
//!
//! - **Every write** (upload, healing request, compaction, self-grant) is one `rizzy-storage`
//!   write transaction that first takes the account lock
//!   ([`lock_account`](rizzy_storage::lock_account), [ADR 0011] "Transactions and
//!   concurrency"). The certificates and revocation state are read under that lock, on the same
//!   connection, through [`DeviceDirectory`], so a revocation cannot commit between the check
//!   and the insert (ADR 0012 §6).
//! - **Every Fetch** is one read transaction (ADR 0021 §4 "One consistent read").
//! - **Events** (`rizzy_bus::Event::CompactionQueued`) are published only after commit; the
//!   durable compaction queue, not the event, is the record of truth.
//!
//! # Contract
//!
//! - **No `unsafe`** (workspace lint and `#![forbid(unsafe_code)]` below).
//! - **No panics** outside tests: every fallible step returns [`VaultError`] or an upload
//!   answer. Integers bound for SQL go through `rizzy_storage::convert`, which refuses a `u64`
//!   above `i64::MAX`.
//! - **Bound parameters only** (ADR 0011 point 2, INV-53): every query is a `&'static str` from
//!   a `.sql` file under `queries/`, over this domain's own `vault_` tables only (ADR 0011
//!   point 5). `clippy.toml` bans sqlx's escape hatches, as in `rizzy-storage`.
//! - **Nothing is logged here, and no error carries a value** (INV-48): errors name a rule or a
//!   column. The one report that names ids is [`IntegrityError`], which ADR 0021 §4 asks the
//!   server to log ("naming the vault, item and dot, never content"). This crate has no logging
//!   dependency, so [`VaultDomain::fetch`] returns those reports and `rizzy-server` logs them.
//! - **Randomness and time are injected**: every call that writes a `*_at_ms` column or checks
//!   an expiry takes `now_ms`; the crate reads no clock and draws no random value.
//! - **No new parser.** Every byte string of an upload is read by a fuzzed parser of
//!   `rizzy-proto` (`proto_json`), `rizzy-core` (`signed_statements`) or `rizzy-sync`
//!   (`sync_header`, `sync_types`); `intake` only slices the 82-byte
//!   signature container off a bounded buffer with checked arithmetic, and compares. Stored
//!   rows read back are checked for their shape and reported as [`VaultError::Corrupt`].
//!
//! # Conservative readings (reported to the owner)
//!
//! Where an Accepted ADR leaves a server detail open, this crate takes the stricter reading and
//! says so where it is applied:
//! - **Upload batches** follow `rizzy-proto`'s reading ([`UploadResult`](rizzy_proto::vault::UploadResult)):
//!   after the first rejected record nothing more is stored; the records before it commit.
//! - **Suspended authors** (revocation phase 1, ADR 0012 §6): every record the device authored
//!   is refused, whoever uploads it ([`AuthorStatus::Suspended`]).
//! - **Stale epoch inside a healing request**: no record of a healing request gets the check
//!   (see [`upload`], "Stale epoch inside a healing request").
//! - **Re-published self-grants** follow the lag rule of ADR 0032 §3 in healing step 3b: a
//!   self-grant behind the held signed state's `account_key_epoch` is replaced, inside or outside
//!   the reconciliation epoch, by a device session of a durable device of the held device set,
//!   raising the vault's `vault_key_epoch` above the restored one and deleting the wrap rows and
//!   record wraps below it. A step-3b wrap whose row the server lacks is left out (re-published in
//!   step 4), the conservative reading of "replaces each stored row". Self-grants sent through
//!   `healing/grants` keep the earlier reading: only during the epoch, never above a verified
//!   epoch, never moving `vault_key_epoch` ([`keys`]).
//! - **Compaction failures** are isolated per item: a failing item is moved behind every other
//!   queued item and reported, and the job goes on with the next one ([`compact`]).
//! - **"Already stored"** compares the signed statement and every attachment held on both sides
//!   (`store::same_record`): a body the server deleted, or a wrap it stopped serving, is bound
//!   by the identical signed hash and is no difference.
//!
//! # Open wire details (not frozen here)
//!
//! - How a paged Fetch bounds its covers and wrap-set rows: a page holds at most
//!   [`PAGE_MAX_OPS`] ops so that its covers fit one list, and at most [`PAGE_BYTES`] bytes of
//!   ops and covers together, a bodiless header always with its covers; the wrap set is sent whole on every
//!   page and a Fetch fails with [`VaultError::WrapSetTooLarge`] rather than truncate it, since
//!   `rizzy-proto` has no way to page it.
//! - Per-device cursors (`vault_device_cursors`, ADR 0011 "What is stored") are not recorded:
//!   a Fetch request does not name the fetching device, and no Accepted ADR says when the
//!   server writes them.
//!
//! # Tests
//!
//! `tests/vault/` runs against real SQLite files, or against PostgreSQL when
//! `RIZZY_TEST_POSTGRES_URL` names a database the tests may wipe (ADR 0021 §8, ADR 0011 point
//! 3; no CI job runs it yet), with real `op` and `snapshot` statements signed by `rizzy-core`
//! device keys drawn from a seeded test RNG: upload → Fetch round trips, "Already stored" and
//! conflicts, chain gaps, stale epochs and their exemptions, revoked, suspended and kind-4
//! authors, bogus self-grant epochs, compaction with two-author covers and a failing item, the
//! page byte budget, a Fetch racing compaction (200 runs by default, `RIZZY_TEST_RACE_RUNS` to
//! change it, 1,000 for the ADR 0021 §8 figure; it requires a Fetch that read the old state
//! while the compaction committed), a healing request after a backup and restore, and healing
//! step 3b (ADR 0032): a lagging self-grant repaired with its wrap set, one test per refusal.
//!
//! [ADR 0010]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0010-server-shape.md
//! [ADR 0011]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0011-storage.md
//! [ADR 0012]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0012-sync-engine.md
//! [ADR 0016]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0016-workspace-layout.md
//! [ADR 0021]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0021-server-compaction.md

#![forbid(unsafe_code)]
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

use core::fmt;

use rizzy_bus::{Bus, Event};
use rizzy_core::ids::{AccountId, ItemId, VaultId};
use rizzy_proto::vault::RestoreGeneration;
use rizzy_storage::{Conn, Database};

pub mod authors;
pub mod compact;
pub mod error;
pub mod fetch;
mod intake;
pub mod keys;
pub mod port;
mod repo;
pub mod rotation;
mod store;
pub mod upload;

pub use authors::{
    AccountKeyState, AuthorCertificate, AuthorStatus, Authors, DeviceDirectory, DirectoryError,
    DuplicateDevice,
};
pub use compact::{CompactionFailure, CompactionReport, CompactionRun};
pub use error::{HealingError, VaultError};
pub use fetch::{FetchOutcome, IntegrityError, PAGE_BYTES, PAGE_MAX_OPS};
pub use keys::create_vault;
pub use port::PersonalVaultOutcome;

/// The vault domain: a database handle, the `auth` domain's certificates through
/// [`DeviceDirectory`], and the event bus. Cheap to share behind an `Arc`; every call opens its
/// own transaction.
pub struct VaultDomain<D> {
    /// The server database (`rizzy-storage`).
    database: Database,
    /// The account's device certificates (ADR 0016 R4).
    directory: D,
    /// Where `CompactionQueued` goes after commit.
    bus: Bus,
    /// The byte budget of one Fetch page, ops and covers together ([`fetch`]).
    page_bytes: usize,
}

impl<D> fmt::Debug for VaultDomain<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultDomain")
            .field("engine", &self.database.engine())
            .finish_non_exhaustive()
    }
}

impl<D: DeviceDirectory> VaultDomain<D> {
    /// The domain over `database`, reading certificates through `directory` and publishing on
    /// `bus`.
    ///
    /// `rizzy-server` calls `rizzy_storage::meta::ensure_restore_generation` once at startup,
    /// before the first request; every upload answer and Fetch response carries that value
    /// (ADR 0021 §2), and a call fails with [`VaultError::NoRestoreGeneration`] without it.
    #[must_use]
    pub const fn new(database: Database, directory: D, bus: Bus) -> Self {
        Self {
            database,
            directory,
            bus,
            page_bytes: PAGE_BYTES,
        }
    }

    /// The same domain with a Fetch page budget of `bytes` (ops and covers together, see
    /// [`fetch`]) instead of [`PAGE_BYTES`]. A page always holds at least one op and its
    /// covers, whatever the budget.
    #[must_use]
    pub const fn with_page_bytes(mut self, bytes: usize) -> Self {
        self.page_bytes = bytes;
        self
    }
}

impl<D> VaultDomain<D> {
    /// The database handle.
    pub(crate) const fn database(&self) -> &Database {
        &self.database
    }

    /// The byte budget of one Fetch page.
    pub(crate) const fn page_bytes(&self) -> usize {
        self.page_bytes
    }

    /// The certificate source.
    pub(crate) const fn directory(&self) -> &D {
        &self.directory
    }

    /// Publishes that `item` of `vault` was queued for compaction. After commit only.
    pub(crate) fn publish_compaction_queued(
        &self,
        account: AccountId,
        vault: VaultId,
        item: ItemId,
    ) {
        // The receiver count is informational: the durable queue is the record of truth.
        let _receivers = self.bus.publish(Event::CompactionQueued {
            account: rizzy_bus::AccountId::from_bytes(account.to_bytes()),
            vault: rizzy_bus::VaultId::from_bytes(vault.to_bytes()),
            item: rizzy_bus::ItemId::from_bytes(item.to_bytes()),
        });
    }
}

/// The database's restore generation (ADR 0021 §2), read inside the caller's transaction so a
/// response carries the value of the database it was built from.
///
/// # Errors
/// [`VaultError::NoRestoreGeneration`] when none was drawn; [`VaultError::Storage`].
pub(crate) async fn restore_generation(conn: Conn<'_>) -> Result<RestoreGeneration, VaultError> {
    let generation = rizzy_storage::meta::restore_generation(conn)
        .await?
        .ok_or(VaultError::NoRestoreGeneration)?;
    Ok(RestoreGeneration::from_bytes(*generation.as_bytes()))
}

/// The server clock as an SQL integer for the `*_at_ms` columns.
///
/// # Errors
/// [`VaultError::Storage`] ([`rizzy_storage::Error::OutOfRange`]) above `i64::MAX`.
pub(crate) fn to_sql_time(now_ms: u64) -> Result<i64, VaultError> {
    Ok(rizzy_storage::convert::u64_to_sql(now_ms, "now_ms")?)
}

#[cfg(test)]
mod tests {
    //! Limits this crate sees from both sides: `rizzy-proto`'s and the backup file's.

    use rizzy_proto::limits;
    use rizzy_storage::backup::file::{MAX_BLOB_LEN, MAX_TEXT_LEN};

    /// ADR 0023 §3: the backup file's blob limit "must be ≥ every `rizzy-proto` limit on a
    /// stored value", so every row the server accepted over the API fits a backup. The text
    /// limit covers the one text column, `auth_accounts.login_name`.
    #[test]
    fn backup_value_limits_cover_every_stored_value() {
        const {
            assert!(limits::MAX_ENVELOPE_LEN <= MAX_BLOB_LEN);
            assert!(limits::MAX_OP_STATEMENT_LEN <= MAX_BLOB_LEN);
            assert!(limits::MAX_SNAPSHOT_STATEMENT_LEN <= MAX_BLOB_LEN);
            assert!(limits::MAX_KEY_GRANT_STATEMENT_LEN <= MAX_BLOB_LEN);
            assert!(limits::MAX_ACCOUNT_STATEMENT_LEN <= MAX_BLOB_LEN);
            assert!(limits::MAX_KEY_ENVELOPE_LEN <= MAX_BLOB_LEN);
            assert!(limits::MAX_OPAQUE_MESSAGE_LEN <= MAX_BLOB_LEN);
            // A clamped version vector or a device cursor: `u16 n` and `n` entries of 24 bytes.
            assert!(2 + limits::MAX_VV_ENTRIES * (16 + 8) <= MAX_BLOB_LEN);
            assert!(<limits::LoginNameRule as rizzy_proto::wire::TextRule>::MAX <= MAX_TEXT_LEN);
        }
    }
}
