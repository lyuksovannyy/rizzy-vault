// SPDX-License-Identifier: AGPL-3.0-only

//! Integration tests of `rizzy-domain-vault` against real SQLite files, or a real PostgreSQL
//! database when `RIZZY_TEST_POSTGRES_URL` names one the tests may wipe (`common::Slot`), with
//! real `op` and `snapshot` statements signed by `rizzy-core` device keys.
//!
//! - [`attachments`]: encrypted attachments (ADR 0054 §5–§7): the lifecycle, exact chunk
//!   lengths, retries and conflicts, the cap and the quota charged at create, another account's
//!   id answered `not_found`, and the 24 h sweep.
//! - [`common`]: the harness: a migrated database with one account, created through
//!   `rizzy-storage`'s restore (so the `auth_accounts` row is written by `rizzy-storage`, never
//!   by this domain's SQL); an in-memory [`DeviceDirectory`](rizzy_domain_vault::DeviceDirectory);
//!   devices that sign records.
//! - [`upload`]: upload → Fetch round trips, "Already stored", conflicts, chain gaps, forged
//!   authors, stale epochs and their exemptions, revoked, suspended and kind-4 authors.
//! - [`compaction`]: two-author covers, R1 and R3 through the `worker` job, a failing item that
//!   does not stop the others, per-page covers and the page byte budget, integrity errors, and a
//!   Fetch racing compaction (`RIZZY_TEST_RACE_RUNS`, 200 by default).
//! - [`healing`]: a healing request after a backup and restore, and its atomic refusal.
//! - [`paged_tombstone`]: ADR 0050 §4, a tombstone cover served a page before its recorded
//!   purge, over small page budgets, through a client's causal layer: the boundary case across
//!   devices, the retry, and a purge that never comes.
//! - [`rotation`]: the vault half of a key rotation (ADR 0025): the rewrite of the wrap set, one
//!   test per refusal, epochs after a restore, a planted junk wrap, healing below the current
//!   epoch, the recovery cursor, and uploads racing rotations (`RIZZY_TEST_RACE_RUNS`).
//! - [`quota`]: the per-account storage quota (ADR 0048): the counted unit, the refusal at the
//!   exact boundary, the headroom, the healing exemption, compaction's credit.
//! - [`selfgrant`]: healing step 3b (ADR 0032 §2–§3): a lagging self-grant repaired with its
//!   wrap set, one test per refusal of the lag rule, the repeat rules, and a vault epoch ahead
//!   of the account epoch.

mod attachments;
mod common;
mod compaction;
mod healing;
mod paged_tombstone;
mod quota;
mod rotation;
mod selfgrant;
mod upload;
