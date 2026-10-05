//! `rizzy-storage` — the server's storage layer (roadmap M1 step 3, [ADR 0011]; [ADR 0016] §3
//! row `rizzy-storage`): sqlx pools, embedded migrations, the per-account lock, the `worker`
//! leader lock, the instance lock, and backup and restore primitives. Server mode only
//! ([ADR 0022]): there are no relay tables.
//!
//! # What this crate is, and is not
//!
//! It owns the database: the connection pools and their settings, the schema (every domain's
//! migrations, per engine, [ADR 0011] point 8), the transaction types, the account lock, the
//! worker leader lock, and the restore hooks. It holds **no domain logic**: `rizzy-domain-auth`
//! and `rizzy-domain-vault` own their tables' queries (`auth_`, `vault_`, [ADR 0011] point 5) and
//! run them through this crate's [`WriteTx`] / [`ReadTx`] with [`on_engine!`]. It has no
//! internal dependencies ([ADR 0016] §3), knows nothing of keys or envelopes, and stores
//! every envelope, signed statement and hash as the opaque bytes it is given.
//!
//! # Contract
//!
//! - **Bound parameters only** ([ADR 0011] point 2, THREAT_MODEL INV-53). Every query text is a
//!   `&'static str` loaded from a `.sql` file with `include_str!` (`queries/`, `migrations/`);
//!   sqlx 0.9's `SqlSafeStr` refuses anything else at compile time, and this crate's
//!   `clippy.toml` bans the escape hatches (`sqlx::AssertSqlSafe`, `sqlx::QueryBuilder`,
//!   `String::leak`, `Box::leak`). `cargo xtask check-clippy` fails if clippy stops resolving an
//!   entry. Shared query files use `$1, $2, …` on both engines.
//! - **No plaintext, no secrets in the database beyond THREAT_MODEL §3.4**: the schema has no
//!   TEXT column for user content (`login_name` is metadata); server secrets never enter it
//!   (INV-50).
//! - **Nothing is logged** by this crate, and errors carry no bound value, row, token or key
//!   (INV-48; [`Error`]). [`backup::Value`]'s `Debug` shows kinds and lengths only.
//! - **No `unsafe`**, no `unwrap`/`expect`/`panic!` outside tests; every fallible function
//!   returns [`Error`] and documents it.
//! - **Paths.** Library code touches only the paths it is given: the database file, its lock
//!   file `<database>.lock` next to it ([`WriterLock`]), and the backup and pre-migration copies
//!   the caller names. One accepted exception: [`PostgresOptions::from_url`] follows libpq's
//!   defaults through sqlx, so it reads `PG*` environment variables for settings the URL
//!   leaves out and, when the URL has no password, the password file `$PGPASSFILE` or
//!   `~/.pgpass`; its docs say how to avoid both. Randomness and time are injected ([`RestoreGeneration`], `now_ms`
//!   arguments); the crate draws no random value and reads no clock.
//!
//! # Module map
//!
//! | Module | Spec | Purpose |
//! |---|---|---|
//! | [`db`] | ADR 0011 points 1, 3, "Transactions and concurrency", "SQLite settings"; ADR 0021 §4 | [`Database`] (enum over the SQLite pools and the PostgreSQL pool), [`WriteTx`] (`BEGIN IMMEDIATE` on the one SQLite writer), [`ReadTx`] (read-only SQLite reader; `REPEATABLE READ READ ONLY` on PostgreSQL), [`Conn`] and [`on_engine!`], the PRAGMAs, PostgreSQL TLS policy |
//! | [`writer_lock`] | ADR 0010 §2 | [`WriterLock`]: one process writes an SQLite file |
//! | [`lock`] | ADR 0011 "Transactions and concurrency"; ADR 0010 §2 | [`lock_account`]: `pg_advisory_xact_lock` in its own key space, nothing on SQLite |
//! | [`leader_lock`] | ADR 0010 §2 | [`WorkerLeader`] from [`Database::try_lead_worker`]: one active `worker` per database, a session-level advisory lock on a dedicated PostgreSQL connection outside the pool; on SQLite the writer lock already covers it |
//! | [`instance_lock`] | ADR 0023 §5 step 1 | [`InstanceLock`] from [`Database::try_instance_lock`]: every server process on PostgreSQL holds it shared, `restore`, `migrate`, `secrets rotate` and `secrets retire-setups` take it exclusively, on a dedicated connection outside the pool; on SQLite the writer lock already covers it |
//! | [`migrate`] | ADR 0011 points 8–10 | Embedded forward-only migrations per engine; the startup rule with the `VACUUM INTO` pre-migration copy (SQLite) or the refusal (PostgreSQL) |
//! | [`backup`] | ADR 0011 "Backups"; ADR 0023 | `VACUUM INTO`; the logical [`Dump`], [`Database::check_restore_target`] and [`Database::restore`] into an empty database, which draws a new restore generation, opens every account's reconciliation epoch and raises the store-sequence counters; [`backup::file`], the backup file's canonical writer and strict parser (format version 1, trailing SHA-256, size limits) |
//! | [`tables`] | ADR 0011 "Backups" | The backed-up tables and columns, in restore order |
//! | [`meta`] | ADR 0021 §2; THREAT_MODEL INV-59; ADR 0012 §7 | The restore generation and the reconciliation epochs, for the domain crates |
//! | [`convert`] | ADR 0011 point 4 | `u64`/`u32` ↔ SQL `i64`, refusing values SQL cannot order |
//! | [`error`] | – | [`Error`], [`RestoreError`], [`Engine`] |
//!
//! # Schema (M1)
//!
//! `migrations/<engine>/0001_auth_initial.sql`, `0002_vault_initial.sql`,
//! `0003_storage_restore.sql`, `0004_auth_retired_setups.sql` and
//! `0005_auth_credential_epochs.sql`: the tables of [ADR 0011] "What is stored" as [ADR 0022] §2 replaces it, plus the clamped VV,
//! store sequence, bodiless headers and restore generation of [ADR 0021] §2, the reconciliation
//! epochs of INV-59, the retirement time of an OPAQUE setup (ADR 0031 point 1), and the
//! `account_key_epoch` of the credential and recovery rows (ADR 0032 §4). Each file documents its
//! tables.
//!
//! # Tests
//!
//! `tests/sqlite.rs` runs against real SQLite files in a temporary directory: migrations and
//! PRAGMAs, schema-to-backup-list drift, the writer lock, writer/reader separation,
//! serialised writes, the startup copy, the backup → file → restore round trip, and the worker
//! leader and the instance lock (always granted on a writable file, refused read-only).
//! `tests/postgres.rs` runs the same
//! against PostgreSQL, plus the leader lock (one of two workers leads; a dropped or terminated
//! connection releases it) and the instance lock (shared holders refuse the exclusive lock and
//! the reverse), when `RIZZY_TEST_POSTGRES_URL` names an empty database;
//! its tests are `#[ignore]`d otherwise.
//!
//! [ADR 0010]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0010-server-shape.md
//! [ADR 0011]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0011-storage.md
//! [ADR 0016]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0016-workspace-layout.md
//! [ADR 0021]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0021-server-compaction.md
//! [ADR 0022]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0022-server-mode-only.md

#![forbid(unsafe_code)]
#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]

pub mod backup;
pub mod convert;
pub mod db;
pub mod error;
pub mod instance_lock;
pub mod leader_lock;
pub mod lock;
pub mod meta;
pub mod migrate;
pub mod tables;
pub mod writer_lock;

pub use backup::{Dump, RestoreReport, TableDump, Value};
pub use db::{Conn, Database, PostgresOptions, ReadTx, SqliteOptions, WriteTx};
pub use error::{Engine, Error, RestoreError};
pub use instance_lock::{InstanceLock, InstanceLockMode};
pub use leader_lock::WorkerLeader;
pub use lock::lock_account;
pub use meta::{ReconciliationEpoch, RestoreGeneration};
pub use migrate::{StartupMigration, remove_pre_migration_copy, schema_version};
pub use writer_lock::WriterLock;
