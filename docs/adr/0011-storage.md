# ADR 0011: Storage: SQLite and PostgreSQL via sqlx

- Status: Proposed
- Date: 2026-09-25
- Deciders: project owner
- Milestone: M1 (SQLite) / M3 (PostgreSQL supported)

## Context

The relevant ROADMAP rows:
- [ROADMAP §4.9](../ROADMAP.md#49-server-self-hosting--ops-m1-onward), Must: "SQLite (default, personal) and PostgreSQL (orgs/SMB)", M1 for SQLite and M3 for PostgreSQL.
- §4.9, Must, M1: "DB migrations".
- §4.9, Must, M1: "Backup & restore command + documented procedure (tested, not just written)".
- [ROADMAP §5](../ROADMAP.md#5-architecture-decisions-to-make-in-m0-with-current-recommendation) recommends both engines through sqlx, with SQLite as the default.

The data is small and regular. Per account there are a few hundred to a few thousand rows of ciphertext, key wraps, signed statements, public keys and metadata. A personal instance writes a few ops a minute at peak. Almost every row has the shape (id, owner, ciphertext blob, a few integers).

Constraints:
- **No plaintext user content, ever** ([ROADMAP §2](../ROADMAP.md#2-guiding-principles-non-negotiable), principle 1; [INV-15](../THREAT_MODEL.md#8-security-invariants) canary test). [THREAT_MODEL §3.4](../THREAT_MODEL.md#34-what-the-server-holds-by-sync-mode) lists the metadata the server may hold.
- **Server secrets stay out of the DB** ([INV-50](../THREAT_MODEL.md#8-security-invariants), [CRYPTO.md §5.8](../CRYPTO.md#58-loss-or-rotation-of-the-server-opaque-secrets)).
- **Server-side check-then-write rules.** [ADR 0012](0012-sync-engine.md) needs the server to check state and write in one step: the revocation cut-off (§6), the `vault_prev_seq` head check (§7), the `state_seq` compare-and-swap ([CRYPTO.md §10.2](../CRYPTO.md#102-ed25519-signatures-and-signed-statements)) and the switch point (§10).
- **sqlx 0.9.0 has MSRV 1.94.0**, which is our toolchain floor (V). A sqlx upgrade can force a toolchain bump.
- **sqlx 0.9 and rusqlite 0.40 cannot share a build.** Both link `sqlite3`, through incompatible `libsqlite3-sys` versions (V, resolver error reproduced). rusqlite 0.39 does resolve (V).
- RUSTSEC-2024-0363 affected sqlx before 0.8.1 (V).
- [ADR 0010](0010-server-shape.md): with SQLite, a single process writes the database file.

## Decision

### Engines and access

1. **sqlx 0.9** with the `sqlite` and `postgres` drivers, `runtime-tokio`, and rustls for PostgreSQL TLS.
   - **SQLite is the default** and needs no configuration: it is a file on the data volume.
   - **PostgreSQL** is selected with a `postgres://` URL. Remote databases use `sslmode=verify-full`.
2. **Bound parameters only** ([INV-53](../THREAT_MODEL.md#8-security-invariants)).
   - Query text is a `&'static str`, loaded from a `.sql` file with `include_str!` (rule 7). Nothing is built with `format!`.
   - **sqlx 0.9 enforces this at compile time.** `query`, `query_as`, `query_scalar` and `raw_sql` take `impl SqlSafeStr`. sqlx implements that trait only for `&'static str`, `SqlStr` and `AssertSqlSafe<_>` (sqlx-core 0.9.0 source, V). A `format!` string does not compile. INV-53 relies on this guard, so a sqlx upgrade that removes or weakens `SqlSafeStr` needs a security review.
   - **The escape hatches are banned** through clippy, in every crate that depends on sqlx:
     - `disallowed-types`: `sqlx::AssertSqlSafe` and `sqlx::QueryBuilder`. `QueryBuilder::push` appends any `Display` value to the SQL text.
     - `disallowed-methods`: `sqlx::AssertSqlSafe` again, because `disallowed-types` does not flag its tuple-constructor call; and `std::string::String::leak` and `std::boxed::Box::leak`, which turn a runtime string into a `&'static str`. Checked with clippy 1.94.1 against sqlx 0.9.0: each entry is flagged at its call site (V).
     - A reviewed use carries `#[expect(clippy::disallowed_types, reason = "...")]` at the narrowest scope, like any other silenced lint.
   - `raw_sql` with a literal is harmless and is not banned.
3. **Runtime-checked queries, tested on both engines.**
   - sqlx's compile-time macros check each query against one configured database (U, confirm in M1). That does not fit two SQL dialects.
   - **One repository method, two engines, by enum dispatch.** The handle is an enum over `SqlitePool` and `PgPool`. A repository method matches on it once and runs the same query text on either engine. A small macro keeps the two arms identical.
   - Shared query files use `$1, $2, …` placeholders. sqlx-sqlite 0.9 maps `$N` to argument position N (sqlx-sqlite 0.9.0 source, V). A query gets per-engine files only where the dialects differ.
   - Not the sqlx `Any` driver, whose type support is narrower than the native drivers' (U), and not code generic over `DB: Database`, whose trait bounds would spread through every repository method and transaction helper. The M1 spike confirms the choice on the first domain (open question 5).
   - Every repository method has an integration test that runs against both SQLite and PostgreSQL in CI.
   - **The PostgreSQL CI job exists from the first migration in M1**, although PostgreSQL is supported only from M3. Fixing dialect drift after twenty migrations costs more than testing from the first one.
4. **Portable column types:**
   - IDs: `BLOB` / `bytea`, 16 random bytes created by the client ([CRYPTO.md §2](../CRYPTO.md#2-conventions)).
   - Envelopes and signed statements: `BLOB` / `bytea`.
   - Times: `INTEGER` / `bigint`, milliseconds since the Unix epoch, set by the server.

   No JSON columns, no engine-specific types, no triggers and no stored procedures.

### Table ownership

5. **Each domain owns its tables.**
   - Table names carry the domain prefix: `auth_`, `vault_`, `relay_`, `share_`, `mail_`, `org_`.
   - A domain crate queries only its own tables.
   - Another domain gets that data through the owner's Rust API or a bus event, never through SQL ([ADR 0016](0016-workspace-layout.md)).
6. **One cross-domain reference is allowed:** a foreign key to `auth_accounts(id)` with `ON DELETE CASCADE`, so that deleting an account is one transaction. No other foreign key crosses a domain.
7. **Enforcement.**
   - Queries live in `.sql` files under each domain crate's `queries/` directory and are loaded with `include_str!`.
   - A repo check, `cargo xtask check-tables` ([ADR 0016](0016-workspace-layout.md)), scans migration and query files. It reads the table names after `FROM`, `JOIN`, `INTO`, `UPDATE`, `TABLE` and `REFERENCES`.
   - It fails when a prefix does not match the owning crate. The one allowed foreign key is the only exception.

### Migrations

8. **sqlx migrations, forward-only, embedded in the binary.**
   - Files live in `crates/rizzy-storage/migrations/sqlite/` and `crates/rizzy-storage/migrations/postgres/`, one ordered sequence per engine.
   - Each file name carries the owning domain, e.g. `0007_vault_add_snapshots.sql`.
   - There are no down-migrations. A bad migration is fixed by a new one.
9. **When migrations run.**
   - **SQLite:** automatically at startup.
     - Only when migrations are pending, the server first writes a consistent copy of the database next to it with `VACUUM INTO`, mode 0600. With no pending migration, no copy is written.
     - `worker` deletes the copy 24 h after the migrated server started and passed its startup self-check.
     - An account deletion or a Server → On-device switch deletes the copy at once. Otherwise the copy would still hold what that deletion removed, and the deletion receipt would be false ([INV-28](../THREAT_MODEL.md#8-security-invariants), [CRYPTO.md §5.7](../CRYPTO.md#57-on-device-sync-mode)). The operator then has only their own backups to fall back on.
     - `secure_delete` does not reach the copy. [AR-11](../THREAT_MODEL.md#9-accepted-risks-and-out-of-scope) and the transparency page mention it.
   - **PostgreSQL:** explicitly, with `rizzy-vault migrate`, before new replicas start. A server that finds pending migrations on PostgreSQL refuses to start and names the command to run.
10. **Upgrade test.** CI loads a fixture database produced by the previous release, migrates it and runs the integration suite, on both engines. From M1 on, every release adds its fixture.

### Transactions and concurrency

The check-then-write rules in the Context break under default isolation:
- On PostgreSQL's default READ COMMITTED, a revocation and a concurrent upload from the revoked device can both commit (write skew). An honest server would then break [ADR 0012](0012-sync-engine.md) §6's promise that every replica agrees on the cut-off.
- On SQLite, a deferred transaction that reads and then writes can fail on the lock upgrade with `SQLITE_BUSY`, or with `SQLITE_BUSY_SNAPSHOT` in WAL mode. `busy_timeout` does not help: SQLite skips the busy handler where waiting could deadlock (SQLite locking documentation; not re-checked for this ADR).

Rules:
- **One lock per account.** Every write transaction that reads state and then writes based on it first takes the account's lock, through one `rizzy-storage` call, `lock_account(tx, account_id)`.
  - PostgreSQL: `pg_advisory_xact_lock` on a key derived from the account id, in a key space distinct from `worker`'s leader lock ([ADR 0010](0010-server-shape.md) §2). A transaction-level lock is released at commit or rollback, so pool recycling cannot leak or drop it.
  - SQLite: no extra step, because every write transaction already holds the database write lock (next rule).
  - Domains take the lock through `rizzy-storage`, so no domain reads another domain's table to lock a row (rule 5). A cross-domain operation (revocation, account deletion, mode switch) is one transaction that takes the lock once.
- **SQLite write transactions start with `BEGIN IMMEDIATE`** (sqlx 0.9 `begin_with`, V), on a writer pool of one connection. Reads use a separate reader pool. `busy_timeout` then covers the only wait left: acquiring the write lock at `BEGIN`.
- **Not SERIALIZABLE on PostgreSQL.** Every write path would need a retry loop for serialization failures. A per-account lock serialises exactly the writes that can conflict, and contention per account is near zero at our scale.
- **Concurrency tests on both engines:** a revocation racing an upload from the revoked device; two enrolments racing on `state_seq`. Exactly one of the allowed outcomes happens in each run.

### SQLite settings

| Pragma | Value | Why |
|---|---|---|
| `journal_mode` | `WAL` | Concurrent readers during writes |
| `synchronous` | `FULL` | A password manager must not lose an acknowledged write on power loss. The write load is too small for the cost to matter |
| `foreign_keys` | `ON` | Needed for the cascade in rule 6 |
| `busy_timeout` | `5000` | ms. Covers waiting for the write lock at `BEGIN IMMEDIATE` |
| `secure_delete` | `ON` | Overwrites deleted content in the database file ([THREAT_MODEL §7.9](../THREAT_MODEL.md#79-worker-role-m1)). It does not reach the WAL before a checkpoint, the pre-migration copy, or backups ([AR-11](../THREAT_MODEL.md#9-accepted-risks-and-out-of-scope)). The docs say so |
| `auto_vacuum` | `INCREMENTAL` | Returns space from purged rows. It must be set when the file is created, before the first table exists; on an existing file it takes effect only after a full `VACUUM`. So it is set in the sqlx connect options (`auto_vacuum`), before the first migration runs. It frees nothing by itself: `worker` runs `PRAGMA incremental_vacuum(N)` after purges, and a test checks that the file shrinks after a purge |

SQLite files must not live on NFS or SMB shares, and the docs say so.

### What is stored, by sync mode

[THREAT_MODEL §3.4](../THREAT_MODEL.md#34-what-the-server-holds-by-sync-mode) is the authoritative list. By domain:

| Domain | Server mode | On-device mode |
|---|---|---|
| `auth` | accounts; OPAQUE records with `setup_id`; `E_srv`, `E_rec`, `H_rec`; session-token hashes; 2FA secrets encrypted under a server key kept outside the DB; device certificates and revocations; key bundles; signed `account-state`; key grants; short-lived auth state: sealed login state, challenges, rate-limit counters, pending recoveries ([ADR 0010](0010-server-shape.md) §5) | the same, **except** the OPAQUE record, `E_srv`, `E_rec` and `H_rec`, which are not stored ([CRYPTO.md §5.7](../CRYPTO.md#57-on-device-sync-mode), INV-28) |
| `vault` | vault self-grants, item-key wraps, per-item snapshots, op records not yet compacted, signed op headers kept after compaction, per-device cursors ([ADR 0012](0012-sync-engine.md)) | nothing: the server deletes it at the switch point ([CRYPTO.md §5.7](../CRYPTO.md#57-on-device-sync-mode), [ADR 0012](0012-sync-engine.md) §10) |
| `relay` (M4) | nothing | pending relay batches, per-device ack cursors, TTL bookkeeping, short-lived pairing sessions |
| `share` (M5) | share envelopes, link-token and access-token hashes ([CRYPTO.md §11.10](../CRYPTO.md#1110-public-share-link-creation-m5)), expiry, view counts | the same |
| `mail` (M6) | aliases, the alias → account mapping, mail envelopes, retention dates | the same, but each message is also purged once every active device has acknowledged it ([ROADMAP §4.6](../ROADMAP.md#46-sync-modes-m4)) |
| `org` (M9) | defined in M9 | – |

A mode switch moves an account from one column to the other, with one transaction per domain ([ADR 0012](0012-sync-engine.md)).

### No plaintext

- A column that holds user content is a `BLOB` / `bytea` containing an envelope ([ADR 0007](0007-ciphertext-envelope.md)) or a signed statement. There are no `TEXT` columns for user content.
- Clear-text columns are limited to the metadata in [THREAT_MODEL §3.4](../THREAT_MODEL.md#34-what-the-server-holds-by-sync-mode): login name, alias addresses, share recipient emails (M5), sizes, counts, timestamps, IDs and flags. Adding a clear-text column requires a THREAT_MODEL change in the same PR.
- The INV-15 canary test exercises every flow, dumps both databases, and searches them for the known secrets.

### Backups

- **Logical backup.** `rizzy-vault backup` writes a consistent, engine-neutral dump: every table as rows, in a versioned and documented file format, stamped with the schema version. `rizzy-vault restore` loads it into an empty SQLite or PostgreSQL database. The same pair moves an instance from SQLite (profile A) to PostgreSQL (profile C).
  - On SQLite, `backup` runs next to the running server as a read-only reader; `restore` needs the server stopped ([ADR 0010](0010-server-shape.md) §2).
- **Native methods** stay valid and are documented: `VACUUM INTO` or the SQLite backup API for SQLite, `pg_dump` for PostgreSQL.
- **Server secrets are not in the DB backup** (INV-50), and not on the data volume either: they have their own read-only mount ([ADR 0010](0010-server-shape.md) §4).
  - `rizzy-vault backup-secrets` writes them to a separate file with mode 0600. The docs say to store it apart from the DB backups.
  - The server refuses to start against a DB whose OPAQUE records do not match the loaded setup ([CRYPTO.md §5.8](../CRYPTO.md#58-loss-or-rotation-of-the-server-opaque-secrets)).
- **Restore drill in CI**, on both engines ([ROADMAP §7](../ROADMAP.md#7-definition-of-done-for-v10-end-of-m8), [INV-59](../THREAT_MODEL.md#8-security-invariants)):
  1. populate an instance with simulated clients;
  2. back it up;
  3. after the backup: change a password, enrol a device, revoke a device, and run a key rotation that also replaces the recovery code;
  4. wipe the instance and restore the backup;
  5. reconnect the simulated clients. Check that:
     - they heal the server as [ADR 0012](0012-sync-engine.md) §7 describes, and converge;
     - the device enrolled after the backup authenticates;
     - the old password, the old recovery code and the revoked device are refused;
     - every item written under the rotated keys decrypts on every remaining device.
- **What a restore cannot do.**
  - A DB backup holds nothing of On-device-mode vaults. For those users, their devices and their own backup files are the backup.
  - Restoring an old backup rolls every Server-mode account back: ops, and also the key and state layer (signed `account-state`, device certificates and revocations, the bundle, grants and wraps, the OPAQUE record and `E_srv`, `E_rec`). `rizzy-vault restore` puts every restored account into a reconciliation epoch ([THREAT_MODEL §5.8](../THREAT_MODEL.md#58-server-restore-from-backup), INV-59).
  - Clients detect the rollback ([INV-25](../THREAT_MODEL.md#8-security-invariants)) and re-publish what the server lost, state first and ops last ([ADR 0012](0012-sync-engine.md) §7). The OPAQUE record and `E_srv` are not re-uploaded: an enrolled device re-registers OPAQUE the next time the user types the password. Recovery stays refused until a device issues a new recovery code.
  - Accounts whose devices never reconnect stay rolled back ([AR-19](../THREAT_MODEL.md#9-accepted-risks-and-out-of-scope)). The restore command says so.

### Clients

- Clients persist only ciphertext: the same envelopes, plus their local wraps.
- They write through a storage interface that `rizzy-client` defines and each platform implements ([ADR 0013](0013-shared-client-core.md)):
  - IndexedDB in the extension;
  - SQLite on desktop, CLI and mobile;
  - nothing in the web vault, which keeps everything in memory and persists only the Secret Key, and only if the user opts in ([CRYPTO.md §11.4](../CRYPTO.md#114-web-vault)).
- Native clients that use SQLite use sqlx as well, so the workspace never links two `libsqlite3-sys` versions.

### Attachments (M3)

Out of scope here. The M3 attachments ADR chooses between DB blobs and a separate blob store. Until then the DB is the only place that holds user data.

## Consequences

### Positive

- A personal instance is one file on one volume, with nothing to configure.
- A team instance runs on PostgreSQL with the same code and the same tests.
- A backup of either engine holds only ciphertext and the metadata the threat model already lists.
- Domain ownership of tables keeps a future split cheap ([ADR 0010](0010-server-shape.md), split criteria) and is checked by CI, not by memory.
- The engine-neutral backup format doubles as the SQLite-to-PostgreSQL migration path.
- SQL injection through string building fails to compile, and the escape hatches fail the lint.

### Negative

- Two dialects and two migration sequences to maintain. Every schema change is written twice.
- Runtime-checked queries catch a typo at test time, not at compile time. Coverage of repository methods has to stay complete.
- `synchronous=FULL` and `secure_delete=ON` cost write throughput. That is irrelevant at our load, but it would matter for a large SQLite instance, which should move to PostgreSQL anyway.
- One SQLite writer connection and a per-account lock serialise writes. That is fine at personal scale and per account on PostgreSQL.
- Banning `QueryBuilder` rules out dynamic `IN (…)` lists and bulk inserts built at run time. Those become loops or fixed-arity queries, or a reviewed `#[expect]`.
- sqlx's MSRV tracks our toolchain floor. Upgrading sqlx may force a toolchain bump in the same PR.
- The logical backup format is one more versioned format to maintain.

### Risks

- A sqlx major release could change the query API, drop an engine feature we rely on, or weaken `SqlSafeStr`. Every upgrade is a reviewed PR, and both engines' suites must pass.
- A check-then-write path that forgets `lock_account` reintroduces write skew on PostgreSQL. The concurrency tests cover the known paths; review covers new ones.
- If the data grows beyond what fits in rows (attachments, large mailboxes), the DB-only rule needs the M3 blob-store decision.
- Deleted ciphertext survives in the WAL until a checkpoint, in the pre-migration copy for up to 24 h, and in backups until they expire. The threat model accepts this (AR-11), and the docs must keep saying it.

## Alternatives considered

- **SQLite only.** Simplest, but it rules out multiple processes and HA, which SMB (M10) and profile C need.
- **PostgreSQL only.** One dialect, but a personal self-hoster then runs and backs up a second container. [ROADMAP §5](../ROADMAP.md#5-architecture-decisions-to-make-in-m0-with-current-recommendation) calls zero configuration the point for personal users.
- **rusqlite for SQLite, sqlx for PostgreSQL.** Two query APIs and two sets of types. It also cannot link together with sqlx 0.9 unless rusqlite is held at 0.39 (fact sheet, V).
- **An ORM** (Diesel, SeaORM). A layer of abstraction over a schema that is mostly (id, owner, blob, version) rows. It adds a large dependency and hides the SQL we want to review for INV-53.
- **An embedded key-value store** (sled, redb). No SQL, no path to PostgreSQL, and we would build indexes and transactions ourselves.
- **MySQL or MariaDB.** A third dialect nobody has asked for.
- **sqlx compile-time macros with offline data per engine.** Compile-time checking is valuable, but two dialects in one crate fight the one-database-per-build model (U, confirm in M1). Revisit if sqlx supports this cleanly.
- **The sqlx `Any` driver, or repositories generic over `DB: Database`,** instead of enum dispatch. See rule 3.
- **SERIALIZABLE isolation with retries** on PostgreSQL, instead of the per-account lock. See "Transactions and concurrency".

## Open questions for the owner

1. **PostgreSQL in CI from M1**, officially supported from M3. *Recommendation:* yes.
2. **Automatic migration on SQLite, with a pre-migration copy kept for 24 h; explicit migration on PostgreSQL.** *Recommendation:* yes. A longer window keeps deleted data around longer.
3. **Encrypting the server-secrets backup file under an operator passphrase.** This is server-side cryptography, so it needs a CRYPTO.md amendment and a new purpose id. *Recommendation:* yes from M1, reusing the export-file construction ([CRYPTO.md §11.14](../CRYPTO.md#1114-encrypted-export-m1)) with its own purpose id.
4. **The engine-neutral backup format** versus documenting `pg_dump` and `VACUUM INTO` only. *Recommendation:* build it. It is the only way to move from SQLite to PostgreSQL, and the restore drill needs one format for both engines.
5. **Engine dispatch.** Enum dispatch over the two pools with shared `$N` query files, confirmed by an M1 spike on the first domain. *Recommendation:* yes. The alternatives are the sqlx `Any` driver, or code generic over `DB: Database`.

## References

- [ROADMAP](../ROADMAP.md) §4.6, §4.9, §5 (row "DB"), §7
- [THREAT_MODEL](../THREAT_MODEL.md) §3.4, §5.8, §7.9, §7.12, INV-15, INV-25, INV-28, INV-50, INV-53, INV-59, AR-11, AR-19
- [CRYPTO.md](../CRYPTO.md) §2, §5.7, §5.8, §9.6, §10.2, §11.4, §11.14
- [ADR 0007](0007-ciphertext-envelope.md), [ADR 0010](0010-server-shape.md), [ADR 0012](0012-sync-engine.md), [ADR 0013](0013-shared-client-core.md), [ADR 0016](0016-workspace-layout.md)
- Fact sheet 2026-09-25: sqlx 0.9.0 (MSRV 1.94.0), rusqlite 0.40.2 / 0.39 link conflict, RUSTSEC-2024-0363 (V)
- sqlx-core 0.9.0 `src/sql_str.rs` (`SqlSafeStr`, `AssertSqlSafe`), `src/pool/mod.rs` (`begin_with`); sqlx-sqlite 0.9.0 `src/arguments.rs` (`$N` parameters), `src/options/mod.rs` (`auto_vacuum`): read in `~/.cargo/registry` (V)
- Clippy 1.94.1 `disallowed-types` / `disallowed-methods` against sqlx 0.9.0, scratch crate (V)
