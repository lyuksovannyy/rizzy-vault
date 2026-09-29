# ADR 0023: Logical database backup file format

- Status: Accepted
- Date: 2026-09-29
- Deciders: project owner
- Milestone: M1

## Context

[ADR 0011](0011-storage.md) "Backups" (Accepted, in part superseded by [ADR 0022](0022-server-mode-only.md)) requires `rizzy-vault backup` to write "a consistent, engine-neutral dump: every table as rows, in a versioned and documented file format, stamped with the schema version", and `rizzy-vault restore` to load it "into an empty SQLite or PostgreSQL database". [ROADMAP §4.9](../ROADMAP.md#49-server-self-hosting--ops-m1-onward) makes "Backup & restore command + documented procedure" an M1 Must. No Accepted ADR defines the bytes, so neither command exists, and the only restore today is a native file copy, which opens no reconciliation epoch ([INV-59](../THREAT_MODEL.md#8-security-invariants)) and keeps the old restore generation ([ADR 0021](0021-server-compaction.md) §2). A restored old database then accepts revoked devices, superseded passwords and replaced recovery codes, and reconnecting devices cannot close that ([THREAT_MODEL §5.8](../THREAT_MODEL.md#58-server-restore-from-backup); `docs/self-hosting.md` §9).

What exists (V, `crates/rizzy-storage/src/backup.rs`, `tables.rs` at 1387df9):
- `Database::dump` reads every table of `TABLES` (22 tables, `auth_*` and `vault_*` minus sessions, login states, device challenges, `storage_meta`, `storage_reconciliation`) in one read transaction, in foreign-key order, into an in-memory `Dump { schema_version: i64, tables: Vec<TableDump> }`. Each row holds one `Value` (`Null`, `Integer(i64)`, `Text(String)`, `Blob(Vec<u8>)`) per column. It refuses a database not at exactly this release's schema.
- `Database::restore(dump, generation, now_ms)` requires the dump's schema version to equal this release's, every table present once and in order, every row to fit its columns, and the target to hold no row. In one write transaction it inserts the rows, sets the new restore generation, opens a reconciliation epoch for every account and raises each vault's store-sequence counter.
- The only text column is `auth_accounts.login_name` (at most 254 ASCII bytes, [CRYPTO.md §2](../CRYPTO.md#2-conventions)).

Constraints: the file is untrusted input when read back (CLAUDE.md: size-limited, parsed without panics, fuzzed); the server secrets are never in it ([INV-50](../THREAT_MODEL.md#8-security-invariants)); `backup` runs next to the running server without the writer lock, `restore` takes it on SQLite ([ADR 0010](0010-server-shape.md) §2), and ADR 0010 defines no equivalent for PostgreSQL (§5); [CRYPTO.md §2](../CRYPTO.md#2-conventions) prefers fixed binary layouts to serde encodings for anything that must not drift.

## Decision

### 1. Container layout (format version 1)

Notation as in [CRYPTO.md §2](../CRYPTO.md#2-conventions): big-endian fixed-width integers, `bytes(x) = u32(len(x)) ‖ x`, `str(x) = bytes(UTF-8(x))`. `i64` is two's complement in 8 bytes, big-endian.

```text
file    = header ‖ table{table_count} ‖ digest
header  = magic ‖ u16(format_version) ‖ u64(schema_version) ‖ u64(created_at_ms) ‖ u16(table_count)
magic   = 22 bytes: the 21 ASCII bytes "rizzy-vault-db-backup" followed by one 0x00 byte
          (hex 72697a7a792d7661756c742d64622d6261636b757000; identifies the file and names the format)
table   = str(table_name) ‖ u16(column_count) ‖ column{column_count} ‖ u64(row_count) ‖ row{row_count}
column  = str(column_name) ‖ u8(kind) ‖ u8(nullable)      kind: 1 integer, 2 text, 3 blob; nullable: 0 or 1
row     = value{column_count}
value   = 0x00 (NULL) | 0x01 ‖ i64 | 0x02 ‖ str(text) | 0x03 ‖ bytes(blob)
digest  = SHA-256(every preceding byte of the file)          (32 bytes, the last bytes of the file)
```

- `format_version` is 1. A reader accepts only the versions it implements; a new layout is a new version, decided by an ADR. `schema_version` is the `Dump`'s (the last applied migration), 1 ≤ it ≤ 2^63 − 1. `created_at_ms` is informational and never trusted.
- Tables appear in `TABLES` order, each exactly once, an empty table included (`row_count` 0); `table_count` equals `TABLES.len()`. The column descriptors repeat the schema so that the file documents itself; the reader requires them to equal `TableSpec::columns` exactly (name, kind, nullability, order), and refuses the file otherwise.
- Each value's tag must match its column's kind, or be `0x00` on a nullable column (the rule `check_row` already applies). Text is valid UTF-8.
- The encoding is canonical: one `Dump` has exactly one file apart from `created_at_ms`, so a round-trip test compares bytes.

### 2. Integrity, and what the file does not protect

- The trailing SHA-256 ([CRYPTO.md §2](../CRYPTO.md#2-conventions)) detects truncation and corruption. The reader verifies it over the whole file **before** it parses anything; a mismatch or any byte after the digest refuses the file. The digest is not secret, so an ordinary comparison is fine. `backup` prints the hex digest on stderr so the operator can record it.
- It is **not** authentication: anyone who can write the file can recompute it. A tampered backup is a malicious server database ([A2](../THREAT_MODEL.md#a2-active-malicious-or-compromised-server), A3); clients' signature, rollback and chain checks are the defence, as for any server state.
- **Confidentiality is out of scope.** The database holds only ciphertext, signed statements, hashes, OPAQUE records, sealed TOTP secrets and the clear-text metadata of [THREAT_MODEL §3.4](../THREAT_MODEL.md#34-what-the-server-holds-by-sync-mode); the file holds the same. The server secrets (OPRF seed, AKE keypair, data key) are never in it (INV-50): `rizzy-vault backup-secrets` backs them up to a separate, passphrase-encrypted file ([CRYPTO.md §5.11](../CRYPTO.md#511-server-side-encryption-not-zero-knowledge)). Because a database backup plus the secrets allows offline guessing, the operator guide tells operators to encrypt the file at rest (e.g. `age`) and store it apart from the secrets backup.

### 3. Size limits and strict parsing

- `MAX_BACKUP_FILE_LEN` = 2 GiB for the M1 reader, which holds the file and the `Dump` in memory ("fits M1's personal-scale databases", `backup.rs`). `backup` refuses to write a file longer than the reader's limit, so no backup this release writes is one it cannot restore. Raising the limit, or a streaming reader, is a release change, not a format change.
- Per value: text ≤ 4 KiB; blob ≤ 32 MiB, which must be ≥ every `rizzy-proto` limit on a stored value (a unit test asserts it). Names: 1–63 bytes of `[a-z0-9_]`. `column_count` ≤ 64.
- No allocation is sized by a declared count or length before the bytes are present: every `bytes`/`str` length is checked against its limit and the remaining input first, and `row_count × column_count` must not exceed the remaining bytes (each value is at least one byte) before any row vector is reserved.
- The parser is pure (no I/O), returns an error on every malformed input, and never panics. Errors name the table index, row and column, never a value (INV-48; `Value`'s `Debug` already redacts).
- **Fuzz target** `db_backup_parse`: arbitrary bytes never panic; and for arbitrary `Dump`s within the limits, `parse(write(d)) == d`. A committed known-answer file of a small dump pins the bytes.

### 4. Ownership

The writer and the parser live in `rizzy-storage` (`backup::file`), next to `Dump` and `TABLES` (its [ADR 0016](0016-workspace-layout.md) row: "backup and restore"). The digest uses `sha2` =0.11.0 with `zeroize`, already in the [ADR 0009](0009-crypto-dependency-policy.md) table; no new crate. File creation (mode 0600, `create_new`, never overwriting, removing a partial file on failure) and the commands live in `rizzy-server`'s `admin` module.

### 5. Restore semantics

`rizzy-vault restore`, in this order. Any failure leaves the target with no application row; it may be left migrated to this release's schema, because `Database::restore` runs the migrations before its write transaction (V, `backup.rs` at 1387df9). A retry into that target is allowed (step 1).
1. Exclude every server process, then check the target:
   - **SQLite:** take the writer lock (ADR 0010 §2); the server must be stopped.
   - **PostgreSQL:** ADR 0010 §2 defines only the worker's lock, and a transaction under `READ COMMITTED` does not stop a concurrent signup, nor an `api` replica that keeps serving the old restore generation. This ADR therefore adds the **instance lock**: every `rizzy-vault` process on PostgreSQL, whatever its roles, holds `pg_advisory_lock_shared(K)` on a dedicated connection outside the sqlx pool for its whole life, checked alive as ADR 0010 §2 does for the worker lock, and exits when that connection drops. `restore` (and `migrate`, `secrets rotate`) take `pg_try_advisory_lock(K)` on their own dedicated connection and refuse if any holder remains. `K` is one fixed `i64` chosen by the implementing PR, distinct from the worker lock's key, and documented in `docs/self-hosting.md`. **Until the instance lock is implemented, `restore` refuses a PostgreSQL target** with a usage error (exit 2).
   - The target must be empty: no row in any application table, and either no migration applied or exactly this release's.
2. Read the file (≤ limit), verify magic, `format_version` and digest, then parse it into a `Dump`.
3. Require `schema_version` to equal this release's. An older backup is restored with the release that wrote it, then upgraded with `rizzy-vault migrate`.
4. Load the secrets file and require the dump's `auth_opaque_setups` to match it, as the startup check does ([CRYPTO.md §5.8](../CRYPTO.md#58-loss-or-rotation-of-the-server-opaque-secrets)); otherwise refuse and tell the operator to restore the secrets first.
5. Draw a new restore generation (ADR 0021 §2) from the OS RNG and call `Database::restore`, which in one transaction inserts every row, sets the generation, **opens the reconciliation epoch for every restored account** (INV-59) and raises the store-sequence counters.
6. Print the row count, the number of accounts in reconciliation, and the INV-59 notice with the AR-19 warning: accounts whose devices never reconnect stay rolled back; ask users to open a device.

### 6. Commands

```text
rizzy-vault backup  --out <file|->  [--config <file>]
rizzy-vault restore --in  <file|->  [--config <file>]
```

- `backup` opens the read-only reader on SQLite or a `REPEATABLE READ` transaction on PostgreSQL and takes no writer lock, so it runs next to the server (`docker compose exec`). `-` writes to stdout for piping into `age` or a backup tool; a TTY on stdout is refused. It never writes the secrets.
- `restore` reads `-` from stdin. Exit codes as the other commands: 0, 1 runtime failure, 2 usage or configuration error.
- The same pair moves an instance from SQLite to PostgreSQL (ADR 0011), once the PostgreSQL instance lock of §5 exists.

## Consequences

### Positive
- `restore` exists, and with it the only path that opens INV-59's reconciliation epoch and draws a new restore generation; native restores become the documented fallback for disk loss only.
- The layout reuses CRYPTO.md §2's conventions and the existing `Dump`, so it is small, canonical and easy to fuzz; the self-describing column list catches schema drift.

### Negative
- The M1 reader is in-memory and capped at 2 GiB. A larger instance needs a later release with a streaming reader.
- A backup restores only with the release (schema version) that wrote it.
- Binary, so an operator cannot inspect it with a text editor.

### Risks
- The SHA-256 gives no protection against a deliberate edit. If operators need authenticated or encrypted backups (M8's scheduled backups, ROADMAP §4.2), that is a new format version and an ADR.
- A future table with a very large column (M3 attachments) may exceed the value or file limits: that ADR must revisit §3.

## Alternatives considered

- **JSON lines with base64 blobs.** Readable, but inflates blobs by a third, relies on a serde encoding CRYPTO.md §2 avoids for stable formats, and integers above 2^53 are unsafe in common JSON tooling.
- **The SQLite file itself (`VACUUM INTO`) or `pg_dump` output.** Engine-specific: cannot move SQLite to PostgreSQL, and `restore` would have to parse SQL.
- **CBOR or another schema format.** A new dependency for no gain over a fixed layout.
- **Encrypting the file under an operator passphrase** like `backup-secrets`. Adds a password to lose, and the content is already ciphertext and hashes; deferred to open question 1.
- **Per-table digests or a streaming trailer check.** More code for M1's in-memory reader; the whole-file digest allows streaming later.

## Open questions for the owner

1. **Passphrase encryption of the database backup in M1?** Recommendation: no; document `age` and backup-tool encryption. Revisit with M8's scheduled encrypted backups.
2. **The 2 GiB reader limit.** Recommendation: accept for M1; the attachments ADR (M3) revisits it.
3. **The PostgreSQL instance lock (§5 step 1).** It adds a lock every server process holds, beyond ADR 0010 §2. Alternatives: an owner-run "stop every replica" procedure with no check (unsafe: nothing detects a forgotten replica), or `LOCK TABLE` inside the restore transaction (blocks writers only while it runs, and leaves a live `api` serving the old restore generation afterwards). Recommendation: the advisory lock; PostgreSQL restore stays refused until it lands.
4. **Restoring a backup of an older schema version** (restore with the old release, then `migrate`) versus migrating the dump on restore. Recommendation: refuse, as `Database::restore` does today; migrating dumps needs per-migration dump transforms.

## References

- [ADR 0010](0010-server-shape.md) §2, §4; [ADR 0011](0011-storage.md) "Backups"; [ADR 0016](0016-workspace-layout.md); [ADR 0021](0021-server-compaction.md) §2; [ADR 0022](0022-server-mode-only.md); [ADR 0009](0009-crypto-dependency-policy.md)
- [CRYPTO.md §2](../CRYPTO.md#2-conventions), [§5.8](../CRYPTO.md#58-loss-or-rotation-of-the-server-opaque-secrets), [§5.11](../CRYPTO.md#511-server-side-encryption-not-zero-knowledge)
- [THREAT_MODEL](../THREAT_MODEL.md) §3.4, §5.8, A2, A3, INV-48, INV-50, INV-59, AR-11, AR-19
- `crates/rizzy-storage/src/backup.rs`, `tables.rs` (V, read at 1387df9); `docs/self-hosting.md` §8–§10
