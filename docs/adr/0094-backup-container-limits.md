# ADR 0094: Database backup container limits: a streaming writer and reader, a 1 TiB file cap, and ADR 0007's stale "backup files are JSON" sentence

- Status: Accepted
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M3 (must land before attachments ship; the format_version 2 parts apply from M8)
- Supersedes: [ADR 0023](0023-logical-backup-format.md) §3 (first bullet) and §5 (steps 2, 4 and 5), and [ADR 0007](0007-ciphertext-envelope.md) point 6 (third sub-bullet), each in part, on acceptance. §5 below names each part and gives its full replacement.

## Context

Trigger: the owner's instruction "start" (2026-10-25), given after the [2026-10-25 ADR gap review](../reviews/2026-10-25-adr-gap-review.md), to fix the gaps it found. This ADR answers review rows **D3** (findings G03-6 and G06-3) and **C4** (finding G01-8). Raw findings: [G01](../reviews/2026-10-25-raw/G01.md), [G03](../reviews/2026-10-25-raw/G03.md), [G06](../reviews/2026-10-25-raw/G06.md).

ROADMAP rows: "Backup & restore command + documented procedure (tested, not just written)" (Must, M1); "Attachments (encrypted, size-limited)" (Should, M3); "Scheduled encrypted backups to user-chosen storage" (Should, M8).

### D3: one account can make `backup` refuse to run

- [ADR 0023](0023-logical-backup-format.md) §3, first bullet (binding): "`MAX_BACKUP_FILE_LEN` = 2 GiB for the M1 reader, which holds the file and the `Dump` in memory … `backup` refuses to write a file longer than the reader's limit, so no backup this release writes is one it cannot restore. Raising the limit, or a streaming reader, is a release change, not a format change."
- ADR 0023 Risks: "A future table with a very large column (M3 attachments) may exceed the value or file limits: that ADR must revisit §3." Open question 2: "**The 2 GiB reader limit.** Recommendation: accept for M1; the attachments ADR (M3) revisits it."
- [ADR 0054](0054-attachments-envelope-and-api.md) (Accepted) stores attachment bytes as database rows (`vault_attachment_chunks(attachment_id, chunk_index, chunk_envelope BLOB, …)`, 512 KiB chunks, `MAX_ATTACHMENT_LEN` 25 MiB). Its Consequences, "Backup growth": "the logical-backup dump … now scales with total attachment bytes … Accepted for M3; revisit before M8 if dump size or restore time proves unacceptable." It does not revisit ADR 0023 §3.
- [ADR 0048](0048-per-account-storage-quota.md) (Accepted) sets the per-account quota; [self-hosting.md](../self-hosting.md) documents `RIZZY_ACCOUNT_QUOTA_BYTES` default `5368709120` (5 GiB), "no maximum".
- So one account at the default quota can push the whole instance's dump past 2 GiB, after which `backup` refuses to write anything. G03-6: "That disables the only restore path that opens INV-59's reconciliation epoch." G06-3 says the same, rated major.
- Code at `1869179`: `crates/rizzy-storage/src/backup/file.rs:84` `pub const MAX_BACKUP_FILE_LEN: usize = 2 * 1024 * 1024 * 1024;` (doc comment l.39: "2 GiB, for this in-memory reader"); `crates/rizzy-server/src/db_backup.rs:84` `pub const CHUNK_LEN: usize = 8 * 1024 * 1024;`, l.169 `"encrypted backup exceeds the 2 GiB file limit"`; `crates/rizzy-server/src/admin.rs:1163–1167` builds the whole `Dump`, then the whole file, in memory (`db.dump().await`, `backup_file::write(&dump, …)`); `crates/rizzy-storage/src/backup.rs:393` reads each table with `fetch_all`. (V: files read.)
- [ADR 0071](0071-encrypted-db-backup-format.md) format_version 2 (Accepted): header `… ‖ u64(plaintext_len) ‖ u32(chunk_count) ‖ chunk{chunk_count}`, `chunk_count = ceil(plaintext_len / CHUNK_LEN)`, `CHUNK_LEN` = 8 MiB, and "**Size.** `MAX_BACKUP_FILE_LEN` (ADR 0023 §3) caps the format_version 2 file, not the payload". Neither format has a structural limit near 2 GiB: format_version 1 uses `u32` value lengths and `u64` row counts; `u32(chunk_count)` × 8 MiB is 32 PiB. The 2 GiB cap is purely the in-memory reader's, as ADR 0023 says.

### C4: ADR 0007 point 6 still says backup files are JSON

- [ADR 0007](0007-ciphertext-envelope.md) point 6, third sub-bullet (binding, un-superseded): "Export and backup files are JSON, with the envelope in a `data` field."
- ADR 0023 §1's format_version 1 (`header = magic ‖ u16(format_version) ‖ …`, no envelope) and ADR 0071's format_version 2 ("a binary container (below), not JSON") are binary. ADR 0071 changed only CRYPTO.md ("Not ADR supersession"), and [ADR 0020](0020-partial-supersession.md) point 9 says nothing is superseded by implication. G01-8: "a reviewer holding code to 0007 finds a violation." [CRYPTO.md §9.6](../CRYPTO.md#96-encoding-for-transport-and-storage) has since been fixed (it now states both binary formats and points to the 0007 conflict in [the errata candidates](../reviews/2026-10-25-errata-candidates.md)); ADR 0007 itself still needs the supersession.

### Constraints

- ADR 0020 point 9: the smallest supersedable part is a whole sentence (here, whole bullets and whole steps); each replacement is written out in full.
- [ADR 0083](0083-db-backup-plaintext-len-erratum.md) (Proposed) supersedes two sentences of ADR 0071's "Container (format_version 2)" subsection. **This ADR supersedes nothing in ADR 0071**, so it cannot overlap ADR 0083; it changes only the value behind the name `MAX_BACKUP_FILE_LEN`, which ADR 0071 and ADR 0083 use by name.
- [ADR 0072](0072-remote-backup-destinations.md) (Proposed) caps the scheduled in-server upload at `RIZZY_BACKUP_UPLOAD_MAX_MIB` (default 512, at most 2048, "ADR 0023 §3's own cap"). This ADR decides nothing for ADR 0072; see On acceptance item 6.
- Threat model: [A1](../THREAT_MODEL.md#a1-passive-server-compromise-db-or-backup-theft) (backup theft), [A2](../THREAT_MODEL.md#a2-active-malicious-or-compromised-server) (a tampered backup is a malicious database), INV-48 (errors never carry values), INV-50 (no server secrets in a DB backup), INV-59 (restore opens the reconciliation epoch). None of these changes.

## Decision

### 1. Limits

| Name | Value | Owner | Applies to |
|---|---|---|---|
| `MAX_BACKUP_FILE_LEN` | 2^40 bytes (1 TiB), type `u64` | `rizzy-storage` `backup::file` | Every database backup file this release writes, and every one it reads from a regular file, format_version 1 or 2. For format_version 2 it caps the whole file, as ADR 0071 "Size" says; ADR 0083's `plaintext_len ≤ MAX_BACKUP_FILE_LEN` check uses the same constant. |
| `MAX_IN_MEMORY_BACKUP_LEN` | 2^31 bytes (2 GiB, today's value), type `usize` | `rizzy-storage` `backup::file` | A backup read from stdin (`--in -`) or from a path that is not a regular file; the in-memory `parse(&[u8])` wrapper; the fuzz target. |
| `CHUNK_LEN` | 8 MiB, unchanged (ADR 0071, owner answer 5 of 2026-10-22) | `rizzy-server` `db_backup` | format_version 2. |
| `chunk_count` | derived, ≤ 2^40 / 2^23 = 131 072; still `u32` | — | format_version 2. |
| Per-value, name and column limits | unchanged (ADR 0023 §3: text ≤ 4 KiB, blob ≤ 32 MiB, names 1–63 bytes, ≤ 64 columns) | `backup::file` | both formats. |

- **No format change.** format_version 1 and format_version 2 bytes are exactly as ADR 0023 §1 and ADR 0071 define them; there is no new `format_version`. A file of at most 2 GiB written by an earlier release reads unchanged; a file between 2 GiB and 1 TiB written by this release is refused by an earlier release with its existing `TooLarge` error, which is the expected downgrade behaviour (ADR 0023 §5 step 3 already ties a backup to its schema version).
- `MAX_BACKUP_FILE_LEN` becomes `u64` because 1 TiB does not fit a 32-bit `usize`; every comparison with a file length or `plaintext_len` is made in `u64` with checked arithmetic.
- Raising either limit later is a release change, not a format change (as ADR 0023 §3 already says).

### 2. The writer streams, in two passes over one snapshot

`rizzy-vault backup` must not hold the file, the `Dump` or a whole table in memory. In the one read transaction `dump` already uses (the read-only reader on SQLite, one `REPEATABLE READ` transaction on PostgreSQL; ADR 0023 §6), it makes two passes over the same tables in `TABLES` order, rows fetched as a stream (`fetch`, never `fetch_all`) with the existing `select` queries and their order:

1. **Pass 1 (sizing).** Every row goes through the format_version 1 encoder into a counting sink that discards the bytes. Pass 1 records each table's `row_count` and the format_version 1 length `L1` (header, tables and the 32-byte digest). The output length is `L = L1` for format_version 1, or `L = sealed_len(L1) = 64 + L1 + 90 × ceil(L1 / CHUNK_LEN)` for format_version 2 (ADR 0071 "Size"; the 64-byte header as ADR 0083 describes it). If `L > MAX_BACKUP_FILE_LEN`, `backup` refuses with `BackupTooLarge` (§4) **before** it creates the output file or writes a byte to stdout.
2. **Pass 2 (writing).** The same encoder writes the header and each table with pass 1's `row_count`, streams every value, feeds every format_version 1 byte to SHA-256 and writes the digest last. For format_version 2 the format_version 1 bytes are cut into `CHUNK_LEN` plaintext chunks, each sealed as ADR 0071 specifies (algorithm `0x01`, ADR 0071's ctx, `plaintext_len = L1`, `chunk_count = ceil(L1 / CHUNK_LEN)`) and written as soon as it is sealed.
3. At the end of pass 2 the writer requires every table's streamed row count to equal pass 1's and the bytes written to equal `L`. A difference means the two passes did not see one snapshot, which is a bug: `backup` fails with `SnapshotChanged` (§4), removes the partial file (file output) and exits 1.

Memory bound: the writer holds at most one row, one `CHUNK_LEN` plaintext buffer, one sealed chunk and the hash state; nothing grows with the file. The encoder is the existing canonical encoder: for any `Dump` within the limits the streamed bytes must equal today's `write(&dump, created_at_ms)` byte for byte (ADR 0023 §1 "canonical"), so the committed known-answer file and the committed `db_backup.json` vectors of ADRs 0071 and 0083 stay valid.

Crash and retry: file creation stays as ADR 0023 §4 says (mode 0600, `create_new`, never overwriting, the partial file removed on a reported failure). A process killed during pass 2 can leave a partial file; it cannot be restored (its length or digest fails pass 1 of §3), and the next `backup` to the same path is refused by `create_new` until the operator deletes it. To stdout, a failure after the first byte leaves an incomplete stream, and `backup` says so (§4).

### 3. The reader streams, in two passes over one open file

`rizzy-vault restore --in <path>`, where `<path>` is a regular file, opens it **once** and uses that one handle for both passes (`seek` to the start between them), so renaming or replacing the path between the passes has no effect.

1. **Pass 1 (verify; no parsing, no transaction).** Read the length from the open handle's metadata and refuse if it exceeds `MAX_BACKUP_FILE_LEN` (`TooLarge`). Check the magic and `format_version`.
   - format_version 1: stream every byte before the last 32 through SHA-256 and compare with the last 32 bytes (ADR 0023 §2: verified over the whole file before anything is parsed).
   - format_version 2: apply the header checks of ADR 0071 (and of ADR 0083, if accepted: exact framing, `chunk_count`, exact file length) before any crypto, then open every chunk in order, streaming the plaintext through SHA-256 and discarding it, and compare with the format_version 1 digest at the end of the plaintext. This is ADR 0071's "opens every chunk, refuses on any commitment or AEAD failure", done without holding the reassembled bytes.
   - Pass 1 keeps only the format_version 1 header (42 bytes: magic, `format_version`, `schema_version`, `created_at_ms`, `table_count`), the digest, and for format_version 2 the 64-byte container header.
2. **ADR 0023 §5 step 3** (schema version) runs on the kept header, before any transaction.
3. **Pass 2 (parse and insert, in one transaction).** Rewind and stream the same bytes again (format_version 2: reopen every chunk) into a **sans-I/O incremental decoder** in `backup::file`: the caller hands it buffers of any size; it yields the header, each table's descriptor, each row and the digest; it holds at most one row and one partial value. Every rule in ADR 0023 §3's other bullets applies unchanged; "the remaining input" is the length known from pass 1 minus the bytes consumed. Each row is inserted as it is decoded, inside `Database::restore`'s one write transaction. The decoder does no I/O (the caller reads), so ADR 0023 §3's "The parser is pure (no I/O)" still holds.
4. Before commit, pass 2 requires the header bytes it read to equal pass 1's (both headers for format_version 2) and its recomputed digest to equal pass 1's. A difference means the file changed between the passes: `FileChanged` (§4), rollback.
5. Any error in pass 2 rolls the whole transaction back, so ADR 0023 §5's "Any failure leaves the target with no application row" holds, and a retry into that target is allowed as today (ADR 0023 §5 step 1).

**Stdin and non-regular paths.** `--in -`, or a path whose metadata is not a regular file (a FIFO, `/dev/stdin`, a character device), cannot be read twice. It is read into memory, at most `MAX_IN_MEMORY_BACKUP_LEN` bytes: one more byte refuses with `StdinTooLarge` (§4) before anything is parsed. The in-memory bytes then go through the same two passes, from memory. This is today's behaviour at today's limit.

Memory bound for a file restore: one read buffer (at most `CHUNK_LEN` plus one sealed chunk for format_version 2), one row, the hash state, and what the database driver holds for its open transaction.

### 4. What the CLI says

Every error goes to stderr, names sizes in bytes and never a value (INV-48). Exit codes are ADR 0023 §6's (0 success, 1 runtime failure, 2 usage or configuration error).

| Condition | Detected | Message (exact text; `{…}` are decimal numbers) | Exit |
|---|---|---|---|
| `BackupTooLarge` | `backup`, end of pass 1, before any output | `error: this backup would be {L} bytes, over this release's limit of 1099511627776 bytes (1 TiB); nothing was written. Use the database's native backup until a later release raises the limit.` | 1 |
| `SnapshotChanged` | `backup`, end of pass 2 | `error: the database changed during the backup snapshot; the partial file was removed.` To stdout the last clause reads `the output is incomplete and must be discarded.` | 1 |
| Note: too large for stdin | `backup`, after success, if `L > 2147483648` | `note: this backup is {L} bytes; restore it from a file (--in <file>): restore reads at most 2147483648 bytes from stdin.` | 0 |
| Warning: near the limit | `backup`, after success, if `L ≥ 824633720832` (75 % of the limit) | `warning: this backup is {L} bytes, {P}% of this release's limit of 1099511627776 bytes.` (`P = floor(100 × L / limit)`) | 0 |
| `TooLarge` | `restore`, pass 1, file length | `error: the backup file is {N} bytes, over this release's limit of 1099511627776 bytes.` | 1 |
| `StdinTooLarge` | `restore`, reading stdin or a non-regular path | `error: restore reads at most 2147483648 bytes from stdin or a pipe; save the backup to a file and pass --in <file>.` | 1 |
| `FileChanged` | `restore`, end of pass 2 | `error: the backup file changed while it was being restored; nothing was restored.` | 1 |

The `backup` success output that prints the hex digest (ADR 0023 §2) also prints `L`. The existing messages that say "2 GiB" (`db_backup.rs:169`, `file.rs:259`) are replaced by the texts above.

**The server says nothing.** `rizzy-vault serve` does not estimate the dump size and refuses no writes because of it: `backup` is the only place that knows the exact size, and ADR 0048's quota counters do not cover op logs and the other tables (open question 3).

### 5. What this ADR supersedes

Three Accepted parts, each named exactly and replaced in full (ADR 0020 point 9). Everything else in ADRs 0007, 0023 and 0071 stays binding, including all of ADR 0023 §2, the other three bullets of §3, §5 steps 1, 3 and 6, and all of ADR 0071 (and so everything ADR 0083 touches).

**(a) [ADR 0023](0023-logical-backup-format.md) §3, the first bullet (all three sentences, beginning "`MAX_BACKUP_FILE_LEN` = 2 GiB for the M1 reader").** Replacement, complete in itself:

> - `MAX_BACKUP_FILE_LEN` = 2^40 bytes (1 TiB, a `u64`) caps every database backup file this release writes, and every one it reads from a regular file, format_version 1 or 2 ([ADR 0094](0094-backup-container-limits.md) §1). The writer and the reader stream, in two passes each, and neither holds the file, the `Dump` or a table in memory (ADR 0094 §2–§3). `backup` measures the file before it writes a byte and refuses one longer than this limit, so no backup this release writes is one it cannot restore from a file. A backup read from stdin or from a path that is not a regular file is held in memory and capped at `MAX_IN_MEMORY_BACKUP_LEN` = 2^31 bytes (2 GiB). Raising either limit is a release change, not a format change.

**(b) [ADR 0023](0023-logical-backup-format.md) §5, steps 2, 4 and 5 (each whole step).** Replacements, complete in themselves, keeping the step numbers:

> 2. Verify the file without parsing it (pass 1 of [ADR 0094](0094-backup-container-limits.md) §3): from a regular file, through one open handle used for both passes, check its length (≤ `MAX_BACKUP_FILE_LEN`), magic and `format_version`, then stream it through SHA-256 (format_version 1), or open every chunk and stream the reassembled format_version 1 bytes through SHA-256 (format_version 2, [ADR 0071](0071-encrypted-db-backup-format.md)), and compare the digest. From stdin or a path that is not a regular file, first read at most `MAX_IN_MEMORY_BACKUP_LEN` bytes into memory, then do the same. Nothing beyond the fixed header is parsed, and no transaction is opened, until the digest has matched.

> 4. Load the secrets file before step 5 opens its transaction. The dump's `auth_opaque_setups` must match it, as the startup check requires ([CRYPTO.md §5.8](../CRYPTO.md#58-loss-or-rotation-of-the-server-opaque-secrets)); the comparison runs inside step 5's transaction as soon as that table has been parsed and before any later table is read, and a mismatch rolls the transaction back and tells the operator to restore the secrets first.

> 5. Draw a new restore generation (ADR 0021 §2) from the OS RNG and call `Database::restore` with a streaming source over the same bytes from the start (pass 2 of ADR 0094 §3). In one transaction it parses the file again with the strict parser of §3, inserts each row as it is parsed, makes step 4's comparison, requires the header bytes and the recomputed digest to equal pass 1's, sets the generation, **opens the reconciliation epoch for every restored account** (INV-59) and raises the store-sequence counters, and only then commits. Any failure, including a file that changed between the passes, rolls the whole transaction back.

**(c) [ADR 0007](0007-ciphertext-envelope.md) point 6, the third sub-bullet ("Export and backup files are JSON, with the envelope in a `data` field.").** Replacement, complete in itself:

> - Export files and the server-secrets backup are JSON, with the envelope in a `data` field. Database backups written by `rizzy-vault backup` are not JSON: they are the binary containers of [ADR 0023](0023-logical-backup-format.md) (format_version 1, no envelope) and [ADR 0071](0071-encrypted-db-backup-format.md) (format_version 2, chunked `0x01` envelopes).

Nothing in ADR 0054 is superseded: its "Backup growth" consequence is answered here, not changed. Nothing in ADR 0048 is superseded: the quota default and its "no maximum" stay.

### 6. Ownership and tests

- `rizzy-storage` `backup::file`: the constants, the streaming encoder (generic over a byte sink, with a counting sink), the sans-I/O decoder, and `write`/`parse` kept as thin wrappers over them, so the fuzz target exercises the streaming code. `rizzy-storage` `backup`: `Database::dump` becomes the two-pass streaming writer; `Database::restore` takes a streaming source and a pre-commit check hook. `rizzy-server` `db_backup`: streaming seal and open of format_version 2 chunks with the unchanged `0x01` construction from `rizzy-core`. `rizzy-server` `admin`: the commands, the stdin path and the messages of §4. No new crate (`sha2` already hashes incrementally); no crate-boundary change.
- Tests, each required before the change merges:
  1. `stream_write_equals_write`: property test; for arbitrary `Dump`s within the limits, the streamed bytes equal `write()`'s. The committed known-answer file still matches.
  2. `decoder_split_invariance`: property test; any split of a valid file into feed buffers gives the same `Dump`, and any split of an invalid file the same error.
  3. Fuzz target `db_backup_parse` drives the decoder with arbitrary bytes at arbitrary split points and never panics. The committed `db_backup.json` vectors replay unchanged (`committed_vectors_replay`).
  4. Limit tests through test-only `*_with(limits)` entry points (the pattern of `sealed_len_with` in `db_backup.rs`): with the file limit set to 64 KiB, `backup` of a larger dump refuses with `BackupTooLarge`, creates no file and writes nothing to stdout; `restore` of a file one byte over refuses with `TooLarge`; with the in-memory limit lowered, a stdin restore over it refuses with `StdinTooLarge`.
  5. `restore_file_changed_between_passes` (SQLite and PostgreSQL): a test hook flips one byte after pass 1; restore fails with `FileChanged` and the target has no application row. The same for an `auth_opaque_setups` mismatch.
  6. `backup_restore_over_2gib` (`#[ignore]`, Linux; run by hand before the M3 attachments release, result recorded in the PR): a SQLite instance holding about 2.5 GiB of attachment rows round-trips through `backup` and `restore` in both formats, with peak RSS (`VmHWM` in `/proc/self/status`) under 512 MiB.

## Consequences

### Positive
- One account at the default quota, or a whole instance up to 1 TiB of rows, no longer stops `backup`; INV-59's restore path stays available as attachments grow.
- Memory use of `backup` and `restore` no longer grows with the database, which also removes today's peak of roughly twice the file size.
- No format change: existing files, vectors and the known-answer file stay valid; ADRs 0071 and 0083 need no edit.
- ADR 0007 point 6 stops contradicting ADRs 0023 and 0071 (review C4).

### Negative
- Two passes: `backup` reads every table twice and `restore` reads (format_version 2: decrypts) the file twice, roughly doubling the I/O and, for format_version 2, the AEAD work. Chosen over holding data in memory or writing plaintext temporary files.
- `backup` keeps one read snapshot open for both passes; on SQLite a long read transaction keeps WAL checkpoints from completing until it ends (already true today, for one pass).
- `restore` inserts up to 1 TiB in one write transaction; the SQLite journal or the PostgreSQL WAL grows to match, so operators need that much free disk, and self-hosting.md must say so.
- A backup larger than 2 GiB cannot be piped into `restore`; it must be saved to a file first. `backup --out - | age …` still works; decrypt to a file before restoring.

### Risks
- An instance past 1 TiB of database rows is refused by `backup` and falls back to native backups, which do not open INV-59's epoch. Signal to revisit: any operator report of the 75 % warning.
- A slow, very large restore may exceed operators' maintenance windows. Signal: the M8 restore-drill timings (ROADMAP M8, "backup/restore drills").
- If ADR 0072 is accepted with its in-memory 2 GiB maximum, scheduled backups stop at a smaller size than manual ones (On acceptance item 6).

## Alternatives considered
- **Raise the cap but keep the in-memory reader.** A 16 GiB cap would need 16–32 GiB of RAM on the host during backup. Rejected: self-hosters run small machines.
- **Multi-file backups (one file per table, or per N GiB).** Needs a new `format_version` and a manifest binding the parts, and changes how operators copy and verify backups. Rejected: streaming reaches the same sizes with no format change.
- **Spool to a temporary file** (writer: compute the length afterwards; reader: copy stdin to disk for two passes). For format_version 2 this writes decrypted backup bytes to disk, undoing ADR 0071's purpose. Rejected.
- **Size pass in SQL** (`SUM(length(col))`). SQLite's `length()` counts characters for text, PostgreSQL needs `octet_length`, and the per-value framing must be added by hand: two engines and one more place to get the canonical length wrong. Rejected for a pass through the real encoder.
- **Single-pass streaming restore that checks the digest at the end and rolls back.** Saves a pass and would allow streaming stdin, but parses and inserts unverified bytes, contrary to ADR 0023 §2's "verifies it over the whole file before it parses anything". Rejected for files; offered for stdin only, as open question 2.
- **Cap the sum of all quotas below the backup limit, or refuse writes that would make the dump unrestorable** (G03-6's other suggestions). Couples every write path to a whole-instance estimate that does not match the dump size. Rejected.
- **No cap beyond `u64`.** No bound on restore time or on a corrupted `plaintext_len`. Rejected for a large explicit cap (open question 1).

## Open questions for the owner
1. **The file cap.** 1 TiB (2^40) as decided above, 256 GiB, or no cap beyond `u64`? *Recommendation:* 1 TiB: about 200 accounts at the 5 GiB default quota, and still a bound on a corrupted length.
2. **Stdin restore.** Keep stdin and pipes in memory at 2 GiB, as decided, or allow a single-pass streaming restore from stdin that checks the digest at the end and rolls back on a mismatch? *Recommendation:* keep the 2 GiB in-memory path; ADR 0023 §2's verify-before-parse rule is worth more than piping very large backups.
3. **A server-side warning.** Should `rizzy-vault serve` log a warning when the sum of ADR 0048's usage counters passes 75 % of `MAX_BACKUP_FILE_LEN`? *Recommendation:* no: it is an estimate that omits op logs and other tables, and `backup`'s exact warning (§4) reaches the operator who runs backups.

## On acceptance

Edits made when the owner accepts this ADR, not now:
1. **Status lines (the owner's act).** ADR 0023 → `Partially superseded by [ADR 0071](0071-encrypted-db-backup-format.md) (§2 in part); [ADR 0094](0094-backup-container-limits.md) (§3 in part, §5 in part)`. ADR 0007 → `Partially superseded by [ADR 0054](0054-attachments-envelope-and-api.md) (§3 in part); [ADR 0094](0094-backup-container-limits.md) (§6 in part)` (ADR 0007's points are numbered; "§6" follows the form its status line already uses for point 3). The README rows of 0007, 0023 and 0094 mirror them; CLAUDE.md's list of Accepted ADRs gains 0094.
2. **CRYPTO.md §9.6** (the "Files" bullet, l.809): drop the parenthetical about ADR 0007 point 6's conflict. **§9.8 "Size"** (l.830): name the value, "`MAX_BACKUP_FILE_LEN` (1 TiB, ADR 0094)".
3. **self-hosting.md §8**: l.376 "At most 2 GiB … reads the whole file into memory" → at most 1 TiB, streamed; a backup over 2 GiB restores only from a file, not from stdin; restore needs free disk for one transaction of the backup's size. l.409 and l.456: the 2 GiB figures → 1 TiB (stdin: 2 GiB). Document the messages of §4.
4. **Errata candidates** ([2026-10-25-errata-candidates.md](../reviews/2026-10-25-errata-candidates.md)): mark the ADR 0007 point 6 row as resolved by ADR 0094.
5. **THREAT_MODEL.md**: where INV-59's "Verified by" names the restore tests, add test 6 of §6 (`backup_restore_over_2gib`). (U: that cell's current wording was not read for this draft.)
6. **ADR 0072** (Proposed): its "2048 (2 GiB, ADR 0023 §3's own cap)" parenthetical becomes stale; its own track updates it, and may adopt §2's streaming writer for scheduled runs. Not edited by this ADR.

## Implementation plan
1. `rizzy-storage`: the constants (§1), the streaming encoder and decoder with the `write`/`parse` wrappers; tests 1–3; the fuzz target updated.
2. `rizzy-storage`: two-pass `Database::dump` over `fetch` streams, and streaming `Database::restore` with the pre-commit hook; SQLite and PostgreSQL tests (test 5).
3. `rizzy-server` `db_backup`: streaming seal and open; the committed vectors replay unchanged.
4. `rizzy-server` `admin`: wiring, the stdin path, messages and exit codes (§4); test 4.
5. Test 6 run by hand and recorded; On acceptance items 2–3 made in the same change as the code (ADR 0020 point 7).

## References
- [ADR 0007](0007-ciphertext-envelope.md) point 6; [ADR 0020](0020-partial-supersession.md) points 7 and 9; [ADR 0023](0023-logical-backup-format.md) §1–§6, Risks, open question 2; [ADR 0048](0048-per-account-storage-quota.md); [ADR 0054](0054-attachments-envelope-and-api.md) Decision 5 and "Backup growth"; [ADR 0071](0071-encrypted-db-backup-format.md) "Container", "Ordering and completeness", "Size", commands; [ADR 0072](0072-remote-backup-destinations.md) (Proposed); [ADR 0083](0083-db-backup-plaintext-len-erratum.md) (Proposed).
- [Gap review](../reviews/2026-10-25-adr-gap-review.md) rows C4 and D3; raw findings G01-8, G03-6, G06-3.
- [CRYPTO.md §9.6](../CRYPTO.md#96-encoding-for-transport-and-storage), [§9.8](../CRYPTO.md#98-chunked-db-backup-format_version-2-m8); [THREAT_MODEL.md](../THREAT_MODEL.md) INV-48, INV-50, INV-59; [self-hosting.md §8](../self-hosting.md).
- Code at `1869179`: `crates/rizzy-storage/src/backup/file.rs`, `crates/rizzy-storage/src/backup.rs`, `crates/rizzy-server/src/db_backup.rs`, `crates/rizzy-server/src/admin.rs` (V).
