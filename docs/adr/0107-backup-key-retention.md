# ADR 0107: Backup-key retention: keys are kept until an explicit, evidence-gated `secrets backup-key retire`

- Status: Proposed
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M8

## Context

[ROADMAP §4.2](../ROADMAP.md#42-core-vault-m1), row "Scheduled encrypted backups to user-chosen storage (local folder, WebDAV, S3-compatible)" (Should, M8). Trigger: the owner's instruction "start" (2026-10-25), given after the [2026-10-25 ADR gap review](../reviews/2026-10-25-adr-gap-review.md), whose item **M10** reads: "**Backup-key retention.** 0071 answer 3 defers it to Proposed 0072, which never prunes." Raw findings: [G07-27 and G07-31](../reviews/2026-10-25-raw/G07.md).

**The gap, quoted.**
- [ADR 0071](0071-encrypted-db-backup-format.md) (Accepted) "Owner answers at acceptance" 3: "Old `backup_keys` entries are not dropped automatically: retention depends on ADR 0072's still-undecided off-site retention."
- [ADR 0072](0072-remote-backup-destinations.md) (Proposed) §2: "**Retention.** This job never prunes. Every upload stays until something else removes it: an operator cron, `webdav`/`s3`'s own lifecycle rule, or a manual `find`/delete for `local`."
- G07-27: "Nothing says when an old `backup_key_id` may be removed, how (`secrets rotate --backup-key` only adds keys), or what restore does when a header names a removed id. Dropping a key by hand silently strands every backup sealed under it, and keeping them all forever is the only safe reading today." Suggested resolution: "a retire command that refuses while any retained backup … names the id. Restore of an unknown `backup_key_id` gets a distinct error … never a generic AEAD failure."
- G07-31: "Accepted 0071 hands backup-key retention to 0072, and 0072 declares retention out of its job. Neither text says which `backup_key_id` values must stay in the secrets file."

So the key lifecycle of an Accepted mechanism has no owner. Today a key can only be removed by hand-editing `secrets.json`. The docs never describe that, and it orphans backups with no warning.

**What exists (code read this session, V).**
- `crates/rizzy-domain-auth/src/secrets.rs`: `backup_keys: BTreeMap<u32, ServerDbBackupKey>`, `current_backup_key_id: Option<u32>` ("`Some` exactly when `backup_keys` is not empty"). `rotate_backup_key` draws id = (highest held id) + 1, or 1 when none. It refuses on `IdOverflow` and on `BackupKeyReused` (INV-98), and otherwise inserts the key and marks it current. No method removes a backup key. `generate_after_loss` carries `backup_keys` forward on a setup-only loss and starts with none on a whole loss.
- `crates/rizzy-server/src/secrets_file.rs`: the ADR 0028 item 13 layout as ADR 0071 replaced it. `backup_keys` and `current_backup_key_id` are written only when a current key exists. File cap `MAX_SECRETS_FILE_LEN` = 256 KiB. No cap on the number of backup keys.
- `crates/rizzy-server/src/admin.rs`: `secrets rotate --backup-key` is exclusive. On `SQLite` it takes only the writer lock and does not open the database. On `PostgreSQL` it opens the database and takes the instance lock (`open_exclusive`). The file is written with `fsutil::replace_private`, which is atomic: the old file or the new one, never a mix. `restore` opens a format_version 2 file with `db_backup::open(|id| secrets.backup_key(id), …)` before it touches the target database. `AdminError::is_usage` separates exit code 2 (usage or configuration) from exit code 1 (runtime failure).
- `crates/rizzy-server/src/db_backup.rs`: header `MAGIC(22) ‖ u16 format_version ‖ backup_id(16) ‖ u64 created_at_ms ‖ u32 backup_key_id ‖ u64 plaintext_len ‖ u32 chunk_count`, big-endian, `HEADER_LEN` = 64. `DbBackupError::UnknownBackupKey { backup_key_id }` already exists and prints "encrypted backup is sealed under backup key {backup_key_id}, which the secrets file does not hold". The lookup runs after the framing checks and before any chunk is decrypted (module docs). So the code already avoids a generic AEAD error for a missing key, but no Accepted text requires it: ADR 0071 "Commands and restore" says only "refuses on any commitment or AEAD failure".
- `crates/rizzy-server/src/cli.rs`: the rotate message already says "the older backup keys stay so their backups remain restorable".
- [ADR 0047](0047-opaque-secrets-operator-commands.md) (Accepted): `secrets restore` replaces the whole secrets file with a backup's content (step 5). A secrets backup taken before a `rotate --backup-key` lacks the newer key, so restoring it silently drops that key. That is a second orphaning path, and no text mentions it. ADR 0047 step 4 already reports (never blocks) setups that the database names but the backup lacks. It says nothing about backup keys.

**Facts that shape the design.**
- A key that is not current never seals a new backup. So once a key stops being current, the set of backups that need it is closed. Only `backup --encrypt` and the ADR 0072 job seal, and both use `current_backup_key_id`.
- The server cannot list every backup it ever wrote. Manual `backup --out` files can go anywhere, ADR 0072 destinations are Proposed, and lifecycle rules delete objects without the server knowing. The only reliable evidence is each backup file's own header, which holds the key id in the clear at offset 48.
- Retiring a key from the live secrets file does not erase it: every earlier `backup-secrets` snapshot still holds it (ADR 0011 "store the secrets backup apart").

Threat model: [A1](../THREAT_MODEL.md#a1-passive-server-compromise-db-or-backup-theft) (off-site copies). [INV-98](../THREAT_MODEL.md#8-security-invariants) (backup key only in the secrets file) is unchanged. The failure this ADR prevents is a loss of availability: a backup that can no longer be restored.

## Decision

### 1. Retention rule

1. A backup key stays in the secrets file until an operator retires it with `rizzy-vault secrets backup-key retire` (§3). Nothing else removes one: not `secrets rotate`, not `--data-key`'s `drop_unused_data_keys`, not the worker, not the ADR 0072 job. No future pruning setting may remove one either, unless a later ADR routes it through §3's checks.
2. The current key can never be retired. `rotate_backup_key` always makes the new highest id current, so retiring never removes the highest id. As a result `backup_keys` never becomes empty once it has a key, and rotation never reuses an id.
3. **Proposed INV-121** (provisional; renumbered at acceptance if taken): *A backup key leaves the secrets file only through `secrets backup-key retire --confirm`, never while it is current, and only after a header scan of every operator-named path, made while every server process is shut out, has found no format_version 2 backup naming it.*
4. **Cap.** At most `MAX_BACKUP_KEYS` = 256 backup keys are held. `rotate --backup-key` with 256 keys held refuses with `BackupKeyLimit` (exit 1) and leaves the file unchanged: "the secrets file already holds 256 backup keys; retire unused ones first (`rizzy-vault secrets backup-key retire`)". 256 entries are about 19 KiB of JSON (about 75 bytes each, U: estimated from the layout, not measured), well inside the 256 KiB file cap. This adds a refusal that ADR 0071 does not rule out, so it supersedes nothing there.

### 2. Command group `rizzy-vault secrets backup-key`

Flags follow the existing grammar: unknown flags, repeated single-use flags and missing values are usage errors (exit 2, ADR 0047 owner answer 3). Every subcommand takes `[--config <file>]`. No subcommand ever prints key bytes.

**`secrets backup-key list`**: reads the secrets file only. It takes no lock (like `backup-secrets`) and opens no database. It prints one line per held key in ascending id order, exactly `backup_key <id> current` or `backup_key <id> retained`, and exits 0. With no backup key it prints `no backup keys` and exits 0. A missing or unparsable secrets file is the existing configuration error (exit 2).

**`secrets backup-key rotate`**: the same code path as `secrets rotate --backup-key`, plus §1.4's cap. That command stays, unchanged apart from the cap. Same lock, same message.

**`secrets backup-key retire <id> --scan <path> [--scan <path>]… [--confirm]`**: see §3.

### 3. `secrets backup-key retire`

**Arguments.** `<id>` must be a decimal `u32`; anything else is a usage error. `--scan` is required at least once and allowed at most 16 times; otherwise it is usage error `ScanArguments`. Each `<path>` is a regular file or a directory.

**Step 1: check the id (no lock).** Load the secrets file. Refuse with exit 2 if:
- `BackupKeyNotHeld`: "backup key {id} is not in the secrets file (already retired, or never added); `rizzy-vault secrets backup-key list` shows the held ids";
- `BackupKeyCurrent`: "backup key {id} is current; run `rizzy-vault secrets backup-key rotate` first, then retire it".

**Step 2: scan.** Each `--scan` path is handled in the order given:
- A file path is examined. For a directory, each entry is examined, **non-recursively**. Each entry is checked with `symlink_metadata`, and only regular files are examined. Symbolic links, subdirectories and other kinds are skipped and counted, never followed.
- At most `MAX_SCAN_ENTRIES` = 100 000 entries in total, across all paths. One more entry refuses with `ScanTooLarge` (exit 1, nothing changed): "more than 100000 entries under the scanned paths; scan a narrower directory".
- **Examining a file** reads at most its first `HEADER_LEN` = 64 bytes, never more. A new pure function `db_backup::peek_backup_key(prefix: &[u8]) -> Peek` classifies them. It allocates nothing beyond the 64-byte buffer and never panics on any input. The classes:
  - `NotABackup`: fewer than 22 bytes, or bytes that do not start with `MAGIC`. Counted, ignored.
  - `Unencrypted`: `MAGIC` followed by `format_version` 1. Counted, ignored: it needs no key.
  - `OtherVersion(v)`: any other `format_version` except 2. Counted, ignored: this binary cannot restore it under any key.
  - `Truncated`: `MAGIC` followed by fewer than 2 bytes (so no readable `format_version`), or `MAGIC`, `format_version` 2 and fewer than 64 bytes in total. Counted, ignored: no reader accepts it, so no key can restore it.
  - `Sealed { backup_id, created_at_ms, backup_key_id }`: `MAGIC`, `format_version` 2, at least 64 bytes. The fields are read from offsets 24, 40 and 48, big-endian. They are **not** checked against `plaintext_len` or the file length, so a partial upload or a file still being written counts. When in doubt, the scan keeps the key.
- An I/O error while opening or reading any path or entry (permission denied, a file that vanished) refuses with `ScanFailed { path }` (exit 1, nothing changed): "could not read {path} while scanning: {io kind}". A path the operator named but the command cannot read is no evidence of absence.

**Step 3: report.** Every run that reaches step 2 prints the report, with or without `--confirm`:
- one line per `--scan` path: `scanned <path>: <n> examined, <m> skipped, <k> sealed under backup key <id>, <s> sealed under other keys`;
- then the first 100 matching files at most, in scan order: `needs backup key <id>: <file path> backup_id=<32 hex> created_at_ms=<u64>`, followed by `… and <r> more` if there are more.

Paths and header fields are not secrets. The header fields are in the clear in the file anyway.

**Step 4: decide.**
- One or more `Sealed` files name `<id>`: refuse with `BackupKeyInUse { count }` (exit 1), file unchanged, even with `--confirm`: "backup key {id} is still needed by {count} backup(s) listed above; delete or move them, or keep the key". There is no override flag.
- No file names it, and `--confirm` is absent: usage error `RetireConfirmRequired` (exit 2), file unchanged: "no scanned backup needs backup key {id}; backups outside the scanned paths are not checked. Re-run with --confirm to retire it". This is the same pattern as `secrets invalidate` (ADR 0047 owner answer 1).
- No file names it, and `--confirm` is given: go on to step 5.

**Step 5: retire (exclusive).**
1. Take the same exclusion as `secrets rotate --backup-key`: on `SQLite` the writer lock alone, without opening the database; on `PostgreSQL`, `open_exclusive`. This meets `fsutil::replace_private`'s rule that its caller first shuts out every server process. The ADR 0072 job runs inside the server process, so it is shut out too.
2. **Re-read the secrets file and repeat steps 1 and 2 under the lock.** The file may have changed since the unlocked pass, or a new backup may have arrived. Only the result of the locked pass decides. If it now finds a match, refuse with `BackupKeyInUse` as in step 4.
3. `ServerSecrets::retire_backup_key(id)` (new, pure, in `rizzy-domain-auth`) removes the entry. It returns `Err(BackupKeyNotHeld)` or `Err(BackupKeyCurrent)` and then leaves the secrets unchanged. `current_backup_key_id` is never touched.
4. Call `secrets_file::serialize`, then `fsutil::replace_private`, then release the exclusion.
5. Print: "backup key {id} retired. Make a new secrets backup (`rizzy-vault backup-secrets`); older secrets backups still hold this key, so retiring it is not erasure".

**Crash and retry.** `replace_private` is atomic. A crash before the rename leaves the key held, and a re-run repeats the whole command. A crash after the rename leaves the key retired, and a re-run fails at step 1 with `BackupKeyNotHeld` (exit 2), whose message points to `list` to confirm. No marker table and no migration are needed: the only state is the one file.

**No undo command.** There is no `unretire`. A key retired by mistake survives only in older secrets backups (Consequences).

### 4. Restore when the key is missing

When `rizzy-vault restore` opens a format_version 2 file whose header names a `backup_key_id` the secrets file does not hold, it must refuse with `DbBackupError::UnknownBackupKey`. The refusal comes after framing, before any chunk is decrypted and before the target database is touched. The exit code is 1. This case must never be reported as `Authentication`. The variant gains a summary of the held keys, `held: Option<(u32 /*count*/, u32 /*lowest*/, u32 /*current*/)>`. The message is the first of these whose case applies:
- no backup key held: "encrypted backup is sealed under backup key {id}, but this secrets file holds no backup key. Restore the secrets backup taken with this database backup (`rizzy-vault secrets restore`), then retry; nothing was changed";
- `id > current`: "encrypted backup is sealed under backup key {id}, newer than this secrets file's current backup key {current}: the secrets file is older than the backup. Restore the secrets backup taken with this database backup (`rizzy-vault secrets restore`), then retry; nothing was changed";
- otherwise: "encrypted backup is sealed under backup key {id}, which this secrets file does not hold ({count} held, ids {lowest} to {current}): it was retired, or this backup belongs to other secrets. Restore the secrets backup taken while that key was held (`rizzy-vault secrets restore`), then retry; nothing was changed".

A header that names a held key, but whose chunks fail, still gives `Authentication`, unchanged. After a whole-loss `secrets invalidate`, ids start again at 1. An old backup that names id 1 then gets `Authentication` ("belongs to other secrets"). That error is still distinct from a missing key, and correct (Risks).

### 5. `secrets restore` reports the backup keys it would drop

If the secrets file being replaced parses, `secrets restore` reports every `backup_key_id` that this file holds and the restored backup lacks. It never blocks on them: "the restored secrets file lacks backup key(s) {ids}; encrypted database backups sealed under them can no longer be restored with it. Keep a copy of the replaced file until those backups are gone". The report is made during ADR 0047 step 4, before the write. If the current file is absent or does not parse, nothing extra is reported.

### 6. What this ADR supersedes

Three Accepted parts, each named exactly and replaced in full ([ADR 0020](0020-partial-supersession.md) point 9). The rest of each ADR stays binding unchanged.

1. **[ADR 0071](0071-encrypted-db-backup-format.md) Decision, "Owner answers at acceptance (2026-10-22)", item 3**, full replacement text:

   > 3. Old `backup_keys` entries are never dropped automatically: no rotation, worker step, backup job or pruning setting removes one. A backup key leaves the secrets file only through `rizzy-vault secrets backup-key retire <id> --scan <path>… --confirm` ([ADR 0107](0107-backup-key-retention.md) §3), which refuses the current key and any key named by a format_version 2 backup under the scanned paths. Retention of the backup objects themselves stays with ADR 0072.

2. **[ADR 0071](0071-encrypted-db-backup-format.md) Decision, "Commands and restore", first paragraph, second sentence** ("`rizzy-vault restore` dispatches on `format_version`: … continues at ADR 0023 §5 step 2."), full replacement text:

   > `rizzy-vault restore` dispatches on `format_version`: 2 loads the secrets file and looks up the header's `backup_key_id`; if the secrets file does not hold it, it refuses with the distinct missing-key error of [ADR 0107](0107-backup-key-retention.md) §4, before any chunk is opened and before the target is touched; otherwise it opens every chunk, refuses on any commitment or AEAD failure, reassembles the format_version-1 bytes, and continues at ADR 0023 §5 step 2.

   The first sentence (`rizzy-vault backup --out <file> [--encrypt]` …) is not superseded.

3. **[ADR 0047](0047-opaque-secrets-operator-commands.md) Decision, `secrets restore` step 4, third sentence** ("Also reports (never blocks) any `setup_id` … but are reported."), full replacement text:

   > Also reports (never blocks) any `setup_id` with rows in the database but absent from this backup: those accounts keep taking the missing-setup path, but are reported. Also reports (never blocks), when the secrets file being replaced parses, every `backup_key_id` it holds that this backup lacks, worded as in [ADR 0107](0107-backup-key-retention.md) §5: encrypted database backups sealed under those keys can no longer be restored with the restored file.

**Not superseded, and why.**
- ADR 0071's key-generation sentence ("`rizzy-vault secrets rotate --backup-key` adds a new current key…") still holds: §1.4's cap only adds a refusal.
- ADR 0071's Consequences and Risks are not edited. That includes "If old `backup_keys` entries are never dropped, the secrets file grows slowly"; §1.4 bounds that growth.
- ADR 0028 item 13, as ADR 0071 replaced it, is untouched. **The secrets-file format does not change**: no new member and no tombstone list, so no new one-way compatibility break.
- ADR 0072 is Proposed. §1.1 constrains it, and its own drafting can cite this ADR.

### 7. Ownership, enforcement and tests

- `rizzy-domain-auth::secrets`: `retire_backup_key`, `MAX_BACKUP_KEYS`, `SecretsError::{BackupKeyNotHeld, BackupKeyCurrent, BackupKeyLimit}`. Pure, no I/O.
- `rizzy-server::db_backup`: `peek_backup_key`, `Peek`, the extended `UnknownBackupKey`.
- `rizzy-server::admin`: the scan, the exclusion, the report, and the `AdminError` variants `ScanArguments`, `ScanTooLarge`, `ScanFailed`, `BackupKeyInUse` and `RetireConfirmRequired`, plus the step-1 refusals mapped from `SecretsError`. `is_usage` covers `ScanArguments`, `RetireConfirmRequired`, `BackupKeyNotHeld` and `BackupKeyCurrent`.
- `rizzy-server::cli`: parsing and messages.
- No crate-boundary change, no new dependency, no migration, no new table.
- **Untrusted input:** the scanned files. `peek_backup_key` reads at most 64 bytes and is added to the existing `db_backup_parse` fuzz target. If that target's harness cannot take it, it gets a new `db_backup_peek` target instead (U: the target's contents were not read this session).

## Consequences

### Positive

- Every Accepted text now says which keys must stay. There is exactly one way to remove a key, and it requires evidence and `--confirm`.
- The two silent orphaning paths are closed or made visible: hand-editing gets a supported replacement, and `secrets restore` names the keys it drops.
- A missing key at restore time is a distinct error that tells the operator what to do. An ADR now requires it; today only the code does it.
- No persistent-format change, so no compatibility cost.

### Negative

- If an operator's backups live only in WebDAV or S3, they must download or mount the objects before they can retire a key, at least until ADR 0072 adds a listing source (open question 1). Until then the safe default, keeping every key, still applies.
- The scan proves absence only under the scanned paths. Backups elsewhere (a USB disk, a colleague's copy) are the operator's responsibility, as the `--confirm` message says.
- Retiring a key does not erase it: older secrets backups still hold it.

### Risks

- An operator scans the wrong directory and retires a key that is still needed. Recovery then needs an older secrets backup. Signal: support reports of `UnknownBackupKey` in its "otherwise" form. Response: a later ADR could add an opt-in list of retired ids (a format change).
- A whole-loss `secrets invalidate` restarts backup ids at 1 (V, `generate_after_loss`). Backups from before the loss then fail with `Authentication`, not `UnknownBackupKey`. They cannot be restored either way. Fixing this, by carrying a minimum next id, would change the secrets-file format, so it is left to a later ADR if it matters.
- An instance that rotates more often than about weekly reaches the 256 cap within five years. It shows as `BackupKeyLimit`, never as a silent failure.

## Alternatives considered

- **Never retire (the status quo, made explicit).** Safe, but it gives no answer for compromised or long-obsolete keys, and it invites hand edits. Lost to a gated command.
- **A server-side ledger of written backups** (a table recording `backup_id`, `created_at_ms`, `backup_key_id`). `backup --encrypt` takes no write lock (V, admin module table: "none: the read-only reader"). Manual copies and lifecycle deletes make such a ledger wrong in both directions, and a DB restore rolls it back. The headers are the ground truth.
- **Record each key's active window in the secrets file** (`added_at_ms`, and when it stopped being current), matched against ADR 0072's `<created_at_ms>.rzbak` object names. Useful for remote destinations, but it changes the secrets-file format, with another one-way compatibility break. Names are also not evidence: files can be renamed or copied by hand. It could come back with open question 1.
- **Retire with an override flag when backups still name the key.** Lost: orphaning backups must never be one flag away. Deleting the backups first is the explicit act.
- **Automatic retirement driven by an ADR 0072 pruning setting** (G07-31's alternative). Pruning is undecided in Proposed ADR 0072. If it comes, it must go through §3's checks (§1.1).

## Open questions for the owner

1. **Retiring when backups exist only remotely.** Should `retire` accept a configured ADR 0072 destination as a scan source (list the objects, then read the first 64 bytes of each with a ranged read)? *Recommendation:* yes, but decide it in ADR 0072, not here. Until then, local paths only, and no flag to retire without evidence.
2. **When `secrets restore` would drop keys: report or refuse?** §5 only reports. That matches ADR 0047's `setup_id` precedent and what disaster recovery needs. *Recommendation:* report only. Refusing would block recovery in exactly the case where the old file is being abandoned.

## On acceptance (not made now)

1. Status lines (the owner's act):
   - ADR 0071 becomes "Partially superseded by [ADR 0107](0107-backup-key-retention.md) (owner answer 3; "Commands and restore" sentence 2)", appended to any existing partial-supersession list under ADR 0020 point 9's accumulation rule. ADR 0083, also Proposed, also targets ADR 0071.
   - ADR 0047 becomes "Partially superseded by [ADR 0107](0107-backup-key-retention.md) (`secrets restore` step 4, third sentence)".
2. INV-121 (renumbered if taken) gets a row in THREAT_MODEL.md §8, whose test column names the domain and CLI tests below.
3. CRYPTO.md §5.11's `backup_keys` bullet gains: "Removed only by `secrets backup-key retire` ([ADR 0107](adr/0107-backup-key-retention.md)), never while current; at most 256."
4. `docs/self-hosting.md` "Rotation" and §8 "Backup" gain the `backup-key list|rotate|retire` commands and a warning: before a key is retired, every backup sealed under it must be gone.
5. The `admin.rs` module table gains the three subcommand rows.
6. The owner updates this ADR's status in the README index row. The lead updates CLAUDE.md's list of Proposed and Accepted ADRs.

## Implementation plan (after acceptance only)

1. `rizzy-domain-auth`: `retire_backup_key`, the cap and the errors. Unit tests:
   - retiring a non-current key removes exactly that key;
   - retiring the current key gives `Err(BackupKeyCurrent)` and leaves the secrets unchanged;
   - retiring an unknown id gives `Err(BackupKeyNotHeld)`;
   - after retiring id 1 of {1, 2, 3}, `rotate_backup_key` yields 4 (no reuse);
   - the 257th rotate fails with `BackupKeyLimit` and leaves the secrets unchanged;
   - `current_backup_key_id` never changes on retire;
   - `Debug` shows ids only.
2. `rizzy-server::db_backup`: `peek_backup_key`. Tests:
   - each `Peek` class from a crafted prefix;
   - the first 64 bytes of a real `seal` output yield its `backup_id`, `created_at_ms` and `backup_key_id`;
   - every prefix length from 0 to 64 of a sealed file is classified without a panic;
   - a proptest over arbitrary inputs of 0–128 bytes.
   Add the function to the fuzz target.
3. `rizzy-server::db_backup`, the `UnknownBackupKey` messages: one test per §4 case (no key held, `id > current`, otherwise), asserting the exact text. Another test asserts that a held id with tampered chunks still yields `Authentication`.
4. `rizzy-server::cli` parsing: the `backup-key list|rotate|retire` grammar. For `retire`, these are usage errors: no `--scan`, 17 `--scan` flags, a non-numeric id, a repeated `--confirm`. Unknown flags are refused.
5. `rizzy-server` integration tests, in the style of `tests/cli.rs` and `tests/db_backup.rs`, with real files on `SQLite`:
   - Rotate twice and write a `backup --encrypt` under key 1 into directory A. `retire 1 --scan A` exits 1 and lists the file. Delete the file: the dry run now exits 2 with "Re-run with --confirm", and `--confirm` exits 0. `list` then shows only `backup_key 2 current`, the secrets file parses, and `restore` of a key-2 backup still works.
   - `retire 2` (current) exits 2. `retire 9` exits 2 with the `list` hint. Re-running a completed retire exits 2 (the retry after a crash after the rename).
   - In the scanned directory, a symlink to a key-1 backup is skipped and not followed. An unreadable file (mode 000; the test is skipped when run as root) exits 1 with `ScanFailed`. 100 001 entries exit 1 with `ScanTooLarge`. A 40-byte format_version 2 file counts as `Truncated`.
   - Locking: while another process holds the writer lock, `--confirm` fails the same way `rotate --backup-key` does. A key-1 file added between the dry run and `--confirm` makes `--confirm` refuse (the locked re-scan).
   - `restore` with key 1 retired prints the "otherwise" message, exits 1 and leaves the target empty.
   - `secrets restore` of a snapshot taken before a `rotate --backup-key` prints the dropped-key report and still succeeds.
   - A `PostgreSQL` variant of the `--confirm` exclusion test, under the existing `PostgreSQL` test gate.
6. The docs in "On acceptance" items 3–5 land in the same change as the code.

## References

- [ADR 0071](0071-encrypted-db-backup-format.md), [ADR 0072](0072-remote-backup-destinations.md), [ADR 0047](0047-opaque-secrets-operator-commands.md), [ADR 0028](0028-api-v1-http-conventions.md) item 13, [ADR 0023](0023-logical-backup-format.md), [ADR 0020](0020-partial-supersession.md) point 9, [ADR 0083](0083-db-backup-plaintext-len-erratum.md) (Proposed, also against ADR 0071; no overlap, since it supersedes only "Container" sentences).
- [2026-10-25 gap review](../reviews/2026-10-25-adr-gap-review.md) M10; [raw findings G07](../reviews/2026-10-25-raw/G07.md), G07-27 and G07-31.
- [CRYPTO.md §5.11](../CRYPTO.md#511-server-side-encryption-not-zero-knowledge), [THREAT_MODEL.md §8](../THREAT_MODEL.md#8-security-invariants) INV-98.
- Code (V, this session): `crates/rizzy-domain-auth/src/secrets.rs`; `crates/rizzy-server/src/` `secrets_file.rs`, `db_backup.rs`, `admin.rs`, `cli.rs` and `fsutil.rs`.
- Unverified (U): the contents of the `db_backup_parse` fuzz target; the size estimate of 75 bytes per entry (computed from the layout, not measured); whether `docs/self-hosting.md` §8 is the right place for the operator text.
