# ADR 0047: Operator commands for OPAQUE secrets: restore and invalidate

- Status: Accepted
- Date: 2026-10-11 (accepted 2026-10-24)
- Deciders: project owner
- Milestone: M1
- Supersedes: [ADR 0011](0011-storage.md) owner decision 3, in part (reader half), on acceptance.

## Context

CRYPTO.md [§5.8](../CRYPTO.md#58-loss-or-rotation-of-the-server-opaque-secrets) names two admin
steps no command implements. HANDOFF gap 22 ("restoring from a `backup-secrets` file") and gap 11
("a way back after the OPAQUE `server_setup` is lost") carry both forward. Distinct from the M8
scheduled-DB-backup ADRs (0071, 0072): this is the secrets file, not the database dump.

**Gap 22.** `rizzy-vault backup-secrets` seals the secrets file under an operator passphrase
([ADR 0011](0011-storage.md) "Backups"; CRYPTO.md §5.11 `SERVER_SECRETS_BACKUP`).
`secrets_backup.rs` already has the reader, `open`, documented as "no Accepted ADR names a
command that restores the secrets from it, so none exists". Nothing installs its output.

**Gap 11.** §5.8 says the admin marks the records invalid and the client re-registers OPAQUE at
the next typed password (credential-replacement rule, [§11](../CRYPTO.md#11-flows)). No command
does. With the file gone and no backup, the server can never start again: `secrets init` always
writes `setup_id` 1, and `ServerSecrets::check_database` (`rizzy-domain-auth/src/secrets.rs`)
refuses a loaded setup whose id the database already holds under a different key
(`SetupMismatch`) before reaching the "fresh file, existing records" case (`NoRecordedSetup`)
this scenario is.

Both commands are admin, one-off, server-stopped operations like `secrets rotate`/`retire-setups`
([ADR 0010](0010-server-shape.md) §2, §4): excluded by the SQLite writer lock or the exclusive
PostgreSQL instance lock.

**`check_database` is not read-only.** Every early refusal returns before `tx.commit()` and rolls
back cleanly. The hazard is its success path: it commits inserted setup hashes, and the caller can
still fail to write the file afterward; with no `auth_credentials` rows yet, `NoRecordedSetup` is
skipped, so even a wrong backup's setup gets inserted and can poison a later restore with
`SetupMismatch`. ADR 0023's `restore` gates on the pure `check_dump` instead — a gate deciding
whether to write a file at all must be equally pure.

## Decision

### Owner answers at acceptance (2026-10-24)

The owner accepted this ADR as drafted. Recommendations stand:
1. Bare `--confirm` flag (recommendation 1).
2. Refuse `invalidate` outside the two diagnosed cases (recommendation 2).
3. Reject unknown flags (recommendation 3).

Restore is not a new construction: it reuses `secrets_backup::open`, `secrets_file`'s JSON layout
and `ServerSecrets`'s existing primitives. `invalidate` reuses the same plus one new table (below),
needed only to make its own crash recovery decidable. No CRYPTO.md text changes: §5.8 already
describes "the admin marks the records invalid"; this ADR builds it.

**New: `ServerSecrets::check_database_dry_run`** — checks 1–3 of `check_database`, read-only,
never inserting. Both commands gate on this, never on `check_database`; real server startup keeps
using `check_database` unchanged.

**New: `auth_invalidate_pending`** — a one-row marker (`case`, the minted `setup_id`,
`diagnosed_at_ms`), written by `invalidate` step 4 and cleared by step 6, so a re-run after a
step-6 crash resumes the diagnosed case directly instead of re-deriving it from a file whose
diagnosis a completed step 4 can already have changed (step 2). Needs its own migration, as any
`auth_` table change does (ADR 0031 point 1).

### `rizzy-vault secrets restore --in <file|-> --passphrase-file <file|-> [--config <file>]`

1. Flags follow `backup-secrets`'s and `restore`'s grammar. Exclusive admin command, database
   opened (unlike `secrets rotate`'s setup-only fast path).
2. Reads the backup file (path or `-`) and the passphrase as `backup-secrets` does (a file or
   stdin, never the command line), and calls `secrets_backup::open`; one error for a wrong
   passphrase and a tampered file, as today.
3. Parses the result with `secrets_file::parse`, refusing a damaged backup before any write.
4. **Gates on `check_database_dry_run`.** Any error refuses the restore, nothing touched, with a
   message that this backup does not belong to this database — enforced now, not discovered at
   the next start. Also reports (never blocks) any `setup_id` with rows in the database but
   absent from this backup: those accounts keep taking the missing-setup path, but are reported.
5. Only on `Ok(())` does it write the file with `fsutil::replace_private` (creates an absent file,
   replaces an existing one, as `secrets rotate`/`retire-setups` do).
6. No new parser, so no new fuzz target: `server_secrets_file` (ADR 0031 point 11) covers both.
   Changes nothing in ADR 0023's `restore` (unchanged): recovering both backups runs `secrets
   restore` first, then `rizzy-vault restore`.

### `rizzy-vault secrets invalidate --confirm [--config <file>]`

Only when the setup cannot be made to match the database and restore above was refused or never
tried. Discards only what the diagnosis shows is actually broken, not the data keys too.

1. Exclusive admin command, database opened, schema current, as `secrets retire-setups`.
2. **Diagnoses.** Reads `auth_invalidate_pending` first: a row there means a step-6 crash
   interrupted an earlier run — resumes with the recorded case and `setup_id`, never re-derived.
   Re-deriving would be wrong, not redundant: a setup-only-loss crash leaves every row retired, so
   `check_database_dry_run` on the unchanged file now sees `RetiredSetupLoaded`, not
   `SetupMismatch`/`NoRecordedSetup`, which case 3 below refuses — locking the operator out on the
   second run without the marker. No marker row: loads the file and runs `check_database_dry_run`:
   - Absent or unparsable: **whole loss**, nothing carried forward.
   - `Err(SetupMismatch)` or `Err(NoRecordedSetup)`: **setup-only loss** — `enum_key`, data keys
     and `bootstrap_token` carried forward unchanged; only the setup is wrong.
   - Anything else (`Ok(())`, `MissingDataKey`, unexplained `RetiredSetupLoaded`): refuses —
     `secrets rotate`/`restore` fits better, or the break is a data key, untouched here.
3. Requires `--confirm`; without it, a usage error reports (read-only) which case applies and the
   account/TOTP counts affected, so the operator sees the cost first.
4. One transaction, after generating a new `server_setup` in memory (its hash now known): retires
   every unretired `auth_opaque_setups` row (`retired_at_ms = now` where NULL), including
   "current" and any row an earlier crashed attempt minted and never used (never deleted, ADR
   0031 point 1; tombstoned harmlessly, since `check_database` walks only the loaded file's
   setups) — unlike `retire-setups`, since no current setup needs protecting. Deletes every
   `auth_login_states` row. On a whole loss deletes every `auth_totp_credentials` row (none of its
   data keys carry forward); on a setup-only loss, none (its key is intact). `auth_credentials`
   stays untouched (ADR 0031 point 7). Then **inserts the new setup's row** — `setup_id` = (the
   highest id seen, burned ones included) + 1, never 1 or reused; its hash; now; `retired_at_ms`
   NULL — so next start's `check_database` finds it recorded and matching (`recorded_any = true`)
   and never reaches `NoRecordedSetup`. Also writes `auth_invalidate_pending` (case, `setup_id`)
   in the same transaction. Converges after the first attempt whose step 6 succeeds: a crash
   before that burns the just-minted id (its key lived only in that process); a re-run retires the
   orphan and mints a fresh one.
5. Installs a `ServerSecrets` from the carried-forward parts (setup-only loss) or fresh ones
   (whole loss — **no** fresh `bootstrap_token`: a silent one would re-arm first-run admin
   bootstrap, INV-69 territory), plus the `server_setup` step 4 already generated, at that
   `setup_id`. `ServerSecrets::generate` gains a constructor taking the starting `setup_id`, the
   carried-forward parts and that already-built setup.
6. Writes the file with `fsutil::replace_private`, then clears `auth_invalidate_pending`: the
   file write is what step 2 treats as "done".
7. **Logged.** Today `log::init` runs only from `server::serve` (`server.rs:582`); no admin
   subcommand calls it, so `invalidate`'s handler is the first (logging still runs at the default
   `Level::Info` without it, since `log::enabled` falls back to it when unset, `log.rs:93,100`).
   Emits one `secrets_invalidated` line at `Level::Warn` with the case, `setup_count`,
   `totp_rows_deleted` and the new `setup_id` — before commit, so it records intent; a line with
   no matching file is step 2's crash branch.
8. Reports counts (no names): accounts needing re-registration, TOTP enrollments to redo (0 on a
   setup-only loss).

**Tests** (mirroring ADR 0031 point 11): `check_database_dry_run` commits nothing on every branch
`check_database` does. `restore` refuses a mismatched backup, or one into an absent file, without
writing anything, and reports an unlisted setup without blocking. `invalidate` refuses outside the
diagnosed cases; a setup-only loss keeps the data keys, deletes no TOTP row; a whole loss deletes
every TOTP row and mints no bootstrap token; a step-6 crash then re-run completes cleanly for
both cases via the marker, each attempt minting a fresh `setup_id`; a setup-only-loss crash where
re-diagnosing the file alone would wrongly see `RetiredSetupLoaded` resumes correctly instead.

## What this ADR supersedes

Under [ADR 0020](0020-partial-supersession.md) point 9:

| Part, quoted | Replaced by |
|---|---|
| [ADR 0011](0011-storage.md) owner decision 3: "Encrypting the server-secrets backup file under an operator passphrase → Yes, from M1, reusing the export-file construction (CRYPTO.md §11.14) with its own purpose id, `SERVER_SECRETS_BACKUP` (CRYPTO.md §5.11)." | "...with its own purpose id, `SERVER_SECRETS_BACKUP` (CRYPTO.md §5.11). Reading it back: `rizzy-vault secrets restore` decrypts the file, gates on the database, and only then installs it ([ADR 0047](0047-opaque-secrets-operator-commands.md))." |

Everything else in ADR 0011 stays binding.

## Consequences

### Positive
- Closes the only path by which a lost secrets file, backed up or not, permanently strands a
  server. A setup-only loss, the likelier accident, costs no TOTP enrollment or bootstrap token.

### Negative
- A whole loss still deletes every TOTP enrollment (forced by the data key's loss); every account
  re-registers OPAQUE through a device or recovery, no bulk shortcut.
- One new table and migration (`auth_invalidate_pending`), for a marker only `invalidate` writes.

### Risks
- An operator who confirms `invalidate` while a usable backup exists loses TOTP needlessly; step 2
  narrows this to "looked and found none," not "skipped looking." `check-tables` and ADR 0011
  rule 5 keep this ADR's table list from going stale.

## Alternatives considered

- **Leave the gap documented**, as `secrets_backup.rs` does today. Rejected: an operator would
  hand-edit the database with raw SQL, with none of this ADR's guards.
- **`invalidate` always discards the data keys too.** Rejected: destroys TOTP for no gain when
  only the OPAQUE setup is broken.
- **Build this into the M3 admin panel's audit log (INV-69).** Rejected for M1: neither exists
  yet; `log.rs` is what M1 has.

## Open questions for the owner

1. **Confirmation flag.** Bare `--confirm`, or a typed phrase? *Recommendation:* bare `--confirm`,
   the same barrier `secrets retire-setups --grace-days 0` already accepts.
2. **Refusing `invalidate` outside the two diagnosed cases.** *Recommendation:* yes: the cheapest
   guard against the wrong command or destroying intact data keys.
3. **Crash-marker shape.** A dedicated table, or columns on `auth_opaque_setups`?
   *Recommendation:* the dedicated table — those columns already have fixed meaning (ADR 0031
   point 1).
4. **Doc updates.** `docs/self-hosting.md` has no section for either command, and
   `fsutil::replace_private`'s doc comment names only its other two callers.
   *Recommendation:* fix both in the same change, as ADR 0031 did.
5. **A fresh bootstrap token on a whole loss.** Minting none (step 5) leaves no admin-bootstrap
   path until the M3 admin panel (ADR 0060) lands and an operator runs whatever it provides.
   *Recommendation:* accept it — minting one silently is the INV-69 outcome this ADR avoids.

## References

- CRYPTO.md [§5.8](../CRYPTO.md#58-loss-or-rotation-of-the-server-opaque-secrets), [§5.11](../CRYPTO.md#511-server-side-encryption-not-zero-knowledge), [§11](../CRYPTO.md#11-flows), [§11.14](../CRYPTO.md#1114-encrypted-export-m1)
- THREAT_MODEL.md §8.8 "Server and operations": INV-48, INV-50, INV-69
- [ADR 0010](0010-server-shape.md) §2, §4; [ADR 0011](0011-storage.md) "Backups"; [ADR 0023](0023-logical-backup-format.md) §5; [ADR 0031](0031-retiring-old-opaque-setups.md) points 1, 5, 6, 7
- Code at `5a78bb5` (V): `crates/rizzy-server/src/{secrets_backup,secrets_file,admin,cli,log,fsutil}.rs`; `crates/rizzy-domain-auth/src/secrets.rs`; new migration `crates/rizzy-storage/migrations/sqlite/0006_auth_invalidate_pending.sql` (allocated as the next free migration number ahead of sibling claims in ADRs 0048 and 0064 this batch, in ADR-number order. Provisional: the allocation was made across the 2026-10-11 batch in ADR-number order; if ADRs are accepted out of order, the owner renumbers at acceptance.)
- `docs/HANDOFF.md`, "New ADRs needed", gaps 11 and 22 (2026-10-09)
