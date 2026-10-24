# ADR 0071: Encrypted scheduled database backup format (SERVER_DB_BACKUP envelope)

- Status: Accepted
- Date: 2026-10-11
- Deciders: project owner
- Milestone: M8

## Context

[ROADMAP §4.2](../ROADMAP.md#42-core-vault-m1), row "Scheduled encrypted backups to user-chosen storage (local folder, WebDAV, S3-compatible)" (Should, M8). This ADR is the encryption-format half; ADR 0072, a sibling of this batch not yet in `docs/adr/` at drafting time, owns the destination, the schedule and destination-credential storage, and is not duplicated here.

[ADR 0023](0023-logical-backup-format.md) defines format_version 1: an unencrypted, self-describing dump, capped at `MAX_BACKUP_FILE_LEN` = 2 GiB (§3), with a trailing SHA-256 that "is not authentication: anyone who can write the file can recompute it" (§2). §1 provides for a new `format_version`, decided by an ADR; the Risks section names exactly this case, and open question 1 says "revisit with M8's scheduled encrypted backups." A scheduled job has no operator present to type a passphrase, so the `age`-at-rest answer to that open question does not fit it.

[CRYPTO.md §5.11](../CRYPTO.md#511-server-side-encryption-not-zero-knowledge) defines `SERVER_SECRETS_BACKUP` (purpose `0x0102`): an operator-passphrase-derived key, Argon2id, JSON-with-base64 shape. That shape does not fit a multi-gigabyte dump, and a passphrase does not fit an unattended run. [§9.1](../CRYPTO.md#91-symmetric-envelope-algorithm-0x01) caps algorithm `0x01`'s plaintext at 16 MiB, rejected before any crypto, so a 2 GiB dump cannot be one envelope either; the existing way past that ceiling (M3 attachments) is a new chunked algorithm id, not a bigger `0x01`.

`crates/rizzy-core/src/envelope/purpose.rs` already reserves `BACKUP_FILE` (`0x0071`, "backup key / 0x01", "defined by the M8 backup ADR") — outside the server-only `0x0100`–`0x01FF` range. This ADR does not define it: an object sealed *by the server, for the server*, under a server-only key is a server-only purpose ([§5.11](../CRYPTO.md#511-server-side-encryption-not-zero-knowledge)); `0x0071` reads as room for a possible future operator-passphrase manual backup, a different object (Open questions).

**This ADR also reopens two Accepted texts it did not originally name**: [ADR 0028](0028-api-v1-http-conventions.md) item 13 fixes the secrets file's exact JSON schema and says CRYPTO.md §5.11 owns "the single normative list" of its contents — a 4-item list with no backup key. [CRYPTO.md §9.6](../CRYPTO.md#96-encoding-for-transport-and-storage) already fixes "Files (export, M8 backup)" as JSON with the envelope base64url-encoded in a `data` field. Both are addressed below, not left implicit.

Threat model: [A1](../THREAT_MODEL.md#a1-passive-server-compromise-db-or-backup-theft) — off-site copies (ADR 0072) are typically less protected than the server itself. [INV-50](../THREAT_MODEL.md#8-security-invariants) already excludes the OPRF seed from DB backups; unaffected.

## Decision

### What this ADR supersedes

Two Accepted parts, each only for format_version 2; format_version 1 and the rest of each ADR are unchanged ([ADR 0020](0020-partial-supersession.md) point 9).

**[ADR 0023](0023-logical-backup-format.md) §2** (one bullet, the "Confidentiality is out of scope" one; **narrowed scope**, below):
- Replacing "It is not authentication…" (the whole bullet): **Format_version 1, unchanged.** Format_version 2: the file is authenticated under `backup_keys[current_backup_key_id].key`; a party who can write the destination but not the secrets file cannot forge, truncate or reorder it ("Chunking" below).
- Replacing only the "Confidentiality is out of scope" bullet's **first sentence** (the bold lead-in) and its **last sentence** (the `age`/at-rest-encryption guidance) — **not** its middle two sentences ("The database holds only ciphertext…" and "The server secrets… are never in it (INV-50)…"), which stay as ADR 0023 wrote them for format_version 1 and are separately, additively amended for format_version 2 by sibling [ADR 0072](0072-remote-backup-destinations.md) (its own, narrower edit to the "database holds only ciphertext" sentence, naming the backup-destination credential — not this ADR's concern): **Format_version 1, unchanged**, operator at-rest guidance included. **Format_version 2**: the whole payload, schema metadata included, is sealed under `backup_keys[current_backup_key_id].key`. A holder of the file alone gets no plaintext; a holder of the file *and* the secrets file has today's joint exposure, unchanged ([ADR 0011](0011-storage.md) "store the secrets backup apart from database backups"). At-rest encryption of a format_version 2 file is now optional defence in depth only.

**[ADR 0028](0028-api-v1-http-conventions.md) item 13**, full replacement text:

> **13. Secrets file.** Single owners: CRYPTO.md §5.11 owns what the file contains (its "single normative list", `format = 1`, the key sizes) and the backup's header fields, context and key; this item owns the JSON layout of both files, and the module docs of `secrets_file.rs` and `secrets_backup.rs` mirror it. JSON, unknown members refused, ≤ 256 KiB, outside the data directory, written with mode 0600 (the reader does not check the mode): `{"format":1,"setups":[{"setup_id","server_setup"}],"enum_key","data_keys":[{"data_key_id","key"}],"current_data_key_id","bootstrap_token"?,"backup_keys":[{"backup_key_id","key"}]?,"current_backup_key_id"?}`, binary as base64url. `backup_keys`/`current_backup_key_id` are present together or absent together. **Compatibility is one-way:** `RawFile` derives `deny_unknown_fields` (`secrets_file.rs`), so a file an upgraded server wrote with `backup_keys` present is refused outright by an older binary; rollback or a mixed-version deployment sharing one secrets file breaks until every instance is upgraded (Consequences). The secrets backup file mirrors §11.14: `{"format":"rizzy-vault-secrets-backup","version":1,"kdf_id","backup_salt","backup_id","created_at","data"}`, unchanged. *Why:* exactly CRYPTO.md §5.11's list, in the file shape CRYPTO.md already uses.

On acceptance, ADR 0028's status line gains `; [ADR 0071](0071-encrypted-db-backup-format.md) (item 13)` (point 9's accumulation rule: appended, with no repeated "Partially superseded by" prefix, after its existing "Partially superseded by ADR 0031 (item 3 in part); ADR 0032 (item 3 in part)").

### CRYPTO.md and `rizzy-core` edits landing in this change

Not ADR supersession — CRYPTO.md is fixed in the same change as the mechanism it documents ([ADR 0020](0020-partial-supersession.md) point 7) — but binding once Accepted:
- [§5.11](../CRYPTO.md#511-server-side-encryption-not-zero-knowledge) "Secrets file" list gains a fifth item, `backup_keys` per `backup_key_id`, matching item 13 above.
- §5.11 "Envelope" list and [§8.4](../CRYPTO.md#84-aad-and-purposes)'s purpose table both gain the `SERVER_DB_BACKUP` row (below).
- [§9.6](../CRYPTO.md#96-encoding-for-transport-and-storage) "Files (export, M8 backup)" is replaced **for format_version 2 only**: a binary container (below), not JSON; format_version 1 backups and exports keep the existing line.
- [§1](../CRYPTO.md#1-goals-non-goals-and-rules) rule 2's numbered list gains item 12, "chunked db-backup framing" (below) — the construction [ADR 0009](0009-crypto-dependency-policy.md) sizes the M8 audit scope from.
- [§4.3](../CRYPTO.md#43-derivations) gains a "Server DB-backup subkey" row (below, a new row — it has its own `ikm`, not `server_data_key`'s row); `rizzy-core/src/labels.rs` gains `SERVER_DB_BACKUP = "server/db-backup"`, with the registry test's expected-label list amended in the same PR.

### Container (format_version 2)

The file keeps ADR 0023 §1's `magic`. After it: `u16(format_version) = 2 ‖ backup_id(16) ‖ u64(created_at_ms) ‖ u32(backup_key_id) ‖ u64(plaintext_len) ‖ u32(chunk_count) ‖ chunk{chunk_count}`, one algorithm-`0x01` envelope per chunk ([§9.1](../CRYPTO.md#91-symmetric-envelope-algorithm-0x01)). `plaintext_len` is the exact byte length of a complete format_version-1 file; `chunk_count = ceil(plaintext_len / CHUNK_LEN)`, `CHUNK_LEN` = 8 MiB (last chunk shorter). Opening every chunk, concatenating in order and truncating to `plaintext_len` reconstructs it byte for byte. `backup_id` is 16 fresh random bytes per run.

**This is a new composition, not only a reuse** (§1 rule 2 item 12 above): no existing section specifies "an object chunked into independent `0x01` envelopes, ordering and completeness bound through AAD." [§9.1](../CRYPTO.md#91-symmetric-envelope-algorithm-0x01)'s own chunked answer, algorithm `0x03`, is ADR 0054's (M3, a sibling, different requirements — random access, per-chunk retrieval); borrowing it would make M8 wait on M3. Each chunk still uses only the audited, unmodified `0x01` construction; the new part is the framing, written into a new CRYPTO.md §9.x before code lands (Open questions).

**Ordering and completeness.** Chunk *i* (0-indexed, by position) seals/opens under `ctx = backup_id ‖ u64(created_at_ms) ‖ u32(backup_key_id) ‖ u32(i) ‖ u32(chunk_count)`. Because `chunk_count` and `i` sit in every chunk's AAD, reordering, duplicating, dropping a chunk, or editing the clear `chunk_count`/`plaintext_len` fields fails every surviving chunk's commitment check, not only the edited one. A reader refuses a file where `chunk_count != ceil(plaintext_len / CHUNK_LEN)` before opening any chunk.

**Size.** `MAX_BACKUP_FILE_LEN` (ADR 0023 §3) caps the format_version 2 file, not the payload: `backup --encrypt` computes output size (payload + 90 bytes/chunk + header) and refuses past the limit. No outer digest: per-chunk AEAD tags already cover every byte.

### The `SERVER_DB_BACKUP` purpose and the backup encryption key

New purpose `SERVER_DB_BACKUP` = `0x0105`, allocated across the 2026-10-11 batch in ADR-number order: sibling ADR 0060 (SMTP credentials) takes `0x0103`, sibling ADR 0066 (`SERVER_SHARE_EMAIL_CODE`) takes `0x0104` ahead of this ADR, and sibling ADR 0072 (`SERVER_BACKUP_DESTINATION`) takes `0x0106` after it. Provisional: the allocation was made across the 2026-10-11 batch in ADR-number order; if ADRs are accepted out of order, the owner renumbers at acceptance. `Purpose::ALL`'s count becomes 34 with this purpose added on top of 0060's and 0066's (base 31, +1 each for 0060, 0066 and this ADR). `0x0071` `BACKUP_FILE` stays reserved, unused.

The secrets file gains `backup_keys`/`current_backup_key_id` (item 13 above). `rizzy-vault secrets rotate --backup-key` adds a new current key, 32 bytes from the injected CSPRNG — never a passphrase, never equal to any `server_data_key` or `enum_key` entry. **Proposed INV-98:** a format_version 2 backup's key lives only in the secrets file, is CSPRNG-drawn, and is never passphrase-derived or shared with any other §5.11 purpose's key.

Subkey: `k = HKDF(ikm = backup_keys[backup_key_id].key, salt = empty, info = LABEL("server/db-backup") ‖ 0x00 ‖ u32(backup_key_id), 32)` (new §4.3 row above; `backup_key_id` here is the one recorded in the container header being opened, which may no longer be `current_backup_key_id` by restore time) — the same construction every other server purpose uses, with its **own** key rather than `server_data_key`: an off-site backup (ADR 0072) leaves the instance's boundary and outlives the `worker`'s DB-internal re-sealing cadence ([§5.11](../CRYPTO.md#511-server-side-encryption-not-zero-knowledge) "Rotation"). No new crate: `hkdf` 0.13.0, `sha2` 0.11.0, `chacha20poly1305` 0.11.0 are all in [ADR 0009](0009-crypto-dependency-policy.md)'s table.

### Crate ownership (no boundary change)

`rizzy-core::server_seal` gains `ServerDbBackupKey`/`ServerDbBackupCtx`, mirroring `ServerSecretsBackupKey`/`ServerSecretsBackupCtx`. `rizzy-domain-auth::types` re-exports it, as it already re-exports `ServerSecretsBackupKey`. **Correction to the original citation:** `rizzy-domain-auth`'s `Cargo.toml` description is "server auth domain: OPAQUE server side, sessions, devices, key bundles, account state, 2FA and recovery" — it says nothing about "server-side sealing" generally; that phrase is a comment on the crate's own *dependency* on `rizzy-core` ("OPAQUE server side, server-side sealing, …"), describing what `rizzy-core` supplies, not this crate's scope. The `types` module's own doc says it re-exports exactly what `AuthService`'s public API needs, named one by one — not a general sealing surface. The real reason this still fits without a boundary change: `rizzy-server`'s `Cargo.toml` depends on the domain crates and `rizzy-storage` only, not on `rizzy-core` directly (a comment there calls a direct dependency "an ADR 0016 §3 question for the owner"); giving `rizzy-server` its own `ServerDbBackupKey` re-export would raise that question now, which this ADR does not. A new `rizzy-server/src/db_backup.rs`, sibling to `secrets_backup.rs`, owns the format_version 2 container and calls the unchanged `rizzy_storage::backup::file` writer/reader. `rizzy-storage` itself is untouched: its `Cargo.toml` depends only on `sqlx` and `sha2`.

### Commands and restore

`rizzy-vault backup --out <file> [--encrypt]`: `--encrypt` requires a current `backup_key_id` (else a usage error) and writes format_version 2; its absence keeps format_version 1. `rizzy-vault restore` dispatches on `format_version`: 2 loads the secrets file, opens every chunk, refuses on any commitment or AEAD failure, reassembles the format_version-1 bytes, and continues at ADR 0023 §5 step 2.

**This ADR depends on [ADR 0047](0047-opaque-secrets-operator-commands.md)** (M1, Proposed, filed in this same review batch) for a secrets-restore path. ADR 0047's `rizzy-vault secrets restore` reinstalls the secrets file's whole parsed JSON content verbatim, via `secrets_file::parse` and `fsutil::replace_private` — generic over every field the file holds, not field-specific — so it already carries `backup_keys` and `current_backup_key_id` forward together with every pre-existing field, once a `backup-secrets` snapshot captured them; no change to ADR 0047 is needed for that. Until ADR 0047 is Accepted, no command restores a lost secrets file at all, and a secrets-file loss leaves every format_version 2 backup permanently unrestorable even once the rest of the file is recovered (Consequences).

### Owner answers at acceptance (2026-10-22)

The owner accepted this ADR as drafted; the recommendations of "Open questions for the owner" stand:

1. Placement of the chunk-framing text: no recommendation recorded, so this question stays open. The drafted CRYPTO.md edits assume a new §9.x after §9.7, and this change follows the draft with a new §9.8. Folding that text into §5.11 instead is still the owner's call.
2. `BACKUP_FILE` (`0x0071`) stays reserved and unused.
3. Old `backup_keys` entries are not dropped automatically: retention depends on ADR 0072's still-undecided off-site retention.
4. `--encrypt` does not become the default. The scheduled job (ADR 0072) always uses format_version 2.
5. `CHUNK_LEN` is fixed at 8 MiB, with no operator override, for now.

Of "CRYPTO.md and `rizzy-core` edits landing in this change" and "What this ADR supersedes", the documentation edits are made in the accepting change: CRYPTO.md §1 rule 2 item 12, §4.3's "Server DB-backup subkey" row, the §5.11 secrets-file and envelope lists, §8.4's `SERVER_DB_BACKUP` row, §9.6 for format_version 2, and the new §9.8; INV-98 (THREAT_MODEL.md §8.8); and the status lines of ADR 0023 (§2 in part) and ADR 0028 (item 13), with their index rows. The `rizzy-core` `labels.rs` constant and its registry test, and the purpose count in `Purpose::ALL`, are code for the implementation.

## Consequences

### Positive
- Scheduled, unattended backups get confidentiality and real authenticity with no human in the loop and no new primitive or crate.
- Closes format_version 1's schema-metadata leak and forgeability gap for an off-site copy (A1).
- Format_version 1 stays available for operators who prefer their own tool.

### Negative
- A new, audit-target-12 chunk composition, even though every primitive inside it is already audited.
- `rizzy-server` gains a second server-sealing object type alongside `secrets_backup.rs`.
- **One-way compatibility:** an upgraded secrets file (`backup_keys` present) is refused by an older binary (`deny_unknown_fields`); rollback and mixed-version deployment break until every instance upgrades.
- Until sibling [ADR 0047](0047-opaque-secrets-operator-commands.md) is Accepted and its `secrets restore` command exists, a lost secrets file silently strands every format_version 2 backup; ADR 0047's restore is generic over the file's fields, so once it lands this ADR needs no further change to be covered.

### Risks
- If old `backup_keys` entries are never dropped, the secrets file grows slowly over the instance's life.
- A reviewer who treats "reuse of `0x01`" as "no new construction" misses what the M8 audit (target 12) actually needs to look at.

## Alternatives considered

- **Reuse `SERVER_SECRETS_BACKUP`'s passphrase derivation.** Rejected: no operator is present for a scheduled run; JSON-with-base64 roughly triples a multi-gigabyte dump.
- **One `0x01` envelope for the whole dump.** Rejected: exceeds the 16 MiB M1 plaintext ceiling.
- **A new chunked algorithm id now.** Rejected for M8: that is ADR 0054's construction, with different requirements.
- **Key from `server_data_key`.** Rejected: couples a long-retained, off-site object to a key on the DB-internal rotation cadence.
- **Define `BACKUP_FILE` (`0x0071`) instead.** Rejected: outside the server-only range that §5.11 reserves for server-sealed-for-the-server objects.

## Open questions for the owner

1. Exact placement of the chunk-framing spec text: this ADR's CRYPTO.md edits assume a new §9.x after §9.7. Confirm, or fold into §5.11 instead.
2. Keep `BACKUP_FILE` (`0x0071`) reserved and unused? *Recommendation:* yes, for a possible future operator-passphrase manual backup.
3. Should old `backup_keys` entries auto-drop? *Recommendation:* no; retention depends on ADR 0072's still-undecided off-site retention.
4. Should `--encrypt` become the default once a `backup_key_id` exists? *Recommendation:* no; the scheduled job (ADR 0072) always uses format_version 2 regardless.
5. Fixed `CHUNK_LEN` (8 MiB), no operator override? *Recommendation:* yes, for now.

## References

- [ADR 0023](0023-logical-backup-format.md) §1–§3, §5; [ADR 0028](0028-api-v1-http-conventions.md) item 13 (secrets file schema, superseded here); [ADR 0072](0072-remote-backup-destinations.md) (sibling, this batch: destinations/scheduling); [ADR 0054](0054-attachments-envelope-and-api.md) (sibling, this batch: the M3 chunked algorithm 0x03 this ADR does not use); [ADR 0047](0047-opaque-secrets-operator-commands.md) (sibling, this batch: the secrets-restore dependency above); [ADR 0009](0009-crypto-dependency-policy.md) (crate pins); [ADR 0011](0011-storage.md) "Backups"; [ADR 0016](0016-workspace-layout.md) (crate boundaries, the open question this ADR does not resolve); [ADR 0020](0020-partial-supersession.md) points 7 and 9
- [CRYPTO.md](../CRYPTO.md) §1 rule 2, §4.3, §5.11, §8.4, §9.1, §9.6 (all amended or cited above)
- [THREAT_MODEL.md](../THREAT_MODEL.md) A1, INV-50
- `crates/rizzy-core/src/server_seal.rs`, `envelope/purpose.rs`, `labels.rs` (V); `crates/rizzy-server/src/secrets_file.rs` (V: `RawFile` `deny_unknown_fields`), `secrets_backup.rs`, `Cargo.toml` (V: domain crates + `rizzy-storage` only); `crates/rizzy-domain-auth/Cargo.toml`, `src/lib.rs` `types` module (V: re-export scope); `crates/rizzy-storage/Cargo.toml` (V: `sqlx` + `sha2` only)

<!-- All five reviewer blockers checked out against the cited sources (ADR 0028 item 13's text, secrets_file.rs's deny_unknown_fields, CRYPTO.md §9.6/§1 rule 2/§4.3, rizzy-domain-auth's Cargo.toml and types-module doc, labels.rs's three registered server/* labels); none was wrong, so this comment records that the "if a blocker is itself wrong" escape hatch went unused, not that one was found and kept anyway. -->
