# ADR 0048: Per-account storage quota and its wire error code

- Status: Accepted
- Date: 2026-10-11
- Deciders: project owner
- Milestone: M1
- Supersedes: [ADR 0028](0028-api-v1-http-conventions.md) (item 3 in part, item 12 in part), on acceptance.

## Context

[HANDOFF.md](../HANDOFF.md) "Blocked: needs the owner" lists gap 23, "a per-account storage quota", as a new ADR M1 needs. [ADR 0021](0021-server-compaction.md) §6 already leans on it: "no per-item cap in M1 (owner decision 2); the account storage quota bounds their bytes ([THREAT_MODEL](../THREAT_MODEL.md) A15, §7.6)" — unmet, since no ADR has fixed a number or mechanism. THREAT_MODEL A15 lists "Per-account quotas and body-size limits"; §7.6 row D lists "Quotas, body-size limits" against storage abuse; §3.4 already counts "ciphertext sizes" as Visible metadata, so a byte counter needs no new CRYPTO.md construction or plaintext exposure.

Scope is wider than `vault_` rows: [ADR 0011](0011-storage.md) "What is stored, by sync mode" gives `mail` (M6) its own row; [ADR 0064](0064-share-api-storage-lifecycle.md) (M5, this batch) adds `share_` rows per `owner_account_id`, both storing bytes under the same account once built. [ADR 0054](0054-attachments-envelope-and-api.md) (M3, this batch) depends on this ADR and sets only a per-attachment ceiling, never a second account-wide total.

Constraints: the upload path (`rizzy-domain-vault::upload::open_session`) opens one write transaction under `rizzy_storage::lock_account` before touching a vault row ([ADR 0011](0011-storage.md) "Transactions and concurrency"); a healing request (ADR 0021 §9) is one atomic, all-or-nothing transaction, and a device that cannot heal stays read-only indefinitely ("Server behind", "Leaving read-only"); R1 compaction deletes an op's body only when retained snapshots by two different authors cover it, and owner decision 1 makes an item snapshotted by one device only never compacted, so a single-device M1 account's bytes effectively only grow; each domain owns its own tables and crosses into another's only through Rust or a bus event, except one allowed FK to `auth_accounts(id)` ([ADR 0011](0011-storage.md) rules 5–6; [ADR 0016](0016-workspace-layout.md) R4) — `rizzy-storage`'s own `storage_meta` and `storage_reconciliation` tables already use exactly that FK for account bookkeeping no domain owns; [ADR 0028](0028-api-v1-http-conventions.md) item 3 closes the error-code set and item 12 enumerates `RIZZY_*` settings, both frozen for v1 except by an ADR.

## Decision

### 0. What this ADR supersedes

| ADR 0028 part, quoted | Replaced by |
|---|---|
| Item 3, first sentence: "Every error under `/api/` is `{"error":"<code>"}` with this status: `invalid_request` and `client_too_old` 400; `unauthorized` and `second_factor_required` 401; `fresh_session_required` 403; `not_found` 404 (also an unknown `/api/` path, and a role not running); `state_conflict`, `stale_epoch`, `record_conflict`, `prev_seq_mismatch` 409; `api_version_gone` 410; `payload_too_large` 413; `rate_limited` 429; `internal` 500." | §5 |
| Item 12, settings clause: "Settings `RIZZY_ROLES`, `RIZZY_ORIGIN`, `RIZZY_LISTEN` (default `127.0.0.1:8080`), `RIZZY_DATA_DIR` (`/data`), `RIZZY_DATABASE_URL`, `RIZZY_SECRETS_FILE` (`/run/rizzy-secrets/secrets.json`), `RIZZY_SIGNUP` (`closed`\|`open`), `RIZZY_TRUSTED_PROXIES`, `RIZZY_LOG_LEVEL`, `RIZZY_WORKER_INTERVAL_SECS`, `RIZZY_MAX_UPLOAD_BYTES`" | §1 |

The §5 sentence below already includes ADR 0031's `setup_retired` and ADR 0032's `credentials_stale`, regardless of the order in which this ADR, ADR 0031 and ADR 0032 are accepted. Nothing else in ADR 0028 is touched.

### 1. The number

One instance-wide setting, `RIZZY_ACCOUNT_QUOTA_BYTES` (default 5 GiB = 5 368 709 120, minimum 256 MiB, no maximum: the operator's disk is the limit, as item 8 already reasons for upload concurrency). No per-account override in M1; a later ADR gives the M3 admin panel ([ADR 0060](0060-admin-panel-stack-boundary.md), this batch) one. Settings `RIZZY_ROLES`, `RIZZY_ORIGIN`, `RIZZY_LISTEN` (default `127.0.0.1:8080`), `RIZZY_DATA_DIR` (`/data`), `RIZZY_DATABASE_URL`, `RIZZY_SECRETS_FILE` (`/run/rizzy-secrets/secrets.json`), `RIZZY_SIGNUP` (`closed`|`open`), `RIZZY_TRUSTED_PROXIES`, `RIZZY_LOG_LEVEL`, `RIZZY_WORKER_INTERVAL_SECS`, `RIZZY_MAX_UPLOAD_BYTES`, `RIZZY_ACCOUNT_QUOTA_BYTES`.

### 2. Counted bytes

The unit is the portable wire size `rizzy-domain-vault::fetch::op_size` already computes for paging: `STATEMENT_FRAME + header.len() + container.len() + body.len() + key_wrap.len()` (CRYPTO.md §9.6 framing), applied the same way to a snapshot's statement, envelope and wrap: engine-independent ([ADR 0011](0011-storage.md) point 4), unlike a `SUM` over each engine's own row encoding, and exactly what THREAT_MODEL §3.4 already marks Visible. **Compaction only credits the body it deletes.** The signed header, both hashes and the signature stay for the life of the vault (ADR 0021 §9 "Headers kept") and keep counting after their body is gone; only R1's body deletions and R3's snapshot drops credit the account. **Scope.** The counted bytes are every row of every table `rizzy-domain-vault` owns, not only `vault_ops` and `vault_snapshots`: today that is those two tables; once [ADR 0054](0054-attachments-envelope-and-api.md) is accepted, `vault_attachments` and `vault_attachment_chunks` count the same way, with no further edit to this section needed.

### 3. Where it is enforced

`rizzy-storage` gains one table and one function, not a domain crate's: the counter spans domains by design (§6). New file `crates/rizzy-storage/src/quota.rs`, beside `lock.rs`: `adjust(tx, account_id, delta: i64) -> Result<u64, Error>`, callable only inside a transaction already holding `lock_account`, upserting and returning the account's new `bytes_used`.

`rizzy-domain-vault::store` gains a step between the stale-epoch check and the insert (its module doc's "Order of the checks"): for an ordinary upload, if `session.bytes_used + added > quota_bytes + max_upload_bytes` (the account's headroom is the instance's own `RIZZY_MAX_UPLOAD_BYTES`, item 7 — not a separate fixed constant: it already bounds the raw wire size of everything one `UploadRequest` can carry, since base64url/JSON encoding (CRYPTO.md §9.6) only inflates a request beyond the raw lengths §2 sums, so every record of one request — however many ops and whichever snapshot covers them, the ordinary sync pattern — fits when the account was at or under quota before the request started, even exactly at the configured number), the record is refused `quota_exceeded`; else it is stored and `session.bytes_used` advances, written once at commit under the lock already held. The check runs once per record, in request order, inside the one transaction the request opens; a refusal on one record never undoes a record of the same request the transaction already stored before it. If the refused record is the snapshot covering ops the same request just stored, those ops keep their bodies, uncompacted — R1 needs a retained snapshot to credit them (§2) — until a later request resends a snapshot that then fits; this can only happen once the account is already over quota from a prior request or the healing exemption below, since within quota the whole request fits by construction. **A healing request is never refused for quota**: ADR 0021 §9 makes it one atomic, all-or-nothing transaction a device needs to leave read-only, so `quota_exceeded` is never among its refusals; its bytes still charge `adjust`, so the counter matches reality for the next ordinary upload. This exemption is bounded, not open-ended (Risks): each healing request is itself capped at the upload limit (item 7), and ADR 0032 §2 makes at most one step-3b request (self-grant and wraps) and one step-4 request (records) per vault per restore, so the quota's bound on an account's bytes loosens by at most two upload limits per vault, once per restore. `compact_item` reads each deleted body's and dropped snapshot's length before deleting it and calls `adjust` with the freed total, in the same transaction, before `dequeue`.

Proposed INV-72 (allocated across the 2026-10-11 batch in ADR-number order. Provisional: the allocation was made across the 2026-10-11 batch in ADR-number order; if ADRs are accepted out of order, the owner renumbers at acceptance.): the server never stores, for one account, more counted bytes (§2) than that account's configured quota plus its enforcement headroom (§3), except bytes a healing request re-publishes so a device can leave read-only, bounded as above.

### 4. Storage

One migration, `0007_storage_account_usage.sql` (sibling ADR 0047, same batch, takes `0006`; this ADR takes the next free number after it, in ADR-number order), in `crates/rizzy-storage/migrations/{sqlite,postgres}/`: `storage_account_usage(account_id BLOB PRIMARY KEY REFERENCES auth_accounts(id) ON DELETE CASCADE, bytes_used INTEGER NOT NULL CHECK (bytes_used >= 0), updated_at_ms INTEGER NOT NULL)`, `STRICT` on the SQLite file as every other `rizzy-storage` table already is, following the `storage_meta`/`storage_reconciliation` precedent of a `rizzy-storage`-owned, non-domain-prefixed table (Context). This ADR does not resolve HANDOFF gap 19 (`cargo xtask check-tables` has no rule yet for `storage_` tables); it only extends the existing precedent, pending that owner decision. The table joins `TABLES`, not `NOT_BACKED_UP`, in `rizzy-storage::tables`, so a restore's counter matches its restored rows (the ADR 0011 restore drill gains that check); the migration raises the backup `schema_version` to 6 ([ADR 0023](0023-logical-backup-format.md)).

**Backfill.** The migration itself only creates the table: a `storage_`-owned migration must not read any `vault_`-prefixed table (ADR 0011 rule 5, "a domain crate queries only its own tables"; `cargo xtask check-tables` would fail it). Instead, at first startup after the migration runs — after SQLite's automatic migration or PostgreSQL's `rizzy-vault migrate`, which the server already waits on before opening for requests (ADR 0011 "When migrations run") — `rizzy-domain-vault` sums, over every row of every table it owns (today `vault_ops` and `vault_snapshots`; `vault_attachments` and `vault_attachment_chunks` too, once [ADR 0054](0054-attachments-envelope-and-api.md) is accepted, with no further edit to this section needed), each existing account's current total in the unit §2 defines (the `fetch::op_size` figure for each op row, the equivalent header-plus-envelope-plus-wrap figure for each snapshot row, and ADR 0054's own per-row figure for its two tables), and reports each account's total through its own Rust API; `rizzy-storage` then calls `adjust` once per account, from zero, to seed `storage_account_usage.bytes_used`, keeping the counter `rizzy-storage`'s alone to write (§3). This finishes before the server opens for requests, so no upload races it and no pre-existing account is checked against an implicit zero baseline. Mail and share rows need no backfill: neither domain exists yet; each reports its own total through the same per-domain pattern once built.

The cached counter is a denormalized sum the stored rows define authoritatively. `worker` gains a daily reconciliation pass: each domain recomputes its own account totals through the same per-domain Rust API the backfill uses (`rizzy-domain-vault` today; mail and share once those domains exist), and `rizzy-storage` corrects `storage_account_usage` on drift, logging the account id and the correction, never content.

### 5. Wire, and one number across several domains

**The complete item 3 replacement** (ADR 0020 point 9, carrying forward ADR 0031's and ADR 0032's own glosses so naming the whole sentence narrows nothing): "Every error under `/api/` is `{"error":"<code>"}` with this status: `invalid_request` and `client_too_old` 400; `unauthorized` and `second_factor_required` 401; `fresh_session_required` 403; `not_found` 404 (also an unknown `/api/` path, and a role not running); `state_conflict`, `stale_epoch`, `record_conflict`, `prev_seq_mismatch`, `setup_retired` (ADR 0031 point 3: a registration whose echoed OPAQUE `setup_id` is retired or unknown), `credentials_stale` (ADR 0032 §4: after KE3 verified, the account's OPAQUE record lags its signed state), `quota_exceeded` (this ADR §3: the record would push the account's counted bytes past its quota and headroom) 409; `api_version_gone` 410; `payload_too_large` 413; `rate_limited` 429; `internal` 500."

New closed error code `quota_exceeded`, `409`: the conflict-with-server-state bucket `state_conflict`/`stale_epoch`/`record_conflict`/`prev_seq_mismatch`/`setup_retired`/`credentials_stale` already uses, not `413`, which item 7 fires from `Content-Length` before any body byte is parsed — an unrelated check. `rizzy-proto::error::ErrorCode` gains `QuotaExceeded`, documented in error.rs's "Named by a spec" list as naming this ADR. `AccountView` (a response type; unknown fields are ignored) gains two plain fields, `bytes_used: u64` and `quota_bytes: u64`, so a client shows usage without a dedicated endpoint.

The counter lives in `rizzy-storage`, not in any `rizzy-domain-*` crate, so it is this ADR's one account-level number. `rizzy-domain-mail` and `rizzy-domain-share` charge the same `storage_account_usage` row through `adjust`, under their own account-locked transactions, when built (ADR 0068/0069 for mail, ADR 0064 for shares); the M3 attachments ADR, [ADR 0054](0054-attachments-envelope-and-api.md), sets only a per-attachment byte ceiling (Context) and must not define a second account-wide total.

### On acceptance

ADR 0028's status line gains "; [ADR 0048](0048-per-account-storage-quota.md) (item 3 in part, item 12 in part)", appended after any earlier entry; [README](README.md) row 0028 repeats it and row 0048 becomes Accepted. [THREAT_MODEL.md](../THREAT_MODEL.md) §8 gains INV-72's text (§3 above), checked against this batch's other proposed invariants first. Nothing in [ADR 0021](0021-server-compaction.md) is edited: this ADR only fulfils its owner decision 2, by citation.

### Owner answers at acceptance (2026-10-22)

The owner accepted this ADR as drafted; the recommendations of "Open questions for the owner" stand:

1. `RIZZY_ACCOUNT_QUOTA_BYTES` defaults to 5 GiB, with a minimum of 256 MiB and no maximum.
2. `quota_exceeded` is a `409`, not a `413`.
3. The enforcement headroom is the instance's own `RIZZY_MAX_UPLOAD_BYTES`, not a separate constant.
4. `storage_account_usage` is backed up, so a restored counter matches the restored rows.
5. There is no per-account override before the M3 admin panel: one instance-wide value in M1.

Of the "On acceptance" edits, ADR 0028's status line, its index row and INV-72 (THREAT_MODEL.md §8.8) are made in the accepting change.

## Consequences

### Positive

- Fulfils ADR 0021 owner decision 2 and THREAT_MODEL A15/§7.6 "D" with one concrete number and mechanism.
- One `O(1)` check per record, under a lock the upload path already holds; no table scan.
- One cross-domain primitive: mail, shares and attachments charge one number instead of each inventing their own account-wide bookkeeping.

### Negative

- A new table, migration and backup `schema_version` bump on every instance, plus a one-time per-domain backfill step at first startup for every existing account.
- `worker` gains a periodic reconciliation job; `AccountView` grows two fields per response.
- `compact_item` now reads a length before each delete it already performs.

### Risks

- **Healing exemption bound.** §3's quota exemption for healing is not unconditional: it is bounded by at most two upload limits (`RIZZY_MAX_UPLOAD_BYTES`) per vault, once per restore (§3). Within that bound it can still push `bytes_used` above `quota_bytes` with nothing to flag the overage: the daily reconciliation pass (§4) only recomputes the true sum and corrects drift, it does not compare the result against `quota_bytes` or log a breach. This narrows ADR 0021's existing "Pinning" risk ("a faulty device can pin snapshots through R3, up to the storage quota") for the restore case: after a restore that needed healing, the quota bounds an account's bytes only up to that two-upload-limit-per-vault slack, until a later ADR gives the operator a quota-versus-usage alert.
- **Single-device M1 use gives compaction nothing to reclaim** (owner decision 1): the counter is effectively monotonic for the typical dogfood account, so the quota is a ceiling against faulty or runaway growth (ADR 0021 §6's stated purpose), not a budget a lone user manages by deleting things, until a second device exists or M9 revisits multi-vault accounts.
- **Drift** between the cached counter and the true sum, if the daily reconciliation lags or a crash loses an in-flight `adjust`; mitigated, never eliminated, by §4's recompute.
- **Worker lag** delays credit, not only deletion; a permanently failing queued item (ADR 0021 §7 "Failures are isolated per item") never credits its freed bytes.

## Alternatives considered

- **A `SUM` query per write instead of a cached counter.** Does not scale, is not portable the same way across engines, and cannot gate a write without an extra read under the lock anyway.
- **A per-item or per-vault cap instead of per-account.** ADR 0021 owner decision 2 already chose account-wide and rejected a per-item cap.
- **Plaintext byte counts.** Padmé padding (ADR 0005) means plaintext size is not what is stored; THREAT_MODEL §3.4 already treats ciphertext size as visible.
- **A per-account override from M1.** YAGNI before the M3 admin panel exists to set one safely.

## Open questions for the owner

1. **Default and minimum for `RIZZY_ACCOUNT_QUOTA_BYTES`.** Recommendation: default 5 GiB, minimum 256 MiB, no maximum.
2. **HTTP status for `quota_exceeded`.** Recommendation: 409, the existing conflict-with-server-state bucket (§5), not 413 (a different, pre-parse check).
3. **Enforcement headroom above the configured number.** Recommendation: the instance's own `RIZZY_MAX_UPLOAD_BYTES` (item 7), not a separate fixed constant — it already bounds everything one `UploadRequest` can carry, so every record of one request fits when the account was at or under quota beforehand, even exactly at the configured number (§3).
4. **Back up `storage_account_usage`, or leave it `NOT_BACKED_UP` like `storage_reconciliation`?** Recommendation: back it up, so a restored counter matches restored rows.
5. **A per-account override before the M3 admin panel.** Recommendation: no; one instance-wide value in M1 (§1).

## References

- [ADR 0011](0011-storage.md) rules 5–6, "Transactions and concurrency", "When migrations run", "Backups"; [ADR 0016](0016-workspace-layout.md) R4; [ADR 0020](0020-partial-supersession.md) point 9; [ADR 0021](0021-server-compaction.md) §3, §6, §9, owner decisions 1–2; [ADR 0023](0023-logical-backup-format.md); [ADR 0028](0028-api-v1-http-conventions.md) items 3, 7, 8, 12; [ADR 0031](0031-retiring-old-opaque-setups.md) point 3; [ADR 0032](0032-healing-rotation-after-backup.md) §2, §4
- [THREAT_MODEL](../THREAT_MODEL.md) §3.4, §7.6 row D, A15; [CRYPTO.md](../CRYPTO.md) §9.6
- [docs/HANDOFF.md](../HANDOFF.md), "Blocked: needs the owner", gap 23
- Code (V, 5a78bb5): `crates/rizzy-domain-vault/src/{upload,store,fetch,compact}.rs`; `crates/rizzy-storage/src/{lock,tables}.rs`; `crates/rizzy-proto/src/{error,account}.rs`
