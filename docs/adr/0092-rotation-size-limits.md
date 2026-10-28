# ADR 0092: Rotation size limits: a write-time cap on wrap-set rows, the `rotation_limit` code, and staged rotation so revocation and recovery never fail on size

- Status: Accepted
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M3
- Supersedes: on acceptance, in part: [ADR 0025](0025-rotation-vault-half.md) (§1, the "Recovery (§11.9 step 3)." and "Body limit." bullets; §3 check 3; "Risks", third bullet); [ADR 0081](0081-multiple-vaults-personal-and-shared.md) (§0 item 3, its replacing text for the ADR 0025 §1 "Vault half:" bullet); [ADR 0028](0028-api-v1-http-conventions.md) (item 3 in part, as [ADR 0048](0048-per-account-storage-quota.md) §5 replaced it). §0 quotes each part and gives its full replacement ([ADR 0020](0020-partial-supersession.md) point 9).

## Context

**Trigger.** The owner's instruction "start" (2026-10-25), given after the ADR gap review of that day ([docs/reviews/2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md)). Its row D4 reads: "Key rotation is one request, capped at 65,536 wraps per vault and by the 32 MiB body limit (about 115k wraps). Nothing caps growth, and no refusal code is defined: a large account can't revoke a stolen device or finish recovery. | G03-9 | new ADR". The raw finding ([G03](../reviews/2026-10-25-raw/G03.md) G03-9, major) quotes ADR 0025: "Vaults above `MAX_ITEM_KEY_WRAPS` rows cannot rotate in M1 (their Fetch already fails with `WrapSetTooLarge`)", and the code: "the rotation is refused as `invalid_request` (ADR 0025 "Risks")", and concludes: "Rotation is how a stolen device is revoked (§11.8) and how recovery finishes (§11.9), so the failure is a security failure, not only an availability one."

The sibling [ADR 0091](0091-revoked-device-rotation-race.md) (Proposed, same track) already reserves this ADR's code in its complete ADR 0028 item 3 replacement: "`rotation_limit` (ADR 0092 §3: the write would take the account or a vault past the size it can still rotate in one request) 409", and names this ADR in its Risks ("10 minutes is too short for slow links or large accounts") and open question 2 ("revisited with M3 measurements of rotation time at the ADR 0092 limit"). This ADR defines that code with that meaning and status, so the item 3 sentence is the same in both. (ADR 0091 links this file as `0092-rotation-size-bound.md`; the file is `0092-rotation-size-limits.md`, see "On acceptance".)

### What the binding texts and the code say (V, read at `251c702`)

- **One request.** ADR 0025 §1, as ADR 0081 §0 item 3 replaced its "Vault half:" bullet: `vault_rotation: { vaults: List<VaultRotation, MAX_VAULT_GRANTS>, regrants: … }` with `VaultRotation { self_grant, cursor: SeqVector, item_key_wraps: List<ItemKeyWrap, MAX_ITEM_KEY_WRAPS>, dropped: List<WrapLocator, MAX_ITEM_KEY_WRAPS> }`. ADR 0025 Alternatives: "**Two phases (vault request, then auth commit).** Rejected: breaks §11.6 step 9's "one atomic request"; a crash leaves the account half-rotated" and "**A streamed upload.** Rejected: more wire and state; M1's bound fits one body."
- **The per-vault limit.** `crates/rizzy-proto/src/limits.rs:152`: `pub const MAX_ITEM_KEY_WRAPS: usize = 65_536;`. `crates/rizzy-domain-vault/src/rotation.rs:49–51`: "A vault with more than [`MAX_ITEM_KEY_WRAPS`] wrap-set rows cannot rotate in M1 (its rows do not fit one upload, and its Fetch already fails with `WrapSetTooLarge`); the rotation is refused as `invalid_request`".
- **The body limit.** ADR 0025 §1: "`POST /api/v1/account/commit` and `/recovery/complete` take `RIZZY_MAX_UPLOAD_BYTES` (default 32 MiB). Estimate (U, arithmetic only): a 127-byte wrap envelope (§8.4, §9.1) is about 290 bytes of JSON, so 65,536 wraps are about 19 MiB." `limits.rs:228`: `DEFAULT_UPLOAD_BODY_LEN: usize = 32 * 1024 * 1024`, `:233` `MAX_UPLOAD_BODY_LEN = 256 * 1024 * 1024`; `rizzy-server` `config.rs` test `the_upload_limit_is_between_32_and_256_mib`: 32 MiB is the floor an operator cannot go below. `http/api.rs:589`: `Self::Upload | Self::Heal | Self::CommitChange => max_upload_bytes`; the recovery-complete route is not in that arm, so it takes the 1 MiB `BODY_LIMIT` (its request carries no wraps; the wraps are in its response).
- **Several vaults.** ADR 0081 §A9: "In Part A every vault of the account is unshared, so V is all of them and each gets a `VaultRotation`"; §D: "Owned vaults per account (Personal included) | 64 (`MAX_OWNED_VAULTS`)". So one commit carries the rows of up to 64 vaults: at about 290 bytes a row, 32 MiB holds about 115,000 rows (`33,554,432 / 290`, U), far below `64 × 65,536`.
- **Quota is bytes, not rows.** ADR 0048 §1 sets `RIZZY_ACCOUNT_QUOTA_BYTES` (default 5 GiB); nothing in it bounds the number of wrap-set rows. A 5 GiB account of small items holds millions of rows (U). ADR 0048 §3's headroom rule ("the account's headroom is the instance's own `RIZZY_MAX_UPLOAD_BYTES`") is the precedent this ADR follows for "checked under the account lock in the upload transaction".
- **Who needs rotation.** CRYPTO.md §11.8 step 3 (device revocation) and §11.9 step 5 (recovery) both end in the standard rotation (INV-19). ADR 0091 §4 makes a full rotation with an SK change the default for a stolen device and gives it a 10-minute window.

### Forces

1. Revocation and recovery are security operations; their failure for size is the one outcome this ADR must exclude (INV-115).
2. The account-state commit is atomic: the account key, device set, revocation H and every vault's re-wraps change in one transaction under the account lock, or none do (CRYPTO.md §11.6 step 9, ADR 0025 §4). Any chunking must keep that.
3. A write-time cap alone cannot give the guarantee: accounts stored before the cap exists, and a healing request (ADR 0021 §9) that restores rows lost to a restore, can put an account above any cap the ordinary write path enforces.
4. The server never decrypts (THREAT_MODEL §3.4); everything it counts is a row it already stores.

## Decision

### 0. What this ADR supersedes

The parts below are named under ADR 0020 point 9. Each replacing text binds as Decision text of this ADR from its acceptance. Nothing else in any Accepted ADR changes.

1. **[ADR 0081](0081-multiple-vaults-personal-and-shared.md) §0 item 3, its replacing text** (the ADR 0025 §1 "Vault half:" bullet as ADR 0081 gives it). Replacing text: "- **Vault half:** `vault_rotation: { vaults: List<VaultRotation, MAX_VAULT_GRANTS>, regrants: List<VaultSelfGrant, MAX_VAULT_GRANTS>, staging: Option<RotationId> }`. `vaults` is strictly ascending by `self_grant.vault_id`, one per vault in V (§3), with `VaultRotation { self_grant, cursor: SeqVector, item_key_wraps: List<ItemKeyWrap, MAX_ITEM_KEY_WRAPS>, dropped: List<WrapLocator, MAX_ITEM_KEY_WRAPS> }`. `cursor` is canonical (ADR 0012 §3). `dropped` names `(item_id, item_key_id)` rows the rotator cannot open (§2 step 3). `regrants` is strictly ascending by `vault_id` and holds, for each shared vault the account holds a self-grant for ([ADR 0081](0081-multiple-vaults-personal-and-shared.md) §B8), that self-grant re-wrapped under the new account key at the vault's unchanged `vault_key_epoch`. It is empty while the account holds no shared vault, and the server refuses a `regrants` list that does not name exactly those vaults. `staging`, when present, names the account's open rotation staging ([ADR 0092](0092-rotation-size-limits.md) §4), whose staged rows count as uploaded rows of their vaults in §3 check 3; when absent, every uploaded row is inline."
2. **[ADR 0025](0025-rotation-vault-half.md) §1, the "Recovery (§11.9 step 3)." bullet** ("`RecoveryCompleteResponse` gains `vaults: List<{vault_id, self_grant, heads: SeqVector, item_key_wraps}>`, read in one consistent read. The recovering client sends those heads as its cursor. Open question 7."). Replacing text: "- **Recovery (§11.9 step 3).** `RecoveryCompleteResponse` gains `vaults: List<{vault_id, self_grant, heads: SeqVector, item_key_wraps}>` and `wraps_paged: bool`, read in one consistent read. When the account's wrap-set rows over all its vaults number at most `MAX_ACCOUNT_WRAP_ROWS` ([ADR 0092](0092-rotation-size-limits.md) §1), `wraps_paged` is false and every vault's `item_key_wraps` is complete; otherwise `wraps_paged` is true, every `item_key_wraps` is empty, and the recovering client reads the rows through `POST /api/v1/recovery/wraps` (ADR 0092 §5). The recovering client sends the heads it holds as its cursor. Open question 7."
3. **[ADR 0025](0025-rotation-vault-half.md) §1, the "Body limit." bullet** (quoted in full in Context: "`POST /api/v1/account/commit` and `/recovery/complete` take `RIZZY_MAX_UPLOAD_BYTES` (default 32 MiB). Estimate …"). The replacement drops `/recovery/complete`, whose request carries no wraps (the code already gives it the default limit, `http/api.rs:589`), and adds the stage route. Replacing text: "- **Body limit.** `POST /api/v1/account/commit` and `POST /api/v1/account/rotation/stage` take `RIZZY_MAX_UPLOAD_BYTES` (default and floor 32 MiB, ADR 0028 item 7). A client sends the rotation inline only when the encoded commit body is at most `DEFAULT_UPLOAD_BODY_LEN` (32 MiB, the floor every instance accepts), and through staging ([ADR 0092](0092-rotation-size-limits.md) §4) otherwise; it never reads the instance's configured value. Estimate (U, arithmetic only): a 127-byte wrap envelope (§8.4, §9.1) is about 290 bytes of JSON, so 65,536 wraps are about 19 MiB."
4. **[ADR 0025](0025-rotation-vault-half.md) §3, check 3 ("Wraps")** ("each wrap is at the new epoch, parses and is 127 bytes; all header `key_id`s of the vault's wraps are equal and differ from every stored row's (…); `item_key_wraps` and `dropped` are disjoint, both are subsets of the stored rows, and together they must equal them. A stored row in neither is `state_conflict`: the client has not seen it. …"). Replacing text: "3. **Wraps** (`InvalidRequest` unless noted): a vault's *uploaded rows* are its inline `item_key_wraps` and `dropped` and, when `staging` is present, the rows staged for that vault under it ([ADR 0092](0092-rotation-size-limits.md) §4); a `staging` that does not name the account's open staging, or whose staging was opened on another `state_seq`, `account_key_id` or `vault_key_epoch` than this commit's, is `state_conflict`. Each uploaded wrap is at the new epoch, parses and is 127 bytes; all header `key_id`s of the vault's uploaded wraps are equal and differ from every stored row's (guards a re-wrap under the old key, proves nothing about content); no locator is uploaded twice (inline and staged together), uploaded wraps and uploaded drops are disjoint, both are subsets of the stored rows, and together they must equal them. A stored row in neither is `state_conflict`: the client has not seen it. This is this ADR's reading of "`ITEM_KEY_WRAP` beyond that cursor"."
5. **[ADR 0025](0025-rotation-vault-half.md) "Risks", third bullet** ("Vaults above `MAX_ITEM_KEY_WRAPS` rows cannot rotate in M1 (their Fetch already fails with `WrapSetTooLarge`)."). Replacing text: "- **Size.** An account above `MAX_ACCOUNT_WRAP_ROWS` rows rotates through staging ([ADR 0092](0092-rotation-size-limits.md) §4); a vault above `MAX_ITEM_KEY_WRAPS` rows, which only an account stored before ADR 0092 can hold, still fails its Fetch with `WrapSetTooLarge` and so cannot rotate (ADR 0092 "Risks")."
6. **[ADR 0028](0028-api-v1-http-conventions.md) item 3, in part**, as ADR 0048 §5 replaced it. The complete item 3 replacement is the one [ADR 0091](0091-revoked-device-rotation-race.md) §6 gives (its paragraph "The complete item 3 replacement"), word for word, so the sentence is the same whichever of the two is accepted first; if ADR 0091 is not Accepted, its `revocation_pending` entry is left out: "Every error under `/api/` is `{"error":"<code>"}` with this status: `invalid_request` and `client_too_old` 400; `unauthorized` and `second_factor_required` 401; `fresh_session_required` 403; `not_found` 404 (also an unknown `/api/` path, and a role not running); `state_conflict`, `stale_epoch`, `record_conflict`, `prev_seq_mismatch`, `setup_retired` (ADR 0031 point 3: a registration whose echoed OPAQUE `setup_id` is retired or unknown), `credentials_stale` (ADR 0032 §4: after KE3 verified, the account's OPAQUE record lags its signed state), `quota_exceeded` (ADR 0048 §3: the record would push the account's counted bytes past its quota and headroom), `revocation_pending` (ADR 0091 §2: another device's revocation window is open), `rotation_limit` (ADR 0092 §3: the write would take the account or a vault past the size it can still rotate in one request) 409; `api_version_gone` 410; `payload_too_large` 413; `rate_limited` 429; `internal` 500."

### 1. The limits

New constants in `rizzy-proto::limits`, compiled in, no configuration (ADR 0028 item 12 gains no setting):

| Constant | Value | Meaning |
|---|---|---|
| `MAX_ITEM_KEY_WRAPS` | 65,536 (existing) | wrap-set rows of one vault: the Fetch limit and now a write-time cap |
| `MAX_ACCOUNT_WRAP_ROWS` | 65,536 | wrap-set rows over every vault the account owns (shared or not, the vault-settings item included) |
| `ROTATION_WARN_ROWS` | 52,429 (80 %) | the client's first warning |
| `ROTATION_URGENT_ROWS` | 62,259 (95 %) | the client's second warning |
| `ROTATION_STAGE_ROWS` | 16,384 | rows (wraps plus drops) in one stage request |
| `ROTATION_STAGE_TTL_MS` | 86,400,000 (24 h) | a staging's life after its last stage request |

**A wrap-set row** is one stored `(vault_id, item_id, item_key_id)` row of the wrap set ([CRYPTO.md §4.2](../CRYPTO.md#42-key-inventory)), the unit ADR 0025 §3 check 3 compares. Rows of a vault count against the account that owns the vault ([ADR 0081](0081-multiple-vaults-personal-and-shared.md) §A9, as for quota); a member's writes to a shared vault count against its owner.

**Why 65,536 for the account.** It is the per-vault limit, so a single-vault account loses nothing, and it is the largest power of two whose inline rotation fits the 32 MiB floor with headroom: 65,536 rows × about 290 bytes ≈ 19.0 MB = 18.1 MiB (U; ADR 0025 rounds it to "about 19 MiB"), leaving about 13.9 MiB for the auth half, 64 self-grants and cursors and `regrants`. The bound the client relies on is not this estimate but the encoded length (§0 item 3): a body that does not fit goes through staging. §8 test 2 checks the estimate on a maximal account.

### 2. Write-time cap (server)

Every request that inserts a wrap-set row checks, inside its transaction under `rizzy_storage::lock_account` and after its existing checks (in `rizzy-domain-vault::store`, after ADR 0048 §3's quota step):

1. the vault's row count after the request ≤ `MAX_ITEM_KEY_WRAPS`, and
2. the owning account's row count after the request ≤ `MAX_ACCOUNT_WRAP_ROWS`.

If either fails, the whole request is refused with `rotation_limit` (§3) and nothing is written. The requests that can insert a row are an ordinary upload (a new item, an item-key change, an import, an A6 copy or move), the creation of a vault (its settings item) and a healing upload. **A request that inserts no row is never refused for size**, whatever the counts: trash, purge, edits under an existing item key, deletes, and the rotation itself (it overwrites or deletes rows, never adds them). An account above a cap (only possible as below) can therefore always shrink.

**Healing** (ADR 0021 §9) is checked against check 1 only. It restores rows the server lost, so refusing it for the account total would leave the healing device read-only for a size it did not grow; above `MAX_ITEM_KEY_WRAPS` in one vault, though, the vault's Fetch fails anyway (`WrapSetTooLarge`), so healing past it is refused rather than producing an unreadable vault. An account healed past `MAX_ACCOUNT_WRAP_ROWS` rotates through staging (§4) and its ordinary row-adding writes are refused until it is back under the cap.

**Accounts stored before this ADR** are not migrated: the count is computed from the rows, so an account already above `MAX_ACCOUNT_WRAP_ROWS` is simply refused row-adding writes and rotates through staging. The count is a `COUNT(*)` over the wrap-set rows of the account's owned vaults inside the transaction; a stored counter is an implementation choice that §8 test 4 must keep equal to that count.

### 3. The error code `rotation_limit`

New closed error code `rotation_limit`, `409`, in the conflict-with-server-state bucket, as ADR 0048 §5 placed `quota_exceeded` and ADR 0091 §6 `revocation_pending`. `rizzy-proto::error::ErrorCode` gains `RotationLimit`, documented as naming this ADR; `rizzy-server` `http::api::status` maps it to `409`. It carries no detail (INV-48: no error carries a value); the client reads the counts from the account answer (§6). Meaning: "the write would take the account or a vault past the size it can still rotate in one request" (the ADR 0091 item 3 gloss). It is never returned by `account/commit`, `account/rotation/stage`, `recovery/complete` or `recovery/wraps`: size never refuses a rotation (INV-115).

The existing `invalid_request` in `rotation.rs` for a vault above `MAX_ITEM_KEY_WRAPS` stays what it is, a wire-shape refusal of a list longer than its bound; a client following §4 never sends one.

### 4. Staged rotation

Staging moves the re-wrapped rows to the server ahead of the commit. **Staged rows are not state:** no Fetch, recovery read, export, compaction or check other than §0 item 4 reads them, and they change nothing until the commit applies them. The commit stays the single atomic step (CRYPTO.md §11.6 step 9, ADR 0025 §4): one transaction under the account lock checks the auth half, every vault's uploaded rows (inline plus staged) and the cut-off, then writes everything and deletes the staging, or writes nothing.

**When.** A client stages exactly when the inline commit body would exceed `DEFAULT_UPLOAD_BODY_LEN` (§0 item 3). It then stages every row of every vault and sends the commit with empty `item_key_wraps` and `dropped` lists and `staging` set. The server accepts either form at any size the lists allow (tests stage small accounts).

**Opening.** `POST /api/v1/account/rotation/stage`, authorised as `account/commit` would be for the same commit (the session and freshness rules of the classified step; the recovery-only session for a recovery rotation). Body (`deny_unknown_fields`):

```text
StageRequest {
  rotation_id: RotationId,          // 16 random bytes, base64url, chosen by the client
  base_state_seq: u64,              // the account state_seq the commit will advance
  account_key_id: KeyId,            // the new account key id (state') the commit will sign
  vault_id: VaultId,
  vault_key_epoch: u32,             // the new epoch of this vault (§3 check 2's value)
  item_key_wraps: List<ItemKeyWrap, ROTATION_STAGE_ROWS>,
  dropped: List<WrapLocator, ROTATION_STAGE_ROWS>,   // wraps + dropped ≤ ROTATION_STAGE_ROWS
}
StageResponse { staged_rows: u32 }  // rows staged for this vault under rotation_id so far
```

The server, in one transaction under the account lock:

1. `base_state_seq` ≠ the stored `state_seq` → `state_conflict`. The vault is not in the account's V → `invalid_request`.
2. The account holds at most one staging. If one exists with another `rotation_id`, it is deleted first (the newer client wins; a stale staging is useless once its `state_seq` passes, and only a session that could commit may stage). The `(rotation_id, base_state_seq, account_key_id)` triple of an existing staging is fixed: a request with the same `rotation_id` and another `base_state_seq` or `account_key_id` → `invalid_request`; per vault, `vault_key_epoch` is fixed by its first stage request likewise.
3. Per row, the checks of §0 item 4 that do not need the whole set: at `vault_key_epoch`, parses, 127 bytes, header `key_id` equal to the vault's other staged wraps and different from every stored row's; the locator names a stored row; wraps and drops of the request are disjoint (`invalid_request`).
4. **Idempotent retry.** A locator already staged under this `rotation_id` with the identical wrap (or as a drop again) is a no-op; with a different wrap, or wrap versus drop, → `invalid_request`.
5. Insert the rows into `vault_rotation_staging(account_id, rotation_id, vault_id, item_id, item_key_id, wrap BLOB NULL)` (NULL = dropped) and set the staging's `last_stage_at`; return `staged_rows`.

The number of staged rows is bounded by the stored rows (each names a distinct stored row), so staging needs no cap of its own and does not count toward quota (it is deleted at or before commit; ADR 0048 §2 counts stored records).

**Committing.** `account/commit` with `staging = rotation_id` runs ADR 0025 §3 with check 3 as §0 item 4 replaces it, over the union of inline and staged rows; check 5's writes apply the union, and the same transaction deletes the staging. A staged row whose stored row was deleted since (a purge by another device) fails "subset of the stored rows" → `state_conflict`; a row added since fails "together equal them" → `state_conflict`.

**Crash and retry.**
- Crash or lost response *during staging*: nothing changed; the client resends the same stage request (idempotent, step 4) or reads `staged_rows` and continues.
- Crash *during the commit*: the transaction rolls back; the staging is intact; the client resends the commit.
- Commit applied, response lost: the retry gets `state_conflict` (`state_seq` moved); the client reads `account/state` and finds its own new state, as for an inline commit (ADR 0025 open question 3).
- `state_conflict` from the commit because rows changed: the client fetches (enrolled device) or re-reads (§5), stages the missing rows under the same `rotation_id`, and commits again, within ADR 0025's 5 attempts. A staging whose `base_state_seq` was passed by another commit is useless: the client starts again with a new `rotation_id`.
- **Expiry.** Any commit that advances `state_seq` deletes every staging of the account in its own transaction. The worker deletes a staging whose `last_stage_at` is older than `ROTATION_STAGE_TTL_MS`. An expired `rotation_id` named by a commit is `state_conflict`.

**Revocation window.** Staging is part of the revoker's rotation, so it runs inside ADR 0091's window; nothing in this ADR extends the window. A revocation that needs staging takes longer (about 290 bytes a row, U); see Risks.

### 5. The paged recovery read

`POST /api/v1/recovery/wraps`, recovery-only session (as `recovery/complete`), used only when `wraps_paged` is true (§0 item 2). Body `{ vault_id, after: Option<WrapLocator> }`, default body limit; response `{ heads: SeqVector, self_grant, item_key_wraps: List<ItemKeyWrap, ROTATION_STAGE_ROWS>, next: Option<WrapLocator> }`, rows strictly ascending by `(item_id, item_key_id)` after `after`, each page one consistent read. The client uses the `heads` of each vault's last page as that vault's cursor. If the commit returns `state_conflict`, the client re-reads the vaults from `after = None` and stages what is missing (§4 retry). The endpoint is rate-limited as `recovery/complete` is.

### 6. Client behaviour and the early warning

- The account answer that ADR 0081 §A9 extends with per-vault `bytes_used` gains per vault `wrap_rows: u32`, and for the account `wrap_rows: u32` and `wrap_rows_limit: u32` (= `MAX_ACCOUNT_WRAP_ROWS`), all unsigned server figures for display. The client also counts its own replica.
- At `ROTATION_WARN_ROWS` the client shows a persistent, dismissable-per-session notice: "This account is close to its item limit (N of 65,536). Above it you can't add items; delete or empty Trash to free space." At `ROTATION_URGENT_ROWS` the notice is not dismissable. In a vault, the same at 80 % and 95 % of `MAX_ITEM_KEY_WRAPS`.
- Before any row-adding action the client checks locally and refuses at the cap without uploading; an importer ([ADR 0027](0027-export-payload.md)) and a bulk move (ADR 0081 §A5–§A6) check the whole batch first and refuse it whole, before the first upload. A `rotation_limit` from the server (another device raced the count) aborts the action; an A6 move aborts before the source is touched, as `quota_exceeded` does (ADR 0081 §A6 point 4).
- Revoking a device, changing the SK or master password and finishing recovery never show the size warning as a blocker; the client picks inline or staged by §0 item 3 and shows progress while staging.

### 7. Proposed invariant INV-115

"Revoking a device and finishing recovery never fail because of the account's size. Every account the server stores can complete the standard rotation: inline when its commit fits `DEFAULT_UPLOAD_BODY_LEN`, through rotation staging otherwise, and staged rows change nothing until the one commit that applies the whole rotation atomically. The server refuses with `rotation_limit` every write, healing aside, that would take an account past `MAX_ACCOUNT_WRAP_ROWS` wrap-set rows or a vault past `MAX_ITEM_KEY_WRAPS`, and never refuses a write that adds no row, nor any rotation, for size."

### 8. Tests

1. **Constants.** `limits.rs` unit test pins the §1 values and `ROTATION_WARN_ROWS = ⌈0.8 × 65,536⌉`, `ROTATION_URGENT_ROWS = ⌈0.95 × 65,536⌉`.
2. **Fits inline at the cap.** A `rizzy-proto` test builds the worst-case inline commit at the cap — 64 vaults, 65,536 rows in total with the longest encodings, cursors of 4,096 entries each, `MAX_DEVICE_GRANTS` grants, 16 retired keys — and asserts its JSON length; if it exceeds `DEFAULT_UPLOAD_BODY_LEN`, this ADR's estimate is wrong and the test says so (the client still stages; the cap's value is revisited, open question 1).
3. **Write cap.** `rizzy-domain-vault` store tests: an upload taking a vault to `MAX_ITEM_KEY_WRAPS + 1` → `rotation_limit`, nothing written; the account to `MAX_ACCOUNT_WRAP_ROWS + 1` over two vaults → `rotation_limit`; exactly at either cap → accepted; at the cap, a trash, a purge, an edit under an existing key → accepted; vault creation at the account cap → `rotation_limit`. Small caps by a test-only constructor parameter, not by a configuration setting.
4. **Healing.** Healing past the account cap → accepted; past the vault cap → `rotation_limit`; afterwards an ordinary row-adding upload → `rotation_limit`, a purge → accepted.
5. **Staged equals inline.** Property test: for random wrap sets split at random between inline and staged parts, a staged commit yields the same stored rows, epochs and nulled `key_wrap`s as the inline commit of the same rows, and the staging is deleted.
6. **Atomicity.** A commit with a staging that fails any check (auth half, check 2, check 3, cut-off) leaves wrap set, epochs, account state and the staging unchanged; fault injection after the writes and before the transaction commits leaves the same.
7. **Staging checks.** Wrong `base_state_seq` → `state_conflict`; repeated identical stage → no-op; conflicting re-stage → `invalid_request`; a new `rotation_id` deletes the old staging; a commit naming a deleted or expired staging → `state_conflict`; any commit advancing `state_seq` deletes stagings; the worker deletes after `ROTATION_STAGE_TTL_MS`; staged rows are invisible to Fetch, recovery and quota.
8. **Race.** Another device adds a row and purges another between staging and commit → `state_conflict`; the client fetches, stages the delta, commits.
9. **Recovery paging.** An account above `MAX_ACCOUNT_WRAP_ROWS`: `recovery/complete` returns `wraps_paged = true`; paging returns every row once, in order; the recovering client stages and commits; `rotation_limit` never appears.
10. **End to end (INV-115).** An account of 200,000 rows over 4 vaults, created by direct seeding (the write cap forbids it through the API), revokes a device with an SK change through staging and then finishes a recovery; both succeed. An account at the cap revokes inline.
11. **Fuzz.** `StageRequest`, `StageResponse`, the recovery-wraps request and response and the extended `vault_rotation` go through the `proto_json` fuzz target.

### On acceptance (doc edits, not made now)

1. [THREAT_MODEL.md](../THREAT_MODEL.md) §8 gains INV-115 (§7), linked to this ADR.
2. [CRYPTO.md §11.6](../CRYPTO.md#116-key-rotation) step 9 gains one sentence: "A rotation too large for one request stages its re-wraps first ([ADR 0092](adr/0092-rotation-size-limits.md) §4); the commit stays the one atomic request." §11.8 step 3 and §11.9 step 5 link INV-115.
3. ADR 0025's and ADR 0081's Status lines name this ADR's parts (the owner's act, ADR 0020 points 3–4); ADR 0028's as ADR 0091 does for item 3.
4. ADR 0091's two links to `0092-rotation-size-bound.md` become `0092-rotation-size-limits.md` (ADR 0091 is Proposed, so it may be edited; this change does not).
5. [docs/adr/README.md](README.md) row status; CLAUDE.md's ADR list (by the lead).
6. The code comments that cite ADR 0025 "Risks" for the size refusal (`rotation.rs:49–51`) cite this ADR.

## Consequences

### Positive

- A stolen device can be revoked and a recovery finished at any size (INV-115); the refusal that ends growth is a defined code with a defined client message, given before the user is surprised.
- The commit stays one atomic transaction; staging adds no half-rotated state, and a crash at any point leaves either the old or the new account state.
- Write-time caps keep ordinary rotations inline and within one request, so staging is the rare path, not the common one.

### Negative

- A hard item limit of 65,536 rows per account: a power user who exceeds it must delete or split across accounts. (Typical accounts hold a few thousand items, U.)
- Two new endpoints, one new table and one new error code; the commit gains one optional field.
- A member of a shared vault (M9) can be refused for its owner's size.

### Risks

- **Staged revocation outruns ADR 0091's 10-minute window** on slow links (200,000 rows ≈ 55 MiB, U). Signal: staged revocations reaching window expiry → raise the window or the client's part size (ADR 0091 open question 2).
- **The 290-byte estimate is low** and the cap's inline rotation does not fit. Signal: §8 test 2 fails → lower `MAX_ACCOUNT_WRAP_ROWS` (open question 1); correctness is unaffected because the client stages by measured length.
- **A legacy vault above `MAX_ITEM_KEY_WRAPS`** cannot Fetch and so cannot rotate; this ADR does not page Fetch. No such vault is known (U: pre-v1.0 instances). Signal: `WrapSetTooLarge` reports → a paged wrap-set Fetch ADR.
- **Healing refused at the vault cap** leaves that device read-only; another device must delete items first. Signal: `rotation_limit` on healing in the field.

## Alternatives considered

- **Write caps only.** Rejected as the guarantee: pre-existing accounts and healing can exceed any write cap (Force 3), and INV-115 would then be false exactly where it matters. Kept as the primary mechanism.
- **Staging only, no caps.** Rejected: unbounded rotation time against ADR 0091's window, and Fetch already fails per vault above `MAX_ITEM_KEY_WRAPS`.
- **Per-vault commits** (rotate vaults one request at a time). Rejected: breaks the one atomic request; between commits the account key and some vault keys are new and others old, the half-rotated state ADR 0025 rejected.
- **Wrapping the old vault key under the new one** instead of re-wrapping each item key. Rejected: a key-hierarchy change (CRYPTO.md §4.2) and a new construction; the revoked device would still read every old item through the chain.
- **Raising the body limit floor.** Rejected: 64 × 65,536 rows is about 1.2 GiB (U); no single request should be that large.
- **A per-account cap derived from the configured `RIZZY_MAX_UPLOAD_BYTES`.** Rejected: the client does not know it, and a later lowering by the operator would break rotations; the 32 MiB floor is fixed.

## Open questions for the owner

1. **Account cap value.** 65,536 rows (inline at about 18 MiB) or 98,304 (about 27 MiB, little headroom)? *Recommendation:* 65,536.
2. **Staging in M3, or caps only now and staging later?** *Recommendation:* both in M3; without staging INV-115 does not hold for healed or legacy accounts.
3. **Healing past the vault cap:** refuse (this draft) or accept and leave the vault unfetchable until purged? *Recommendation:* refuse.
4. **Warning thresholds** 80 % and 95 %? *Recommendation:* yes.

## Implementation plan (for the implementer, once Accepted)

1. `rizzy-proto`: the §1 constants; `ErrorCode::RotationLimit`; `RotationId`, `StageRequest`/`StageResponse`, the recovery-wraps types, `staging` and `wraps_paged`; fuzz entries (§8 tests 1, 2, 11).
2. `rizzy-server`: `status` maps `RotationLimit` to 409; routes `account/rotation/stage` (upload body limit) and `recovery/wraps` (default limit); body-limit arm updated.
3. `rizzy-domain-vault`: the count and the write cap in `store` and healing (§8 tests 3–4); migration adding `vault_rotation_staging`; `rotation` reads the union and deletes the staging; staging checks; the worker's expiry (§8 tests 5–8).
4. `rizzy-domain-auth`: the commit passes `staging` through `VaultPort::apply_rotation`; any `state_seq` advance deletes stagings via the port; recovery paging (§8 test 9).
5. `rizzy-client`: inline-or-staged choice by encoded length, staging with idempotent retry, the warnings and local pre-checks (§6); e2e test 10.

## References

- [ADR 0025](0025-rotation-vault-half.md) §1–§4, Alternatives, Risks; [ADR 0081](0081-multiple-vaults-personal-and-shared.md) §0, §A6, §A9, §D; [ADR 0048](0048-per-account-storage-quota.md) §1–§5; [ADR 0091](0091-revoked-device-rotation-race.md) §0, §6; [ADR 0021](0021-server-compaction.md) §9; [ADR 0028](0028-api-v1-http-conventions.md) items 3, 7, 12; [ADR 0020](0020-partial-supersession.md) point 9.
- [CRYPTO.md](../CRYPTO.md) §4.2, §11.6, §11.8, §11.9; [THREAT_MODEL.md](../THREAT_MODEL.md) §3.4, §8.
- Gap review row D4; raw finding [G03](../reviews/2026-10-25-raw/G03.md) G03-9.
- Code (V at `251c702`): `crates/rizzy-proto/src/limits.rs` lines 129, 152, 221–233; `crates/rizzy-domain-vault/src/rotation.rs` lines 49–51; `crates/rizzy-server/src/http/api.rs` line 589.
