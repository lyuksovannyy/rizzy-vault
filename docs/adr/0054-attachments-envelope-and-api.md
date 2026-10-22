# ADR 0054: Encrypted attachments: chunk layout, storage shape and upload/download API

- Status: Accepted
- Date: 2026-10-11
- Deciders: project owner
- Milestone: M3
- Supersedes: [ADR 0007](0007-ciphertext-envelope.md) §3 (the algorithm-registry row for `0x03`), in part.

## Context

[ROADMAP §4.2](../ROADMAP.md#42-core-vault-m1) lists, Should, M3: "Attachments (encrypted, size-limited)". [§4.7](../ROADMAP.md#47-public-sharing-m5), Should, M5: "'Send'-style arbitrary text/file share", whose file half needs attachment ciphertext to exist first; this ADR does not design Send (ADR 0067's).

Several slots are already reserved, waiting for this ADR:
- [CRYPTO.md §2](../CRYPTO.md#2-conventions): `attachment` is already one of the 16-random-byte `id` kinds.
- [CRYPTO.md §4.1–§4.2](../CRYPTO.md#41-diagram): the attachment key (32 B, CSPRNG, one per attachment, never rotated) and `ATTACHMENT_KEY_WRAP` under the item key are already in the key hierarchy. §4.2's "Where each wrapped-key object lives" table has `ATTACHMENT_KEY_WRAP (M3) | With the attachment; the M3 attachments ADR decides`.
- [CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes): `ATTACHMENT_CHUNK` (0x0033, key/alg "attachment key / 0x03 (reserved)", ctx "defined by the M3 attachments ADR") and `ATTACHMENT_KEY_WRAP` (0x0034, item key / 0x01, ctx `vault_id ‖ item_id ‖ attachment_id`, already fixed) are reserved purposes.
- [CRYPTO.md §9.4](../CRYPTO.md#94-algorithm-registry) / [ADR 0007](0007-ciphertext-envelope.md) §3: algorithm `0x03`, "chunked/streaming variant of 0x01 for attachments" / "reserved: chunked attachments (M3)", "reserved for the M3 ADR".
- [ADR 0018](0018-item-record-encoding.md) §7: the `attachment/` field-key prefix is reserved, "a new key needs a line in the ADR that ships it, never a version bump" — no supersession needed to fill it. §3's record kind `0x04` is **not** for attachments; it is reserved for M5 `SHARE_SNAPSHOT` (ADR 0063's). Attachments need no new record kind: metadata lives in ordinary item fields (kinds `0x01`/`0x02`), and chunk ciphertext never passes through the item-record parser at all.
- [ADR 0011](0011-storage.md), "Attachments (M3)": "Out of scope here. The M3 attachments ADR chooses between DB blobs and a separate blob store."

Constraints: the server never decrypts ([rizzy-domain-vault](../../crates/rizzy-domain-vault/src/lib.rs) module doc, V, 5a78bb5: "It stores and forwards. It never decrypts and never merges"), so it cannot discover which attachment ids a vault still references; deletion must be an explicit call. [ADR 0028](0028-api-v1-http-conventions.md) item 7 fixes 1 MiB as the default request-body limit for every endpoint not named otherwise, and item 1's rationale bars ids from URLs (INV-52). [THREAT_MODEL](../THREAT_MODEL.md) G-1/AST-7 count attachments among the confidential item plaintext; INV-9/10/11 (envelope, allow-list, commitment) and INV-13 (AAD binding) are the invariants an attachment chunk must also satisfy. The M1 storage-quota ADR (this batch, "ADR 0048") owns the single account-level byte quota; this ADR counts attachment bytes against it but does not redefine it.

## Decision

### What this ADR supersedes

[ADR 0007](0007-ciphertext-envelope.md) §3, the row whose first cell is `0x03`. Replacing text, complete in itself: `| 0x03 | reserved; not used by attachments — a real streaming/incremental AEAD needs its own ADR |`. Attachments use `0x01` (Decision 1); `0x03` is freed, not committed to a future construction.

### 1. Chunking reuses the existing envelope; no new construction

Each chunk is an ordinary algorithm-`0x01` envelope ([CRYPTO.md §9.1](../CRYPTO.md#91-symmetric-envelope-algorithm-0x01), unchanged layout, [§8.3](../CRYPTO.md#83-key-commitment) commitment unchanged) under the attachment key, purpose `ATTACHMENT_CHUNK` (0x0033). `ctx = vault_id ‖ item_id ‖ attachment_id ‖ u32 chunk_index ‖ u32 chunk_count`. A chunk moved to another index, another attachment, or opened against a different `chunk_count` fails the commitment before the AEAD runs ([§9.5](../CRYPTO.md#95-parsing-and-allow-list-rules) rule 1). Algorithm `0x03` stays reserved and **undefined**; this ADR does not consume it (Alternatives, Route B; What this ADR supersedes, above). `0x01`'s existing per-purpose allow-list (`{0x01}` for every symmetric purpose, [§9.5](../CRYPTO.md#95-parsing-and-allow-list-rules) rule 2) already covers `ATTACHMENT_CHUNK`, and [§8.5](../CRYPTO.md#85-plaintext-framing-and-padding)'s framed-purpose list already omits it — chunks are unpadded, by text already in force. Neither section needs editing.

`chunk_count` is **never** read from the server. The client derives it from `attachment/<id>/size` (below) as `ceil(size / CHUNK_SIZE)`, the same value on seal and on open, so no server-supplied number enters any AAD (the purpose-binding rule already general in §8.4: "the reader rebuilds … from where it expected the object to be").

### 2. Chunk size and the per-attachment cap

`CHUNK_SIZE = 512 KiB` (524 288 bytes) plaintext. `MAX_ATTACHMENT_LEN = 25 MiB` (26 214 400 bytes), both compiled in (no config), giving at most 50 chunks. Rationale, computed from facts already fixed elsewhere, not measured: a chunk envelope under JSON/base64url ([CRYPTO.md §9.6](../CRYPTO.md#96-encoding-for-transport-and-storage)) is `⌈(524288+90)/3⌉×4 ≈ 699 KiB`, about 65 % of [ADR 0028](0028-api-v1-http-conventions.md) item 7's universal 1 MiB default body limit — comfortably under it with JSON-field margin, so upload needs no large-body allowance and no ADR 0028 edit. 25 MiB keeps the iOS AutoFill ~120 MB memory ceiling (L, [CRYPTO.md §6.4](../CRYPTO.md#64-feasibility)) and the web vault's in-memory-only model ([ADR 0011](0011-storage.md), "Clients") workable one chunk at a time, and sits inside the task's 25–50 MiB range at its conservative end. Streaming encrypt/decrypt loops live in `rizzy-client`/leaves (ADR 0016 R1, INV-58), never in `rizzy-core`.

### 3. The attachment key and its wrap

`ATTACHMENT_KEY_WRAP` uses the ctx [CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes) already fixes, verbatim. It is **never** re-wrapped when the item key rotates, lazily or otherwise: a vault-key rotation re-wraps `ITEM_KEY_WRAP` (the wrap, not the item-key value, [§11.6](../CRYPTO.md#116-key-rotation) step 3), and old item keys stay retained and readable forever. The wrap's envelope header already carries the item key's `key_id` (§9.1), exactly as `ITEM_OP`/`ITEM_SNAPSHOT` do, so a reader opens it with whichever item key that `key_id` names — but *obtaining* the wrap bytes on a device other than the creator is new, and it does not ride the `vault/fetch` wrap-set response the way `ITEM_KEY_WRAP` does: that response is filtered by `vault_key_epoch` ([ADR 0012](0012-sync-engine.md) §7), and this wrap, never re-wrapped, carries no epoch to clear that filter past the first fetch. §6 below adds `attachments/get` for exactly this read. No new field, no re-wrap step. Creating an attachment is itself a write under the item key, so it follows the existing writer rule: a stale item key is rotated first ([§11.6](../CRYPTO.md#116-key-rotation) "Writer rule (MUST)").

### 4. Item metadata: field keys under `attachment/`

| Key | Value | Notes |
|---|---|---|
| `attachment/<id>/name` | Text | filename, as entered |
| `attachment/<id>/mime` | Text | declared, not content-sniffed |
| `attachment/<id>/size` | U64 | plaintext byte length; client-only display value, never trusted by the server |
| `attachment/<id>/order` | SortKey | list order, as `uri/<id>/order` |

No `attachment/<id>/wrap` field exists: the wrap travels only through `attachments/get` (§6), never through item data, so [ADR 0018](0018-item-record-encoding.md) §7's "a new key needs a line in the ADR that ships it" has nothing to discharge here.

`<id>` is the attachment's own 16-byte id, so one id names both the list element and the storage row. Existence follows [ADR 0018](0018-item-record-encoding.md) §6: the element exists while `/name` (or another content attribute) is non-empty; clearing it removes the attachment from the item but, per §4's "Registers are never dropped" rule, does not by itself delete the blob (§7 below). The client MUST write `/size` equal to the `total_plaintext_len` it declares at `create` (§6): the client's `chunk_count = ceil(size / CHUNK_SIZE)` and the server's `ceil(total_plaintext_len / CHUNK_SIZE)` are then the same number by construction, never two sources that can disagree.

### 5. Storage shape (completes ADR 0011's deferred choice: DB blobs)

Two new `vault_`-prefixed tables ([ADR 0011](0011-storage.md) rule 5, domain `vault`, owned by `rizzy-domain-vault`/`rizzy-storage`):

- `vault_attachments(attachment_id, vault_id, item_id, attachment_key_wrap BLOB, total_plaintext_len, chunk_count, created_at_ms)`.
- `vault_attachment_chunks(attachment_id, chunk_index, chunk_envelope BLOB, PRIMARY KEY(attachment_id, chunk_index))`.

Rows go through sqlx on SQLite/PostgreSQL exactly like every other domain table, covered by the existing engine-neutral logical backup/restore ([ADR 0011](0011-storage.md) "Backups") with no separate blob-store backup to run — at the dump-size cost named in Consequences, Negative. `cargo xtask check-tables` enforces the `vault_` prefix as it already does for every other table.

### 6. API: five endpoints, all small-bodied, no ADR 0028 edit

| Method, path | Request → response | Session |
|---|---|---|
| `POST /api/v1/attachments/create` | declares `attachment_id, vault_id, item_id, attachment_key_wrap, total_plaintext_len` → 204 | OPAQUE or device |
| `POST /api/v1/attachments/get` | `attachment_id` → `attachment_key_wrap` | OPAQUE or device |
| `POST /api/v1/attachments/upload-chunk` | `attachment_id, chunk_index, envelope` → 204 | OPAQUE or device |
| `POST /api/v1/attachments/download-chunk` | `attachment_id, chunk_index` → `envelope` | OPAQUE or device |
| `POST /api/v1/attachments/delete` | `attachment_id` → 204 | OPAQUE or device |

`get` is the read path §3 needs: any device holding the item key fetches the wrap once, over the authenticated session, and unwraps it locally. It returns the wrap only — never `chunk_count` or `total_plaintext_len` — so no server-supplied number enters an AAD (Decision 1 is unchanged by this endpoint).

All five extend [ADR 0028](0028-api-v1-http-conventions.md) item 1's table additively, under a new `attachments` resource group (the 10th, after the base nine, in ADR-number order across this batch); Open questions gives the formal replacement text if the owner wants the table itself edited instead. No request exceeds the universal 1 MiB default (item 7 unedited); no response exceeds one chunk. `download-chunk` keeps the id in the body, matching item 1's own INV-52 rationale (no id in a URL).

`create` MUST reject a declared `total_plaintext_len` over `MAX_ATTACHMENT_LEN` or over the account's remaining ADR-0048 quota, charging the quota atomically with the row insert; `chunk_count` is derived server-side the same way (`ceil(total/CHUNK_SIZE)`) purely to size the table, never fed into any AAD. `upload-chunk` MUST reject `chunk_index ≥ chunk_count` and a ciphertext longer than `CHUNK_SIZE + 90` (only the last index may be shorter, by exactly what `total_plaintext_len` implies); without this check the cap and the quota are advisory. **Ownership.** All five endpoints resolve `attachment_id` through the authenticated session's account (`vault_attachments.vault_id` must be a vault the account holds), the same shape every vault endpoint already uses; an id belonging to another account answers `not_found`, never a distinct error — otherwise `get`, `download-chunk` and `delete` are an IDOR surface (THREAT_MODEL A15). Retries reuse [ADR 0028](0028-api-v1-http-conventions.md) item 3's closed error set unchanged for everything but the cap: a byte-identical repeat of `create` or `upload-chunk` is a no-op success, a conflicting one is `record_conflict`; an unknown or foreign `attachment_id` or index is `not_found`. This ADR defines no error code of its own: none of item 3's fourteen existing codes fits a declared-size rejection in a JSON field (`payload_too_large` is a `Content-Length`/frame check, item 7, not this), so `create`'s over-cap and over-quota rejections use the code the sibling storage-quota ADR ("ADR 0048") defines for exactly this case — a dependency this ADR carries into Open questions.

### 7. Deletion and garbage collection

`attachments/delete` removes both tables' rows for that id and releases its counted bytes from the ADR-0048 quota in the same transaction; the GC sweep below does the same. **Ordering that bounds the orphan risk:** a client MUST write (or queue) the item op that adds the `attachment/<id>/…` fields referencing an attachment before, not after, that attachment's last chunk finishes uploading. An interruption then always leaves either no reference (nothing to clean up beyond the sweep) or a *dangling* reference — visible to every device, self-healing: `download-chunk` or `get` on it answers `not_found`, and the client re-uploads or clears the field. The failure mode this rules out is the opposite order: a complete, unreferenced blob no device can ever name. `worker` ([ADR 0010](0010-server-shape.md) §1, the role table's "scheduled deletion" duty; its locking mechanics are §2 and are not what is cited here) sweeps `vault_attachments` rows with `created_at_ms` over 24 h old and a stored chunk count still short of `chunk_count` (mirrors ADR 0011's 24 h pre-migration-copy pattern), deleting the row and its chunks and releasing the quota. A fully-uploaded, referenced attachment later orphaned by a client that skips `delete` is a residual risk, not caught by this sweep (Open questions).

### 8. Tests ([CRYPTO.md §15](../CRYPTO.md#15-testing))

Added in this milestone, as §15 item 1 already provides for M3 constructions: normative vectors (tier A, `crates/rizzy-core/tests/vectors/`) for a single-chunk and a three-chunk attachment with a short final chunk, and for `ATTACHMENT_KEY_WRAP`, nonces fed through the injected RNG (§15 item 1). Negative vectors: a chunk opened at the wrong `chunk_index`; a chunk from another `attachment_id`; a chunk opened against a `chunk_count` derived from a different `size` — each fails the commitment before the AEAD (§15 item 4's ordering). Reassembly property tests for the completeness rule below: `chunk_count − 1` delivered chunks never assemble; an extra chunk past `chunk_count` is refused. Chunk envelopes are ordinary 0x01 envelopes, so the existing envelope-parser fuzz target (§15 item 7) already covers their parse; the reassembly path (index/count handling over untrusted input) gets its own fuzz target, per CLAUDE.md's "untrusted input is size-limited and parsed without panics, add a fuzz target".

**Proposed INV text** (allocated across the 2026-10-11 batch in ADR-number order. Provisional: the allocation was made across the 2026-10-11 batch in ADR-number order; if ADRs are accepted out of order, the owner renumbers at acceptance.): *(a, INV-78)* an attachment chunk's AAD binds `vault_id, item_id, attachment_id, chunk_index, chunk_count`; a chunk served at another index, for another attachment, or under a different declared size fails to decrypt. *(b, INV-79)* a client assembles an attachment only after verifying exactly `chunk_count` chunks, indices `0..chunk_count-1`, each decrypted; a short or long set is reported, never assembled. *(c, no new id)* INV-15's canary extends to attachment chunk plaintexts, `attachment_key_wrap` plaintext and the unwrapped attachment key.

**On-acceptance edits.** CRYPTO.md: §8.4's `ATTACHMENT_CHUNK` row — algorithm "0x03 (reserved)" → "0x01"; ctx → as in Decision 1. §8.4's "Attachment keys (M3)" sentence "The chunked envelope (algorithm 0x03) is the M3 attachments ADR's to define" → chunks are `ATTACHMENT_CHUNK`/0x01 envelopes; 0x03 stays reserved, undefined. §9.4's `0x03` row — Construction: "chunked/streaming variant of 0x01 for attachments" → "undefined"; Status: "reserved for the M3 ADR" → "reserved; undefined; a real streaming/incremental AEAD needs its own ADR and CRYPTO.md section" (consistent with What this ADR supersedes, above). §4.2's `ATTACHMENT_KEY_WRAP` storage-location cell → "Server, `vault` domain: the `vault_attachments` row for that `attachment_id`; read back only via `attachments/get` (§6)." THREAT_MODEL.md §3.4 gains the row given in Consequences, Negative, below, and the M3 transparency page follows it. Separately, as the owner's act on acceptance ([ADR 0020](0020-partial-supersession.md) point 9): ADR 0007's status line gains "Partially superseded by ADR 0054 (§3 in part)"; its text is otherwise unedited.

## Consequences

### Positive
- No new audit target (CRYPTO.md §1 rule 2's list is unchanged): chunking is an existing envelope under an existing purpose with a now-fixed ctx.
- Attachments ride the existing `vault_` table conventions; no second blob-store *code path* to build, test or fuzz — see Negative for the backup-size cost this still carries.
- The per-attachment cap and chunk size fit every self-hoster's default config (ADR 0028 item 7, item 12) with zero operator action.

### Negative
- 50 small requests for a 25 MiB attachment is more round trips than one large upload; acceptable for M3's first cut, parallelisable by the client.
- A fully-uploaded, referenced attachment later orphaned by a client that never calls `delete` is not caught by the 24 h sweep and bills the quota until a future reconciliation flow exists.
- **New metadata leak.** [THREAT_MODEL §3.4](../THREAT_MODEL.md#34-what-the-server-holds-by-sync-mode)'s "ciphertext sizes" row and [NG-5](../THREAT_MODEL.md#14-non-goals) were written for Padmé-padded envelopes and concede only "approximate item count and sizes". `ATTACHMENT_CHUNK` is unpadded (Decision 1) and `total_plaintext_len` is declared in the clear (Decision 6), so the server now learns an attachment's exact plaintext byte count, plus a new per-item attachment count neither row describes. §3.4 gains a row for this in the same change ([ADR 0011](0011-storage.md) "No plaintext": "Adding a clear-text column requires a THREAT_MODEL change in the same PR"), and the M3 transparency page follows.
- **Backup growth.** [ADR 0011](0011-storage.md)'s Risks flagged that DB-only storage would need "the M3 blob-store decision" if data grows beyond what fits in rows; this ADR answers that by choosing rows (Decision 5), which means the logical-backup dump (ADR 0011 "Backups") now scales with total attachment bytes — a 25 MiB attachment is roughly 50 rows in every dump — inflating `rizzy-vault backup`/`restore` size and time, and the M8 remote-backup destinations (siblings 0071/0072) by the same sum. Accepted for M3; revisit before M8 if dump size or restore time proves unacceptable.
- Two new tables and five new endpoints to review, test and fuzz.

### Risks
- `MAX_ATTACHMENT_LEN` or `CHUNK_SIZE` could prove too small. Signal: users hitting the 25 MiB cap, or round-trip-latency complaints on large attachments; either triggers the larger-chunk, large-body transport in Alternatives, not a silent constant bump.
- A malicious server can withhold a chunk on download; the client-side completeness check (proposed INV-79) turns that into a reported gap, not silent corruption — the same residual class THREAT_MODEL already accepts for withheld ops. Signal for revisiting: none expected before M9's hostile-server review.

## Alternatives considered

- **Route B: a real streaming/incremental AEAD under algorithm `0x03`.** Lower per-chunk overhead at large sizes, but it is a new construction (CRYPTO.md §1 rule 2) needing its own ADR and CRYPTO.md section first (Open questions). Deferred.
- **One-shot upload inside ADR 0028's existing large-body allowance** (`RIZZY_MAX_UPLOAD_BYTES`). Rejected on the arithmetic in Decision 2: 25 MiB base64'd (~33.3 MiB) exceeds item 7's own 32 MiB *minimum*, so it would force every self-hoster to raise a config value just to receive the default cap.
- **A separate object store** (S3/filesystem) instead of DB rows. Simpler at very large sizes, but it is a second backup surface and a second storage interface before M8's remote-backup ADRs exist; ADR 0011 left exactly this choice open, and DB rows answer it for M3 (at the backup-growth cost in Consequences, Negative).
- **Attachment bytes as item-field values.** Would blow every §10 item-record size limit and defeat independent fetch/delete of one attachment; rejected without a spike.

## Open questions for the owner

1. **Chunk size and cap.** *Recommendation:* 512 KiB / 25 MiB as in Decision 2 — fits the existing config floor with no operator action.
2. **Formalising the endpoint-table growth.** ADR 0028's preamble says its items change pre-v1.0 "only under ADR 0002 point 5," though item 1 names "new endpoints" as additive text elsewhere (ADR 0002 point 3). *Recommendation:* additive, no supersession — the five new rows contradict no existing one. This ADR adds 5 endpoints (the `attachments` resource group) to item 1's base of 27, for 32; sibling ADRs 0064 (+4), 0066 (+1) and 0068 (+3) each add their own delta on top of this one in ADR-number order, for a cumulative 40. If the owner wants the formal route instead, the full replacing text for ADR 0028 item 1's first sentence is: "The 32 endpoints of `rizzy-server` `http/api.rs` (module table), under `/api/v1/`, grouped by resource, verb last; `POST` for everything, including reads that carry a body; `GET` (and `HEAD`) only for `GET /api/v1/devices/grants`."
3. **The fully-uploaded, dereferenced-without-`delete` orphan.** *Recommendation:* accept as a known M3 gap (Negative consequences); add a client-side "reconcile my attachments" sweep (list owned attachment ids server-side, compare against referenced ids client-side, batch-`delete` the rest) in a later milestone rather than blocking M3 on it.
4. **Whether to reserve `0x03` for a future streaming construction now, or leave it fully open.** *Recommendation:* leave it open; nothing here needs it, and committing to streaming AEAD specifics without a spike risks a second ADR anyway.
5. **Dependency on ADR 0048's error code.** Decision 6's `create` over-cap/over-quota rejection needs the wire error code the sibling M1 storage-quota ADR ("ADR 0048") defines; it is not yet Accepted. *Recommendation:* land 0048 at or before 0054's acceptance, and cite its code here in the same change — 0054 should not be Accepted while this is unresolved.

## References

- [ROADMAP](../ROADMAP.md) §4.2, §4.7
- [THREAT_MODEL](../THREAT_MODEL.md) G-1, AST-7, INV-9, INV-10, INV-11, INV-13, INV-15, INV-27 (withholding precedent), §3.4 (gains a new row for attachment sizes/counts in this change, Consequences Negative), NG-5
- [CRYPTO.md](../CRYPTO.md) §2, §4.1, §4.2, §6.4 (L: AutoFill memory figure), §8.3, §8.4, §8.5, §9.1, §9.4, §9.5, §9.6, §11.6, §15
- [ADR 0007](0007-ciphertext-envelope.md) §3 (partially superseded by this ADR, above); [ADR 0009](0009-crypto-dependency-policy.md); [ADR 0010](0010-server-shape.md) §1 (`worker` role table), §2 (locking, not cited for the sweep duty); [ADR 0011](0011-storage.md) rule 5, "Backups", "Clients", "No plaintext", "Attachments (M3)", Risks; [ADR 0012](0012-sync-engine.md) §7 (wrap-set delivery, filtered by epoch); [ADR 0016](0016-workspace-layout.md) R1; [ADR 0018](0018-item-record-encoding.md) §3, §6, §7; [ADR 0020](0020-partial-supersession.md) point 9; [ADR 0025](0025-rotation-vault-half.md) §1; [ADR 0028](0028-api-v1-http-conventions.md) items 1, 3, 7, 9, 12; the sibling M1 storage-quota ADR ("ADR 0048") for the account-level counter this ADR charges and whose error code Decision 6 depends on (Open questions 5).
- Code read at branch head 5a78bb5 (V): `crates/rizzy-domain-vault/src/lib.rs`; `crates/rizzy-storage/migrations/sqlite/0002_vault_initial.sql` (table-prefix precedent); `crates/rizzy-proto/src/limits.rs` (`MAX_UPLOAD_BODY_LEN`, body-limit doc style); `crates/rizzy-server/src/http/api.rs` (item-1 endpoint table).

<!-- All six cited blockers checked out against the sources named above (ADR 0007 §3, ADR 0010 §1/§2, ADR 0011 "No plaintext"/Risks/Backups, ADR 0018 §7, ADR 0020 point 9, ADR 0028 item 3/7, ADR 0012 §7, THREAT_MODEL §3.4/NG-5, CRYPTO.md §8.4/§8.5/§9.4); none was itself mistaken, so none is kept unchanged with a rebuttal. -->
