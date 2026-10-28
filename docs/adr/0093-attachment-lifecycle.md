# ADR 0093: Attachment lifecycle: cleanup after Purge, export and import, and unsupported items on move

- Status: Accepted
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M3
- Supersedes: on acceptance, in part: [ADR 0054](0054-attachments-envelope-and-api.md) (§7 in part), [ADR 0027](0027-export-payload.md) (§2 in part, §6 in part), [ADR 0081](0081-multiple-vaults-personal-and-shared.md) (§A5 in part, §A6 in part). "What this ADR supersedes" names the parts and gives the replacement text ([ADR 0020](0020-partial-supersession.md) point 9).

## Context

**Trigger.** The 2026-10-25 ADR gap review ([docs/reviews/2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md)) lists three attachment-lifecycle gaps, D1, D2 and D6. The owner said "start" (2026-10-25) to fixing the gaps. The raw findings, with quotes and file:line, are in [G06.md](../reviews/2026-10-25-raw/G06.md) (G06-1, G06-2), [G03.md](../reviews/2026-10-25-raw/G03.md) (G03-12) and [G08.md](../reviews/2026-10-25-raw/G08.md) (G08-8).

[ROADMAP §4.2](../ROADMAP.md#42-core-vault-m1), Should, M3: "Attachments (encrypted, size-limited)". This ADR adds no scope; it closes holes in the accepted design behind that row.

### D1 (G06-1): a Purge never deletes the item's attachments

- [ADR 0054](0054-attachments-envelope-and-api.md) §7: "`attachments/delete` removes both tables' rows for that id and releases its counted bytes from the ADR-0048 quota in the same transaction; the GC sweep below does the same." The sweep covers only rows "with `created_at_ms` over 24 h old and a stored chunk count still short of `chunk_count`". §7 ends: "A fully-uploaded, referenced attachment later orphaned by a client that skips `delete` is a residual risk, not caught by this sweep". ADR 0054's owner answer 3 accepts orphans from a client that *skips* `delete` "as a known M3 gap"; no binding text tells any client to call it when an item goes away.
- [ADR 0012](0012-sync-engine.md) §5: "**Only clients purge.** Lifecycle is encrypted, so the server cannot see which items are trashed or since when". [ADR 0021](0021-server-compaction.md) §5: "The server cannot tell a tombstone snapshot from a live one". The server cannot cascade on a Purge: it never learns that one happened (V, read).
- What the server *does* know: `vault_attachments(attachment_id, vault_id, item_id, attachment_key_wrap, total_plaintext_len, chunk_count, created_at_ms)` (ADR 0054 §5). The client declares `item_id` at `attachments/create`; the server stores it, and no endpoint uses it (V, read).
- [ADR 0081](0081-multiple-vaults-personal-and-shared.md) §A6 step 2: a move is a copy, then "a `Trash` op and a `Purge` op on the source item in one upload". Step 1 re-uploads every attachment "under a new `attachment_id` and attachment key in the target". The source's blobs stay. §A5's vault delete is different: "The server deletes the vault row and everything that cascades from it (self-grant, wraps, ops, snapshots, attachments and their chunks)" and releases the bytes in the same transaction.
- Code, as read at `262bbd0` (V, read or grep):
  - `rv` never sends `attachments/delete`: no file under `crates/rizzy-cli/src` names it. `Command::ItemPurge` calls `VaultSync::purge_item` (`crates/rizzy-cli/src/commands.rs` ~230); `Device::auto_purge` calls `auto_purge_due` per vault (`crates/rizzy-cli/src/device.rs` ~1633). Neither touches attachments.
  - The Web app's manual purge deletes first: `apps/web/src/core-worker.ts` ~353, "ADR 0054 §7: the item's attachments go from the server first", calls `deleteAttachmentsOf(id)`, then `purgeItem(id)`. Its auto-purge (`packages/core/src/index.ts` ~1640 and ~3457, `s.autoPurge(now)`) and its move (`#copyInto`, then `finishMoves`, ~2455–2490) send no delete for the source.
  - `crates/rizzy-client/src/items.rs` `purge_item` (~626) and `auto_purge_due` (~665), and `vaults.rs` `PendingMove::finish` (~819, "a `Trash` op (unless trashed) and a `Purge` op on the source"), have no attachment handling.
  - `apps/extension/src` names neither `attachments/delete` nor a purge.

So on `rv` every purge of an item with attachments, and on every client every auto-purge and every §A6 move, leaves complete blobs. They count against the [ADR 0048](0048-per-account-storage-quota.md) quota forever, and nothing in the account ever names them again.

### D2 (G06-2, G03-12): export and import silently create dangling attachments

- [ADR 0027](0027-export-payload.md) §1 exports every live item "with its registers and history exactly as the merge holds them, unknown keys and unsupported values included", so the `attachment/<id>/name`, `/mime`, `/size` and `/order` fields of ADR 0054 §4 are in the file. The blob, the attachment key and its wrap are not: the wrap "travels only through `attachments/get` (§6), never through item data" (ADR 0054 §4). `grep -ci attach docs/adr/0027*.md` = 0 (G06-2).
- §2 step 3 writes "each register's **displayed** value …, unknown keys included, byte for byte" into a new item under a new `item_id`. An attachment's wrap is bound to `vault_id ‖ item_id ‖ attachment_id` ([CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes), `ATTACHMENT_KEY_WRAP`), so even in the same account the old blob could never serve the new item. Every imported attachment element is dangling from birth: `get` answers `not_found`, and the user learns that the file is gone only on opening it. G03-12: "exports carry attachment metadata without content or keys, so import creates dangling attachments and loses data silently".
- ADR 0081's copy path already strips them: `crates/rizzy-client/src/vaults.rs` ~622, `.filter(|(_, key, _)| !key.as_str().starts_with("attachment/"))`, then the host re-uploads each attachment under a new id (V, read). Two paths over the same importer disagree.
- Embedding the blobs does not fit ADR 0027: the payload holds at most 16 MiB of plaintext (`MAX_PLAINTEXT_LEN`, §1), and one attachment may be 25 MiB (ADR 0054 §2, owner answer 1).

### D6 (G08-8): unsupported items on a cross-vault move, and on "move items to Personal, then delete"

- [ADR 0078](0078-retire-bank-account-type.md) §1: `0x0009` is retired; "no writer creates an item of it"; to a client it is "an **unsupported** item in the sense of ADR 0018 §8's 'Unknown type' bullet", and "`check_write` refuses a create of it". §3: an own-format read-back "skips a `0x0009` entry and counts it in the import report".
- ADR 0081 §A6 step 1 makes a copy "through the importer path ADR 0027 §2 step 3 already uses". That path refuses any type that is not a supported user type: `check_import` returns `ClientError::InvalidEdit` unless the type's `supported()` value `is_some_and(SupportedType::is_user_item)` (`crates/rizzy-client/src/items.rs` ~288–296; V, read). So a `0x0009` item, or an item of a type a newer client added, can be neither copied nor moved.
- §A5 offers "**Move its N items to Personal, then delete**" with no rule for an item that cannot be moved. Today both clients abort the whole delete on the first refusal, after moving the items before it: `rv`'s `delete_vault` propagates `move_item`'s error (`crates/rizzy-cli/src/device/vaults.rs` ~636–646), and the Web client's `deleteVault` awaits `#copyInto` in a loop (`packages/core/src/index.ts` ~2416–2420; V, read). Nothing is lost today, but no ADR says it must stay that way: a client that skipped the item and went on would delete it with the vault. G08-8: "the importer path refuses the type, so the item can be lost silently with the vault".

### Forces

- Fail toward duplicates, never toward loss (ADR 0081 §A6 step 3, proposed INV-104: "The worst case is a duplicate, never a loss"). A blob may be deleted only once nothing can bring its item back. A receiver applies every Purge ("A Purge is never rejected", [ADR 0018](0018-item-record-encoding.md) §3), but only once the server holds the Purge is it sure to reach every device.
- The server learns nothing new about content. `item_id` is already stored in cleartext with every attachment row. The server still never learns which items are trashed or purged, beyond the timing of a cleanup request (Risks).
- No new crypto, envelope, purpose id or `item_schema_version`. This ADR adds one endpoint, one storage index and one client cache table.

## Decision

### What this ADR supersedes

Each replacement is complete in itself ([ADR 0020](0020-partial-supersession.md) point 9).

1. **[ADR 0054](0054-attachments-envelope-and-api.md) §7, its last sentence.** Replaced text: "A fully-uploaded, referenced attachment later orphaned by a client that skips `delete` is a residual risk, not caught by this sweep (Open questions)." Replacing text: "When an item is purged, its attachments are deleted by the cleanup step of [ADR 0093](0093-attachment-lifecycle.md) §1 through `attachments/delete-item`; the server never infers a purge. An attachment that stays orphaned anyway is a residual risk, not caught by this sweep (owner answer 3). It arises when a fully-uploaded attachment is dereferenced without a delete while its item stays live, or when no device ever runs the cleanup of its item."
2. **[ADR 0027](0027-export-payload.md) §2 step 3, its first bullet.** Replaced text: "each register's **displayed** value (ADR 0018 §6 display rules), unknown keys included, byte for byte; element ids (`uri/<id>`, `field/<id>`) kept;". Replacing text: "each register's **displayed** value (ADR 0018 §6 display rules), unknown keys included, byte for byte, except every key under the `attachment/` prefix ([ADR 0054](0054-attachments-envelope-and-api.md) §4), which is never written ([ADR 0093](0093-attachment-lifecycle.md) §2); element ids (`uri/<id>`, `field/<id>`) kept;".
3. **[ADR 0027](0027-export-payload.md) §2 step 4.** Replacing text, in full: "4. **Per-item refusals do not refuse the file.** An item the schema layer refuses (for example an unknown item type) is skipped. The import report counts skipped items, fields whose concurrent values collapsed to the displayed one, history entries not carried (histories of other fields), and attachments not carried: each `attachment/<id>` element of an imported item that exists by ADR 0018 §6 ([ADR 0093](0093-attachment-lifecycle.md) §2). The report names no value ([INV-48](../THREAT_MODEL.md#8-security-invariants))."
4. **[ADR 0027](0027-export-payload.md) §6, the "Writes" bullet** (binding only as far as §6 binds). Replacing text, in full: "- **Writes.** `item.type` = `type` (a `fields` entry with that key is ignored); `import.created_ms` = `created_ms` when present; each field's value under its key, except keys under the `attachment/` prefix, which are dropped and counted as §2 step 4 says ([ADR 0093](0093-attachment-lifecycle.md) §2); `history` of `login.password` as in §2 step 3 (at most 50, more are counted); a `trashed` item is created, then trashed. Every write passes `rizzy-core`'s `check_carried` for `WriteMode::Import`: any key of the grammar and any value bytes within §10 are kept verbatim and show as unsupported where unknown (ADR 0018 §6, §11; open question 5). Writes beyond one op's limits split as §2 step 5."
5. **[ADR 0081](0081-multiple-vaults-personal-and-shared.md) §A5, its first bullet.** Replacing text, in full: "- Only an owned (kind 2) vault, only by its owner. The UI offers two choices, the first preselected: **"Move its N items to Personal, then delete"** (each item moved as §A6 says, then the vault deleted), or **"Delete the vault and its N items"**. Both need the vault's name typed as confirmation. If the vault holds an unsupported item, Active or Trashed ([ADR 0093](0093-attachment-lifecycle.md) §3), the first choice is refused before any item is moved, and the second names how many unsupported items it deletes."
6. **[ADR 0081](0081-multiple-vaults-personal-and-shared.md) §A6 step 4.** Replacing text, in full: "4. A move needs quota headroom for the copy (both exist for a moment); a `quota_exceeded` refusal aborts before the source is touched. The vault-settings item is never copied or moved (clients never list it). An unsupported item ([ADR 0093](0093-attachment-lifecycle.md) §3) is never copied or moved: the client refuses with `unsupported_item` before it writes the pending-move row."

Nothing else in ADRs 0012, 0018, 0027, 0048, 0054, 0078 or 0081 changes. ADR 0054 §6's endpoint table grows by one row, additively, the way ADR 0054's owner answer 2 accepted for ADR 0028 item 1. ADR 0054 §5's tables gain one index and no column.

### 1. Cleanup after a Purge (D1)

#### 1.1 Who deletes: the client, through one per-item endpoint

The server cannot cascade (Context), so the client deletes. It deletes **by item, not by attachment id**. After a Purge the item's state is a tombstone, which names no attachments. And the attachments a device's merged state names are not always all the attachments the server holds for the item: there may be a concurrent add, an upload still in progress, or a field cleared without a delete. The server already holds the `item_id` of every row.

The new endpoint belongs to ADR 0054 §6's `attachments` resource group and follows [ADR 0028](0028-api-v1-http-conventions.md)'s conventions:

| Method, path | Request → response | Session |
|---|---|---|
| `POST /api/v1/attachments/delete-item` | `vault_id, item_id` → 200 `{ "remaining": bool }` | OPAQUE or device |

- **Body.** `AttachmentItemRequest { vault_id, item_id }`. Both are 16-byte ids, encoded the way `AttachmentRequest` encodes `attachment_id` (`rizzy-proto`). Unknown members are refused (`deny_unknown_fields`, as `AttachmentRequest`). The body is far below ADR 0028 item 7's 1 MiB.
- **Access.** The server applies to `vault_id` the same check that `attachments/create` applies for the caller's account. A vault the caller may not write, or one that does not exist (including one deleted under ADR 0081 §A5), answers `404 not_found`.
- **Effect.** One account-locked transaction (`lock_account`, as in `delete_attachment`) selects at most **16** `vault_attachments` rows with this `(vault_id, item_id)`, complete or not. It deletes them and their `vault_attachment_chunks`, and releases their counted bytes from `storage_account_usage` (ADR 0048 §2, with the per-record size function that `attachments/delete` uses). `remaining` is `true` when a row with this `(vault_id, item_id)` is left after the transaction. Zero matching rows is a success with `remaining: false`, never `not_found`, so the call is idempotent.
- **Batch bound.** 16 attachments of at most 50 chunks each (25 MiB / 512 KiB) bound one transaction at 816 deleted rows. A client repeats the call while `remaining` is `true`, at most **64** times per cleanup row per sync round (1,024 attachments; the quota keeps the real number far lower).
- **Storage.** A migration adds `CREATE INDEX vault_attachments_by_item ON vault_attachments(vault_id, item_id)` on SQLite and PostgreSQL. No column changes. `cargo xtask check-tables` is unaffected (no new table).
- **Rate limit.** ADR 0028's general per-session limits apply; no new class.
- The existing `attachments/delete` stays, for deleting one attachment from a live item. ADR 0054 §7's ordering rule is unchanged.

#### 1.2 When: after the server acknowledges the Purge, from a crash-safe cache row

A new client cache table holds cleartext ids only, like `pending_move` (ADR 0081 §A7):

```sql
CREATE TABLE attachment_cleanup(
  vault_id  BLOB    NOT NULL,   -- 16 B
  item_id   BLOB    NOT NULL,   -- 16 B
  purge_seq INTEGER NOT NULL,   -- device_seq of this device's Purge op; 0 = nothing of ours to wait for
  PRIMARY KEY (vault_id, item_id))
```

`cache_meta.format` **5** adds it ([ADR 0026](0026-client-device-state-and-cache.md) §5), with a migration in `MIGRATIONS` and `migration_writes` that creates the empty table. A cache of format 4 is upgraded before it is opened. A client that knows only format 4 refuses a format-5 cache, as it refuses any newer format.

A row is written in each of the following cases, in the **same cache write** that persists the state that causes it, so no crash can separate the two:

1. **Own Purge.** Every own Purge op writes a row with `purge_seq` = that op's `device_seq`: a manual `purge_item`, `auto_purge_due`, and ADR 0081 §A6 step 2's `PendingMove::finish`. The row is written whether or not the device's merged state names an attachment, because a device may not know of all of them.
2. **Received Purge.** A device writes a row with `purge_seq = 0` when it applies a received Purge to an item that its merged state held **live**, with at least one `attachment/<id>` element existing by ADR 0018 §6, and the Purge turns the item into a tombstone. This covers a purger that crashes or is wiped before its own cleanup. A device that only ever sees the tombstone writes nothing.
3. **Late op on a tombstone.** A device writes a row with `purge_seq = 0` when it surfaces a late op on a purged item (ADR 0012 §5, "Restore it as a new item?") and that op adds or names an `attachment/<id>` element, whatever the user answers. "Restore as a new item" restores field values only, and the prompt adds "Its attachments cannot be restored." This catches a blob that an offline device uploaded after the cleanup ran.

If a row for the same `(vault_id, item_id)` exists, it is kept, with `purge_seq = max(old, new)`.

**Running a row.** At the end of each sync round the client takes each row whose vault is open and has no unacknowledged own op with `device_seq ≤ purge_seq`, and sends `delete-item` for it as §1.1 says. Then:

| Answer | Action |
|---|---|
| 200, `remaining: false` | delete the row |
| 200, `remaining: true` | call again (at most 64 calls this round), then keep the row for the next round |
| `404 not_found` | delete the row (the vault is gone, and ADR 0081 §A5's cascade released the bytes) |
| network error, 5xx, `429`, `401` or an expired session | keep the row for the next sync round |
| any other 4xx | delete the row and report once: "Files of a deleted item could not be removed from the server and still count toward your storage." The report names no value (INV-48). |

A device that learns from the vault directory that a vault was deleted drops that vault's rows with its other cache rows (ADR 0081 §A5). Rows never block a sync round, an unlock or another vault, and a failed cleanup is never a sync error.

**Order: Purge first, delete second.** The blobs go only after the server holds the Purge. Deleting first, as the Web `purgeItem` does today, can lose files the user still has: the device crashes between the delete and the Purge upload, another device restores the item from the trash in the meantime, and the live item's files are gone. Purge-first can at worst leak until the next sync round of a device that holds a row. It never loses data.

**Quota.** The server releases the bytes in the delete transaction, as for `attachments/delete`. A client shows the new figure on its next usage read; it does not predict it.

**Vault deletion** (ADR 0081 §A5) needs no row: the server cascade already deletes every attachment of the vault and releases its bytes. "Move its N items to Personal, then delete" writes rows (case 1, through `finish`). They end with `404 not_found` once the vault is deleted, or with a real cleanup if the delete never happens.

#### 1.3 Client API (`rizzy-client`, mirrored by `rizzy-wasm` and `rv`)

`VaultSync`, or the multi-vault host that owns the cache, gains:

- `attachment_cleanups_due(&self) -> Vec<(VaultId, ItemId)>`: the rows runnable now (§1.2);
- `attachment_cleanup_request(vault_id, item_id) -> HttpRequest` for `delete-item`;
- `attachment_cleanup_respond(vault_id, item_id, status, body) -> Result<CleanupStep, ClientError>`, with `CleanupStep = Done | Again | Keep`, which applies the table above and writes the row change;
- the row writes of §1.2, inside the existing `purge_item`, `auto_purge_due` and `PendingMove::finish`, the received-op apply path and the late-op surfacing path. No host can purge without writing the row.

The one-time report uses the new client error code `attachment_cleanup_failed`. The other answers map to existing codes.

### 2. Export and import (D2)

- **Exports keep the fields and carry no contents.** ADR 0027 §1 is unchanged: the payload and plaintext JSON keep `attachment/<id>/name`, `/mime`, `/size` and `/order` byte for byte, as an inventory of the files the user had. No blob, key or wrap is ever exported (the 16 MiB limit and the 25 MiB attachment cap rule embedding out; see Context). CSV is unchanged (ADR 0027 §4).
- **The writer tells the user before writing.** When the exported vault has at least one existing attachment element, the export confirmation adds one line: "N files attached to M items are not included in the export. Their names are. Download the files separately first." That confirmation is the ADR 0027 §5 / ADR 0034 step that already comes before writing. `rv export` prints the same line to stderr, also when it runs non-interactively; no flag suppresses it. This adds to ADR 0027 §5 and ADR 0034 without replacing any of their text.
- **Every importer path drops `attachment/` keys.** `VaultSync::import_item_writes` and `import_item_writes_as` drop every write whose key starts with `attachment/` before `check_import`. They return, with the new item id, the number of distinct `<id>`s dropped whose element existed (ADR 0018 §6). This covers ADR 0027 §2 (encrypted read-back), §6 (plaintext JSON read-back), ADR 0081 §A6's copy, and any foreign importer. The copy's own filter (`vaults.rs` ~622) becomes redundant and is removed. No import ever writes a reference to an attachment the importing device did not upload under that item. The import report counts "attachments not carried" (supersession items 3–4).
- **Copy and move are unchanged in effect.** They drop the fields through the importer, then re-add each attachment by downloading it, decrypting it and uploading it under a new id (ADR 0081 §A6 step 1).
- The ADR 0027 §2 step 2 parser still parses and limit-checks a payload's `attachment/` fields before they are dropped. The drop is a write-side rule, so the existing fuzz targets for the readers keep their inputs.

### 3. Unsupported items on copy, move and vault delete (D6)

**Decision: refuse. An unsupported item is never carried opaquely.**

- *Unsupported* means a user item whose type this client does not support as a user type: `ItemType::supported()` is `None`, or its value is not `is_user_item`. That covers an unassigned or unknown id, a type a newer client added, and the retired `0x0009` (ADR 0078 §1). The vault-settings item (`0xF001`) is not a user item, and §A6 step 4 handles it as before.
- **Copy and move** of an unsupported item fail with the new client error `unsupported_item` (`ClientError::UnsupportedItem`). The check comes first, before the pending-move row (ADR 0081 §A6 step 3) or any write. It replaces today's `invalid_edit` from deep inside the importer with an explicit code. The UI says: "This item's type is not supported by this version, so it cannot be copied or moved. Update rizzy-vault, or copy its fields out by hand."
- **"Move its N items to Personal, then delete"** (ADR 0081 §A5): before the first move, the client counts the vault's unsupported items, Active and Trashed. If that count K is above zero, the choice is refused with `unsupported_item` and nothing is moved. The UI says: "K items of this vault cannot be moved (unsupported type). Copy their fields out by hand, update rizzy-vault, or delete the vault with its items." Both clients apply the check (`rv`'s `delete_vault`, `packages/core`'s `deleteVault`). It also sits inside `rizzy-client`'s bulk-move entry point, so a host cannot skip it.
- **"Delete the vault and its N items"** stays allowed. When K > 0, its confirmation names K: "including K unsupported items that this version cannot show in full".
- **A failed move-all never deletes the vault.** If a move-all fails for any other reason after moving some items, those items stay moved (each move is resumable, INV-104) and the vault is not deleted.

**Why refuse and not carry.** ADR 0078 §1 says "no writer creates an item of it", and `check_write` refuses that create. Carrying would need a second create path that skips the schema layer for exactly the items a client cannot interpret. That path would re-encrypt, under a new `item_id`, data whose meaning may be bound to the item (a future type), and it would supersede ADR 0078 §1. Refusing keeps the data where it is, visible and copyable by hand (ADR 0078 §1, §3), and it is never lost unless the user explicitly chooses "delete with its items". Open question 1 asks whether the retired `0x0009` alone should be carried.

### 4. Invariant (proposed INV-113)

**INV-113 (proposed): an item's attachments follow the item.**
- (a) Once the server has acknowledged a Purge of an item, every attachment row the server holds for that item is deleted and its bytes released, by the next completed sync round of any device that holds a cleanup row for it. The row is written in the same cache write as the Purge, or as the state that reveals it, so no crash drops it.
- (b) No attachment is deleted for a Purge before the server has acknowledged that Purge.
- (c) No import or copy writes an `attachment/<id>/…` field for an attachment that the writing device did not itself upload under that item.
- (d) Deleting a vault with "move its items" never deletes an item that was not moved.

### 5. Tests

- **Domain and storage** (`rizzy-domain-vault`, SQLite and PostgreSQL):
  - `delete_item_attachments` deletes the complete and incomplete rows of exactly one `(vault_id, item_id)`, and their chunks, and leaves another item's attachments untouched;
  - it releases the counted bytes in the same transaction (usage before and after);
  - 17 attachments: the first call returns `remaining: true`, the second `false`; zero rows return `false`;
  - another account's vault and a deleted vault answer `not_found`;
  - the index exists after the migration.
- **HTTP** (`rizzy-server/tests/http/attachments.rs`): the route, the body size, an unknown member refused, the session types, the status codes.
- **Client** (`rizzy-client`):
  - a row is written on each Purge path (manual, auto, `finish`);
  - crash between the Purge write and the upload: the row is there and nothing is sent;
  - crash after the ack and before the delete: the row runs the next round;
  - the `Again` loop stops at 64;
  - `not_found` and other-4xx answers remove the row, and the one-time report appears;
  - a received Purge writes a row only when the live state named attachments;
  - a late op that names an attachment writes a row;
  - a deleted vault drops its rows;
  - the format 4 → 5 migration;
  - a property test: random interleavings of purge, crash, ack and delete never send `delete-item` before the Purge's ack, and always end with no cleanup row and no server row.
- **Import and export:** a round trip of a vault with attachments. The export contains the fields; the import writes none and reports the count; the export confirmation shows N and M; a copy still re-adds the attachments.
- **Unsupported items** (a `0x0009` record injected as a test fixture, since writers cannot create it): copy and move refuse with `unsupported_item` and write no pending-move row; move-all with K = 1 moves nothing and deletes nothing; delete-with-items names K.
- **e2e** (`packages/core/test/e2e.test.ts`, `rv` integration): a purge, an auto-purge and a move of an item with an attachment each bring the account's usage back down within one sync round. A second device that receives the purge cleans up when the purger is gone.

## Consequences

### Positive

- Purges, auto-purges and moves stop leaking blobs and quota, so usage figures are trustworthy again (D1).
- One rule covers every client. `rizzy-client` writes the row inside the purge paths, so `rv`, Web, the extension and the M3 native apps cannot forget it.
- No silent data loss on import: the user is told before an export and after an import (D2). Copy and import agree.
- No path can delete a vault's unsupported item unless the user explicitly chooses "delete with its items" (D6).
- Deleting by item also catches attachments that no merged state names (concurrent adds, half-finished uploads), which per-id deletes could not.

### Negative

- One cleanup duty costs a new endpoint, a storage index, a cache-format bump (4 → 5) and a new client table: more surface.
- Several devices may send `delete-item` for the same purge (case 2). Each extra call is a no-op that costs one round trip.
- Exports still do not carry files: a user who moves to a new account must download the attachments by hand.
- A vault that holds a retired `0x0009` item cannot use "move items to Personal, then delete" until the user copies its fields out by hand (open question 1).

### Risks

- **Metadata.** The server sees `delete-item` for an `(vault_id, item_id)` shortly after an upload, and can infer that the item was probably purged. It already sees an item's ops stop; the new inference is about timing, not content. Accepted for the server-side adversaries of the threat model ([THREAT_MODEL](../THREAT_MODEL.md) A2, A3); THREAT_MODEL gets a line on acceptance.
- **A malicious or buggy client of the same account** can delete all attachments of a live item by naming it. It could already delete each one with `attachments/delete`. This adds no capability across accounts or vaults.
- **A leak remains** when the purging device dies before its cleanup and no other device held the item live with attachments (case 2 does not fire). This is the "client that skips delete" residual of ADR 0054's owner answer 3, which its later reconcile sweep would catch.
- **"Restore as a new item" after a late op loses that op's attachments.** Today it would silently produce dangling references; now the prompt says so.

## Alternatives considered

- **Server cascade on Purge.** Impossible: the server cannot see a Purge (ADR 0012 §5, ADR 0021 §5). Making the purge marker visible would leak the lifecycle, which ADR 0012 keeps encrypted.
- **Per-id `attachments/delete` from the merged state** (the review's suggestion). It needs no new endpoint, but it misses attachments the purger's state does not name, and a device that receives a Purge has only the tombstone. Rejected for the per-item call, which uses a column the server already stores.
- **Delete first, then purge** (today's Web order). It never leaks on a crash, but it can lose the files of an item that another device restores at the same time. Rejected: a loss is worse than a bounded leak.
- **Embed attachments in exports.** A single 25 MiB attachment exceeds ADR 0027's 16 MiB payload. It would need a new container format (a new ADR, a new `EXPORT_FILE` version). Not for M3.
- **Strip `attachment/` fields at export.** It loses the user's only record of which files existed, and old exports would still carry the fields, so the reader would have to drop them anyway.
- **Carry unsupported items opaquely on move and copy.** It saves retired `0x0009` items from being stuck. But it needs a schema-skipping create path and a supersession of ADR 0078 §1, and it lets an old client re-home a newer client's item whose meaning it cannot check (open question 1).

## Open questions for the owner

1. **Carry retired `0x0009` items opaquely on move and copy?** Only `0x0009` is permanently unsupported; a future type becomes supported once the client is updated. Carrying it would let "move items to Personal, then delete" finish for vaults that hold Bank-account items. The cost is a narrow schema-skipping create path for one retired type, and a supersession of ADR 0078 §1's "no writer creates an item of it". **Recommendation: no**, as this ADR decides. That matches ADR 0078 open question 2's recommendation against a "Convert to Secure Note" action. Only integration builds ever held such items, and nothing has shipped (ADR 0078 Context).

## On acceptance (doc edits, not made now)

1. [docs/THREAT_MODEL.md](../THREAT_MODEL.md) §8: add INV-113 as §4 states it, and add the `delete-item` timing inference to the server-adversary metadata notes.
2. Status lines (the owner's act): ADR 0054 becomes "Partially superseded by ADR 0093 (§7 in part)"; ADR 0027 adds "ADR 0093 (§2 in part, §6 in part)"; ADR 0081 becomes "Partially superseded by ADR 0093 (§A5 in part, §A6 in part)"; plus the README rows of all three and of this ADR.
3. [docs/CRYPTO.md](../CRYPTO.md): no edit (no construction, purpose or key changes).
4. `CLAUDE.md`'s list of ADR statuses: the lead updates it.
5. The code-doc tables that list the attachment endpoints (`crates/rizzy-proto/src/attachments.rs`, `crates/rizzy-server/src/http/api.rs`) gain the sixth row in the implementing change.
6. [docs/reviews/2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md): mark D1, D2 and D6 as answered by ADR 0093.

## Implementation plan

Each step is one commit with its tests. Nothing starts before acceptance.

1. `rizzy-storage` and `rizzy-domain-vault`: the index migration; `VaultDomain::delete_item_attachments(account, vault, item, now)`, returning whether rows remain; the domain tests (§5).
2. `rizzy-proto`: `AttachmentItemRequest`, `AttachmentItemResponse` and `paths::ATTACHMENTS_DELETE_ITEM`. `rizzy-server`: the route and the HTTP tests. Add the new body to the existing proto body fuzz target.
3. `rizzy-client`: cache format 5 and `attachment_cleanup`; the row writes in the purge paths, the received-op apply path and the late-op surfacing path; the `attachment_cleanup_*` API; the `UnsupportedItem` and `AttachmentCleanupFailed` codes; the client tests and the property test.
4. `rizzy-client` import: drop `attachment/` writes in `import_item_writes[_as]` and return the count; remove the copy's filter; add the report field and the helper that counts attachments for the export notice.
5. `rizzy-client`: the unsupported-item checks in copy, move and the bulk move-all.
6. `rizzy-wasm` and `packages/core`: run the cleanups in `sync()`; remove `deleteAttachmentsOf` from `core-worker.ts`'s `purgeItem`; the export notice; the vault-delete precheck; the e2e tests. Regenerate the wasm expansion baseline (ADR 0019 §4.1).
7. `rv`: run the cleanups after each sync; the export notice; the vault-delete precheck; the integration tests.
8. The full gate (CLAUDE.md, "Before any push").

## References

- [ADR 0012](0012-sync-engine.md) §5; [ADR 0018](0018-item-record-encoding.md) §3, §6, §8; [ADR 0021](0021-server-compaction.md) §5; [ADR 0026](0026-client-device-state-and-cache.md) §5; [ADR 0027](0027-export-payload.md); [ADR 0028](0028-api-v1-http-conventions.md); [ADR 0034](0034-export-reauth-and-plaintext-hold.md); [ADR 0048](0048-per-account-storage-quota.md); [ADR 0054](0054-attachments-envelope-and-api.md); [ADR 0078](0078-retire-bank-account-type.md); [ADR 0081](0081-multiple-vaults-personal-and-shared.md) §A5–§A7.
- [Gap review 2026-10-25](../reviews/2026-10-25-adr-gap-review.md) D1, D2, D6; raw findings [G06](../reviews/2026-10-25-raw/G06.md), [G03](../reviews/2026-10-25-raw/G03.md), [G08](../reviews/2026-10-25-raw/G08.md).
- [THREAT_MODEL.md](../THREAT_MODEL.md) §8 (INV-48, INV-104); [CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes).
