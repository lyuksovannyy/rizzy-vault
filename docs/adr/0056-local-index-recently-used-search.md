# ADR 0056: M3 local index: recently-used tracking and client-side search

- Status: Accepted
- Date: 2026-10-11
- Deciders: project owner
- Milestone: M3 (`rv`, `rizzy-ffi`)
- Supersedes: [ADR 0026](0026-client-device-state-and-cache.md) §1 in part, §3 in part, on acceptance. Item 1 below names the parts.

## Context

[ROADMAP §4.2](../ROADMAP.md#42-core-vault-m1), Should, M3: "Favorites, recently used, full-text search on decrypted index (client-side only)." Favorites is an already-Accepted item field (`item.favorite`, [ADR 0018](0018-item-record-encoding.md) §7) and pure UI; it needs no ADR. This ADR covers the other two: recently-used tracking and client-side search.

[ADR 0018](0018-item-record-encoding.md) §7 already rules this data out of sync: "'recently used', last-autofill times and usage counts... stay on the device (the M3 local index)," because a signed op would show the server when an item was used. [ADR 0026](0026-client-device-state-and-cache.md) §1 reserves `LOCAL_CACHE_INDEX` (0x0090, [CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes)) for whatever this ADR persists, and its §3 states that today "a reader of the [cache] file... learns no item content (G-1)." Both sentences are written for this ADR to extend or change.

What binds: [ADR 0026](0026-client-device-state-and-cache.md) §3's cache schema and cleartext/encrypted column split, §4's load, §5's versioning, failure handling and "no plaintext-bearing copy" migration property, §6's test style; [ADR 0018](0018-item-record-encoding.md) §6's value types, §7's "concealed by default" field list (`login.password`, `login.totp`, `card.number`, `card.code`, `card.pin`, `identity.ssn`, `identity.passport_number`, hidden custom fields, `share/<id>/secret`), §8's vault-settings item (type `0xF001`, "never listed, searched, exported... shared or trashed"); [CRYPTO.md §4.2](../CRYPTO.md#42-key-inventory)/[§4.3](../CRYPTO.md#43-derivations) already define a "Local index key" (32 B, `HKDF(account_key, salt=empty, info=LABEL("local-index-key")‖account_id‖device_id)`); [§8.4](../CRYPTO.md#84-aad-and-purposes) reserves purpose `LOCAL_CACHE_INDEX` (that key, algorithm 0x01, ctx `account_id ‖ device_id`, no `item_id`) for "M3," with no plaintext layout defined. [THREAT_MODEL](../THREAT_MODEL.md) G-1, AST-7 ("Encrypted everywhere at rest"), AST-19, INV-61 (device state and the cache excluded from OS/cloud backups — documentation-only for the CLI, §3 below), A8 (stolen or lost device, including a backup copy of its storage) and AR-14 (the CLI's state file in the user's own backups).

Code (V, 5a78bb5): `rizzy-client` is sans-I/O ([ADR 0016](0016-workspace-layout.md) R1) and owns the cache schema as SQL text in `crates/rizzy-client/src/store/{mod,rows,load,floors}.rs`; `rows::CACHE_FORMAT = 1`, and `store/mod.rs` reports "Migrations. Format 1 is the only format; there is no migration step yet" — this ADR drives the first real one. `items.rs` already has `field_value`/`field_keys` over a merged item; no display-projection function exists yet. The leaf `rizzy-cli` runs the schema through `sqlx-client` (pinned sqlx 0.9.0, feature `sqlite-bundled`, no PostgreSQL driver, no ICU extension, [ADR 0016](0016-workspace-layout.md) R5).

## Decision

### 1. What this ADR supersedes

- ADR 0026 §1, "No extra encryption layer in M1," last sentence ("`LOCAL_CACHE_INDEX` (0x0090) stays reserved for the M3 local index (CRYPTO.md §4.3); anything derived from plaintext that a later milestone persists (search index, 'recently used') goes under it, by that milestone's ADR.") → replaced by: "`LOCAL_CACHE_INDEX` (0x0090) and the local index key ([CRYPTO.md §4.3](../CRYPTO.md#43-derivations)) stay reserved and unused: ADR 0056 stores the M3 local index — display-safe decrypted fields, last-used time and use count — as cleartext columns in the tier §3 'What is cleartext on disk' already documents, not wrapped under this purpose."
- ADR 0026 §3, the sentence "It learns no item content (G-1)." → replaced by: "Without any key, a reader of the file also learns the display-safe fields, last-used time and use count of every item in every vault this device has loaded (ADR 0056 §2): the full merge at load builds them for every item, not only ones the user has opened. It learns no field ADR 0056 §2 does not name, and no concealed field (ADR 0018 §7)."

`item_index` (§2) is a table ADR 0026 never enumerated, so it is outside §5(a)–(e)'s failure cases and §4's floors without superseding either: §4 below states its own, narrower failure rule. ADR 0026 §1's "**Never persisted** in M1: any decrypted value…" is scoped to M1 by its own next paragraph, which defers what "a later milestone persists (search index, 'recently used')" to that milestone's ADR — this is that ADR, and nothing else in that sentence changes.

### 2. What is indexed

Rows exist only for non-tombstoned, user-visible items: the vault-settings item (type `0xF001`, [ADR 0018](0018-item-record-encoding.md) §8) is excluded, matching its exclusion from listing and search there. For every other item, `display_name`/`search_text` are built from the **full merge at each load** (ADR 0026 §4 step 5 already computes it) — for every item, not only ones the user has opened. `last_used_ms`/`use_count` start absent/zero and are set only when the user actually views, copies a field from, or autofills that item; they are device-local, never read from a sync op, never uploaded, never compared across devices.

`search_text` is a **closed allow-list** of field keys, not the ADR 0018 §7 concealed list inverted — that list omits `pwhist/<id>/value` (imported password history) and `identity.drivers_license`, which this ADR deliberately still excludes:

> `item.name` (as `display_name`), `login.username`, `uri/<id>/value`, decoded `tag/<hex>` names, `field/<id>/label` and `/value` where `kind = 1` (text only; `kind 2` hidden and `kind 3` boolean are excluded), `card.holder`, `card.brand`, `identity.title`/`.first_name`/`.middle_name`/`.last_name`/`.company`/`.email`.

(`item_id`, `vault_id` and `item_type` are row locators in ADR 0026 §3's existing cleartext tier, like every other id and type column there, not indexed field values; the allow-list governs only `display_name` and `search_text`.) A field key not on this list is **never** indexed, including every key ADR 0055 (M3 item types, sibling, Proposed) adds for the M3 item types: extending the allow-list is a future amendment to this ADR, not automatic. `item.notes` is likewise excluded for M3 (open question 1): it is not on ADR 0018 §7's concealed list, but it is a Secure Note's entire, unbounded, user-typed body.

**Proposed INV-80** (allocated across the 2026-10-11 batch in ADR-number order. Provisional: the allocation was made across the 2026-10-11 batch in ADR-number order; if ADRs are accepted out of order, the owner renumbers at acceptance.): every byte of `item_index.display_name` and `search_text` is either (a) copied from an allow-listed field's *value*, or (b) a decoded `tag/<hex>` name copied from an allow-listed tag's *key* — the only key-derived content the projection may use, since a tag's value is always the fixed byte Bool `0x01` and its name lives in the key (ADR 0018 §2, "Keys are user content too"; §7's field-key table). No other field key's value, and no other key's name or fragment — of any item type, including ones ADR 0055 defines — ever reaches either column. Verified by a property test over arbitrary field keys and arbitrary key-bearing content, `pwhist/<id>/value`, `identity.drivers_license`, a concealed custom field's key and an unlisted key's name included, asserting that none of their values, and none of their keys' bytes, appear in the built row except the decoded tag names the §2 allow-list permits.

The projection that builds each row runs over the same zeroizing types as the rest of the merge ([ADR 0018](0018-item-record-encoding.md) §2); `display_name` and `search_text` are never written to a log, error or `Debug` output (CLAUDE.md; ADR 0018 §2 "Keys are user content too").

### 3. Storage: cleartext, local only, no new construction

The index is a new table in the same per-account SQLite cache ADR 0026 §3 defines (`rv`: its cache database; `rizzy-ffi`: the same schema), added as cache-format 2, the first migration `rizzy-client`'s `store` module runs:

```sql
item_index(item_id BLOB PRIMARY KEY, vault_id BLOB NOT NULL, item_type INTEGER NOT NULL,
           display_name TEXT NOT NULL, search_text TEXT NOT NULL,
           last_used_ms BLOB, use_count INTEGER NOT NULL DEFAULT 0)
```

Every column is cleartext: no envelope, no AAD, no purpose id. This is a deliberate choice against using `LOCAL_CACHE_INDEX` and the local index key ([CRYPTO.md §4.3](../CRYPTO.md#43-derivations)):

- The local index key derives from the account key alone, with no independent secret. A device that can derive it already holds the account key, which already opens every item, so wrapping buys no guessing-resistance once the device is **unlocked** (A5b).
- It does change what a **locked, stolen** device's filesystem yields (A8): today the cache gives no item content without an Argon2id guess; a cleartext index gives item names, usernames, URLs and tag names for free. INV-61 specifies a real exclusion mechanism, not just documentation, for `rizzy-ffi`'s other platforms: Desktop gets an app-data path "marked excluded from OS backup where the OS supports it," and iOS/Android get the backup-exclusion resource attribute and `ThisDeviceOnly` keychain class. **`rv` is the one row with no mechanism at all.** INV-61's own CLI entry is documentation only — "the docs say where the state file lives and that it must stay out of backups," nothing enforced — confirmed by A8's Residual risk ("The CLI cannot keep its state file out of the user's backups; its docs say so") and by AR-14 ("the CLI (and its state file in the user's own backups)"). So for `rv`, `item_index`'s cleartext item names, usernames, URLs and tag names land in ordinary user backups (Time Machine, home-directory backups, and the like) too, not only on a stolen live device: a second, explicit and unmitigated cost of this decision, specific to `rv` (open question 2).
- Wrapping under `LOCAL_CACHE_INDEX` would close that A8 gap, but it is not a drop-in: the purpose's ctx (`account_id ‖ device_id`) binds no row-level id, so one sealed row's ciphertext could silently replace another's — the same ctx-binding gap ADR 0026's Alternatives already flagged for persisting merge state under this purpose. Closing it needs a CRYPTO.md §8.4 change (binding `item_id` into the ctx), which this ADR does not make, so the purpose is not used here.
- `LOCAL_CACHE_INDEX` and the local index key stay reserved and unused by this ADR.

No new cryptographic construction is proposed, and no CRYPTO.md floor changes: this ADR adds zero cryptography. A later format migration of `item_index` drops and rebuilds it rather than copying its rows forward, so ADR 0026 §5's "no plaintext-bearing copy is made" property holds for this table too.

### 4. Rebuild and corruption

- **Built at load**, from the merge ADR 0026 §4 step 5 already computes: no extra decryption. `use_count`/`last_used_ms` are read back from the existing table and carried over.
- **Kept incrementally.** Every op or snapshot that changes an item's allow-listed fields upserts its row in the same transaction ADR 0026 §4 step 2 already commits; a purge or auto-purge deletes the row.
- **Its own failure rule.** A row that fails to parse, or a schema mismatch scoped to `item_index`, drops and rebuilds only this table from the in-memory merge; this never blocks or fails the rest of the load, since `item_index` carries no floor ADR 0026 §4 tracks (§1).
- **User-triggered rebuild.** `rv cache reindex` (and the equivalent on other leaves) drops and rebuilds the table on demand, for a "search looks wrong" report.

### 5. Search, for M3

A query is a lower-cased substring match over `display_name` and `search_text`: both the stored columns and the incoming query are lower-cased **in Rust** (Unicode-aware `str::to_lowercase`, not a byte/ASCII table) before the `LIKE '%term%'` comparison — never through SQLite's built-in `lower()`, which lower-cases ASCII only unless an ICU extension is loaded, and `sqlx-client`'s feature list (`runtime-tokio`, `sqlite-bundled`) loads no ICU extension. Lower-casing in SQLite instead would silently mis-match non-ASCII item names and tags, Cyrillic included. An empty query sorts by `last_used_ms` ("recently used"). A vault holds a few thousand items ([ADR 0012](0012-sync-engine.md)); a linear scan of short strings needs no index structure yet. SQLite FTS5 is the natural upgrade (ranked, tokenised search) but is not adopted now: the pinned `sqlx-client` build's exact FTS5 feature surface is unverified (U), and unranked substring search meets the ROADMAP Should for M3 (open question 3).

### 6. Tests

Known-answer and property tests, [ADR 0026](0026-client-device-state-and-cache.md) §6's style: the allow-list property above; a non-ASCII (Cyrillic) lower-casing vector, confirming a query matches regardless of case through the Rust `to_lowercase` path and not SQLite's `lower()`; `0xF001` is never a row; the rebuild from a full merge equals the row set reached by incremental upserts over the same ops, for every op order; a format 1→2 migration creates an empty table without touching any other row; `item_index` corruption (truncated row, bad UTF-8) rebuilds that table alone and leaves every other table's load unaffected.

### 7. On acceptance

1. ADR 0026's status line (and its README row) → "Partially superseded by [ADR 0056](0056-local-index-recently-used-search.md) (§1 in part, §3 in part)"; `docs/adr/README.md` gains a row for 0056.
2. THREAT_MODEL.md A8, "Access to the file system" bullet, gains: item names, usernames, URLs and tag names, through `item_index` (ADR 0056), with no Argon2id guess — for `rv`, this reaches the attacker through a backup copy too, since INV-61 is documentation-only for the CLI.
3. THREAT_MODEL.md AST-19's **Asset** cell, "Local encrypted cache and device state (`E_local`, `device_salt`, `E_dev`, SK)" → "Local cache (encrypted, except `item_index`, ADR 0056, cleartext) and device state (`E_local`, `device_salt`, `E_dev`, SK)"; its Impact cell ("A target for offline guessing [A8]") gains ", except `item_index`'s fields, which need no Argon2id guess — they are read directly."
4. THREAT_MODEL.md AST-7's "Where it lives" cell ("Encrypted everywhere at rest...") gains: "except the display-safe fields ADR 0056 §2 keeps in a cleartext local search index."
5. THREAT_MODEL.md AR-14's entry gains, after "the CLI (and its state file in the user's own backups)": "and, from M3, its `item_index` (ADR 0056)."
6. CRYPTO.md §8.4's `LOCAL_CACHE_INDEX` row, "First used" cell: "M3" → "reserved; not used by ADR 0056." §4.2's and §4.3's "Local index key (M3)" row label, in each table: → "Local index key (reserved; ADR 0056 does not use it)."

### Owner answers at acceptance (2026-10-22)

The owner accepted this ADR as drafted; the recommendations of "Open questions for the owner" stand:

1. `item.notes` is not indexed in M3. Secure Notes get title-only search until a length-capped version is proposed separately.
2. Cleartext is accepted for M3 desktop, where INV-61 gives a real exclusion mechanism. It is accepted for `rv` too, as a knowingly larger cost, since INV-61 is documentation-only for the CLI. The `LOCAL_CACHE_INDEX` route is not taken.
3. FTS5 is deferred, to revisit with M3 performance data.
4. The browser extension's IndexedDB cache keeps its M2 plain item list. This ADR commits only `rv` and `rizzy-ffi`.
5. The §2 allow-list grows for ADR 0055's M3 item types by a short amendment, once ADR 0055 names which of its fields are display-safe. Until then those items are findable only by `item.name`. ADR 0055, accepted the same day, names no display-safe field, so that amendment is still to be written.

Of the §7 "On acceptance" edits, all six are made in the accepting change: ADR 0026's status line and index row; THREAT_MODEL.md A8, AST-19, AST-7 and AR-14; CRYPTO.md §8.4, §4.2 and §4.3. The same change adds INV-80 (THREAT_MODEL.md §8.9), which §7 does not list but this ADR allocates for THREAT_MODEL.

## Consequences

### Positive

- Recently-used and search work fully offline, with no signed op and no server-visible timing of item use (ADR 0018 §7's own reason for deferring this).
- No new key, envelope or CRYPTO.md change; the reserved purpose and key stay available, and useable once the ctx-binding gap (§3) is fixed, for a future milestone that wants them.
- `item_index` is the first part of the cache that is disposable: losing or corrupting it costs a rebuild and the use counters, never a device removal.

### Negative

- Filesystem access to a **locked** device now yields item names, usernames, URLs and tag names with no password guess (§3, §7 item 2); it still yields no concealed field, no `pwhist`/`identity.drivers_license` value and no password.
- For `rv` specifically, that same exposure also reaches through any backup of its state directory, not only a stolen live device, because INV-61 enforces nothing there (§3, §7 item 2 and 5).
- `use_count`/`last_used_ms` are lost on cache loss, reinstall or `cache reindex`, like any other rebuildable local-only counter.
- `store::mod`'s migration runner does not exist yet (Context) and is built for the first time here, ahead of any other format-2 need.

### Risks

- **Substring search over thousands of rows could be slow enough to need FTS5 or a real index**, the same "if load time becomes a problem" signal ADR 0026's Risks already uses, revisited with M3 measurements.
- **A field later marked concealed** (a new ADR 0018/0055 amendment) must also leave the §2 allow-list, and a reader rule is needed so an old row holding a since-concealed value is dropped, not merely left stale.
- **`secure_delete` does not erase old pages** (ADR 0026 §3 already notes this for `E_local`: the journal, SSD remapping and CoW snapshots can keep them). `item_index`'s drop-and-rebuild and `cache reindex` rely on the same imperfect erasure, so a stale page can keep a trashed or purged item's display-safe fields and tags readable after the row is gone — no worse in kind than the existing `E_local` caveat, but now the leftover is a readable name, not ciphertext.

## Alternatives considered

- **Encrypt under `LOCAL_CACHE_INDEX`/the local index key.** Closes the A8 gap in §3, but is not a drop-in: the purpose's ctx binds no `item_id`, a gap ADR 0026's Alternatives already flagged, so it needs a CRYPTO.md §8.4 change first. Deferred to open question 2 rather than built now.
- **Keep the index in memory only, rebuilt every unlock, never persisted.** No new disk exposure at all, but it grows ADR 0026 §4's "seconds of CPU" unlock cost (Negative) further, and "recently used" across restarts needs `last_used_ms`/`use_count` on disk regardless; this ADR confines the new exposure to exactly the §2 allow-list plus those two columns.
- **SQLite FTS5 virtual table from M3.** Better ranking and tokenised search, but the pinned `sqlx-client` build's exact feature surface is unverified; deferred to open question 3.

## Open questions for the owner

1. **Index `item.notes`?** *Recommendation:* not for M3 (§2). Secure Notes get title-only search until a length-capped version is proposed separately, since the whole note is unbounded, user-typed text that may be more sensitive than its author expected to see cached in cleartext.
2. **Accept the new A8 exposure, or require the CRYPTO.md §8.4 ctx fix and use `LOCAL_CACHE_INDEX` instead?** *Recommendation:* accept cleartext for M3 desktop (§3, §7 item 2), where INV-61 specifies a real exclusion mechanism (conditional: "where the OS supports it") rather than mere documentation, so the residual is physical/filesystem access to the live device or a backup where that mechanism fails — which A8 already treats as a partial compromise of the rest of the cache. For `rv`, accept cleartext too, but as a knowingly larger cost: INV-61 is documentation-only for the CLI (§3), with no mechanism at all, so the residual there is any backup of `rv`'s state directory, not only the live device — closer to AR-14's existing accepted risk for the CLI's state file than to the desktop case. Revisit for the browser extension (no hardware binding, AR-14) and M7 mobile, where doing the CRYPTO.md §8.4 fix and using `LOCAL_CACHE_INDEX` may be worth it.
3. **Adopt FTS5 once its availability under the pinned `sqlx-client` is verified?** *Recommendation:* defer; revisit with M3 performance data (Risks).
4. **Extend to the browser extension's IndexedDB cache in M3, or leave its M2 plain item list as is?** *Recommendation:* leave it; this ADR commits only `rv` and `rizzy-ffi`.
5. **Grow the §2 allow-list for ADR 0055's M3 item types (SSH, API credential, license, Wi-Fi, bank)?** *Recommendation:* as a short amendment once ADR 0055 is Accepted and names which of its fields are display-safe; until then those items are findable only by `item.name`.

## References

- [ROADMAP](../ROADMAP.md) §4.2
- [ADR 0018](0018-item-record-encoding.md) §2, §6, §7, §8; [ADR 0020](0020-partial-supersession.md) point 9; [ADR 0026](0026-client-device-state-and-cache.md) §1, §3, §4, §5, §6; ADR 0055 (M3 item types, sibling, Proposed)
- [CRYPTO.md](../CRYPTO.md) §4.2, §4.3, §8.4
- [THREAT_MODEL](../THREAT_MODEL.md) G-1, AST-7, AST-19, A8, AR-14, INV-61
- Code (V, 5a78bb5): `crates/rizzy-client/src/store/{mod,rows,load,floors}.rs`, `crates/rizzy-client/src/items.rs`, `crates/rizzy-cli/Cargo.toml`, root `Cargo.toml` (`sqlx-client`)
