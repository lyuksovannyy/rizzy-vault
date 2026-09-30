# ADR 0027: Export payload encoding and plaintext export

- Status: Proposed
- Date: 2026-09-29
- Deciders: project owner
- Milestone: M1

## Context

[ROADMAP §4.2](../ROADMAP.md#42-core-vault-m1), Must for M1: "Export: encrypted JSON (own format) + plaintext JSON/CSV with scary warning". [ADR 0002](0002-own-protocol.md) point 2 lists the same M1 exporters.

- **What is fixed.** [CRYPTO.md §11.14](../CRYPTO.md#1114-encrypted-export-m1) fixes the encrypted file: the JSON document with seven members, the export file key, the `EXPORT_FILE` envelope (not framed, not padded, at most 16 MiB of plaintext, [§9.1](../CRYPTO.md#91-symmetric-envelope-algorithm-0x01)), and the field-size checks. It says nothing about the plaintext inside `data`, and nothing about the plaintext JSON or CSV shape.
- **What exists** (V, 3087233). `rizzy-core::export` derives the key and seals or opens `data`; `rizzy-client::export` writes and strictly parses the JSON document (fuzz target `client_export`) and "takes and returns the payload as bytes and freezes no item encoding". `rizzy-import` maps other products' files to create ops through `VaultSync::import_item` (`WriteMode::Import`).
- **What can be reused.** [ADR 0018](0018-item-record-encoding.md) defines the canonical live-snapshot `data` (record kind `0x02`) with its parser `parse_snapshot(covered_vv, data)`, the §5 rejection rules and the §10 limits, all already fuzzed (`record_snapshot`). §7 defines the field keys, including `import.created_ms` and `pwhist/<id>/value` · `/ms` for imported password history; §8 says the vault-settings item is never "exported as an item"; §11 says unknown keys are "exported byte for byte".
- **An export is not a backup.** An export (§1, §3, §4) is a user-level portability file: the items of a vault as one client sees them, protected by the export password (encrypted form) or by nothing (plaintext forms). It holds no account, device, key, grant or op log, so it restores no account and no server. The operator's database backup ([ADR 0023](0023-logical-backup-format.md)) holds every account's server state, ciphertext only, for `rizzy-vault restore`: it protects against loss of the server, gives no confidentiality of its own, and is unreadable without each user's keys. The server-secrets backup ([CRYPTO.md §5.11](../CRYPTO.md#511-server-side-encryption-not-zero-knowledge)) holds the server's own secrets under the operator passphrase. None replaces another, and this ADR never calls an export a backup.
- **Forces.** An export file is hostile input when imported ([THREAT_MODEL](../THREAT_MODEL.md) A16): size-limited, parsed without panics, fuzzed. The file `version` field is not in the `EXPORT_FILE` ctx, so a version the plaintext relies on must also be inside the envelope. Plaintext never crosses the binding in a larger unit than needed ([ADR 0013](0013-shared-client-core.md) §3 rule 3), and `rv` prints a secret to a terminal only when asked (INV-56).

## Decision

### 1. The encrypted payload (payload version 1)

The plaintext of the `EXPORT_FILE` envelope, in [CRYPTO.md §2](../CRYPTO.md#2-conventions) notation:

```text
payload = u16(payload_version = 1) ‖ u32(n) ‖ entry{n}
entry   = item_id (16) ‖ u16(item_schema_version = 1) ‖ covered_vv ‖ bytes(data)
covered_vv = u16(c) ‖ c × ( device_id (16) ‖ u64(seq) )      canonical VV of ADR 0012 §3
data    = ADR 0018 §3 live snapshot data (record kind 0x02) of the item's merged state
```

- **What is exported.** Every item of the vault whose state is live (Active or Trashed; `@lifecycle` is inside `data`), with its registers and history exactly as the merge holds them, unknown keys and unsupported values included. Not exported: tombstones, the vault-settings item (`0xF001`), parked records.
- **Canonical.** Entries strictly ascending by `item_id`, no duplicates; `data` is the ADR 0018 §4 canonical encoding. One vault state gives one payload.
- **Oversize items** (ADR 0018 §10) cannot be encoded within the limits. The writer refuses the export and names the items; the user runs "duplicate as a new item" first. Items with an unresolved disagreement are exported as merged and reported.
- **Too large.** If the payload exceeds 16 MiB (`MAX_PLAINTEXT_LEN`), the writer refuses before any key derivation (open question 2).
- **The file's `version` stays 1.** A reader requires `version` = 1 and `payload_version` = 1; a payload of any other version is refused as "update required".

### 2. Reading a payload (import of our own export)

1. The existing reader opens `data` (§11.14). The plaintext stays in a zeroizing buffer.
2. The payload parser checks, before any allocation: `len ≤ 16 MiB`; `n ≤ 1,048,576` and `n × 24 ≤ remaining` (24 = the fixed part of an entry); ascending `item_id`; `item_schema_version` = 1 (anything else refuses the file); `c ≤ 65,535` and `c × 24 ≤ remaining`; `bytes(data)` ≤ 12 MiB; then `parse_snapshot(covered_vv, data)` with every ADR 0018 §5 rule; no trailing bytes. **Any failure refuses the whole file**; nothing is imported from a malformed payload.
3. Each entry becomes a **new item**, through `VaultSync::import_item`, like any importer's output: a new `item_id` and item key, and a create op of the importing device (dots and HLCs of the exporting account are never reused):
   - each register's **displayed** value (ADR 0018 §6 display rules), unknown keys included, byte for byte; element ids (`uri/<id>`, `field/<id>`) kept;
   - `import.created_ms` = the ADR 0018 §9 "Created" time of the exported state;
   - the history of `login.password`, newest first, as `pwhist/<id>/value` and `/ms` (`hlc >> 16`) with fresh element ids, at most 50;
   - a Trashed item is created, then trashed in a second op.
4. **Per-item refusals do not refuse the file.** An item the schema layer refuses (for example an unknown item type) is skipped, and the import report counts skipped items, fields whose concurrent values collapsed to the displayed one, and history entries not carried (histories of other fields). The report names no value ([INV-48](../THREAT_MODEL.md#8-security-invariants)).
5. If one item's writes exceed an op's ADR 0018 §10 limits, `import_item` splits them into consecutive ops, as §6 "List order" already allows.

Code: the payload writer and parser live in `rizzy-client::export` next to the JSON document; fuzz target `client_export_payload` runs step 2 on arbitrary bytes. Tests: a known-answer payload through a real `EXPORT_FILE` envelope with a fixed RNG; a round trip vault → file → new vault comparing displayed values; refusal vectors for each step 2 rule.

### 3. Plaintext JSON

UTF-8 without BOM, LF line endings, [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259) JSON, members in the order shown:

```json
{"format":"rizzy-vault-plaintext-export","version":1,"exported_at":1790000000000,
 "items":[{"id":"<32 lowercase hex>","type":1,"trashed":false,"created_ms":…,"modified_ms":…,
   "fields":[{"key":"item.name","value":{"text":"Bank"}},
             {"key":"login.password","value":{"text":"…"},
              "conflicts":[{"text":"…"}],"history":[{"value":{"text":"…"},"ms":…}]}]}]}
```

- One entry per exported item of §1; `type` is the `item.type` enum value; `created_ms` and `modified_ms` are ADR 0018 §9's; `fields` ascending by key, displayed values only, a cleared field left out.
- **Typed values** (ADR 0018 §6): `{"text":s}` (valid UTF-8, JSON-escaped), `{"bytes":b64url}`, `{"bool":b}`, `{"u64":"<decimal>"}` (a string, beyond JavaScript's 2^53), `{"enum":n}`, `{"sort_key":b64url}`, and `{"raw":b64url}` (the whole value, type byte included) for any unsupported or malformed value, including Text that is not UTF-8. base64url is unpadded ([CRYPTO.md §9.6](../CRYPTO.md#96-encoding-for-transport-and-storage)). `conflicts` lists the other current values; `history` exists only for `login.password`.
- No key, id of another object, dot or device id appears. The document is not signed or encrypted.

### 4. Plaintext CSV

[RFC 4180](https://www.rfc-editor.org/rfc/rfc4180): UTF-8 without BOM, CRLF, every field quoted, one header row, one row per item of §1 (vault settings excluded). Columns, in this order: `type,name,notes,favorite,tags,uris,login.username,login.password,login.totp`, then every Card key and every Identity key of ADR 0018 §7 in the §7 table's order, by key name. `type` is `login`, `note`, `card` or `identity` (other types are left out of CSV); `tags` and `uris` are joined with LF inside the cell, in list order; `favorite` is `true` or empty; a trashed item is left out.

- **Lossy by design:** custom fields, password history, conflicts, unknown keys and unsupported values are not in CSV. The export dialog states this and gives the count of affected items; the JSON form is the complete one.
- **No cell rewriting.** A cell starting with `=`, `+`, `-` or `@` is written as is: prefixing it (the usual CSV-injection defence) would corrupt passwords. The warning says not to open the file in a spreadsheet (open question 3).

### 5. The warning and the output path

- `rizzy-client` exposes plaintext export only through a call that takes an explicit acknowledgement value. Before creating it, every host shows the warning below and requires the user to type `EXPORT PLAINTEXT` exactly; no flag, setting or environment variable skips this, and `rv` reads the phrase from the terminal, so a plaintext export never runs unattended. The plaintext goes to the host as one zeroizing byte buffer.
- **Warning** (the ROADMAP's "scary warning"; frozen English source, a translation keeps every sentence): "This file will hold every password, one-time-code secret, card number and note of this vault, unencrypted. Anyone and any program that can read the file can read them all, including backup and cloud-sync tools and other users of this computer. rizzy-vault cannot protect, track or erase the file once it is written. Delete it as soon as you have used it. To keep a copy of your vault, use the encrypted export instead."
- **CSV adds:** "Do not open this file in a spreadsheet program: a cell that begins with =, +, - or @ can run as a formula, and saving from a spreadsheet can change your passwords. CSV leaves out custom fields, password history, conflicting values and trashed items; N items lose data. The JSON export is complete." N is §4's count.
- **Output file, encrypted and plaintext alike.** `rv` writes to a path the user names, under the rules of ADR 0023 §4: `create_new`, mode 0600 set at creation on Unix (elsewhere the directory's inherited permissions), a partial file removed on failure. If anything exists at the path, a symlink included, the export fails with "file exists" and writes nothing; M1 has no `--force`, and the user names another path or removes the file. `rv` refuses stdout when stdout is a terminal (INV-56).
- **Hosts that save through the platform** (a browser download, an OS save dialog) cannot set a mode or refuse an overwrite themselves: they write only where the user chose in that dialog and replace a file only after the dialog's own confirmation.

### 6. Reading plaintext JSON back (binds only if open question 4 is answered yes)

If the answer is no, this section is dropped and M1 reads back only the encrypted export (§2). This ADR defines no reader for §4 in either case.

- **Its own format.** `Format::RizzyPlaintextJson` in `rizzy-import`, with its own fuzz target `import_rizzy_json`, over that crate's bounded `json` reader (zeroizing strings, no I/O, no panics). The file is unauthenticated hostile input (A16): it yields only create ops of the importing device, as §2 step 3, and nothing in it is trusted.
- **Whole-file checks; each failure refuses the file.** Length ≤ 64 MiB (`MAX_JSON_LEN`) before any parsing; UTF-8 and RFC 8259 syntax; nesting ≤ 64 (`MAX_DEPTH`; the format needs 8); ≤ 4,000,000 JSON values (`MAX_NODES`); the root is an object whose `format` is the exact string of §3, whose `version` is the integer 1 and whose `items` is an array of ≤ 100,000 entries (`MAX_ENTRIES`). Another `format` is "not this format"; another `version` is "update required", never guessed or migrated. `exported_at` is optional and ignored. The §3 writer refuses to write a file above these caps, so every file it writes reads back.
- **Unknown members** of any object are ignored and counted in the report; a change to the meaning of a §3 member needs a new `version`. Of duplicate members the first counts (the `json` reader's rule).
- **Per item.** Required: `type` (integer 0–65,535) and `fields` (array of ≤ 4,096 entries, ADR 0018 §10's register cap). Optional: `trashed` (boolean, default false) and `created_ms` (integer fitting a `u64`). Ignored: `id` (the item gets a new one), `modified_ms`, and `conflicts` (counted as collapsed). A field requires `key` (ADR 0018 §7 grammar, 1–160 bytes, no duplicate in the item) and `value`, an object with exactly one §3 type member.
- **Values become ADR 0018 §6 bytes:** `text` → Text, `bytes` → Bytes, `bool` → Bool, `u64` (1–20 decimal digits, no leading zero, fitting a `u64`) → U64, `enum` (0–65,535) → Enum, `sort_key` → SortKey, `raw` → the decoded bytes verbatim. Each value is ≤ 65,536 bytes, type byte included (§10), checked on the JSON string's length before any base64url decoding.
- **Writes.** `item.type` = `type` (a `fields` entry with that key is ignored); `import.created_ms` = `created_ms` when present; each field's value under its key; `history` of `login.password` as in §2 step 3 (at most 50, more are counted); a `trashed` item is created, then trashed. Every write passes `rizzy-core`'s `check_carried` for `WriteMode::Import`: any key of the grammar and any value bytes within §10 are kept verbatim and show as unsupported where unknown (ADR 0018 §6, §11; open question 5). Writes beyond one op's limits split as §2 step 5.
- **Per-item failures skip the item, never the file:** a missing or mistyped member, a bad or duplicate key, an oversize value or list, or a type the schema refuses (unknown and reserved types, and `0xF001`, never imported as an item). The report counts skipped items, ignored members, collapsed conflicts and dropped history, and names positions only (INV-48).

## Consequences

### Positive

- The encrypted payload reuses one audited, fuzzed parser; no new item encoding exists.
- The encrypted export keeps everything the merge knows, including history and conflicts, so a later reader can do better than M1's flattening.
- Our own import is an importer like the others: new ids, new dots, per-item warnings.

### Negative

- Importing flattens conflicts and drops history other than passwords; the report counts it.
- The encrypted file carries device ids and edit times of the exporting account (inside the envelope) and reveals the payload length, as §11.14 already says.
- A vault above 16 MiB of payload cannot be exported in M1.

### Risks

- If users hit the 16 MiB bound (signal: user reports, or vault sizes measured on real M1–M3 vaults), a multi-file or chunked export needs a new ADR and CRYPTO.md change.
- A second `item_schema_version` needs a rule for exporting mixed versions; the ADR that defines it adds that rule.

## Alternatives considered

- **Displayed values only (op-data form) in the encrypted payload.** Smaller and simpler, but the export would lose history and conflicts for good.
- **serde JSON inside the envelope.** A second, non-canonical item encoding to audit and fuzz, against CRYPTO.md §2 "Canonical encoding".
- **Import that keeps the exported dots.** Dots belong to the exporting account's devices; replaying them in another account would forge authorship. Rejected.
- **CSV with injection prefixes.** Corrupts secrets that begin with `-` or `=`.

## Open questions for the owner

1. **Trashed items.** Exported, and imported as trashed (§1, §2 step 3)? Recommendation: yes; a user's own copy of the vault should hold them.
2. **Over 16 MiB.** Refuse in M1 (§1)? Recommendation: yes; revisit with a chunked format if needed.
3. **CSV formula cells.** Write as is, with the warning (§4)? Recommendation: yes.
4. **Re-importing plaintext JSON.** Add a `rizzy-import` reader for §3 in M1? Recommendation: yes, as its own fuzzed format (§6), since the JSON form is complete. ROADMAP §4.2's import row and ADR 0002 point 2 do not list this format, so a yes is also a ROADMAP edit for the owner; a no drops §6.
5. **Unknown keys and `raw` values in a plaintext file** (§6 "Writes"). Carried verbatim through `check_carried`, which today serves only restore and duplicate, or checked as entered writes, which drops them with a warning? Recommendation: carried; ADR 0018 §6 keeps such values harmless, and a round trip stays complete.
6. **Warning wording, the `EXPORT PLAINTEXT` phrase, no bypass and no `--force`** (§5). Accept as written? Recommendation: yes.

## References

- [CRYPTO.md](../CRYPTO.md) §2, §5.11, §8.4, §9.1, §9.6, §11.14; [THREAT_MODEL.md](../THREAT_MODEL.md) A16, INV-48, INV-56; [ROADMAP.md](../ROADMAP.md) §4.2.
- [ADR 0002](0002-own-protocol.md) point 2, [ADR 0012](0012-sync-engine.md) §3, [ADR 0013](0013-shared-client-core.md) §3, [ADR 0018](0018-item-record-encoding.md) §3–§11, [ADR 0023](0023-logical-backup-format.md) §2–§4.
- Code (V, 3087233): `crates/rizzy-core/src/export.rs`, `crates/rizzy-client/src/{export,items}.rs`, `crates/rizzy-import/src/{lib,limits,json}.rs`, `crates/rizzy-core/src/item/schema.rs`.
- RFC 8259 (JSON), RFC 4180 (CSV), RFC 4648 §5 (base64url) (L: as cited by CRYPTO.md, not re-read for this ADR).
