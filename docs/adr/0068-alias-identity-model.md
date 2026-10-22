# ADR 0068: Alias identity model, storage, and no-enumeration lookup

- Status: Proposed
- Date: 2026-10-11
- Deciders: project owner
- Milestone: M6
- Supersedes: [ADR 0028](0028-api-v1-http-conventions.md) item 3 in part (one new `409` code, `alias_local_part_taken`; the same narrow pattern ADR 0031 and ADR 0032 already used on that item), on acceptance. Otherwise extends without superseding: [ADR 0006](0006-key-hierarchy.md) point 8 (mail key, referenced, unchanged), [ADR 0010](0010-server-shape.md) §2 (gives `resolve`/`deliver` a concrete schema, text unchanged), [ADR 0011](0011-storage.md) rule 5 (defines the first `mail_` table under its existing rule, text unchanged), and [ADR 0018](0018-item-record-encoding.md)'s §7 provision that "a new key needs a line in the ADR that ships it". Does not define the smtp↔api wire protocol or the SMTP listener (ADR 0069, sibling in this batch) or approve `mail-auth` (ADR 0070, sibling); it only supplies the schema and record layout those rely on.

## Context

ROADMAP §4.8 (M6, Must) requires: alias identity generation from item creation; a catch-all per configured domain with "alias → owner lookup without revealing which aliases exist (no SMTP user enumeration)"; encrypt-at-ingress with ciphertext-only storage; disable/delete with rejection at SMTP time for a disabled alias.

[ADR 0010](0010-server-shape.md) §2 already fixes the shape of lookup: `smtp` calls `api`'s `resolve(alias address, last pinned bundle_seq)`, which returns `accept(alias_id, bundle, chain)` or `reject`, with unknown and disabled aliases on the same code path ([INV-47](../THREAT_MODEL.md#8-security-invariants)). It does not fix a schema behind `resolve`, and none exists yet. [ADR 0011](0011-storage.md) rule 5 reserves the `mail_` table prefix but defines no `mail_` table; rule 6 allows one cross-domain foreign key per domain, to `auth_accounts`. [ADR 0006](0006-key-hierarchy.md) point 8 fixes one mail X25519 key per account (not per alias); [CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes) fixes `MAIL_SECRET_KEY` (0x0012, keyed by `account_id`) and `MAIL_MESSAGE` (0x0060, HPKE to the mail key, context `account_id ‖ alias_id ‖ message_id ‖ received_at_ms`). [CRYPTO.md §11.13](../CRYPTO.md#1113-mail-ingress-m6) step 3 says `smtp` builds "the plaintext `bytes(metadata) ‖ raw MIME`, framed and padded [§8.5], where the metadata holds the authentication results, spam score, envelope-from and rcpt-to" but does not pin `metadata`'s byte layout, the gap [ADR 0018](0018-item-record-encoding.md) closed for item records. [ADR 0016](0016-workspace-layout.md)'s planned-crate table already names the owning module: `rizzy-domain-mail`, lib, M6, "Aliases, mailbox envelopes, retention, internal ingress endpoints", depending on `rizzy-proto`, `rizzy-storage`, `rizzy-bus` (V: read 2026-10-11; not yet created under `crates/`, alongside the existing `rizzy-domain-auth` and `rizzy-domain-vault`).

[THREAT_MODEL.md](../THREAT_MODEL.md) already analyses the lookup trade-off (Q-18) and the key-linkage trade-off (Q-19/AR-21):
- **Q-18.** RCPT always separates active aliases from non-existent ones, because active aliases must be accepted. Option (a): reject unknown and disabled identically, accept active, rely on ≥64 random bits per generated local part ([INV-65](../THREAT_MODEL.md#8-security-invariants)) plus per-IP RCPT limits and tarpitting ([AR-20](../THREAT_MODEL.md#9-accepted-risks-and-out-of-scope)). Option (b): accept every RCPT for the domain and silently drop after `DATA`, which stores and scans spam for addresses that do not exist and contradicts the Must row's "rejected at SMTP time".
- **Q-19/AR-21.** `resolve` returns the account's one mail-key bundle, so a compromised `smtp` can link any two aliases that share it. Accepting this for v1.0 costs nothing beyond what a compromised `smtp` already gets by reading all later mail to those aliases; per-alias keys would add one signed key and one bundle entry per alias.

This ADR turns both recommendations into a binding Decision, gives `resolve`/`deliver` their backing schema, and pins the `MAIL_MESSAGE` plaintext layout. No new cryptographic construction is introduced: every object below reuses the symmetric envelope (algorithm 0x01, [§9.1](../CRYPTO.md#91-symmetric-envelope-algorithm-0x01)), the HPKE envelope (0x10, [§9.2](../CRYPTO.md#92-hpke-envelope-algorithms-0x10-and-0x12)), the §8.5 frame, and the §2 primitives (`u8`/`u16`/`u32`, `bytes`, `str`).

## Decision

### 1. Lookup: THREAT_MODEL option (a), accepted as the design

`resolve` rejects an unknown alias and a disabled alias through the identical response, on the identical code path ([INV-47](../THREAT_MODEL.md#8-security-invariants)): same `mail_aliases` lookup, same "no row or `enabled = false`" branch, same SMTP reply. It accepts an active alias. This ADR fixes the schema and the branch; the exact SMTP reply text is ADR 0069's, and whether the two branches also need to run in constant time is Open question 4, below. No-enumeration rests entirely on alias entropy (≥64 random bits per generated local part, [INV-65](../THREAT_MODEL.md#8-security-invariants)) and on `api`'s per-IP RCPT rate limit and tarpit ([THREAT_MODEL §6.4](../THREAT_MODEL.md#64-mitigations)), not on hiding which addresses accept mail. ROADMAP §4.8's row changes, on acceptance, from "alias → owner lookup without revealing which aliases exist (no SMTP user enumeration)" to "alias → owner lookup that does not reveal which aliases exist beyond confirming a guessed address; generated addresses carry enough entropy that guessing them is infeasible" (THREAT_MODEL Q-18's wording).

### 2. Account-level mail key linkage: accepted for v1.0

`resolve` keeps returning the account's single current mail-key bundle, per [ADR 0006](0006-key-hierarchy.md) point 8 and `MAIL_SECRET_KEY`. A compromised `smtp` can therefore link aliases of one account (THREAT_MODEL AR-21); this is accepted for v1.0 and revisited at M9 when multiple mail domains make per-alias or per-domain keys worth their cost (THREAT_MODEL Q-19).

### 3. Storage: `mail_aliases`, no server-visible item link

A new table, under [ADR 0011](0011-storage.md) rule 5's `mail_` prefix, owned by `rizzy-domain-mail` ([ADR 0016](0016-workspace-layout.md)):

| Column | Type | Clear or cipher | Notes |
|---|---|---|---|
| `account_id` | `BLOB`/`bytea` (16) | clear | The one cross-domain FK this domain uses ([ADR 0011](0011-storage.md) rule 6): `REFERENCES auth_accounts(id) ON DELETE CASCADE` |
| `alias_id` | `BLOB`/`bytea` (16) | clear | Primary key; 16 random bytes, client-generated ([CRYPTO.md §2](../CRYPTO.md#2-conventions) id convention) |
| `local_part` | `TEXT` | clear | ASCII, lowercased like `login_name` ([CRYPTO.md §2](../CRYPTO.md#2-conventions)); "alias addresses" are already on ADR 0011's clear-text allow-list |
| `domain` | `TEXT` | clear | Must be one of the operator's configured domains (a config value, not a table, until M9's multi-domain row) |
| `label` | `BLOB`/`bytea` | **cipher** | `Envelope(account_key, MAIL_ALIAS_LABEL, account_id ‖ alias_id)`, algorithm 0x01 reused, new purpose id `0x0061`. A free-text label is not on ADR 0011's clear-text allow-list, and it would tell the server what the alias is for; sealing it under the already-defined account key costs one new AAD-purpose row, not a new construction |
| `enabled` | flag (`u8`/`boolean`) | clear | Needed by `resolve` itself |
| `created_at` | `INTEGER`/`bigint` ms | clear | Server-set, per [ADR 0011](0011-storage.md) rule 4 |

Unique index on `(domain, local_part)`. Creation is `POST /api/v1/mail/aliases` ([ADR 0028](0028-api-v1-http-conventions.md)'s error-code table, item 3): the client picks `alias_id` and `local_part` (random, or user-typed for a human-readable address); a `(domain, local_part)` collision is refused with a new code, `409 alias_local_part_taken`, distinct from the existing `record_conflict`/`state_conflict` codes so a client never takes their CAS-resend path for what is only a naming collision, and retries with fresh randomness instead. `resolve(alias_address, last_pinned_bundle_seq)` splits `alias_address` into `local_part`/`domain` — the wire shape of the call itself is ADR 0069's — looks up the row, and returns `reject` when no row matches or `enabled = false`, otherwise `accept(alias_id, …)` as [ADR 0010](0010-server-shape.md) §2 already specifies. This and the two §5 calls add 3 endpoints under a new `mail` resource group to ADR 0028 item 1's list — the 12th resource group (after the base nine, plus sibling ADRs 0054's `attachments` and 0064's `shares`, in ADR-number order) and a cumulative endpoint count of 40 (base 27, plus 0054's +5, 0064's +4 and 0066's +1 ahead of this ADR's own +3); all three follow item 1's convention unchanged (`POST`, verb-last, no id in a URL), so, as ADR 0031 and ADR 0032's own pre-v1.0 wire changes did, they need only ADR 0002 point 5's minimum-client-version process, not a partial supersession of item 1 (contrast ADR 0028 item 3's error-code table, which is a closed list every client branches on by name and so does need one, below).

**No server-visible link to a vault item.** `mail_aliases` has no `item_id` column and no foreign key into `vault_` tables. Instead, the vault item that owns an alias carries the association itself, encrypted: a new item field, added under [ADR 0018](0018-item-record-encoding.md) §7's own provision for new keys —

| Key | Value | Types | Notes |
|---|---|---|---|
| `alias.id` | Bytes, 16 | Login | The `alias_id` of the `mail_aliases` row this login's address was generated from. Absent when the login's address is not a generated alias |

This is the "linked by `alias_id` carried inside the item's encrypted fields" model: the server can route mail by `(account_id, local_part, domain, enabled)` without ever learning which item, or how many items, reference a given `alias_id`.

### 4. `MAIL_MESSAGE` plaintext layout (pins CRYPTO.md §11.13 step 3)

The `data` inside the §8.5 frame of a `MAIL_MESSAGE` envelope:

```
data (MAIL_MESSAGE)
  u8    mail_message_version = 0x01   other values rejected (rule 3 below)
  u8    spf_result                    one MailAuthResult code (table below)
  u8    dkim_result                   one MailAuthResult code (table below)
  u8    dmarc_result                  one MailAuthResult code (table below)
  str   spam_score                    rspamd's score, ASCII decimal as reported (may be signed,
                                       e.g. "-1.23"); "" means not scored (rspamd unreachable),
                                       never rendered as the score zero
  bytes envelope_from                 SMTP MAIL FROM as received, opaque bytes
  bytes rcpt_to                       SMTP RCPT TO that matched this alias, opaque bytes
  bytes raw_mime                      the message exactly as received after DATA
```

`bytes(x) = u32(len) ‖ x` ([§2](../CRYPTO.md#2-conventions)); `str(x)` is `bytes(UTF-8(x))`, the same framing plus a UTF-8 contract that `bytes` does not carry — load-bearing below. No signed-integer convention is added to §2. `received_at_ms` is not repeated here: it is already in the envelope's AAD context ([CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes)), the same reasoning ADR 0018 owner decision 3 used for the item VV.

**`envelope_from` and `rcpt_to` are `bytes`, not `str`.** They are SMTP protocol bytes from an anonymous session on the open internet ([ADR 0010](0010-server-shape.md) Context, "accepts mail from anyone on port 25"), not guaranteed valid UTF-8 (a conforming `SMTPUTF8` mailbox is UTF-8, but nothing stops a non-conforming peer from sending otherwise). `str` would bind them to a text contract they cannot promise to meet; as `bytes`, `smtp` copies them from the command line verbatim, unvalidated. The mailbox UI decodes them the way it decodes any other untrusted display bytes (lossily, never panicking on invalid UTF-8); that decoding rule is the UI's, not this ADR's.

**`MailAuthResult` (one byte, shared by the three fields):** `0x00` none (the check ran; no SPF/DKIM/DMARC record is published for this domain), `0x01` pass, `0x02` fail, `0x03` softfail (SPF only), `0x04` neutral, `0x05` temperror, `0x06` permerror, `0x07`-`0xFE` reserved, `0xFF` not evaluated (the check never ran, e.g. mail-auth unreachable — distinct from `none`, which is a definite result). This id set is fixed here, independent of any crate; ADR 0070 (sibling), once Accepted, states the mapping from its chosen implementation's own result type onto these ids, including which of `softfail`/`neutral` a DKIM or DMARC checker that has no such state should never emit.

**Limits:** `spam_score` ≤ 32 bytes; `envelope_from` and `rcpt_to` ≤ 320 bytes each (a cap at or above RFC 5321 §4.5.3.1.3's mailbox-length limit, L: not re-verified this session); `raw_mime` is bounded by the §8.5 frame's `data` ceiling (16 MiB − 4 bytes) minus the other fields' overhead: 4 fixed bytes (`mail_message_version ‖ spf_result ‖ dkim_result ‖ dmarc_result`) plus a 4-byte length prefix for each of `spam_score`, `envelope_from`, `rcpt_to` and `raw_mime` itself (16 bytes), so `len(raw_mime) ≤ (16 MiB − 24) − len(spam_score) − len(envelope_from) − len(rcpt_to)`, a bound in the other three fields' lengths, not a constant. `smtp`'s own message-size cap (ROADMAP §4.8 "Size limits", ADR 0069) is a fixed setting, so it is pinned against the worst case of that bound — the other three fields at their own ceilings (32 + 320 + 320 = 672 bytes) — giving a fixed ceiling of 16 MiB − 696 bytes (16,776,520); ADR 0069's cap must sit at or below that and is enforced at `DATA`, before this record is built, never by truncation. Every stored `raw_mime` byte counts toward the account's storage quota like any other stored ciphertext (ADR 0048, sibling in this batch).

**Parsing (mirrors [ADR 0018](0018-item-record-encoding.md) §5's style, simplified for a record nobody merges or state-hashes — it is written once by `smtp` and read as-is by the account's own devices, so ADR 0018's one-encoding-per-state canonicity rule does not need to bind it):**
1. `mail_message_version ≠ 1`, a length that breaks a §Limits bound or runs past the end, or trailing bytes after `raw_mime` → the whole record is rejected and reported like a failed decryption; never a panic, and no allocation in proportion to a length before it is bounds-checked ([CRYPTO.md §9.5](../CRYPTO.md#95-parsing-and-allow-list-rules) rule 5, reused, not redefined). This includes a non-UTF-8 `envelope_from`/`rcpt_to`: as `bytes`, not `str`, no UTF-8 check applies to them at all.
2. A `spf_result`/`dkim_result`/`dmarc_result` value in `0x07`-`0xFE` (reserved) is carried and ignored, never rejected, so a future mail-auth result needs no version bump.
3. An unrecognised `mail_message_version` shows as "Unsupported message, update rizzy-vault" (the mailbox-UI counterpart of ADR 0018's "Unsupported item"), not a dropped message. 0 and `0xFF` are reserved and always rejected; 2-254 are unassigned, each needing a line in a future ADR, same rule as `item_schema_version`.

**Tests:** normative vectors (CRYPTO.md §15, a new item) covering each defined `MailAuthResult` code in each of the three fields, a reserved code carried through unrejected, an empty `envelope_from` (null-sender bounce), a non-UTF-8 `envelope_from`, and `raw_mime` at its maximum given an empty `spam_score` and minimal `envelope_from`/`rcpt_to`; one negative vector per Parsing rule above; a fuzz target over `data`, registered in the scheduled job ([ADR 0009](0009-crypto-dependency-policy.md) owner decision 4) alongside ADR 0018's targets.

### 5. Lifecycle: disable and delete

Both are plain authenticated API calls, never signed ops: `POST /api/v1/mail/aliases/disable` and `POST /api/v1/mail/aliases/delete`, each body-only with `{alias_id}` ([ADR 0028](0028-api-v1-http-conventions.md) item 1: `POST` for everything, verb-last, no id in a URL or access log, INV-52 — the same convention §3's creation endpoint already follows). This table is server-routing metadata, like `auth_` session state, not synced vault content. Disabling flips `enabled`; `resolve` then rejects it on the same path as unknown (§1). Deleting removes the row outright. **Mail already received under that alias is unaffected by either call.** The table that stores `MAIL_MESSAGE` ciphertext (`mail_messages` or similar; its own schema is ADR 0069's to define) must not take a foreign key to `mail_aliases` with `ON DELETE CASCADE`: [ADR 0011](0011-storage.md) rule 6 caps only the one *cross*-domain foreign key, so a same-domain cascade from `mail_aliases` to stored mail is otherwise permitted by that rule and would silently delete received mail on an alias delete. This ADR forbids it explicitly. Neither lifecycle call touches the owning item's `alias.id` field; the client issues a separate, ordinary item edit (clearing `alias.id`, per the normal sync path) when the user deletes an alias from its item's view. The two calls are not atomic with each other, by construction (§3): see Risks.

### Proposed invariants

To add to [THREAT_MODEL.md §8.7](../THREAT_MODEL.md#87-mail) on acceptance, allocated across the 2026-10-11 batch in ADR-number order. Provisional: the allocation was made across the 2026-10-11 batch in ADR-number order; if ADRs are accepted out of order, the owner renumbers at acceptance.

- **proposed INV-93.** `mail_aliases` carries no column and no foreign key that names a vault item, a vault, or an account's item count; the alias-to-item association exists only inside that item's encrypted fields.
- **proposed INV-94.** `mail_aliases.label`, where present, is ciphertext under the account key (`MAIL_ALIAS_LABEL`); no free-text column describing an alias's purpose is ever added without this ADR's successor.
- **proposed INV-95.** Disabling or deleting a `mail_aliases` row never deletes, hides or re-routes mail already stored under its `alias_id`; the stored-mail table carries no `ON DELETE CASCADE` from `mail_aliases`.

### On acceptance

None of these edits is made now; the owner makes them in the change that accepts this ADR, the same convention [ADR 0018](0018-item-record-encoding.md) uses:

1. [CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes)'s table gains the `MAIL_ALIAS_LABEL` (0x0061) row from §3.
2. [CRYPTO.md §11.13](../CRYPTO.md#1113-mail-ingress-m6) step 3's sentence on `metadata` is replaced by a cross-reference to this ADR's §4.
3. [THREAT_MODEL.md §8.7](../THREAT_MODEL.md#87-mail) gains the "Proposed invariants" above as INV-93, INV-94 and INV-95; Q-18 and Q-19 in [§10](../THREAT_MODEL.md#10-open-questions-for-the-owner) are marked Decided, citing this ADR.
4. [ROADMAP.md §4.8](../ROADMAP.md#48-aliases--email-receiving-m6)'s lookup row is reworded as in §1 above.
5. [ADR 0028](0028-api-v1-http-conventions.md) item 3's `409` list gains `alias_local_part_taken`; the owner appends "; [ADR 0068](0068-alias-identity-model.md) (item 3 in part)" to ADR 0028's existing status line ("Partially superseded by [ADR 0031](0031-retiring-old-opaque-setups.md) (item 3 in part); [ADR 0032](0032-healing-rotation-after-backup.md) (item 3 in part)"), one "Partially superseded by" prefix, semicolon-separated entries (ADR 0020 point 9).

## Consequences

### Positive

- `resolve`/`deliver` and the mailbox UI now have a concrete, reviewable table instead of a placeholder.
- The server never learns which vault item, or how many items, an alias serves, matching the zero-knowledge posture the rest of the vault already has.
- Reusing algorithm 0x01, HPKE 0x10 and the §8.5 frame means no new construction reaches the M8 audit scope.
- `MAIL_MESSAGE`'s layout is now cross-platform-pinned, the same reason ADR 0018 pinned item records.

### Negative

- One more AAD-purpose row (`MAIL_ALIAS_LABEL`) and one more small envelope per alias, for a feature (a label) that is cosmetic.
- Disable/delete and the item-field edit are two independent calls; a crash or a dropped connection between them leaves a dangling `alias.id` (pointing at a deleted or disabled alias) or an enabled `mail_aliases` row no item references. Neither is a security problem — a dangling `alias.id` just displays as "deleted" and an orphan alias row just keeps accepting mail nobody reads — but it needs a reconciliation story (§Open questions).
- Catch-all per domain plus a 409-on-collision create path means an attacker who can create many accounts can learn whether a specific guessed `local_part` is already taken on a given domain; this is weaker than RCPT probing (authenticated, rate-limited the same as any account action) and is accepted on that basis, not re-litigated here.

### Risks

- If a future client skips clearing `alias.id` on delete, the owner of a stale reference could be confused about why an old alias "still shows" on an item. Mitigation is UX, not crypto: the client should treat an `alias.id` that no longer resolves in the account's alias list as "deleted," locally, without a server round trip per item.
- An indexed `(domain, local_part)` lookup has different hit/miss timing by construction; §1 claims only an identical response and code path, not a timing guarantee. Whether `resolve` also needs to run in constant time is Open question 4, below.

## Alternatives considered

- **Per-alias mail keys** (true unlinkability). Rejected per THREAT_MODEL Q-19/AR-21: one more signed key and bundle entry per alias, against a linkage a compromised `smtp` already gets for free once mail arrives.
- **THREAT_MODEL option (b)** (accept every RCPT, drop unknown/disabled after `DATA`). Rejected: stores and spam-scans mail for addresses that were never allocated, and breaks ROADMAP §4.8's "rejected at SMTP time".
- **`mail_aliases.item_id` as a server-visible foreign key to `vault_items`.** The simplest schema, and exactly the leak this ADR exists to avoid: the server would then know which item each alias belongs to, a direct map of part of the user's vault structure. Rejected.
- **Plaintext `label` column.** Simpler, but not on ADR 0011's clear-text allow-list and it leaks the alias's purpose. Rejected in favour of the encrypted column (§3).
- **A `mail_domains` table.** YAGNI before M9's multi-domain/custom-domain row; one operator-configured list is enough for one or a few domains.

## Open questions for the owner

1. **Keep the encrypted `label` column, or drop it and rely solely on the owning item's `item.name`?** *Recommendation:* keep it. It lets an alias-management screen show a human label while the vault is locked (the web vault often is); dropping it saves one AAD-purpose row but forces "unlock to see what this alias was for."
2. **Should alias creation default to a random, high-entropy `local_part`, with a human-chosen one offered as an explicit, labelled-as-guessable opt-in?** *Recommendation:* yes, default random (THREAT_MODEL Q-18's own recommendation), so INV-65 holds for the common case and the UI, not this ADR, carries the guessability warning for the opt-in.
3. **Reconciliation for a dangling `alias.id` or an orphaned `mail_aliases` row (Negative, above).** *Recommendation:* client-side only, on each alias-list fetch: diff the account's `mail_aliases` list against every item's `alias.id` field already loaded; flag (never auto-delete) a mismatch in either direction. No server change, no signed op, no new invariant.
4. **Does `resolve`'s unknown/disabled-vs-active branch need to run in constant time, on top of returning the identical response?** An indexed lookup's hit and miss paths differ in work done, which a very precise timing side channel could exploit to probe a guessed address faster than RCPT. *Recommendation:* no, for M6 — this is a strictly smaller channel than the already-accepted "a compromised `smtp` can enumerate aliases slowly" ([AR-21](../THREAT_MODEL.md#9-accepted-risks-and-out-of-scope)), and constant-time DB lookups are a disproportionate cost for personal-scale deployments. ADR 0069 may add response-time padding if its own timing analysis of the SMTP path says otherwise.

## References

- [ROADMAP.md](../ROADMAP.md) §4.8
- [THREAT_MODEL.md](../THREAT_MODEL.md) §6, §8.7 (INV-47, INV-65), §9 (AR-20, AR-21), §10 (Q-18, Q-19)
- [CRYPTO.md](../CRYPTO.md) §2, §8.4, §8.5, §9.1, §9.2, §9.5 rule 5, §11.13
- [ADR 0006](0006-key-hierarchy.md) point 8, [ADR 0010](0010-server-shape.md) §2, [ADR 0011](0011-storage.md) rules 4-6, [ADR 0016](0016-workspace-layout.md) (`rizzy-domain-mail`, V), [ADR 0018](0018-item-record-encoding.md) §3-§7, [ADR 0028](0028-api-v1-http-conventions.md)
- ADR 0069, ADR 0070, ADR 0048 — siblings in this ADR batch, cited above for scope boundaries only
- RFC 5321 §4.5.3.1.3 (SMTP mailbox length limits, L: not re-verified this session)
