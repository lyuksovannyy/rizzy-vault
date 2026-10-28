# ADR 0068: Alias identity model, storage, and no-enumeration lookup

- Status: Accepted
- Date: 2026-10-11
- Deciders: project owner
- Milestone: M6
- Supersedes: on acceptance, in part: [ADR 0048](0048-per-account-storage-quota.md) (§5 in part: its complete replacement of [ADR 0028](0028-api-v1-http-conventions.md) item 3's first sentence, which gains two `409` codes, `alias_local_part_taken` and `alias_limit_reached`) and [ADR 0028](0028-api-v1-http-conventions.md) (item 1 in part: a new `mail` resource, as ADR 0075 and ADR 0081 did). §6 below names the parts and gives the replacement text. Otherwise extends without superseding: [ADR 0006](0006-key-hierarchy.md) point 8 (mail key, referenced, unchanged), [ADR 0010](0010-server-shape.md) §2 (gives `resolve`/`deliver` a concrete schema, text unchanged), [ADR 0011](0011-storage.md) rule 5 (defines the first `mail_` table under its existing rule, text unchanged), and [ADR 0018](0018-item-record-encoding.md)'s §7 provision that "a new key needs a line in the ADR that ships it". Does not define the smtp↔api wire protocol or the SMTP listener (ADR 0069, sibling in this batch) or approve `mail-auth` (ADR 0070, sibling); it only supplies the schema and record layout those rely on.

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
| `local_part` | `TEXT` | clear | The canonical form of §3's "Addresses" grammar (lowercase `[a-z0-9._-]`, 1–64 octets); "alias addresses" are already on ADR 0011's clear-text allow-list |
| `domain` | `TEXT` | clear | Must be one of the operator's configured domains (a config value, not a table, until M9's multi-domain row) |
| `label` | `BLOB`/`bytea`, `NULL` when the alias has no label | **cipher** | `Envelope(account_key, MAIL_ALIAS_LABEL, account_id ‖ alias_id ‖ u32 account_key_epoch)`, algorithm 0x01 reused, new purpose id `0x0061`. Plaintext: the label as NFC UTF-8 ([CRYPTO.md §2](../CRYPTO.md#2-conventions)), 1–128 bytes, framed and padded by [§8.5](../CRYPTO.md#85-plaintext-framing-and-padding), so the envelope does not show the label's length. A free-text label is not on ADR 0011's clear-text allow-list, and it would tell the server what the alias is for; sealing it under the already-defined account key costs one new AAD-purpose row, not a new construction. The epoch names the account key, as in every other account-key purpose (`VAULT_KEY_SELF_GRANT`, `MAIL_SECRET_KEY`); a rotation re-seals every label ("Rotation", below) |
| `label_epoch` | `INTEGER`/`bigint` (`u32`), `NULL` exactly when `label` is | clear | The `account_key_epoch` the label is sealed under. The server stores a label only at the account's current `account_key_epoch` (creation and "Rotation", below), so it always equals it; a client that reads another value treats the label as a failed decryption |
| `enabled` | flag (`u8`/`boolean`) | clear | Needed by `resolve` itself |
| `created_at` | `INTEGER`/`bigint` ms | clear | Server-set, per [ADR 0011](0011-storage.md) rule 4 |

Unique index on `(domain, local_part)`.

**Addresses.** An alias address is `local_part@domain`, `domain` one of the operator's configured domains. `local_part` is 1–64 octets (RFC 5321 §4.5.3.1.1, L) of lowercase `[a-z0-9._-]`, with no leading, trailing or doubled `.`: the grammar [ADR 0079](0079-identity-generator.md) §4 step 10 already emits, so every generated local part, ADR 0079 §9's base32-token form included, is valid as it is. No `+` (left free for sub-addressing, never part of an allocated name), no quoted form, no non-ASCII. The client lowercases a typed local part before sending it; the server never normalises, and refuses a `local_part` that is not already in this canonical form with `400 invalid_request`, so each address has exactly one stored spelling. `resolve` lowercases the RCPT local part before the lookup and treats one outside the grammar as unknown, on the same path (§1).

- **Reserved names**, refused at creation with `400 invalid_request`: `postmaster` and `abuse` (the role addresses RFC 5321 §4.5.1 and RFC 2142 expect the domain's operator to own, L); `admin`, `administrator`, `hostmaster` and `webmaster` (the addresses a certificate authority may mail to validate control of the domain, CA/Browser Forum Baseline Requirements §3.2.2.4.4, L: not re-verified this session; a user holding one could obtain a TLS certificate for the alias domain); `root`, `mailer-daemon`, `security`, `noc`, `noreply`, `no-reply`. The list is fixed here so that clients refuse the same names before sending; a new name is a change to this ADR.
- **Per-account cap.** At most 1 000 rows in `mail_aliases` per account (active and disabled count; deleted aliases do not, §5). One more is refused with a new code, `409 alias_limit_reached`.
- **Creation rate.** At most 100 creations per account per rolling 24 h, then the existing `429 rate_limited`. The bucket is a `mail_`-prefixed table with `rizzy-domain-auth` `ratelimit.rs`'s counting rules (ADR 0011 rule 5: the mail domain keeps its own state). It bounds how fast one account can add rows to the permanent register of §5.

**Creation** is `POST /api/v1/mail/aliases/create` (verb last, as ADR 0064's `shares/create`) on the owner's session, body `{alias_id, domain, local_part, label?, label_epoch?}` under ADR 0028 item 7's 1 MiB limit; a field past its bound above is `400 invalid_request`. The client picks `alias_id` and `local_part` (random, or user-typed for a human-readable address). In one transaction under the account lock, the server checks the cap, inserts `(domain, local_part)` into `mail_alias_addresses` (§5) and inserts the `mail_aliases` row. An address already in `mail_alias_addresses`, whether a live alias of any account holds it or an alias deleted at any earlier time did, is refused with a new code, `409 alias_local_part_taken`, distinct from the existing `record_conflict`/`state_conflict` codes so a client never takes their CAS-resend path for what is only a naming collision, and retries with fresh randomness instead. A label whose `label_epoch` is not the account's current `account_key_epoch` is refused with the existing `409 stale_epoch`; the client re-seals and retries. `resolve(alias_address, last_pinned_bundle_seq)` splits `alias_address` into `local_part`/`domain` — the wire shape of the call itself is ADR 0069's — looks up the row, and returns `reject` when no row matches or `enabled = false`, otherwise `accept(alias_id, …)` as [ADR 0010](0010-server-shape.md) §2 already specifies.

**Rotation.** A standard or full rotation ([CRYPTO.md §11.6](../CRYPTO.md#116-key-rotation)) replaces the account key, so its step 3 re-seals every label next to `MAIL_SECRET_KEY`: the rotating client opens each label under the old account key and seals it under account key' at `account_key_epoch + 1`. The commit carries them as one optional list, `alias_labels: List<{alias_id, label}, 1000>` (`deny_unknown_fields`, present exactly when the account has a labelled alias). In the commit's transaction, under the account lock, through a `rizzy-domain-mail` port that `rizzy-domain-auth` calls the way it calls `VaultPort::apply_rotation` ([ADR 0025](0025-rotation-vault-half.md)), the server refuses a commit whose list does not name exactly the account's aliases with a non-`NULL` label (the same "exactly those" check CRYPTO.md §11.6 step 3 makes for `regrants`), and stores each label with `label_epoch` set to the new epoch. A create that raced the rotation carries the old epoch and fails with `stale_epoch` (above). An alias without a label needs nothing.

**Endpoints.** Creation and the four §5 calls add 5 endpoints under a new `mail` resource. ADR 0028 item 1's first sentence is superseded in part for it (§6), as [ADR 0075](0075-session-listing-and-ending.md) §1 and [ADR 0081](0081-multiple-vaults-personal-and-shared.md) did for their resources: the count is whatever the `http/api.rs` module table holds once every accepted change has landed. All five follow item 1's convention unchanged (`POST`, verb last, every id a body field, no id in a URL or access log, INV-52). Before v1.0 they are additive, since an older client never calls them, so they need only ADR 0002 point 5's changelog entry, not a raise of the minimum client versions. Their retry classes are in §6.

**No server-visible link to a vault item.** `mail_aliases` has no `item_id` column and no foreign key into `vault_` tables. Instead, the vault item that owns an alias carries the association itself, encrypted: a new item field, added under [ADR 0018](0018-item-record-encoding.md) §7's own provision for new keys —

| Key | Value | Types | Notes |
|---|---|---|---|
| `alias.id` | Bytes, 16 | Login, Identity | The `alias_id` of the `mail_aliases` row this item's address was generated from: a login's address, or a generated identity's email ([ADR 0079](0079-identity-generator.md) §9 item 1). Absent when the item's address is not a generated alias |

This is the "linked by `alias_id` carried inside the item's encrypted fields" model: the server can route mail by `(account_id, local_part, domain, enabled)` without ever learning which item, or how many items, reference a given `alias_id`.

### 4. `MAIL_MESSAGE` plaintext layout (pins CRYPTO.md §11.13 step 3)

The `data` inside the §8.5 frame of a `MAIL_MESSAGE` envelope:

```
data (MAIL_MESSAGE)
  u8    mail_message_version = 0x01   other values: rules 1 and 3 below
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

**Limits:** `spam_score` ≤ 32 bytes; `envelope_from` and `rcpt_to` ≤ 320 bytes each (a cap at or above RFC 5321 §4.5.3.1.3's mailbox-length limit, L: not re-verified this session); `raw_mime` is bounded by the §8.5 frame's `data` ceiling (16 MiB − 4 bytes) minus the other fields' overhead: 4 fixed bytes (`mail_message_version ‖ spf_result ‖ dkim_result ‖ dmarc_result`) plus a 4-byte length prefix for each of `spam_score`, `envelope_from`, `rcpt_to` and `raw_mime` itself (16 bytes), so `len(raw_mime) ≤ (16 MiB − 24) − len(spam_score) − len(envelope_from) − len(rcpt_to)`, a bound in the other three fields' lengths, not a constant. `smtp`'s own message-size cap (ROADMAP §4.8 "Size limits", ADR 0069) is a fixed setting, so it is pinned against the worst case of that bound — the other three fields at their own ceilings (32 + 320 + 320 = 672 bytes) — giving a fixed ceiling of 16 MiB − 696 bytes (16,776,520); ADR 0069's cap must sit at or below that and is enforced at `DATA`, before this record is built, never by truncation. Every stored `raw_mime` byte counts toward the account's storage quota like any other stored ciphertext ([ADR 0048](0048-per-account-storage-quota.md), Accepted).

**Parsing (mirrors [ADR 0018](0018-item-record-encoding.md) §5's style, simplified for a record nobody merges or state-hashes — it is written once by `smtp` and read as-is by the account's own devices, so ADR 0018's one-encoding-per-state canonicity rule does not need to bind it):**
1. `mail_message_version` 0 or `0xFF` (reserved, never valid), or, in a version 1 record, a length that breaks a §Limits bound or runs past the end, or trailing bytes after `raw_mime` → the whole record is rejected and reported like a failed decryption; never a panic, and no allocation in proportion to a length before it is bounds-checked ([CRYPTO.md §9.5](../CRYPTO.md#95-parsing-and-allow-list-rules) rule 5, reused, not redefined). This includes a non-UTF-8 `envelope_from`/`rcpt_to`: as `bytes`, not `str`, no UTF-8 check applies to them at all.
2. A `spf_result`/`dkim_result`/`dmarc_result` value in `0x07`-`0xFE` (reserved) is carried and ignored, never rejected, so a future mail-auth result needs no version bump.
3. A `mail_message_version` from 2 to 254 is unassigned (each needs a line in a future ADR, the same rule as `item_schema_version`). Such a record is not parsed past its first byte and not rejected: the client keeps the ciphertext and shows "Unsupported message, update rizzy-vault" (the mailbox-UI counterpart of ADR 0018's "Unsupported item"), never a dropped or broken message. Rule 1 alone decides what is corrupt.

**Tests:** normative vectors (CRYPTO.md §15, a new item) covering each defined `MailAuthResult` code in each of the three fields, a reserved code carried through unrejected, an empty `envelope_from` (null-sender bounce), a non-UTF-8 `envelope_from`, and `raw_mime` at its maximum given an empty `spam_score` and minimal `envelope_from`/`rcpt_to`; one negative vector per rejection in Parsing rule 1, and a version 2 record shown as unsupported, not rejected (rule 3); a fuzz target over `data`, registered in the scheduled job ([ADR 0009](0009-crypto-dependency-policy.md) owner decision 4) alongside ADR 0018's targets.

### 5. Lifecycle: list, disable, enable, delete, and the permanent address register

Every lifecycle call is a plain authenticated API call on the owner's session, never a signed op, body-only ([ADR 0028](0028-api-v1-http-conventions.md) item 1: `POST` for everything, verb last, no id in a URL or access log, INV-52 — the convention §3's creation endpoint follows). This table is server-routing metadata, like `auth_` session state, not synced vault content.

- **`POST /api/v1/mail/aliases/list`**, body `{}`: every `mail_aliases` row of the account, as `alias_id`, `domain`, `local_part`, `enabled`, `created_at`, `label` and `label_epoch` (the sealed label as stored; the client opens it). Not paged: the per-account cap of §3 bounds it to 1 000 rows of a few hundred bytes each plus the label envelope (at least 256 + 90 bytes, §8.5 and §9.1), under 1 MiB (an estimate, not measured). It is what the alias-management screen (Open question 1), the reconciliation of Open question 3 and [ADR 0079](0079-identity-generator.md) §9's Mailbox panel read. A deleted alias is not listed.
- **`POST /api/v1/mail/aliases/disable`** and **`…/enable`**, body `{alias_id}`: set `enabled` to false or true. `resolve` then rejects a disabled alias on the same path as an unknown one (§1) and accepts it again once enabled. An `alias_id` the account holds no row for is `404 not_found`, so a deleted alias cannot be enabled.
- **`POST /api/v1/mail/aliases/delete`**, body `{alias_id}`: removes the `mail_aliases` row, so `resolve` rejects the address on the same path as an unknown one (§1, INV-47). **Deleting is permanent:** the address stays in the register below and can never be created again, by any account (proposed INV-109). The client says so before it deletes and offers disable as the reversible choice.

**The permanent address register.** A second table, `mail_alias_addresses`, owned by `rizzy-domain-mail`:

| Column | Type | Clear or cipher | Notes |
|---|---|---|---|
| `domain` | `TEXT` | clear | As `mail_aliases.domain` |
| `local_part` | `TEXT` | clear | As `mail_aliases.local_part` |
| `allocated_at` | `INTEGER`/`bigint` ms | clear | Server-set at creation, per [ADR 0011](0011-storage.md) rule 4 |

Primary key `(domain, local_part)`. Every creation inserts its row in the creation's transaction (§3), and **no code path updates or deletes a row**: not alias deletion, not `worker`, and not account deletion, since the table has no `account_id` and no foreign key, so ADR 0011 rule 6's cascade, which removes the account's `mail_aliases` rows, never reaches it. Without the register, a deleted alias's address would become free again: another account on the instance could create it and receive the mail meant for the previous owner, including password resets and login codes from every site the alias was registered on (alias takeover; gap review of 2026-10-25, B3). Once an alias is deleted, its register row holds only the address and its allocation time, nothing that names the account. Both tables are in the logical backup ([ADR 0023](0023-logical-backup-format.md) `TABLES`, `mail_alias_addresses` before `mail_aliases`, with the dump schema-version bump every migration brings): a restore without the register would reopen every deleted address.

**Mail already received under that alias is unaffected by any of these calls.** The table that stores `MAIL_MESSAGE` ciphertext (`mail_messages` or similar; its own schema is ADR 0069's to define) must not take a foreign key to `mail_aliases` with `ON DELETE CASCADE`: [ADR 0011](0011-storage.md) rule 6 caps only the one *cross*-domain foreign key, so a same-domain cascade from `mail_aliases` to stored mail is otherwise permitted by that rule and would silently delete received mail on an alias delete. This ADR forbids it explicitly. No lifecycle call touches the owning item's `alias.id` field; the client issues a separate, ordinary item edit (clearing `alias.id`, per the normal sync path) when the user deletes an alias from its item's view. The two calls are not atomic with each other, by construction (§3): see Risks.

**Tests** (`rizzy-domain-mail`, both engines): account A creates `x@d` and deletes it, then A's and account B's creates of `x@d` both get `alias_local_part_taken`; the same after A's account is deleted (the cascade leaves the register row), and after a backup and restore; `resolve` answers a deleted address exactly as a never-allocated one (INV-47's test, extended); a byte-identical retried create succeeds and leaves one register row; each reserved name, an upper-case letter, `+`, a leading, trailing or doubled `.`, 65 octets and an empty local part are `invalid_request`; the 1 001st alias is `alias_limit_reached`; `list` returns exactly the live rows; `enable` after `disable` restores `accept`, and `enable` of a deleted alias is `not_found`; a label sealed at the previous epoch is `stale_epoch`; a rotation commit whose `alias_labels` misses or adds an alias is refused, and one that names them all leaves every label opening under account key' at the new epoch. KAT ([CRYPTO.md §15](../CRYPTO.md#15-testing)): one `MAIL_ALIAS_LABEL` envelope with fixed key, ids, epoch and nonce.

### 6. What this ADR supersedes

Two Accepted parts ([ADR 0020](0020-partial-supersession.md) point 9). Everything else in ADR 0028 and ADR 0048 stays binding.

1. **[ADR 0048](0048-per-account-storage-quota.md) §5, the sentence it gives as "The complete item 3 replacement"**, which is the binding text of [ADR 0028](0028-api-v1-http-conventions.md) item 3's first sentence. Replacement, in full:

   > Every error under `/api/` is `{"error":"<code>"}` with this status: `invalid_request` and `client_too_old` 400; `unauthorized` and `second_factor_required` 401; `fresh_session_required` 403; `not_found` 404 (also an unknown `/api/` path, and a role not running); `state_conflict`, `stale_epoch`, `record_conflict`, `prev_seq_mismatch`, `setup_retired` (ADR 0031 point 3: a registration whose echoed OPAQUE `setup_id` is retired or unknown), `credentials_stale` (ADR 0032 §4: after KE3 verified, the account's OPAQUE record lags its signed state), `quota_exceeded` ([ADR 0048](0048-per-account-storage-quota.md) §3: the record would push the account's counted bytes past its quota and headroom), `alias_local_part_taken` ([ADR 0068](0068-alias-identity-model.md) §3: the new alias's address is allocated on this instance, now or at any earlier time), `alias_limit_reached` (ADR 0068 §3: the account already holds its maximum number of aliases) 409; `api_version_gone` 410; `payload_too_large` 413; `rate_limited` 429; `internal` 500.

   It carries forward ADR 0031's, ADR 0032's and ADR 0048's glosses, so naming the whole sentence narrows nothing. If another ADR that adds a code to this sentence is accepted first, the owner restates its code here at acceptance, as ADR 0048 §5 did for ADR 0031 and ADR 0032.
2. **[ADR 0028](0028-api-v1-http-conventions.md) item 1, first sentence, in part**, as already superseded in part by [ADR 0052](0052-icon-proxy-role.md), [ADR 0075](0075-session-listing-and-ending.md) and [ADR 0081](0081-multiple-vaults-personal-and-shared.md), following ADR 0075 §1's precedent: the resource list gains `mail`, with the five endpoints `mail/aliases/create`, `mail/aliases/list`, `mail/aliases/enable`, `mail/aliases/disable` and `mail/aliases/delete`. The count is whatever the `http/api.rs` module table holds once every accepted change has landed; the table stays the authoritative list. The rest of item 1 stands.

**Added, not superseded:** ADR 0028's "Retry after an unknown outcome" table gains one row and changes none (Open question 7):

| Class | Endpoints | A repeat | Owner |
|---|---|---|---|
| Mail aliases | `mail/aliases/create`, `mail/aliases/list`, `mail/aliases/enable`, `mail/aliases/disable`, `mail/aliases/delete` | `create`: a byte-identical repeat by the same account is success, without a second insert (the server looks up `alias_id` before the register, so a retry does not collide with its own address); a different body at an existing `alias_id` is `invalid_request`. `list` changes nothing. `enable` and `disable` give the same result. A repeated `delete` finds no row and answers success | [ADR 0068](0068-alias-identity-model.md) §3, §5 |

### Proposed invariants

To add to [THREAT_MODEL.md §8.7](../THREAT_MODEL.md#87-mail) on acceptance, allocated across the 2026-10-11 batch in ADR-number order. Provisional: the allocation was made across the 2026-10-11 batch in ADR-number order; if ADRs are accepted out of order, the owner renumbers at acceptance. INV-109 is outside that batch: it is the next free id after the ones [ADR 0085](0085-admin-authentication-bootstrap.md) (INV-107) and [ADR 0087](0087-invite-only-signup-tokens.md) (INV-108) were drafted with, added when the 2026-10-25 gap review found the alias-takeover gap, and equally provisional.

- **proposed INV-93.** `mail_aliases` carries no column and no foreign key that names a vault item, a vault, or an account's item count; the alias-to-item association exists only inside that item's encrypted fields.
- **proposed INV-94.** `mail_aliases.label`, where present, is ciphertext under the account key of the epoch in its ctx (`MAIL_ALIAS_LABEL`), which is always the account's current `account_key_epoch`; no free-text column describing an alias's purpose is ever added without this ADR's successor.
- **proposed INV-95.** Disabling or deleting a `mail_aliases` row never deletes, hides or re-routes mail already stored under its `alias_id`; the stored-mail table carries no `ON DELETE CASCADE` from `mail_aliases`.
- **proposed INV-109.** An alias address `(domain, local_part)` is allocated at most once per instance. Once created it stays in `mail_alias_addresses`, which no code path updates or deletes, and no later creation by any account, the first owner included, gets it: not after the alias is deleted, not after its account is deleted, and not after a restore from a backup taken after the address was allocated. *Verified by:* the §5 tests (re-creation by another account and by the same one after delete, after account deletion and after backup and restore, each `alias_local_part_taken`; `resolve` of a deleted address identical to an unknown one), and a repo check that no query file under `rizzy-domain-mail` holds an `UPDATE` or `DELETE` on `mail_alias_addresses`.

### On acceptance

None of these edits is made now; the owner makes them in the change that accepts this ADR, the same convention [ADR 0018](0018-item-record-encoding.md) uses:

1. [CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes)'s table gains the `MAIL_ALIAS_LABEL` (0x0061) row from §3: account key / 0x01, ctx `account_id ‖ alias_id ‖ u32 account_key_epoch`, M6. [§8.5](../CRYPTO.md#85-plaintext-framing-and-padding)'s list of framed plaintexts gains `MAIL_ALIAS_LABEL`. [§11.6](../CRYPTO.md#116-key-rotation) step 3 gains, after the `MAIL_SECRET_KEY` bullet: "every `mail_aliases` label (M6) re-sealed under account key' at `account_key_epoch + 1` (`alias_labels`; the server refuses a list that does not name exactly the account's labelled aliases, [ADR 0068](adr/0068-alias-identity-model.md) §3)."
2. [CRYPTO.md §11.13](../CRYPTO.md#1113-mail-ingress-m6) step 3's sentence on `metadata` is replaced by a cross-reference to this ADR's §4.
3. [THREAT_MODEL.md §8.7](../THREAT_MODEL.md#87-mail) gains the "Proposed invariants" above as INV-93, INV-94, INV-95 and INV-109; the §7 mail table's "S" row (forged senders, alias enumeration) adds "a deleted alias's address is never allocated again (INV-109)" to its mitigations and INV-109 to its invariants; Q-18 and Q-19 in [§10](../THREAT_MODEL.md#10-open-questions-for-the-owner) are marked Decided, citing this ADR.
4. [ROADMAP.md §4.8](../ROADMAP.md#48-aliases--email-receiving-m6)'s lookup row is reworded as in §1 above.
5. **Status lines and tables** ([ADR 0020](0020-partial-supersession.md) point 9, one "Partially superseded by" prefix, semicolon-separated entries): [ADR 0048](0048-per-account-storage-quota.md)'s "Accepted" becomes "Partially superseded by [ADR 0068](0068-alias-identity-model.md) (§5 in part)"; [ADR 0028](0028-api-v1-http-conventions.md)'s status line, whatever it holds then, gains "; [ADR 0068](0068-alias-identity-model.md) (item 1 in part)" (item 3's first sentence is already ADR 0048's text, so ADR 0028's line needs no item 3 entry); ADR 0028's retry table gains §6's row. The implementing migration adds `mail_alias_addresses` and `mail_aliases` to [ADR 0023](0023-logical-backup-format.md)'s `TABLES` (§5).

## Consequences

### Positive

- `resolve`/`deliver` and the mailbox UI now have a concrete, reviewable table instead of a placeholder.
- The server never learns which vault item, or how many items, an alias serves, matching the zero-knowledge posture the rest of the vault already has.
- Reusing algorithm 0x01, HPKE 0x10 and the §8.5 frame means no new construction reaches the M8 audit scope.
- A deleted alias's address is never handed to another account, so mail for the sites it was registered on cannot be captured by re-registering it (INV-109).
- Labels survive key rotation: the epoch in their ctx names the key, and the rotation commit re-seals them in the same transaction.
- `MAIL_MESSAGE`'s layout is now cross-platform-pinned, the same reason ADR 0018 pinned item records.

### Negative

- One more AAD-purpose row (`MAIL_ALIAS_LABEL`) and one more small envelope per alias, for a feature (a label) that is cosmetic.
- Disable/delete and the item-field edit are two independent calls; a crash or a dropped connection between them leaves a dangling `alias.id` (pointing at a deleted or disabled alias) or an enabled `mail_aliases` row no item references. Neither is a security problem — a dangling `alias.id` just displays as "deleted" and an orphan alias row just keeps accepting mail nobody reads — but it needs a reconciliation story (§Open questions).
- Catch-all per domain plus a 409-on-collision create path means an attacker who can create many accounts can learn whether a specific guessed `local_part` is taken on a given domain, now or at any earlier time (the register); this is weaker than RCPT probing (authenticated, rate-limited the same as any account action) and is accepted on that basis, not re-litigated here.
- The register only grows. Every address ever allocated stays on the instance after its alias and its account are deleted, two short strings and a time per row; the creation rate (100 per account per day) bounds the growth. A user-typed address, which can contain a name, outlives the account (Open question 6).
- A deleted alias cannot be restored, not even by its owner; disable is the reversible choice, and the client says so before a delete.
- One more field in the rotation commit and one more check in its transaction, through a new `rizzy-domain-mail` port.

### Risks

- If a future client skips clearing `alias.id` on delete, the owner of a stale reference could be confused about why an old alias "still shows" on an item. Mitigation is UX, not crypto: the client should treat an `alias.id` that no longer resolves in the account's alias list as "deleted," locally, without a server round trip per item.
- An indexed `(domain, local_part)` lookup has different hit/miss timing by construction; §1 claims only an identical response and code path, not a timing guarantee. Whether `resolve` also needs to run in constant time is Open question 4, below.
- A restore from a backup taken before an address was allocated forgets that address, so it can be allocated again. A restore to an older backup already rolls every account back; the operator documentation for restores says this for mail too. A restore of a backup taken after the allocation keeps it (§5).

## Alternatives considered

- **Per-alias mail keys** (true unlinkability). Rejected per THREAT_MODEL Q-19/AR-21: one more signed key and bundle entry per alias, against a linkage a compromised `smtp` already gets for free once mail arrives.
- **THREAT_MODEL option (b)** (accept every RCPT, drop unknown/disabled after `DATA`). Rejected: stores and spam-scans mail for addresses that were never allocated, and breaks ROADMAP §4.8's "rejected at SMTP time".
- **`mail_aliases.item_id` as a server-visible foreign key to `vault_items`.** The simplest schema, and exactly the leak this ADR exists to avoid: the server would then know which item each alias belongs to, a direct map of part of the user's vault structure. Rejected.
- **Plaintext `label` column.** Simpler, but not on ADR 0011's clear-text allow-list and it leaks the alias's purpose. Rejected in favour of the encrypted column (§3).
- **A `mail_domains` table.** YAGNI before M9's multi-domain/custom-domain row; one operator-configured list is enough for one or a few domains.
- **Delete frees the address** (this draft's first version). Rejected after the 2026-10-25 gap review (B3, G07-12): alias takeover, §5.
- **A time-limited tombstone** (for example one year). Rejected: password-reset and login-code mail for a site account can arrive years after the alias was deleted, and nobody can say when the last site forgets the address.
- **Reuse by the same account only.** Rejected as the default: the register would have to keep `account_id`, which links every deleted address to its account, and it would have to outlive account deletion against ADR 0011 rule 6's cascade, or lose the guarantee exactly when the account goes. Open question 5 leaves the choice to the owner.
- **A `deleted_at` tombstone column in `mail_aliases`.** Rejected: the account-deletion cascade (ADR 0011 rule 6) would delete the tombstone with the account and free the address.

## Open questions for the owner

1. **Keep the encrypted `label` column, or drop it and rely solely on the owning item's `item.name`?** *Recommendation:* keep it. It lets an alias-management screen show a human label while the vault is locked (the web vault often is); dropping it saves one AAD-purpose row but forces "unlock to see what this alias was for." The label is set at creation and changes only by rotation; renaming an alias needs an endpoint this ADR does not define.
2. **Should alias creation default to a random, high-entropy `local_part`, with a human-chosen one offered as an explicit, labelled-as-guessable opt-in?** *Recommendation:* yes, default random (THREAT_MODEL Q-18's own recommendation), so INV-65 holds for the common case and the UI, not this ADR, carries the guessability warning for the opt-in.
3. **Reconciliation for a dangling `alias.id` or an orphaned `mail_aliases` row (Negative, above).** *Recommendation:* client-side only, on each `mail/aliases/list` fetch (§5): diff the account's `mail_aliases` list against every item's `alias.id` field already loaded; flag (never auto-delete) a mismatch in either direction. No server change, no signed op, no new invariant.
4. **Does `resolve`'s unknown/disabled-vs-active branch need to run in constant time, on top of returning the identical response?** An indexed lookup's hit and miss paths differ in work done, which a very precise timing side channel could exploit to probe a guessed address faster than RCPT. *Recommendation:* no, for M6 — this is a strictly smaller channel than the already-accepted "a compromised `smtp` can enumerate aliases slowly" ([AR-21](../THREAT_MODEL.md#9-accepted-risks-and-out-of-scope)), and constant-time DB lookups are a disproportionate cost for personal-scale deployments. ADR 0069 may add response-time padding if its own timing analysis of the SMTP path says otherwise.
5. **A deleted address: never reusable on the instance, or reusable by the same account?** *Recommendation:* never (§5, INV-109). Same-account reuse would need the register to keep `account_id` (see Alternatives) and helps only a user who deleted by mistake, for whom disable exists.
6. **Should the register forget an account's addresses when the account is deleted?** *Recommendation:* no. The takeover risk is the same after account deletion, and the register row names no account. The privacy notice says that an alias address stays reserved on the instance after deletion.
7. **ADR 0028's retry table: an added row, or a superseded table?** *Recommendation:* an added row (§6), since no existing row changes. If the owner prefers the form ADR 0064 uses (superseding the rows it extends), §6 gains an entry with the full row text.
8. **The numbers: 1 000 aliases per account, 100 creations per day, labels of at most 128 bytes, and the reserved-name list of §3?** *Recommendation:* yes, as drafted; each is an ADR edit later, and the reserved list only grows.
9. **Does the rotation commit's new `alias_labels` field need an [ADR 0025](0025-rotation-vault-half.md) §1 entry?** It adds one optional field to `CommitChangeRequest` and changes none of §1's bullets, the way the M6 `MAIL_SECRET_KEY` re-wrap will need its own. *Recommendation:* no supersession; the ADR that gives the M6 rotation its wire form lists the field beside `MAIL_SECRET_KEY`'s.

## References

- [ROADMAP.md](../ROADMAP.md) §4.8
- [THREAT_MODEL.md](../THREAT_MODEL.md) §6, §8.7 (INV-47, INV-65), §9 (AR-20, AR-21), §10 (Q-18, Q-19)
- [CRYPTO.md](../CRYPTO.md) §2, §8.4, §8.5, §9.1, §9.2, §9.5 rule 5, §11.13
- [ADR 0023](0023-logical-backup-format.md) (`TABLES`), [ADR 0025](0025-rotation-vault-half.md) (rotation commit), [ADR 0048](0048-per-account-storage-quota.md) §5, [ADR 0075](0075-session-listing-and-ending.md) §1, [ADR 0079](0079-identity-generator.md) §4 step 10 and §9
- [Gap review of 2026-10-25](../reviews/2026-10-25-adr-gap-review.md) (B3) and its raw findings G07-12 to G07-17
- RFC 5321 §4.5.1 and §4.5.3.1.1, RFC 2142, CA/Browser Forum Baseline Requirements §3.2.2.4.4 (L: not re-verified this session)
- [ADR 0006](0006-key-hierarchy.md) point 8, [ADR 0010](0010-server-shape.md) §2, [ADR 0011](0011-storage.md) rules 4-6, [ADR 0016](0016-workspace-layout.md) (`rizzy-domain-mail`, V), [ADR 0018](0018-item-record-encoding.md) §3-§7, [ADR 0028](0028-api-v1-http-conventions.md)
- ADR 0069, ADR 0070, ADR 0048 — siblings in this ADR batch, cited above for scope boundaries only
- RFC 5321 §4.5.3.1.3 (SMTP mailbox length limits, L: not re-verified this session)
