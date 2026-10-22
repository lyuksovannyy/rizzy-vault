# ADR 0055: M3 item types: field keys for SSH key, API credential, software license, Wi-Fi and bank account

- Status: Accepted
- Date: 2026-10-11
- Deciders: project owner
- Milestone: M3
- Supersedes: none — an extension of [ADR 0018](0018-item-record-encoding.md) §7-§8, the route [ADR 0039](0039-passkeys-vault-and-extension.md) used for the `passkey/` list

## Context

[ROADMAP §4.2](../ROADMAP.md#42-core-vault-m1), Should, M3: "Item types: SSH key, API credential, Software license, Wi-Fi, Bank account". [ADR 0018](0018-item-record-encoding.md) §8 already reserves item-type ids `0x0005`–`0x0009` for these five types (`crates/rizzy-core/src/item/types.rs`, `ItemType::SSH_KEY`…`BANK_ACCOUNT`, mapped by `class()` to `ItemTypeClass::ReservedM3`; V, read). §7 reserves the prefixes `ssh.`, `api.`, `license.`, `wifi.`, `bank.`; a key under them classifies today as `KeyClass::Reserved(ReservedFor::M3Types)` in `crates/rizzy-core/src/item/schema.rs` (V, read). No field key is assigned yet, so no M3 client can read or write a field of these types.

§7's own rule is the mechanism for closing this gap: "A new key needs a line in the ADR that ships it, never a version bump." ADR 0039 used exactly this route for `passkey/<id>/private_key` ("concealed by default like `login.password`", schema.rs:222-224) and to release `0x000A` back to unassigned (types.rs:17-21; ADR 0039 line 107) — without a `Supersedes:` line, and ADR 0018 is still plain `Accepted` in [docs/adr/README.md](README.md). This ADR follows that precedent rather than partially superseding ADR 0018.

It also follows a companion precedent: THREAT_MODEL.md §2 keeps AST-8 (TOTP seeds) and AST-9 (Passkeys) as their own rows rather than folding them into AST-7's generic "item plaintext" impact, and ADR 0039's own "On acceptance" point 2 amends AST-9's row directly (its parenthetical, "Passkeys (M7)" to "Passkeys (M2 in the extension; M7 for native OS providers)") rather than leaning on AST-7's impact column. The `ssh.`, `api.` and `bank.` keys below are the same kind of case (shell/infrastructure access, third-party service takeover, direct financial fraud), so this ADR has its own [On acceptance](#on-acceptance) section naming the THREAT_MODEL.md §2 edit.

Constraints: `rizzy-core` is a no-I/O, wasm32 R1 crate ([ADR 0016](0016-workspace-layout.md)); these are ordinary item-plaintext fields, so nothing here touches that boundary. CRYPTO.md defines no field-level concept of "concealed" — it is a schema-layer, ADR-0018-only term (display and M5-share-exclusion), not a cryptographic one.

## Decision

No new cryptographic construction, envelope purpose, algorithm id or key. These are `str(field_key) ‖ bytes(value)` writes inside the existing `ITEM_OP`/`ITEM_SNAPSHOT` layouts (ADR 0018 §3), under the already-approved value types (§6) and canonical rules (§4).

**1. Field keys.** Five new rows for ADR 0018 §7's table, grouped as §7 groups `card.` and `identity.`:

| Prefix | Keys | Value | Concealed |
|---|---|---|---|
| `ssh.` | `host`, `port`, `username`, `private_key`, `public_key`, `passphrase` | Text | `private_key`, `passphrase` |
| `api.` | `name`, `key`, `secret`, `endpoint` | Text | `key`, `secret` |
| `license.` | `name`, `key`, `seats`, `expires` | Text | `key` |
| `wifi.` | `ssid`, `password`, `security_type` | Text | `password` |
| `bank.` | `bank_name`, `account_holder`, `account_number`, `routing_number`, `account_type` | Text | `account_number`, `routing_number` |

All 22 keys are Text, "stored as entered"; every prefix's numeric-looking attribute (`ssh.port`, `license.seats`, `license.expires`) follows §7's Card precedent (`card.exp_month`/`.exp_year` are Text, not U64) rather than adding a new value type or U64 timestamp convention. Every key applies only to its own item type (`Applies::Only`, as `CARD`/`IDENTITY` do), writers are `Writers::Any`. `api.name`, `license.name` and `bank.bank_name` name the service, the product and the institution, distinct from `item.name`'s user-chosen title of the item itself. `ssh.port` absent means 22, the same convention as `item.favorite` absent meaning false — a display default, not a stored value. This ADR assigns nothing under `attachment/`, `passkey.` or `passkey/`; those stay ADR 0054's and ADR 0039's.

**2. Item types.** `0x0005`–`0x0009` move from "M3, reserved" to assigned: SSH key, API credential, Software license, Wi-Fi, Bank account, each a new `SupportedType` variant. `ItemTypeClass::ReservedM3` becomes unreachable once every id in `0x0005..=0x0009` maps to `Supported`; the implementation may drop the variant (see [Open question 2](#open-questions-for-the-owner)), but `ReservedFor::M3Types` in `schema.rs` stays live for any key under these five prefixes this ADR does not assign (for example a later `ssh.key_type`).

**3. Code deltas** (`crates/rizzy-core/src/item/`): `schema.rs`'s `FIXED_KEYS: [(&str, KeySpec); 35]` grows to 57 (22 new rows: 6 ssh + 4 api + 4 license + 3 wifi + 5 bank), 8 of them `secret_text(...)` (`ssh.private_key`, `ssh.passphrase`, `api.key`, `api.secret`, `license.key`, `wifi.password`, `bank.account_number`, `bank.routing_number`), the rest `text(...)`; five new `Applies` consts beside `CARD`/`IDENTITY`. `types.rs` gains the five `SupportedType` variants and loses the `0x0005..=0x0009 => ItemTypeClass::ReservedM3` arm from `class()`.

**4. Concealment list.** ADR 0018 §7's "Concealed by default" bullet is a closed enumeration. Rather than rewrite it, this ADR extends it the way ADR 0039 did: the eight concealed keys above join that list as this ADR's own text, binding from acceptance, without editing ADR 0018. Open question 1 below asks the owner to confirm this route.

**5. Test vectors.** CRYPTO.md §15 item 1 already provides for this: "Vectors for M3, M5 and M6 constructions are added in the milestone that ships them" (V, read, §15 item 1). No vectors are added now; a create of each new type, each concealed field and the `ssh.port`-absent default are added when M3 implements these types, following ADR 0018 §12's pattern.

### Owner answers at acceptance (2026-10-22)

The owner accepted this ADR as drafted; the recommendations of "Open questions for the owner" stand:

1. ADR 0018 §7's "Concealed by default" bullet is extended by each shipping ADR, as ADR 0039 did. It is not consolidated by a supersession.
2. The dead `ItemTypeClass::ReservedM3` variant is dropped, and `item_type_registry`'s table in `crates/rizzy-core/src/item/tests.rs` is updated in the same change.
3. `license.expires` is Text for M3.
4. Option (a): a carried field that `check_carried` rejects with `WrongItemType` skips the whole item, like any other per-item write failure. No supersession is needed.

Of the "On acceptance" edits, item 1 (AST-23 in THREAT_MODEL.md §2) is made in the accepting change. Dropping `ReservedM3` (open question 2) is code, for the implementation.

## Consequences

### Positive

- The M3 roadmap row has concrete, reviewable field keys instead of bare reserved prefixes.
- No new value type, envelope purpose or crate; the existing merge, parser and concealment machinery (ADR 0018 §3-§7) covers all five types unchanged.
- Each type's fields sit behind `Applies::Only`, so an SSH field can never be written to a Login item or vice versa.

### Negative

- **`check_carried` tightens** (`crates/rizzy-core/src/item/schema.rs`). Today a key under `ssh.`/`api.`/`license.`/`wifi.`/`bank.` classifies as `KeyClass::Reserved`, and `check_carried` accepts it unconditionally (`KeyClass::Unknown | KeyClass::Reserved(_) => return Ok(())`, line 945) regardless of item type. After this ADR, `classify` returns `KeyClass::Known`, so `check_carried` runs `check_placement`, which now rejects (`WriteError::WrongItemType`) a carried `ssh.host` on anything but an SSH-key item. This changes the result of "restore as a new item" and "duplicate as a new item" (ADR 0018 §3, §10) unconditionally, and the ADR 0027 §2 step 3 own-export read-back path the same way whenever that path binds; [Open question 4](#open-questions-for-the-owner) below resolves how, so the choice is not left to the M3 implementer.
- 22 more string keys to parse, classify and keep concealed correctly; one more place the §7 grammar and 160-byte key limit must hold (`bank.account_number` is 20 bytes, well inside it).

### Risks

- **The concealment list grows ad hoc, one ADR at a time** (owner decision below). The code already flags one such gap — `pwhist/<id>/value` is grammar-known but unlisted, so unconcealed (schema.rs:38-40) — evidence this enumeration needs active upkeep, not just a one-time list.
- **Text for `license.expires`** gives up timestamp sorting the M3 "recently used" and favorites work (ROADMAP §4.2) might want; a later ADR would need a version bump to add a U64 variant of the same key, which this ADR cannot avoid without picking a type the owner has not asked for.

## Alternatives considered

- **U64 for `ssh.port`, `license.expires`, `license.seats`.** Rejected: breaks the Card precedent of Text for numeric-looking attributes, for a sort/validate benefit M3 does not yet need (YAGNI).
- **Enum for `wifi.security_type`.** Rejected for the same reason `card.brand` is Text, not Enum: an Enum needs an ADR-governed value registry for no M3 behavior.
- **Reserve `ssh.key_type`/`ssh.fingerprint` now.** Deferred: `ssh.public_key`'s text already carries the algorithm (`ssh-ed25519 …`); add the key with its own ADR line when a client needs it structured, per §7's own rule.
- **Partially supersede ADR 0018 §7's concealment bullet now**, consolidating it into one list. Rejected in favor of extension, matching ADR 0039; left to open question 1 if the owner disagrees.

## Open questions for the owner

1. **Should the "Concealed by default" bullet be extended per shipping ADR (this ADR's route, matching ADR 0039), or consolidated by partially superseding it?** *Recommendation:* extend, as ADR 0039 did. If the owner instead wants consolidation, this ADR needs a "What this ADR supersedes" entry naming ADR 0018 §7's "Concealed by default" bullet and writing out the full replacement list, word for word, under [ADR 0020](0020-partial-supersession.md) point 9 — a larger change the owner would need to ask for explicitly.
2. **Drop the dead `ItemTypeClass::ReservedM3` variant, or keep it as a documented historical no-op?** *Recommendation:* drop it; nothing constructs it once `0x0005`–`0x0009` are assigned. Checked across the whole workspace, not only `types.rs`: besides `class()`'s own match arm, `crates/rizzy-core/src/item/tests.rs` lines 720-721 (`item_type_registry`) also construct it directly — `(0x0005, ItemTypeClass::ReservedM3)` and `(0x0009, ItemTypeClass::ReservedM3)` — and that test's table must be updated to the five new `SupportedType` variants in the same change that drops the variant.
3. **Is Text the right value type for `license.expires`, given the M3 "recently used/favorites" work may want to sort by it?** *Recommendation:* Text for M3, matching the Card precedent; revisit with a version bump only if that M3 UI work actually needs expiry sorting.
4. **How do "restore as a new item", "duplicate as a new item" and the ADR 0027 own-export import paths (§2 step 3, §6 "Writes") handle a carried `ssh.`/`api.`/`license.`/`wifi.`/`bank.` field that `check_carried` now rejects on the wrong item type (`WriteError::WrongItemType`), instead of accepting it unconditionally as before this ADR?** Two concrete options, not a choice for the M3 implementation to make:
   - **(a) Skip the whole item**, the same as any other per-item write failure. Matches both ADR 0027 §2 step 4 ("Per-item refusals do not refuse the file," binding unconditionally) and §6 ("Per-item failures skip the item, never the file," binding only if ADR 0027's own open question 4 is answered yes) as written today, with no further ADR text needed.
   - **(b) Drop only the offending field**, keeping the rest of the item. Contradicts §2 step 4 outright, and contradicts §6's sentence whenever §6 binds; either way it needs its own "What this ADR supersedes" entry under [ADR 0020](0020-partial-supersession.md) point 9, naming the exact sentence(s) and the replacement.

   *Recommendation:* (a); it needs no supersession and matches every other per-item rejection ADR 0027 already lists (missing member, bad key, oversize value, refused type).

## On acceptance

The owner makes this edit in the change that accepts this ADR; it is not made now:

1. **[THREAT_MODEL.md](../THREAT_MODEL.md) §2** gains a new asset row — the same mechanism ADR 0039's "On acceptance" point 2 used to amend AST-9 — for the three new secret classes whose impact is not AST-7's generic one:

   | ID | Asset | Where it lives | Must never be readable by | Impact if an attacker gets it |
   |---|---|---|---|---|
   | AST-23 | SSH and API credential material, and bank account/routing numbers, inside items (`ssh.private_key`, `ssh.passphrase`, `api.key`, `api.secret`, `bank.account_number`, `bank.routing_number`) | Inside items | Server, network | `ssh.`/`api.`: pivot to the user's other infrastructure or third-party accounts, beyond the vault itself. `bank.`: direct financial fraud (ACH/wire). |

   `license.key` and `wifi.password` are not added: a license key's impact is piracy of one product and a Wi-Fi password's is access to one network, both already inside AST-7's "direct takeover" framing, so they stay there.

## References

- [ADR 0018](0018-item-record-encoding.md) §6-§8 (values, field keys, item types), §12 (tests)
- [ADR 0039](0039-passkeys-vault-and-extension.md) §1 (the extension-not-supersession precedent, `0x000A`'s release) and "On acceptance" point 2 (amends AST-9's row directly; this ADR's precedent for an On-acceptance THREAT_MODEL.md edit)
- [ADR 0027](0027-export-payload.md) §2 step 4 ("Per-item refusals do not refuse the file," binds unconditionally) and §6 ("Per-item failures skip the item, never the file," binds only if ADR 0027's own open question 4 is answered yes) — both are the import paths `check_carried` affects
- [ADR 0020](0020-partial-supersession.md) point 9 (partial supersession, for open questions 1 and 4)
- [THREAT_MODEL.md](../THREAT_MODEL.md) §2 Assets, AST-7/AST-8/AST-9 (the precedent for a distinct asset row; AST-9's row predates ADR 0039, which only amends its parenthetical)
- [ROADMAP.md](../ROADMAP.md) §4.2 (the M3 row this ADR implements)
- [CRYPTO.md](../CRYPTO.md) §15 item 1 (vectors added in the shipping milestone)
- `crates/rizzy-core/src/item/types.rs`, `crates/rizzy-core/src/item/schema.rs`, `crates/rizzy-core/src/item/tests.rs` (read in full for this ADR, 2026-10-11; V)

<!-- Blocker 1's fix is applied (an "On acceptance" section now names the THREAT_MODEL.md §2 edit), but its premise that "ADR 0039's On acceptance section is exactly where AST-9 got added" is inaccurate: ADR 0039 line 132 shows AST-9's row already existed and was only amended ("becomes"), not created. -->
