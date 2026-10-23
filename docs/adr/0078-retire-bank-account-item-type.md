# ADR 0078: Retire the Bank account item type (`0x0009`) and its `bank.` field keys

- Status: Proposed
- Date: 2026-10-23
- Deciders: project owner
- Milestone: M3 (`rizzy-core`, `rizzy-client`, `rizzy-sync` vectors, `rizzy-wasm`, `rv`, web vault)
- Supersedes: [ADR 0055](0055-m3-item-type-field-keys.md) (§1 in part, §2, §3, §4 in part), on acceptance. §7 below names the parts.

## Context

**The owner's instruction, verbatim (2026-10-23):** "remove bank account type".

[ADR 0055](0055-m3-item-type-field-keys.md) (Accepted 2026-10-22) assigned five M3 item types, among them **Bank account = item type `0x0009`**, with five Text keys under `bank.`: `bank.bank_name`, `bank.account_holder`, `bank.account_number`, `bank.routing_number` and `bank.account_type`, of which `bank.account_number` and `bank.routing_number` are concealed (ADR 0055 §1, §4; `crates/rizzy-core/src/item/schema.rs` lines 236-245 and 632-636, `FIXED_KEYS: [(&str, KeySpec); 57]`; V, read). The implementation is integrated on the integration branch `claude/password-manager-planning-2gg9yc` (commit `a7e005c`; V, `git log`):

- **Core:** `ItemType::BANK_ACCOUNT` (`0x0009`), `SupportedType::BankAccount`, `class()`'s `0x0009 => Supported(BankAccount)` arm, the `BANK` `Applies` const, and `bank` in `M3_TYPE_NAMESPACES` / `ReservedFor::M3Types` (`types.rs`, `schema.rs`; V, read).
- **Vectors:** the layout-level vector "create Bank account" (`HEX_CREATE_BANK_ACCOUNT`) in `crates/rizzy-sync/src/record/vectors.rs`, which ADR 0055 §5 and [CRYPTO.md §15](../CRYPTO.md#15-testing) item 1 ("a create of each of the five types … so each of the eight concealed keys") call for (V, read).
- **Clients:** `rv item new bank-account` (`crates/rizzy-cli/src/commands.rs` line 393), the wasm type table (`crates/rizzy-wasm/src/items.rs` line 92), the web create menu, editor and sidebar type filter (`apps/web/src/fields.ts` lines 39 and 145-151), `IconBankAccount` (`packages/ui`), the `"bank-account"` member of `packages/core`'s `ItemType` (V, read).
- **Export:** CSV already leaves Bank-account items out as "other types" and counts them in the CSV loss (`csv_row` returns `None`, `csv_document` adds them to `left_out`; `crates/rizzy-client/src/export/plaintext.rs` lines 590-595 and 686-690; ADR 0027 §4; V, read). The encrypted payload and plaintext JSON carry every live item byte for byte (ADR 0027 §1, §3). No foreign importer produces the type: 1Password's other categories become Secure Notes (`onepux.rs` docs, V, read).
- **Docs:** [docs/rv.md](../rv.md), `apps/web/README.md`, [THREAT_MODEL.md](../THREAT_MODEL.md) AST-23, CRYPTO.md §15 item 1, and [ROADMAP §4.2](../ROADMAP.md#42-core-vault-m1): "| S | Item types: SSH key, API credential, Software license, Wi-Fi, Bank account | M3 |" (V, read).

**Nothing has shipped.** There is no git tag, the workspace version is `0.0.0`, and `origin/main` (`5922c1d`) predates ADR 0055: there `0x0009` is still "M3, reserved" (V, `git tag -l`, `Cargo.toml`, `git show origin/main:crates/rizzy-core/src/item/types.rs`). M3's exit criterion "Author uses it daily" ([ROADMAP §3](../ROADMAP.md#3-milestones)) is not reached ([HANDOFF §1](../HANDOFF.md)). Items of type `0x0009` can therefore exist only in vaults written by builds of the integration branch since 2026-10-22: development, test and e2e vaults, and any vault the owner has tried those builds on. They cannot be ruled out, and the encrypted server never knows (item type is inside item data, ADR 0012 §11).

**Rules this ADR works within.**

- [ADR 0018](0018-item-record-encoding.md) §8, "Unknown type": "An item of an unknown type shows as "Unsupported item, update rizzy-vault". Trash, restore and purge work; field edits are not offered." §11: unknown keys are carried byte for byte, and "No version bump is needed for new value types, enum values, list names, keys or item types." §7: "A new key needs a line in the ADR that ships it, never a version bump."
- [ADR 0039](0039-passkeys-vault-and-extension.md) §1 released `0x000A` "back to unassigned", keeping the number "permanently retired in practice" even though unassigned slots are "reusable in principle" (ADR 0039, line 107), without a `Supersedes:` line against ADR 0018; ADR 0055 moved `0x0005`–`0x0009` the same way (its Context). An id that was never written by any build is safe to release; `0x0009` has been written.
- [ADR 0027](0027-export-payload.md) §2 step 4: "An item the schema layer refuses (for example an unknown item type) is skipped, and the import report counts skipped items". §4: "other types are left out of CSV", with the affected items counted in the dialog.
- [ADR 0056](0056-local-index-recently-used-search.md) §2: a closed allow-list for the local search index that names no ADR 0055 key; owner answer 5: the list "grows for ADR 0055's M3 item types by a short amendment", still unwritten.
- [ADR 0020](0020-partial-supersession.md) point 9 (partial supersession), and CLAUDE.md: an Accepted ADR is never edited; a ROADMAP scope change is the owner's edit.

## Decision

No new construction, envelope purpose, algorithm id, value type, key, layout or `item_schema_version`. Retiring a type is a schema-layer change like ADR 0055's, made under ADR 0018 §11 ("no version bump is needed for … item types"). Items already written keep their bytes.

### 1. Item type `0x0009`: retired, never reused

`0x0009` stops being a supported type and becomes **retired**: no later ADR may assign it to any type, and no writer creates an item of it. It is not "unassigned", because unassigned ids are reusable (ADR 0018 §8, "each needs an ADR line"), and a reused `0x0009` would make every Bank-account item already in a vault read as the new type, its `bank.` fields then failing that type's placement checks (`WrongItemType`) or, worse, being shown under the new type's meaning.

To a client that implements this ADR, an item of type `0x0009` is an **unsupported** item in the sense of ADR 0018 §8's "Unknown type" bullet, which applies to it unchanged ([open question 1](#open-questions-for-the-owner) asks whether to give it a label of its own instead): it shows as "Unsupported item, update rizzy-vault", trash, restore and purge work, and field edits are not offered. `ItemType::supported()` returns `None` for it, so `check_write` refuses a create of it and every field write to it, as for any unassigned id today. Its fields stay displayed, concealed (§2), and can be revealed and copied, so the user can move the data out by hand.

In code, `ItemTypeClass` gains a `Retired` variant, documented as "`0x0009`, the Bank account type ADR 0055 assigned and ADR 0078 retired; behaves as an unsupported type; never reassigned", and `class()` maps exactly `0x0009` to it. `SupportedType::BankAccount` is removed. The id keeps a named constant (`ItemType::RETIRED_BANK_ACCOUNT`) for tests and the registry table; nothing outside tests writes it. The registry table in `types.rs` gains the row "`0x0009` | Bank account, retired (ADR 0078 §1); never reassigned | –".

### 2. The `bank.` prefix: retired and reserved, never reassigned

The five `bank.` keys stop being known keys. Every key under `bank.` (the five and any other) classifies as `KeyClass::Reserved(ReservedFor::Retired)`, a new `ReservedFor` variant documented as "keys of a retired item type (ADR 0078 §2): carried, never assigned again". `bank` leaves `M3_TYPE_NAMESPACES` (which keeps `ssh`, `api`, `license`, `wifi`) and moves to a new `RETIRED_NAMESPACES: [&str; 1] = ["bank"]`. No later ADR may assign a key under `bank.`, so the meaning of the bytes already stored there never changes.

As a reserved key, a `bank.` key is carried byte for byte (ADR 0018 §11), written by this client only as Cleared in an edit or copied verbatim (`check_carried`), and exported in the encrypted payload and plaintext JSON as it is (ADR 0027 §1, §3).

**Concealment.** Every key under `bank.` is concealed by default and left out of an M5 share unless chosen. This is a line of this ADR in ADR 0018 §7's "Concealed by default" list, the route ADR 0039 and ADR 0055 §4 took (ADR 0055 owner answer 1). It matches what the clients already do for any key that is not `Known` ("to be safe", `concealed()` in `crates/rizzy-wasm/src/items.rs` and `crates/rizzy-cli/src/commands.rs`; V, read), and it keeps `bank.account_number` and `bank.routing_number` concealed after they stop being known keys.

**Local index** (ADR 0056). No `bank.` key may join the §2 allow-list. A retired item keeps an index row like any user-visible item, searchable by `item.name` only. Nothing in ADR 0056 changes: the amendment owner answer 5 foresees covers the types ADR 0055 still assigns after §7 below, which are four.

### 3. Items that already exist

No migration, no automatic conversion and no op of any kind is issued for existing `0x0009` items. An automatic conversion would be a write the user did not make, issued concurrently by every device that syncs the vault, each making its own new item. Existing items:

- **Sync and storage:** carried unchanged (ADR 0018 §11). The server sees no change.
- **Display:** as §1: "Unsupported item, update rizzy-vault" (or open question 1's label), with the fields shown, concealed, revealable and copyable; trash, restore and purge work.
- **Export:** the encrypted payload and plaintext JSON carry them byte for byte (ADR 0027 §1, §3). CSV leaves them out and counts them in the loss figure, as it already does (ADR 0027 §4).
- **Import:** an own-format read-back (encrypted payload, plaintext JSON) skips a `0x0009` entry and counts it in the import report (ADR 0027 §2 step 4; `UnsupportedItemType` in `rizzy-import`). No foreign importer maps to the type, so none changes.
- **Older builds** (integration builds between ADR 0055 and this ADR) keep showing them as Bank accounts and may keep writing their fields; a client implementing this ADR carries those writes as reserved keys.

Whether to add a one-shot, user-started "Convert to Secure Note" action is [open question 2](#open-questions-for-the-owner); its recommendation is no.

### 4. Test vectors

- **Deleted:** the layout-level positive vector "create Bank account" and its `HEX_CREATE_BANK_ACCOUNT` in `crates/rizzy-sync/src/record/vectors.rs`, its entry in that file's "each M3 type" check, and `bank.account_number` / `bank.routing_number` in its concealed-key check. It records a create no writer makes any more, and the record layer it pins is type-blind: the other vectors keep the same coverage of the ADR 0018 §3 layout and §4 key order (`api.` keys sort before `item.` in the API-credential vector).
- **Kept byte for byte:** every other record vector, the four other M3 create vectors included. The existing test that compares encoder output, spec bytes and committed hex proves they did not move.
- **No new known-answer vector:** this ADR adds no construction or layout. The retired type is pinned by unit and property tests instead (implementation plan below).
- CRYPTO.md §15 item 1's sentence on the M3 vectors is updated in the implementing change ("each of the four types", "each of the six concealed keys"), as ADR 0055's implementation updated it.

### 5. Clients and docs

The implementing change removes the type from everything that creates or labels it: `rv item new bank-account` and the `bank-account` row of `rv`'s type table, the wasm type table, the web create menu, editor fields, sidebar type filter and `IconBankAccount`, the `"bank-account"` member of `packages/core`'s `ItemType`, and the type's rows in docs/rv.md and apps/web/README.md. A wasm host sees a `0x0009` item as type `unknown`.

### 6. Scope (ROADMAP)

This ADR does not edit ROADMAP.md. Removing "Bank account" from the ROADMAP §4.2 row is the owner's edit; "On acceptance" item 1 gives the text and [open question 3](#open-questions-for-the-owner) its wording.

### 7. What this ADR supersedes

Under [ADR 0020](0020-partial-supersession.md) point 9, each part below stops binding when this ADR is Accepted and is replaced by the text given, which binds as Decision text of this ADR. Everything not named stays binding. ADR 0055's title, Context, Consequences, "Owner answers at acceptance" (answers 1-4 stand) and §5 ("a create of each new type" now covers the four types §2 below assigns) are not superseded.

**[ADR 0055](0055-m3-item-type-field-keys.md)**

1. *§1, first sentence* ("**1. Field keys.** Five new rows for ADR 0018 §7's table, grouped as §7 groups `card.` and `identity.`:") is replaced by: "**1. Field keys.** Four new rows for ADR 0018 §7's table, grouped as §7 groups `card.` and `identity.`:"
2. *§1, the table row whose first cell is "`bank.`"* is deleted with no replacement row.
3. *§1, the sentence beginning "All 22 keys are Text"* is replaced by: "All 17 keys are Text, "stored as entered"; every prefix's numeric-looking attribute (`ssh.port`, `license.seats`, `license.expires`) follows §7's Card precedent (`card.exp_month`/`.exp_year` are Text, not U64) rather than adding a new value type or U64 timestamp convention."
4. *§1, the sentence "`api.name`, `license.name` and `bank.bank_name` name the service, the product and the institution, distinct from `item.name`'s user-chosen title of the item itself."* is replaced by: "`api.name` and `license.name` name the service and the product, distinct from `item.name`'s user-chosen title of the item itself."
5. *§2, in full*, is replaced by: "**2. Item types.** `0x0005`–`0x0008` move from "M3, reserved" to assigned: SSH key, API credential, Software license, Wi-Fi, each a new `SupportedType` variant. `0x0009` is retired ([ADR 0078](0078-retire-bank-account-item-type.md) §1). `ItemTypeClass::ReservedM3` becomes unreachable once every id in `0x0005..=0x0008` maps to `Supported` and `0x0009` to `Retired`; the implementation may drop the variant, but `ReservedFor::M3Types` in `schema.rs` stays live for any key under `ssh.`, `api.`, `license.` and `wifi.` this ADR does not assign (for example a later `ssh.key_type`). Keys under `bank.` are ADR 0078 §2's."
6. *§3, in full*, is replaced by: "**3. Code deltas** (`crates/rizzy-core/src/item/`): `schema.rs`'s `FIXED_KEYS: [(&str, KeySpec); 35]` grows to 52 (17 new rows: 6 ssh + 4 api + 4 license + 3 wifi), 6 of them `secret_text(...)` (`ssh.private_key`, `ssh.passphrase`, `api.key`, `api.secret`, `license.key`, `wifi.password`), the rest `text(...)`; four new `Applies` consts beside `CARD`/`IDENTITY`. `types.rs` gains the four `SupportedType` variants and loses the `0x0005..=0x0009 => ItemTypeClass::ReservedM3` arm from `class()`."
7. *§4, second sentence* ("Rather than rewrite it, this ADR extends it the way ADR 0039 did: the eight concealed keys above join that list as this ADR's own text, binding from acceptance, without editing ADR 0018.") is replaced by: "Rather than rewrite it, this ADR extends it the way ADR 0039 did: the six concealed keys above join that list as this ADR's own text, binding from acceptance, without editing ADR 0018."

**No other ADR is superseded.**

- [ADR 0018](0018-item-record-encoding.md): §8's table row for `0x0005`–`0x0009` was already moved by ADR 0055's own text, the ADR 0039 route, and §1 above retires `0x0009` by the same route; §7's "Reserved prefixes" bullet still holds (`bank.` stays reserved); the "Unknown type" bullet applies to `0x0009` unchanged. Only option (b) of open question 1 would supersede that bullet, and the question gives the replacement text.
- [ADR 0027](0027-export-payload.md): §1, §2 step 4 and §4 already give §3's export and import behaviour.
- [ADR 0056](0056-local-index-recently-used-search.md): see §2, "Local index"; its open question 5 names "bank" in its heading, but open questions are not Decision text, and owner answer 5 names no type.

### On acceptance

The owner makes these edits in the change that accepts this ADR; none is made now:

1. **[ROADMAP.md](../ROADMAP.md) §4.2** (owner approval required; wording per open question 3): the row "| S | Item types: SSH key, API credential, Software license, Wi-Fi, Bank account | M3 |" becomes "| S | Item types: SSH key, API credential, Software license, Wi-Fi (Bank account removed on 2026-10-23, ADR 0078) | M3 |".
2. **Status line of ADR 0055:** "Partially superseded by [ADR 0078](0078-retire-bank-account-item-type.md) (§1 in part, §2, §3, §4 in part)". The README index row for 0055 gets the same status.
3. **[THREAT_MODEL.md](../THREAT_MODEL.md) §2, AST-23:** the asset cell becomes "SSH and API credential material inside items (`ssh.private_key`, `ssh.passphrase`, `api.key`, `api.secret`; [ADR 0055](adr/0055-m3-item-type-field-keys.md)), and bank account and routing numbers in items of the retired Bank account type (`bank.account_number`, `bank.routing_number`; [ADR 0078](adr/0078-retire-bank-account-item-type.md))". The other cells stay: retired items may still hold those numbers, so the `bank.` impact stays listed.
4. **CLAUDE.md** status line: 0078 moves from the Proposed list to the Accepted list, and this README row's status to Accepted.

## Consequences

### Positive

- Follows the owner's instruction with no format change, no version bump and no server change: the server stores and syncs the same ciphertext.
- Data already written survives. Every `0x0009` item stays readable (revealable, copyable), trashable and purgeable, and travels unchanged through sync and the complete export forms.
- Retiring rather than releasing the id and the prefix means stored bytes can never be read under a different meaning.
- Five fewer known keys, one fewer type in every client's type table, editor and test matrix.

### Negative

- A user who stored real data in a Bank-account item on an integration build sees "Unsupported item, update rizzy-vault", a message that is misleading here (no update brings the type back), unless open question 1 is answered (b). They must copy the fields out by hand unless open question 2 is answered (b).
- An own-format export taken on an integration build and imported on a later one skips Bank-account items (counted in the report, not silently lost).
- `bank.` keys show in a retired item under their raw key names (`bank.account_number`), since the web's `labelOf` falls back to the key for a key it does not know, and all five are concealed, `bank.bank_name` included.
- Two ids now carry history: `0x000A` (released, retired in practice) and `0x0009` (retired by rule). The registry grows a class that exists only for compatibility.
- A future request for a bank or payment-account type needs a new id and a new prefix (for example `bank_account.`), never `0x0009` or `bank.`.

### Risks

- **Concealment of a retired key** depends on two client helpers concealing every non-`Known` key. A client that displays reserved keys unconcealed would show account numbers. §2 makes the concealment a rule, and the implementation pins it in the wasm and CLI tests.
- **Older integration builds keep writing `bank.` fields** to existing items until they are replaced. Those writes are carried, never lost, and never interpreted; the risk ends when the builds are gone.
- **The owner may later want the type back.** That needs a new ADR assigning a new id and a new prefix. Reviving `0x0009` would need a supersession of this ADR and a decision on items written in between.

## Alternatives considered

- **Release `0x0009` to unassigned** (ADR 0039's route for `0x000A`). Lost because, unlike `0x000A`, `0x0009` has been written by real builds: reuse would reinterpret existing items under another type.
- **Keep `bank.` under `ReservedFor::M3Types`.** Lost because that class means "a later M3 key may be assigned here" (ADR 0055 §2), which is exactly what must not happen to a prefix whose existing values mean bank data.
- **Unreserve `bank.`** (plain `KeyClass::Unknown`). Lost for the same reason; it would also lose the "never assigned again" guarantee.
- **Keep the five keys `Known` with `Applies::Only` a type no client supports.** Lost: it keeps a dead `SupportedType` (or a fake `Applies` target) in the schema only for display labels, while reserved handling already carries and conceals the values.
- **Automatic conversion to Secure Note** on sync or upgrade. Lost: a write the user did not make, issued by every device independently, so concurrent devices would each create a copy; and it needs the conversion mapping as new Decision text.
- **A new `item_schema_version`** to drop the type. Lost: ADR 0018 §11 says no version bump is needed for item types, and a bump is a forced client update.
- **Keep the "create Bank account" vector** renamed as a retired-type vector. Lost: the record layer it pins is type-blind, so it would only re-test the layout the other vectors pin; the retired behaviour lives in the schema layer and is tested there.

## Open questions for the owner

1. **What a `0x0009` item is labelled.**
   - **(a) "Unsupported item, update rizzy-vault"**, ADR 0018 §8 "Unknown type" unchanged. No supersession of ADR 0018, no UI code beyond the removal.
   - **(b) Its own label.** ADR 0078 would also supersede ADR 0018 §8's "Unknown type" bullet with: "**Unknown type.** An item of an unknown type shows as "Unsupported item, update rizzy-vault". An item of a retired type ([ADR 0078](0078-retire-bank-account-item-type.md) §1) shows as "Retired item type: Bank account". For both, trash, restore and purge work; field edits are not offered." The wasm type table would name `0x0009` `retired-bank-account`, and the web and `rv` would show that label.

   *Recommendation:* (a). Nothing has shipped, so the items exist only in the owner's development and test vaults, and (a) costs no change to an ADR as central as 0018. Choose (b) if any vault you keep using holds Bank-account items you mean to look at again.

2. **Offer a user-started "Convert to Secure Note" action for `0x0009` items?**
   - **(a) No.** The fields stay revealable and copyable; the user moves them by hand, then trashes or purges the item.
   - **(b) Yes.** One action (web, `rv`, wasm) creates a new Secure Note (`item.name`, `item.notes`, tags and `item.favorite` copied; each `bank.` key becomes a custom field labelled "Bank", "Account holder", "Account number", "Routing number", "Account type", kind 2 hidden for `account_number` and `routing_number`, kind 1 text otherwise), then trashes the original. It is a create plus a trash, so ADR 0018 §7's "converting an item is a new item" already allows it, but the mapping becomes Decision text of this ADR, and it needs UI, an a11y-audited dialog, a CLI command and tests.

   *Recommendation:* (a). The affected items are the owner's own test data from one day of integration builds; (b) is a permanent feature for a transient population.

3. **ROADMAP §4.2 wording.**
   - **(a)** Drop "Bank account" from the row: "| S | Item types: SSH key, API credential, Software license, Wi-Fi | M3 |".
   - **(b)** Drop it and say why: "| S | Item types: SSH key, API credential, Software license, Wi-Fi (Bank account removed on 2026-10-23, ADR 0078) | M3 |".

   *Recommendation:* (b), as ROADMAP already records moves ("moved from M1 on 2026-10-07"), so a later reader does not reinstate the type unknowingly.

## Implementation plan (for the implementer, once Accepted)

Code is not written until this ADR is Accepted. With the recommended answers:

- **`rizzy-core`** (`src/item/types.rs`, `schema.rs`, `tests.rs`): `ItemTypeClass::Retired`; `class()` maps `0x0009` to it; remove `SupportedType::BankAccount` and its `ItemType` mapping; rename the constant to `RETIRED_BANK_ACCOUNT`; remove the five `BANK_*` constants, the `BANK` `Applies` and the five `FIXED_KEYS` rows (57 → 52); `ReservedFor::Retired` and `RETIRED_NAMESPACES`; module docs (registry table row, key table, concealed list).
  - Unit tests: the registry table (`item_type_registry`) gains `(0x0009, Retired)`; the key-count test expects 17 M3 keys and 52 in all; each of the five former keys and `bank.other` classify as `Reserved(Retired)`; `check_write` refuses a create of `0x0009` and a field write to a `0x0009` item; `check_carried` accepts a verbatim `bank.` copy and a Cleared, as for every reserved key; trash, restore and purge of a `0x0009` item succeed.
  - Property tests (proptest, as the crate already uses): for every `u16`, `class(id) == Retired` iff `id == 0x0009`, and `supported()` is `None` for it; for any grammar-valid suffix `s`, `classify("bank." + s)` is `Reserved(Retired)` and never `Known`.
- **`rizzy-sync`** (`src/record/vectors.rs`): delete the "create Bank account" vector, `HEX_CREATE_BANK_ACCOUNT`, and its entries in the per-type and concealed-key checks; update the module docs. The existing comparison test proves every other hex is unchanged. CRYPTO.md §15 item 1 updated in the same change.
- **`rizzy-client`** (`src/export/plaintext.rs`, `payload.rs` docs, `src/tests/export.rs`, `src/tests/local_index.rs`): drop `SupportedType::BankAccount` from `csv_row`; turn the Bank-account export test into a simulated-older-writer test (a `0x0009` snapshot with the five keys, built as `tests/export.rs` builds its unassigned-type item): JSON export carries every key byte for byte, the encrypted payload round trip skips it and counts one skipped item, CSV leaves it out and counts it in `left_out`. The local-index test that uses `bank.account_number` as a never-indexed key stays valid; reword its comment.
- **`rizzy-import`** (`src/rizzy_json.rs` docs, `src/tests.rs`): `{"type":9,…}` gives `UnsupportedItemType`; the cross-type case `{"type":8, bank.account_number}` no longer gives `MalformedEntry` (a reserved key is carried), so it is replaced by `{"type":8, ssh.host}`, and the `bank.` key list at lines 1505-1509 is dropped.
- **`rizzy-wasm`** (`src/items.rs`): drop `bank-account` from `TYPES` and the doc comment; `concealed()` tests assert all five `bank.` keys concealed; a `0x0009` item's summary type is `unknown`. Regenerate `generated/` with `RUSTC_BOOTSTRAP=1 cargo xtask expand-bindings --write`; the `unsafe`/`extern`/`no_mangle`/`export_name` counts must not change (doc-comment and table changes only).
- **`rizzy-cli`** (`src/commands.rs`, `src/args.rs`, `tests/e2e.rs`): drop `bank-account`; the e2e test that creates one asserts instead that `rv item new bank-account` is refused, and `item show` on a `0x0009` item prints it as unsupported with `bank.` values as `********` unless `--reveal` (an e2e case if the harness can seed a raw create op, else a unit test of `commands.rs` over a simulated older writer's snapshot).
- **Web and packages** (`apps/web/src/fields.ts`, `test/fields.test.ts`, `e2e/m3-types.ts`, `e2e/command-palette.spec.ts`, `packages/core/src/index.ts`, `packages/ui/src/icons.tsx`, `index.ts`, `apps/web/README.md`): remove the type, its fields and icon. `command-palette.spec.ts` lines 65-69 expect a "Bank account" type-filter option for the query "Bank"; they must assert its absence (or match another type). Unit test: `typeLabel("unknown")` and `canEditFields("unknown")` unchanged. The axe audit and keyboard walk (`a11y.ts`, `keyboard-nav.spec.ts`) rerun over the create menu and sidebar with four M3 types; no new screen is added under (a)/(a).
- **Fuzz:** no new parser and no new untrusted input, so no new target. Add a `0x0009` item with `bank.` keys to the seed corpora of `import_rizzy_json` and `client_export_payload`.
- **Docs:** docs/rv.md (type list, the `bank-account` table row, the `bank.bank_name` sentence), CRYPTO.md §15 item 1.
- **Gate:** the full CLAUDE.md list plus `bin/gate.sh --full` (web e2e, extension Playwright, `check-js`, `expand-bindings`).

If open question 1 is (b): add `retired-bank-account` to the wasm `TYPES` with a "Retired item type: Bank account" label in web and `rv`, plus an e2e and axe check of the item view. If open question 2 is (b): a `convert_retired_to_note` client API, wasm export, `rv item convert`, a confirm dialog in the web item view (axe and keyboard-walk coverage), and client tests that the new note holds the mapped fields with the right kinds and the original is trashed.

## References

- [ADR 0055](0055-m3-item-type-field-keys.md): the M3 item types, partially superseded here.
- [ADR 0018](0018-item-record-encoding.md) §7, §8, §11: keys, types, forward compatibility.
- [ADR 0039](0039-passkeys-vault-and-extension.md) §1: the `0x000A` release precedent.
- [ADR 0027](0027-export-payload.md) §1-§4: export and import read-back.
- [ADR 0056](0056-local-index-recently-used-search.md) §2 and owner answer 5: the local-index allow-list.
- [ADR 0020](0020-partial-supersession.md) point 9: partial supersession.
- [ROADMAP §4.2](../ROADMAP.md#42-core-vault-m1), [THREAT_MODEL.md](../THREAT_MODEL.md) AST-23, [CRYPTO.md §15](../CRYPTO.md#15-testing) item 1, [HANDOFF §1](../HANDOFF.md).
- Code read on 2026-10-23 at integration HEAD `35d7079` (V): `crates/rizzy-core/src/item/{types,schema,tests}.rs`, `crates/rizzy-sync/src/record/vectors.rs`, `crates/rizzy-client/src/export/{plaintext,payload}.rs`, `crates/rizzy-import/src/{rizzy_json,onepux,tests}.rs`, `crates/rizzy-wasm/src/items.rs`, `crates/rizzy-cli/src/commands.rs`, `apps/web/src/fields.ts`, `apps/web/src/views/ItemView.tsx`.
