# ADR 0081: Multiple vaults per account: the Personal vault, user-created vaults, and sharing a vault with other users

- Status: Accepted
- Date: 2026-10-23 (accepted 2026-10-24)
- Deciders: project owner
- Milestone: M3 (Part A: several vaults per account, no sharing) / M9 (Part B: shared vaults), both subject to open question 1
- Supersedes: on acceptance, in part: [ADR 0012](0012-sync-engine.md) (§1 in part), [ADR 0021](0021-server-compaction.md) (§9 in part), [ADR 0025](0025-rotation-vault-half.md) (§1 in part, §3 in part), [ADR 0028](0028-api-v1-http-conventions.md) (item 1 in part), [ADR 0042](0042-account-settings-matching-layout.md) (§2 in part), [ADR 0056](0056-local-index-recently-used-search.md) (§3 in part). §0 names the parts ([ADR 0020](0020-partial-supersession.md) point 9).

## Context

**The owner's request, verbatim (2026-10-23):** "each account by default has own vault called Personal and each account can create new vaults which can be shared with other users (Personal vault is default root one and is not allowed to be deleted nor shared (except for selective creds sharing) and is default option when saving new creds)".

### What the ROADMAP says

- [§2](../ROADMAP.md#2-guiding-principles-non-negotiable) principle 3: "Design the data model for orgs on day one. UI for orgs comes late; the key hierarchy (per-user keypairs, per-vault keys) must exist from M1 or we rewrite everything at M9."
- [§3](../ROADMAP.md#3-milestones): M5 "Public sharing (**after v1.0**) … Scheduled after the v1.0 release by owner decision of 2026-10-22"; M8 "Hardening → **v1.0** … It follows M3 and M7 directly; M5 and M6 come after it"; M9 "Families & enthusiasts: Shared vaults, family org, emergency access, multiple mail domains, admin panel".
- [§4.3](../ROADMAP.md#43-cryptography--authentication-m0m1-audited-in-m8), Must, M1: "Key hierarchy: master key → account key → per-vault keys → item keys; enables rotation & sharing without re-encrypting the world" and "Per-user asymmetric keypair (**X25519** for key wrapping, **Ed25519** for signing) generated at signup — required for sharing, orgs, email".
- [§4.7](../ROADMAP.md#47-public-sharing-m5), Won't: "Live shared items between two personal accounts (that is what shared vaults in M9 are for)". The section models sharing as "an **encrypted snapshot**, not a live link to the item".
- [§4.11](../ROADMAP.md#411-families--enthusiasts-m9--wont-for-v10), *Won't for v1.0*: "Shared vaults with per-member permissions (view / edit / manage)"; "Family organization (up to N users), invites".
- **No ROADMAP row covers several vaults for one account without sharing.** The first half of the request is therefore out of scope until the owner adds a row (On acceptance item 1).

### What the current implementation does (V, read at `5f7b698`)

The **key hierarchy and the storage model are already multi-vault**; the **clients and the server's write paths assume exactly one vault per account**, and **nothing about sharing exists beyond a reserved purpose**.

| Area | Finding | Where |
|---|---|---|
| Server tables | `vault_vaults(id, account_id, vault_key_epoch, next_store_seq, created_at_ms)`, with a non-unique index on `account_id`: the schema allows any number of vaults per account. Every other vault table (`vault_self_grants`, wraps, ops, snapshots, attachments) is keyed by `vault_id`. | `crates/rizzy-storage/migrations/sqlite/0002_vault_initial.sql` lines 15–22 (and the PostgreSQL twin); `0007_vault_attachments.sql` |
| One self-grant per vault | `vault_self_grants.vault_id` is the **primary key**: one self-grant per vault, so one account per vault. | same file, line 25 ff. |
| Only creation path | Signup: `register/finish` carries `vault_self_grant` ("The personal vault's self-grant"), stored by `create_personal_vault` → `create_vault`, which requires `vault_key_epoch = 0`. No endpoint creates, deletes or lists a further vault. | `crates/rizzy-proto/src/auth.rs` lines 101–102; `crates/rizzy-domain-vault/src/port.rs` line 60; `src/keys.rs` line 81 |
| Ownership check | Upload and Fetch take a `vault_id` in the request and refuse a vault whose `account_id` is not the caller's (`NotFound`). There is no membership concept. | `crates/rizzy-domain-vault/src/upload.rs` lines 81–84; `src/fetch.rs` lines 330–333 |
| Per-vault keys are real | `VaultKey` is 32 random bytes bound to a `VaultId` and an epoch (`VaultKey::generate(rng, vault_id, epoch)`); `VAULT_KEY_SELF_GRANT` (0x0020) wraps it under the account key; `ITEM_KEY_WRAP` (0x0030) wraps one random key per item under it; the `ITEM_OP`, `ITEM_SNAPSHOT` and `ATTACHMENT_*` contexts all start with `vault_id`. | `crates/rizzy-core/src/keys/mod.rs` lines 327–360; [CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes) |
| Signup vault id | Random: `VaultId::generate(rng)`, then `VaultKey::generate(rng, vault_id, 0)`. No vault-settings item (`0xF001`, `vault.name`) is written at signup; "Personal" appears only in a test vector. | `crates/rizzy-client/src/signup.rs` lines 178–179; `crates/rizzy-sync/src/record/vectors.rs` line 211; `crates/rizzy-core/src/item/schema.rs` line 270 |
| Op log | One op stream per vault (ADR 0012 §1), a per-vault store sequence (`next_store_seq`) and per-vault heads; `device_seq` is per device across all vaults and each op carries `vault_prev_seq` (ADR 0012 §2). `VaultSync` keeps its own `next_seq`, seeded at construction, so two `VaultSync` instances on one device would each count from the same start. | `crates/rizzy-client/src/sync.rs` lines 361, 516–541 |
| Multi-vault-ready code | The account answer carries `vault_self_grants: List<VaultSelfGrant, MAX_VAULT_GRANTS>`; rotation uploads one `VaultRotation` per vault, strictly ascending (ADR 0025 §1); recovery handles several vaults; the client cache has a `vaults` table and every `wraps`/`ops`/`snapshots` row carries `vault_id`, and the loader refuses a row for a vault without a self-grant. | `crates/rizzy-proto/src/account.rs` line 57, `src/change.rs` lines 203–259; `crates/rizzy-client/src/recovery.rs` lines 219–234; `src/store/rows.rs` lines 128–145; `src/store/load.rs` lines 370–384 |
| Single-vault clients | The web/extension wasm session and the device opener take `account.vault_ids().next()`, the first vault in the answer; `rv` holds one `vault: VaultSync` ("The personal vault (M1 has one vault per account)"); `rv` enrolment does the same. The TypeScript apps and `packages/core` have no notion of a vault id. | `crates/rizzy-wasm/src/session.rs` lines 215–221; `src/device.rs` lines 404–410; `crates/rizzy-cli/src/device.rs` line 430; `src/enrol.rs` line 359 |
| Local index | `item_index(item_id BLOB PRIMARY KEY, vault_id …)`: keyed by `item_id` alone. Cache format 3. | `crates/rizzy-client/src/store/rows.rs` lines 59, 66–68 |
| Limits | `MAX_VAULT_GRANTS = 1024`, documented "One vault per account in M1 (ADR 0021 §9), several from M9". | `crates/rizzy-proto/src/limits.rs` lines 119–121 |
| Sharing | `VAULT_KEY_MEMBER_GRANT` (0x0021, HPKE Base `0x10` to the grantee's identity X25519 key) is registered, with its context type compiled only under `cfg(test)`. No membership table, statement, endpoint or role exists. | `crates/rizzy-core/src/envelope/purpose.rs` lines 188, 295, 708–720 |
| Quota | Per account (`storage_account_usage`, ADR 0048), charged to the session's account. | `crates/rizzy-domain-vault/src/store.rs` lines 77–100 |

### Constraints from Accepted documents

- [CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes): the reader rebuilds the purpose and context, so "a ciphertext moved anywhere else fails the commitment"; item AAD names `vault_id` and no `account_id` because "Vaults become shareable between accounts in M9".
- [CRYPTO.md §11.6](../CRYPTO.md#116-key-rotation), "Current vault epoch": "In M1–M8 a vault key rotates only together with the account key … M9 member removal rotates a vault key alone, and the M9 ADR must carry `vault_key_epoch` in a signed vault statement." The writer rule (a fresh item key on the first write after a vault-key rotation) binds.
- [CRYPTO.md §10.1](../CRYPTO.md#101-hpke-key-wrapping) signed grants and [§10.3](../CRYPTO.md#103-public-key-authenticity) public-key authenticity: safety numbers (60 digits), TOFU pinning in `ACCOUNT_SETTINGS`, silent update only along a chain that keeps both identity keys, fork and rollback alarms, and "Invites (M9) must verify the fingerprint, or explicitly accept TOFU with a visible 'not verified' badge, *before* any vault key is granted."
- [THREAT_MODEL](../THREAT_MODEL.md) A17 (vault member), INV-17 (wrap only to a verified or pinned key), INV-67 ("clients accept an op only if its author holds, in a membership statement signed by a vault manager and verified by the client, a role that allows that op … The statement format belongs to the M9 ADR"), §5.4 (public-key substitution), §5.7 (org-invite abuse), AR-6 (TOFU), Q-8 (key transparency post-1.0).
- [ADR 0042](0042-account-settings-matching-layout.md): `ACCOUNT_SETTINGS` is a tagged, versioned record whose freshness the signed `account-state` guarantees (`settings_seq`, `settings_hash`); unknown tags are kept verbatim.
- [ADR 0011](0011-storage.md) point 5: tables carry the owning domain's prefix (`vault_`, `auth_`, …); point 6: the only cross-domain foreign key is to `auth_accounts(id)`.
- [ADR 0002](0002-own-protocol.md) point 5: before v1.0 a breaking change raises the minimum client versions in `/api/meta`; from v1.0, point 3: additive changes only within `v1`.
- [ADR 0012](0012-sync-engine.md) §5: a `Purge` is allowed only on a trashed item; §6: a replica that holds an op it must not hold removes it and recomputes.

## Decision

### Owner answers at acceptance (2026-10-24)

The owner accepted this ADR as drafted. The recommendations of the "Open questions for the owner" stand:
1. Part A in M3, Part B in M9 (recommendation a).
2. "Selective creds sharing" from the Personal vault: move (default) or copy into a shared vault, plus M5 link shares (recommendation a).
3. The Personal vault cannot be renamed; always shown as "Personal" (localised).
4. No setting for default save target; Personal is preselected every time.
5. Deleting a vault that has items defaults to "move items to Personal" with alternative "delete with items".
6. `directory/lookup` rate-limited with `not_found` for unknown names (recommendation a).
7. Invites to an unverified key are allowed with a visible persistent "not verified" badge.
8. Ownership transfer is out of scope for this ADR.
9. Limits (64 owned vaults, 32 active members, 255 statement entries) stand.
10. The vault owner pays for a shared vault's quota bytes.
11. Accepted as a whole.

The decision has two parts with different milestones (open question 1). **Part A** gives one account several vaults, none shared; it needs no new cryptographic construction, no new envelope purpose and no new signed statement. **Part B** lets a vault other than Personal be shared with other accounts; it adds one signed statement type and puts the reserved `VAULT_KEY_MEMBER_GRANT` to use. Part A reserves, in its own wire and settings formats, the fields Part B needs, so that Part B stays additive after v1.0 (§A12, §B12).

### 0. What this ADR supersedes

The parts below are named under ADR 0020 point 9. Each replacing text binds as Decision text of this ADR from its acceptance. Nothing else in any Accepted ADR changes.

1. **[ADR 0012](0012-sync-engine.md) §1, the "Vault:" bullet** (Part A). Replacing text: "- **Vault:** the unit of keys and membership. Each vault has its own op stream. Every account has exactly one Personal vault, created at signup, and may own further vaults it creates ([ADR 0081](0081-multiple-vaults-personal-and-shared.md) Part A); a vault other than the Personal vault may be shared with other accounts (ADR 0081 Part B). Vault-level settings (name, icon) are an item of a reserved type, whose id the item-record encoding defines (§3)."
2. **[ADR 0021](0021-server-compaction.md) §9, the "Revoked and kind-4 authors." bullet** (Part A). Replacing text: "- **Revoked and kind-4 authors.** A snapshot by a revoked or kind-4 device is accepted only if its covered-VV entry for its author is at most that device's last accepted `device_seq`; the server refuses new ones after the author's revocation or expiry, and keeps counting retained ones as covers. The server refuses any snapshot whose covered-VV entry for its author is above that author's head. After a complete Fetch of every vault the account holds a self-grant for, a client whose highest cursor for a revoked device of its own account, taken over all those vaults, is below that device's `last_accepted_device_seq` reports missing data (INV-27). For another account's devices in a shared vault, [ADR 0081](0081-multiple-vaults-personal-and-shared.md) §B7 states what the client checks."
3. **[ADR 0025](0025-rotation-vault-half.md) §1, the "Vault half:" bullet** (Part A carries the field, Part B fills it). Replacing text: "- **Vault half:** `vault_rotation: { vaults: List<VaultRotation, MAX_VAULT_GRANTS>, regrants: List<VaultSelfGrant, MAX_VAULT_GRANTS> }`. `vaults` is strictly ascending by `self_grant.vault_id`, one per vault in V (§3), with `VaultRotation { self_grant, cursor: SeqVector, item_key_wraps: List<ItemKeyWrap, MAX_ITEM_KEY_WRAPS>, dropped: List<WrapLocator, MAX_ITEM_KEY_WRAPS> }`. `cursor` is canonical (ADR 0012 §3). `dropped` names `(item_id, item_key_id)` rows the rotator cannot open (§2 step 3). `regrants` is strictly ascending by `vault_id` and holds, for each shared vault the account holds a self-grant for ([ADR 0081](0081-multiple-vaults-personal-and-shared.md) §B8), that self-grant re-wrapped under the new account key at the vault's unchanged `vault_key_epoch`. It is empty while the account holds no shared vault, and the server refuses a `regrants` list that does not name exactly those vaults."
4. **[ADR 0025](0025-rotation-vault-half.md) §3, first paragraph, third sentence** ("All in the commit's transaction under the account lock; V is the account's vaults.") (Part B). Replacing text: "All in the commit's transaction under the account lock; V is the account's vaults that are not shared, that is, that have no stored `vault-membership` statement ([ADR 0081](0081-multiple-vaults-personal-and-shared.md) §B3); a shared vault the account holds a self-grant for is not in V and is handled by `regrants` (§1) as ADR 0081 §B8 says."
5. **[ADR 0028](0028-api-v1-http-conventions.md) item 1, first sentence, in part**, as already superseded in part by [ADR 0052](0052-icon-proxy-role.md) and [ADR 0075](0075-session-listing-and-ending.md) (Part B), following ADR 0075 §1's precedent: the resource list gains `directory`, and the existing `vault` resource gains the verbs of §B11 under `vault/members/`. The count is whatever the `http/api.rs` module table holds once every accepted change has landed; the table stays the authoritative list. The rest of item 1 stands. Item 3 is not superseded: every refusal in this ADR uses an existing code.
6. **[ADR 0042](0042-account-settings-matching-layout.md) §2, the "Tag registry." bullet** (Part A assigns `0x0002`, Part B `0x0003`). Replacing text: "- **Tag registry.** `0x0000` invalid. `0x0001` = matching settings (§3). `0x0002` = vault directory ([ADR 0081](0081-multiple-vaults-personal-and-shared.md) §A2). `0x0003` = contact pins (ADR 0081 §B2). `0x0004`–`0xFFFE` unassigned — a new setting gets a line here by ADR amendment, **no version bump**, same pattern as [ADR 0018](0018-item-record-encoding.md) §7's field keys. `0xFFFF` reserved, never assigned."
7. **[ADR 0056](0056-local-index-recently-used-search.md) §3, the first paragraph and the SQL block after it** (Part A). Replacing text: "The index is a table in the same per-account SQLite cache ADR 0026 §3 defines (`rv`: its cache database; `rizzy-ffi`: the same schema). It was added as cache-format 2 keyed by `item_id` alone; the cache format [ADR 0081](0081-multiple-vaults-personal-and-shared.md) §A7 introduces drops it and creates it again (§4), keyed by `(vault_id, item_id)`:" followed by the block `item_index(vault_id BLOB NOT NULL, item_id BLOB NOT NULL, item_type INTEGER NOT NULL, display_name TEXT NOT NULL, search_text TEXT NOT NULL, last_used_ms BLOB, use_count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (vault_id, item_id))`.

**Not superseded, and why.** [ADR 0006](0006-key-hierarchy.md) point 3 ("The user's own vaults are self-granted … From M9, other members receive HPKE grants signed by the granter") stays true: members still receive HPKE grants, and §B5 only adds that a member then stores its own self-grant. [ADR 0027](0027-export-payload.md) already exports "the items of a vault". [ADR 0048](0048-per-account-storage-quota.md) §2–§3 count bytes against "the account" whose lock a store transaction holds; §B9 states which account that is for a shared vault (its owner) without changing a rule (open question 10). [ADR 0054](0054-attachments-envelope-and-api.md)'s contexts and endpoints already carry `vault_id`. [ADR 0018](0018-item-record-encoding.md)'s vault-settings item (`0xF001`, `vault.name`, `vault.icon`) is used as written.

---

### Part A: several vaults for one account, none shared

#### A1. Vault kinds and the Personal vault

- **Personal vault.** Every account has exactly one: the vault created at signup ([CRYPTO.md §11.1](../CRYPTO.md#111-signup-server-mode)). Its id stays **random** (`VaultId::generate`, as today); it is not derived from the account id. It:
  - is the **default target** for every new item, import and save prompt in every client (§A8);
  - **cannot be deleted**: clients offer no delete action and `rizzy-client` refuses one, and the server refuses `vault_delete` for it (§A5);
  - **cannot be shared as a whole**: clients never create a `vault-membership` statement or a member grant for it, and the server refuses both (§B9); single items may leave it as §C says;
  - is **named "Personal" by the client**, a localised label, not data. Clients write no `vault.name` for it and ignore one if present; it cannot be renamed (open question 3);
  - is told apart from other vaults by the authenticated vault directory (§A2), never by server metadata.
- **Owned vault.** Any further vault the account creates (§A3). Owned vaults may be renamed, deleted and, under Part B, shared.
- **Joined vault** (Part B only). Another account's vault this account was invited to and accepted (§B5).

#### A2. The vault directory (`ACCOUNT_SETTINGS` tag `0x0002`)

The account's authenticated list of the vaults it holds. It lives in the existing `ACCOUNT_SETTINGS` envelope (purpose 0x0014, account key, [ADR 0042](0042-account-settings-matching-layout.md)), so it is encrypted, written only by the account's own clients, and fresh through the signed `account-state` (`settings_seq`, `settings_hash`). No new purpose, statement or `account-state` field.

```
tag 0x0002 value
  u8  format = 1
  u16 n ‖ n × entry            1 ≤ n ≤ MAX_DIRECTORY_ENTRIES (128), strictly ascending by vault_id
entry
  vault_id (16)
  u8  kind                     0 invalid; 1 Personal; 2 owned; 3 joined (Part B); 4–255 unassigned
  u16(len) ‖ body
body, kind 1:  u8 flags = 0                                                   (len 1)
body, kind 2:  u8 flags; if bit 0: u64 membership_seq ‖ membership_hash (32)  (len 1, or 41 with bit 0)
body, kind 3:  u8 flags = 0x01 ‖ owner account_id (16) ‖ u64 membership_seq ‖ membership_hash (32)  (len 57)
```

- Exactly one kind-1 entry. Flag bits other than bit 0 must be 0. Bit 0 of a kind-2 entry means "shared" and carries the highest `vault-membership` statement the account has verified for that vault (§B3, the rollback pin). A kind-3 entry always carries one.
- **Rejected outright**, as ADR 0042 §2 rejects any violation inside a recognised tag: wrong lengths, trailing bytes, unsorted or duplicate ids, zero or two kind-1 entries, a set reserved flag bit, `format ≠ 1`, `n` above the limit.
- **Unknown kind** (4–255): the entry is kept verbatim on every rewrite, shown as "This vault needs a newer rizzy-vault", and never opened or deleted by this client.
- **Completeness check (proposed INV-102).** After every account answer the client compares the self-grants served with the directory's kind-1 and kind-2 entries (and, under Part B, kind 3). A listed vault without a self-grant is being withheld: the client raises an alarm and keeps that vault read-only from its cache. A self-grant whose vault is not listed is not opened and is reported (§A3 makes creation atomic, so an honest server never serves one).
- **Before a directory exists** (accounts created before Part A ships, §A10): while tag `0x0002` is absent and the account answer holds exactly one self-grant, that vault is the Personal vault. An absent tag with two or more self-grants raises the same alarm as a withheld vault.

#### A3. Creating a vault

1. The client generates `vault_id` (16 random bytes) and a vault key at epoch 0, and builds its `VAULT_KEY_SELF_GRANT` under the current account key (purpose 0x0020, context `account_id ‖ vault_id ‖ u32 account_key_epoch ‖ u32 0`), exactly as signup does.
2. It commits **one atomic account change** (`POST /api/v1/account/commit`, [CRYPTO.md §11](../CRYPTO.md#11-flows) "Replacing credentials"): a new `account-state` with `settings_seq + 1`, the new `ACCOUNT_SETTINGS` whose directory gains the kind-2 entry, and the new field `vault_create: VaultSelfGrant`. The server inserts the vault (`kind = 2`) and its self-grant in the commit's transaction, under the account lock, or refuses the whole change.
3. It then uploads, through the ordinary `vault/upload`, the vault-settings item (`0xF001`) with `vault.name` (and optionally `vault.icon`) as the vault's first op. If that upload fails, the vault shows as "Untitled vault" until a retry succeeds.

The server refuses a `vault_create` beyond `MAX_OWNED_VAULTS` (64) vaults of kind 1 or 2 for the account (`invalid_request`), whose `vault_id` exists (`state_conflict`), whose self-grant is not at the new state's `account_key_epoch` and vault epoch 0 or whose header key id is not the signed `account_key_id` (`invalid_request`), or that comes without `settings_seq + 1` in the same commit (`invalid_request`; the server cannot read the directory, so it checks only that the settings moved). Creation counts against a per-account rate-limit bucket (§D).

#### A4. Renaming

A write of `vault.name` / `vault.icon` to the vault's settings item: an ordinary op, synced and merged like any other. Clients cap the name at 64 Unicode scalar values in the UI; the record limits of [ADR 0018](0018-item-record-encoding.md) §10 apply unchanged. The Personal vault is not renamed (§A1).

#### A5. Deleting a vault

- Only an owned (kind 2) vault, only by its owner. The UI offers two choices, the first preselected: **"Move its N items to Personal, then delete"** (each item moved as §A6 says, then the vault deleted), or **"Delete the vault and its N items"**. Both need the vault's name typed as confirmation.
- The delete itself is **one atomic account change** like §A3: `settings_seq + 1` with the entry removed from the directory, and the new field `vault_delete: Id`. It needs a **fresh OPAQUE session**, checked by the server (`FRESH_SESSION_MS`, [CRYPTO.md §5.10](../CRYPTO.md#510-sessions-after-authentication); `403 fresh_session_required` otherwise), and the client asks for the re-authentication first, as [ADR 0034](0034-export-reauth-and-plaintext-hold.md) does for export. The server deletes the vault row and everything that cascades from it (self-grant, wraps, ops, snapshots, attachments and their chunks), and in the same transaction releases the vault's counted bytes from `storage_account_usage` ([ADR 0048](0048-per-account-storage-quota.md) §2), computed with the same per-record size function.
- Deletion is immediate and irreversible on the server. There is no vault-level trash (alternative in open question 5); items in the vault's trash go with it.
- Other devices learn of it from the new directory and drop the vault's cache rows and index rows. A device that holds unsent ops for a deleted vault reports them once ("N changes to a deleted vault were discarded") and discards them.
- The server refuses `vault_delete` for the Personal vault (`invalid_request`, proposed INV-101) and for a vault the caller does not own (`not_found`).

#### A6. Moving and copying items between vaults

Item ciphertext is bound to its vault by its context ([CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes)), so an item never changes vault. **A copy is a new item in the target vault; a move is a copy followed by a purge of the source.**

1. **Copy.** From the source item's merged state (registers and history, exactly as an [ADR 0027](0027-export-payload.md) payload entry holds it), the client creates a new item in the target vault through the importer path ADR 0027 §2 step 3 already uses (`VaultSync::import_item`): a **new `item_id`**, a new item key wrapped under the target vault key (`created_vault_key_epoch` = the target's current epoch), a create op of this device and a full snapshot. Field values, element ids, tags, passkeys, TOTP secrets and history travel; dots and HLCs do not. Each attachment is downloaded, decrypted and uploaded again under a new `attachment_id` and attachment key in the target ([ADR 0054](0054-attachments-envelope-and-api.md)). The local-index row's `last_used_ms` and `use_count` are copied to the new key.
2. **Move** = copy, then, **only after the server has acknowledged the target** (all ops, the snapshot and every attachment chunk), a `Trash` op and a `Purge` op on the source item in one upload (ADR 0012 §5 allows a purge only on a trashed item). Late ops on the source follow ADR 0012 §5 ("Late ops after a purge"); the prompt names the target vault when this device recorded the move.
3. **Crash safety (proposed INV-104).** Before step 1 the client writes a pending-move row to its cache (source vault and item, target vault and item). On restart it resumes: a target already stored is not created again; a source not yet purged is purged. The worst case is a duplicate, never a loss.
4. A move needs quota headroom for the copy (both exist for a moment); a `quota_exceeded` refusal aborts before the source is touched. The vault-settings item is never copied or moved (clients never list it).
5. Bulk "move all to Personal" (§A5) is the same operation per item, resumable.

#### A7. Sync, op log, cache and local index per vault

- **One op log per vault**, as ADR 0012 §1 decided. `device_seq` stays per device across all vaults (ADR 0012 §2): a device running several `VaultSync` drivers allocates `device_seq` from **one per-device counter** (today's cache meta `NEXT_DEVICE_SEQ`), and each driver sets `vault_prev_seq` from its own vault's chain. Fetch and upload stay per vault (`vault_id` in each request); a sync round fetches every vault in the directory.
- **Items are identified by `(vault_id, item_id)`** in every client structure: the cache, the local index, the wasm and FFI APIs, the TypeScript stores and URLs (proposed INV-103). `item_id` is unique only within a vault; nothing looks an item up by `item_id` alone.
- **Cache.** The per-account cache of [ADR 0026](0026-client-device-state-and-cache.md) already holds every vault (`vaults`, `wraps`, `ops`, `snapshots` keyed by `vault_id`). The next cache format (4) re-keys `item_index` (§0 item 7, rebuilt per ADR 0056 §4) and adds `pending_move(source_vault_id, source_item_id, target_vault_id, target_item_id, PRIMARY KEY (source_vault_id, source_item_id))`. Leaving or deleting a vault deletes its rows.
- **Search and lists** span all vaults by default, with a vault filter; every list row shows its vault. Autofill and passkey matching ([ADR 0037](0037-url-matching-and-autofill-rules.md), [ADR 0039](0039-passkeys-vault-and-extension.md)) consider items of all vaults.
- **Trash** stays per item; the trash view spans vaults; auto-purge (ADR 0012 §5) runs per vault.

#### A8. Default save target and the clients

- **Web vault and native apps:** a vault switcher ("All vaults", then Personal, then the other vaults by name); a vault picker in the new-item editor and in import, **preselected to Personal** every time (no "last used" memory, open question 4); "Move to…" and "Copy to…" on an item; a vault management screen (create, rename, delete).
- **Extension:** the save-on-submit and passkey-save prompts show the vault picker preselected to Personal; fill offers items from every vault.
- **`rv`:** `rv vault list | create <name> | rename <vault> <name> | delete <vault>`, `rv item move|copy <item> --to <vault>`, and `--vault <name|id>` on `item new` and `import`, defaulting to Personal. A name that matches two vaults is refused with the ids listed.
- **Export** is per vault ([ADR 0027](0027-export-payload.md): one payload is one vault's state): the dialog has a vault picker preselected to Personal. A multi-vault export container is out of scope (a later ADR if wanted).

#### A9. Quota, attachments, rotation and recovery

- **Quota:** unchanged, per account ([ADR 0048](0048-per-account-storage-quota.md)); every owned vault counts against its owner. The account answer gains, per vault, the server's unsigned `bytes_used` figure for display.
- **Attachments:** already vault-scoped by context and API; nothing changes in Part A.
- **Rotation** ([CRYPTO.md §11.6](../CRYPTO.md#116-key-rotation), [ADR 0025](0025-rotation-vault-half.md)): unchanged in substance. In Part A every vault of the account is unshared, so V is all of them and each gets a `VaultRotation`; `regrants` exists on the wire and is always empty (§0 item 3).
- **Recovery** ([CRYPTO.md §11.9](../CRYPTO.md#119-recovery-with-the-emergency-kit)) already returns every vault.

#### A10. Migration of existing accounts

- **Server:** migration `0008_vault_kinds` (both engines) adds `kind INTEGER NOT NULL DEFAULT 1 CHECK (kind IN (1, 2))` to `vault_vaults` and a partial unique index `ON vault_vaults (account_id) WHERE kind = 1` (both engines support partial indexes, U, to be confirmed by the migration's tests). Every existing row becomes kind 1: the only creation path so far is signup (Context), so each account has exactly one vault, and the unique index makes the migration fail loudly if that is ever false. Signup keeps creating the Personal vault with kind 1.
- **Clients:** an account without tag `0x0002` follows the §A2 rule (its single vault is Personal). The client writes the directory, with that vault as kind 1, as part of its next settings write or of its first `vault_create`, whichever comes first. No write is made just to migrate.
- **Cache:** format 3 → 4 as §A7; the index is rebuilt from the merged state, so no index data is migrated (ADR 0056 §4).
- **Vault name:** none is written; the existing vault shows as "Personal".

#### A11. Wire and storage (Part A)

- `rizzy-proto`: `CommitChangeRequest` (`deny_unknown_fields`) gains optional `vault_create: VaultSelfGrant` and `vault_delete: Id`, at most one of them per commit, each only with `settings_seq + 1`; `vault_rotation.regrants` (§0 item 3, empty in Part A); `AccountView` (a response type) gains `vaults: List<VaultSummary, MAX_VAULT_GRANTS>` with `{ vault_id, kind: u8, bytes_used: u64 }`, informational and unsigned. New limits `MAX_OWNED_VAULTS = 64`, `MAX_DIRECTORY_ENTRIES = 128`. The `MAX_VAULT_GRANTS` doc comment loses "One vault per account in M1".
- `rizzy-storage`: migration `0008_vault_kinds` (§A10). No new table.
- No new endpoint, envelope purpose, signed statement or error code.

#### A12. Compatibility

Before v1.0, [ADR 0002](0002-own-protocol.md) point 5 applies: an older client takes the first self-grant as "the" vault and can show the wrong one, so the server release that ships Part A **raises the minimum client versions** in `/api/meta`, after the store-distributed extension with Part A is live. So that Part B stays additive after v1.0, a Part A client already: parses directory kind 2 with bit 0 and kind 3, and keeps them; never opens a vault it cannot verify (it shows "needs update"); treats `client_too_old` on one vault's Fetch as "this vault needs an update" while the other vaults keep working (§B12); and sends and accepts an empty `regrants`.

---

### Part B: sharing a vault with other users

Part B code waits for its ROADMAP milestone (open question 1), even once this ADR is Accepted.

#### B1. Roles

| Role | Byte | May |
|---|---|---|
| former | 0 | nothing; kept in the statement so the account's earlier ops stay verifiable |
| view | 1 | fetch, decrypt, copy items out to its own vaults (§C), export the vault |
| edit | 2 | view, plus create, edit, trash, restore and purge items, and add or delete attachments |
| manage | 3 | edit, plus write the vault-settings item (rename), invite, change roles, remove members, rekey |

The **owner** is the account that created the vault (`vault_vaults.account_id`). The owner always has role manage, cannot be demoted or removed, cannot leave, and is the only account that may delete the vault (§A5). Ownership transfer is out of scope (open question 8). Only an owned (kind 2) vault can become shared, and only by its owner; never the Personal vault.

#### B2. Other accounts' keys: contact pins (`ACCOUNT_SETTINGS` tag `0x0003`)

[CRYPTO.md §10.3](../CRYPTO.md#103-public-key-authenticity) applies as written; this section fixes where the pins live.

```
tag 0x0003 value
  u8  format = 1
  u16 n ‖ n × contact          n ≤ MAX_CONTACTS (256), strictly ascending by account_id
contact
  account_id (16) ‖ identity Ed25519 pk (32) ‖ identity X25519 pk (32)
  u64 bundle_seq ‖ bundle_hash (32)            the highest bundle seen (§10.3 point 2)
  u8  state                                    1 pinned on first use, unverified; 2 fingerprint verified;
                                               3 blocked: identity changed or fork (INV-17)
  u64 state_changed_at_ms
```

- A contact is added at the first lookup the user acts on (§B4) or the first invite received (§B5).
- **The other account's key is authenticated by TOFU plus safety numbers**, as §10.3 decides: the client shows the 60-digit safety number and QR code (§10.3 point 1) before any grant, and the user either confirms they compared it (state 2) or explicitly continues unverified (state 1: a persistent "not verified" badge on that member everywhere). A later bundle is accepted silently only along §10.3's chain rule; an identity change or a fork sets state 3, which blocks every new grant to that contact until the user re-verifies (INV-17).
- A **signed key directory or key transparency** is not adopted (THREAT_MODEL Q-8, post-1.0 Could). The residual risk is AR-6: a server that substitutes keys at first contact beats users who never compare safety numbers. §B5 adds one check the invitee gets for free.

#### B3. The `vault-membership` statement

A new signed statement in the [CRYPTO.md §10.2](../CRYPTO.md#102-ed25519-signatures-and-signed-statements) message format: `LABEL("sig/vault-membership") ‖ 0x00 ‖ u16(statement_version = 1) ‖ body`, Ed25519, verified with `verify_strict`. It is the signed vault statement CRYPTO.md §11.6 requires and the membership statement INV-67 requires.

```
body
  vault_id (16)
  u64 membership_seq             1 for the first statement; +1 per statement
  prev_membership_hash (32)      SHA-256 of the previous statement's signed message; zero for seq 1
  owner account_id (16)
  u32 vault_key_epoch            the vault's current epoch
  vault_key_id (16)              the symmetric key id (CRYPTO.md §4.4) of that epoch's vault key
  u8  n ‖ n × member             1 ≤ n ≤ 255, strictly ascending by account_id
  u64 created_at_ms
member
  account_id (16) ‖ identity Ed25519 pk (32) ‖ identity X25519 pk (32) ‖ u32 identity_epoch
  u8  role                       0 former, 1 view, 2 edit, 3 manage (§B1)
  u8  m ‖ m × cut                strictly ascending by device_id; m = 0 when role is 2 or 3
cut
  device_id (16) ‖ u64 last_accepted_device_seq
```

- **Signer:** a member with role manage in statement `seq − 1`, signing with the identity Ed25519 key that statement lists for it; for `seq = 1`, the owner. The owner appears with role 3 in every statement. A manager whose identity keys changed (full rotation) signs with its new key only after another manager has re-listed it, or, for the owner, only for readers who have re-verified that contact (§B2 state back to 1 or 2 after the "safety number changed" prompt).
- **Limits:** at most 32 members with role ≥ 1 (`MAX_VAULT_MEMBERS`), at most 1,024 cuts in total, signed message at most 64 KiB.
- **Verification by every reader** (proposed INV-105): the chain from `seq = 1` (each `prev_membership_hash` links, each signer is a manager of the previous statement under the key it lists); the chain is anchored in the reader's own pins: the inviter's or another known manager's identity key in the latest statement must equal the reader's contact pin for that account, and the reader's own entry must carry the reader's own current identity keys. `vault_id` matches. A statement below the reader's pinned `membership_seq` (directory, §A2) is a rollback alarm; two different statements with the same `seq` are a fork alarm ("the server has shown you two versions of this vault's members"), and the vault turns read-only until the users resolve it out of band.
- **What the epoch fields give:** a member learns the current `vault_key_epoch` and checks every vault key it receives against `vault_key_id`, so a grant can deliver only the key the managers signed for. For a shared vault, the "current vault epoch" of the CRYPTO.md §11.6 writer rule is the statement's `vault_key_epoch`.
- **Cuts** apply the device-revocation pattern to roles: for a member whose role does not allow writing (view, former), an op or snapshot by device d is accepted only if its `device_seq` ≤ the cut for d (0 when d has none). A manager sets the cuts of a demoted or removed member to the server's heads for that member's devices in this vault, after a complete Fetch; the server refuses a statement whose cut for a device differs from its head h(V, d) (`state_conflict`), as ADR 0025 §3 check 4 does for rotations.

#### B4. Inviting

1. The manager's client fetches the vault to completion, then resolves the invitee's login name with `directory/lookup` (§B11), which returns the account id and its bundle chain. It verifies the chain's self-signatures and applies §B2 (pin, safety number, explicit verify-or-continue choice). A blocked contact (state 3) cannot be invited.
2. It signs statement `seq + 1` adding the invitee, with the chosen role and the invitee's identity keys from the pinned bundle. If the vault had no statement, this is `seq = 1`, made by the owner, and the vault's directory entry gets bit 0.
3. It builds a `VAULT_KEY_MEMBER_GRANT` (purpose 0x0021, HPKE Base `0x10` to the invitee's identity X25519 key, context `vault_id ‖ u32 vault_key_epoch ‖ granter account_id ‖ grantee account_id`, [CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes)), signed as a `key-grant` by the manager's identity key ([§10.1](../CRYPTO.md#101-hpke-key-wrapping)).
4. `vault/members/invite` carries the statement and the grant. The server checks §B9 and stores both; the invitee's member state is `invited`.
5. The manager's client commits the new pins (the directory's `membership_seq` and hash, and the contact pin if new) in its next settings write.

#### B5. Accepting or declining

1. The invitee's account answer lists pending invites: per vault, the statement chain, the grant and the bundle chain of every signer.
2. The invitee's client verifies the chain (§B3) and the grant's signature, applies §B2 to the inviter, and checks that the statement lists **the invitee's own current identity keys**. If it lists any other key, the client shows a hard alarm ("the inviter was given a different key for you") and offers only decline. This detects a key substituted at the inviter's lookup whenever the real invitee receives the invite.
3. It opens the grant and checks that the delivered key's id equals the statement's `vault_key_id`. It may then fetch the vault to show its name and size before the user decides (an invited member can fetch, §B9).
4. **Accept** is one atomic account change: `settings_seq + 1` with a kind-3 directory entry (owner, pinned `membership_seq` and hash) and the new commit field `vault_join: VaultSelfGrant`, the vault key wrapped under the invitee's own account key (purpose 0x0020, unchanged context). The server checks the self-grant as §A3 does, stores it under `(vault_id, account_id)`, sets the member state to `active` and **deletes the member grant**, so no long-lived X25519-only wrap of the vault key stays on the server (harvest now, decrypt later; [CRYPTO.md §13](../CRYPTO.md#13-post-quantum-readiness)).
5. **Decline** (`vault/members/decline`) deletes the grant and sets the member state to `declined`. The invitee could have opened the grant, so managers treat a declined member like a removed one (§B6).

#### B6. Role changes, removal, leaving and rekeying

All of these are `vault/members/update` with a new statement, signed by a manager after a complete Fetch:

- **Promotion, or demotion to view:** a new statement only, no rotation. A demotion sets cuts (§B3).
- **Removal** (role → 0; also for a member who declined, left or whose account was deleted): a new statement with **`vault_key_epoch + 1`** and the new `vault_key_id`; a `VaultRotation` for this vault in the ADR 0025 §1 shape (the updater's new self-grant, its cursor, every wrap re-wrapped, `dropped`), checked as ADR 0025 §3 checks 2–5 with the updater's current `account_key_epoch` and `account_key_id`; and one new `VAULT_KEY_MEMBER_GRANT` per remaining active member other than the updater. Item contents are not re-encrypted: the CRYPTO.md §11.6 writer rule gives every item a fresh item key on its next write.
- **Rekey** without a membership change (after a member's device revocation, §B8): the same as a removal with an unchanged member list.
- **Adopting a new key:** each remaining member's client, on seeing the new statement, opens its grant, checks `vault_key_id`, and sends `vault/members/adopt` with its new self-grant; the server deletes the grant and the member's superseded self-grant.
- **Leaving** (a member other than the owner): one atomic account change removing the directory entry, with the commit field `vault_leave: Id`; the server deletes the leaver's self-grant and sets the state `left`. Managers' clients see `left` in their next Fetch and remove the member with a rotation at their next unlock.
- **Deleting the vault** (owner only) is §A5. Members' Fetch then answers `not_found`. A member's client cannot tell deletion from withholding, so it keeps the directory entry and shows "This vault is unavailable: its owner deleted it, or the server is withholding it" until the user removes the entry.

#### B7. Which ops a member's client accepts (INV-67)

For an op or snapshot in shared vault V by device d of account a, with S the reader's highest verified statement:

1. a is listed in S;
2. d's device certificate chains to the identity key S lists for a, at S's `identity_epoch` for a, and d is not revoked at that `device_seq` by a's revocations (served with the Fetch, §B11);
3. a's role in S is edit or manage, or `device_seq` ≤ the cut for d;
4. a write to the vault-settings item (`0xF001`) additionally needs role manage, or `device_seq` ≤ the cut.

An op that fails is not applied, is kept parked, and is reported once ("An edit by Bob in Family was ignored: Bob has view access"). A reader that applied an op under an older S and then verifies an S that rejects it removes the op and recomputes the item (the ADR 0012 §6 path). Acceptance is a deterministic function of the op set and S, so readers that hold the same S converge. A member's full rotation (new identity keys) parks that member's new ops until a manager has re-verified the contact and published a statement with the new keys (§B2); this is conservative because a full rotation can mean a thief holds the old identity key. For another account's revoked device, a reader checks that device's chain within V through `vault_prev_seq` only: it cannot see the device's ops in other vaults, so a withheld tail of a revoked device's ops in V goes undetected (Risks). The own-account rule of §0 item 2 is unchanged.

#### B8. Account-key rotation, revocation and recovery with shared vaults

- A standard or full rotation ([CRYPTO.md §11.6](../CRYPTO.md#116-key-rotation)) rotates the vault keys of the account's **unshared** vaults (V, §0 item 4) and **re-wraps** its self-grant of every shared vault, owned or joined, under the new account key at the unchanged `vault_key_epoch` (`regrants`, §0 item 3). Rotating a shared vault's key needs a statement and grants to other members, so it is never part of the account commit.
- When the trigger is a device revocation, a recovery or a suspected compromise, the rotating client then **rekeys** (§B6) every shared vault where its account has role manage. For a shared vault where it has a lower role, the server sets an unsigned `rekey_requested` flag on the vault, which managers' clients act on at their next unlock (a hint a malicious server can drop; Risks).
- Recovery (CRYPTO.md §11.9) returns the self-grants of joined vaults as it does for owned ones; the recovering client re-wraps them through `regrants`.
- A full rotation changes the identity keys, which every contact sees as a safety-number change (§B2, §B7).

#### B9. Server enforcement, and what the server learns

- The server mirrors each vault's latest accepted statement into `vault_members` and checks every request against it: Fetch and attachment download need role ≥ 1 or state `invited`; upload and attachment create, upload-chunk and delete need role ≥ 2, and an op or snapshot by a device past its cut is refused; `vault/members/update` needs role 3; deleting the vault needs the owner. A non-member gets `not_found`; a member whose role or cut forbids the write gets `state_conflict`.
- Before storing a statement, the server checks: shape and limits; `seq = stored + 1` and `prev_membership_hash`; the signature against the signer's current bundle (held by the `auth` domain, reached through its Rust API), and that the signer is a manager in the stored statement; that the owner stays manage; that the vault is not the Personal vault (`invalid_request`, proposed INV-101); the cuts against the heads (§B3); and that `vault_key_epoch` moves by exactly one when, and only when, a rotation is carried, with a grant for every added or remaining member.
- The **client check is authoritative** (INV-67); the server check is a second layer that a malicious server can skip.
- A shared vault's writes take the **owner's** account lock and are charged to the **owner's** quota ([ADR 0048](0048-per-account-storage-quota.md)), whoever uploads (open question 10).
- **What the server learns** (proposed AR-29): the membership graph (which accounts share which vault, their roles, and the times of invites, accepts, declines, departures and removals), which login names a user looked up, each member's write activity per vault (it already sees per-device activity), vault counts and sizes, and every member's public identity keys. It does not learn vault names, item contents or which item is which.

#### B10. What a removed member keeps

- Everything their clients decrypted while they were a member: cached plaintext, exports, and copies made into their own vaults (THREAT_MODEL A17, residual risk). An honest client deletes the vault's cache and index rows when it learns of the removal; nothing enforces that.
- The old vault key and every item key it opened. They can therefore still decrypt **ciphertext from before their removal**, for example from a later DB leak, which is content they could already read. Content written after the removal is under the new vault key and, by the writer rule, under fresh item keys, so it is closed to them: forward secrecy for new writes only.
- Eager re-encryption of every item at removal is not done: it would protect only content the removed member could already read.

#### B11. Wire and storage (Part B)

- **Endpoints** ([ADR 0028](0028-api-v1-http-conventions.md) conventions: `POST`, JSON, `deny_unknown_fields` on requests, existing error codes):
  - `directory/lookup` `{ login_name }` → `{ account_id, bundles }`, or `not_found`. Authenticated sessions only; rate-limited (§D); open question 6 on enumeration.
  - `vault/members/invite` `{ vault_id, statement, member_grant }`.
  - `vault/members/update` `{ vault_id, statement, rotation?: VaultRotation, member_grants: List<MemberGrant, MAX_VAULT_MEMBERS> }`.
  - `vault/members/decline` `{ vault_id }`; `vault/members/adopt` `{ vault_id, self_grant }`.
  - `account/commit` gains `vault_join: VaultSelfGrant` and `vault_leave: Id`, each only with `settings_seq + 1`.
- **Responses:** `AccountView` gains `pending_invites`; `FetchRequest` gains `membership: bool`, sent only to a server whose `/api/meta` advertises Part B; for a shared vault, the Fetch response adds the statements after the client's pinned `membership_seq` and `member_authors` (per member: bundle chain, device certificates, revocations). A Fetch of a shared vault without `membership: true` answers `client_too_old`.
- **Tables** (`vault_` prefix, owned by `rizzy-domain-vault`; the only cross-domain keys reference `auth_accounts(id) ON DELETE CASCADE`, ADR 0011 point 6), migration `0009_vault_members`:
  - `vault_memberships(vault_id, membership_seq, statement, signature, statement_hash, created_at_ms, PRIMARY KEY (vault_id, membership_seq))`;
  - `vault_members(vault_id, account_id, role, state, updated_at_ms, PRIMARY KEY (vault_id, account_id))`, with `state` one of invited, active, declined, left;
  - `vault_member_grants(vault_id, grantee_account_id, vault_key_epoch, envelope, signature, created_at_ms, PRIMARY KEY (vault_id, grantee_account_id, vault_key_epoch))`;
  - `vault_self_grants` re-keyed to `PRIMARY KEY (vault_id, account_id)`, existing rows taking the vault's owner;
  - `vault_vaults` gains `rekey_requested INTEGER NOT NULL DEFAULT 0`.
- Deleting a member's account cascades its membership rows away; managers' clients see the member gone and remove it with a rotation. Deleting an owner's account deletes its vaults, shared ones included; the delete-account screen lists those shared vaults and their members first.

#### B12. Compatibility after v1.0

Part B is additive under `v1` (ADR 0002 point 3): new endpoints, new optional request fields sent only to servers that advertise them, new response fields (response types ignore unknown fields), and the per-vault `client_too_old` of §B11 for a client without membership support, which a Part A client already handles (§A12).

---

### C. "Selective creds sharing" from the Personal vault

The owner's exception lets single items leave the Personal vault, never the vault as a whole. Recommended reading (open question 2): a **"Share…" action on a Personal item** offers

1. **"Move to a shared vault"** (preselected) or **"Copy to a shared vault"**: §A6 into a shared vault the user picks or creates on the spot. From then on the item is live, under that vault's members and roles (Part B).
2. **"Share a link"**: the M5 snapshot link share ([ADR 0063](0063-share-snapshot-format.md) to [ADR 0067](0067-send-style-share.md), Proposed), once M5 ships; available from any vault.

There is **no per-item live grant** to another account: item keys are never wrapped to another account's key, and ROADMAP §4.7's Won't row ("Live shared items between two personal accounts (that is what shared vaults in M9 are for)") stays true.

### D. Limits and rate limits

| Limit | Value | Enforced by |
|---|---|---|
| Owned vaults per account (Personal included) | 64 (`MAX_OWNED_VAULTS`) | server (`invalid_request`), client |
| Directory entries (owned, joined and unknown kinds) | 128 | client parser |
| Vault name | 64 Unicode scalar values (UI); ADR 0018 §10 record limits | client |
| Active members per vault (role ≥ 1) | 32 (`MAX_VAULT_MEMBERS`) | server, client |
| Statement entries / cuts / signed size | 255 / 1,024 / 64 KiB | server, client parser |
| Contacts | 256 | client parser |
| Pending invites | 32 per vault, 64 per invitee | server (`state_conflict`) |
| Vault creation | 20 per account per 24 h | server (`rate_limited`) |
| `directory/lookup` | 30 per account per hour and 100 per 24 h | server (`rate_limited`) |
| `vault/members/invite` | 50 per account per 24 h | server (`rate_limited`) |

Request bodies: `invite`, `decline`, `adopt` and `lookup` take the default limit of [ADR 0028](0028-api-v1-http-conventions.md) item 7; `update` and `account/commit` take `RIZZY_MAX_UPLOAD_BYTES`.

### E. Proposed invariants (ids provisional: the next free after INV-100)

- **INV-101** (Part A): The Personal vault exists exactly once per account, is never deleted, and never has a `vault-membership` statement or a member grant. Clients refuse to create either; the server refuses `vault_delete`, statements and grants for it. *Verified by:* server integration tests for each refusal; client API tests.
- **INV-102** (Part A): A client opens a vault only if the authenticated vault directory lists it, and raises an alarm when a listed vault's self-grant is missing (withholding) or an unlisted one is served. *Verified by:* malicious-server double tests.
- **INV-103** (Part A): Clients identify items by `(vault_id, item_id)`; an `item_id` from one vault never addresses an item of another. *Verified by:* a test with the same `item_id` in two vaults.
- **INV-104** (Part A): A move purges the source only after the server has acknowledged the target copy with every attachment chunk. *Verified by:* fault-injection tests at each step.
- **INV-105** (Part B): A client accepts a vault key, an op or a snapshot of a shared vault only under a `vault-membership` chain it verified from `seq = 1` and anchored in its own pins (§B3), and never below its pinned `membership_seq`. *Verified by:* negative tests (non-manager signer, broken chain, fork, rollback, wrong `vault_key_id`).
- **AR-29** (Part B): The server sees the membership graph and lookups (§B9). Accepted: every server-mediated sharing design has it.

INV-17 and INV-67 are implemented by Part B (their "From" stays M9 unless open question 1 moves Part B).

### On acceptance

The owner makes these edits in the change that accepts this ADR, or in a docs change right after it; none is made now:

1. **[ROADMAP.md](../ROADMAP.md)** (owner approval required):
   - §4.2 gains the row "| S | Multiple vaults per account: a Personal vault (created at signup, default save target, cannot be deleted or shared) plus vaults the user creates; rename, delete, move and copy items between vaults ([ADR 0081](adr/0081-multiple-vaults-personal-and-shared.md) Part A) | M3 |" (milestone per open question 1).
   - §4.11, the row "Shared vaults with per-member permissions (view / edit / manage)" gains "([ADR 0081](adr/0081-multiple-vaults-personal-and-shared.md) Part B; never the Personal vault)". If open question 1 moves Part B earlier, §3 and §4.11 change accordingly.
   - §4.7 gains, per open question 2, the row "| S | Share one item from the Personal vault: link share (M5) or move/copy into a shared vault (M9) ([ADR 0081](adr/0081-multiple-vaults-personal-and-shared.md) §C) | M5 / M9 |".
2. **Status lines** (and their README rows): ADR 0012 gains "; [ADR 0081](0081-multiple-vaults-personal-and-shared.md) (§1 in part)"; ADR 0021 gains "; ADR 0081 (§9 in part)"; ADR 0025 becomes "Partially superseded by ADR 0081 (§1 in part, §3 in part)"; ADR 0028 gains "; ADR 0081 (item 1 in part)"; ADR 0042 becomes "Partially superseded by ADR 0081 (§2 in part)"; ADR 0056 becomes "Partially superseded by ADR 0081 (§3 in part)".
3. **[CRYPTO.md](../CRYPTO.md):** §4.2, the vault-key row ("Rotated when": account-key rotation for unshared vaults; member removal or rekey for shared vaults) and the "Where each wrapped-key object lives" rows for `VAULT_KEY_SELF_GRANT` (one per vault and account) and `VAULT_KEY_MEMBER_GRANT` (server, `vault` domain, until accepted, declined or adopted); §8.4, the `ACCOUNT_SETTINGS` row naming tags `0x0002` and `0x0003`, and `VAULT_KEY_MEMBER_GRANT`'s "First used" pointing at Part B; §10.2, a `vault-membership` row (§B3); §10.3 point 2 naming tag `0x0003` and point 3 pointing at §B4–§B5; §11.6 steps 2–3 and the "Current vault epoch" bullet (§B3, §B8); new flows "Vault create and delete", "Item move and copy" and "Invite, accept, remove, rekey"; §15, the vectors, property tests and fuzz targets of the implementation plan.
4. **[THREAT_MODEL.md](../THREAT_MODEL.md):** A17 mitigations pointing at §B3 and §B7 (resolving "The statement format belongs to the M9 ADR"); §5.4 and §5.7 pointing at §B2, §B4 and §B5; §3.4, the `vault` domain row gains memberships, member grants and the vault kind; §8, rows INV-101 to INV-105; §9, AR-29.
5. **CLAUDE.md** status line and this ADR's README row: 0081 moves from Proposed to Accepted.
6. **[docs/rv.md](../rv.md)** and the web help: the `rv vault` commands and `--vault` (with the Part A code).

## Consequences

### Positive

- Delivers the owner's model on the key hierarchy ROADMAP principle 3 put in place in M1: per-vault keys, per-vault op streams and multi-vault storage already exist, so Part A adds no cryptography and Part B adds one signed statement.
- The Personal vault's protections are checked twice (client and server), and which vault is Personal rests on the account-key-encrypted, signed-fresh directory, not on server metadata.
- The directory closes a gap several vaults would open: without it, a server could hide a whole vault and no client would notice.
- Part A ships before the M8 audit, so the audit sees the final vault model; Part B is additive after v1.0.
- Members' long-lived copies of a vault key are symmetric self-grants; HPKE grants live only until accepted.
- INV-67's role enforcement reuses the revocation pattern (`last_accepted_device_seq`), with no change to the op header (ADR 0018).

### Negative

- A move rewrites the item: new id, new dots, attachments uploaded again. References to the old item id (deep links, open editors on other devices) break, except the local-index usage data §A6 copies; a 25 MiB attachment is downloaded and uploaded again.
- A forced client update when Part A ships (§A12), and a cache-format bump.
- Every client UI gains a vault dimension (switcher, picker, badges, filters, management screens), and every new screen must pass the axe audit and the keyboard walk.
- Vault deletion is immediate; a mistaken "delete with items" is unrecoverable except from an export or a server backup.
- Part B is a large feature: membership-aware op acceptance, contact pins, safety-number UX, invites, rekeys, and members' authors in Fetch.
- The server learns the membership graph (AR-29).

### Risks

- **TOFU** (AR-6): users who never compare safety numbers can be given a server's key at the first invite. §B5's own-key check helps only when the real invitee receives the invite.
- **Withheld tail of another member's revoked device** (§B7): undetected in a shared vault, because a reader sees only that vault of the device.
- **`rekey_requested` is an unsigned hint** (§B8): a malicious server can suppress it, leaving a revoked device's copy of the vault key current in a shared vault where its account is not a manager, until a manager rekeys for another reason.
- **Statement growth:** former members are kept forever (255 entries per vault, ever). A long-lived family vault could reach that; a later ADR would need a compaction rule.
- **Restore from backup** ([ADR 0021](0021-server-compaction.md), [ADR 0032](0032-healing-rotation-after-backup.md)) can roll memberships back; clients detect it through their pins and must re-publish their highest statements through healing, which the Part B implementation adds.
- **Conservative parking on identity change** (§B7) stalls a member's writes until a manager re-verifies them; an owner who is the only manager and does a full rotation needs every member to re-verify the owner (§B3).

## Alternatives considered

- **Folders or tags as "vaults", one key per account.** Rejected: they cannot be shared without re-encrypting, which ROADMAP principle 3 exists to avoid.
- **One op log for all of an account's vaults.** Rejected: the vault is the unit of membership; a member must see only the vaults they belong to (ADR 0012 §1, `vault_prev_seq`).
- **Mark the Personal vault by its `vault.name` or by server metadata.** Rejected: a name is renameable vault data that any manager could write, and server metadata is untrusted. The marker belongs to the account, so it lives in the account's directory.
- **Derive the Personal vault id from the account id.** Rejected: no benefit (the server already knows which vault is Personal), and it would make a vault id predictable.
- **Vault list in a new identity-signed statement or an `account-state` field.** Rejected: `ACCOUNT_SETTINGS` already has signed freshness and an extensible tag registry; a new statement or field is a format change for the same guarantee.
- **Move by re-wrapping the item key under the target vault key and keeping the ciphertext.** Rejected: every item context names `vault_id`; dropping it would remove the cross-vault binding CRYPTO.md §8.4 relies on.
- **Keep the `item_id` across a move.** Rejected: both copies coexist until the purge, late ops would target two items, and INV-103 would need exceptions.
- **Vault-level trash** (a deleted vault recoverable for 30 days). Not chosen for now (open question 5): server-side retention of a deleted vault's ciphertext and a restore flow, for a rare action that the "move to Personal" default already makes safe.
- **Per-item live grants to another account** for "selective sharing". Rejected (§C): a second membership and rotation system per item, a per-item sharing graph on the server, and the ROADMAP §4.7 Won't row.
- **A signed key directory or key transparency instead of TOFU.** Deferred: THREAT_MODEL Q-8 rates it a post-1.0 Could, and CRYPTO.md §10.3 already decided TOFU plus safety numbers.
- **Server-only role enforcement.** Rejected by INV-67.
- **A `membership_seq` in every op header** to bind ops to roles. Rejected: an ADR 0018 op-header change for every op; cuts give the same determinism with today's header.
- **Keep members on HPKE grants for good.** Rejected: an X25519-only wrap sitting on the server for the vault's lifetime is the harvest-now-decrypt-later exposure CRYPTO.md §10.1 avoids elsewhere with PSK mode.
- **Charge a shared vault's bytes to the uploading member.** Not chosen (open question 10): one vault's bytes would be spread over accounts whose holders cannot delete them.

## Open questions for the owner

1. **Milestones.** (a) Part A in **M3**, before v1.0, and Part B as the first deliverable of **M9**; (b) Part A in M3 and Part B in a new post-1.0 milestone before M9; (c) both after v1.0. *Recommendation:* (a). Part A changes a persistent format, the cache and every client's model, so it is cheapest now and is audited in M8; sharing stays after v1.0, in line with the owner's 2026-10-22 decision for M5. Choose (b) if sharing between family members is wanted before the rest of M9 (family org, emergency access).
2. **Meaning of "selective creds sharing".** (a) §C: move (default) or copy into a shared vault, plus M5 link shares; (b) per-item live grants to another account; (c) link shares only. *Recommendation:* (a): live where it should be, one key model, and ROADMAP §4.7's Won't row kept.
3. **May the Personal vault be renamed?** *Recommendation:* no; it is always shown as "Personal" (localised), which keeps the default root vault recognisable on every device.
4. **May the user change the default save target?** *Recommendation:* no setting; Personal is preselected every time, with the picker one click away, as the request says.
5. **Deleting a vault that has items.** (a) §A5: default "move items to Personal", alternative "delete with items", immediate; (b) add a 30-day vault-level trash. *Recommendation:* (a).
6. **`directory/lookup` is an enumeration oracle for signed-in users.** (a) Accept it, rate-limited (§D), answering `not_found` for unknown names; (b) answer unknown names with a deterministic fake bundle, as login does for unknown names (CRYPTO.md §5.9); (c) add an operator switch that turns sharing off. *Recommendation:* (a): only authenticated users of the same instance can probe, and registration already reveals taken names; (b) costs a fake-key path for little gain on a family instance.
7. **May an invite go to an unverified key?** CRYPTO.md §10.3 point 3 allows "explicitly accept TOFU with a visible 'not verified' badge". *Recommendation:* allow it, with the persistent badge and a reminder on the member list.
8. **Ownership transfer, and the owner leaving.** *Recommendation:* not in this ADR; the owner can only delete. A later ADR if families ask.
9. **The numbers:** 64 owned vaults, 32 active members, 255 statement entries, and the rate limits of §D. *Recommendation:* accept as written and revisit for M10.
10. **Who pays for a shared vault's bytes.** *Recommendation:* the owner (§B9).
11. **One ADR or two.** Acceptance covers a whole ADR. *Recommendation:* accept 0081 as a whole and let the ROADMAP milestone gate Part B's code. If you want Part B's details to stay open longer, say so: Part B then moves to a new ADR, and 0081 keeps Part A and the reservations of §A12.

## Implementation plan (for the implementer, once Accepted)

Code waits for acceptance and, for each part, its ROADMAP row.

**Part A**
- **`rizzy-proto`:** `change.rs` (`vault_create`, `vault_delete`, `regrants`), `account.rs` (`VaultSummary`, `vaults`), `limits.rs` (new limits and the doc comment). The `proto_json` fuzz target covers the new types.
- **`rizzy-storage`:** `migrations/{sqlite,postgres}/0008_vault_kinds.sql`; migration tests, including the failing case (two vaults for one account).
- **`rizzy-domain-vault`:** `keys.rs` (`create_vault` with the kind, `delete_vault` with the quota release), the commit bridge (`port.rs`). Integration tests: create; the 64 cap; Personal delete refused; delete releases quota; delete needs a fresh session; the rate limit.
- **`rizzy-domain-auth`:** commit classification for `vault_create` / `vault_delete` (only with `settings_seq + 1`, at most one), the fresh-session rule, the rate-limit bucket.
- **`rizzy-client`:** the tag `0x0002` parser and writer (next to tag `0x0001`, ADR 0042 §1); a vault set with one `VaultSync` per vault and one per-device `device_seq` allocator; the directory completeness check and the legacy rule; create, rename, delete; move and copy with the `pending_move` resume (`items.rs`, `attachments.rs`); cache format 4 (`store/rows.rs`, the migration, the index rebuild, `(vault_id, item_id)` keys in `store/index.rs`); export and import take a vault.
- **`rizzy-sync`:** no format change.
- **`rizzy-wasm`:** remove `vault_ids().next()` (`session.rs`, `device.rs`); vault-aware exports (list, create, rename, delete, move, copy, picker data); regenerate and review the bindings baseline (`cargo xtask expand-bindings --write`; explain any change in the `unsafe` counts).
- **`rizzy-cli`:** `device.rs` holds a vault set instead of one `VaultSync`; `enrol.rs`; `rv vault …`, `--vault`, `rv item move|copy`; `docs/rv.md`.
- **`packages/core`, `packages/ui`, `apps/web`:** vault ids in the item model and routes; switcher, picker, badges; dialogs (create, rename, delete with the two choices, move and copy).
- **`apps/extension`:** the picker in save prompts; cross-vault matching.
- **Vectors (CRYPTO.md §15 item 1):** tag `0x0002` encodings: Personal only; Personal plus two owned vaults (one with bit 0); a kind-3 entry; an unknown kind kept verbatim; negatives (no kind-1 entry, two kind-1 entries, unsorted, duplicate, reserved flag bit, wrong body length, 129 entries, trailing byte).
- **Property tests:** random ops over 1–4 vaults with interleaved per-vault delivery converge per vault, keep `device_seq` gap-free per device across vaults and `vault_prev_seq` chained per vault; a move with a failure injected at every step leaves every field value in at least one vault; the same `item_id` in two vaults never crosses (INV-103).
- **Fuzz targets:** `client_vault_directory` (tag `0x0002`); the existing settings target extended.
- **e2e and a11y:** web (create, rename, delete with both choices, move, copy, the picker's Personal default, the "All vaults" filter) and extension (the save prompt's picker); every new screen and dialog added to `apps/web/e2e/a11y.ts` and the keyboard walk; `rv` integration tests.

**Part B**
- **`rizzy-core`:** `sign/statements.rs`, the `vault-membership` statement (build, parse, verify, chain, fork and rollback checks); the `VaultKeyMemberGrant` context out of `cfg(test)` (`envelope/purpose.rs`); seal and open helpers next to `keys/grant.rs`; safety-number rendering (CRYPTO.md §10.3 point 1) if not already present.
- **`rizzy-proto`:** `vault/members/*`, `directory/lookup`, `vault_join`, `vault_leave`, the Fetch additions, `pending_invites`.
- **`rizzy-storage`:** `0009_vault_members` (§B11).
- **`rizzy-domain-vault`:** a `members` module (statement checks, grants, adopt, decline, role and cut enforcement in upload, fetch and attachments, the owner's lock and quota, `rekey_requested`); healing re-publishes statements.
- **`rizzy-domain-auth`:** the `directory.rs` lookup, its rate limits, and members' bundle chains for the vault domain through its port.
- **`rizzy-client`:** tag `0x0003`; invite, accept, decline, leave, role change, removal and rekey; membership-aware authors and the §B7 rule with parking and recompute; `regrants` in rotation; recovery for joined vaults.
- **Vectors:** `vault-membership` known-answer statements (seq 1 by the owner; seq 2 adding a member; a removal with cuts and a new epoch) from fixed seeds, plus negatives (non-manager signer, wrong `prev_membership_hash`, owner demoted, Personal vault, unsorted members, a cut on an edit member, oversize); tag `0x0003` encodings and negatives; a `VAULT_KEY_MEMBER_GRANT` vector promoted to the committed tier, with its signature.
- **Property tests:** any delivery order of ops and statements gives the same accepted set once the final statement is held; ops at or below a cut survive a demotion, ops above it never apply.
- **Negative protocol tests** (malicious-server double): substituted invitee key (the §B5 alarm), substituted inviter key (TOFU prompt, then the INV-17 block after an identity change), rolled-back and forked statements, a withheld membership update, a wrong `vault_key_id` in a grant, a view member's op accepted by the server and rejected by clients.
- **Fuzz targets:** `core_vault_membership`, `client_contacts`, `proto_json` additions.
- **e2e and a11y:** invite with safety number and QR code; accept and decline, including the own-key alarm; the member list with badges; role change; removal; leaving. All in the axe audit and the keyboard walk, with a two-account e2e (owner and member browsers).

## References

- The owner's request of 2026-10-23 (Context); the owner decisions of 2026-10-22 (M5 and M6 after v1.0), [docs/HANDOFF.md](../HANDOFF.md).
- [ROADMAP.md](../ROADMAP.md) §2 principle 3, §3, §4.2, §4.3, §4.7, §4.11.
- [CRYPTO.md](../CRYPTO.md) §4.1–§4.4, §8.4, §10.1–§10.3, §11.1, §11.6, §11.9, §13, §15.
- [THREAT_MODEL.md](../THREAT_MODEL.md) A8, A17, §5.4, §5.6, §5.7, INV-17, INV-27, INV-67, AR-6, Q-8.
- ADRs [0002](0002-own-protocol.md), [0006](0006-key-hierarchy.md), [0011](0011-storage.md), [0012](0012-sync-engine.md), [0018](0018-item-record-encoding.md), [0020](0020-partial-supersession.md), [0021](0021-server-compaction.md), [0025](0025-rotation-vault-half.md), [0026](0026-client-device-state-and-cache.md), [0027](0027-export-payload.md), [0028](0028-api-v1-http-conventions.md), [0034](0034-export-reauth-and-plaintext-hold.md), [0042](0042-account-settings-matching-layout.md), [0048](0048-per-account-storage-quota.md), [0054](0054-attachments-envelope-and-api.md), [0056](0056-local-index-recently-used-search.md), [0075](0075-session-listing-and-ending.md); Proposed [0063](0063-share-snapshot-format.md) to [0067](0067-send-style-share.md) (M5 link shares).
- Code read at `5f7b698` (V): the files cited in the Context table.
