# ADR 0018: Item-record encoding: canonical binary layout and the M1 item schema

- Status: Proposed
- Date: 2026-09-25
- Deciders: project owner
- Milestone: M1 (encoding, M1 item types) / M2, M3, M5, M7 (keys and type ids reserved here)

## Context

[ADR 0012](0012-sync-engine.md) §3 requires this ADR "before M1 freezes the formats". It must define, canonically and with vectors in [CRYPTO.md §15](../CRYPTO.md#15-testing) item 1:
- **(a)** the `ITEM_OP` data: a list of (`str` field_key, `bytes` value), sorted by field_key with no duplicates, plus a lifecycle or purge marker;
- **(b)** the `ITEM_SNAPSHOT` data: per field, the register values (dot, `u64 hlc`, `bytes` value) sorted by field_key then dot; the history in the same form; the item VV. Unknown field keys are carried verbatim, "tested from M1" (ADR 0012 §1);
- **(c)** the tombstone layout: the item id, the purge op's dot and causal context, and the `item_key_id` (ADR 0012 §5);
- **(d)** the reserved item type for vault settings, name and icon (ADR 0012 §1);
- **(e)** the `item_schema_version` registry: 1 is the M1 model, and the value versions the body encoding.

[CRYPTO.md](../CRYPTO.md) adds:
- **§8.4, §8.5.** The `data` of `ITEM_OP` and `ITEM_SNAPSHOT` is framed as `u32(data_len) ‖ data ‖ padding` (Padmé, at least 256 bytes). This ADR defines `data`. `item_schema_version` is in both headers and in the AAD.
- **§8.1.** One save of one item is one envelope, and a snapshot is one envelope. Field identity is inside the plaintext. M5 builds a share from chosen fields under the share key.
- **§2.** "Anything that is signed or used as AAD uses the fixed binary layouts in this document, never a serde-derived encoding." The item plaintext is inside the AEAD, not in the AAD, and signatures cover `SHA-256(envelope)`, not the plaintext, so the rule does not bind it literally. Determinism still matters here, for three reasons:
  - ADR 0012 §12 property 1 compares replicas "by a hash of the canonical item state";
  - §15 item 1(A) makes these bytes normative vectors, and item 8 requires byte-identical output natively, on wasm32 and through UniFFI;
  - two client versions that parse one signed body differently diverge silently. From M9 on, a vault member can craft such a body.
- **§11.10 step 7, [INV-32](../THREAT_MODEL.md#8-security-invariants).** The owner's copy of the M5 share secret lives in the item's encrypted data. **§11.15:** item TOTP secrets are item data.

ROADMAP rows:
- [§4.2](../ROADMAP.md#42-core-vault-m1), Must, M1: "Item types: Login, Secure Note, Card, Identity"; "Custom fields (text, hidden, boolean), multiple URLs per login, notes"; "Folders **or** tags (pick one for M1 — tags recommended; folders are a UI over tags)"; "TOTP secret storage"; "Password history per item"; "Trash with restore (soft delete, auto-purge after N days)".
- §4.2, Should, M3: the SSH key, API credential, Software license, Wi-Fi and Bank account types; "Favorites, recently used"; revision history; attachments.
- [§4.4](../ROADMAP.md#44-url-matching--autofill-m2), Must, M2: "Per-URI match mode". [§4.7](../ROADMAP.md#47-public-sharing-m5), Must, M5: "Choose which fields are included". [§4.10](../ROADMAP.md#410-mobile--passkeys-m7), Must, M7: "Passkey storage".

Constraints:
- **Placement.** ADR 0012 §13 puts "the op and snapshot record formats" and a merge "generic over field keys and values" in `rizzy-sync`, and "the item schema: which fields exist and how they are validated" in `rizzy-core`.
- **Dependencies.** Both are R1 crates ([ADR 0016](0016-workspace-layout.md)): no I/O, wasm32, an allow-list of external crates. A new crate must pass `cargo deny check` "with no new `ignore`, ban exception or license addition" ([CLAUDE.md](../../CLAUDE.md)), and cargo-vet covers all dependencies by M8 ([ADR 0009](0009-crypto-dependency-policy.md), owner decision 2).
- **Merge and verification.** Merge follows ADR 0012 §4–§5: multi-value registers, N = 50 history entries per field, Active wins over a concurrent trash, and a tombstone for purged items. Verification must give the same answer on every replica (§4 step 1). A parse rule that one client version applies and another does not breaks that.
- **Sizes.** An item has 5–30 fields, and a vault a few thousand items (ADR 0012). An envelope plaintext is at most 16 MiB ([CRYPTO.md §9.1](../CRYPTO.md#91-symmetric-envelope-algorithm-0x01)).

The candidate libraries, checked on 2026-09-25 with `cargo info`, the crates.io API, and their sources in `~/.cargo/registry`:

| Crate | Release | License | Facts |
|---|---|---|---|
| minicbor | 2.3.0, 2026-07-23 | BlueOak-1.0.0, every release | Not on the `deny.toml` allow-list. Its derive does not use serde. The decoder accepts indefinite-length items, and the source has no deterministic mode (absence found by grep). About 6.3k lines (V) |
| ciborium | 0.2.2, 2024-01-24 | Apache-2.0 | "serde implementation of CBOR". Its only key ordering is `CanonicalValue`, and that is the length-first order (RFC 7049 §3.9 / RFC 8949 §4.2.3), for `Value` maps only. The serde serializer does not sort. Pulls in ciborium-io, ciborium-ll, half and serde. About 5.7k lines (V) |
| cbor4ii | 1.2.3, 2026-09-07 | MIT | Low-level API, serde optional. No deterministic or strict mode (absence found by grep). About 3.9k lines (V) |
| prost | 0.14.4, 2026-06-07 | Apache-2.0 | Depends on `bytes`; codegen through prost-build (V). Decode skips unknown fields (`skip_field`) instead of keeping them (L). Protobuf documents its serialization as not canonical (L) |

## Decision

### 1. Encoding: hand-written, canonical, no new dependency

- The item record uses the primitives of [CRYPTO.md §2](../CRYPTO.md#2-conventions): fixed-width big-endian `u8`/`u16`/`u32`/`u64`, `bytes(x) = u32(len) ‖ x`, `str(x) = bytes(UTF-8(x))`, and the dot `device_id (16) ‖ u64 seq` and canonical VV of ADR 0012 §3. It is the same family as the op header, so one parsing style covers everything the M8 audit reads.
- **Not used:** serde, CBOR or protobuf, and no new crate. The codec uses only `core` and `alloc` APIs.
- **One encoding per state.** Every state has exactly one valid encoding. The parser rejects every other byte string (§5), and every serializer output must parse (property test).

### 2. Two layers

| Layer | Where | Owns | Does not interpret |
|---|---|---|---|
| Record | `rizzy-sync`, module `record` | the layouts (§3), canonical rules (§4), parsing (§5), limits (§10) | what a key means; value bytes other than `@lifecycle` |
| Schema | `rizzy-core`, module `item` | item types, field keys, value types, display rules (§6–§9) | dots, merge |

- **Flow.** `rizzy-client` validates a write through the schema layer, encodes it through the record layer and encrypts it through `rizzy-core`.
- **Secrets.** The parser borrows from the decrypted `Zeroizing<Vec<u8>>`, and owned values are zeroizing.
- **Keys are user content too.** A tag name is part of its key (§7). Keys and values never appear in logs, errors or `Debug` output. A parse error reports only a byte offset and an error kind.

### 3. Layouts (`item_schema_version` 1)

```
op data (ITEM_OP)
  u8  record_kind = 0x01
  u8  lifecycle                          0x01 Active | 0x02 Trashed | 0x03 Purge
  u16 n ‖ n × ( str(field_key) ‖ bytes(value) )           field writes, n ≤ 1,024

live snapshot data (ITEM_SNAPSHOT)
  u8  record_kind = 0x02
  u16 r ‖ r × register                   current registers, 1 ≤ r ≤ 4,096; the first is "@lifecycle"
  u16 h ‖ h × register                   history groups, h ≤ 4,096; values = history entries

tombstone data (ITEM_SNAPSHOT)
  u8  record_kind = 0x03
  dot purge_dot ‖ u64 purge_hlc
  u16 c ‖ c × ( device_id ‖ u64 seq )    the purge op's causal context, canonical VV (ADR 0012 §3)
  16  item_key_id                        key id (CRYPTO.md §4.4) of the item key current at the purge
  u16 h ‖ h × register                   late-op field writes (ADR 0012 §5), as history groups

register = str(field_key) ‖ u16 m ‖ m × ( dot ‖ u64 hlc ‖ bytes(value) )      1 ≤ m ≤ 256
dot      = device_id (16) ‖ u64 seq                                         seq ≥ 1
```

- **Op (a).**
  - Create and edit carry their writes and `Active`, because every field edit writes `Active` (ADR 0012 §5).
  - Trash is `Trashed` with no writes, restore is `Active` with no writes, and purge is `Purge` with no writes.
  - The dot, HLC and causal context are in the op header and are not repeated.
- **Lifecycle.** In snapshots, the lifecycle field is the register with the reserved key `@lifecycle`, whose values are one byte: `0x01` Active or `0x02` Trashed.
  - An op's marker is applied as a write to it. `Purge` is never a register value; it produces a tombstone.
  - Values removed from `@lifecycle` go into history like any others.
- **Snapshot (b).** Registers and history use one layout. The item VV and the item id are the snapshot header's covered VV and item id, which the AAD binds ([CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes)), and they are not repeated in `data` (open question 3).
- **Tombstone (c).**
  - It replaces the live snapshot at a purge and holds no value or history of the purged item.
  - Without late ops it is 53 + 24·c bytes.
  - Clients store it as a snapshot envelope ([ADR 0011](0011-storage.md), Clients) and keep it for the life of the vault.
- **Record kinds.** `0x04` is reserved for the M5 `SHARE_SNAPSHOT` data, so a share can never parse as an item record. The M5 ADR defines it. The recommendation is displayed values only: no dots, history or VV, because device ids and edit history are not the recipient's business. `0x00` and `0x05`–`0xFF` are invalid.

### 4. Canonical form

- **Order.** Field keys are strictly ascending bytewise, with no duplicates, in op writes, in registers and in history groups. Within a register or group, dots are strictly ascending: `device_id` bytewise, then `seq`.
- **Uniqueness.** A dot appears at most once per field key, across that field's register and history.
- **Coverage.** In a snapshot, every dot, including `purge_dot` and the late-op dots, is covered by the header's covered VV.
- **Registers are never dropped,** even when they hold only a cleared value (§6). Dropping one changes how a later concurrent write merges, and replicas would diverge.
- **Equal states give equal bytes.** The ADR 0012 §12 state hash is `SHA-256(u16 item_schema_version ‖ covered VV ‖ data)`. It is for tests only; a user-visible vault fingerprint ([THREAT_MODEL §5.6](../THREAT_MODEL.md#56-rollback-withholding-and-forks), Should) needs its own ADR.

### 5. Parsing

- **Shape.** `parse(&[u8]) -> Result<RecordRef<'_>, RecordError>`. It never panics, and it never allocates in proportion to a count or length before checking `count × minimum size ≤ remaining input` ([CRYPTO.md §9.5](../CRYPTO.md#95-parsing-and-allow-list-rules) rule 5).
- **What is rejected.** The whole op or snapshot is rejected and reported, as for a failed decryption (ADR 0012 §4 step 1), when:
  1. the record kind is not allowed for the purpose: `0x01` for `ITEM_OP`, `0x02` or `0x03` for `ITEM_SNAPSHOT`;
  2. a count or length exceeds §10, or runs past the end, or bytes follow the last element;
  3. a key breaks the §7 grammar, or the order and uniqueness rules of §4;
  4. `lifecycle` is outside `0x01`–`0x03`, or writes come with `Trashed` or `Purge`;
  5. a live snapshot does not start with `@lifecycle`, a `@lifecycle` value is not the single byte `0x01` or `0x02`, `@lifecycle` appears in an op or a tombstone, or a register has no values;
  6. a dot has `seq` 0, or is not covered as §4 requires.
- **Values are not checked here.** Apart from `@lifecycle`, the record layer never inspects value bytes. Value checks are the schema layer's, and they never reject a record (§6).
- **Frozen rules.** These rules and the §10 limits are frozen with the version-1 vectors. Any change is a new `item_schema_version` (§11); otherwise two client versions would accept different ops.

### 6. Values

A value is either empty, or `u8 value_type ‖ payload`:

| Type | Id | Payload |
|---|---|---|
| Cleared | – (0 bytes) | The field has no value. Removing a list element writes this to each attribute of the element that the writer holds |
| Text | `0x01` | UTF-8 as entered, not normalised, so a stored site password round-trips. Tag names are the exception (§7) |
| Bytes | `0x02` | raw |
| Bool | `0x03` | one byte, `0x00` or `0x01` |
| U64 | `0x04` | `u64`, for example Unix milliseconds |
| Enum | `0x05` | `u16` |
| SortKey | `0x06` | 1–64 bytes, last byte ≠ `0x00`. Ordered bytewise |
| Reserved | `0x00`, `0x07`–`0xFF` | new value types need no version bump |

- **Invalid values never reject an op.** That covers an unknown type, a type the key does not expect, and a malformed payload such as bad UTF-8 or a Bool of `0x02`.
  - The value is kept, merged and snapshotted verbatim, and shown as "unsupported value".
  - Rejecting it would make replicas that run different schema versions diverge.
- **Display** follows ADR 0012 §4 step 5, with two refinements. They change presentation only, never the merge or the converged state:
  - byte-identical concurrent values count as one value, not a conflict;
  - a cleared value never displays over a concurrent non-empty one. The edit shows, with "cleared on X while edited on Y", the field-level counterpart of "Active wins" (open question 4).
- **List elements.** An element exists while one of its content attributes displays a non-empty value; for `tag/<hex>`, the key itself is the content attribute. `order`, `match` and `kind` are layout attributes and never make an element exist.
- **List order.** A list sorts by `order`, then by element id. Elements without `order` sort last. `rizzy-core` generates a key strictly between two neighbours. When none fits in 64 bytes, it rewrites that list's `order` keys in one op.

### 7. Field keys

Keys are ASCII, 1–160 bytes, and follow this grammar (RFC 5234 ABNF):

```
field_key = fixed / element
fixed     = name 1*( "." name )               ; login.password
element   = name "/" elem [ "/" name ]         ; uri/<id>/value, tag/<hex>
name      = %x61-7A *( %x61-7A / DIGIT / "_" ) ; at most 32 bytes
elem      = 2*128( DIGIT / %x61-66 )           ; even count; a random 16-byte id is exactly 32
```

`@lifecycle` is the only other key, and it is used by the record layer only.

| Key | Value | Types | Notes |
|---|---|---|---|
| `item.type` | Enum | all | Written by the create op only, and never changed: converting an item is a new item. An item without a valid type shows as unsupported |
| `item.name`, `item.notes` | Text | all | Title and notes. The notes are a Secure Note's body. Conflicts are whole-field; there is no text merge (ADR 0012, owner decision 4) |
| `item.favorite` | Bool | all | Absent means false. Stored from M1; the UI comes in M3 |
| `import.created_ms` | U64 | all | Written by importers only. Shown as "created" instead of the HLC time |
| `field/<id>/label` · `/kind` · `/value` · `/order` | Text · Enum · Text or Bool · SortKey | all | Custom fields. `kind`: 1 text, 2 hidden, 3 boolean (whose value is a Bool). An unknown kind displays as hidden |
| `tag/<hex>` | Bool `0x01` | all | One tag. `<hex>` is the lowercase hex of UTF-8(NFC(name)); a name is 1–64 bytes with no control characters. Keying by name makes concurrent adds of one tag one register. Folders are a UI over `/` in names |
| `share/<share_id>/secret` | Bytes, 32 | all | M5: the owner's copy of the share secret. `<share_id>` is the share's 16-byte id. Cleared on revoke. The M5 ADR may add attributes |
| `login.username`, `login.password` | Text | Login | The history of `login.password` is the password history (ADR 0012 §5) |
| `login.totp` | Text | Login | An otpauth URI or a Base32 secret, as entered, parsed when a code is shown ([CRYPTO.md §11.15](../CRYPTO.md#1115-totp-m1)) |
| `uri/<id>/value` · `/match` · `/order` | Text · Enum · SortKey | Login | `value` is the URL as entered; M2 normalises it only when matching. `match` is reserved for M2: absent means the account default, and the M2 ADR assigns its values. M1 clients carry it and never write it (open question 2) |
| `pwhist/<id>/value` · `/ms` | Text · U64 | Login | Password history imported from another manager |
| `card.holder`, `.number`, `.brand`, `.exp_month`, `.exp_year`, `.code`, `.pin` | Text | Card | Stored as entered or imported; the UI validates |
| `identity.title`, `.first_name`, `.middle_name`, `.last_name`, `.company`, `.email`, `.phone`, `.username`, `.address1`, `.address2`, `.address3`, `.city`, `.state`, `.postal_code`, `.country`, `.ssn`, `.passport_number`, `.drivers_license` | Text | Identity | |
| `vault.name`, `vault.icon` | Text | Vault settings | `icon` is an identifier from the client's icon set |

- **Concealed by default,** and left out of an M5 share unless chosen: `login.password`, `login.totp`, `card.number`, `card.code`, `card.pin`, `identity.ssn`, `identity.passport_number`, hidden custom fields and `share/…`.
- **Reserved prefixes:** `ssh.`, `api.`, `license.`, `wifi.` and `bank.` (M3 types); `passkey.` and `passkey/` (M7); `attachment/` (M3 attachments ADR); further `share/` attributes (M5). A new key needs a line in the ADR that ships it, never a version bump.
- **Not item data:** "recently used", last-autofill times and usage counts. Each would be a signed op whose timing the server sees (ADR 0012 §11), so they stay on the device (the M3 local index).

### 8. Item types (d)

| Id | Type | Milestone |
|---|---|---|
| `0x0000` | invalid | – |
| `0x0001` / `0x0002` / `0x0003` / `0x0004` | Login / Secure Note / Card / Identity | M1 |
| `0x0005` / `0x0006` / `0x0007` / `0x0008` / `0x0009` | SSH key / API credential / Software license / Wi-Fi / Bank account | M3, reserved |
| `0x000A` | Passkey, standalone | M7, reserved (open question 6) |
| `0x000B`–`0xEFFF` | unassigned; each needs an ADR line | – |
| `0xF001` | **Vault settings** (system type) | M1 |
| `0xF000`, `0xF002`–`0xFFFF` | reserved for system types | – |

- **Unknown type.** An item of an unknown type shows as "Unsupported item, update rizzy-vault". Trash, restore and purge work; field edits are not offered.
- **Vault settings** (ADR 0012 §1). The settings item is an ordinary item with a random id and type `0xF001`.
  - **Creation.** The device that creates a vault writes it in the same upload as the vault's self-grant.
  - **Which item counts.** The one with the lowest item id among non-tombstoned items of that type. Clients create another only when a complete sync finds none.
  - **Visibility.** It is never listed, searched, exported as an item, shared or trashed. If a faulty client trashes it, it stays in effect; if one purges it, the vault settings reset to defaults.
  - **Why not a derived id.** An id derived from `vault_id` breaks [CRYPTO.md §2](../CRYPTO.md#2-conventions), under which object ids are random, and it would tell the server which item holds the settings.

### 9. Times, trash and purge, from the HLC

- **Created:** `hlc >> 16` (Unix milliseconds) of the lowest HLC among the values of the `item.type` register, unless `import.created_ms` is set.
- **Modified:** the highest `hlc >> 16` among the current values of every register except `@lifecycle`.
- **Trashed at:** the highest HLC among the `Trashed` values, while `@lifecycle` displays Trashed. The retention period of ADR 0012 §5 (30 days) runs from it.
- **No wall-clock field is written.** The HLC is the only time source, so every replica derives the same times.

### 10. Size limits

| Limit | Value |
|---|---|
| One value | ≤ 65,536 bytes, type byte included |
| Field key | 1–160 bytes |
| Writes per op | ≤ 1,024 |
| Op data | ≤ 1 MiB, checked before decoding |
| Registers, and history groups, per snapshot | ≤ 4,096 each |
| Values per register or history group | ≤ 256 (the merge keeps ≤ 50 history entries per field) |
| Snapshot data | ≤ 12 MiB, so the Padmé-padded plaintext stays under CRYPTO.md §9.1's 16 MiB |

- **Writers check the same limits** before encrypting.
- **A merged state can still outgrow a snapshot,** through concurrent writes or 50 history entries per large field. The client then writes no snapshot. The ops stay, so nothing is compacted and nothing is lost. The client flags the item and offers "duplicate as a new item", which starts a fresh history.

### 11. Forward compatibility and `item_schema_version` (e)

- **Unknown field keys** that fit the grammar are merged, snapshotted and exported byte for byte. An edit writes only the keys the user changed. Tested from M1 with a simulated newer client.
- **No version bump is needed** for new value types, enum values, list names, keys or item types.

| `item_schema_version` | Meaning |
|---|---|
| 0 | invalid, rejected |
| 1 | M1: this ADR |
| 2–`0xFFFE` | unassigned. Each needs an ADR, including the rule for when writers start using it |
| `0xFFFF` | reserved |

- **What needs a new version:** any change to §3–§5 or §10. `data` carries no second version number.
- **Reader rule.** A record with an unknown version is neither applied nor dropped. The client keeps it and reports "update required". Causal delivery waits for it (ADR 0012 §4 step 2), so later ops of that device in that vault wait too. A version bump is therefore a forced client update ([ADR 0002](0002-own-protocol.md) point 5).

### 12. Tests

- **Normative vectors** ([CRYPTO.md §15](../CRYPTO.md#15-testing) item 1(A)), through real `ITEM_OP` and `ITEM_SNAPSHOT` envelopes with the fixed-nonce hook: a create of each M1 type; a list edit; trash, restore and purge; a live snapshot with a two-value conflict, history and an unknown key; a tombstone with a late op; each value type.
- **Negative vectors:** one per rejection rule in §5.
- **Property tests:** encode → parse → encode is the identity; reordering, duplication and truncation are rejected, never a panic; unknown keys and values are carried through; the ADR 0012 §12 convergence property compares the §4 state hash.
- **Fuzz targets,** in the scheduled job (ADR 0009, owner decision 4): op data, snapshot data, tombstone, the value decoder and the key grammar. Once this ADR is accepted, CRYPTO.md §15 item 7 lists them, and §8.4 "Op and snapshot plaintexts" links here.
- **Cross-platform byte equality:** CRYPTO.md §15 item 8.

## Consequences

### Positive

- One encoding style for headers and bodies. Nothing is added to the R1 allow-lists, `deny.toml` or the cargo-vet scope.
- Each state has exactly one encoding, so convergence tests compare hashes and vectors are byte-exact on every platform.
- The merge stays generic. The schema grows by keys and type ids without a version bump, and older clients carry newer data verbatim.
- A value that fails validation cannot split replicas.
- The share secret, match modes, passkeys and the M3 types already have a place, so M2–M7 add keys, not formats.

### Negative

- We own a parser for untrusted plaintext; from M9, a vault member is the author. It is fuzzed and in the M8 audit. Our estimate is under 1,000 lines for both layers, without tests (U).
- There is no off-the-shelf debugging tooling, such as CBOR diagnostic notation. A test helper dumps records instead.
- String keys cost 12–60 bytes each, against 1–2 for integer tags. Padmé hides most of the difference.
- Registers of removed list elements, and their history, are never collected, like tombstones. An item whose URIs change often grows toward §10; "duplicate as a new item" is the way out.
- Renaming a tag writes one op per tagged item.
- A version bump forces every client to update.

### Risks

- **A parser bug that rejects valid records stalls a device's chain on every replica.** Vectors and fuzzing are the defence. A rejection is reported, never skipped.
- **The frozen limits could be too small,** for example for Markdown notes in M3. Raising one is a version bump. The signal: users hitting the 64 KiB value limit.
- **Tag keys depend on NFC.** A normalisation-table change could split one tag into two keys, the same concern as on the password path (`unicode-normalization` is pinned, ADR 0009).
- **Favorites are per item,** so in an M9 shared vault a favorite is every member's. M9 may move favorites to per-user settings.
- **Where the per-URI match mode lives** is still open (open question 2).

## Alternatives considered

- **Deterministic CBOR (RFC 8949 §4.2.1) with minicbor.** A careful no_std codec whose derive does not use serde. It lost on four points:
  - its BlueOak-1.0.0 license would need an owner-approved license addition;
  - its decoder accepts non-deterministic input, so we would write the canonical checks, or decode, re-encode and compare, anyway;
  - it adds about 6k third-party lines to the plaintext audit scope;
  - CBOR's type system offers nothing our (key, bytes) records use.

  [ADR 0007](0007-ciphertext-envelope.md) rejected COSE partly for the same CBOR parser surface.
- **CBOR with ciborium.** It is serde-based, which CRYPTO.md §2 excludes for signed data, and the same stability argument applies here. Its serializer does not sort, and its canonical helper uses length-first order rather than the bytewise order of §4.2.1 (L). Its last release was in January 2024.
- **CBOR with cbor4ii.** MIT and active, but it has no strict mode either, so we would still write the rules, and gain little.
- **Protobuf with prost.** Its serialization is not canonical (L), and prost drops unknown fields (L), which ADR 0012 §1 forbids. proto3 omits default values, so an absent field and a zero field look the same. It also needs codegen and the `bytes` crate.
- **serde formats (bincode, postcard, JSON).** A serde representation can change with a crate update (CRYPTO.md §2). JSON has no canonical form without JCS, and number and escape forms are ambiguous.
- **Integer field ids instead of string keys.** Smaller. But ADR 0012 §3 fixes `str` keys, list elements need a structured key anyway, and unknown fields would show up as anonymous numbers in exports.
- **Random tag ids with a tag registry.** This allows renaming a tag in one op, and tag colours. But the same tag added on two devices becomes two tags, and the registry is one more object to sync. It can be revisited in M3.

## Open questions for the owner

1. **The encoding.** Should it be the hand-written layout, or deterministic CBOR (minicbor with a BlueOak-1.0.0 license addition, or cbor4ii)? *Recommendation:* hand-written (§1). It adds no dependency, and it is the same style as the op header.
2. **Per-URI match mode.** ADR 0012 §1 names `uri/<id>/match` as an item field. CRYPTO.md §8.4 and [INV-14](../THREAT_MODEL.md#8-security-invariants) list "per-URI match modes" among the settings that live in `ACCOUNT_SETTINGS` or the signed `account-state`. This is an invariant-level conflict, so this ADR only reserves the key. *Recommendation:* keep the mode in item data, and amend INV-14 and §8.4 to name account-level match defaults, equivalence groups and autofill rules. Item ops are encrypted, never visible to the server, device-signed (INV-22), rollback-checked (INV-25) and gap-checked (INV-27). Decide before M2.
3. **The item VV and item id are not repeated in `data`.** ADR 0012 §3 lists the item VV in the snapshot data, and §5 lists the item id in the tombstone. Both are already in the snapshot header, and the AAD binds them. *Recommendation:* carry them only there, so the two copies can never disagree. The alternative is to repeat them and check that they are equal.
4. **Cleared value against a concurrent edit.** *Recommendation:* the edit displays, marked as a conflict, as "Active wins" already does for items (§6). The merge and the converged state do not change.
5. **Limits.** 64 KiB per value, 1 MiB per op, 12 MiB per snapshot, 1,024 writes per op and 4,096 registers. *Recommendation:* accept them, and revisit with M3 data. Attachments will take large content out of fields.
6. **Passkeys.** Reserve both a standalone type (`0x000A`) and a `passkey/` list on Login? *Recommendation:* yes. The M7 passkey ADR uses one and releases the other.
7. **Tags keyed by name.** *Recommendation:* yes for M1, so that concurrent adds of a tag merge. A tag registry for colours or one-op renames is an M3 decision.

## References

- [ROADMAP](../ROADMAP.md) §4.2, §4.4, §4.7, §4.10
- [THREAT_MODEL](../THREAT_MODEL.md) §5.6, INV-13, INV-14, INV-22 to INV-27, INV-32
- [CRYPTO.md](../CRYPTO.md) §2, §4.4, §8.1, §8.4, §8.5, §9.1, §9.5, §11.10, §11.15, §15
- [ADR 0002](0002-own-protocol.md), [ADR 0007](0007-ciphertext-envelope.md), [ADR 0009](0009-crypto-dependency-policy.md), [ADR 0011](0011-storage.md), [ADR 0012](0012-sync-engine.md), [ADR 0013](0013-shared-client-core.md), [ADR 0016](0016-workspace-layout.md); `deny.toml` (license allow-list)
- `cargo info` and the crates.io API, 2026-09-25: minicbor 2.3.0, ciborium 0.2.2, cbor4ii 1.2.3, prost 0.14.4 (versions, dates, licenses, dependencies; V)
- Sources read: `minicbor-2.3.0/src/decode/decoder.rs`, `ciborium-0.2.2/src/value/canonical.rs`, `prost-0.14.4/src/encoding.rs`, plus greps of each crate for canonical or deterministic modes (V for what was read; absence claims are grep-based)
- RFC 8949 §4.2.1 and §4.2.3, deterministic and length-first CBOR (L, not re-read for this ADR); RFC 7049 §3.9 (L); RFC 5234, ABNF
- Protocol Buffers documentation, "serialization is not canonical" (L)
