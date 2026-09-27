# ADR 0018: Item-record encoding: canonical binary layout and the M1 item schema

- Status: Accepted
- Date: 2026-09-27
- Deciders: project owner
- Milestone: M1 (encoding, M1 item types) / M2, M3, M5, M7 (keys and type ids reserved here)
- Supersedes: [ADR 0012](0012-sync-engine.md) in part (§1, §3, §4, §5, §6, §7, §12), on acceptance and once [ADR 0020](0020-partial-supersession.md) is Accepted. On acceptance item 1 names the parts.

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
- **One encoding per state.** Every state has exactly one valid encoding. The parser rejects every other byte string (§5), and every serializer output within the §10 limits must parse (property test).

### 2. Two layers

| Layer | Where | Owns | Does not interpret |
|---|---|---|---|
| Record | `rizzy-sync`, module `record` | the layouts (§3), canonical rules (§4), parsing (§5), limits (§10) | what a key means; value bytes other than `@lifecycle` |
| Schema | `rizzy-core`, module `item` | item types, field keys, value types, display rules (§6–§9) | dots, merge |

- **Flow.** `rizzy-client` validates a write through the schema layer, encodes it through the record layer and encrypts it through `rizzy-core`.
- **Secrets.** The parser borrows from the decrypted `Zeroizing<Vec<u8>>`, and owned values are zeroizing.
- **Keys are user content too.** A tag name is part of its key (§7). Keys and values never appear in logs, errors or `Debug` output. A parse error reports only a byte offset and an error kind, both local diagnostics outside the frozen format.

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
  dot purge_dot ‖ u64 purge_hlc          the recorded purge (Tombstone, below)
  u16 c ‖ c × ( device_id ‖ u64 seq )    join of the applied purges' contexts, canonical VV (ADR 0012 §3)
  16  item_key_id                        key_id in the recorded purge's ITEM_OP envelope header
  u16 l ‖ l × register                   late registers (Tombstone, below), l ≤ 4,096

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
- **Snapshot (b).** Registers and history use one layout. The item VV and the item id are the snapshot header's covered VV and item id, which the AAD binds ([CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes)), and they are not repeated in `data` (owner decision 3).
- **History.** On a live item, every value removed from a register goes into the item's history, with its dot and HLC (ADR 0012 §5). A tombstone keeps no history: the first Purge discards the live item's history, and a late value that a later write removes, or that `c` covers, is dropped (owner decision 9).
- **Tombstone (c)** (owner decisions 3, 8 and 9). A purge replaces the item's state with a tombstone when the first Purge is applied. The item id is the snapshot header's. The tombstone holds no value or history of the purged item, only late values.
  - **Size and life.** With l = 0 its `data` is 53 + 24·c bytes, the `u16 l` included. Clients store it as a snapshot envelope ([ADR 0011](0011-storage.md), Clients) and keep it for the life of the vault.
  - **A Purge is never rejected.** "A `Purge` op is allowed only on trashed items" (ADR 0012 §5) binds the writer. A receiver applies every Purge that passes §5, to a live item or a tombstone, whatever `@lifecycle` displays, because verification depends only on the op and the signed account state (ADR 0012 §4 step 1).
  - **Recorded purge.** Of all applied Purge ops of the item, the one with the highest (`hlc`, `device_id`, `seq`): `hlc` numerically, then `device_id` bytewise, then `seq` numerically. `purge_dot` and `purge_hlc` are its dot and HLC. `item_key_id` is the `key_id` in its `ITEM_OP` envelope header ([CRYPTO.md §9.1](../CRYPTO.md#91-symmetric-envelope-algorithm-0x01)), never a key the replica picks from its own view of the wrap set. By the CRYPTO.md §11.6 reader rule, that `key_id` names an item key from the item's wraps, and every replica records the same one.
  - **Context.** `c` is the canonical join of the causal contexts of all applied Purge ops: per `device_id`, the highest `seq` in any of them.
  - **Late values.** Take the multi-value registers that ADR 0012 §4 step 4 builds from every applied op other than a Purge, whether applied before or after a purge. A current value in them is *late* when its key is not `@lifecycle` and `c` does not cover its dot. The late registers hold exactly the late values, one register per key that has any. So a late value stays unless a later write of the same key superseded it or `c` covers it. There is no pruning; §10 bounds a late register like a register.
  - **Applying.** Every applied op that is not a duplicate (ADR 0012 §4 step 3) adds its dot to the covered VV.
    1. The first Purge applied to a live item keeps the late values of its current registers and discards everything else.
    2. A Purge applied to a tombstone joins its context into `c`, becomes the recorded purge if it is now the highest, and removes every late value that the new `c` covers.
    3. Any other op applied to a tombstone is never rejected and never resurrects the item, whether it is concurrent with a purge or its context covers `purge_dot`. For each key it writes, it removes the late values its context covers (ADR 0012 §4 step 4.1) and adds its own value. Its lifecycle byte writes nothing, so a late Trash or Restore only advances the covered VV.
  - **Why the arrival order does not matter.** The recorded purge is a maximum and `c` is a join, so both depend only on the set of applied purges. The late registers are ADR 0012 §4's multi-value registers, which do not depend on delivery order, filtered by `c`. The filter commutes with each step. A new op's dot lies outside the covered VV, which covers every applied purge's context (causal delivery, ADR 0012 §4 step 2), so `c` never covers the value the op adds. A larger `c` only removes more. Example: device L writes E1, then E2 over it, to `login.password`, both concurrent with purge P. In the orders E1 E2 P, P E1 E2 and E1 P E2 the late register is {E2}.
  - **Surfacing** is local presentation and changes no bytes. A device shows this notice once for late values it has not yet surfaced: "An edit from Laptop arrived for an item you deleted permanently. Restore it as a new item?" Restoring creates a new item, of a type the user confirms, from the displayed values of the late registers (§6).
- **Absorbing a snapshot** (Settled by the merge spike, item 1). A replica absorbs a verified snapshot under "Snapshots are claims", which on every honest state gives the join of the two, either side live or a tombstone: the state it would reach by applying, as ADR 0012 §4 and "Applying" define, every op that either state covers. The covered VV becomes the entrywise maximum, and a snapshot whose covered VV the replica's covers changes nothing. Absorbing is a receipt under ADR 0012 §2: the clock receives the highest HLC among the snapshot's values, history entries and `purge_hlc`, under the skew guard. The merged snapshot that follows is §10 "No snapshot" (owner decision 13).
- **Snapshots are claims** (owner decision 14). A snapshot is its author's signed claim, never a substitute for the op bodies it covers, and in Server-mode sync a replica absorbs one only as the cover of a bodiless header (ADR 0021 §4); ADR 0012's snapshot-only M4 transfers are left to the M4 ADR (owner decision 16). It cuts the covered VV to the op headers it has verified, ignores values above the cut or whose HLC is not their header's, and reports the cut. A key's current values are those that no other held value's verified header context covers. The replica refuses and reports a snapshot that contradicts an op body it holds or received with it, reports any other disagreement between sources, and writes no snapshot of the item while one is unresolved. One dot carried in two versions keeps the version whose HLC is the verified header's, then the lower (`hlc`, value); on one purge dot, the `item_key_id` in the wrap set first. Each dot's verified header, and which dots a replica merged from bodies, are local state, not frozen.
  - **Covered ops** (the text that replaces ADR 0012 §4 step 3). If the item VV already covers an op's dot, the op body still merges; a body already merged changes nothing.
- **Re-issued ops** (owner decision 15). An op re-issued after a stale-epoch rejection (ADR 0012 §7 "Upload") keeps `device_seq`, `vault_prev_seq`, `hlc`, the causal context and the op data; only `vault_key_epoch`, the item key the CRYPTO.md §11.6 writer rule picks (so the envelope's `key_id`), the carried wrap and the signature change. The first op under a fresh item key carries its wrap, a re-issued one too, and a later unsent op under that key drops it. The author holds the re-issued op in place of the original, so a re-issued recorded purge gives `item_key_id` = the re-issued `key_id`, and it discards every unsent snapshot that covers the op and writes the writer rule's snapshot. Which ops are re-issued, and the server's answer to a re-upload, are ADR 0021's (open question 9).
- **Record kinds.** `0x04` is reserved for the M5 `SHARE_SNAPSHOT` data, so a share can never parse as an item record. The M5 ADR defines it. The recommendation is displayed values only: no dots, history or VV, because device ids and edit history are not the recipient's business. `0x00` and `0x05`–`0xFF` are invalid.

### 4. Canonical form

- **Order.** Field keys are strictly ascending by their raw ASCII bytes, compared without the `u32` length prefix of `str()`, a proper prefix first, with no duplicates, in op writes, registers, history groups and late registers. So `login.password` < `login.totp` < `login.username`, and `tag/61` < `tag/6162`. Within a register or group, dots are strictly ascending: `device_id` bytewise, then `seq`. The entries of `c` are strictly ascending by `device_id`, with no duplicates (ADR 0012 §3).
- **Uniqueness.** A dot appears at most once per field key, across that field's register and history.
- **History groups.** A field has at most one history group, and only while it has a history entry. In a live snapshot, every history group's key is also the key of a current register. A tombstone has no history groups.
- **Coverage.** In a snapshot, every dot, `purge_dot` and the late values' dots included, and every entry of `c`, is covered by the header's covered VV. In a tombstone, `c` covers no late value's dot.
- **Registers are never dropped** from a live snapshot, even when they hold only a cleared value (§6). Dropping one changes how a later concurrent write merges, and replicas would diverge. In a tombstone, a key without late values has no register.
- **Equal states give equal bytes.** The ADR 0012 §12 state hash is `SHA-256(u16 item_schema_version ‖ covered VV ‖ data)`, with `data` unframed and encoded without the §10 limits, so an oversize state (§10) has one too. It is for tests only; a user-visible vault fingerprint ([THREAT_MODEL §5.6](../THREAT_MODEL.md#56-rollback-withholding-and-forks), Should) needs its own ADR.

### 5. Parsing

- **Shape.** Two entry points: `parse_op(data)` for `ITEM_OP` and `parse_snapshot(covered_vv, data)` for `ITEM_SNAPSHOT`, each returning `Result<RecordRef<'_>, RecordError>`.
  - The names are illustrative. What is frozen is that every rule below runs, with these inputs, on every path that yields a record: sync, a load from the local store and the M4 transfers.
  - `data` is the CRYPTO.md §8.5 `data` with the frame removed. It carries no version and no purpose. The caller has already verified the envelope and header, and only `item_schema_version` 1 reaches the parser (§11).
  - The purpose selects the entry point, for rule 1. `covered_vv` is the snapshot header's covered VV, for rule 6.
  - It never panics, and it never allocates in proportion to a count or length before checking `count × minimum size ≤ remaining input` ([CRYPTO.md §9.5](../CRYPTO.md#95-parsing-and-allow-list-rules) rule 5).
- **What is rejected.** The whole op or snapshot is rejected and reported, as for a failed decryption (ADR 0012 §4 step 1), when, and only when:
  1. the record kind is not allowed for the purpose: `0x01` for `ITEM_OP`, `0x02` or `0x03` for `ITEM_SNAPSHOT`;
  2. a count or length exceeds §10, or runs past the end, or bytes follow the last element;
  3. a key breaks the §7 grammar, or the record breaks a §4 order or uniqueness rule;
  4. `lifecycle` is outside `0x01`–`0x03`, or writes come with `Trashed` or `Purge`;
  5. a live snapshot does not start with `@lifecycle`, a `@lifecycle` value is not the single byte `0x01` or `0x02`, `@lifecycle` appears in an op or a tombstone, or any `register` production (current register, history group or late register) has m = 0;
  6. a dot or an entry of `c` has `seq` 0, or is not covered as §4 requires;
  7. a live snapshot has a history group whose key is not the key of one of its current registers;
  8. a tombstone has a late value whose dot `c` covers.
- **Nothing else rejects a version-1 record,** and no layer normalises one; only absorption (§3, "Snapshots are claims", owner decision 14) refuses a verified snapshot or takes part of one. These parse and are carried verbatim, although no honest merge produces most of them: several current values from one `device_id` in one register (reachable through a faulty context); one dot with different HLCs under different keys; a `purge_dot` that `c` covers; a late value whose dot is `purge_dot`; an `item_key_id` that names no key the reader holds.
- **Values are not checked here.** Apart from `@lifecycle`, the record layer never inspects value bytes. Value checks are the schema layer's, and they never reject a record (§6).
- **Frozen rules.** These rules, the §3 layouts with the rules that give them meaning (Surfacing excepted), the §4 canonical rules and the §10 limits are frozen with the version-1 vectors. Any change is a new `item_schema_version` (§11); otherwise two client versions would accept different ops or reach different states.

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

- **Empty and non-empty.** *Empty* means the zero-length Cleared value only. Every value of one byte or more is non-empty, including a Text with an empty payload and every unsupported or malformed value. Writers write Cleared, never an empty Text, when the user empties a field, and a create op writes no field the user left blank.
- **Invalid values never reject an op.** That covers an unknown type, a type the key does not expect, and a malformed payload such as bad UTF-8 or a Bool of `0x02`.
  - The value is kept, merged and snapshotted verbatim, and shown as "unsupported value".
  - Rejecting it would make replicas that run different schema versions diverge.
- **Display** restates ADR 0012 §4 step 5 with three refinements: byte-identical values count as one, a cleared value never displays over a concurrent non-empty one, and `seq` breaks ties. They change presentation only, never the merge or the converged state (owner decision 4).
  - A field holds one value, or several if writes were concurrent. Byte-identical concurrent values count as one value, not a conflict.
  - The **displayed** value is the one with the highest (`hlc`, `device_id`, `seq`), the order ADR 0012 §5 uses for pruning; `seq` breaks the tie that two current values of one device can reach after a faulty context.
  - A cleared value never displays over a concurrent non-empty one. The non-empty value highest in that order displays, with "cleared on X while edited on Y", the field-level counterpart of "Active wins".
  - The other values stay in the register, and the UI marks the field as conflicting ([ROADMAP §4.6](../ROADMAP.md#46-sync-modes-m4), Should: "keep both / pick one"). Picking a value, or any new edit of the field, writes a value whose context covers all of them. That resolves the conflict.
- **List elements.** An element exists while one of its content attributes displays a non-empty value; for `tag/<hex>`, the key itself is the content attribute. `order`, `match` and `kind` are layout attributes and never make an element exist.
- **List order.** A list sorts by `order`, then by element id. Elements without `order` sort last. `rizzy-core` generates a key strictly between two neighbours. When none fits in 64 bytes, it rewrites that list's `order` keys in one op, or in consecutive ops if one would break §10.

### 7. Field keys

Keys are ASCII and follow this grammar (RFC 5234 ABNF):

```
field_key = fixed / element
fixed     = name 1*( "." name )                    ; login.password
element   = name "/" elem [ "/" name ]              ; uri/<id>/value, tag/<hex>
name      = %x61-7A *31( %x61-7A / DIGIT / "_" )    ; 1-32 bytes
elem      = 1*64( 2hexlc )                          ; a random 16-byte id is 32 digits
hexlc     = DIGIT / %x61-66
```

- **The length rules are in the productions,** not in comments: a `name` is 1–32 bytes, and an `elem` is an even number of lowercase hex digits, from 2 to 128.
- **A key is also 1–160 bytes** (§10), a separate check (§5 rule 2), since the grammar alone allows longer keys.
- **`@lifecycle`** is the only other key, and it is used by the record layer only.

| Key | Value | Types | Notes |
|---|---|---|---|
| `item.type` | Enum | all | Written by the create op only, and never changed: converting an item is a new item. An item without a valid type shows as unsupported |
| `item.name`, `item.notes` | Text | all | Title and notes. The notes are a Secure Note's body. Conflicts are whole-field; there is no text merge (ADR 0012, owner decision 4) |
| `item.favorite` | Bool | all | Absent means false. Stored from M1; the UI comes in M3 |
| `import.created_ms` | U64 | all | Written by importers only. Shown as "created" instead of the HLC time |
| `field/<id>/label` · `/kind` · `/value` · `/order` | Text · Enum · Text or Bool · SortKey | all | Custom fields. `kind`: 1 text, 2 hidden, 3 boolean (whose value is a Bool). An unknown kind displays as hidden |
| `tag/<hex>` | Bool `0x01` | all | One tag. `<hex>` is the lowercase hex of UTF-8(NFC(name)), which is 1–64 bytes after NFC and contains no code point of general category Cc. Writers write Bool `0x01` to add a tag and Cleared to remove it. Keying by name makes concurrent adds of one tag one register. Folders are a UI over `/` in names |
| `share/<share_id>/secret` | Bytes, 32 | all | M5: the owner's copy of the share secret. `<share_id>` is the share's 16-byte id. Cleared on revoke. The M5 ADR may add attributes |
| `login.username`, `login.password` | Text | Login | The history of `login.password` is the password history (ADR 0012 §5) |
| `login.totp` | Text | Login | An otpauth URI or a Base32 secret, as entered, parsed when a code is shown ([CRYPTO.md §11.15](../CRYPTO.md#1115-totp-m1)) |
| `uri/<id>/value` · `/match` · `/order` | Text · Enum · SortKey | Login | `value` is the URL as entered; M2 normalises it only when matching. `match` is reserved for M2: absent means the account default, and the M2 ADR assigns its values. M1 clients carry it and never write it (owner decision 2) |
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
| `0x000A` | Passkey, standalone | M7, reserved (owner decision 6) |
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
| Registers, history groups and late registers, per snapshot | ≤ 4,096 each |
| Values per register, history group or late register | ≤ 256 (the merge keeps ≤ 50 history entries per field) |
| Snapshot data | ≤ 12 MiB, so the Padmé-padded plaintext stays under CRYPTO.md §9.1's 16 MiB |

- **Writers check the same limits,** and the §7 grammar on each final key, before encrypting.
- **Oversize items.** An item is *oversize* while the §3–§4 encoding of its merged state breaks a §10 limit, through concurrent writes, registers that are never collected, or 50 history entries per large field. Replicas with the same state agree on it.
  - **No snapshot.** A client writes a snapshot of an item after more than 32 ops on it since its last snapshot, after the first write under a fresh item key (the writer rule in CRYPTO.md §11.6), after a purge, or, once the response's ops are applied, after a Fetch in which it absorbed a snapshot whose covered VV is concurrent with its own (owner decision 13), unless the item is oversize or has an unresolved disagreement (§3, "Snapshots are claims"). Clients keep an oversize item's ops (ADR 0012 §6), so nothing is compacted and nothing is lost. Snapshots resume once the state fits again.
  - **Newest snapshot** (owner decision 13; the text that replaces ADR 0012 §6's last bullet). Clients keep each item's ops since its newest snapshot, which makes the ADR 0012 §6 recomputation possible. After a Fetch in which a client absorbed a snapshot whose covered VV is concurrent with its own, until it writes the merged snapshot that "No snapshot" requires, and for good for an oversize item, its newest snapshot is the pair of its previous one and the absorbed one, and it keeps the ops neither covers.
  - **The way out.** The client flags the item and offers "duplicate as a new item": a create op, then edit ops as needed, each within §10, which start a fresh history.
  - **Flows that need a snapshot of every item** (owner decision 12). For an oversize item, the CRYPTO.md §11.6 writer rule writes the op and its new wrap without the snapshot (On acceptance item 5), and restore healing (ADR 0012 §7) sends no fresh snapshot (ADR 0021 open question 4). ADR 0012 §9 pairing and stale re-sync and §10 On-device → Server go to the M4 ADR. A move to another vault ([ADR 0006](0006-key-hierarchy.md), Consequences, Positive) goes to the M9 ADR.

### 11. Forward compatibility and `item_schema_version` (e)

- **Unknown field keys** that fit the grammar are merged, snapshotted and exported byte for byte. An edit writes only the keys the user changed. Tested from M1 with a simulated newer client.
- **No version bump is needed** for new value types, enum values, list names, keys or item types.

| `item_schema_version` | Meaning |
|---|---|
| 0 | invalid, rejected |
| 1 | M1: this ADR |
| 2–`0xFFFE` | unassigned. Each needs an ADR, including the rule for when writers start using it |
| `0xFFFF` | reserved and never assigned; rejected like 0 |

- **What needs a new version:** any change to the rules §5 lists as frozen. `data` carries no second version number.
- **Reader rule.** A record with an unknown version is neither applied nor dropped. The client *parks* it: it keeps it unapplied and reports "update required". Causal delivery waits for it (ADR 0012 §4 step 2), so later ops of that device in that vault wait too. A version bump is therefore a forced client update ([ADR 0002](0002-own-protocol.md) point 5).
- **Parked records.** A parked record is not part of the item's state or the §4 state hash, never raises the persisted VV of ADR 0012 §7 "Freshness" (INV-25), and nothing that waits for it is applied.
- **No purge over an unapplied record.** While a client holds an unapplied record for an item, parked or waiting for predecessors or a wrap (ADR 0012 §4 step 2, CRYPTO.md §11.6), it issues no Purge for that item, manual or automatic. ADR 0012 §5 permits a purge and never requires one. Otherwise a restore the client received but cannot yet apply would be purged on every replica.

### 12. Tests

- **Normative vectors** ([CRYPTO.md §15](../CRYPTO.md#15-testing) item 1(A)), through real `ITEM_OP` and `ITEM_SNAPSHOT` envelopes, the nonce fed through the injected RNG: a create of each M1 type, the Login create writing `login.username`, `login.password` and `login.totp` to pin the §4 key order; a list edit; trash, restore and purge; a live snapshot with a two-value conflict, history, an unknown key and the tags `tag/61` and `tag/6162`; a tombstone with a late value; a tombstone from two concurrent purges under different item keys, the lower-HLC one under the newer key, so that `item_key_id` is the older key; a purge re-issued under a new key, `item_key_id` = the re-issued key (owner decision 15); each value type.
- **Negative vectors:** one per rejection rule in §5, each breaking only that rule, given as (purpose, covered VV, `data`). Rule 3 also gets an odd hex count (`uri/abc/value`), a 33-byte name and uppercase hex; rule 2 a 161-byte key. A vector asserts rejection only, not the error kind or offset.
- **Property tests:**
  - encode → parse → encode is the identity; reordering, duplication and truncation are rejected, never a panic; unknown keys and values are carried through;
  - the ADR 0012 §12 convergence property compares the §4 state hash;
  - tombstones, with concurrent purges in the ADR 0012 §12 generator: two concurrent purges, an edit covered by one purge's context only, edits E1 → E2 concurrent with a purge, a concurrent restore and purge, and an op whose context covers `purge_dot`, each in every arrival order, give identical tombstone bytes;
  - absorbing honest snapshots (§3) interleaved with ops, with concurrent covered VVs and either side live or a tombstone, reaches the state of the ops alone (the merge spike's `absorb` family);
  - **no silent loss** (it replaces ADR 0012 §12 "Properties", item 2): on a live item, every field value ever written is a current value, in history, or removed by the deterministic pruning rule. On a tombstone, the late registers equal the §3 definition computed directly from the set of applied ops; the values a purge discards and superseded late values are removed as §3 says (owner decision 9). The generator must reach l > 0.
- **Unit tests:** no auto-purge while an unknown-version restore is parked; a parked snapshot never raises the persisted VV; an oversize item gets no snapshot and keeps its ops.
- **Fuzz targets,** in the scheduled job (ADR 0009, owner decision 4): op data, snapshot data, tombstone, the value decoder and the key grammar.
- **Cross-platform byte equality:** CRYPTO.md §15 item 8.

### Owner decisions (2026-09-26)

The owner answered open questions 1–7 on 2026-09-26, each as recommended, and decided points 8–11 the same day, after the independent review:

1. **The encoding** → the hand-written canonical layout of §1–§5. No CBOR, no protobuf, no new dependency.
2. **Per-URI match mode** → item data (`uri/<id>/match`). Item ops are encrypted, device-signed (INV-22), rollback-checked (INV-25) and gap-checked (INV-27). [INV-14](../THREAT_MODEL.md#8-security-invariants) and [CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes) are amended on acceptance to name account-level match defaults, equivalence groups and autofill rules instead of per-URI match modes. M2 assigns the values.
3. **Item VV and item id** → carried only in the snapshot header, which the AAD binds. `data` does not repeat them.
4. **Cleared value against a concurrent edit** → the edit displays, marked as a conflict (§6). The merge and the converged state are unchanged.
5. **Limits** → accepted as in §10: 64 KiB per value, 1 MiB per op, 12 MiB per snapshot, 1,024 writes per op, 4,096 registers. Revisit with M3 data. Late registers are bounded like registers.
6. **Passkeys** → both are reserved: the standalone type `0x000A` and the `passkey/` list on Login. The M7 passkey ADR uses one and releases the other.
7. **Tags keyed by name** → yes for M1. A tag registry for colours or one-op renames is an M3 decision.
8. **Concurrent purges** → the tombstone records one purge, the one with the highest (`hlc`, `device_id`, `seq`); `c` is the join of all applied purge contexts; `item_key_id` comes from that purge's `ITEM_OP` envelope header. A Purge is never rejected (§3).
9. **Late values** → the register-like rule (§3): a late value survives unless a later write of the same key superseded it, and late registers are not pruned. The owner rules that this satisfies [INV-24](../THREAT_MODEL.md#8-security-invariants).
10. **Server compaction with concurrent snapshots** → a small separate ADR, [ADR 0021](0021-server-compaction.md) (Server-side compaction with concurrent snapshots), to be Accepted before M1 step 3. The server's rules live there, not here.
11. **How this ADR's changes to Accepted ADRs take effect** → partial supersession through [ADR 0020](0020-partial-supersession.md) (Record architecture decisions, with partial supersession), a small successor to ADR 0001. The older ADR's status becomes "Partially superseded by ADR NNNN (§…)", and everything not named stays binding.

### Owner decisions (2026-09-27)

The owner answered open questions 12–15 and decided 16 on 2026-09-27, each as recommended, and accepted the limits in Settled by the merge spike, item 4, as M1 limits to revisit before M9:

12. **Oversize items in the M1 flows that need a snapshot** → for an oversize item, the CRYPTO.md §11.6 writer rule writes the op and its new wrap without the snapshot (On acceptance item 5); restore healing as ADR 0021 open question 4 (§10).
13. **A merged snapshot after a concurrent absorption** → a §10 "No snapshot" trigger, with §10 "Newest snapshot". A partial supersession of ADR 0012 §6 under ADR 0020, not a clarification.
14. **Dishonest snapshots** → the evidence merge, §3 "Snapshots are claims" and §5, with two-author covers (ADR 0021 open question 1). A partial supersession of ADR 0012 §4 step 3 under ADR 0020 ("the op is a no-op" → "a covered op body still merges").
15. **`item_key_id` of a re-issued purge** → §3 "Re-issued ops", with a §12 vector.
16. **ADR 0012's snapshot-only transfers** (§9 pairing and stale re-sync, §10 step 4 and On-device → Server; M4, not modelled by the spike), raised by the review of 12–15 → "Snapshots are claims" governs Server-mode sync; the M4 ADR decides how those transfers meet it. Nothing in ADR 0012 §9 or §10 is superseded.

### On acceptance

This ADR makes none of these edits. The owner makes them in the change that accepts it.

1. **ADR 0012 is partially superseded** (owner decisions 11, 13 and 14). ADR 0020 is Accepted first or in the same change. ADR 0012's status line, and its Status cell in [docs/adr/README.md](README.md), gain "Partially superseded by [ADR 0018](0018-item-record-encoding.md) (§1 in part, §3 in part, §4 in part, §5 in part, §6 in part, §7 in part, §12 in part)", after any earlier entry and separated from it by a semicolon (ADR 0020 point 9). Its text is not otherwise edited. The parts, each replaced by the section of this ADR after the arrow; everything else in ADR 0012 stays binding:
   - §1 "Field key", first sub-bullet (fixed-field names) → §7: the keys are `item.notes` and `login.totp`, not `notes` and `totp.secret`;
   - §1 "Field key", second sub-bullet (list-like parts), as it applies to tags → §7: a tag is keyed `tag/<hex>` by the lowercase hex of UTF-8(NFC(name)) and has no attributes (owner decision 7). URIs, custom fields and passkeys keep random 16-byte element ids;
   - §3 "Item-record encoding", the `ITEM_SNAPSHOT` sub-bullet's first sentence → §3 layout and "Snapshot (b)": the item VV is not repeated in `data` (owner decision 3);
   - §4 step 3 ("**Ignore duplicates.**") → §3 "Covered ops" (owner decision 14);
   - §4 step 5 ("**Resolve for display.**"), with its sub-bullets → §6 "Display" (owner decision 4);
   - §5 "History", first sentence → §3 "History";
   - §5 "Purge", second sub-bullet (the tombstone) → §3 "Tombstone (c)" (owner decisions 3 and 8);
   - §5 "Late ops after a purge", second sentence → §3 "Late values", "Applying" and "Surfacing" (owner decision 9);
   - §6, last bullet ("Clients keep each item's ops since its newest snapshot, which makes the recomputation possible.") → §10 "Newest snapshot" (owner decision 13);
   - §7 "Snapshots and compaction", "Triggers" sub-bullet → §10 "Oversize items", "No snapshot";
   - §12 "Properties", item 2 → §12 "no silent loss".
2. **CRYPTO.md §8.4:** in "Security-relevant settings", "per-URI match modes" becomes "account-level match defaults" (owner decision 2); "Op and snapshot plaintexts" links here.
3. **CRYPTO.md §15 item 7** lists the §12 fuzz targets.
4. **THREAT_MODEL.md INV-14:** "match modes" becomes "account-level match defaults", and the §5.3 example "revert a per-URI match mode" is reworded to an account-level default (owner decision 2). INV-24 does not change (owner decision 9).
5. **CRYPTO.md §11.6 writer rule:** "and writes a full snapshot under the new key" gains "unless the item is oversize (ADR 0018 §10), when it writes the op and its new wrap without the snapshot" (owner decision 12).

## Consequences

### Positive

- One encoding style for headers and bodies. Nothing is added to the R1 allow-lists, `deny.toml` or the cargo-vet scope.
- Each state has exactly one encoding, so convergence tests compare hashes and vectors are byte-exact on every platform.
- The merge stays generic. The schema grows by keys and type ids without a version bump, and older clients carry newer data verbatim.
- A value that fails validation cannot split replicas.
- The share secret, match modes, passkeys and the M3 types already have a place, so M2–M7 add keys, not formats.
- The tombstone is a function of the set of applied ops, so concurrent purges, the normal case when several devices auto-purge, and late edits converge in any arrival order.

### Negative

- We own a parser for untrusted plaintext; from M9, a vault member is the author. It is fuzzed and in the M8 audit. Our estimate is under 1,000 lines for both layers, without tests (U).
- String keys cost 12–60 bytes each, against 1–2 for integer tags. Padmé hides most of the difference.
- Registers of removed list elements, and their history, are never collected, like tombstones. An item whose URIs change often grows toward §10; "duplicate as a new item" is the way out.
- Renaming a tag writes one op per tagged item.
- A version bump forces every client to update.
- A tombstone keeps late values for the life of the vault, but not a late value that a later write superseded (owner decision 9).
- An oversize item is not compacted while it stays oversize, and the M4 and M9 flows that need a snapshot of it are left to those ADRs (§10).
- A snapshot no longer stands in for the ops it covers: an item with an unresolved disagreement gets no snapshot, and each replica keeps local evidence state (§3, owner decision 14).

### Risks

- **A parser bug that rejects valid records stalls a device's chain on every replica.** Vectors and fuzzing are the defence. A rejection is reported, never skipped.
- **The frozen limits could be too small,** for example for Markdown notes in M3. Raising one is a version bump. The signal: users hitting the 64 KiB value limit.
- **Tag keys depend on NFC.** A normalisation-table change could split one tag into two keys, the same concern as on the password path (`unicode-normalization` is pinned, ADR 0009).
- **Favorites are per item,** so in an M9 shared vault a favorite is every member's. M9 may move favorites to per-user settings.
- **Accepted M1 limits** (Settled by the merge spike, item 4): a lie about the content of a compacted op is undecidable and only reported, and two or more faulty devices can defeat two-author covers. Until M9 every device is the owner's own; both are revisited before M9 shared vaults.
- **Partial supersession spreads ADR 0012 over two documents.** A reader of ADR 0012 must also read the parts On acceptance item 1 names.

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
- **A tombstone that lists every purge,** `u16 p ‖ p × (dot ‖ u64 hlc ‖ item_key_id)`. It also converges, but it grows with each concurrent purge. Owner decision 8 records one purge instead.

## Settled by the merge spike

The owner ruled on 2026-09-26 that these merge edge cases are settled by an executable Rust spike, an exhaustive permutation model of the ADR 0012 §12 properties, not by more prose. The spike stays outside the shipped crates, and its results are cited here (ADR 0001 point 6): [`spikes/merge-model`](../../spikes/merge-model/README.md), "Results", `integrated` preset, run on 2026-09-27 over 1,549,576 exhaustive schedules in 19 families and 2.6 million random seeds. P3 (permutation independence) never failed. Answers that change a frozen rule, converged bytes or an Accepted ADR went to the owner as open questions 12–15, now owner decisions 12–15. Server-side compaction behind concurrent snapshots is [ADR 0021](0021-server-compaction.md)'s (owner decision 10), not this ADR's.

1. **Snapshot absorption with concurrent VVs.** On every honest state, absorption (§3 "Absorbing a snapshot") equals the op-by-op state, either side live or a tombstone, and changes no layout, parse rule, limit or converged byte. Families `absorb` (45,360 schedules, all four live and tombstone pairings, 6,764 merged snapshots written), `snapshots` and `compaction`, and flavour `random-absorb`: no P1–P3 violation. In the answer's own copy, replacing the state instead gave false gaps, without the HLC receipt the clock condition failed, and without the merged snapshot (owner decision 13) the newest snapshot and the retained ops no longer rebuilt the item and the server kept a third snapshot (20,924 schedules). A tombstone does not carry a late Restore's HLC, so the receipt misses it (1 of 200,000 `random-reissue-norestore` seeds).
2. **Restore healing.** No layout, parse rule or converged byte of this ADR changes. The healing request is [ADR 0021](0021-server-compaction.md)'s (open question 4); an oversize item gets no fresh snapshot in it (owner decision 12; family `oversize`, 17,040 schedules, no violation). Families `restore`, `healing` and `oversize`, flavour `random-heal`: every violation is on the ADR 0012 §6 path of a revocation signed on a restored server (ADR 0021 open question 7).
3. **Re-issued ops.** The author and every receiver reach the same bytes only under §3 "Re-issued ops" (owner decision 15). Read literally, the author keeps the original op, and its tombstone's `item_key_id` differs from every receiver's (answer 3's copy: 6,000 schedules; `tests/families.rs` `answer3_reissue`); keeping unsent snapshots that cover the op broke P3-mixed in 947 schedules (answer 3's copy). The server side is ADR 0021 open question 9. Family `reissue` (23,218 schedules, 6,138 ending with a re-issued recorded purge) and flavour `random-reissue-norestore`: no violation (`random-reissue`: only on the ADR 0012 §6 path).
4. **Faulty-client snapshots.** A verified snapshot that omits a value or claims unheld dots loses values silently under the plain join and under single-author covers: the plain join fails `faulty-kinds` in 5,192 of 150,720 schedules, 2,343 with silent loss. The evidence merge (owner decision 14) with two-author covers (ADR 0021 open question 1) fails it in 1,136, each reported and each an undetectable fabrication, and leaves no silent loss with one faulty device outside restore healing. Families `faulty` and `faulty-kinds`, flavours `random-faults`, `random-faults-ops` and `random-faults-multi`. **Accepted M1 limits,** each revisited before M9 ([THREAT_MODEL §9](../THREAT_MODEL.md#9-accepted-risks-and-out-of-scope)), since until M9 every device is the owner's own: a lie about the content of an op whose body is compacted is undecidable (two worlds with byte-identical inputs, `tests/faulty.rs`) and only reported; two or more faulty devices exceed the bound; a faulty healer as a header's only cover is ADR 0021's (open question 8).

## Open questions for the owner

None open. Questions 1–7 were answered by the owner on 2026-09-26 and questions 12–15, with decision 16, on 2026-09-27, each as recommended; see [Owner decisions (2026-09-26)](#owner-decisions-2026-09-26) and [(2026-09-27)](#owner-decisions-2026-09-27). The answers keep the question numbers, so "open question N" means owner decision N. Points 8–11 were decided on 2026-09-26 without a question here; 13–15 came from the merge spike. Questions 1–7 are kept for the reasoning.

1. **The encoding.** Should it be the hand-written layout, or deterministic CBOR (minicbor with a BlueOak-1.0.0 license addition, or cbor4ii)? *Recommendation:* hand-written (§1). It adds no dependency, and it is the same style as the op header.
2. **Per-URI match mode.** ADR 0012 §1 names `uri/<id>/match` as an item field. CRYPTO.md §8.4 and [INV-14](../THREAT_MODEL.md#8-security-invariants) list "per-URI match modes" among the settings that live in `ACCOUNT_SETTINGS` or the signed `account-state`. This is an invariant-level conflict, so this ADR only reserves the key. *Recommendation:* keep the mode in item data, and amend INV-14 and §8.4 to name account-level match defaults, equivalence groups and autofill rules. Item ops are encrypted, never visible to the server, device-signed (INV-22), rollback-checked (INV-25) and gap-checked (INV-27). Decide before M2.
3. **The item VV and item id are not repeated in `data`.** ADR 0012 §3 lists the item VV in the snapshot data, and §5 lists the item id in the tombstone. Both are already in the snapshot header, and the AAD binds them. *Recommendation:* carry them only there, so the two copies can never disagree. The alternative is to repeat them and check that they are equal.
4. **Cleared value against a concurrent edit.** *Recommendation:* the edit displays, marked as a conflict, as "Active wins" already does for items (§6). The merge and the converged state do not change.
5. **Limits.** 64 KiB per value, 1 MiB per op, 12 MiB per snapshot, 1,024 writes per op and 4,096 registers. *Recommendation:* accept them, and revisit with M3 data. Attachments will take large content out of fields.
6. **Passkeys.** Reserve both a standalone type (`0x000A`) and a `passkey/` list on Login? *Recommendation:* yes. The M7 passkey ADR uses one and releases the other.
7. **Tags keyed by name.** *Recommendation:* yes for M1, so that concurrent adds of a tag merge. A tag registry for colours or one-op renames is an M3 decision.

Answered on 2026-09-27; the rules are in the sections owner decisions 12–15 name:

12. **Oversize items in the M1 flows that need a snapshot** → owner decision 12, §10.
13. **A merged snapshot after a concurrent absorption** → owner decision 13, §10.
14. **Dishonest snapshots: the evidence merge** → owner decision 14, §3 and §5.
15. **`item_key_id` of a re-issued purge** → owner decision 15, §3 and §12.

## References

- [ROADMAP](../ROADMAP.md) §4.2, §4.4, §4.7, §4.10
- [THREAT_MODEL](../THREAT_MODEL.md) §5.3, §5.6, §9, INV-13, INV-14, INV-22 to INV-27, INV-32
- [CRYPTO.md](../CRYPTO.md) §2, §4.4, §8.1, §8.4, §8.5, §9.1, §9.5, §11.6, §11.10, §11.15, §15
- [ADR 0001](0001-record-architecture-decisions.md), [ADR 0002](0002-own-protocol.md), [ADR 0006](0006-key-hierarchy.md), [ADR 0007](0007-ciphertext-envelope.md), [ADR 0009](0009-crypto-dependency-policy.md), [ADR 0011](0011-storage.md), [ADR 0012](0012-sync-engine.md), [ADR 0013](0013-shared-client-core.md), [ADR 0016](0016-workspace-layout.md); [ADR 0020](0020-partial-supersession.md) and [ADR 0021](0021-server-compaction.md) (both Proposed); `deny.toml` (license allow-list)
- `cargo info` and the crates.io API, 2026-09-25: minicbor 2.3.0, ciborium 0.2.2, cbor4ii 1.2.3, prost 0.14.4 (versions, dates, licenses, dependencies; V)
- Sources read: `minicbor-2.3.0/src/decode/decoder.rs`, `ciborium-0.2.2/src/value/canonical.rs`, `prost-0.14.4/src/encoding.rs`, plus greps of each crate for canonical or deterministic modes (V for what was read; absence claims are grep-based)
- RFC 8949 §4.2.1 and §4.2.3, deterministic and length-first CBOR (L, not re-read for this ADR); RFC 7049 §3.9 (L); RFC 5234, ABNF
- Protocol Buffers documentation, "serialization is not canonical" (L)
- The merge spike, [`spikes/merge-model/README.md`](../../spikes/merge-model/README.md), "Results" (`integrated` preset, run on 2026-09-27; figures as reported there, not re-run for this ADR)
