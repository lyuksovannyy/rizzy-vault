# ADR 0012: Sync engine: op log, HLC and version vectors

- Status: Proposed
- Date: 2026-09-25
- Deciders: project owner
- Milestone: M1 (engine, Server mode) / M4 (On-device mode, pairing, mode switch)

## Context

The ROADMAP requirements:
- [ROADMAP §4.6](../ROADMAP.md#46-sync-modes-m4), Must, M1 engine / M4 modes: "Single sync engine for both modes … client-side encrypted op log, hybrid logical clocks + per-item version vectors, field-level merge, tombstones for deletes, conflicting edits kept as item history instead of dropped".
- [ROADMAP §4.2](../ROADMAP.md#42-core-vault-m1), Must, M1: "no silent data loss. M1 ships Server mode only, but the engine must not assume the server holds the vault".
- [ROADMAP §6.8](../ROADMAP.md#6-risks--hard-truths): this is the hardest correctness problem in the project, and it needs property-based tests on N simulated devices before M4.

Constraints from the other design documents:
- **The server cannot merge.** It never sees plaintext ([THREAT_MODEL](../THREAT_MODEL.md#13-security-goals) G-1). Clients merge (G-10).
- **Ops are encrypted and signed.** The body is encrypted under the item key and signed by the device key ([INV-22](../THREAT_MODEL.md#8-security-invariants); [CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes) `ITEM_OP`; [§10.2](../CRYPTO.md#102-ed25519-signatures-and-signed-statements) `op`). CRYPTO.md leaves the canonical op header to this ADR and requires AAD to cover every header field the server can see.
- **Merge rules:**
  - merge is idempotent and order-independent (INV-23);
  - conflicts become history (INV-24);
  - clients never accept a state that goes backwards (INV-25);
  - server compaction happens only behind snapshots that clients made and signed (INV-26);
  - per-device sequences are gap-free (INV-27).
- **On-device mode and devices:**
  - On-device mode keeps no snapshot and nothing older than the TTL (INV-28);
  - pairing requires a SAS (INV-29);
  - revocation, and a switch to On-device mode, rotate keys (INV-30, INV-31).
- **Portability:** `rizzy-sync` has no I/O and builds for wasm32. Time and randomness are injected (INV-58).
- **Sizes:** an item has about 5–30 fields. A personal vault has hundreds to a few thousand items.

## Decision

### 1. Model

- **Vault:** the unit of keys and membership. Each vault has its own op stream. An M1 account has one personal vault, and the model allows many (M9). Vault-level settings (name, icon) are an item of a reserved type.
- **Item:** a 16-byte random id, created on the client ([CRYPTO.md §2](../CRYPTO.md#2-conventions)). Its state is a set of **fields**.
- **Field key:**
  - Fixed fields have stable names: `login.username`, `login.password`, `notes`, `totp.secret`, and so on.
  - List-like parts (URIs, custom fields, tags, passkeys) are maps from a random 16-byte element id to fields, for example `uri/<id>/value`, `uri/<id>/match`, `uri/<id>/order`.
  - Order is itself a field that holds a sort key. So "added a URI on the phone, added another on the laptop" never conflicts.
- **Lifecycle** is a field too: `Active` or `Trashed`.
- **Unknown fields are kept.** A field written by a newer client is carried through merge and snapshots unchanged by an older one. This is tested from M1.

### 2. Clocks and versions

- **Dot.** Each op is identified by `(device_id, device_seq)`.
  - `device_seq` is a `u64`. It starts at 1 and increases by exactly 1 for every op the device writes, in any vault. It is gap-free per device (INV-27).
  - Each op also carries `vault_prev_seq`: the same device's previous `device_seq` in that vault, or 0 for its first. A reader who sees only one vault, such as an M9 member, can still check that the device's chain in that vault has no gaps.
- **HLC.** A `u64` hybrid logical clock (Kulkarni, Demirbas et al. 2014): the top 48 bits are Unix milliseconds, the low 16 bits a logical counter. The standard update rules apply on local events and on receipt. The host injects the wall clock.
  - HLC orders history and breaks ties between concurrent writes. **It never decides causality.**
- **Skew guard.** A received HLC more than 24 h ahead of the local wall clock is still applied, because every replica must apply the same ops. But the local clock does not adopt it, and the UI reports "Device X's clock is ahead".
- **Per-item version vector (VV).** A map `device_id → highest device_seq applied to this item from that device`. A dot `(d, s)` is *covered* by a VV `V` when `V[d] ≥ s`.
- **Causal context.** Each op carries the item VV its author had at write time. Op A happened before op B if B's context covers A's dot. Otherwise the two are concurrent.

### 3. The op record

An op is **one save of one item**: one or more field writes, or a lifecycle change, that share one dot, one HLC and one causal context. One save is one envelope and one signature, which also hides how many fields changed. [CRYPTO.md §8.1](../CRYPTO.md#81-aead-choice) uses the same definition.

The record uses the canonical binary encoding of [CRYPTO.md §2](../CRYPTO.md#2-conventions):

| Part | Contents | Server sees (Server mode) |
|---|---|---|
| Header | `u8 header_version = 1` ‖ vault_id ‖ item_id ‖ op_id ‖ device_id ‖ `u64 device_seq` ‖ `u64 vault_prev_seq` ‖ `u64 hlc` ‖ `u16 item_schema_version` ‖ causal context (`u16 n` ‖ n × (device_id ‖ `u64 seq`), sorted by device_id) | yes |
| Body | `ITEM_OP` envelope under the item key ([CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes)): the field writes, framed and Padmé-padded ([§8.5](../CRYPTO.md#85-plaintext-framing-and-padding)) | padded size only |
| Key wrap | the `ITEM_KEY_WRAP` envelope. Present only on the first op under a new item key: on create, or on the first write after a vault-key rotation | yes (ciphertext) |
| Signature | an `op` statement by the device key over `bytes(canonical op header) ‖ SHA-256(body envelope) ‖ SHA-256(key-wrap envelope)`, with 32 zero bytes in place of the second hash when the op carries no wrap ([CRYPTO.md §10.2](../CRYPTO.md#102-ed25519-signatures-and-signed-statements)) | yes |

- `op_id` is 16 random bytes.
- The body's AAD binds the header through `SHA-256(canonical op header)`, as CRYPTO.md §8.4 requires.
- **The signature covers the hashes of the body and the key wrap, not their bytes.** The server can then delete a compacted op's body and keep its signed header, which the chain check in §7 needs. Whenever the body or the wrap is present, the receiver checks it against the signed hash before anything else. The wrap hash keeps the wrap's author signed ([ADR 0006](0006-key-hierarchy.md) decision 10). CRYPTO.md §10.2's `op` row uses this form (open question 7).
- A snapshot header is `u8 header_version = 1` ‖ vault_id ‖ item_id ‖ snapshot_id ‖ author device_id ‖ `u16 item_schema_version` ‖ the VV it covers. Its body is an `ITEM_SNAPSHOT` envelope, and it is signed as a `snapshot` statement.
- **The snapshot body's AAD binds `SHA-256(canonical snapshot header)`,** as `ITEM_OP` does for ops. Without it, `header_version` and the author `device_id` are visible to the server but outside the AAD, which breaks CRYPTO.md §8.4's rule that every server-visible header field is covered. The `ITEM_SNAPSHOT` row in [CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes) carries it.

### 4. Apply and merge (clients only)

Each field is a **multi-value register**. To apply an op:

1. **Verify first.**
   - The signature must chain to a device certificate that is not revoked. The exception is a revoked device's op with `device_seq ≤ last_accepted_device_seq` ([CRYPTO.md §11.8](../CRYPTO.md#118-device-revocation)).
   - The body must decrypt, with the commitment check.
   - On any failure, reject the whole op and report it. Never apply part of an op.
   - Verification depends only on the op and the signed account state, never on the local clock; otherwise replicas would disagree. The expiry of a web vault's ephemeral certificate ([CRYPTO.md §11.4](../CRYPTO.md#114-web-vault)) is checked against the op's HLC, and the server refuses uploads from an expired device.
2. **Deliver causally.** Hold the op until every dot in its causal context, and its `vault_prev_seq`, has been applied. Fetch missing predecessors. If they never arrive, report "missing ops from device X" (INV-27).
3. **Ignore duplicates.** If the item VV already covers the op's dot, the op is a no-op.
4. **Write.** For each field written:
   1. remove every current value whose dot is covered by the op's causal context;
   2. add the new value, tagged with the op's dot and HLC;
   3. update the item VV.
5. **Resolve for display.**
   - A field holds one value, or several if writes were concurrent.
   - The **displayed** value is the one with the highest `(hlc, device_id)`.
   - The others stay in the register, and the UI marks the field as conflicting ([ROADMAP §4.6](../ROADMAP.md#46-sync-modes-m4), Should: "keep both / pick one").
   - Picking a value, or any new edit of the field, writes a value whose context covers all of them. That resolves the conflict.

With causal delivery, this is the standard multi-value-register CRDT: the result does not depend on delivery order or on duplicates (Shapiro et al. 2011). INV-23 follows from that.

### 5. History, deletes and tombstones

- **History.** Every value removed from a register goes into the item's history, with its dot and HLC.
  - Password history (M1) is the history of `login.password`. Revision history (M3) is the whole list.
  - Values that lost a conflict end up in history too, so they are never dropped (INV-24).
- **Pruning is deterministic.** History keeps the newest N entries per field, ordered by `(hlc, device_id, device_seq)`. The starting value is N = 50, one constant for every replica. Pruning never depends on the local clock or on arrival order: "the top N of a set" is the same whatever order the set arrived in.
- **Trash.** A delete writes `Lifecycle = Trashed`.
  - **Every field edit also writes `Lifecycle = Active`.**
  - When a delete and an edit are concurrent, the lifecycle register holds both values, and **`Active` wins.** The edited item stays visible, with a notice: "deleted on X while it was being edited on Y".
  - Losing an edit to a concurrent delete would be silent data loss.
- **Purge.** A `Purge` op is allowed only on trashed items: manually, or automatically once an item has been in the trash for the retention period. The default is 30 days, measured against the trash op's HLC, and any device may issue it.
  - **Only clients purge.** Lifecycle is encrypted, so the server cannot see which items are trashed or since when, and it has no unsigned delete path ([ADR 0010](0010-server-shape.md) §1). In Server mode as in On-device mode, auto-purge happens only when some client is online after the retention period. An account whose devices all stay offline keeps its trash on the server until one of them returns.
  - A purge replaces the item's state with a **tombstone**: the item id, the purge op's dot and causal context, and the item-key wrap.
  - Tombstones are kept for the life of the vault. Each is tens of bytes.
- **Late ops after a purge.** An op concurrent with a purge, typically from a device that was offline, does not resurrect the item. It goes into the tombstone's history and is surfaced once: "An edit from Laptop arrived for an item you deleted permanently. Restore it as a new item?"

### 6. Revocation cut-off

- The server refuses a `device-revocation` while it holds ops from the revoked device that the revoking device has not fetched yet. In On-device mode, the relay refuses it while that device has batches beyond the revoker's ack cursor. The revoker syncs and retries.
- After the revocation, the server accepts nothing more from that device.
- The check, the revocation and every upload run under the account's lock ([ADR 0011](0011-storage.md), "Transactions and concurrency"), so a concurrent upload from the revoked device cannot slip past the check.
- With an honest server, every replica therefore agrees on the cut-off.
- Only a misbehaving server can make a replica hold an op past the cut-off. If that happens, the replica removes the op and recomputes the item from its retained ops and snapshots. If it cannot, it flags the item for the user.
- Clients keep each item's ops since its newest snapshot, which makes the recomputation possible.

### 7. Server mode (M1)

The server stores and forwards. It never decrypts and never merges.
- **Upload.** A device uploads its ops in `device_seq` order.
  - The server stores each op record under `(vault_id, device_id, device_seq)`.
  - It rejects an op whose `vault_prev_seq` is not the last op it holds from that device in that vault. The check and the insert are one transaction under the account's lock ([ADR 0011](0011-storage.md)).
  - That check is a convenience. The client-side check is the control.
- **Fetch.** A device sends its cursor: the highest `device_seq` it has per device, per vault.
  - It receives every op header after the cursor, per device and in chain order, each with its signature.
  - An op whose body is still held comes with its body. An op whose body was compacted away comes as the signed header with its two hashes, plus the newest snapshot of that item.
- **Chain check after compaction** (INV-27). The client verifies each header's signature and follows `vault_prev_seq` from its cursor to the newest header. Every link must be a received header. A header without a body counts only if a snapshot of that item, received now or already held, covers its dot. Anything else is reported as missing data, and nothing past the gap is applied.
  - Why the headers are kept: without them, a VV cannot tell a withheld op from an absorbed one. Example: device D writes seqs 11–50 on items X and Z, and X's ops are compacted behind a snapshot with VV[D] = 50. A laptop with cursor 10 for D syncs. The server withholds seq 12, the only edit to Z, and sends X's snapshot. Seq 12 is below X's VV[D], so a VV check would count it as covered, and the laptop would silently miss Z's edit. With retained headers, seq 12's header names item Z, and Z has no snapshot that covers it, so the gap is reported.
- **Snapshots and compaction.**
  - A client that has applied an item's ops writes a signed per-item snapshot: item state, conflicts and history.
  - Triggers: more than 32 ops on the item since its last snapshot, a key rotation, or a purge.
  - The server keeps the two newest snapshots per item. It deletes only the **bodies** of the ops covered by the **older** of the two. So a faulty snapshot never destroys the only copy of anything, and nothing is deleted except behind a signed snapshot (INV-26).
  - The signed header of every op is kept for the life of the vault, with its body and key-wrap hashes. Each costs about 220 bytes plus 24 bytes per causal-context entry: a 93-byte fixed header, two 32-byte hashes and a 64-byte signature. Deleting headers would bring back the ambiguity above.
- **Freshness.** Clients persist the highest VV they have accepted per item, and the last verified `account-state` (INV-25). A response that goes backwards is rejected and reported, never applied.
- **Healing a server rollback** ([THREAT_MODEL §5.8](../THREAT_MODEL.md#58-server-restore-from-backup), [INV-59](../THREAT_MODEL.md#8-security-invariants)). A restore from an old backup rolls back more than ops. It also rolls back:
  - the signed `account-state`;
  - device certificates and revocations, and the bundle;
  - grants and item-key wraps from rotations;
  - the OPAQUE record and `E_srv` after a password change, and `E_rec` after a recovery.

  A device that finds the server behind its own accepted state (a lower `state_seq`, or a VV behind its own) goes read-only as [CRYPTO.md §11.3](../CRYPTO.md#113-unlock-on-an-enrolled-device) requires. While read-only it still re-publishes, in this order:
  1. **The bundle chain,** so the server holds the current identity key.
  2. **Its newest signed `account-state`,** in one request with the device certificates of that state's device set and every `device-revocation` it holds. The server accepts any state that verifies against the current identity key and has a higher `state_seq` than the one it holds, not only `state_seq + 1`. From then on it refuses credentials older than that state (INV-59).
  3. **Key grants, vault self-grants and item-key wraps** that it holds, or can re-create with the keys it has.
  4. **Its ops, and a fresh signed snapshot of each affected item.**

  More rules for restore healing:
  - **A device enrolled after the backup** is unknown to the restored DB, so it cannot device-authenticate on its own. It sends its certificate, the `account-state` that lists it and the bundle chain with its device-auth request. The server verifies them against the identity key it holds, requires a `state_seq` at least as high as its own, and only then issues the challenge.
  - **What is not re-uploaded.** The OPAQUE record and `E_srv` are not re-uploaded. An enrolled device re-registers OPAQUE the next time the user types the password ([CRYPTO.md §5.8](../CRYPTO.md#58-loss-or-rotation-of-the-server-opaque-secrets)). If the recovery epoch moved, recovery stays refused until a device issues a new recovery code.
  - **Leaving read-only.** The device leaves read-only once the server serves a state and VVs at least as new as its own.
  - **Who may upload.** Any client may upload any signed op, snapshot or statement: the signature, not the uploader, establishes origin.
  - **Test.** The [ADR 0011](0011-storage.md) restore drill covers a password change, an enrolment, a revocation and a rotation made after the backup.

### 8. On-device mode (M4)

The server is a store-and-forward relay.
- **It stores:** the device registry and certificates, the signed `account-state`, the account-level key objects that [CRYPTO.md §4.2](../CRYPTO.md#42-key-inventory) keeps in the `auth` domain (bundles, `E_id`, pending grants, `ACCOUNT_SETTINGS`), per-device ack cursors, and pending relay batches.
- **It does not store:** snapshots, an op log, vault self-grants, item-key wraps, an OPAQUE record or any password-derived wrap (INV-28, [CRYPTO.md §4.2](../CRYPTO.md#42-key-inventory), [§5.7](../CRYPTO.md#57-on-device-sync-mode)).

How it works:
- **Sending.** A device packs records into a `RELAY_BATCH` envelope under the relay key ([CRYPTO.md §11.12](../CRYPTO.md#1112-relay-ops-on-device-mode-m4)), numbered with a gap-free `batch_seq` per sender. Two record types:
  - `0x01`: a signed op record (§3), with the item-key wrap it carries, if any;
  - `0x02`: a key record: one `VAULT_KEY_SELF_GRANT` or `ITEM_KEY_WRAP` envelope with its cleartext locator. Key rotations publish their vault-level objects this way ([CRYPTO.md §11.6](../CRYPTO.md#116-key-rotation) step 9).

  A batch closes after 5 s or 64 records, whichever comes first.
- **Ack set.** The relay stores each batch with the set of active devices other than the sender.
  - A device acks by posting, per sender, the highest `batch_seq` it has applied.
  - The relay removes that device from those batches' ack sets.
  - It deletes a batch once its ack set is empty.
- **Active devices** are the devices in the signed device set that are:
  - not revoked;
  - not stale;
  - not past their certificate's `expires_at`, if it has one.

  Web-vault certificates (`device_kind = 4`, [CRYPTO.md §11.4](../CRYPTO.md#114-web-vault)) are never in the signed device set ([CRYPTO.md §10.2](../CRYPTO.md#102-ed25519-signatures-and-signed-statements)), so a web session never joins an ack set and never holds a batch until the TTL. In On-device mode the web vault is disabled anyway ([ROADMAP §4.6](../ROADMAP.md#46-sync-modes-m4)).
- A newly enrolled device joins the ack set of every batch still pending, and skips what its peer transfer already covered (§9).
- **TTL.** The relay deletes a batch after the TTL even if some device has not acked it. The default is 90 days; the admin can set 7–365 days.
  - A device that had not acked such a batch becomes **stale**. The relay removes it from all ack sets.
  - The stale device sees the `batch_seq` gap and stops syncing. It must re-sync from a peer device, never from the server.
  - Its own unsent ops are not lost. They are valid ops, and it uploads them after the re-sync.
- **Revocation** removes the device from every ack set and triggers key rotation (INV-30, [CRYPTO.md §11.8](../CRYPTO.md#118-device-revocation)). Ops written after the rotation are under keys the revoked device never receives.

### 9. Enrolment and re-sync from a peer (M4)

- **Pairing** follows [CRYPTO.md §11.7](../CRYPTO.md#117-new-device-in-on-device-mode): a QR code carrying a pairing secret, then SAS confirmation (INV-29).
  - After the SAS is confirmed and the certificate is issued, the existing device sends the new one the vault state in `PAIRING_TRANSFER_SEALED` chunks, sealed to the new device's certified X25519 key ([CRYPTO.md §11.7](../CRYPTO.md#117-new-device-in-on-device-mode) step 7): the account key and signed state, every current vault self-grant and item-key wrap, a fresh signed snapshot of every item, all tombstones, its per-device high-water marks, and its per-sender `batch_seq` cursors.
  - The new device starts from those cursors.
  - The relay deletes the pairing session after 10 minutes.
- **Stale re-sync** uses the same transfer as `RESYNC_TRANSFER` ([CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes), purpose 0x0043): HPKE PSK mode to the stale device's certified X25519 key, with a PSK derived from the account key instead of the pairing key. There is no SAS, because both devices are already certified.
- **In Server mode,** a new device logs in and downloads snapshots and ops. Approving a new device from an existing one is optional there.

### 10. Mode switch (M4)

Both directions carry the same op records. Only where they wait changes.
- **Server → On-device:**
  1. The switching device syncs to the head and runs a key rotation (INV-31, [CRYPTO.md §5.7](../CRYPTO.md#57-on-device-sync-mode)). The server refuses the switch while it holds ops that the switching device has not fetched, as for a revocation (§6), so nothing uploaded before the switch point is lost. The rotation also publishes a `device-revocation` for every unexpired web-ephemeral certificate (`device_kind = 4`), because the web vault cannot follow the account into On-device mode. Kind-4 certificates are never in the signed device set ([CRYPTO.md §10.2](../CRYPTO.md#102-ed25519-signatures-and-signed-statements)), so peers reject later ops from those sessions through the revocations. The rotation's signed `account-state` sets the sync mode to On-device.
  2. **At the switch point** the server deletes the OPAQUE record, `E_srv`, `E_rec` and `H_rec`, the Server-mode snapshots, op records and retained headers, the vault self-grants and the item-key wraps, and ends every OPAQUE session (CRYPTO.md §5.7, INV-28). Devices authenticate with device keys from then on ([CRYPTO.md §5.10](../CRYPTO.md#510-sessions-after-authentication)).
  3. From the switch point on, new ops go through the relay only.
  4. A device that was behind at the switch point sees the new `account-state` at its next unlock, opens its device grant ([CRYPTO.md §11.3](../CRYPTO.md#113-unlock-on-an-enrolled-device) step 4) and re-syncs from a peer (§9). Its own unsent ops are not lost: it uploads them through the relay after the re-sync. Open question 8 covers keeping the Server-mode data for such devices instead.
  5. The server returns a signed deletion receipt for what step 2 deleted. It is a signed claim, not a proof ([THREAT_MODEL AR-9](../THREAT_MODEL.md#9-accepted-risks-and-out-of-scope)).
- **On-device → Server:** a device re-registers OPAQUE and uploads `E_srv`, the vault self-grants and item-key wraps, and a signed snapshot of every item ([CRYPTO.md §5.7](../CRYPTO.md#57-on-device-sync-mode)), and marks the switch point. Pending relay batches drain as usual.

### 11. What the server can and cannot see

| | Server mode | On-device mode |
|---|---|---|
| Account, device ids, device certificates, `account-state`, sync mode | yes | yes |
| Vault ids, item ids, item count | yes | no; they are inside relay batches |
| Per op: `device_seq`, `vault_prev_seq`, HLC, causal context, padded size, upload time | yes, and the signed header is kept for the life of the vault (§7) | no. Per batch only: sender, `batch_seq`, padded size, time |
| Ops per item; which device edited which item | yes | no |
| Snapshot VVs and padded sizes | yes | nothing stored |
| Field names and values, item type, history, conflicts, tags, URLs | **no** | **no** |
| Which device fetched or acked what, and when | yes | yes |

This matches [THREAT_MODEL §3.4](../THREAT_MODEL.md#34-what-the-server-holds-by-sync-mode) and CRYPTO.md §11.12. In Server mode, the HLC and causal context in the header reveal when an offline edit was made and which devices had seen what. Snapshot VVs would reveal most of that anyway. We accept it as metadata ([NG-5](../THREAT_MODEL.md#14-non-goals)).

### 12. Testing

`rizzy-sync` is a pure state machine, so the whole system runs inside one test process.
- **Harness.**
  - 3–7 simulated devices, plus a simulated server (Server mode) or relay (On-device mode).
  - A deterministic scheduler and a seeded RNG drive everything.
  - The crypto is real: `rizzy-core` with a test RNG.
- **Generated histories** (proptest):
  - creates, field edits, list-element edits;
  - trash, restore, purge;
  - concurrent edits of one field;
  - devices going offline and online;
  - duplicated, delayed and reordered delivery;
  - a server rolled back to an earlier state, including its signed state, certificates, revocations and wraps;
  - a server that withholds an op on one item while serving a compacted snapshot of another;
  - relay TTL expiry;
  - device revocation and pairing a new device;
  - mode switches in both directions, with expired and live web-vault sessions, and a device that is offline at the switch point.
- **Properties:**
  1. **Convergence.** Once the network is quiet, all non-stale devices hold byte-identical state, compared by a hash of the canonical item state.
  2. **No silent loss.** Every field value ever written is a current value, in history, or removed by the deterministic pruning rule.
  3. **Idempotence and order-independence.** Any permutation of a set of ops, with duplicates, yields the same state.
  4. **Monotonicity.** No device ever accepts a VV or an `account-state` lower than one it accepted before.
  5. **Staleness.** A device offline past the TTL detects it, and never merges silently.
  6. **Revocation.** A revoked device cannot decrypt anything written after the rotation.
  7. **Gap detection.** An op that the server withholds is always reported as missing, whether or not other items were compacted.
- **Budget.** Every PR runs a fixed number of cases per property, starting at 1,000. A nightly job runs 100 times more. Every failure prints its seed, and fixed seeds become regression tests.
- **Named scenario** from [ROADMAP §7](../ROADMAP.md#7-definition-of-done-for-v10-end-of-m8): three devices, one of them offline past the TTL, a Server → On-device → Server round trip. It must converge with no loss.

### 13. Where the code lives

- **`rizzy-sync`** holds:
  - the op and snapshot record formats;
  - HLC and version vectors;
  - causal delivery, deduplication and gap detection;
  - cursor and ack arithmetic, and the compaction rules;
  - the multi-value-register merge.

  The merge is generic over field keys and values. It stores and compares them, and never interprets them.
- **`rizzy-core`** holds encryption, signatures and the item schema: which fields exist and how they are validated.
- **`rizzy-client`** drives the cycle ([ADR 0013](0013-shared-client-core.md)): fetch, verify and decrypt through `rizzy-core`, apply through `rizzy-sync`, persist ciphertext.
- **The server** uses only the header, version-vector and cursor types ([ADR 0016](0016-workspace-layout.md)).
- **Plaintext in `rizzy-sync`.** The crate's current doc comment says it "never needs plaintext". That holds for everything the server uses. The merge, however, receives decrypted field writes from `rizzy-client`, as opaque bytes in zeroizing types ([ADR 0009](0009-crypto-dependency-policy.md)). The doc comment has to change when the crate gets code (open question 6).

## Consequences

### Positive

- One engine and one op format serve both modes. The transport changes; the merge does not.
- Concurrent edits to different fields merge. Concurrent edits to the same field are kept and shown.
- The merge does not depend on the order the server delivers ops in. A malicious server can withhold or delay ops, but it cannot pick winners by reordering them.
- For the same reason, LAN or peer-to-peer sync can come later without changing the engine ([ROADMAP §4.6](../ROADMAP.md#46-sync-modes-m4), Could).
- The server stays simple: it stores, forwards, checks sequences and deletes. It runs no merge code.

### Negative

- The clients carry all the complexity. A bug here reaches every platform at once through `rizzy-sync`, which is also the point of having one implementation ([ADR 0013](0013-shared-client-core.md)).
- Version vectors grow with the number of devices that have ever edited an item. Every web-vault session is a new ephemeral device ([CRYPTO.md §11.4](../CRYPTO.md#114-web-vault)), so items edited often in the web vault collect entries, at about 24 bytes each. That is acceptable at personal scale; measure it in M3.
- Tombstones are never collected.
- Signed op headers are never collected in Server mode: about 220 bytes per op plus 24 bytes per causal-context entry. 10,000 ops with three entries each cost about 2.9 MB.
- Trash is purged only when a client is online after the retention period. The server cannot do it alone.
- In Server mode, visible item ids and per-item snapshots reveal edit patterns per item.
- Notes are a single field. Concurrent edits of a long note produce two versions that the user merges by hand. There is no text merge.

### Risks

- Convergence bugs appear only under rare interleavings. The property tests are the defence. The proposal is that M4 does not ship until the nightly job has been green for 30 consecutive days (open question 5).
- Clock skew can make "latest wins" display an older edit. The losing value stays in the register and in history, so nothing is lost.
- The revocation cut-off relies on the server refusing early revocations. Against a malicious server we detect divergence instead of preventing it.

## Alternatives considered

- **Whole-vault last-writer-wins.** A stale device's save overwrites newer edits made elsewhere. The server must hold the vault, so On-device mode is impossible.
- **Per-item last-writer-wins.** Edit the username on the phone and the password on the laptop, and one of the two is lost. That is silent data loss at exactly the level users notice.
- **A full CRDT library (Automerge, Yrs).** It would give text merge and arbitrary structure. Against it:
  - it keeps the document's full change history by design, which is the payload bloat [ROADMAP §5](../ROADMAP.md#5-architecture-decisions-to-make-in-m0-with-current-recommendation) warns about;
  - its sync protocol assumes peers see the document structure, so we would still build encryption, signing and the relay around it;
  - it is a large dependency to audit inside `rizzy-sync`.

  Our records have about 20 fields, and multi-value registers plus maps cover them.
- **A server-assigned total order**, with clients applying ops in the server's order and last-writer-wins. Simpler. But the server decides which concurrent write wins, so a malicious server can pick winners. It also rules out LAN or peer-to-peer sync, where there is no sequencer.
- **Operational transformation.** It needs a central party that reads the operations to transform them, which is impossible over ciphertext.
- **A causal graph of parent op ids** (the Git or Automerge approach) instead of version vectors. Each op is smaller, usually one parent. But after compaction, deciding "have I already seen this op?" needs the set of every op id ever seen, kept forever. Version vectors store exactly that information compactly, because per-device sequences have no gaps.

## Open questions for the owner

1. **`Active` wins over a concurrent delete.** *Recommendation:* yes. The alternative loses the edit.
2. **Late ops after a purge are surfaced, not resurrected.** *Recommendation:* yes.
3. **Defaults.** Relay TTL 90 days (admin range 7–365); trash retention 30 days; history N = 50 per field; a snapshot after 32 ops. *Recommendation:* accept these as starting values and revisit them with M3/M4 data.
4. **Notes: whole-field conflicts or text merge?** *Recommendation:* whole-field for v1.0. Text merge would bring back the CRDT-library question.
5. **M4 release gate.** 30 consecutive days of green nightly property runs before M4 ships. *Recommendation:* yes.
6. **Where the field merge runs** (§13).
   - Option A, recommended: the multi-value-register merge lives in `rizzy-sync` and sees decrypted field writes as opaque bytes. `rizzy-sync` then joins the plaintext audit scope, and the "never needs plaintext" line in its crate doc, and the matching line in [CLAUDE.md](../../CLAUDE.md), must be corrected.
   - Option B: keep `rizzy-sync` ciphertext-only and move the field merge into `rizzy-client`. That splits one algorithm across two crates, and the property tests would have to span both.

   *Recommendation:* option A.
7. **Gap detection after compaction** (§7). This must be settled before M1 freezes the op and snapshot formats.
   - Option (a): each snapshot lists every dot it absorbed, with its `vault_prev_seq`. The `op` signature then covers the full body and key-wrap bytes. But every snapshot grows with the item's whole edit history and is re-uploaded every 32 ops.
   - Option (b), recommended and written into §3 and §7: the `op` statement signs the canonical op header plus the SHA-256 of the body envelope and of the key-wrap envelope, and the server keeps signed headers after deleting bodies. Storage grows with the op count, and a brand-new device can check every device's chain from seq 1.

   *Recommendation:* option (b), which CRYPTO.md §10.2's `op` row already uses. Choosing (a) changes that row back.
8. **Server-mode ciphertext after a switch to On-device mode** (§10). The decision above deletes everything at the switch point, as [CRYPTO.md §5.7](../CRYPTO.md#57-on-device-sync-mode) and INV-28 require, and devices that were behind re-sync from a peer. The alternative keeps the snapshots and op log until every active device acks the switch point or the TTL passes, so lagging devices catch up without a peer. It leaves vault ciphertext on the server for up to the TTL (90 days by default) after the user asked for it to go, and it needs INV-28 amended, which is the owner's call. *Recommendation:* delete at the switch point. Peer re-sync already exists for stale devices, and "my data never rests on someone else's disk" is why users pick the mode. If the owner prefers the delay, show the deletion deadline on the transparency page and amend CRYPTO.md §5.7 step 2 and INV-28 in the same PR.

## References

- [ROADMAP](../ROADMAP.md) §4.2, §4.6, §5 (row "Sync engine"), §6.8, §7
- [THREAT_MODEL](../THREAT_MODEL.md) §3.4, §5.5, §5.6, §5.8, A13, G-1, G-10, INV-22 to INV-31, INV-58, INV-59, AR-5, AR-9, NG-5
- [CRYPTO.md](../CRYPTO.md) §2, §5.7, §5.8, §5.10, §8.4, §8.5, §10.2, §11.3, §11.4, §11.7, §11.8, §11.12: op and snapshot encryption, signatures, device authentication, relay batches, pairing
- [ADR 0006](0006-key-hierarchy.md), [ADR 0007](0007-ciphertext-envelope.md), [ADR 0010](0010-server-shape.md), [ADR 0011](0011-storage.md), [ADR 0013](0013-shared-client-core.md)
- S. Kulkarni, M. Demirbas et al., "Logical Physical Clocks and Consistent Snapshots in Globally Distributed Databases", 2014 (hybrid logical clocks; background reading, not re-verified for this ADR)
- M. Shapiro, N. Preguiça, C. Baquero, M. Zawirski, "Conflict-free Replicated Data Types", SSS 2011 (multi-value register; background reading, not re-verified for this ADR)
