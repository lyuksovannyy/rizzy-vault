# ADR 0088: Erratum to ADRs 0046 and 0057: one device-state record grammar (record version 1 | 2, stage 1 | 2 | 3)

- Status: Proposed
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M1
- Partially supersedes (on acceptance): [ADR 0046](0046-recovery-pending-device-stage.md) ("What this ADR supersedes" bullet 1; §1 in part); [ADR 0057](0057-device-state-v2-keystore.md) (§2 in part)
- Format change: none. The bytes the shipped code reads and writes are unchanged.

## Context

The 2026-10-25 ADR gap review ([summary](../reviews/2026-10-25-adr-gap-review.md), blocker **B1**; raw finding **G05-12** in [G05.md](../reviews/2026-10-25-raw/G05.md)) found that two Accepted ADRs give incompatible definitions of the same persistent format, the device-state record. The owner said "start" (2026-10-25) to fixing the review's gaps. This ADR is the erratum the finding asks for ("Fix route: erratum ADR").

**ADR 0057** (Accepted 2026-10-22), §2 "Record version 2", extends ADR 0026 §2's grammar with `u8(has_ks: 0|1) ‖ [ks] ‖ u8(forward_count: 0..=8) ‖ forward*`, "`has_ks` and `[ks]` exist only when `record_version = 2`", and sets the composition rule "`stage = 3 ⇒ has_ks = 0`". Its §3 says: "`DeviceRecord::parse` accepts `record_version ∈ {1, 2}`, filling `has_ks = 0`, `forward_count = 0` for a v1 record; `encode` always writes version 2."

**ADR 0046** (Accepted 2026-10-24), "What this ADR supersedes" bullet 1, replaces "the whole `device_state` notation block of [ADR 0026] §2" in full by a block that begins `device_state = u16(record_version = 1) ‖ u8(stage: 1 committed | 2 signup-pending | 3 recovery-pending)` and has no `has_ks`, `[ks]`, `forward_count` or `forward` field. Its §1 ends: "`RECORD_VERSION` stays 1: a build that does not know stage 3 reports `CacheCorrupt`, not `CacheUpdateRequired`, for such a record — accepted below (open question 2)."

Neither ADR names the other's text as superseded (ADR 0020 point 9: "Nothing is superseded by implication"). As G05-12 puts it, "an implementer cannot satisfy 'stays 1' and 'always writes 2' at once, and the binding ADR 0026 §2 text no longer describes the record the code writes." ADR 0046's own composition rule ("whichever of this ADR, 0051 and 0057 is accepted last appends its own edit … rather than overwriting the other's", ADR 0046 line 42) was not followed: 0046 was accepted last and overwrote the block.

**What the code does.** The shipped code combines both ADRs. ADR 0057's version 2 came in commit `985f6d3` (2026-10-23) and ADR 0046's stage 3 in commit `418a100` (2026-10-25). Both are on this branch, whose HEAD was `262bbd0` when this ADR was drafted. In `crates/rizzy-client/src/store/record.rs`:

- The module doc carries the combined grammar (`record.rs:8–18`): `u16(record_version = 1 | 2)`, `u8(stage: 1 committed | 2 signup-pending | 3 recovery-pending)`, and `has_ks`/`forward_count` marked "version 2 only".
- `pub const RECORD_VERSION: u16 = 2;` (`record.rs:86`) and `pub const RECORD_VERSION_1: u16 = 1;` "read, upgraded on the next write, never written" (`record.rs:88–89`). `MAX_DEVICE_STATE_LEN: usize = 4096` (`record.rs:92`).
- `Stage::to_u8`/`from_u8`: `Committed => 1`, `SignupPending => 2`, `RecoveryPending => 3`, anything else `None` (`record.rs:122–138`).
- `DeviceRecord::parse` (`record.rs:300–395`) and `DeviceRecord::encode` (`record.rs:406–482`); the rules are listed in §2 below with their lines.

**The committed vectors** (the KATs this ADR's grammar must reproduce byte for byte):

- `crates/rizzy-client/src/tests/recovery_pending.rs:125–160`, `recovery_pending_vector` (ADR 0046 §5): a stage-3 record whose first seven bytes are `00020300000019` ("version 2, stage 3, then the origin's length"). Its length is `3 + 29 + 16 + 16 + 1 + 16 + 16 + 2 + 94 + 1 + 8 + 94 + 1 + 1 + 1` = 299 bytes, and its last four bytes are `44000000` ("`E_local`'s last byte, `has_ks = 0`, `forward_count = 0`, `pending = 0`"). It differs from the committed vector at byte index 2 only (the stage byte) and parses back to itself.
- `crates/rizzy-client/src/tests/store.rs:490–524`, `device_record_vectors` (ADR 0026 §6): the committed, `has_local = 0`, stage-2 and stage-3 vectors, built from `vector_bytes_of(2, …)` (`store.rs:441–447`). The committed vector starts `0002 01 00000019 68747470733a2f2f7661756c742e6578616d706c652e636f6d a1a1a1a1`: version 2, stage 1, `str("https://vault.example.com")`, then the first bytes of `account_id`.
- `crates/rizzy-client/src/tests/store.rs:534–541`: version 3 gives `CacheUpdateRequired`, version 0 gives `CacheCorrupt`, and `assert_eq!(RECORD_VERSION, 2)`.
- `crates/rizzy-client/src/tests/store.rs:795`, `a_v1_record_is_upgraded_on_its_next_write`: a version-1 record is the version-2 record with `record_version = 1` and the `has_ks` and `forward_count` bytes removed in front of the final `pending` byte. The next write gives version 2. `store.rs:684–687` (`canonical_or_upgraded`) is the property-test form of the same rule.

So the code follows ADR 0057 on the version and ADR 0046 on the stage. Only the binding text is wrong. HANDOFF.md's ADR table row for 0046 (`docs/HANDOFF.md:281`) also repeats "`RECORD_VERSION` stays 1".

## Decision

No byte of the format changes. This ADR replaces the two ADR 0046 sentences that conflict with ADR 0057, and the partial grammar block of ADR 0057 §2, with one combined grammar. That grammar is the one `record.rs` implements and the vectors above pin.

### What this ADR supersedes

Three parts, each replaced in full (ADR 0020 point 9):

**1. [ADR 0046](0046-recovery-pending-device-stage.md), Decision, "What this ADR supersedes", bullet 1**, the bullet that begins "The whole `device_state` notation block of §2:" together with the fenced block it contains. That bullet is the text that binds in place of ADR 0026 §2's notation block, so once this ADR is Accepted, the block below is also the binding `device_state` grammar at ADR 0026 §2. Replaced in full by:

> - The whole `device_state` notation block of §2:
>   ```text
>   device_state = u16(record_version = 1 | 2)
>                ‖ u8(stage: 1 committed | 2 signup-pending | 3 recovery-pending)
>                ‖ str(server_origin) ‖ account_id (16) ‖ device_id (16) ‖ u8(device_kind: 1–3)
>                ‖ secret_key (16) ‖ device_salt (16) ‖ u16(kdf_id) ‖ bytes(E_dev)
>                ‖ u8(has_local: 0 | 1) ‖ [local]
>                ‖ u8(has_ks: 0 | 1) ‖ [ks]                        -- record_version = 2 only
>                ‖ u8(forward_count: 0..=8) ‖ forward*             -- record_version = 2 only
>                ‖ u8(pending: 0 | 1) ‖ [pending]
>   local        = u32(local_account_key_epoch) ‖ u32(local_password_epoch) ‖ bytes(E_local)
>   ks           = u32(ks_account_key_epoch) ‖ bytes(E_ks)
>   forward      = u32(from_account_key_epoch) ‖ u32(to_account_key_epoch) ‖ bytes(E_ks_forward)
>   pending      = secret_key' (16) ‖ device_salt' (16) ‖ u16(kdf_id') ‖ u32(account_key_epoch')
>                ‖ u32(password_epoch') ‖ bytes(E_local') ‖ bytes(E_dev' or empty)
>   ```
>   `u16` and `u32` are big-endian. `bytes(x)` is `u32(length of x) ‖ x`, and `str(s)` is `bytes(UTF-8 of s)`. A field marked `(16)` is exactly 16 raw bytes with no length prefix. `[local]`, `[ks]` and `[pending]` are present if and only if the flag byte just before them is 1. `forward*` is exactly `forward_count` entries, oldest first. `bytes(E_dev' or empty)` is the empty string when `E_dev` stays and a non-empty envelope otherwise. The `stage` byte means the same in both record versions, and stage 3 is valid in both. A `record_version = 1` record has no `has_ks` byte and no `forward_count` byte at all, so its `pending` flag follows `[local]` directly, and it is read as `has_ks = 0`, `forward_count = 0`. Every write is `record_version = 2`, so a record read as version 1 is written back as version 2 by its next write, in the same transaction ([ADR 0057](0057-device-state-v2-keystore.md) §3). A `record_version` above 2 is refused as "update required" (`CacheUpdateRequired`, ADR 0026 §5). `record_version = 0` is refused as corrupt (`CacheCorrupt`).

**2. [ADR 0046](0046-recovery-pending-device-stage.md) §1, the last sentence**, word for word: "`RECORD_VERSION` stays 1: a build that does not know stage 3 reports `CacheCorrupt`, not `CacheUpdateRequired`, for such a record — accepted below (open question 2)." Replaced in full by:

> Stage 3 does not bump the record version: a stage-3 record is written as `record_version = 2`, the version every write uses ([ADR 0057](0057-device-state-v2-keystore.md) §3; grammar in [ADR 0088](0088-device-state-record-grammar.md) §1), and a build that reads record version 2 but does not know stage 3 reports `CacheCorrupt`, not `CacheUpdateRequired`, for such a record.

**3. [ADR 0057](0057-device-state-v2-keystore.md) §2, the opening two sentences and the fenced block after them**: the sentences "Extends ADR 0026 §2's grammar." and "New text only:", word for word, and the `text` block that follows them (from `device_state = u16(record_version = 1 | 2) ‖ u8(stage) ‖ …` to `forward = u32(from_account_key_epoch) ‖ u32(to_account_key_epoch) ‖ bytes(E_ks_forward)`). This block does not contradict the code, but it is a second, partial statement of the same grammar, and two partial statements are what caused B1. Replaced in full by:

> The record's complete grammar, for both record versions and all three stages, is the one `device_state` block that [ADR 0088](0088-device-state-record-grammar.md) §1 writes. This section adds the `has_ks`, `[ks]`, `forward_count` and `forward*` fields to that block, for `record_version = 2` only.

Nothing else in ADR 0046 or ADR 0057 changes. That includes ADR 0046's other three supersession bullets (the ADR 0026 §2 "Parsing" sentence, the §3 sentence and the §4 step 5 parenthetical), all of ADR 0057 §2's bullets (`stage = 3 ⇒ has_ks = 0`, `has_ks = 1` requires `has_local = 1`, `forward_count ≤ 8`, the platform gate) and ADR 0057 §3. ADR 0046's open question 2 and its recommendation ("keep it at 1") are not Decision text and are not edited (ADR 0020 point 4). After this ADR, their binding reading is part 2 above: stage 3 needs no version bump of its own.

### 1. The combined grammar

The binding grammar is the block in part 1 above. It equals the module doc of `record.rs:8–18` field for field. Checked against the committed stage-3 vector, the bytes are: `00 02` (`record_version = 2`) ‖ `03` (`stage`) ‖ `00 00 00 19` + 25 bytes (`str(server_origin)`, 29 bytes) ‖ 16 ‖ 16 ‖ 1 (`device_kind`, at byte index 64) ‖ 16 ‖ 16 ‖ 2 ‖ 94 (`bytes(E_dev)`) ‖ `01` ‖ 8 ‖ 94 (`bytes(E_local)`) ‖ `00` (`has_ks`) ‖ `00` (`forward_count`) ‖ `00` (`pending`), 299 bytes in all. The version-1 form of the same state is 297 bytes: `00 01`, then the same bytes, minus the `has_ks` and `forward_count` bytes.

### 2. The rules the grammar is read and written with (a checklist, not new rules)

Each rule below is already binding where cited, and the code implements it at the lines given. This list is here so that two implementers build the same codec. It adds and changes nothing. If it ever disagrees with a cited source, the source binds and this list is an erratum candidate.

| # | Rule | Error on violation | Source | Code |
|---|---|---|---|---|
| R1 | Total length ≤ `MAX_DEVICE_STATE_LEN` = 4096, checked **before** the version is read, so an oversized record is `CacheCorrupt` whatever its version | parse: `CacheCorrupt`; encode: `Internal`, nothing written | ADR 0026 §2 Parsing | `record.rs:302`, `:478` |
| R2 | `record_version` ∈ {1, 2} is read. 0, or fewer than 2 bytes, is corrupt. ≥ 3 is "update required", and nothing more is read | `CacheCorrupt` / `CacheUpdateRequired` | ADR 0057 §3; ADR 0026 §5 | `record.rs:306–310` |
| R3 | `stage` ∈ {1, 2, 3} in either version | `CacheCorrupt` | ADR 0026 §2 as ADR 0046 bullet 2 amends it; part 1 above | `record.rs:131–138`, `:311` |
| R4 | `server_origin` goes through the one origin parser and must already be canonical (one state, one encoding) | `CacheCorrupt` | ADR 0026 §2 Parsing | `record.rs:312–318` |
| R5 | `device_kind` 1–3 (durable kinds) | `CacheCorrupt` | ADR 0026 §2 Parsing | `record.rs:321–324` |
| R6 | Each `kdf_id` on the client allow-list | `CacheCorrupt` | ADR 0026 §2 Parsing | `record.rs:276–279` |
| R7 | Each envelope (`E_dev`, `E_local`, `E_ks`, `E_ks_forward`, `E_local'`, a non-empty `E_dev'`) is ≤ `MAX_KEY_ENVELOPE_LEN` = 256 bytes and parses as a symmetric envelope. Only `E_dev'` may be empty | parse: `CacheCorrupt`; encode: `Internal` | ADR 0026 §2 Parsing | `record.rs:215–232`, `:419–421`, `:471–475` |
| R8 | Each flag byte (`has_local`, `has_ks`, `pending`) is 0 or 1 | `CacheCorrupt` | ADR 0026 §2 Parsing | `record.rs:235–241` |
| R9 | `forward_count` ≤ `MAX_FORWARD_COUNT` = 8, checked before any entry is read | parse: `CacheCorrupt`; encode: `Internal` | ADR 0057 §2 | `record.rs:258–261`, `:414`; `device.rs:62` |
| R10 | No trailing byte | `CacheCorrupt` | ADR 0026 §2 Parsing | `record.rs:366` |
| R11 | `stage` ∈ {2, 3} requires `has_local = 1` and `pending = 0` | parse: `CacheCorrupt`; encode: `Internal` | ADR 0026 §2 Parsing as ADR 0046 bullet 2 replaces it | `record.rs:369–371`, `:407–409` |
| R12 | `stage = 3 ⇒ has_ks = 0` | as R11 | ADR 0057 §2 | `record.rs:372–374`, `:410–412` |
| R13 | `has_ks = 1` requires `has_local = 1`, and is accepted only when the host passed `keystore_capable = true` (INV-81) | parse: `CacheCorrupt`; encode: `Internal` (the encoder checks `has_local` only) | ADR 0057 §2 | `record.rs:377–379`, `:413` |
| R14 | Encode always writes `RECORD_VERSION` = 2. A parsed version-2 record encodes back to its input, and a parsed version-1 record to its version-2 form | n/a | ADR 0057 §3; ADR 0026 §2 "One state has one encoding" | `record.rs:425`; `store.rs:684–687` |

No error carries a byte of the record, and nothing panics (CLAUDE.md, `record.rs:48`). The parse order inside `record.rs` decides nothing visible except R1 before R2: every other failure is the same `CacheCorrupt`.

### 3. Crash, retry and migration

Unchanged and restated only for completeness. The v1 → v2 upgrade happens in the same transaction as the write that follows a load (ADR 0057 §3, ADR 0026 §4), so no half-upgraded record exists. A stage-3 record is written before the send (ADR 0046 §2), as `record_version = 2`. The commit history suggests that no build on this branch ever wrote a version-1 stage-3 record: version 2 (`985f6d3`) came before stage 3 (`418a100`). Such a record is still accepted on read, because the code accepts it and part 1 says so, and it is upgraded on its next write.

## Consequences

### Positive

- One binding grammar, equal to the code and to the committed vectors. Blocker B1 is closed without a code or format change.
- ADR 0046's "stays 1" no longer contradicts ADR 0057's "always writes version 2". Its intent, no version bump *for stage 3*, is kept.

### Negative

- It adds a third ADR to read for the device-state record (0026 → 0046/0057 → 0088). The §2 checklist partly offsets that.
- It supersedes a replacement text (ADR 0046's bullet 1, which already stands in for ADR 0026 §2). ADR 0020 point 9 does not spell out this nesting. Part 1 says explicitly which text binds at ADR 0026 §2.

### Risks

- The §2 checklist could drift from its sources. Mitigation: it is marked non-normative, and every row cites its source and code line.
- A pre-`418a100` build that knows version 2 but not stage 3 reports a stage-3 record as `CacheCorrupt`, not "update required". ADR 0046 already accepted this (its open question 2), and part 2 keeps it.

## Alternatives considered

- **Bump to record version 3 for stage 3** (a clean `CacheUpdateRequired` on older builds). Rejected: it is a format change, it contradicts the shipped code and the KATs, and ADR 0046's owner answer chose no bump.
- **Supersede ADR 0057 §3 instead (go back to version 1).** Rejected: the code and every committed vector write version 2, and `E_ks` needs the version-2 fields.
- **Supersede only ADR 0046's two parts and leave ADR 0057 §2's block.** Consistent, but it leaves two statements of the grammar. See open question 1.
- **A docs-only erratum in `docs/reviews/2026-10-25-errata-candidates.md`.** Rejected: Accepted Decision text conflicts, and only an ADR can supersede it (ADR 0020 point 9).

## On acceptance (doc edits, not made now)

1. The owner sets status lines (ADR 0020 point 9). ADR 0046: `Accepted` → `Partially superseded by [ADR 0088](0088-device-state-record-grammar.md) ("What this ADR supersedes" bullet 1; §1 in part)`. ADR 0057: `Accepted` → `Partially superseded by [ADR 0088](0088-device-state-record-grammar.md) (§2 in part)`. ADR 0026's line is not changed, because this ADR names no ADR 0026 text directly.
2. `docs/adr/README.md`: the status cells of rows 0046 and 0057 as in item 1, and this ADR's row → Accepted.
3. `docs/HANDOFF.md:281` (ADR 0046's row): "`RECORD_VERSION` stays 1" → "no record-version bump for stage 3 (written as version 2, ADR 0088)".
4. CLAUDE.md's Accepted/Proposed list, by the lead.
5. `docs/reviews/2026-10-25-adr-gap-review.md`: mark B1 / G05-12 as resolved by ADR 0088, if the review file tracks resolution.
6. CRYPTO.md and THREAT_MODEL.md: no edit. A grep at drafting time found no device-state grammar or `RECORD_VERSION` text in either.

## Implementation plan (after acceptance; docs and tests only)

1. `crates/rizzy-client/src/store/record.rs:3–5`, module doc: cite "[ADR 0088] §1" as the grammar's source, in place of "ADR 0057 §2, extending ADR 0026 §2, with the recovery-pending stage of ADR 0046 §1". `Stage`'s doc (`record.rs:94`) and `parse`'s doc are unchanged. No code change.
2. New test in `crates/rizzy-client/src/tests/recovery_pending.rs`: the **version-1 stage-3** record (the stage-3 vector with `record_version = 1` and the `has_ks`/`forward_count` bytes removed, 297 bytes) parses with `keystore_capable` false and true, gives `Stage::RecoveryPending`, and encodes to exactly the committed version-2 stage-3 vector. This pins part 1's "stage 3 is valid in both" sentence.
3. New assertion in `device_record_refusals` (`store.rs:527`): a record of 4097 bytes whose first two bytes are `00 03` is `CacheCorrupt`, not `CacheUpdateRequired` (R1 before R2). A 1-byte input is `CacheCorrupt`.
4. Check, and add if missing: a version-2 stage-3 record with `has_ks = 1` is `CacheCorrupt` with `keystore_capable = true` (R12), and `encode` of such a record is `Internal`. This may already be covered at `recovery_pending.rs:162` ff. (not re-read for this draft).
5. The fuzz target `fuzz/fuzz_targets/client_device_state.rs` needs no change: it already runs `DeviceRecord::parse`.
6. Gate: `cargo test -p rizzy-client --locked`, `cargo fmt --all -- --check`, `cargo clippy -p rizzy-client --all-targets --locked -- -D warnings`, and `RUSTDOCFLAGS="-D warnings" cargo doc -p rizzy-client --no-deps --locked` for the doc link.

## Open questions for the owner

1. **Also supersede ADR 0057 §2's partial grammar block (part 3)?** It does not conflict with the code. Superseding it leaves exactly one grammar statement. Keeping it leaves a second, consistent but partial copy. *Recommendation:* supersede it, as drafted, because two partial copies are how B1 arose. If you prefer the narrowest erratum, drop part 3 and the "§2 in part" entry from item 1 of "On acceptance".

## References

- Review: [2026-10-25 ADR gap review](../reviews/2026-10-25-adr-gap-review.md) B1; [raw finding G05-12](../reviews/2026-10-25-raw/G05.md).
- [ADR 0020](0020-partial-supersession.md) point 9; [ADR 0026](0026-client-device-state-and-cache.md) §2, §4, §5, §6; [ADR 0046](0046-recovery-pending-device-stage.md) §1, §2, §5; [ADR 0057](0057-device-state-v2-keystore.md) §2, §3.
- Code: `crates/rizzy-client/src/store/record.rs` (lines cited above); `crates/rizzy-core/src/encoding.rs:45–76` (`put_u16`/`put_u32` big-endian, `put_bytes` = `u32` length ‖ bytes, `put_str` = `put_bytes` of UTF-8); `crates/rizzy-client/src/device.rs:62`; `crates/rizzy-proto/src/limits.rs:35`.
- Vectors: `crates/rizzy-client/src/tests/recovery_pending.rs:125–160`; `crates/rizzy-client/src/tests/store.rs:441–447`, `:490–524`, `:534–541`, `:684–687`, `:795`.
