# ADR 0057: Device-state record version 2: OS-keystore-backed local unlock (`E_ks`)

- Status: Accepted
- Date: 2026-10-11
- Deciders: project owner
- Milestone: M3
- Partially supersedes: [ADR 0026](0026-client-device-state-and-cache.md) (§1, one table row; §4 step 5, the "Load" step; see "What this ADR supersedes")
- Extends (no change to their text): [ADR 0026](0026-client-device-state-and-cache.md) §2 ("Not in v1" bullet, discharged here); [ADR 0019](0019-native-clients.md) §5 ("Local-unlock key storage" row), §5.2

## Context

[ROADMAP §4.3](../ROADMAP.md#43-cryptography--authentication-m0m1-audited-in-m8), Should, M3/M7: "Unlock with biometrics / OS keychain on desktop & mobile. Windows: deferred … Linux: master password only." ADR 0026 §2 already names the gap: v1's device-state record has no field for `E_ks`: "**Not in v1:** `E_ks` and `ACCOUNT_KEY_FORWARD` (M3/M7). They arrive as record version 2 with a v1→v2 upgrade in `rizzy-client`" (V, 0026 §2). The crypto layer needs nothing new — CRYPTO.md already specifies the construction in full:

- §4.2 "Key inventory": a "Keystore unlock secret (M3/M7)", 32 B, CSPRNG per device, held in "the OS keystore of that device, released only after an OS-enforced user-presence check (INV-62)", opening `E_ks` "and nothing else", deleted "when the user turns keystore unlock off"; the "Where each wrapped-key object lives" row lists `E_local, E_ks, E_dev, ACCOUNT_KEY_FORWARD` as "That device only. **Never uploaded**".
- §8.4: purpose `ACCOUNT_KEY_KEYSTORE_WRAP` (`E_ks`, 0x0006), ctx `account_id ‖ device_id ‖ u32 account_key_epoch`; purpose `ACCOUNT_KEY_FORWARD` (0x0007), ctx with `from`/`to` epochs, "Device-local only".
- §5.6 step 3: "A keystore unlock (M3/M7) skips steps 2–3: the OS releases the keystore unlock secret after its user-presence check, and it opens `E_ks` … instead."
- §11.3 steps 1, 4.3, 5: the offline/online unlock flow, the re-wrap-on-rotation flow (writing a local `ACCOUNT_KEY_FORWARD` envelope when a keystore-only unlock crosses a rotation, resolved "at the next password unlock"), and the delete-on-password-loss flow (`E_local` and `E_ks` destroyed together).

ADR 0046 ("A recovery-pending device-state stage for `rv recovery complete`", Proposed, M1) is a sibling touching the same ADR 0026 §1 row and §2 `stage` field, from the other side: a new stage 3 (recovery-pending) rather than a new record version. §1 and §2 below coordinate with it as far as this ADR can without re-reading its file (U where marked).

So this ADR decides **only the persisted record format and its parsing/migration rules**. THREAT_MODEL: [AST-22](../THREAT_MODEL.md#2-assets); [INV-62](../THREAT_MODEL.md#8-security-invariants); [AST-19](../THREAT_MODEL.md#2-assets), A8. Code (V, `crates/rizzy-client/src/store/record.rs`): `DeviceRecord::parse`/`encode`, `MAX_DEVICE_STATE_LEN = 4096`, record version 1 only; `device.rs`: `DeviceState::unlock(&self, password: &str)`; `error.rs`: `ClientError::{WrongPasswordOrSecretKey, CacheCorrupt, CacheUpdateRequired, LocalUnlockUnavailable, Internal}`.

## Decision

### 1. What this ADR supersedes

[ADR 0026](0026-client-device-state-and-cache.md) §1, the table row whose first cell is, as Accepted, exactly: "Device-state record (§2): stage, origin, ids, kind, SK, `device_salt`, `kdf_id`, `E_dev`, `E_local` (if present) with its ctx epochs, the pending record". ADR 0046 also supersedes part of this same row and of §2's `stage` field, for its stage 3. ADR 0020 point 9 names a row "by the exact text of its first cell": if ADR 0046 is Accepted before this ADR, the first cell this entry quotes is by then ADR 0046's replacement text, not ADR 0026's original (U: ADR 0046's exact replacement wording is not re-read here). Subject to that ordering, replaced in full by:

> Device-state record (§2, extended to record version 2 by [ADR 0057](0057-device-state-v2-keystore.md)): stage, origin, ids, kind, SK, `device_salt`, `kdf_id`, `E_dev`, `E_local` (if present) with its ctx epochs, `E_ks` (if present), the forward-envelope chain (if present), the pending record | one opaque byte string

[ADR 0026](0026-client-device-state-and-cache.md) §4 step 5 ("Load"), which reads "parse the device state, open `E_local` and `E_dev`, then verify …", assumed `E_local` is always opened. Record version 2 adds a keystore-only load path (CRYPTO.md §5.6 step 3) that never opens `E_local`. [ADR 0046](0046-recovery-pending-device-stage.md) (this batch, Proposed) edits this same step too, adding `stage = 3` to its "does not unlock" parenthetical; the replacement below folds that addition in rather than dropping it, so whichever of this ADR and ADR 0046 is accepted second still matches what the other already wrote there, per the ordering rule §1 above states for the table row. Replaced in full by:

> **Load** (after the offline unlock; a state with `has_local = 0`, `stage = 2`, or — composing with [ADR 0046](0046-recovery-pending-device-stage.md)'s stage 3, where that ADR is also Accepted — `stage = 3`, does not unlock, §2): parse the device state, then — on a password unlock, open `E_local` and `E_dev`; on a keystore unlock (`has_ks = 1`, CRYPTO.md §5.6 step 3), open `E_ks` and `E_dev` instead — then verify every account object and every record through the same code as a Fetch (signatures, headers, wraps, envelopes, ADR 0018 §5 rules) and rebuild the logs and merges. The persisted VV is the verified headers' VV (ADR 0012 §7 "Freshness").

No other part of ADR 0026 is named. §2's "Without `E_local`" bullet and the rest of §4 step 5's meaning stay true under §2 below (rule 3): every Accepted flow that deletes `E_local` deletes `E_ks` with it (CRYPTO.md §11.3 steps 5, 5.3.3), so `has_local = 0 ∧ has_ks = 1` never arises. §2's Parsing bullet (`MAX_DEVICE_STATE_LEN = 4096`) stays true: §2 below bounds the new fields to fit inside it unchanged.

**Proposed status-line text**, for the owner to set on acceptance (ADR 0020 point 9), each ADR naming only its own parts, in acceptance order: if ADR 0046 is accepted first, `Partially superseded by ADR 0046 (§1 row "Device-state record"; §2 "stage" field); [ADR 0057](0057-device-state-v2-keystore.md) (§1 row "Device-state record"; §4 step 5)`; if this ADR is accepted first, the two entries swap places. `docs/adr/README.md`'s row for ADR 0026 carries neither entry yet (checked 2026-10-11), so this ADR does not know which order the owner will use, and writes both.

### 2. Record version 2

Extends ADR 0026 §2's grammar. New text only:

```text
device_state = u16(record_version = 1 | 2) ‖ u8(stage) ‖ str(server_origin) ‖ account_id (16)
             ‖ device_id (16) ‖ u8(device_kind) ‖ secret_key (16) ‖ device_salt (16) ‖ u16(kdf_id)
             ‖ bytes(E_dev) ‖ u8(has_local: 0|1) ‖ [local] ‖ u8(has_ks: 0|1) ‖ [ks]
             ‖ u8(forward_count: 0..=8) ‖ forward* ‖ u8(pending: 0|1) ‖ [pending]
local   = u32(local_account_key_epoch) ‖ u32(local_password_epoch) ‖ bytes(E_local)   -- unchanged (0026 §2)
ks      = u32(ks_account_key_epoch) ‖ bytes(E_ks)
forward = u32(from_account_key_epoch) ‖ u32(to_account_key_epoch) ‖ bytes(E_ks_forward)
```

`has_ks` and `[ks]` exist only when `record_version = 2`; a version-1 record has neither `has_ks` nor `forward_count` at all, not merely zero, and is read as `has_ks = 0`, `forward_count = 0`. `forward_count`/`forward*` sit **outside** `[ks]`, present whenever `record_version = 2` regardless of `has_ks` (one byte of overhead when unused): CRYPTO.md §11.3 step 4.3 writes an `ACCOUNT_KEY_FORWARD` envelope while keystore-only, and that chain is resolved only "at the next password unlock" — a password unlock, not a change to `has_ks`. Nesting it under `[ks]` would delete a live chain the moment a user turns keystore unlock off (CRYPTO.md §4.2's "deleted" trigger), leaving `E_local` wrapping a stale account key with no local path to the current one; keeping it independent avoids that.

- **Context, not shape, differs from `E_local`.** `ACCOUNT_KEY_KEYSTORE_WRAP`'s ctx is `account_id ‖ device_id ‖ u32 account_key_epoch` only — no `password_epoch`, no `kdf_id`, since the keystore secret is not password-derived (§8.4). The record's existing `account_id`/`device_id` address `E_ks` to this device's keystore item; no separate key-handle field is added. The platform binding leaf finds its own keystore entry for `(account_id, device_id)`; that lookup is host-side and out of this ADR's scope.
- **`has_ks = 1` requires `has_local = 1`.** Mirrors ADR 0026 §2's `stage = 2` rule. Enforced by `parse`; violating it is refused like a bad `stage`.
- **Composition with ADR 0046's stage 3, if Accepted.** `stage` is read the same way in record version 1 and 2; this ADR adds no new `stage` value, only `has_ks`/`[ks]`/`forward` alongside whichever `stage` ADR 0046 defines. The composition rule this ADR sets: `stage = 3 ⇒ has_ks = 0`, mirroring the existing `stage = 2 ⇒ has_local = 1 ∧ pending = 0` rule (ADR 0026 §2) — nothing has enrolled a keystore secret on a device mid-recovery, since recovery issues a fresh SK, `device_salt` and `E_local` before any device-local keystore wrap could exist (U: ADR 0046's own stage-3 payload fields are not re-read here; this is this ADR's own constraint on how `has_ks` composes with any `stage`, not a restatement of ADR 0046's text).
- **`forward_count ≤ 8`.** Fits the budget: with `server_origin` at its 512-byte cap, both envelope fields at `MAX_KEY_ENVELOPE_LEN` (256 B) and a full pending record, 8 forward entries (~268 B each) still total under `MAX_DEVICE_STATE_LEN = 4096` (worked in review, V). CRYPTO.md names no cap; this ADR sets one so the record stays bounded.
- **Platform gate.** Only a leaf on a presence-enforcing keystore parses `has_ks = 1`. **Mechanism:** `DeviceRecord::parse` takes a new `keystore_capable: bool` from its host, so `rizzy-client` itself stays platform-agnostic — no `cfg(target_os)` inside it, matching ADR 0016 R1's no-I/O rule and the existing injection pattern for randomness and time. `rv` and `rizzy-wasm` always pass `false`. `rizzy-ffi` — one crate shared by macOS, iOS, Android and Windows (ADR 0019 §1.4) — passes `true` only on its macOS/iOS/Android builds and `false` on Windows, the same per-target split it already makes for its HTTP and sqlx wiring (ADR 0019 §1.4); `rizzy-ffi-cpp` (Linux) always passes `false`. A caller that passes `false` and meets `has_ks = 1` refuses the record as a parse error (`CacheCorrupt`), matching ADR 0019 §1.4's "Local-unlock key storage" row (CLI "Never a keystore-unlock secret", extension "none"). The exclusion itself rests on [THREAT_MODEL](../THREAT_MODEL.md) INV-62, which already states that on Windows's plain DPAPI, Linux's Secret Service, or the CLI's keyring/file, "keystore unlock is not offered" for lack of OS-enforced presence — not on ADR 0019 §2.1, which separately defers only Windows *Hello* unlock because no CRYPTO.md construction exists yet, an independent second reason. (Proposed INV-81, §4 below.)
- **Lifecycle:** created, read, re-wrapped and deleted exactly as CRYPTO.md §11.3 already specifies (steps 1, 4.3, 5, 5.3.3) and §5.6 step 3. Because `forward`/`forward_count` sit outside `[ks]` (above), turning keystore unlock off (`E_ks` deleted, `has_ks → 0`) never drops a live forward chain; it is cleared only the way §11.3 step 4.3 already describes, at the next password unlock. Between a keystore-only unlock that crosses a rotation and that next password unlock, the device still runs §11.3 step 4 in full — fetching and storing each new epoch's `ACCOUNT_KEY_DEVICE_GRANT`, extending the forward chain — exactly as a password-unlocked device would; only a *further keystore-only* unlock is refused once it would push `forward_count` past 8 (open question 2). `rizzy-client` gains one sibling unlock entry point next to `DeviceState::unlock(&self, password: &str)`, taking the released keystore secret as `&[u8]` (ADR 0019 §3 "Secrets cross as bytes"), and `ClientError::KeystoreUnlockUnavailable` alongside `LocalUnlockUnavailable`.

### 3. Migration (v1 → v2), using ADR 0026 §5's mechanism

ADR 0026 §5 already covers both directions: "A format or record version newer than the build knows is refused: 'update required', read nothing, write nothing." A pre-M3 build meeting a v2 record refuses it exactly that way.

The upgrade path is in `rizzy-client`'s codec, not a SQL step: `DeviceRecord::parse` accepts `record_version ∈ {1, 2}`, filling `has_ks = 0`, `forward_count = 0` for a v1 record; `encode` always writes version 2. A build that knows v2 upgrades every record in place on its first write after loading it, with no separate migration step and no window where a partially-written record exists (ADR 0026 §4's one-transaction write rule, unchanged).

### 4. Proposed invariants (for THREAT_MODEL, written here, not edited there until acceptance)

- **proposed INV-81:** A device-state record with `has_ks = 1` is parsed, and the keystore branch of unlock offered, only when the host passed `keystore_capable = true` into `DeviceRecord::parse` (§2). Every other build refuses such a record as corrupt.
- **proposed INV-82:** The keystore unlock secret itself never enters the device-state record or the local cache; only `E_ks` does. (Extends AST-19's scope to record version 2.)

Allocated across the 2026-10-11 batch in ADR-number order. Provisional: the allocation was made across the 2026-10-11 batch in ADR-number order; if ADRs are accepted out of order, the owner renumbers at acceptance.

### 5. Tests and fuzzing

Mirrors [ADR 0026](0026-client-device-state-and-cache.md) §6 for the new surface:

- Known-answer vectors for a v2 record with `has_ks = 1` and ≥ 1 `forward` entry, and at the `forward_count` boundary (8 accepted, 9 refused).
- A canonical-form test for v2 (encode → parse → encode is byte-identical).
- A round-trip test of the v1 → v2 upgrade-on-write (§3): load a v1 fixture, write once, assert the stored bytes decode as v2 with `has_ks = 0`.
- `client_device_state` (ADR 0026 §6) extended to v2 inputs: `has_ks`, the forward list and its count byte, and the `has_ks = 1 ⇒ has_local = 1` constraint, under both `keystore_capable` values.
- Crash injection (ADR 0026 §6 method): fail after the first write that upgrades a loaded v1 record to v2; reload and assert the record is still valid v1 or valid v2, never a torn mix.

## Consequences

### Positive

- No new cryptographic construction, purpose or CRYPTO.md section: every primitive `E_ks` needs is already Accepted and M3-scoped.
- One record codec, one `MAX_DEVICE_STATE_LEN`; the platform gate's host-supplied `keystore_capable` flag keeps a weaker build from trusting a field it cannot safely act on, without `rizzy-client` inspecting `cfg(target_os)` itself.
- The migration is lazy and transactional: an M3 build reads every existing v1 cache unchanged and upgrades it on the next write it was already making.
- Moving `forward_count`/`forward` outside `[ks]` means disabling keystore unlock can never silently strand a forward chain.

### Negative

- `keystore_capable` is a new parameter on `DeviceRecord::parse`, so every existing call site (`rv`, tests, fuzz harnesses) is updated to pass it explicitly (ripple, §5).
- Two code paths in `DeviceRecord::parse`/`encode` (v1 shape, v2 shape) persist until a v3 or a full rewrite retires v1 reading, which ADR 0026 §5 never requires.
- `forward_count ≤ 8` is a new client-side limit with no CRYPTO.md counterpart; §5 above is its test coverage.

### Risks

- If a rotation storm is more than a corner case, the 8-entry cap forces a password prompt for keystore-only unlock more often than users expect; signal: M3/M7 telemetry, trigger for revisiting the cap, not the construction.
- [ADR 0051](0051-equivalence-list-version-persistence.md) (this batch, Proposed) also extends ADR 0026's client state, but its own Decision and Alternatives sections place its counter in `cache_meta`, not the device-state record, for exactly the reason given below (open question 4) — so it does not compete with this ADR for record version 3.

## Alternatives considered

- **Raise `MAX_DEVICE_STATE_LEN` instead of capping the forward chain.** Rejected: it would supersede ADR 0026 §2's Parsing bullet for a case CRYPTO.md never asks to be unbounded.
- **A platform-specific record shape.** Rejected: ADR 0026 §1 is explicit that "one state has one encoding"; a divergent shape needs its own fuzz target and KAV set per platform for no gain over one shape with a host-supplied parse-time gate.
- **Store a platform keystore handle in the record.** Rejected for now: CRYPTO.md's `E_ks` context already addresses the item from `(account_id, device_id)`; a handle is host-side plumbing until a concrete platform API needs one.
- **A Cargo feature instead of a `keystore_capable` parameter.** Rejected: it would need `rizzy-ffi` to build itself twice per non-Windows target to flip the feature, where a runtime bool, host-supplied once at the call site, needs no second build and keeps the gate testable without feature-gated test binaries.

## Open questions for the owner

1. **Ship `ACCOUNT_KEY_FORWARD` in the same record version as `E_ks`, or split them?** `E_ks` is unusable across a rotation without the forward chain. *Recommendation:* ship together, as drafted.
2. **Forward-chain overflow behaviour.** At `forward_count = 8`, does the device still fetch and store each new epoch's wrapped key via the normal device-grant path (CRYPTO.md §11.3 step 4.1–4.2, 4.4–4.5), or refuse new-epoch data outright until a password unlock? *Recommendation:* still fetch and store it — receiving a device grant is a normal online-sync action independent of which unlock path is in use. Only a *further keystore-only* unlock is refused once it would exceed the cap, going read-only for that path (like the existing "no grant served for an epoch" case, step 4.1) until a password unlock collapses the chain; no new UI state.
3. **The platform gate's strength.** Hard parse refusal (as drafted) versus a softer "ignore `has_ks` on this platform" read. *Recommendation:* hard refusal.
4. **ADR 0051's placement (confirmed, not open).** Record version 3 can hold only one new owner, and [ADR 0051](0051-equivalence-list-version-persistence.md)'s own Decision (§1, §4) and Alternatives already settle this on their side: its equivalence-list-version counter goes in `cache_meta`, not the device-state record, explicitly rejecting the latter because "its one reserved version bump is already spoken for by `E_ks`/`ACCOUNT_KEY_FORWARD`." No owner decision is needed here; record version 3 stays free for whichever next change needs it.
5. **The sibling unlock entry point's exact signature and the new `ClientError` variant name.** Placeholders pending the M3 `rizzy-ffi` API review. *Recommendation:* settle it there; this ADR only requires the secret cross as bytes (ADR 0019 §3) and `keystore_capable` be host-supplied (§2).

## References

- [ADR 0026](0026-client-device-state-and-cache.md) §1, §2, §4, §5; ADR 0046 (Proposed, M1); [ADR 0019](0019-native-clients.md) §1.4, §3, §4.2, §5, §5.2; [ADR 0020](0020-partial-supersession.md) point 9; [ADR 0016](0016-workspace-layout.md) R1.
- [CRYPTO.md](../CRYPTO.md) §4.2, §4.3, §4.4, §8.3, §8.4, §5.6, §11.3.
- [THREAT_MODEL.md](../THREAT_MODEL.md) AST-19, AST-22, A8, INV-62, INV-69 (V: checked against every `INV-N` row in `THREAT_MODEL.md` on 2026-10-11; 69 is the current highest).
- [ROADMAP.md](../ROADMAP.md) §4.3.
- Code (V, HEAD 5a78bb5): `crates/rizzy-client/src/store/{record,mod}.rs`, `crates/rizzy-client/src/device.rs`, `crates/rizzy-client/src/error.rs`, `crates/rizzy-client/Cargo.toml` (no existing feature flags, checked 2026-10-11).
