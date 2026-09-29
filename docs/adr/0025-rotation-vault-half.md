# ADR 0025: Key rotation upload: the vault half and the rotation cut-off

- Status: Proposed
- Date: 2026-09-29
- Deciders: project owner
- Milestone: M1

## Context

[ROADMAP](../ROADMAP.md) §4.3 "Master password change & key rotation" is a Must for M1. [INV-19](../THREAT_MODEL.md#8-security-invariants) requires the standard rotation, run by default by an SK change ([CRYPTO.md §11.5](../CRYPTO.md#115-master-password-or-secret-key-change)), device revocation step 3 ([§11.8](../CRYPTO.md#118-device-revocation)) and recovery step 5 ([§11.9](../CRYPTO.md#119-recovery-with-the-emergency-kit)). All are blocked today.

- **What exists (V: code at e05bbcb).** `AuthService::commit_change` checks the auth half (state step, `E_srv'`, `E_id'`, device grants, bundle, re-issues, the revocation's H). Under the account lock, in the same transaction and before the compare-and-swap on `state_seq`, it calls `VaultPort::apply_rotation` with an opaque `V::Rotation`, which `bridge.rs` sets to the uninhabited `NoRotation`. `CommitChangeRequest` has no rotation fields, so every rotating state is refused. `/api/v1/vault/fetch` refuses the recovery-only session, and `RecoveryCompleteResponse` carries no wraps, heads or cursor (`rizzy-proto` `recovery.rs` leaves this open "with the rotation's wire form").
- **What the specs fix.** [§11.6](../CRYPTO.md#116-key-rotation) step 3 re-wraps every item key under vault key' (`ITEM_KEY_WRAP` at the new `vault_key_epoch`) and every self-grant under account key'. Step 9: the request "carries the rotating device's fetch cursor", the server applies the cut-off under the account lock "in one atomic request", deletes the superseded wraps, and the re-wraps overwrite the wrap set ([§4.2](../CRYPTO.md#42-key-inventory)). [ADR 0012](0012-sync-engine.md) §6 refuses the rotation "while it holds any op, snapshot or `ITEM_KEY_WRAP` in a rotated vault beyond that cursor"; [ADR 0021](0021-server-compaction.md) §9 "Rotation cut-off" and "Stale epoch" refine it. §11.9 step 3 has `/recovery/complete` return "the self-grants and the item-key wraps".
- **Left open by every Accepted ADR:** the wire form; "beyond the cursor" for a wrap, which has no `device_seq`; which wraps the upload holds; how the server tells a grant is under the new key; wraps the rotator cannot open; the recovering client's cursor; a restore's rolled-back vault epoch (`rizzy-domain-vault` `keys.rs`, reported open); body size (the commit endpoint takes 1 MiB, `BODY_LIMIT`).
- **Forces.** The server never decrypts and never trusts locators ([§4.2](../CRYPTO.md#42-key-inventory)); checks use only cleartext it already holds ([THREAT_MODEL §3.4](../THREAT_MODEL.md#34-what-the-server-holds-by-sync-mode)); one transaction under the account lock ([ADR 0011](0011-storage.md)); input size-limited and fuzzed; no new crate, no new crypto.

## Decision

### 1. The upload message (`rizzy-proto::change`)

`CommitChangeRequest` gains optional fields (`deny_unknown_fields`); each is present exactly when the classified step needs it.
- **Auth half, mirroring `AccountChange`:** `bundle`, `identity_secret_keys`, `retired_secret_keys` (at most 16, moved into `rizzy-proto`), `device_grants: List<DeviceGrant, MAX_DEVICE_GRANTS>`, and `recovery_rewrap: AccountKeyRecoveryWrap` (§11.6 step 5 "keep the current code", exclusive with `recovery`).
- **Vault half:** `vault_rotation: { vaults: List<VaultRotation, MAX_VAULT_GRANTS> }`, strictly ascending by `self_grant.vault_id`, one per vault, with `VaultRotation { self_grant, cursor: SeqVector, item_key_wraps: List<ItemKeyWrap, MAX_ITEM_KEY_WRAPS>, dropped: List<WrapLocator, MAX_ITEM_KEY_WRAPS> }`. `cursor` is canonical (ADR 0012 §3). `dropped` names `(item_id, item_key_id)` rows the rotator cannot open (§2 step 3).
- **Recovery (§11.9 step 3).** `RecoveryCompleteResponse` gains `vaults: List<{vault_id, self_grant, heads: SeqVector, item_key_wraps}>`, read in one consistent read. The recovering client sends those heads as its cursor. Open question 7.
- **Body limit.** `POST /api/v1/account/commit` and `/recovery/complete` take `RIZZY_MAX_UPLOAD_BYTES` (default 32 MiB). Estimate (U, arithmetic only): a 127-byte wrap envelope (§8.4, §9.1) is about 290 bytes of JSON, so 65,536 wraps are about 19 MiB.
- No field carries a key in the clear. The new types go through the `proto_json` fuzz target.

### 2. The rotating client (`rizzy-client`)

1. An enrolled device uploads its queued ops and runs a complete Fetch (`complete = true`) of every vault; the cursor it then holds is sent. A recovering client holds no replica: it uses the §1 recovery rows and heads.
2. If it detects a restore (rollback of its seen state or vault epoch), it first heals (ADR 0012 §7), then rotates (§3 check 2).
3. Build §11.6 steps 2–8. Re-wrap each wrap-set row it can open, one per `(item_id, item_key_id)`. A row that does not open (AEAD failure, or an epoch whose vault key it lacks) goes into `dropped`, and the UI reports the item as unreadable, as §11.6 does for writers.
4. Secrets-before-commit ([CRYPTO.md §11](../CRYPTO.md#11-flows)); the pending record holds the new keys.
5. On `state_conflict`, re-fetch `account-state` and the vault (a recovering client repeats `/recovery/complete`), then apply [§10.2](../CRYPTO.md#102-ed25519-signatures-and-signed-statements):
   - same `state_seq`, same body: rebuild the vault half only (same keys, same signed bytes) and resend;
   - lower `state_seq` (rollback) or same `state_seq` with another body (fork): go read-only;
   - higher, where only `state_seq` and `device_set_hash` changed: rebuild the device grants (one per remaining device, `check_grants`) and the vault half, re-sign under the same new keys, resend;
   - higher, anything else changed: discard the pending keys (and any unconfirmed kit) and restart §11.6 from step 1 with new keys; a new code means a new kit under secrets-before-commit.
   - After 5 attempts that only rebuilt, stop and report "the vault keeps changing"; the pending record stays.

### 3. Server checks (`rizzy-domain-vault`, new module `rotation`)

`apply_rotation` receives the verified new state's `account_key_epoch` and `account_key_id`; `bridge.rs` sets `type Rotation` to the parsed `VaultRotation`, retiring `NoRotation`. All in the commit's transaction under the account lock; V is the account's vaults.

1. **Shape** (`InvalidRequest`): one entry per vault in V, none other.
2. **Self-grant** (`InvalidRequest`): `account_key_epoch` equals the new state's; `vault_key_epoch` > the stored `vault_vaults.vault_key_epoch` (not "= + 1": after a restore the column may be rolled back, and the client, which knows the higher epoch it saw, must not reuse it); the envelope parses (`rizzy_core::envelope::parse`) and its header `key_id` equals the signed `account_key_id` ([§4.4](../CRYPTO.md#44-identifiers-epochs-and-key-ids)).
3. **Wraps** (`InvalidRequest` unless noted): each wrap is at the new epoch, parses and is 127 bytes; all header `key_id`s of the vault's wraps are equal and differ from every stored row's (guards a re-wrap under the old key, proves nothing about content); `item_key_wraps` and `dropped` are disjoint, both are subsets of the stored rows, and together they must equal them. A stored row in neither is `state_conflict`: the client has not seen it. This is this ADR's reading of "`ITEM_KEY_WRAP` beyond that cursor".
4. **Cut-off** (`state_conflict`): for every device d, `cursor[d]` = head h(V, d), missing = 0. Below a head is ADR 0012 §6's refusal; above means the server is behind (ADR 0021 §9 "Server behind"), and that client must be read-only (conservative). Every retained snapshot's clamped VV ≤ cursor (implied, checked anyway).
5. **Writes**, after checks 1–4 pass for every vault: `vault_key_epoch` set to the uploaded value; the self-grant replaced; each re-wrapped row overwritten (exactly one row each); each `dropped` row deleted; `key_wrap` set to NULL on every `vault_ops` and `vault_snapshots` row of the vault (the superseded wraps; signed wrap hashes stay). The cursor is not stored. Storage failures become `Internal` naming the port; no error or log carries a value ([INV-48](../THREAT_MODEL.md#8-security-invariants)).

### 4. Atomicity and ops in flight

- **One write transaction:** `lock_account` → auth checks and writes → vault checks and writes → `cas_state` → commit. Any refusal drops it; nothing is ever half-rotated. A byte-identical repeat of the committed state succeeds before the vault half is read.
- Uploads, healing, compaction and suspensions take the same lock, so each runs wholly before or after. A Fetch is one consistent read.
- **Stored before the lock, beyond the cursor:** refused, the client retries (§2 step 5). **Uploaded after, at the old epoch** (a new item's wrap under the old key included): `stale_epoch` (ADR 0021 §9); the writer creates a fresh item key and re-issues the op with the same `device_seq`.
- **A revoked device's ops:** all are held (§11.8 step 3's H equals the head), so the cursor check makes the rotator fetch them. A junk wrap it planted is `dropped` and cannot block its revocation.
- Other devices process the new state ([§11.3](../CRYPTO.md#113-unlock-on-an-enrolled-device) step 4); every row is now newer than their `wraps_after_epoch`. A client refuses a self-grant whose `vault_key_epoch` it already saw with another key id, and goes read-only (fork alarm).

### 5. Tests

In `tests/vault/` and the `rizzy-domain-auth` suite, through the real bridge, on SQLite and on PostgreSQL when configured:
- Standard, full, revocation and recovery rotations (the recovery one with a cursor from `/recovery/complete`, and a refusal after an op stored between that call and the commit). After each, Fetch serves every row at the new epoch and no record wrap; an old-epoch upload gets `stale_epoch`.
- One test per §3 refusal, incl. a cursor above a head, a row healed in after the Fetch, and a `dropped` row not stored.
- A revoked device's junk `ITEM_KEY_WRAP` is dropped and the revocation commits.
- A vault-half failure leaves `state_seq`, the OPAQUE record and every vault row unchanged; a byte-identical repeat succeeds.
- 1,000 racing upload/rotation runs: exactly one of "upload stored, rotation refused" or "rotation committed, upload `stale_epoch`".
- The client's §10.2 branches, with a concurrent enrolment and a concurrent rotation.
- INV-19: an old password plus a pre-rotation backup's wraps do not yield the current keys.
- Restore drill (ADR 0011): back up at vault epoch E, rotate to E+1, restore, heal, revoke-and-rotate. Pass: the rotation commits at E+2; no client ever sees two keys at one epoch; Fetch serves only E+2 rows; ops at E and E+1 get `stale_epoch`.
- No known-answer vectors: no new construction.

## Consequences

### Positive

- Unblocks INV-19 and the rotations of §11.5 and §11.8; §11.9's once open question 7 is decided.
- Nothing new is visible to the server; heads, wrap rows and epochs are already held (the recovery response adds heads to a response that already carries wraps).
- A wrap left under a revoked key is impossible: every stored row is re-wrapped or deleted.

### Negative

- The commit endpoint takes the large-body slot. The rotation writes O(items) rows under the account lock, blocking that account's uploads meanwhile.
- A busy account can make a rotation fail after 5 attempts. A `dropped` row loses that item for every device.

### Risks

- **Exact cursor locks out a legitimate rotation** (for example after a restore). Signal: restore-drill failures → reopen question 1.
- **An honest client drops a row other devices could open** (it lacks an old vault key). Signal: unreadable-item reports after rotation → reopen question 8.
- Vaults above `MAX_ITEM_KEY_WRAPS` rows cannot rotate in M1 (their Fetch already fails with `WrapSetTooLarge`).

## Alternatives considered

- **Two phases (vault request, then auth commit).** Rejected: breaks §11.6 step 9's "one atomic request"; a crash leaves the account half-rotated.
- **A server-side upload freeze.** Rejected: durable state and a stuck-lock mode; client retry covers honest races.
- **`cursor ≥ heads`.** Rejected: accepts a rotation from a client the server is behind.
- **Keeping unopenable rows unchanged.** Rejected: leaves rows under the revoked key.
- **A streamed upload.** Rejected: more wire and state; M1's bound fits one body.

## Open questions for the owner

1. **Exact cursor** vs `≥`? Recommendation: exact (§3 check 4).
2. **Refusal code:** `state_conflict` or a new `rotation_behind`? Recommendation: `state_conflict`.
3. **Retries:** 5 client attempts, no server hold? Recommendation: yes; revisit with M3 data.
4. **Healing below the current epoch:** may healing fill a row at an older `vault_key_epoch` after a rotation? Recommendation: no.
5. **Commit body limit** = upload limit? Recommendation: yes.
6. **Rotation during a reconciliation epoch** (INV-59). Recommendation: allow it under §3 check 2's `>` rule, after the client heals (§2 step 2), so a stolen device can be revoked after a restore. It depends on the open `keys.rs` question of how healing re-raises the rolled-back column; until that is decided, the `>` rule is what stops epoch reuse.
7. **Recovery cursor:** `/recovery/complete` returns per-vault heads with the wraps (§1), or the recovery-only session may call Fetch? Recommendation: the heads, which keep that session off the vault endpoints. Until decided, the §11.9 default rotation stays blocked.
8. **Dropping unopenable rows** (§2 step 3) vs refusing the rotation? Recommendation: drop, so a planted wrap cannot block a revocation.

## References

- [CRYPTO.md](../CRYPTO.md) §4.2, §4.4, §8.4, §9.1, §10.2, §11, §11.3, §11.5, §11.6, §11.8, §11.9; [THREAT_MODEL.md](../THREAT_MODEL.md) §3.4, INV-19, INV-48, INV-59; [ROADMAP.md](../ROADMAP.md) §4.3.
- [ADR 0011](0011-storage.md), [ADR 0012](0012-sync-engine.md) §3, §6, §7; [ADR 0016](0016-workspace-layout.md) R4; [ADR 0021](0021-server-compaction.md) §9; [ADR 0022](0022-server-mode-only.md).
- Code (V, e05bbcb): `crates/rizzy-domain-auth/src/{change,ports}.rs`; `crates/rizzy-domain-vault/src/{keys,port}.rs`; `crates/rizzy-server/src/bridge.rs`; `crates/rizzy-proto/src/{change,recovery,vault,limits}.rs`; `crates/rizzy-server/src/http/api.rs` (`BODY_LIMIT`, `SessionNeed::NotRecovery`).
