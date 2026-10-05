# ADR 0032: Healing a key rotation made after a backup

- Status: Accepted
- Date: 2026-10-05
- Deciders: project owner
- Milestone: M1
- Supersedes: [ADR 0012](0012-sync-engine.md) (§7 in part), [ADR 0021](0021-server-compaction.md) (§9 "Healing request" in part) and [ADR 0028](0028-api-v1-http-conventions.md) (item 3 in part: one new `409` code), on acceptance; the parts are listed under "What this ADR supersedes".

## Context

[ROADMAP](../ROADMAP.md) §4.9 requires a restore that is "tested, not just written"; [ADR 0012](0012-sync-engine.md) §7 "Test" puts "a rotation made after the backup" into the [ADR 0011](0011-storage.md) restore drill; [INV-59](../THREAT_MODEL.md#8-security-invariants) and [THREAT_MODEL §5.8](../THREAT_MODEL.md#58-server-restore-from-backup) require that devices heal a restore. Account-side healing (commit 02904f2) builds [ADR 0012](0012-sync-engine.md) §7 steps 1–3 and found that a restore to before a key rotation cannot heal (V: code at e60d7be). Every rotation counts: a standalone one, every revocation ([CRYPTO.md §11.8](../CRYPTO.md#118-device-revocation)), every Secret Key change that rotates (§11.5), and a full rotation with new identity keys (§11.6 step 7).

- **`E_id`.** Steps 1–3 re-publish the bundle chain, the state with its device set, and grants and self-grants, but no Accepted text names `E_id`. After the restore the server's `E_id` is under the old account key, so the healed account answer fails at "`E_id` opens" (§11.2 step 6; `rizzy-client` `healing.rs`). The same holds for `ACCOUNT_SETTINGS` (re-encrypted when `settings_seq > 0`, §11.6 step 3) and `RETIRED_SECRET_KEY` after a full rotation.
- **`E_srv`, the OPAQUE record, `E_rec`.** §7 "What is not re-uploaded" defers the record and `E_srv` to the next typed password, but neither the trigger nor what the server does meanwhile is defined. A restored `E_srv` or `E_rec` opens to the pre-rotation account key; a password change undone by the restore leaves the old record. Neither can be rebuilt without the password (`export_key` is never stored, §4.2) or the recovery code (never persisted, §11).
- **The vault epoch.** `rizzy-domain-vault` (`keys.rs`) refuses a self-grant whose `vault_key_epoch` no stored signed record has reached, never raises `vault_vaults.vault_key_epoch` in healing, and step 4 (records) comes after step 3. So the restored, lower epoch stays the stale-epoch reference, and the restored wrap set and record wraps stay under the rotated-away vault key (ADR 0025 §3 step 5 had deleted them).
- **Device grants.** `rizzy-client` persists no `ACCOUNT_KEY_DEVICE_GRANT` ([ADR 0026](0026-client-device-state-and-cache.md) §1), and re-creating one needs the previous account key (§10.1 PSK), which the rotator drops. A device that missed the rotation finds no grant after the restore.
- **Full rotation.** A served state signed by an older identity key than the pinned one is answered `InvalidServerResponse`, not `Rollback`, so no healing starts (V, `healing.rs` "When no healing is tried").
- **What is at stake.** Until healed, the restore makes the pre-rotation keys current again: a device revoked after the backup holds them (INV-19, INV-30). Healing is a security repair, not a convenience. `docs/self-hosting.md` §9 documents the gap.
- **Forces.** The server never decrypts and never trusts a locator (§4.2); it checks only cleartext it holds against the signed `account-state` (THREAT_MODEL §3.4); one transaction under the account lock (ADR 0011); no new construction, no new crate.

## Decision

### 1. Detection (client)

A device also treats as a rollback ([CRYPTO.md §11.3](../CRYPTO.md#113-unlock-on-an-enrolled-device) step 2.5) a served chain whose head is below its pinned `bundle_seq`, when every served bundle is byte-identical to the one it holds at that `bundle_seq` and the served state verifies under the served head with a `state_seq` below the pin. It accepts nothing signed by that older key (INV-30); it only goes read-only and heals. Any other mismatch stays `InvalidServerResponse`.

### 2. The healing order (replaces ADR 0012 §7 steps 2 and 3)

The healer is a durable device (kind 1–3) whose pinned state is newer than the server's. Steps 1 (bundle chain) and 4 (records, [ADR 0021](0021-server-compaction.md) §9) are unchanged.
- **Step 2, one request** (`POST /api/v1/healing/account-state`, `PublishAccountStateRequest`): the newest signed state; every certificate and revocation it holds, including revoked devices' and kind-4 certificates re-issued by a full rotation (§11.6 step 7), all in `device_certificates`; and, verbatim as last served and cached (ADR 0026 §1), `E_id` of the state's `identity_epoch` and, when `settings_seq > 0`, `ACCOUNT_SETTINGS`, in two new optional fields `identity_secret_keys` (`IdentitySecretKeys`) and `account_settings` (`AccountSettings`). The adoption rules of ADR 0012 §7 step 2 apply unchanged; outside the reconciliation epoch the held state is re-sent byte-identically (ADR 0028 "Retry", row "Healing"). Each statement must verify under the chain head; a certificate outside the device set is stored only with the device keys of the stored certificate of that `device_id`, if any.
- **Step 3a, grants:** device grants it holds (`healing/grants`, unchanged).
- **Step 3b, one request per vault** (`POST /api/v1/vault/heal`, `HealingRequest` with a new optional `self_grant: VaultSelfGrant` and an empty `records`): the vault's self-grant, and in `item_key_wraps` every wrap-set row it holds at that grant's `vault_key_epoch` (§3). It uses the upload limit and the large-body slots `vault/heal` already has (ADR 0028 items 7–8), so ADR 0028 item 1 (the 27 endpoints) is unchanged. Step 3b precedes step 4, so no record waits on the epoch.
- **Step 5, interactive** (§4): at the next password unlock, the same-password re-registration.
- **Step 6, by user action** (§4): recovery repair.

The device leaves read-only after steps 1–4 (ADR 0021 §9 "Server behind"); steps 5–6 do not block writes.

### 3. Server checks: the lag rule

An object **lags** when the server's copy disagrees with the signed `account-state` it holds. Lag exists only after a restore, because every flow that rotates writes these objects and the state in one transaction (ADR 0025 Context and §4; not re-read in code for this ADR, U). The server repairs a lagging object, independently of the reconciliation epoch, when all of the following hold under the account lock; otherwise it stores nothing:
- the session is a device session of a durable device in the held state's device set (a device the state revokes, a kind-4 or an OPAQUE-only session is refused);
- the object is checked against the state, never against the request:
  - **`E_id`** lags when its envelope header `key_id` ≠ `account_key_id`. The replacement parses as a symmetric envelope of purpose `IDENTITY_SECRET_KEYS` with header `key_id` = `account_key_id`; `identity_epoch` is stored from the state.
  - **`ACCOUNT_SETTINGS`** lags when its SHA-256 ≠ `settings_hash`. The replacement must hash to `settings_hash`.
  - **Self-grant** of vault V lags when its stored `account_key_epoch` < the state's. The replacement's `account_key_epoch` equals the state's, its envelope parses and its header `key_id` = `account_key_id`, and its `vault_key_epoch` is **greater than** V's stored `vault_key_epoch` (ADR 0025 §3 check 2's rule, for its reason: the column is rolled back, and the vault epoch may have moved further than the account epoch, since `rizzy-client` picks one above every epoch it saw, V `sync.rs` `next_vault_epoch`); and no stored wrap row or record of V names a `vault_key_epoch` above it. No fixed delta is required: epochs need not move in lockstep (§11.6 "Current vault epoch" says only that they rotate together). Records at exactly the new epoch are kept: they can be genuine uploads by a device that adopted the state after step 2 (U: not tested in `rizzy-domain-vault`). The same transaction then: sets V's `vault_key_epoch`; checks the wraps as [ADR 0025](0025-rotation-vault-half.md) §3 check 3 does, at the new epoch, without its completeness clause; replaces each stored row with the same (`item_id`, `item_key_id`); deletes every stored row below the new epoch that the request does not replace; sets `key_wrap` NULL on every record whose header `vault_key_epoch` is below the new epoch. Size limits are ADR 0025 §1's.
- When the object does not lag, a byte-identical or otherwise valid repeat is success and stores nothing. The first valid repair wins; the server cannot tell a junk envelope under a copied `key_id` from a genuine one, and clients detect it (§11.2 step 6).

**Client precondition.** A device sends step 3b only for a vault whose last complete Fetch was at the current `vault_key_epoch`. A row it lacks is re-published by any holder in step 4 ("every item-key wrap the server lacks").

### 4. Credentials that need the user

- **Record lag.** `auth_credentials` and `auth_recovery` gain `account_key_epoch`, written from the state by every credential replacement (a migration fills existing rows from the current state). The OPAQUE record lags when its (`password_epoch`, `kdf_id`, `account_key_epoch`) ≠ the state's. While it lags, the server refuses `login/finish` after KE3 verifies, with a post-authentication `409 credentials_stale` (a new code, ADR 0028 item 3 superseded in part, below) that reveals nothing to an unauthenticated prober (§5.9); a password undone by the restore is already refused by INV-59.
- **Step 5.** `DeviceAuthFinishResponse` (`device-auth/finish`) carries `reregister: true` while the record lags (the field of [ADR 0031](0031-retiring-old-opaque-setups.md) point 2 if that ADR is Accepted; otherwise this ADR adds it, same name and type, `bool`, sent only after the device signature verified). A device that holds the typed password in this unlock, checked by opening `E_local`, runs the same-password re-registration of §5.8 over its device session: new record, `E_srv` under the current account key, a state with `state_seq + 1` and unchanged epochs, by compare-and-swap. A keystore unlock defers it.
- **Step 6.** `H_rec` and `E_rec` are one credential, the `auth_recovery` row; it lags when its `recovery_epoch` or its `account_key_epoch` ≠ the state's. While it lags, `recovery/start` is refused like a wrong token (a `recovery_epoch` mismatch already is, V `rizzy-domain-auth` `recovery.rs`). The repair is a credential replacement ([CRYPTO.md §11](../CRYPTO.md#11-flows) "Replacing credentials"): `account/commit` over a fresh OPAQUE session (so after step 5) with a state at `state_seq + 1`, always carrying **both** `H_rec` and `E_rec`; the server stores `recovery_epoch` and `account_key_epoch` from that state. Two forms, chosen by the stored row, not by §11.6 step 5's "keep" option as such:
  - **Re-type the current code**, only when the stored `recovery_epoch` already equals the state's (the code is unchanged since the backup; an SK change, a recovery and "kit exposed" each issue a new code, so none happened after it while recovery was on). The client derives `H_rec` and `E_rec` under the current account key; `recovery_epoch` stays; the server requires the sent `H_rec` byte-equal to the stored one, else `invalid_request`.
  - **A new code and a new kit** (`recovery_epoch + 1`), the only form when the stored `recovery_epoch` < the state's: the restored `H_rec` is an older code's, which may be exposed (§11.9 step 5 treats an old kit as compromised), and it is replaced, never kept.
- **A device that missed the rotation** and finds no grant: at a password unlock, once the record no longer lags, it runs §11.2 steps 2–6 with that password, opens `E_srv`, requires the key's id = `account_key_id` and continues with §11.3 step 4.3. It gets what a new-device login gets, nothing more. Before that it stays read-only with "open a device that saw the change".

### 5. Crash safety and the reconciliation epoch

- Each request is one transaction under the account lock; a crash loses the whole request. The healer persists nothing new: it re-derives what lags from each account answer, and repeats are success (§3). Step 5 follows §10.2's compare-and-swap rules; a lost answer after commit leaves a consistent record and `E_srv`.
- The reconciliation epoch admits what ADR 0012 §7 admits, plus the re-issued non-set certificates of step 2. Lag repairs need no epoch: the signed state bounds them, and they continue after the epoch ends.
- A **native restore** opens no epoch, so the newer state is never adopted and nothing lags; users repeat their changes (`docs/self-hosting.md` §9).

### 6. Tests

The ADR 0011 drill on SQLite (PostgreSQL when configured): back up; then a standard rotation, a full-rotation revocation, an SK change and a password change; restore; heal from one device. Pass: the account answer verifies on every device; `vault_key_epoch` equals the pre-restore value and old-epoch uploads get `stale_epoch`; no record wrap or wrap row below it is served; web login is refused until step 5, then works with the new password; recovery is refused until step 6; a device that missed the rotation catches up by password; the revoked device's session is refused. Recovery: a rotation that issued a new code after the backup, then restore; step 6 offers only a new code; afterwards the pre-backup code is refused at `recovery/start` and the new one recovers; with the code unchanged since the backup, re-typing it succeeds and a different code is refused. Vault epoch: a restore of a vault whose epoch had moved further than the account epoch (an earlier restore) heals. One test per §3 refusal: a lag repair from a revoked, kind-4 or OPAQUE-only session, a wrong `key_id`, a `vault_key_epoch` not above the stored one or below a stored record's, a settings hash mismatch; and `credentials_stale` only after KE3. INV-19: after healing, a pre-rotation `E_srv` or `E_rec` yields no current key. No known-answer vectors: no new construction.

### What this ADR supersedes

[ADR 0012](0012-sync-engine.md) §7 "Healing a server rollback":
1. **Step 2** ("Its newest signed `account-state`") is replaced by: "**Its newest signed `account-state`,** in one request with every device certificate and `device-revocation` it holds and, as last served, `E_id` and `ACCOUNT_SETTINGS`. While the account is in the reconciliation epoch opened by `rizzy-vault restore` (INV-59), the server accepts any state that verifies against the current identity key and has a strictly higher `state_seq` than the one it holds. Outside that epoch, a new `account-state` is accepted only by compare-and-swap (`state_seq + 1`), over a session of a device in the server's current device set, over a fresh OPAQUE session ([CRYPTO.md §11.2](../CRYPTO.md#112-login-on-a-new-device-server-mode) step 7), or over the recovery-only session ([CRYPTO.md §11.9](../CRYPTO.md#119-recovery-with-the-emergency-kit)). From then on it refuses credentials older than that state (INV-59). `E_id`, `ACCOUNT_SETTINGS`, self-grants and the wrap set are repaired by the lag rule of [ADR 0032](0032-healing-rotation-after-backup.md) §3."
2. **Step 3** is replaced by: "**Key grants it holds, then, per vault and in one request, the vault's self-grant and every wrap-set row it holds at that grant's `vault_key_epoch`** ([ADR 0032](0032-healing-rotation-after-backup.md) §3), before step 4."
3. The bullet **"What is not re-uploaded"** is replaced by: "**Credentials.** The OPAQUE record, `E_srv` and `E_rec` are repaired only with the user, as [ADR 0032](0032-healing-rotation-after-backup.md) §4 says: the same-password re-registration at the next password unlock, and the recovery repair by user action; meanwhile the server refuses a lagging record or `E_rec`."

[ADR 0021](0021-server-compaction.md) §9 **"Healing request"**: its first sentence is replaced by: "Step 4 is one request per vault, atomic under the account lock: every item-key wrap the server lacks, then per chain from h + 1 up to the device's cursor, capped at a known cut-off, every header the device holds, with its body if it holds the body of a record the server stored before, else without it behind the request's fresh snapshot or a held snapshot sent verbatim. A request may instead carry the vault's self-grant, its wrap set at that grant's `vault_key_epoch` and no records; it is [ADR 0032](0032-healing-rotation-after-backup.md) §2 step 3b, checked as its §3 says, and is sent before step 4." The rest of the bullet is unchanged.

[ADR 0028](0028-api-v1-http-conventions.md) **item 3**, its code table: "`state_conflict`, `stale_epoch`, `record_conflict`, `prev_seq_mismatch` 409" is replaced by "`state_conflict`, `stale_epoch`, `record_conflict`, `prev_seq_mismatch`, `credentials_stale` 409 (`credentials_stale`: after KE3 verified, the account's OPAQUE record lags its signed state, [ADR 0032](0032-healing-rotation-after-backup.md) §4)". The rest of item 3, and item 8's "the code set stays closed (item 3)", read against the table so amended. If ADR 0031 is Accepted first, its `setup_retired` stays in the list too.

### On acceptance

This ADR makes none of these edits.
1. **Status lines** (the owner's act): ADR 0012 appends "; [ADR 0032](0032-healing-rotation-after-backup.md) (§7 in part)"; ADR 0021 becomes "Partially superseded by [ADR 0032](0032-healing-rotation-after-backup.md) (§9 "Healing request" in part)"; ADR 0028 becomes "Partially superseded by [ADR 0032](0032-healing-rotation-after-backup.md) (item 3 in part)", or appends it if ADR 0031 got there first. **[README](README.md)**: rows 0012, 0021 and 0028 repeat them; row 0032 becomes Accepted. `rizzy-proto` gains `ErrorCode::CredentialsStale` and the fields of §2 and §4 with the code that builds this ADR.
2. **[CRYPTO.md](../CRYPTO.md) §11.3 step 2.3** gains, at its end: "A served chain whose head is below the cached `bundle_seq`, every served bundle byte-identical to the one this device holds at that `bundle_seq`, with a state that verifies under the served head and a `state_seq` below the stored one, is a rollback (step 2.5); nothing it signs is accepted (ADR 0032 §1)."
3. **CRYPTO.md §11.3 step 4.1** gains: "If no grant is served for an epoch, the device stays read-only; at a password unlock, once the server's OPAQUE record no longer lags, it runs §11.2 steps 2–6 instead and requires the key from `E_srv` to have key id `state.account_key_id` (ADR 0032 §4)."
4. **CRYPTO.md §11, "Replacing credentials"** gains: "The server stores `account_key_epoch` from that state with the OPAQUE record and with `H_rec` and `E_rec`, and refuses a login or recovery against one that lags the state (ADR 0032 §4)."
5. **Not at acceptance:** the two gap notes of [self-hosting.md](../self-hosting.md) §9 and §10 and `rizzy-domain-vault`'s "Re-published self-grants" reading change with the code that builds this ADR.

## Consequences

### Positive

- A restore after any rotation heals: INV-19 and INV-30 hold again once one device reconnects, and the restore drill can be complete.
- The server checks every repair against signed cleartext it already holds; nothing new becomes visible to it.
- A stolen session cannot install a key: at worst it plants a junk envelope that clients reject.

### Negative

- A migration (two columns), a new `409` code, four wire fields (`identity_secret_keys`, `account_settings`, `self_grant`, `reregister`) made before v1.0 under ADR 0028's rule, and two interactive steps; a recovery code changed after the backup must be replaced again, with a new kit. Web logins wait for a password unlock on an enrolled device; recovery waits for the user.
- A web-only account (no durable device) cannot heal; it stays as restored (AR-19).
- `RETIRED_SECRET_KEY` is not cached (ADR 0026 §1), so it cannot be re-published; old HPKE ciphertext to a retired identity key becomes unreadable (U: nothing in M1 seals to identity keys, before M6 or M9).

### Risks

- **Junk first repair.** A current device's stolen session can win the first repair with junk. Signal: an `E_id` or self-grant that fails to open after healing. Remedy: revoke that device, which rotates. The same session can also inflate `vault_key_epoch` (as in an ADR 0025 rotation); the same remedy applies.
- **A compromised device revoked by a standard rotation** holds the identity key and can race the healer in the restored window (§11.6 "Known limitation", THREAT_MODEL §5.8 residual risk). Unchanged by this ADR.
- **A vault-only rotation** (M9 member removal) undone by a restore leaves the self-grant at the state's `account_key_epoch`, so §3 sees no lag. Signal: the M9 ADR, whose signed vault statement must define the vault's own lag.

## Alternatives considered

- **Tell operators to restore only the latest backup, or to back up after every rotation.** The docs keep the advice, but a corrupt or encrypted latest backup is the reason to restore, and backup cadence cannot follow rotations.
- **Tell users to re-enrol.** It needs the old password and the old Secret Key, whose kit an SK change told them to destroy, and it leaves the pre-rotation keys current: the revoked device keeps its access (INV-30).
- **Rotate again instead of healing.** It needs a fresh OPAQUE session, which a password changed after the backup does not give, and it cannot re-grant a device that missed the first rotation. It stays the remedy for a junk repair.
- **Let the healer rebuild `E_srv` without the password.** Needs `export_key` or `server_unlock_key` stored on the device, an offline oracle that weakens §5.5.
- **Accept self-grants only in the reconciliation epoch, with the old "verified epoch" bound.** It cannot raise the epoch (Context) and ends with the epoch.

## Open questions for the owner

Answered on acceptance (2026-10-05): the owner accepted every recommendation below.

1. **Lag repairs outside the reconciliation epoch?** Recommendation: yes, bounded by the signed state (§3), since the epoch can end before a vault is healed.
2. **First valid repair wins, or last?** Recommendation: first; the remedy is a rotation.
3. **Delete restored wrap rows below the new epoch that the healer does not re-publish?** Recommendation: yes, as ADR 0025 does; a holder restores a missing row in step 4.
4. **Refuse login while the record lags?** Recommendation: yes, `409 credentials_stale` after KE3; serving it yields only a key the client rejects.
5. **A device that missed the rotation:** catch-up by password (§4), or persist outgoing grants until acknowledged (an ADR 0026 change)? Recommendation: catch-up in M1; revisit with M3.
6. **`RETIRED_SECRET_KEY`:** accept the loss in M1, and cache it (ADR 0026) before M6? Recommendation: yes.

## References

- [ADR 0011](0011-storage.md); [ADR 0012](0012-sync-engine.md) §6, §7; [ADR 0020](0020-partial-supersession.md) point 9; [ADR 0021](0021-server-compaction.md) §2, §9; [ADR 0023](0023-logical-backup-format.md) §5; [ADR 0025](0025-rotation-vault-half.md) §1, §3; [ADR 0026](0026-client-device-state-and-cache.md) §1; [ADR 0028](0028-api-v1-http-conventions.md) items 1, 3, 7, 8; [ADR 0031](0031-retiring-old-opaque-setups.md) point 2 (Proposed).
- [CRYPTO.md](../CRYPTO.md) §4.2, §5.8, §5.9, §10.1, §10.2, §11, §11.2, §11.3, §11.5, §11.6, §11.9; [THREAT_MODEL.md](../THREAT_MODEL.md) §3.4, §5.8, INV-19, INV-30, INV-59, AR-19; [ROADMAP.md](../ROADMAP.md) §4.9; [self-hosting.md](../self-hosting.md) §9.
- Code (V, e60d7be): `crates/rizzy-client/src/healing.rs`; `crates/rizzy-domain-auth/src/healing.rs`; `crates/rizzy-domain-vault/src/{keys,port}.rs`; `crates/rizzy-storage/migrations/sqlite/0001_auth_initial.sql` (`auth_credentials`, `auth_recovery`: no `account_key_epoch` column).
