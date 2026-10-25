# ADR 0091: Device revocation: the revocation window, the revoked-device rotation race and its accepted residual

- Status: Proposed
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M3
- Supersedes: on acceptance, in part: [ADR 0006](0006-key-hierarchy.md) ("Risks", second bullet, as [ADR 0022](0022-server-mode-only.md) §1 replaced its last sentence); [ADR 0012](0012-sync-engine.md) (§6, third sub-bullet of "Revocation has two phases"); [ADR 0028](0028-api-v1-http-conventions.md) (item 3 in part, as [ADR 0048](0048-per-account-storage-quota.md) §5 replaced it). §0 quotes each part and gives its full replacement ([ADR 0020](0020-partial-supersession.md) point 9).

## Context

**Trigger.** The owner's instruction "start" (2026-10-25), given after the ten-reviewer ADR gap review of that day ([docs/reviews/2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md)). Its §3 row M1 reads: "**Revoked-device rotation race** ("M3 device-management ADR"). | ADR 0022 point 5, ADR 0006 Risks, CRYPTO §11.6, AR-18; ADR 0075 answer 1 passed it on. | G01-6, G02-14, G07-42, G10-26". The four raw findings ([G01](../reviews/2026-10-25-raw/G01.md) G01-6, [G02](../reviews/2026-10-25-raw/G02.md) G02-14, [G07](../reviews/2026-10-25-raw/G07.md) G07-42, [G10](../reviews/2026-10-25-raw/G10.md) G10-26) say one thing four ways: Accepted texts assign the race to an ADR that does not exist, while [ROADMAP](../ROADMAP.md) line 114 schedules "S | Session/device management: list devices, revoke, force logout | M3" in the current milestone.

### The binding texts that point here (V, read at `262bbd0`)

- [ADR 0022](0022-server-mode-only.md) point 5 (line 24): "the device-management ADR that settles the revoked-device rotation race (ADR 0006 "Risks", CRYPTO.md §11.6, AR-18) belongs to M3, with session and device management (ROADMAP §4.3)."
- [ADR 0006](0006-key-hierarchy.md) "Risks", second bullet (line 106), its last sentence as ADR 0022 §1 (line 36) replaced it: "A compromised device that is later revoked holds the old identity key and can race a rotation ([CRYPTO.md §11.6](../CRYPTO.md#116-key-rotation)). The M3 device-management ADR (ROADMAP §4.3) must settle this."
- [CRYPTO.md §11.6](../CRYPTO.md#116-key-rotation) "Known limitation" (line 1132): "A *compromised* revoked device holds the old identity key and could race its own "rotation". Remaining devices accept a rotation only if the key its grants deliver has the `account_key_id` committed in the new `account-state`, and they show the new identity fingerprint for the user to confirm on each device (§11.3 step 3). The details belong to the M3 ADR on device management (ROADMAP §4.3)."
- [THREAT_MODEL](../THREAT_MODEL.md) A8 residual (line 541): "Until the remaining devices publish the rotation, the thief can sign device certificates and `account-state` of their own, and race the owner's rotation. Remaining devices accept a rotation only from a non-revoked device and ask the user to confirm the new identity fingerprint on each device … The M3 device-management ADR settles the rest"; §5.5 (line 801); AR-18 (line 1317), whose last column is "M3 device-management ADR".
- [ADR 0075](0075-session-listing-and-ending.md) (Accepted, M3), line 27: "That race is about signed statements and identity keys, not about sessions, and this ADR does not settle it (open question 1)"; owner answer 1 (line 211): "The revoked-device rotation race is settled by a separate ADR, not this one."

### What the code does today (V, read at `262bbd0`)

- **Suspension (CRYPTO.md §11.8 step 0).** `AuthService::suspend_device` (`crates/rizzy-domain-auth/src/device.rs` lines 705–727) runs under `lock_account` and needs "a fresh OPAQUE session bound to a usable durable device other than `target`" (`revoker`, lines 752–782). It sets `auth_device_certificates.suspended_at_ms` (`queries/cert_suspend.sql`, keeping an earlier time), deletes every session row with that `device_id` (`queries/sessions_delete_device.sql`: `DELETE FROM auth_sessions WHERE account_id = $1 AND device_id = $2`) and returns H (`VaultPort::device_head`, the maximum over the account's vaults). A repeat returns H again. `unsuspend_device` (lines 735–750) clears the column under the same session rule.
- **A suspended device can do nothing with its own key.** Device authentication refuses a suspended certificate (`device.rs` module docs, line 9: "that is not suspended and not expired"); `Devices::usable_durable` (`trust.rs` lines 265–272) excludes it; the vault store refuses every record a suspended author signed, whatever session uploads it (`rizzy-domain-vault/src/store.rs` line 213: "a suspended author's records are refused"); grants are served only over a device session (`device_grants`, `device.rs` line 635).
- **Revocation with rotation.** `commit_change` (`change.rs`) accepts a new revocation only if its `last_accepted_device_seq` equals the head the server still holds (lines 436–441, `StateConflict` otherwise) and, with a rotation, only of a suspended durable device (lines 442–444: `if step.account_key_rotated && target.cert.in_device_set() && !target.suspended { return Err(AuthError::InvalidRequest) }`). The session must be a fresh OPAQUE session of another usable durable device that does not revoke itself (lines 846–856). The new state is applied by compare-and-swap on `state_seq`.
- **What an OPAQUE session bound to no device can do.** `authorize` (`change.rs` lines 806–871) lets any fresh OPAQUE session make every heavy change except a revocation with rotation: a rotation without revocation, a password or SK change, a recovery-code change. `enrol_device` (`device.rs` line 471) enrols a new durable device over any fresh OPAQUE session; `upload_web_certificate` (line 551) stores a kind-4 certificate over any OPAQUE session.
- **The client** revokes at most one device per rotation (`rizzy-client/src/rotation.rs` line 153: `pub revoke: Option<RevokeDevice>`); `rv device revoke <device> --name <login> [--standard]` runs §11.8 (`rizzy-cli/src/args.rs` line 57).
- **The account view** (`rizzy-proto/src/account.rs` `AccountView`, lines 40–71) carries certificates, revocations, self-grants, usage and vault summaries, and no suspension, so a second device cannot see that a revocation is half done.

### The race, defined

A **revoked device** D is a durable device (kind 1–3) the user revokes because it is lost, stolen or compromised. Its thief holds what the device holds: the SK in plaintext ([THREAT_MODEL](../THREAT_MODEL.md) A8: "The device state file holds it in plaintext until an OS keystore does"), `E_local` (one Argon2id evaluation per password guess, A8), the device keys and, if the vault was unlocked, the account key, the identity keys and every vault and item key. Three windows:

- **W0, theft → suspension commit.** D is a legitimate device. Revocation protects only future data (§11.8: "Revocation protects **future** data only"). This ADR only makes W0's after-effects removable (§3 step 2, §4).
- **W1, suspension commit → revocation commit.** D's key is refused everywhere (above). The race lives here and needs one of: (a) a **thief who also knows the master password**. With the SK from the device, they open an OPAQUE session bound to no device from any browser, and with it they can rotate without revoking; change the password or SK; enrol a fresh durable device D′ under the identity key they hold and then suspend the owner's devices from D′; or upload a kind-4 certificate and write ops, which moves the heads so the owner's rotation fails its cursor check ([ADR 0025](0025-rotation-vault-half.md) §3 check 4; ADR 0025 "Negative": "A busy account can make a rotation fail after 5 attempts"). (b) **Any other writer**, honest or not, whose upload or commit makes the revoker lose its compare-and-swap or cursor check again and again.
- **W2, revocation commit → every remaining device has processed it.** With an honest server, D has no session and no grant, and nothing it signs with the old identity key is accepted after a full rotation (INV-30). A **malicious server** (AR-9) colluding with D can show a remaining device that has not yet fetched the owner's rotation a competing chain or state signed by the old identity key: the "Known limitation".

Three concurrency cases the texts above leave open: **concurrent rotations** (two of the owner's devices revoke at once, or one revokes while another rotates for another reason); **a revoked device that holds a pending commit** (its secrets-before-commit record and stored request, [CRYPTO.md §11](../CRYPTO.md#11-flows), [ADR 0026](0026-client-device-state-and-cache.md) §1 `pending_commit`); and **a revoker that crashes** between suspension and commit.

Out of scope, recorded so nobody reads them as settled here: a restore that rolls a revocation back while a reconciliation epoch is open ([ADR 0012](0012-sync-engine.md) §7, [ADR 0032](0032-healing-rotation-after-backup.md); G01 "Unverified suspicions", second bullet); revocation from a web vault alone (G01 "Unverified suspicions", first bullet; open question 3); what recovery does with devices the recovering user does not recognise.

### Forces

- INV-7: rate limits must not become a lockout weapon; a flood "does not block re-authentication, rotation or revocation from an enrolled device" (THREAT_MODEL line 685, [ADR 0075](0075-session-listing-and-ending.md) "Forces").
- [ADR 0025](0025-rotation-vault-half.md) "Alternatives considered": "**A server-side upload freeze.** Rejected: durable state and a stuck-lock mode; client retry covers honest races." That was a freeze for every rotation, kept as durable state. Client retry does not cover a hostile writer (W1 (a)), so this ADR adds a bounded, expiring, non-durable freeze for revocation only.
- No new cryptography. Uniform errors that quote nothing (INV-48). Every check under the account lock ([ADR 0011](0011-storage.md) "Transactions and concurrency").

## Decision

### 0. What this ADR supersedes

| Part, quoted | Replaced by |
|---|---|
| [ADR 0006](0006-key-hierarchy.md) "Risks", second bullet, as ADR 0022 §1 replaced its last sentence: "A compromised device that is later revoked holds the old identity key and can race a rotation ([CRYPTO.md §11.6](../CRYPTO.md#116-key-rotation)). The M3 device-management ADR (ROADMAP §4.3) must settle this." | "A compromised device that is later revoked holds the old identity key and can race a rotation ([CRYPTO.md §11.6](../CRYPTO.md#116-key-rotation)). [ADR 0091](0091-revoked-device-rotation-race.md) settles it: suspension stops the device's key at once; a revocation window keeps every other writer out until the revocation commits; a lost or stolen device's revocation changes the Secret Key by default. What remains is accepted risk AR-18: a thief who acts before the suspension, and a malicious server that shows an old-key chain to a device that has not yet seen the rotation." |
| [ADR 0012](0012-sync-engine.md) §6, "Revocation has two phases", third sub-bullet: "Only a fresh session of another device in the device set can lift a suspension." | "Only a fresh session of another device in the device set can lift a suspension, and while a revocation window is open ([ADR 0091](0091-revoked-device-rotation-race.md) §2) only one bound to the window's revoker device." |
| [ADR 0028](0028-api-v1-http-conventions.md) item 3, first sentence, as [ADR 0048](0048-per-account-storage-quota.md) §5 replaced it (the whole sentence, from "Every error under `/api/` is" to "`internal` 500.") | The sentence in §6. |

Nothing else in those ADRs changes. ADR 0012 §6's two phases (phase 1's second sentence as ADR 0022 §1 replaced it), ADR 0025 §2–§3 and CRYPTO.md §11.8 steps 1–4 keep their meaning; §1–§5 add to them.

### 1. What the server refuses from the suspension commit on (today's behaviour, now named test targets)

From the commit of `devices/suspend` on, under the account lock: device authentication of D is `unauthorized`; every session whose `device_id` is D is deleted (device sessions and OPAQUE re-authentications bound to D alike); every op or snapshot D signed is refused, whatever session uploads it; D can fetch no grant. §7 test 1 names each. The server cannot refuse the **account** credentials D's thief may also hold (master password and SK): they are not D's, and an OPAQUE login proves only them. §4 handles that.

### 2. The revocation window

**State.** A new auth-domain table with at most one row per account, in the next free migration number of both engines (`NNNN_auth_revocation_window.sql`). PostgreSQL form; the SQLite file uses `BLOB`/`INTEGER`, `length()` and `STRICT` as the existing SQLite migrations do:

```sql
CREATE TABLE auth_revocation_windows (
    account_id        BYTEA  NOT NULL PRIMARY KEY REFERENCES auth_accounts (id) ON DELETE CASCADE,
    revoker_device_id BYTEA  NOT NULL CHECK (octet_length(revoker_device_id) = 16),
    opened_at_ms      BIGINT NOT NULL CHECK (opened_at_ms >= 0),
    expires_at_ms     BIGINT NOT NULL CHECK (expires_at_ms > opened_at_ms)
);
```

The table is **ephemeral**. `rizzy-storage`'s backup `TABLES` list leaves it out, as it leaves out sessions and device challenges ([ADR 0023](0023-logical-backup-format.md) Context), so a restore never revives a window. A window is **open** while `now_ms < expires_at_ms`. An expired row counts as absent; the next write that reads it deletes it.

**Constant.** `REVOCATION_WINDOW_MS = 600_000` (10 minutes), in `rizzy-domain-auth::config`, not operator-configurable. It equals the recovery-only session's TTL (CRYPTO.md §11.9 step 3) and covers a 32 MiB rotation upload at 1 Mbit/s, about 4.5 minutes (U: arithmetic only).

**Opening and renewing.** A successful `devices/suspend` from session S (the existing rule: fresh OPAQUE, bound to a usable durable device R other than the target) does, in its transaction:
- no open window: insert or replace the row with `revoker_device_id = R`, `opened_at_ms = now`, `expires_at_ms = now + REVOCATION_WINDOW_MS`;
- an open window whose revoker is R: set `expires_at_ms = now + REVOCATION_WINDOW_MS` (renewal). Repeating the suspend of an already suspended device renews too, and still returns H;
- an open window whose revoker is another device: refuse with `revocation_pending` (§6) before suspending anything.

**Closing.** The row is deleted in the same transaction by: a `commit_change` that revokes at least one device (the revocation commit); a recovery commit (CRYPTO.md §11.9 step 6, which ends every session); a `devices/unsuspend` by R that leaves no suspended durable device in the account. Expiry closes it too. Expiry lifts only the freeze: every suspension stays, and D stays refused (§1) until it is revoked or unsuspended.

**The freeze.** While a window is open, every request in the left column below, from a session whose `device_id` is not R, is refused with `409 revocation_pending`. The check runs under the account lock, after the session checks and before every other domain check but one: a byte-identical repeat of an already applied `account/commit` or `devices/enrol` is still success (CRYPTO.md §11 "Secrets before commit": the repeat check comes "before anything else").

| Refused for every session not bound to R | Never refused by the window |
|---|---|
| `account/commit` (except a commit over the recovery-only session), `devices/enrol`, `devices/web-certificate`, `devices/suspend`, `devices/unsuspend`, `healing/bundles`, `healing/account-state`, `healing/grants`, `vault/upload`, `vault/heal`, `attachments/create`, `attachments/upload-chunk`, `attachments/delete`, `totp/enrol/confirm`, `totp/disable`, `webauthn/enrol/confirm`, `webauthn/remove`, `sessions/end`, `sessions/others/end`, `recovery/cancel`, and the certificate-carrying variant of `device-auth/finish` (ADR 0012 §7 "A device enrolled after the backup") | `GET /api/meta`, `register/*`, `login/*`, `webauthn/login/*`, plain `device-auth/*`, `account/state`, `account/reregister/start`, `devices/grants`, `devices/grants/ack`, `recovery/start`, `recovery/complete`, the recovery commit, `totp/enrol/start`, `webauthn/enrol/start`, `webauthn/list`, `sessions/list`, `sessions/current/end`, `vault/fetch`, `attachments/get`, `attachments/download-chunk` |

The rule behind the table: a window freezes every account write that could change what the revoker's commit is checked against (state, device set, heads, wrap set, credentials, the sessions R relies on), and nothing that only reads, logs in or recovers. Recovery is never frozen (INV-7; §11.9 is the remedy against a thief who holds the password). Every endpoint added later must be placed in one column by its ADR; the default is the left one.

**Where the check lives.** One function, `rizzy-domain-auth::revocation::gate(conn, account_id, session, now_ms) -> Result<(), AuthError>`, called first in each refused auth-domain write, after `lock_account` and `session::reload`. The vault domain reads the window through its existing port: `DeviceDirectory` gains `revocation_window(conn, account_id) -> Option<RevocationWindow { revoker: DeviceId, expires_at_ms: u64 }>`, read on the vault write transaction's connection under the same account lock (as `authors` already is, `rizzy-domain-vault/src/authors.rs` lines 7–12); `vault/upload`, `vault/heal` and the three attachment writes call it first. `AuthError::RevocationPending` and `VaultError::RevocationPending` both map to `ErrorCode::RevocationPending`.

**What clients see.** `AccountView` (a response type: unknown fields are ignored) gains two fields, used only for display and retry timing, never trusted for a security decision:
- `suspended_devices: List<Id, MAX_DEVICE_STATEMENTS>`: the ids of the account's suspended, unrevoked certificates, ascending;
- `revocation_window: Option<{ revoker_device_id: Id, expires_at_ms: u64 }>`: present while a window is open.

A client that gets `revocation_pending` retries the same request after 15 s, then every 15 s until `expires_at_ms + 5 s` (read from a fresh `account/state`), at most 41 tries, and meanwhile shows "Another of your devices is removing a device. Changes are paused for up to 10 minutes." Reads continue. A malicious server that lies in these fields gains only a delayed or a needless retry.

### 3. The revocation flow (refines CRYPTO.md §11.8 for the client)

The revoking client R (kind 1–3, as CRYPTO.md §11's flow table already requires):

1. **Settle first.** If R's device state holds a pending record, R settles it (CRYPTO.md §11, "On restart with a pending record") before step 2. A revocation never starts on top of another pending commit.
2. **Choose.** The user picks one or more devices and a reason: "lost or stolen" (preselected for a device not seen for 24 hours or more) or "wiped and handed over". The list shows every durable certificate with its enrolment time and marks devices enrolled in the last 30 days, so a device the thief enrolled in W0 can be picked as well. `RotationOptions::revoke` becomes a set, `revoke: &[RevokeDevice]` (at most `MAX_DEVICE_STATEMENTS`), each entry with its own H.
3. **Re-authenticate and suspend at once.** A fresh OPAQUE login bound to R, then `devices/suspend` for each chosen device in ascending `device_id` order. The first call opens the window; each returns H. Suspension is the urgent part and comes before anything slow.
4. **Secrets.** For "lost or stolen", the default also changes the **Secret Key** in the same commit (§4). A new SK forces a new recovery code where recovery is on (CRYPTO.md §11.6 step 5: "Except when the rotation was triggered by an SK change … the user MAY instead type the current recovery code"). The kit is generated, rendered and confirmed here (secrets before commit, steps 1–2).
5. **Renew, fetch, build.** If the OPAQUE session is no longer fresh, re-authenticate. Call `devices/suspend` again for the first chosen device: this renews the window to a full 10 minutes, and the returned H must equal step 3's. H cannot move while every refused write is frozen, so a different H means a bug or a malicious server: R restarts at step 3 once, and stops and reports it on a second mismatch. Then fetch `account-state` (fetched **after** this suspend, never before), run ADR 0025 §2 step 1 (R's own uploads are not frozen), and build the rotation of CRYPTO.md §11.6 (full by default for "lost or stolen", standard for "wiped") with one `device-revocation` per chosen device, `last_accepted_device_seq` = its H.
6. **Persist and commit.** Secrets before commit, step 3 (the pending record and the exact request), then `account/commit`.
7. **On `state_conflict`**, ADR 0025 §2 step 5 applies unchanged, with one addition: step 5's renewing suspend runs again before each rebuild or restart. Inside an open window only R and a recovery can move the state, so more than 2 rebuilds mean that a recovery committed (R's sessions are then gone and it reports "this account was recovered") or a bug.
8. **Crash.** On restart R settles its pending record as today. A resend after the window expired is still accepted if the compare-and-swap, the heads and every H still hold: the window gates others, not R's commit. With no pending record but a non-empty `suspended_devices` in a fresh `AccountView`, every durable device of the account offers "Finish removing <device>" (from step 3, which renews or reopens the window) and "Cancel" (`devices/unsuspend`).

**A revoked device with a pending commit.** Its stored request can never land: its sessions were deleted at the suspension, and it cannot open a session bound to itself. If it reaches the server again it gets `unauthorized` at device authentication. If it learns, from an `AccountView` fetched over an OPAQUE login, that a verified revocation names its own `device_id`, it deletes its pending record without resending, stops syncing and offers to delete its local data. If its commit landed before the suspension, the compare-and-swap puts it under the revoker's state, because step 5 fetches only after the suspend.

### 4. What the revoked device can still learn, and the Secret Key change

| D's thief holds | After the suspension, honest server | After the revocation commit, honest server | Malicious server |
|---|---|---|---|
| The device only (no master password) | Nothing new: no session, no Fetch, no grant | Nothing written later: the new account key travels only as grants to remaining devices, as `E_srv'` (needs `export_key`, so password and SK) and as `E_rec'` (needs the code) | The same: the server holds nothing that opens without the password, the SK, the code or a remaining device's key |
| The device and the master password, **SK unchanged** | Can log in over OPAQUE as a web vault and read everything current; its writes are frozen until the window closes | **Everything written later**: an OPAQUE login yields `export_key`, and `E_srv'` yields the new account key | The same |
| The device and the master password, **SK changed in the revocation commit** | As the row above until the commit | Nothing written later: the OPAQUE record is replaced (`password_epoch + 1`), the old `pw_in` fails, and the commit ends every OPAQUE and recovery session ([CRYPTO.md §11.5](../CRYPTO.md#115-master-password-or-secret-key-change) step 5) | The same |

So the **default for a "lost or stolen" revocation is a full rotation with an SK change in the same commit** (`password_epoch + 1`, a new OPAQUE registration, `E_srv'`, a new kit), with an explicit opt-out labelled "Keep my Secret Key (only if nobody can learn your master password)". The master password may stay; the UI offers to change it too. Changing the SK is enough because the thief holds the old SK and the device never held the new one. `rules::classify` and `authorize` appear to accept `password_epoch + 1`, `account_key_epoch + 1`, `identity_epoch + 1`, `recovery_epoch + 1` and new revocations in one fresh-OPAQUE commit from another durable device (`rules.rs` lines 353–396, `change.rs` lines 715–871; V by reading, not by a test; §7 test 8 adds one). For "wiped and handed over", a standard rotation without an SK change stays the default (§11.8 step 3).

### 5. Remaining devices (refines CRYPTO.md §11.3 step 4.2)

A remaining device processing a rotation applies §11.3 steps 3–4 unchanged, plus one rule. The grant that delivers the key whose id is `state.account_key_id` (the grant of the newest epoch) must be signed by a device whose certificate is in the device set that state commits to (`device_set_hash`, CRYPTO.md §10.2: non-revoked, kind 1–3), or, from a kind-4 sender, by the identity key of that state. A grant of an earlier epoch may still come from a device revoked since ("which may since have been revoked", §11.3 step 4.2). Otherwise the device aborts and stays read-only, as step 4.2 already does on a key-id mismatch. This is the rule THREAT_MODEL A8 already states ("accept a rotation only from a non-revoked device"). It rejects a server that pairs a revocation of D with a grant from D, and nothing more; the old-key branch of W2 remains AR-18.

### 6. The error code `revocation_pending`

New closed error code `revocation_pending`, `409`, in the conflict-with-server-state bucket, as ADR 0048 §5 placed `quota_exceeded`. `rizzy-proto::error::ErrorCode` gains `RevocationPending`, documented as naming this ADR; `rizzy-server` `http::api::status` maps it to `409`. It carries no detail; the client reads `revocation_window` from `account/state`.

**The complete item 3 replacement** (ADR 0020 point 9). It carries forward the glosses of ADR 0031, ADR 0032 and ADR 0048, and the code of the sibling [ADR 0092](0092-rotation-size-limits.md), so the sentence is the same whichever of the two is accepted first; if ADR 0092 is not Accepted, its entry is left out: "Every error under `/api/` is `{"error":"<code>"}` with this status: `invalid_request` and `client_too_old` 400; `unauthorized` and `second_factor_required` 401; `fresh_session_required` 403; `not_found` 404 (also an unknown `/api/` path, and a role not running); `state_conflict`, `stale_epoch`, `record_conflict`, `prev_seq_mismatch`, `setup_retired` (ADR 0031 point 3: a registration whose echoed OPAQUE `setup_id` is retired or unknown), `credentials_stale` (ADR 0032 §4: after KE3 verified, the account's OPAQUE record lags its signed state), `quota_exceeded` (ADR 0048 §3: the record would push the account's counted bytes past its quota and headroom), `revocation_pending` (ADR 0091 §2: another device's revocation window is open), `rotation_limit` (ADR 0092 §3: the write would take the account or a vault past the size it can still rotate in one request) 409; `api_version_gone` 410; `payload_too_large` 413; `rate_limited` 429; `internal` 500."

### 7. Tests

In `rizzy-domain-auth/tests/`, through the real bridge, on SQLite and on PostgreSQL when configured, unless noted:

1. **§1, one test each:** after the suspend, D's `device-auth/start` is `unauthorized`; the token of every session D held (device session and bound OPAQUE re-authentication) is `unauthorized`; an op D signed, uploaded over another device's session, is refused; D gets no grant; none of these attempts changes H.
2. **The window, one test per entry of §2's left column:** a session not bound to R gets `revocation_pending` and nothing is written (state, certificates, heads, wraps, sessions compared before and after); the same request from R succeeds; every right-column endpoint succeeds during a window. Boundaries: refused at `expires_at_ms - 1`, accepted at `expires_at_ms`; a renewal moves the expiry; a second revoker's suspend is refused; the unsuspend of the last suspended device, the revocation commit and the recovery commit each delete the row; a byte-identical repeat of a committed request from another device succeeds during the window.
3. **Backup:** a dump taken while a window is open holds no `auth_revocation_windows` row, and a restore of it has no window.
4. **Model-based property test** (`proptest`, `rizzy-domain-auth`, SQLite in memory, an injected clock). An account with the owner's devices A and B, the stolen device D, and a thief who holds the password and SK. Each case is up to 40 steps drawn from: A suspends D (and optionally D′); A commits the revocation (full, with an SK change); A crashes and resends its stored request; B uploads; B rotates; D tries device authentication; D's ops are uploaded over B's session; the thief logs in over OPAQUE and tries each refused write; the thief enrols D′ before the suspension; the clock passes the window; a recovery completes. Invariants after every step: (I1) once D is suspended, no record by D is stored and no session of D exists; (I2) while a window is open, no request from a session not bound to R changes a row, except the recovery commit; (I3) A's commit, attempted in an open window with no recovery since it opened, commits within 2 attempts (no livelock); (I4) `state_seq` strictly increases, and of two commits on one base exactly one wins; (I5) after A's revocation commit with an SK change, the thief's OPAQUE login fails and the thief holds no live session; (I6) after the revocation, no op by D above H is ever stored. 256 cases per CI run and 10,000 in the nightly property job ([ADR 0012](0012-sync-engine.md) owner decision 5).
5. **Crash injection** (`rizzy-cli`, in the style of the ADR 0046 crash tests): a crash after the suspend and before the kit; after the kit and before the pending record is written; after it is written and before sending; after sending and before the answer; after the answer and before finalising. Each restart ends with every chosen device revoked exactly once, R's pending record deleted, the new SK and kit current, and no window open longer than `REVOCATION_WINDOW_MS` after the last suspend.
6. **Concurrent revokers:** A and B both start revoking D; exactly one window opens; the other gets `revocation_pending` and, after A commits, sees D revoked and stops.
7. **Client, §3 and §5:** a served rotation whose newest grant is signed by a device the new state revokes leaves the device read-only with the old key; a rotation that revokes this device makes it delete its pending record unsent.
8. **SK change in the revocation commit:** one commit with `password_epoch + 1`, `account_key_epoch + 1`, `identity_epoch + 1`, `recovery_epoch + 1` and two new revocations is accepted, and the old `pw_in` then fails OPAQUE login.

No known-answer vectors: no new construction.

### 8. Implementation plan

1. `rizzy-proto`: `ErrorCode::RevocationPending`; `AccountView.suspended_devices` and `AccountView.revocation_window`; the `proto_json` fuzz target covers them.
2. `rizzy-storage`: the migration on both engines; `TABLES` leaves the table out; test 3.
3. `rizzy-domain-auth`: a `revocation` module (`gate`, open, renew, close); the gate in every left-column auth write; `suspend_device`, `unsuspend_device`, `commit_change` and the recovery commit open or close the window; the `AccountView` fields; tests 1, 2, 4, 6 and 8.
4. `rizzy-domain-vault`: `DeviceDirectory::revocation_window` and the gate in upload, heal and the three attachment writes; `rizzy-server`'s bridge implements the port method.
5. `rizzy-client`: `RotationOptions::revoke` as a set, the §3 flow, the `revocation_pending` retry, the §5 rule, own-revocation handling; test 7.
6. `rizzy-cli`: `rv device revoke <device>... [--standard] [--keep-secret-key]` and "Finish removing" at start; test 5.
7. Web vault and extension: the `revocation_pending` banner and the suspended state in the Devices pane only (kind 4 cannot revoke, CRYPTO.md §11 flow table).

### 9. On acceptance (doc edits, not made in this change)

- **Status lines** (the owner's act): ADR 0006 gains "; [ADR 0091](0091-revoked-device-rotation-race.md) (Risks in part)"; ADR 0012 gains "; [ADR 0091](0091-revoked-device-rotation-race.md) (§6 in part)"; ADR 0028 gains "; [ADR 0091](0091-revoked-device-rotation-race.md) (item 3 in part)"; their rows in [docs/adr/README.md](README.md) likewise.
- **CRYPTO.md §11.6 "Known limitation"** (line 1132) becomes: "**Known limitation.** A *compromised* revoked device holds the old identity key. Against an honest server it cannot race the rotation: suspension refuses its key at once, and the revocation window of [ADR 0091](adr/0091-revoked-device-rotation-race.md) §2 keeps every other writer out until the revocation commits. Remaining devices accept a rotation only if the key its newest grant delivers has the `account_key_id` committed in the new `account-state` and that grant's sender is in the new device set (ADR 0091 §5), and they show the new identity fingerprint for the user to confirm on each device ([§11.3](#113-unlock-on-an-enrolled-device) step 3). A thief who also knows the master password is cut off only if the revocation also changes the Secret Key (ADR 0091 §4), the default for a lost or stolen device. Revocation never takes back data the device already had."
- **CRYPTO.md §11.8:** step 0 gains "This opens the account's revocation window ([ADR 0091](adr/0091-revoked-device-rotation-race.md) §2): until the revocation commits, or for 10 minutes after the last suspend, the server refuses every write from a session not bound to the revoking device, except recovery."; step 1 gains "Several devices may be suspended and revoked in one request."; step 3 gains "For a lost or stolen device the default also changes the Secret Key in the same request (ADR 0091 §4)."
- **CRYPTO.md §11.3 step 4.2** gains, after "otherwise abort and stay read-only": "The newest grant's sender must be in the device set the new state commits to, or, for a kind-4 sender, the grant must verify under that state's identity key ([ADR 0091](adr/0091-revoked-device-rotation-race.md) §5)."
- **THREAT_MODEL A8:** the table row (line 253), "Residual" cell: "the rotation race of a compromised revoked device" → "a revoked device whose thief acts before the suspension (AR-18)". The residual bullet "The rotation race" (line 541) is rewritten as §4's table in two sentences and ends "([ADR 0091](adr/0091-revoked-device-rotation-race.md), [AR-18](#9-accepted-risks-and-out-of-scope))". §5.5 (line 801) gains "After the suspension, the revocation window ([ADR 0091](adr/0091-revoked-device-rotation-race.md) §2) refuses its writes and every other writer's until the revocation commits."
- **THREAT_MODEL AR-18** (line 1317) becomes: risk "A compromised device that is later revoked, whose thief acts before the suspension, or a malicious server that shows a device which has not yet seen the rotation an old-key chain." | mitigation "Suspension refuses the device key at once; the revocation window freezes every other writer until the revocation commits; a lost or stolen device's revocation changes the SK by default; remaining devices accept a rotation only with its newest grant from a device in the new set, and confirm the new fingerprint. Nothing stops a device that holds the identity key from signing before it is suspended." | "[ADR 0091](adr/0091-revoked-device-rotation-race.md)".
- **THREAT_MODEL §8:** a new invariant (the next free number at acceptance; INV-107 is the highest in use on 2026-10-25): "While an account's revocation window is open, the server applies no write from a session not bound to the revoker device, except the recovery commit. Test: ADR 0091 §7 test 2 and test 4 (I2)." INV-30 gains: "A lost or stolen device's revocation changes the Secret Key unless the user opts out ([ADR 0091](adr/0091-revoked-device-rotation-race.md) §4)."
- **ROADMAP:** no scope change; the line 114 row is built to this ADR.
- **HANDOFF:** ADR 0091 listed as the M3 gate for the "revoke" part of ROADMAP line 114.

## Consequences

### Positive

- The race has an owner and a mechanism; AR-18 stops pointing at an ADR that does not exist.
- Against an honest server, a thief who knows the master password can no longer escalate inside W1 (enrol, counter-suspend, rotate, change credentials) or starve the revocation with uploads, and with the SK change they lose everything written later.
- Several devices, including one the thief enrolled in W0, are revoked in one atomic commit.
- A half-done revocation is visible on every device and can be finished or cancelled from any of them.

### Negative

- New ephemeral state (one table) and a check on about twenty write paths, which ADR 0025 had avoided; every future write endpoint must be placed in §2's table.
- Up to 10 minutes of refused writes on the user's other devices per revocation; usually seconds, since the commit closes the window.
- The default SK change makes a "lost or stolen" revocation print a new Emergency Kit, a real cost in the stress of a theft.
- `AccountView` grows two fields.

### Risks

- **A thief with the password and a device enrolled in W0 opens the window first** and freezes the owner. The window is bounded and only its revoker can renew it; recovery is never frozen and ends every session. But any enrolled device can cancel a pending recovery over a device session (CRYPTO.md §11.9 step 2), which this ADR does not change, so a thief device that keeps cancelling recovery blocks the remedy. Signal: reports of a recovery cancelled by an unknown device → a recovery ADR.
- **10 minutes is too short** for slow links or large accounts (see [ADR 0092](0092-rotation-size-limits.md)). Signal: the revoker's own retries hitting expiry, or measured rotations above 5 minutes → raise `REVOCATION_WINDOW_MS`.
- **The malicious-server split view of W2** stays accepted (AR-18, AR-9): the server can keep a device on an old-key branch until the user compares fingerprints or the device later sees the owner's chain (fork alarm, CRYPTO.md §10.2).

## Alternatives considered

- **Accept the residual and move the race out of M3** (G07-42's second route). Rejected: W1 (a) and (b) are cheap to close server-side, and the default SK change closes the widest hole, a thief who learns the password (guessing against `E_local`, A8).
- **Freeze every rotation, durably** (the freeze ADR 0025 rejected). Rejected again: a revocation-only, expiring, unbacked-up window has no stuck-lock mode.
- **Bind the window to the revoker's session rather than its device.** Rejected: R uploads over its device session and commits over an OPAQUE session; both are R.
- **Refuse a rotation that grants a key to a suspended device.** Rejected: clients cannot see suspensions today, an honest server never serves a grant to a suspended device, and a recovery (which cannot revoke) must not be blocked by a suspension.
- **Require a password change instead of an SK change.** Rejected as the default: the thief may know the password (keylogger, reuse, a guess against `E_local`) but never holds the new SK; the UI still offers both.
- **Suspend inside the revocation commit (one request).** Rejected: the revoker must fetch D's ops up to H before signing (§11.8 step 1), so the suspension must commit first.

## Open questions for the owner

1. **Default SK change for "lost or stolen".** On by default with an opt-out, or off by default with a prompt? *Recommendation:* on by default (§4). Without it, a thief who learns the master password reads everything written after the revocation.
2. **Window length.** 10 minutes, fixed? *Recommendation:* yes, fixed, revisited with M3 measurements of rotation time at the [ADR 0092](0092-rotation-size-limits.md) limit.
3. **Revocation from a web vault alone** (a user whose only durable device was stolen; G01 "Unverified suspicions"). CRYPTO.md §11's flow table says kind 4 cannot revoke, so such a user can rotate, but every rotation grants the new key to the stolen device. *Recommendation:* a separate ADR; this one leaves the flow table as it is.

## References

- [docs/reviews/2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md) row M1; raw findings G01-6, G02-14, G07-42, G10-26.
- [ADR 0006](0006-key-hierarchy.md), [ADR 0011](0011-storage.md), [ADR 0012](0012-sync-engine.md) §6–§7, [ADR 0020](0020-partial-supersession.md), [ADR 0022](0022-server-mode-only.md), [ADR 0023](0023-logical-backup-format.md), [ADR 0025](0025-rotation-vault-half.md), [ADR 0026](0026-client-device-state-and-cache.md), [ADR 0028](0028-api-v1-http-conventions.md), [ADR 0031](0031-retiring-old-opaque-setups.md), [ADR 0032](0032-healing-rotation-after-backup.md), [ADR 0046](0046-recovery-pending-device-stage.md), [ADR 0048](0048-per-account-storage-quota.md), [ADR 0057](0057-device-state-v2-keystore.md), [ADR 0075](0075-session-listing-and-ending.md), [ADR 0081](0081-multiple-vaults-personal-and-shared.md) §A7, [ADR 0092](0092-rotation-size-limits.md).
- [CRYPTO.md](../CRYPTO.md) §10.2, §11 "Secrets before commit", §11.3, §11.5, §11.6, §11.8, §11.9; [THREAT_MODEL](../THREAT_MODEL.md) A8, §5.5, INV-7, INV-30, AR-9, AR-18; [ROADMAP](../ROADMAP.md) §4.3, line 114.
- Code (V, at `262bbd0`): `crates/rizzy-domain-auth/src/device.rs`, `change.rs`, `rules.rs`, `trust.rs`, `queries/cert_suspend.sql`, `queries/sessions_delete_device.sql`; `crates/rizzy-domain-vault/src/store.rs`, `authors.rs`; `crates/rizzy-client/src/rotation.rs`; `crates/rizzy-proto/src/account.rs`, `error.rs`; `crates/rizzy-server/src/http/api.rs`.
