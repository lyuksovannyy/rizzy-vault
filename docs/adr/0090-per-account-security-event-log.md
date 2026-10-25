# ADR 0090: Per-account security event log: `auth_security_events`, event kinds, the `security-events/list` endpoint and the alert summary

- Status: Proposed
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M3 (`rizzy-proto`, `rizzy-storage` migration and backup `TABLES`, `rizzy-domain-auth`, `rizzy-server`, `rizzy-client`/`rizzy-wasm`, web vault, extension, `rv`)
- Supersedes: on acceptance, in part: [ADR 0028](0028-api-v1-http-conventions.md) (item 1 in part). §1 names the part ([ADR 0020](0020-partial-supersession.md) point 9).

## Context

**Trigger.** The ADR gap review of 2026-10-25 ([docs/reviews/2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md)) lists as blocker **B2**: "The per-account security event log (INV-69) has no ADR. It is required by INV-69 (Accepted, M3, with a named test), ADR 0058 point 4 / INV-83 ("notify the user" of a cloned key), THREAT_MODEL §7.6 (listed as an M1 mitigation), and the 0085/0086 admin screens (disable user, recovery wait)." Raw findings: [G10-15](../reviews/2026-10-25-raw/G10.md) (blocker), [G09-15](../reviews/2026-10-25-raw/G09.md) (major), [G06-10](../reviews/2026-10-25-raw/G06.md) (major); related: G09-24 (the actor shape of the admin drafts), G10-17 and G06-15 ("disable user" has no mechanism). After the review the owner said "start" (2026-10-25): fix the gaps. This ADR is B2's "new ADR" route.

**What requires the log** (each quoted from the file, V):

- [THREAT_MODEL](../THREAT_MODEL.md) **INV-69** (M3): "Every admin action, including a change to the recovery waiting period, goes into the affected users' security event log." Its "Verified by" column ends: "event-log test for a wait change."
- THREAT_MODEL **INV-83** (M3, [ADR 0058](0058-webauthn-2fa-second-factor.md) point 5): "a received value at or below a stored value above 0 is refused and flagged in the account's security event log as a possible clone. The credential is never disabled automatically". Verified by: "Unit tests of the four counter cases; an event-log test for the refused case."
- ADR 0058 (Accepted; partially superseded by ADR 0077 in parts that do not include this one) **owner answer 4**: "A clone signal flags the account's security event log and notifies the user. It does not disable the credential automatically."
- THREAT_MODEL **§7.6 `api` role (M1)**, R row: "Disputes over account events (logins, device enrollments, 2FA changes, share creation). | A security event log per account, without secrets, visible to the user. M10 adds org audit logs. | INV-48".
- THREAT_MODEL **§7.19** R row: "'Who disabled this user, or shortened the recovery wait?' | Every admin action goes into the affected users' security event log, without secrets." E row: "Every change to the wait is logged to and visible for each user."
- [ADR 0075](0075-session-listing-and-ending.md) §8 (Accepted): "A 'session ended' event is a candidate for the per-account security event log (THREAT_MODEL §7.6 'R') once that log has an ADR. This ADR does not decide it."
- Proposed [ADR 0085](0085-admin-authentication-bootstrap.md) §9.4 and open question 3 ("a separate small ADR for the per-account security event log before those screens merge"); Proposed [ADR 0086](0086-instance-settings-persistence.md) §4 "Events (INV-69)": "A change to `recovery_wait_hours` writes, in the same transaction as the row, one entry per account into the per-account security event log", and its open question 2 ("Draft the security event log ADR next").
- [docs/self-hosting.md](../self-hosting.md) line 135: "In this build a change of the setting is not recorded in the users' security event log (that log is part of the M3 admin work, INV-69); tell your users when you change it." The setting is `RIZZY_RECOVERY_WAIT_HOURS`, today the only way to change the wait.

**What the code does today** (branch `wip/adr-0090` at 262bbd0, V):

- `crates/rizzy-server/src/http/api.rs` lines 727–739: "A security key's possible clone (INV-83) is logged as a security event: the per-account security event log (threat model R-row, INV-48) is not built yet, so this log line is where ADR 0058 owner answer 4's signal goes for now." The line is `log::warn("webauthn_possible_clone", …)` with the route and the account id: an operator log line the user never sees (G06-10).
- `crates/rizzy-server/src/lib.rs` lines 104–105, under "Not in this build": "Recording a change of the recovery waiting period in the users' security event log (threat model §7.19, INV-69): that log is M3's."
- `rizzy-domain-auth`: `AuthError::PossibleClone` is a *refusal* (`lib.rs` `is_refusal`), so its transaction is committed, not rolled back, and a write made before the refusal stands (`settle_single_use`).
- Login (`login.rs`): nothing differs between a real and an unknown account before KE3 verifies (CRYPTO.md §5.9); after KE3 the server checks the second factor, and "A refused code still counts: the refusal is committed with the take." An account with a security key and no matching TOTP code is demoted to a 60 s pending row (ADR 0058 point 3); a TOTP-only miss restarts the OPAQUE login.
- The server cannot tell a password change from a Secret Key change: `rules::Transition::password_bumped` is "`password_epoch + 1`: the password or the Secret Key changed (§11.5)".
- Rate limits (`rizzy-domain-auth` `config.rs` defaults; "No Accepted ADR fixes the numbers"): logins 100 per hour per name and 5 per 15 min per (name, source); recovery 20 per hour per name; TOTP and WebAuthn 10 per 15 min per account; device re-authentication 10 per 15 min per device.
- Migrations: SQLite and PostgreSQL both run `0001`–`0011` (`0011_auth_invalidate_pending.sql`); the next free number is **0012**. Every `auth_` table except three hangs off `auth_accounts` with `ON DELETE CASCADE` (`0001_auth_initial.sql` header). Counters are explicit columns, not database sequences (`vault_vaults.next_store_seq`).
- Backups: `rizzy-storage` `tables.rs` `TABLES` lists every backed-up table in foreign-key order; inclusion is per table, and a migration bumps the dump's schema version ([ADR 0023](0023-logical-backup-format.md); G09-25).
- `AccountView` (`rizzy-proto/src/account.rs` line 38): "A response type: unknown fields are ignored." [ADR 0045](0045-recovery-pending-notification.md) added the advisory `pending_recovery` field on that basis, and INV-70 makes it "advisory, unsigned and server-set".
- The web vault keeps one value in browser storage, the theme ([CRYPTO.md §11.4](../CRYPTO.md#114-web-vault) "Storage"; `apps/web/src/theme.ts`). §11.4 also says: "The server sends enrolled devices an informational 'web vault session started' notice instead. It is not signed, so a malicious server can suppress it (threat model AR-9)." §11.2 step 8: "The server pushes 'new device enrolled' to every other device." No push channel exists: `notify` ([ADR 0061](0061-notify-websocket-protocol.md)) is Proposed, and no Accepted ADR defines notification mail (G10-16).
- ADR 0075 owner answer 2: "Sessions record no display metadata (source address, user agent, last-used time) in M3." ADR 0045 point 2: the rate-limit `source` "stays server-internal, as it already is for every other bucket."

**Threats.** [A1](../THREAT_MODEL.md#a1-passive-server-compromise-db-or-backup-theft) (DB or backup theft: whatever the log stores leaks with it), [A2](../THREAT_MODEL.md#a2-active-malicious-or-compromised-server) (a malicious server writes, omits or forges whatever it stores), [A3](../THREAT_MODEL.md#a3-malicious-instance-admin) (an admin with panel access only), [A15](../THREAT_MODEL.md#a15-other-users-and-the-anonymous-internet) (anyone who reaches the API: log floods), and the account owner against a third party who holds the password and Secret Key, a cloned security key or the printed kit. [AR-9](../THREAT_MODEL.md#9-accepted-risks-and-out-of-scope): "Server-enforced controls … hold only against an honest server." INV-48: logs never contain secrets.

**ROADMAP.** No row names this log. §4.3 has "| S | Session/device management: list devices, revoke, force logout | M3 |", §4.9 "| S | Admin panel (user list, disable user, invite-only signup, SMTP settings for notifications) | M3 |", and M10 "Event / audit logs, export to SIEM" for organisations. THREAT_MODEL §7.6 places the mitigation at M1, so M1 shipped without it (G10-15). Whether and where to add a row is the owner's call (open question 2).

## Decision

### 1. What this ADR supersedes

The part below is named under ADR 0020 point 9. Nothing else in any Accepted ADR changes.

- **[ADR 0028](0028-api-v1-http-conventions.md) item 1, first sentence, in part** (as already replaced in part by [ADR 0052](0052-icon-proxy-role.md), [ADR 0075](0075-session-listing-and-ending.md) §1 and [ADR 0081](0081-multiple-vaults-personal-and-shared.md) §0 point 5; this follows ADR 0075 §1's precedent). The replacing text:

  > "The endpoints of the `rizzy-server` `http/api.rs` module table, which is the authoritative list, under `/api/v1/`, grouped by resource — the nine of the first release (`register`, `login`, `device-auth`, `account`, `devices`, `healing`, `recovery`, `totp`, `vault`) and each resource an Accepted ADR adds, among them `security-events` of ADR 0090 — verb last (`start`, `finish`, `commit`, `list`, …), plus one endpoint outside `http/api.rs`: `POST /api/v1/icons/fetch`, resource `icons`, verb `fetch`, served by the `icons` role's own router and listener, never combined with `api` or `web` (ADR 0010 §2; ADR 0052)."

  The rest of item 1 stands: `POST` for everything, `GET` only for `devices/grants`, and the reason given there. Item 3 is not superseded: every refusal here uses an existing code.
- **Not superseded, and why.**
  - ADR 0058 point 5 and owner answer 4: this ADR is the log and the notification they name (§3, §8); their text needs no change.
  - ADR 0075 §8 ("The server sends none" [notices]): the log is a record the client pulls, not a notice the server sends, and `session_ended` is an info-class event, which raises no banner (§8). §8's "Later" bullet is answered, not replaced.
  - ADR 0045 and INV-70: unchanged. The pending-recovery banner stays; the entries of §3 add history next to it.
  - ADR 0023: `TABLES` gains one table through a migration, which ADR 0023 provides for; §5's restore steps are unchanged.
- **ADR 0002 point 5.** The change is additive: an older client never calls the endpoint and ignores the new `AccountView` field. No raise of the minimum client versions, only the changelog entry point 5 asks for.

### 2. Trust model: advisory, written by the server, never a trust input

1. **The log is advisory.** Every entry and every field of the alert summary (§7) is server-written, unsigned and unverifiable by the client, exactly like ADR 0045's `PendingRecoveryNotice` (INV-70). A malicious or compromised server (A2), or anyone with write access to the database, can omit, delete, reorder, back-date or invent entries. A client must not use an entry's presence, absence or content in any trust decision: not for the device set, not for `account-state` verification (INV-25), not for recovery state (INV-70), not to enable or disable any control. It is shown to the user and used for nothing else. This is a new invariant (§12, "INV-110").
2. **What it protects, and against whom.** Against an *honest* server it tells the account owner what a third party did with the owner's credentials: a login with the password and Secret Key, a second factor that failed after them, a cloned security key, an enrolled device, a recovery started with the printed kit, a weakened setting. Against an admin who has only the panel (A3 without shell or database access), the panel has no path that edits or deletes an entry (§10). It does not protect against the server operator with database access, and the UI says so (§8).
3. **Why not signed.** Most events (logins, refused second factors, the clone signal, admin actions, the wait setting) originate at the server, which holds no account key, so no account key can sign them. A server-held signing key or a server-side hash chain proves nothing to a client against the server that holds the key and the chain (A2), and truncation is undetectable without a client-held anchor. What the signed account state already carries (device certificates and revocations, `password_epoch`, the key and identity epochs, recovery enablement) the client verifies from the state itself (INV-25, CRYPTO.md §11.2 step 4); the log adds nothing to that verification and is not asked to. Entries that correspond to a signed-state step carry its `state_seq` (§4) only so the UI can relate the two.

### 3. Event kinds

Codes are stored as `INTEGER`; the wire uses the snake_case name. Codes are append-only: a code is never reused or re-meant, and a new kind needs an Accepted ADR. **Class** is `alert` (2) or `info` (1): `alert` when the event adds access, weakens a protection or points to a third party; `info` for routine and protective events. Fields not named in a row are `NULL` (§4 defines the columns).

| Code | `kind` | Class | Written when, in the transaction of… | Fields |
|---|---|---|---|---|
| 1 | `account_created` | info | `register_finish`, only when it inserts the `auth_accounts` row (a byte-identical repeat of a finished signup writes nothing) | `actor_kind` = `sign_in`; `value_new` = the recovery wait in force, ms |
| 2 | `password_login` | info | `login_finish` or `webauthn_login_finish` issuing an OPAQUE session (a web vault login or a native re-authentication): the M3 pull form of CRYPTO §11.4's "web vault session started" notice | `actor_kind` = `sign_in`; `actor_device_id` = the durable device a re-authentication is bound to, else `NULL`; `value_new` = the second factor used: 0 none, 1 TOTP, 2 security key |
| 3 | `second_factor_failed` | alert | the refusing transaction of `login_finish` when KE3 verified and a TOTP code **was supplied** and refused, or of `webauthn_login_finish` when an assertion is refused for any reason other than the counter (code 21). A login that sent no code (the normal first round) writes nothing (open question 3) | `actor_kind` = `sign_in`; `value_new` = 1 TOTP, 2 security key |
| 4 | `device_enrolled` | alert | any path that stores a certificate for a device id the account had no certificate for: `enrol_device`, `commit_change`, certificate-carrying device authentication (CRYPTO §11.2 step 8: "any growth of the device set, by any path"). Kind 4 (web) certificates are not logged; code 2 covers them | actor of the request; `subject_device_id`; `value_new` = `device_kind` (1–3) |
| 5 | `device_suspended` | info | `suspend_device` | actor; `subject_device_id` |
| 6 | `device_unsuspended` | alert | `unsuspend_device` | actor; `subject_device_id` |
| 7 | `device_revoked` | info | any path that stores a revocation for a device id that had none | actor; `subject_device_id`; `state_seq` |
| 8 | `credentials_changed` | alert | `commit_change` with `Transition::password_bumped` (the password or the Secret Key; the server cannot tell which) | actor; `state_seq` |
| 9 | `account_key_rotated` | info | `commit_change` with `account_key_rotated` and not `identity_changed` | actor; `state_seq` |
| 10 | `identity_rotated` | info | `commit_change` with `identity_changed` (a full rotation) | actor; `state_seq` |
| 11 | `recovery_code_changed` | alert | `commit_change` with `RecoveryTransition::NewCode` (not the same-code repair of ADR 0032 §4 step 6) | actor; `state_seq` |
| 12 | `recovery_disabled` | alert | `commit_change` with `RecoveryTransition::Disabled` | actor; `state_seq` |
| 13 | `recovery_started` | alert | `recovery_start` when it opens a pending recovery | `actor_kind` = `recovery_code`; `value_new` = `available_at_ms` |
| 14 | `recovery_cancelled` | info | `recovery_cancel` when it closes a pending recovery | actor (a device session) |
| 15 | `recovery_session_opened` | alert | each successful `recovery_complete` (each issues a recovery-only session and serves the account objects and vaults) | `actor_kind` = `recovery_code` |
| 16 | `recovery_completed` | alert | `commit_change` over a recovery-only session (the commit that closes the pending recovery) | `actor_kind` = `recovery_session`; `state_seq` |
| 17 | `totp_enabled` | alert | `totp_enrol_confirm` | actor |
| 18 | `totp_disabled` | alert | `totp_disable` | actor |
| 19 | `security_key_added` | alert | `webauthn_enrol_confirm` | actor; `label` |
| 20 | `security_key_removed` | alert | `webauthn_remove` | actor; `label` (the removed key's) |
| 21 | `security_key_possible_clone` | alert | the refusing transaction of `webauthn_login_finish` in INV-83's fourth case | `actor_kind` = `sign_in`; `label`; `value_old` = the stored `sign_count`; `value_new` = the received one |
| 22 | `session_ended` | info | `end_session` (ADR 0075 `sessions/end`) | actor; `subject_device_id` = the durable device an ended OPAQUE re-authentication was bound to, if any; `value_new` = the ended session's kind: 1 OPAQUE, 3 recovery-only (2, device, is reserved: R3 of ADR 0075 §4 refuses a device target, §5) |
| 23 | `other_sessions_ended` | info | `end_other_sessions`, only when at least one session ended | actor; `value_new` = the number ended |
| 24 | `recovery_wait_changed` | alert if `value_new < value_old`, else info | §6 | `actor_kind` = `admin_panel`, `operator_cli` or `server`; `actor_admin_id` for the panel; `value_old` (`NULL` = unknown) and `value_new`, ms |
| 25 | `account_disabled` | alert | the admin "disable user" action (§10) | `actor_kind` = `admin_panel` or `operator_cli`; `actor_admin_id` for the panel |
| 26 | `account_enabled` | alert | the admin "enable user" action (§10) | as code 25 |
| 27 | `second_factor_reset_by_admin` | alert | the admin 2FA reset that `totp.rs` names ("Losing the authenticator is the admin's logged 2FA reset, INV-69, M3"), once an ADR defines it | as code 25 |

Rules for every kind:

- **One `commit_change` may write several entries**, all with the same `at_ms` and `state_seq`, in this order: 16, 8, 10 or 9, 11 or 12, then one 7 per newly revoked device and one 4 per newly certified durable device. A step that sets none of these (settings, same-password re-registration, a `kdf_id` upgrade) writes nothing.
- **"Actor of the request"** means: `opaque_session` for an OPAQUE session (with `actor_device_id` = its bound durable device, if any), `device_session` with `actor_device_id` for a device session, `recovery_session` for the recovery-only session.
- **Nothing before KE3.** No entry depends on whether an unauthenticated request named a real account: codes 2, 3 and 21 are written only after KE3 verified, code 1 only when an account is created, codes 13 and 15 only after `H_rec` matched (each of those flows already answers differently on success). Failed OPAQUE logins, wrong recovery codes and unknown names write nothing ([CRYPTO.md §5.9](../CRYPTO.md#59-account-enumeration); and no unauthenticated party may write rows into an account it names).
- **Not logged:** device authentication (`device-auth/finish`: it proves a key whose enrolment is already logged, and runs at every native session start); the web vault's kind 4 certificate upload; `sessions/current/end` (`rv` calls it at every command exit, ADR 0075 owner answer 3); `ACCOUNT_SETTINGS` changes; vault, item and attachment operations; healing; `account/state` reads; admin actions that change no existing account (signup mode, SMTP settings, invites, admin login: ADR 0085's `auth_admin_audit` holds those).

### 4. Storage: `auth_security_events`

One migration, `0012_auth_security_events.sql`, for SQLite and PostgreSQL (0012 is the next free number today; if another migration lands first, the next free number at implementation), in ADR 0011's `auth` domain. SQLite dialect (PostgreSQL: `BYTEA`, `BIGINT`, `TEXT`, the same checks, `octet_length` for the label):

```sql
-- The per-account security event log (ADR 0090). Advisory and server-written; never a secret,
-- a source address or a user agent. Deleted with its account.
CREATE TABLE auth_security_events (
    event_id          BLOB    NOT NULL PRIMARY KEY CHECK (length(event_id) = 16),
    account_id        BLOB    NOT NULL REFERENCES auth_accounts (id) ON DELETE CASCADE,
    at_ms             INTEGER NOT NULL CHECK (at_ms >= 0),
    kind              INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 65535),
    class             INTEGER NOT NULL CHECK (class IN (1, 2)),
    actor_kind        INTEGER NOT NULL CHECK (actor_kind BETWEEN 1 AND 255),
    actor_device_id   BLOB    CHECK (actor_device_id IS NULL OR length(actor_device_id) = 16),
    actor_admin_id    BLOB    CHECK (actor_admin_id IS NULL OR length(actor_admin_id) = 16),
    subject_device_id BLOB    CHECK (subject_device_id IS NULL OR length(subject_device_id) = 16),
    label             TEXT    CHECK (label IS NULL OR length(CAST(label AS BLOB)) BETWEEN 1 AND 64),
    value_old         INTEGER CHECK (value_old IS NULL OR value_old >= 0),
    value_new         INTEGER CHECK (value_new IS NULL OR value_new >= 0),
    state_seq         INTEGER CHECK (state_seq IS NULL OR state_seq >= 0)
) STRICT;
CREATE INDEX auth_security_events_list  ON auth_security_events (account_id, at_ms, event_id);
CREATE INDEX auth_security_events_class ON auth_security_events (account_id, class, at_ms, event_id);
CREATE INDEX auth_security_events_age   ON auth_security_events (at_ms);
```

- **`event_id`**: 16 bytes from the server's CSPRNG (`0001`'s convention for server ids). There is no sequence number: a per-account counter would need the account lock on the bulk path of §6, and a database sequence would need a restore step ADR 0023 does not have. Order is `(at_ms, event_id)` descending; `event_id` only breaks ties.
- **`at_ms`**: the server's injected clock (`now_ms`) of the action's transaction.
- **`actor_kind`**: 1 `opaque_session`, 2 `device_session`, 3 `recovery_session`, 4 `recovery_code` (an anonymous request that presented the recovery code), 5 `sign_in` (the event is the sign-in itself), 6 `admin_panel`, 7 `operator_cli`, 8 `server` (the server on its own, §6). For 6 and 7 this is ADR 0085's `actor_kind` (`panel` | `cli`) plus a nullable 16-byte `actor_admin_id`, the encoding G09-24 recommends for every admin table.
- **`label`**: a copy of the security key's label at the time (`MAX_WEBAUTHN_LABEL_LEN` = 64 bytes, the `WebauthnLabel` rule), so a removed key stays nameable.
- **Integer ranges.** A `u64` above `i64::MAX` is refused before SQL (`rizzy_storage::convert`), as for every table. `value_old`/`value_new` hold milliseconds for codes 1, 13 and 24, counters for code 21, and small enums or counts otherwise.

**Not stored**, by design: the source address (IP or prefix) and the user agent (open question 1); the login name as typed; OPAQUE messages; any token, token hash or `session_id`; TOTP secrets or codes; WebAuthn challenges, assertions or credential ids (the label names the key); recovery codes or `H_rec`; any key, ciphertext, vault, item or attachment id; any setting value except the recovery wait; admin names (and the API never returns `actor_admin_id`, §7); mail addresses. No row holds anything INV-8 or INV-48 protects.

**Quota.** The rows are server-generated and bounded by §5; they are not counted in ADR 0048's `storage_account_usage`.

### 5. Retention, cap and purge

- **Cap per account and class: 500.** After each single-account insert, in the same transaction and under the account lock the flow already holds, the server deletes that account's rows of the same class that are older, in `(at_ms, event_id)` order, than its 500th newest row of that class. Separate caps keep a flood of info entries (logins) from pushing alerts out.
- **Age: 365 days.** The worker's existing purge step (`AuthService::purge_expired`) deletes rows with `at_ms` older than 365 days, and trims every (account, class) above 500 (the bulk path of §6 does not trim inline).
- **Exemption.** Neither rule deletes an account's newest row of code 1 or 24 (the wait in force), so §6 never loses its reference.
- **Size.** At most 1 000 rows per account between sweeps, plus bulk rows, each under 200 bytes of data: under about 200 KiB per account before indexes.
- **Account deletion** deletes the rows (`ON DELETE CASCADE`).
- **Rate of writes.** Every write rides on a flow that already has a limit or a cost: logins 100 per hour per name (codes 2, 3, 21 come only after KE3), TOTP and WebAuthn 10 per 15 min per account (codes 3, 17–21), recovery 20 per hour per name (13, 15), fresh-session or device-session flows for the rest; code 22/23 rows need a session to end; codes 24–27 come from admin actions behind ADR 0085's admin rate limits, or once per start (§6).
- **Residual:** a holder of the account's credentials can generate 500 alert entries to push older ones out. Each alert needs a fresh OPAQUE session or the recovery code and passes its flow's rate limit (for example 10 TOTP operations per 15 min), so this takes hours, and the flood is itself 500 alerts in the summary (§7).

### 6. The recovery wait (INV-69, §7.19 E row)

1. **Panel and CLI.** When ADR 0086 (or its successor) lands the recovery-wait screen and `rizzy-vault settings set`, a saved change writes, in the transaction of the setting row, one code 24 row per existing account: `value_old` = the effective wait before, `value_new` = after, `actor_kind` 6 with `actor_admin_id`, or 7. The server inserts the rows itself, one per account with ids from its CSPRNG, in that transaction and without taking account locks (no counter is involved).
2. **Configuration, at start.** Today the wait changes only through `RIZZY_RECOVERY_WAIT_HOURS` and a restart. When the `api` role starts, after migrations and before its listener accepts, it runs one write transaction: for every account whose newest code 1 or 24 row has a `value_new` other than the effective `recovery_wait_ms`, or that has no such row, it inserts a code 24 row with `actor_kind` 8, `value_old` = that `value_new` (`NULL` when there is none) and `value_new` = the effective wait. The first start after migration 0012 therefore writes one info row per existing account stating the wait in force; later starts write only on a change. Two `api` processes starting together may both write; the duplicate says the same thing. If the transaction fails, the server refuses to start, so a change of the wait cannot take effect unlogged.
3. A pending recovery keeps the release time it opened with (`config.rs`), and its code 13 row records it.
4. Clients show the wait in hours (`value_new / 3 600 000`; the setting is whole hours).

### 7. API: `POST /api/v1/security-events/list` and the alert summary

**Endpoint** (path constant `SECURITY_EVENTS_LIST` in `rizzy-proto` `http::paths`; a new resource `security-events`; `POST` with a body, ADR 0028 item 1):

| Method, path | Request → response | Session |
|---|---|---|
| `POST /api/v1/security-events/list` | `SecurityEventListRequest` → `SecurityEventListResponse` | OPAQUE or device (the recovery-only session is `401 unauthorized` at ADR 0028 item 6(c)) |

New module `rizzy_proto::security_event`:

```rust
/// Body of `security-events/list`. Strict: unknown fields refused.
#[serde(deny_unknown_fields)]
pub struct SecurityEventListRequest {
    /// Entries strictly older than this one, in (at_ms, event_id) order; absent = the newest.
    #[serde(default)]
    pub before: Option<SecurityEventCursor>,
    /// 1 to MAX_SECURITY_EVENTS_LISTED; absent = DEFAULT_SECURITY_EVENTS_LISTED.
    #[serde(default)]
    pub limit: Option<u32>,
}

#[serde(deny_unknown_fields)]
pub struct SecurityEventCursor { pub at_ms: u64, pub event_id: Id }

/// Response types ignore unknown fields.
pub struct SecurityEventListResponse {
    pub events: List<SecurityEventView, MAX_SECURITY_EVENTS_LISTED>, // newest first
    pub more: bool, // true when older entries exist beyond the last one
}

pub struct SecurityEventView {
    pub event_id: Id,
    pub at_ms: u64,
    pub kind: SecurityEventKind,   // the snake_case names of §3; #[serde(other)] Unknown
    pub class: SecurityEventClass, // "info" | "alert"; #[serde(other)] Unknown, shown as an alert
    pub actor: SecurityEventActor,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub subject_device_id: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub label: Option<WebauthnLabel>,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub value_old: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub value_new: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub state_seq: Option<u64>,
}

pub struct SecurityEventActor {
    pub kind: SecurityEventActorKind, // the snake_case names of §4; #[serde(other)] Unknown
    #[serde(default, skip_serializing_if = "Option::is_none")] pub device_id: Option<Id>,
    // actor_admin_id is never sent.
}

/// AccountView.security_alerts (additive, ADR 0045's precedent); absent when no alert-class
/// entry is younger than ALERT_WINDOW_MS.
pub struct SecurityAlertSummary {
    pub count: u32, // alert-class entries younger than ALERT_WINDOW_MS (at most 500)
    pub newest_event_id: Id,
    pub newest_at_ms: u64,
    pub newest_kind: SecurityEventKind,
}
```

- **Limits** in `rizzy_proto::limits`: `MAX_SECURITY_EVENTS_LISTED` = 100; `DEFAULT_SECURITY_EVENTS_LISTED` = 50; `ALERT_WINDOW_MS` = 72 h = 259 200 000 (the default recovery wait, so the alert of a recovery start stays up for at least the default wait). A `limit` of 0 or above 100 is `400 invalid_request`; a longer list in a response is a parse error, like the other bounded lists.
- **Semantics.** The server returns the caller's account's rows (the account comes from the session; no request field names an account) with `(at_ms, event_id)` below `before`, in descending order; it reads `limit + 1` rows to set `more`, and maps codes to names. A cursor that names a purged row still works (keyset paging). A stored code the running server does not know (rows of a newer release read after a downgrade) is skipped.
- **`AccountView.security_alerts: Option<SecurityAlertSummary>`**, `#[serde(default, skip_serializing_if = "Option::is_none")]`, filled wherever `AccountView` is (login finish and `account/state`), from one query on `auth_security_events_class`.
- **Errors:** `401 unauthorized` (no, unknown or expired session, or the recovery-only session); `400 invalid_request` (malformed body, unknown field, bad `limit`); `413 payload_too_large` above the 1 MiB limit (item 7); `500 internal`. No `not_found`: an account with no rows gets `{"events":[],"more":false}`.
- **Rate limit:** no new bucket, as in ADR 0075 §7: an authenticated, indexed read of at most 101 rows.
- **Example response:** `{"events":[{"event_id":"<22 base64url chars>","at_ms":1761400000000,"kind":"security_key_possible_clone","class":"alert","actor":{"kind":"sign_in"},"label":"YubiKey 5C","value_old":41,"value_new":12}],"more":false}`.

### 8. Clients: how the log is shown and how the user is notified

"Notifies the user" (ADR 0058 owner answer 4) is, at M3, **the alert banner** below: every client that fetches `AccountView` shows it while `security_alerts` is present. There is no push and no mail; when `notify` (ADR 0061) or notification mail have Accepted ADRs, those ADRs may announce alert-class entries too.

- **Banner** (the web vault's vault view and the extension popup, next to ADR 0045's recovery banner; `rv account status`): "Security alert: <text of newest_kind>, <newest_at_ms in local time>", plus "and N more in the last 3 days" when `count > 1`, a **Review** action and **Dismiss**. Dismiss hides it until `newest_event_id` changes. The dismissed id is held in memory only (no browser storage: CRYPTO §11.4 "Storage" allows only the theme), so the banner returns after a reload or an unlock while the alert is younger than 72 h. The acting client shows it too: it confirms the action, and no client filters by actor.
- **Web vault:** a **Security activity** section in Settings, below Sessions: newest first, 50 per page with "Show older" (`before` = the last row shown). Each row shows the time, the kind's text, the actor ("a sign-in with your password", "device <name>", "the recovery code", "an administrator", "the server operator", "the server") and the fields of §3. A device id is shown with its name when the device is in the verified device list, and as "unknown device <first 8 base64url characters>" otherwise. An `unknown` kind shows "Unrecognised security event; update this app" with its class. A fixed footnote: "Your server keeps this list. A compromised server can hide or change it; your device list and account state are checked independently." Every string is rendered as text (labels are user content). The section and the banner join the axe audit and the keyboard walk.
- **Extension:** the popup banner only; Review opens the web vault's Security activity section at the server's canonical origin. No list in the extension at M3.
- **`rv`:** `rv account events [--limit N] [--json]` (N from 1 to 500, default 50; pages of 100 internally), one line per entry; `rv account status` prints `security alerts in the last 72 h: N (newest: <kind> at <time>); see rv account events` when the summary is present.
- **`rizzy-client`:** `security_events(before, limit)` and the parsed summary; `rizzy-wasm` exports them (expansion baseline regenerated, `unsafe` counts reviewed). Native apps use the same calls through `rizzy-ffi` when it exists and follow the same banner rule.
- **Kind texts** live in `packages/i18n` (English at M3), one per §3 code; code 8 reads "Password or Secret Key changed".

### 9. Transactions, crashes and failures

- **Same transaction, no action without its row.** Each entry is inserted in the transaction of the action it records (§3), after the action's own writes and before the commit. If the insert fails, the action fails and rolls back (fail closed; the client gets `500 internal` and may retry as after any storage failure). A crash before the commit leaves neither; after it, both.
- **Refusals.** Codes 3 and 21 are written in the refusal's transaction, which `settle_single_use` commits (`is_refusal`). If that insert fails, the transaction rolls back, the single-use row is discarded as after any failure, and the client gets `500 internal`: the login stays refused.
- **Idempotent repeats write nothing:** a byte-identical repeat of a finished signup, an `others/end` that ended nothing, a `recovery_cancel` with no pending recovery.
- **The operator log line stays.** `api.rs`'s `webauthn_possible_clone` warning remains as an operator signal; its comment is updated to name this ADR. No entry is copied into a log line (INV-48).

### 10. Admin actions and "disable user"

- **INV-69's "affected users"** are the accounts whose own access or recovery policy the action changes: the recovery wait (every account, §6), disabling and enabling one account (codes 25, 26), and a 2FA reset of one account (code 27). An admin action that changes no existing account's access writes no account entry.
- **The semantics of "disable user" are not decided here.** What a disabled account can still do, whether its sessions end, and how it is re-enabled belong to the ADR that defines the action (G06-15, G10-17). This ADR fixes only its log entry: the disable (enable) action writes exactly one code 25 (26) row for the target account, in the transaction that changes the account and writes ADR 0085's `auth_admin_audit` row. Sessions it ends get no separate code 22 or 23 rows. The user reads the entry as soon as that ADR lets the account list events again (at the latest after re-enabling).
- **The panel never shows, edits or deletes** a user's security events; `auth_admin_audit` is the admin's view of the same actions. No admin or CLI command deletes or edits a row; rows go only by §5 and by account deletion.

### 11. Backups

`auth_security_events` joins ADR 0023's `TABLES` directly after `auth_accounts` (its one foreign key), with its columns in the order of §4; the migration bumps the dump's schema version as any migration does, and the `tables.rs` schema test covers it. Reason: a dispute ("who disabled me, who changed the wait") must survive a restore. Cost: a backup carries every account's event history (metadata only, no address, §4), inside ADR 0071's encrypted backup file. A restore brings the log back as of the backup; entries written after it are lost with everything else (a residual; a later ADR may add a "restored" entry, which would need a step in ADR 0023 §5).

### 12. Invariant (proposed; drafted as **INV-110**, its number assigned at acceptance, because parallel drafts may also claim numbers after INV-107)

| ID | Invariant | From | Verified by |
|---|---|---|---|
| INV-110 | Every entry of the per-account security event log and every field of `SecurityAlertSummary` is advisory, unsigned and server-set. A client shows them as UI only and never uses them as input to device-set, `account-state` (INV-25) or recovery-state (INV-70) verification. An honest server writes each entry in the transaction of the action it records, never stores a source address, user agent or secret in it, and shows an account's entries only to that account's OPAQUE or device sessions ([ADR 0090](adr/0090-per-account-security-event-log.md)). | M3 | `rizzy-client` and web e2e: forged, missing or reordered entries and a forged summary change nothing the client trusts; a DB-dump inspection after every event kind finds no canary secret, no source address and no user agent; IDOR test (another account's session lists none of the rows); a failing insert rolls its action back. |

### 13. How this satisfies INV-69, INV-83 and ADR 0058 owner answer 4

- **INV-69**, "Every admin action, including a change to the recovery waiting period, goes into the affected users' security event log": §6 (every path that changes the wait: panel, CLI, configuration) and §10 (disable, enable, 2FA reset). Its "event-log test for a wait change" is `a_recovery_wait_change_writes_one_entry_per_account` (domain; the panel and CLI paths once ADR 0086 lands) and `a_changed_wait_setting_is_logged_at_start` (server; the configuration path, testable now).
- **INV-83**, "refused and flagged in the account's security event log as a possible clone": code 21, in the refusal's transaction (§9). Its "event-log test for the refused case" is `a_refused_counter_writes_a_possible_clone_entry` (domain: the row exists after the refusal with the stored and received counts, and the credential is still enrolled) and `a_possible_clone_raises_the_alert_summary` (server: `security-events/list` returns it and `AccountView.security_alerts` names it).
- **ADR 0058 owner answer 4**, "flags the account's security event log and notifies the user": the flag is code 21; the notification is §8's banner on every client for 72 h, tested in the web e2e, the extension popup test and the `rv` e2e.
- **THREAT_MODEL §7.6 R row** ("logins, device enrollments, 2FA changes"): codes 2–4 and 17–21. "Share creation" is M5's and gets its kind with the share ADR.

### 14. Implementation plan and tests

1. **`rizzy-proto`** (`security_event.rs`, `limits.rs`, the `http.rs` path): the types of §7; known-answer JSON for a request, a response with every kind and a summary; strict request parsing (an unknown field, `limit` 0 and 101 refused); an unknown kind, class and actor kind parse as `Unknown`; a 101-entry list fails to parse; a fuzz target on `SecurityEventListResponse` parsing (untrusted input on the client).
2. **`rizzy-storage`**: migration 0012 (both dialects); queries under `queries/{sqlite,postgres}/` (insert, page, summary, trim, age purge, newest wait row); the `TABLES` entry; the `tables.rs` schema test; a dump/restore round trip with every column filled and `NULL`.
3. **`rizzy-domain-auth`**: a module `events.rs` (`record`, `list`, `summary`, `trim`, `purge`, `check_recovery_wait`) and a call in each flow of §3. Tests: one per code, that the flow writes exactly that row with exactly those fields; a failed or refused action writes no row, except codes 3 and 21; an injected insert failure rolls back a password change and a device enrolment; nothing is written for an unknown login name or a wrong recovery code; a commit with several flags writes §3's order with one `state_seq`; the caps (the 501st alert trims the oldest alert and never an info row; the newest code 1/24 row survives both rules); the age purge; `check_recovery_wait` (the first start writes one row per account with `value_old` `NULL`, an unchanged restart writes none, a changed one writes old → new with the right class).
4. **`rizzy-server`**: the route in `api.rs`'s module table with Session "OPAQUE or device". Integration tests: the recovery-only session gets 401; another account's session sees none of the rows (IDOR); paging through 250 rows with `before` returns each row once, in order; `limit` 0 and 101 are 400; the start-up check runs before the listener accepts; the INV-48 canary at the most verbose log level while every kind is written; a DB-dump inspection for source addresses and user agents. Update `lib.rs` "Not in this build" and the `api.rs` comment.
5. **`rizzy-client` / `rizzy-wasm`**: the calls and the summary; a forged-entry test in the style of `a_forged_recovery_notice_cannot_change_what_the_client_trusts`; the regenerated expansion baseline.
6. **Web vault**: the Security activity section and the banner. E2e: a clone signal (a fake authenticator replaying a counter) shows the banner and the row; Dismiss hides it until a newer alert; a lying server's invented entry is shown only as an entry and changes nothing else (in the style of `recovery-notice.spec.ts`); the axe audit and the keyboard walk.
7. **Extension**: the popup banner and its Review link; a unit test in the style of `recovery-notice.test.ts`.
8. **`rv`**: `rv account events` and the status line; e2e; `docs/rv.md`.
9. **Docs with the code:** `docs/self-hosting.md` line 135 (a change of the wait is now logged, the configuration path included), and a note in the web vault's help that the list is kept by the server.
10. **Later, with their ADRs:** code 24's panel and CLI paths, and codes 25, 26 and 27, land with the screens and commands of ADRs 0085/0086 and of the disable-user and 2FA-reset ADRs, each with its test. Code 24's configuration path lands with this ADR.

### 15. On acceptance (documentation edits, not made now)

1. **THREAT_MODEL.md**
   - §8: add the INV-110 row of §12 under its assigned number.
   - §7.6 R row: mitigation "The per-account security event log of [ADR 0090](adr/0090-per-account-security-event-log.md): server-visible metadata only, no secrets, no source address; advisory (AR-9). M10 adds org audit logs."; Inv. column "INV-48, INV-110". Record that this M1 mitigation is met at M3.
   - INV-69 "Verified by": replace "event-log test for a wait change" with the two test names of §13. INV-83 "Verified by": replace "an event-log test for the refused case" with the two test names of §13.
   - §7.19 R and E rows: link ADR 0090 §6 and §10.
   - AR-9: add "the security event log" to its list of server-enforced controls.
2. **CRYPTO.md**
   - §11.4 "Signing ops", last sub-bullet: replace its second sentence with "The server records a `password_login` entry in the account's security event log ([ADR 0090](adr/0090-per-account-security-event-log.md)) instead. It is not signed, so a malicious server can suppress it (threat model AR-9)."
   - §11.2 step 8: add "Until a push channel exists, the alert-class `device_enrolled` entry and its banner (ADR 0090 §8) are the pull form of this notice; the client still verifies the device against the signed device set (step 4)."
3. **ROADMAP.md**: the row the owner chooses under open question 2.
4. **ADR 0028**: its status line gains "; [ADR 0090](0090-per-account-security-event-log.md) (item 1 in part)", and its README row likewise.
5. **ADR 0085 and ADR 0086** (Proposed; edited before their acceptance): 0085 §9.4 and open question 3, and 0086 §4 "Events" and open question 2, point to this ADR; both adopt §4's actor encoding (G09-24).
6. **CLAUDE.md, HANDOFF.md**: the lead's lists of Accepted and Proposed ADRs.

## Consequences

### Positive

- INV-69, INV-83 and ADR 0058 owner answer 4 become buildable and testable, with named tests (§13); on this point ADR 0086's recovery-wait screen and the disable screen are unblocked.
- The user sees what a third party did with their credentials, against an honest server, on every client, without push or mail.
- The configuration path of the recovery wait, unlogged today (self-hosting.md line 135), is logged from the first start.
- One actor encoding for admin rows across the admin ADRs (G09-24).
- No new crate, no cryptography, no envelope purpose, no error code, no rate-limit bucket.

### Negative

- Every flow of §3 gains a write in its transaction, and a failure of that write fails the action (a password change can fail because its entry cannot be written).
- The database and its backups hold per-account activity history (what and when, not where), which an A1 reader learns.
- The banner nags: it comes back after every reload for 72 h until dismissed, on every client, also after the user's own action.
- Without source addresses the user cannot tell their own web login from an attacker's by location, only by time.
- One row per account at the first start after the migration, and per change of the wait.

### Risks

- **False assurance.** Users may read an empty log as "nothing happened". The footnote (§8) and INV-110 address it; the signed device list stays the authority. If users or reviewers start relying on the log for trust, revisit with a client-anchored design.
- **Second-factor probing stays invisible** when the attacker stops at the prompt (open question 3).
- **Log flushing** by a credential holder (§5 residual). If it is seen in practice, add a per-kind rate cap.
- **A server clock that goes back** reorders entries (order is by `at_ms`); the log is advisory.
- **A downgrade** after new kinds were written: the older server skips the unknown codes (§7); the rows remain.

## Alternatives considered

- **Signed entries** (an account key, a server key or a server-side hash chain). Server-originated events cannot carry an account signature, and a server-held key or chain guarantees nothing against the server (§2 point 3). Rejected; the log is advisory, like ADR 0045's notice.
- **Deriving the log on the client from the signed-state history.** It covers device and credential changes only, not logins, second-factor failures, the clone signal or admin actions, which are what the log is for; and the client already verifies the signed part directly.
- **Storing the source address (full or truncated) and the user agent.** Useful for "was that me?", but it builds a location history of every user into the database and its backups (A1), departs from ADR 0075 owner answer 2 and ADR 0045 point 2, is often the proxy's address, and a malicious server forges it at will. Left to open question 1.
- **Logging every failed login and every device authentication.** Failed OPAQUE logins are unauthenticated: anyone could write rows into a named account (up to 100 per hour per name), and writing them only for real accounts would distinguish accounts before KE3. Device authentication runs at every native session start. Both would drown the alerts. Rejected; post-KE3 failures are logged (code 3).
- **A server-stored "acknowledged" marker** for the banner. An attacker with a session could acknowledge the alert their own action raised. A per-device persisted marker needs a device-state or browser-storage format change (ADR 0026/0057, CRYPTO §11.4). Rejected for M3 in favour of dismissal in memory.
- **One instance-wide row for instance-wide events** (the wait) instead of one per account. Smaller, but INV-69 says "the affected users' security event log", and per-account rows keep account deletion, caps and paging uniform.
- **A per-account sequence number as the cursor.** It needs the account lock on every insert, including §6's bulk path (one PostgreSQL advisory lock per account in one transaction); random ids with `(at_ms, event_id)` keyset paging need neither.
- **Writing the clone signal in a separate transaction.** Not needed: the refusal's transaction commits (`is_refusal`).
- **Showing users' events in the admin panel.** Administration does not need it (THREAT_MODEL §7.19 I row: "Show only what administration needs"), and it adds an XSS surface for labels.

## Open questions for the owner

1. **Source address and user agent.** Store none (this draft), a coarse prefix (/24 for IPv4, /48 for IPv6), or the full address? *Recommendation:* none at M3, matching ADR 0075 owner answer 2 and ADR 0045 point 2; reconsider in one ADR together with the session list, which would want the same field.
2. **ROADMAP row and the interim.** No row names this log, and THREAT_MODEL §7.6 lists the mitigation at M1. *Recommendation:* add "| M | Per-account security event log ([ADR 0090](adr/0090-per-account-security-event-log.md)) | M3 |" to §4.3 next to "Session/device management", and record in THREAT_MODEL §7.6 that the M1 mitigation is met at M3. Until this ADR is Accepted and built, the clone signal stays the server log line it is today (G10-15's interim question), and INV-83's "Verified by" stays unmet.
3. **A login whose password and Secret Key verified but whose second factor never arrives.** Today's flow cannot tell this from the normal first round (the client learns that 2FA is on only from `second_factor_required`), so this draft logs only a supplied factor that fails (code 3). Logging the pending state would raise an alert at every honest 2FA login unless the clients change how they log in. *Recommendation:* accept the residual at M3; revisit when a client change can send the code in the first round.

## Self-review (blockers only)

- **Gate:** docs only; no ADR's Status changed; no Context, Decision or Consequences of an Accepted ADR edited; the one superseded part (ADR 0028 item 1, first sentence, in part) is named with full replacement text that keeps ADR 0052's `icons/fetch` clause; CRYPTO.md, THREAT_MODEL.md, ROADMAP.md and CLAUDE.md edits are listed for acceptance, not made. **None found.**
- **Crypto and trust:** no construction, key, envelope purpose or signed format; the log is advisory under a new invariant (INV-110) modelled on INV-70, and no client decision reads it. **None found.**
- **Enumeration and abuse:** no entry is written before KE3 or before `H_rec` matched, so no unauthenticated request writes into a named account or gains a new oracle (§3); every write rides on an existing rate limit (§5). **None found.**
- **Privacy:** no source address, user agent, token, `session_id` or secret is stored (§4); the backup inclusion is stated with its cost (§11). **None found.**
- **Dependencies on Proposed ADRs:** codes 24 (panel and CLI paths), 25, 26 and 27 are written only once the ADRs defining those actions are Accepted (§14 step 10); everything else rests on Accepted ADRs and existing code. **None found.**

## References

- [docs/reviews/2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md) B2; raw findings G10-15, G09-15, G06-10, G09-24, G09-25, G06-15 and G10-17 in [docs/reviews/2026-10-25-raw/](../reviews/2026-10-25-raw/).
- [THREAT_MODEL.md](../THREAT_MODEL.md): §7.6, §7.19, INV-7, INV-8, INV-25, INV-48, INV-69, INV-70, INV-83, AR-9; actors A1, A2, A3, A15.
- [CRYPTO.md](../CRYPTO.md): §5.9, §11.2 step 8, §11.4, §11.5.
- ADRs: [0020](0020-partial-supersession.md) point 9; [0023](0023-logical-backup-format.md); [0028](0028-api-v1-http-conventions.md) items 1, 3, 6, 7; [0045](0045-recovery-pending-notification.md); [0048](0048-per-account-storage-quota.md); [0052](0052-icon-proxy-role.md); [0058](0058-webauthn-2fa-second-factor.md) point 5 and owner answer 4; [0060](0060-admin-panel-stack-boundary.md); [0061](0061-notify-websocket-protocol.md) (Proposed); [0071](0071-encrypted-db-backup-format.md); [0075](0075-session-listing-and-ending.md) §7, §8 and owner answers; [0081](0081-multiple-vaults-personal-and-shared.md) §0; [0085](0085-admin-authentication-bootstrap.md) and [0086](0086-instance-settings-persistence.md) (Proposed).
- Code (V, at 262bbd0): `crates/rizzy-server/src/http/api.rs` (lines 727–739), `crates/rizzy-server/src/lib.rs` (lines 104–105), `crates/rizzy-domain-auth/src/{lib.rs,login.rs,webauthn.rs,rules.rs,recovery.rs,totp.rs,config.rs}`, `crates/rizzy-proto/src/account.rs`, `crates/rizzy-storage/migrations/{sqlite,postgres}/`, `crates/rizzy-storage/src/tables.rs`, `apps/web/src/theme.ts`.
