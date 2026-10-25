# ADR 0103: Disabled accounts: the `disabled_at_ms` state, what it refuses, the `account_disabled` code, and enabling again

- Status: Proposed
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M3
- Supersedes: on acceptance, in part: [ADR 0028](0028-api-v1-http-conventions.md) (item 3 in part: its first sentence, in the text [ADR 0048](0048-per-account-storage-quota.md) §5 gave it, gains one `403` code); [ADR 0008](0008-account-recovery.md) (decision 5, first sub-bullet). §0 quotes each part and gives its full replacement ([ADR 0020](0020-partial-supersession.md) point 9).

## Context

**Trigger.** The 2026-10-25 ADR gap review ([summary](../reviews/2026-10-25-adr-gap-review.md), finding M5) found that the admin panel has a "disable user" screen and nothing defines what a disabled account is. The owner said "start" (2026-10-25) after the review. This ADR is that definition.

**The findings, quoted** ([G06](../reviews/2026-10-25-raw/G06.md), [G10](../reviews/2026-10-25-raw/G10.md)):

- **G06-15 [major]** "'Disable user' has a screen but no defined behaviour". Evidence, [ADR 0060](0060-admin-panel-stack-boundary.md) §4: "What it fixes at M3: the user-list, disable-user and SMTP screens". The gap: "No Accepted ADR … defines what a disabled account is. Undefined: whether OPAQUE login and device-auth are refused and with which error (without breaking CRYPTO.md §5.9 enumeration resistance), whether existing sessions and `notify` connections end, whether sync, shares and aliases keep working, whether it can be undone, and where the flag is stored. Two implementers would build incompatible and possibly enumerating behaviour." Suggested resolution: "Specify the disabled state (storage, the login response …, session revocation through the ADR 0075 machinery, effect on shares and notify, re-enable) before the screen is built."
- **G10-17 [major]** "The M3 admin-panel row rests on one Accepted ADR (0060) and three Proposed ones (0085, 0086, 0087); 'disable user' has no mechanism ADR."

**What binds today.**

- [ROADMAP §4.9](../ROADMAP.md): "S | Admin panel (user list, disable user, invite-only signup, SMTP settings for notifications) | M3".
- [ADR 0060](0060-admin-panel-stack-boundary.md) (Accepted) §1 places the screen: "one page per screen (user list, disable-user confirm, signup-mode toggle, SMTP settings)". It defines no behaviour.
- [ADR 0028](0028-api-v1-http-conventions.md) item 3 (Accepted, partially superseded) keeps the error set closed. Its first sentence is now the text [ADR 0048](0048-per-account-storage-quota.md) §5 gave it ("The complete item 3 replacement"). The rest of item 3 stands: "Clients read an unknown code as `unknown` and branch on the code, never on the status."
- [CRYPTO.md §5.9](../CRYPTO.md#59-account-enumeration): "Nothing else that differs between real and fake accounts is sent before KE3 verifies."
- [ADR 0075](0075-session-listing-and-ending.md) (Accepted) §6: an ended session's row "is deleted in the transaction that ends the session", and "The next request with that token gets `401 unauthorized`, byte for byte the same answer as an unknown or expired token". On `notify`: "If ADR 0061 is accepted, a socket closes at its next `session_is_live` check (≤ 30 s)."
- [ADR 0008](0008-account-recovery.md) decision 5 (Accepted; the ADR is partially superseded by ADR 0022 at point 7 only): "After a **72 h** wait, admin-configurable from 0 to 30 days, the server releases `E_rec`." and "Any enrolled device can cancel the pending recovery."
- [ADR 0045](0045-recovery-pending-notification.md) (Accepted) point 3: the `pending_recovery` notice's "`opened_at_ms`/`available_at_ms` come from the server's existing `pending_recovery` row … The field clears exactly when that row clears … No new clearing path." Point 4: it is shown only to a device session.
- [ADR 0048](0048-per-account-storage-quota.md) (Accepted): per-account counted bytes and quota.

**Proposed ADRs this one fits.**

- [ADR 0085](0085-admin-authentication-bootstrap.md) (admin auth and audit) §8 defines `auth_admin_audit` (`actor_kind` `panel` | `cli` | `system`, `target_account_id`, `detail` "≤ 256 bytes, fixed per action"), and §9.3 lists "ADR 0060's user screens: one action per screen (for example `user_disabled` with `target_account_id`)". §7 sets the CLI pattern: commands that write "against the live database as ADR 0087 §11's `invite` commands do (one insert, no exclusive lock)".
- [ADR 0090](0090-per-account-security-event-log.md) (per-account security event log) gives codes 25 `account_disabled` and 26 `account_enabled` (alert, actor `admin_panel` or `operator_cli`), and §10 says: "The semantics of 'disable user' are not decided here. … This ADR fixes only its log entry: the disable (enable) action writes exactly one code 25 (26) row for the target account, in the transaction that changes the account and writes ADR 0085's `auth_admin_audit` row. Sessions it ends get no separate code 22 or 23 rows. The user reads the entry as soon as that ADR lets the account list events again (at the latest after re-enabling)."
- [ADR 0091](0091-revoked-device-rotation-race.md) and [ADR 0092](0092-rotation-size-limits.md) each also replace ADR 0028 item 3's first sentence, and so does [ADR 0068](0068-alias-identity-model.md) (M6). §0 below follows ADR 0091's pattern, so the sentence comes out the same in whatever order they are accepted.
- [ADR 0064](0064-share-api-storage-lifecycle.md) (shares, M5) and [ADR 0068](0068-alias-identity-model.md) (aliases, M6) are after v1.0. This ADR states the rule they must follow and builds nothing for them.

**The code as it is** (V, this checkout, f3492b2):

- `auth_accounts` has only `id`, `login_name` and `created_at_ms` (`crates/rizzy-storage/migrations/postgres/0001_auth_initial.sql`). The last migration is `0011_auth_invalidate_pending.sql`.
- Every flow that issues a session calls `session::create` inside a transaction that already holds `lock_account`: `login.rs` (line 347), `device.rs` (line 330), `recovery.rs` (line 351). The WebAuthn second factor also takes `lock_account` (`webauthn.rs`). `recovery_start` takes the lock right after the name lookup, on an all-zero id for an unknown name (`recovery.rs` line 174).
- `session::end_all(conn, account_id)` exists (`session.rs` line 254), and so does the query `sessions_delete_account.sql`.
- `session::load` and `reload` read one row by token hash (`session_get.sql`). I did not find an in-process session cache (L: grep only).
- `auth_pending_recoveries` holds `opened_at_ms` and `available_at_ms`, with `CHECK (available_at_ms >= opened_at_ms)`.

**What forces the design.**

1. The check must not turn login, device-auth or recovery into an enumeration oracle (CRYPTO.md §5.9).
2. The code set is closed. A plain `401` makes the web vault say "This session has ended" and makes a native client re-run device auth (ADR 0075 §6), so the user believes the password is wrong and may start a recovery.
3. The account holder must not lose data. The owner's brief: nothing is deleted, and quota is still counted.
4. Disabling is something the server decides about its own service. The server holds no plaintext and no keys that could undo what a client has already synced (THREAT_MODEL: availability is not a goal against the server). It must not pretend otherwise.
5. A disable while a recovery is pending must not let a recovery-kit thief complete the recovery unseen. While the account is disabled, its devices cannot cancel the recovery or see ADR 0045's notice.

## Decision

### 0. What this ADR supersedes ([ADR 0020](0020-partial-supersession.md) point 9)

**0.1. [ADR 0028](0028-api-v1-http-conventions.md) item 3, first sentence, in the text [ADR 0048](0048-per-account-storage-quota.md) §5 gave it.** The current text:

> Every error under `/api/` is `{"error":"<code>"}` with this status: `invalid_request` and `client_too_old` 400; `unauthorized` and `second_factor_required` 401; `fresh_session_required` 403; `not_found` 404 (also an unknown `/api/` path, and a role not running); `state_conflict`, `stale_epoch`, `record_conflict`, `prev_seq_mismatch`, `setup_retired` (ADR 0031 point 3: a registration whose echoed OPAQUE `setup_id` is retired or unknown), `credentials_stale` (ADR 0032 §4: after KE3 verified, the account's OPAQUE record lags its signed state), `quota_exceeded` (this ADR §3: the record would push the account's counted bytes past its quota and headroom) 409; `api_version_gone` 410; `payload_too_large` 413; `rate_limited` 429; `internal` 500.

Replaced in full by the sentence below. It carries forward the glosses of ADR 0031, ADR 0032 and ADR 0048. It also carries the codes of the Proposed [ADR 0091](0091-revoked-device-rotation-race.md), [ADR 0092](0092-rotation-size-limits.md) and [ADR 0068](0068-alias-identity-model.md), so the sentence is the same whichever is accepted first. **Leave out the entry of any of those three that is not Accepted when this ADR is.**

> Every error under `/api/` is `{"error":"<code>"}` with this status: `invalid_request` and `client_too_old` 400; `unauthorized` and `second_factor_required` 401; `fresh_session_required`, `account_disabled` (ADR 0103 §3: every credential and factor check of the flow passed, and an admin has disabled the account) 403; `not_found` 404 (also an unknown `/api/` path, and a role not running); `state_conflict`, `stale_epoch`, `record_conflict`, `prev_seq_mismatch`, `setup_retired` (ADR 0031 point 3: a registration whose echoed OPAQUE `setup_id` is retired or unknown), `credentials_stale` (ADR 0032 §4: after KE3 verified, the account's OPAQUE record lags its signed state), `quota_exceeded` (ADR 0048 §3: the record would push the account's counted bytes past its quota and headroom), `revocation_pending` (ADR 0091 §2: another device's revocation window is open), `rotation_limit` (ADR 0092 §3: the write would take the account or a vault past the size it can still rotate in one request), `alias_local_part_taken` (ADR 0068 §3: the new alias's address is allocated on this instance, now or at any earlier time), `alias_limit_reached` (ADR 0068 §3: the account already holds its maximum number of aliases) 409; `api_version_gone` 410; `payload_too_large` 413; `rate_limited` 429; `internal` 500.

The rest of item 3 is not superseded, including "Clients read an unknown code as `unknown`".

**0.2. [ADR 0008](0008-account-recovery.md) decision 5, first sub-bullet.** The current text:

> - After a **72 h** wait, admin-configurable from 0 to 30 days, the server releases `E_rec`.

Replaced in full by:

> - After a **72 h** wait, admin-configurable from 0 to 30 days, the server releases `E_rec`. Time while an admin has disabled the account ([ADR 0103](0103-disable-user.md) §5) does not count toward the wait, and the server releases nothing to a disabled account.

The rest of decision 5 is unchanged. "Any enrolled device can cancel the pending recovery" still holds once the account is enabled again.

Nothing else is superseded. In particular:

- ADR 0060 keeps its screens; §7 defines what they do.
- ADR 0075 keeps every rule. Disabling ends sessions through its §6 deletion semantics; it adds no endpoint.
- ADR 0045 keeps points 3 and 4. The pause in §5 changes the value in the row; it adds no clearing path.

### 1. The account state

- **Column.** `auth_accounts.disabled_at_ms`: `BIGINT NULL`, `CHECK (disabled_at_ms IS NULL OR disabled_at_ms >= 0)`, in both engines. `NULL` means active. A value means disabled, and records when, in ms since the Unix epoch (server clock). There are no other states, no reason field and no "disabled until".
- **Migration.** One new migration per engine, `NNNN_auth_account_disabled.sql`, with the number next free at implementation. It is one `ALTER TABLE auth_accounts ADD COLUMN …`. Existing rows become active (`NULL`). SQLite accepts a `CHECK` on an added column (L: SQLite documentation on `ALTER TABLE ADD COLUMN`, not re-read for this draft). If it does not, the implementation rebuilds the table the way earlier migrations do.
- **Backups.** The column is part of `auth_accounts`, so it is in ADR 0023's `TABLES` (`rizzy-storage/src/tables.rs`) and in every backup. A restore brings back the state that was in the backup. Restoring a backup taken before a disable makes the account active again (see Risks).
- **Not in any signed or client-verified object.** The flag is not in the signed account state, the device set, `AccountView` or any envelope. No key, grant, certificate, record or quota counter changes when it is set or cleared.

### 2. Disabling is a service decision, not a cryptographic one

When an account is disabled, the server stops serving it. That is all it does:

- No key is rotated, no device is revoked or suspended, no grant is withdrawn, no ciphertext is touched or deleted.
- Whatever a client has already synced stays readable on that client. The server cannot undo that, and this ADR does not claim it can.
- Enabling again restores service exactly as it was. No client has to do any key work.
- Nothing is deleted: vault records, attachments, the OPAQUE record, recovery data, 2FA credentials, security keys, devices, shares and aliases all stay.
- The counted bytes stay counted against the account's quota and the instance's totals (ADR 0048). The login name stays taken: `register/*` and ADR 0087 invites treat it as any existing account.
- Server-internal maintenance (compaction, expiry sweeps, backups, ADR 0090 §5's retention sweep) treats a disabled account like any other.

An admin who wants an account's data gone needs account deletion. No ADR defines it, and it is out of scope here.

### 3. What is refused while disabled, and with which answer

**One code: `account_disabled`, HTTP `403`**, body `{"error":"account_disabled"}`. `rizzy-proto::error::ErrorCode` gains `AccountDisabled`, documented as naming this ADR. `http::api::status` maps it to `403`.

**The check point (the leak rule).** A flow learns of the disabled state only at its **check point**: right after the last credential or factor check the flow performs has passed, and before the flow writes or returns anything beyond that check. Before the check point, a disabled account is handled exactly like an enabled one: same queries, same rate-limit charges, same answers. A wrong password, a wrong factor or a wrong recovery code on a disabled account gets the same `401 unauthorized` (or `second_factor_required`) as on an enabled account. So `account_disabled` is only ever shown to someone who has just proven they hold the account's credentials, and an unknown name, a wrong password or a probe never sees it (CRYPTO.md §5.9). At the check point, the rate-limit buckets are charged as for a success.

| Flow | Check point | While disabled |
|---|---|---|
| `login/start` | none (no credential is verified yet) | unchanged: same answer as for an enabled account |
| `login/finish` (OPAQUE; also re-authentication) | KE3 verified and, if the account has 2FA, the second factor verified. With 2FA, `login/finish` still answers `second_factor_required`, and the check point is the TOTP or WebAuthn step that would issue the session | `account_disabled`; no session, no event row |
| `device-auth/start` | none | unchanged |
| `device-auth/finish` | the device signature verified against a usable durable device | `account_disabled`; no session |
| `recovery/start` | the recovery code verified (in the code's constant-time path) | `account_disabled`; no pending recovery is opened and no ADR 0090 code 13 row is written |
| `recovery/complete` | the recovery code verified, before any check of the wait | `account_disabled`; no `E_rec`, no recovery-only session, no code 15 row |
| `register/*` | none | unchanged (the name is taken) |
| every endpoint that needs a session (sync reads and writes, `account/state`, devices, healing, `account/commit`, TOTP, WebAuthn management, sessions, attachments, `recovery/cancel`) | the session check | `401 unauthorized`: the account has no sessions (§4), and `session::load` refuses one if it finds one (below) |
| `GET /api/meta` | none | unchanged (it is not per account) |

**Backstop.** `session::create` reads `disabled_at_ms` in the caller's transaction, which already holds `lock_account` (V, §Context), and returns `AuthError::AccountDisabled` when it is set. `session_get.sql` joins `auth_accounts` and treats a session row of a disabled account as absent, so `load` and `reload` return `Unauthorized`. Neither should ever fire if §4 holds. They are there so that a missed check point fails closed.

**Why `403` and not `401`.** A `401` means "your credential or session is not valid", and clients act on it: the web vault locks and asks for the password, and a native client re-runs device auth. Here the credential is valid. The account holder must not be led to doubt the password or start a recovery. `403` is "authenticated, and refused".

### 4. Disabling: one transaction, sessions end at once

`rizzy-domain-auth` gains `AuthService::set_account_disabled(account_id, disabled: bool, actor: AdminActor, now_ms) -> Result<Outcome, AuthError>`, with `Outcome` either `Changed` or `Unchanged`. The CLI (§6) and the panel (§7) both call it. The steps, in one write transaction:

1. `lock_account(account_id)`, the same lock every session-issuing flow takes.
2. Read the `auth_accounts` row. If there is none, return `AuthError::NotFound`.
3. If the account is already in the requested state, commit nothing and return `Unchanged`. No audit row and no event row are written (ADR 0090: "Idempotent repeats write nothing").
4. **Disable:**
   - `UPDATE auth_accounts SET disabled_at_ms = now_ms`.
   - `session::end_all` (`sessions_delete_account.sql`): every session of every kind (1 OPAQUE, 2 device, 3 recovery-only) is deleted. There is no tombstone (ADR 0075 §6).
   - In-flight login states, second-factor-pending rows and device-auth challenges are not deleted. They expire on their own TTLs, and each step that could issue a session re-checks at its check point under the same lock.
5. **Enable:**
   - `UPDATE auth_accounts SET disabled_at_ms = NULL`.
   - Apply §5's pause to a pending recovery, if there is one.
6. Insert the `auth_admin_audit` row (ADR 0085 §8): action `user_disabled` or `user_enabled`, `target_account_id` set, `detail` the empty string (the action is fixed; no free text, no login name), and the `actor_kind`/`actor_admin_id` of the caller.
7. Insert exactly one ADR 0090 row for the account: code 25 `account_disabled` or code 26 `account_enabled`, with `actor_kind` `admin_panel` (and `actor_admin_id`) or `operator_cli`. Ended sessions get no code 22 or 23 rows (ADR 0090 §10). (`account_disabled` is also the error code's name; the two live in separate namespaces.)
8. Commit, and return `Changed`.

**Crash and retry.** If any insert fails, the transaction rolls back (ADR 0090 §9's fail-closed rule) and the caller sees a failure. A crash before the commit leaves nothing; a crash after it leaves everything. Re-running the command is always safe: a repeat finds the target state and returns `Unchanged`.

**Race with a login.** A login or device-auth that commits its session before the disable takes the lock has that session deleted by step 4. One that reaches its check point after the disable commits is refused. So once the disable commits, no session of the account exists or can be created (INV-118). A request that was authenticated before the commit may still finish. For reads, ADR 0075 §6 accepts this. For vault writes it is the same residual, at most one request per session already in flight: I have not checked whether every vault-write path re-reads its session inside its own transaction (L).

**`notify`.** If [ADR 0061](0061-notify-websocket-protocol.md) is accepted, an open socket closes at its next `session_is_live` check (≤ 30 s), because its session is gone (ADR 0075 §6). This ADR adds no push of the disable.

### 5. Recovery: the wait pauses while the account is disabled

- **While disabled:** `recovery/start` and `recovery/complete` are refused at their check points (§3). An existing `auth_pending_recoveries` row is kept unchanged at disable time.
- **On enable**, in §4 step 5's transaction: if a pending row exists, then `available_at_ms := available_at_ms + max(0, now_ms − disabled_at_ms)`, saturating at `i64::MAX`. `opened_at_ms` is unchanged, so the `CHECK` still holds. `max(0, …)` makes a backwards clock step a zero shift.
- **Why.** The ADR 0008 wait exists so that the owner's devices see the recovery and can cancel it. While the account is disabled they can do neither. Without the pause, a wait that ran out during the disable would let whoever holds the recovery kit complete the recovery the moment the account is enabled, before any device could see ADR 0045's notice. With the pause, the owner gets the same time to see the notice and cancel that remained when the account was disabled. If the wait had already run out before the disable, it is still over after the enable, because the owner already had the full wait.
- **ADR 0045's notice** reads the row as before (point 3). After the enable, a device session sees `available_at_ms` with the shift. No new field is added, and no clearing path either.
- `last_recovery_at_ms` is unaffected.

### 6. CLI: `rizzy-vault account disable|enable`

Two subcommands in `crates/rizzy-server/src/cli.rs` (the operator CLI; ADR 0060 §1 keeps it apart from `http/admin_panel`):

- `rizzy-vault account disable <login_name>` and `rizzy-vault account enable <login_name>`.
- **Name.** The argument is normalised with the CRYPTO.md §2 login-name function. A name that does not normalise exits with code 1 and prints `invalid login name` to stderr. A name with no account exits with code 1 and prints `no such account`. The operator is trusted, so naming the absence is fine.
- **Database.** The command writes against the live database the way ADR 0087 §11's `invite` commands do: one transaction, no exclusive instance lock. The server may be running. Sessions live only in the database, so the effect is immediate.
- **Output.** Exactly one line to stdout:
  - `disabled <login_name>` or `enabled <login_name>` (exit code 0), or
  - `unchanged <login_name>: already disabled` or `unchanged <login_name>: already enabled` (exit code 0).
  Any storage failure exits with code 1 and prints `internal error` to stderr. No secret is printed, and the account id is not printed.
- **Actor.** The audit `actor_kind` is `cli` (ADR 0085 §8.1). The ADR 0090 `actor_kind` is `operator_cli`.

### 7. Admin panel: the disable-user confirm screen (ADR 0060 §1)

Under `RIZZY_ADMIN_LISTEN`, with ADR 0085's session, CSRF, Host check and rate limits:

| Route | Does |
|---|---|
| `GET /admin/users/{id}/disable` | The confirm page. It shows the login name, the creation date and the counted bytes, and states what happens: "Sign-in, sync and recovery stop for this account. All its sessions end now. Nothing is deleted. You can enable it again." `{id}` is the account id as 32 lowercase hex characters; anything else, or an unknown id, is the listener's plain `404`. |
| `POST /admin/users/{id}/disable` | CSRF checked, then `set_account_disabled(…, true, panel actor)`, then `303` to the user list with a one-line notice: "Disabled." or "Already disabled." |
| `GET /admin/users/{id}/enable`, `POST /admin/users/{id}/enable` | The same, for enable. The confirm text: "Sign-in, sync and recovery work again. A pending recovery's wait resumes where it stopped." |

The user list shows each account's state: "Active", or "Disabled since <UTC date and time>".

### 8. Clients

- **Web vault and extension.** On `account_disabled`, show: "This account is disabled on this server. Nothing has been deleted. Contact the server's administrator." Do not lock-and-retry, do not suggest recovery, and do not clear local state beyond what an ordinary lock clears.
- **Native clients and `rv`.** On `account_disabled` from `device-auth/finish`, stop ADR 0075 §6's single retry. Do not run device auth again automatically until the user acts or the app restarts. Keep the device state, keys and cache. `rv` prints the same sentence and exits non-zero, as for any server error (the exit-code mapping is `rv`'s own, U).
- **Old clients** read the code as `unknown` (ADR 0028 item 3) and show a generic error. That is safe.

### 9. Shares and aliases (M5, M6: rules for their ADRs, nothing built now)

- **Shares (ADR 0064).** Opening a share whose owner account is disabled gets `404 not_found`, exactly as an unknown, revoked or expired share does. The recipient is not the account holder and learns nothing. Share rows stay, and their expiry keeps running. Once the account is enabled, unexpired shares open again.
- **Aliases (ADR 0068).** Mail to an alias of a disabled account is handled exactly as mail to a disabled alias under ADR 0068's Q-18 rule. No alias is deleted.

### 10. Invariant (proposed; drafted as **INV-118**, provisional, its number assigned at acceptance)

| ID | Invariant | From | Verified by |
|---|---|---|---|
| INV-118 | Once a disable of an account commits, no session row of that account exists, and no flow issues a session, opens a pending recovery or returns `E_rec` for it until an enable commits. A flow answers `account_disabled` only after every credential and factor check it performs has passed. Before that point, its queries and answers for a disabled account are the same as for an enabled one. Disabling and enabling delete no account data and change no key, grant, certificate, signed statement, envelope or quota counter. | ADR 0103 | §11 tests 1–7, 9, 12 |

### 11. Implementation plan and tests

Prerequisites: this ADR, ADR 0085 (audit table, panel) and ADR 0090 (event codes 25 and 26) Accepted. The CLI part needs only this ADR and ADR 0090. Without ADR 0085 there is no `auth_admin_audit`, and step 6 waits for it.

1. Migration (both engines) and the `TABLES` entry; `cargo xtask check-tables`.
2. `ErrorCode::AccountDisabled`, `AuthError::AccountDisabled`, the `403` mapping, and a `rizzy-proto` round-trip test.
3. The `session::create` backstop and the `session_get.sql` join; the check points in `login.rs`, the TOTP and WebAuthn login steps, `device.rs` and `recovery.rs`.
4. `set_account_disabled` with §4's steps and §5's pause.
5. CLI (§6), then the panel routes (§7), then the client messages (§8).

Tests: `rizzy-domain-auth` runs each on both engines; `rizzy-server` gets HTTP integration tests; the panel and web parts get e2e tests.

1. Disable sets the column and deletes sessions of all three kinds. It writes one audit row and one code 25 row. Another account's sessions are untouched.
2. The leak rule for login. On a disabled account, `login/start`'s answer has the same shape and `kdf_id` as on an enabled one. A wrong password gets `unauthorized`; the right one gets `account_disabled`. With TOTP: `second_factor_required` first, then a wrong code gets `unauthorized` and a right code gets `account_disabled`. The same for a WebAuthn second factor.
3. `device-auth/finish`: a valid signature gets `account_disabled`; an invalid one gets `unauthorized`.
4. `recovery/start`: the right code gets `account_disabled`, with no pending row and no code 13 row. A wrong code gets `unauthorized`.
5. `recovery/complete` with a pending row on a disabled account: `account_disabled`, no `E_rec` in the body, no session.
6. Table-driven over the endpoint table in `http/api.rs`: every session endpoint called with a token issued before the disable gets `401` `{"error":"unauthorized"}`, byte-identical to an unknown token.
7. The backstop: a session row inserted directly for a disabled account (test fixture) gets `401`, and `session::create` on a disabled account returns `AccountDisabled`.
8. Enable clears the column and writes one audit row and one code 26 row. Login works again. Vault records, attachments and counted bytes are byte-identical before the disable and after the enable.
9. The pause: open a recovery at t0 with wait W, disable at t1, enable at t2. Then `available_at_ms = t0 + W + (t2 − t1)`, and the ADR 0045 notice shows it. With t2 < t1 the shift is 0. A wait that ran out before t1 is still over after t2.
10. Idempotency: disabling twice writes nothing the second time, and the CLI prints `unchanged …` with exit code 0. The same for enabling an active account.
11. Crash: with a fault injected on the audit insert or the event insert, the transaction rolls back, the column is unchanged and the sessions are intact.
12. Race: concurrent `login_finish` (and `device_auth_finish`) against disable, 200 iterations behind a barrier. After the disable commits, no session row of the account exists.
13. Quota: with one account disabled, the instance totals and that account's counted bytes are unchanged.
14. Registering the disabled account's name answers as for any taken name.
15. CLI: an invalid name, an unknown name, success, unchanged, and the exact stdout lines and exit codes.
16. Panel: CSRF is required; a malformed or unknown `{id}` gets `404`; the audit row's actor is `panel` with the admin id; the confirm and list pages are in the axe audit and the keyboard-only walk.
17. Web e2e: logging in to a disabled account shows §8's message and offers no recovery link. The page passes axe.
18. If ADR 0061 is Accepted: an open `notify` socket closes within 30 s of the disable.

### 12. On acceptance (not made now)

1. ADR 0028's status line gains "; [ADR 0103](0103-disable-user.md) (item 3 in part)", and the item 3 sentence in force is §0.1's, without the entries of any ADR that is not Accepted.
2. ADR 0008's status line gains "; [ADR 0103](0103-disable-user.md) (decision 5 in part)".
3. CRYPTO.md:
   - §5.9 gains one sentence: a disabled account answers exactly as an enabled one until the check point (ADR 0103 §3).
   - The recovery flow (§11.9) gains the pause and the refusal (§5).
4. THREAT_MODEL.md: INV-118 is added under its assigned number, and §7.19 (admin panel) gains a sentence on disable as a service decision (§2).
5. ADR 0085 §9.3's example becomes the fixed pair `user_disabled` and `user_enabled` (by an edit of the Proposed ADR, or recorded at its acceptance).
6. ADR 0090 §10's "not decided here" sentence names this ADR.
7. ADR 0064 and ADR 0068 adopt §9's rules before they are accepted.
8. `docs/self-hosting.md` documents §6's commands. The `docs/adr/README.md` row's status is set.

## Consequences

### Positive

- One stored bit with one meaning, set in one transaction that also ends every session and writes both logs. Two implementers build the same thing.
- No enumeration oracle. Only a party that has just proven the account's credentials can tell a disabled account from an enabled one.
- The account holder gets a clear answer instead of a false "wrong password". Nothing is lost, and enabling again restores everything.
- A disable during a pending recovery cannot be used to run out the owner's chance to cancel.

### Negative

- One more code in item 3's closed set, so old clients show a generic error.
- A credential holder (including a thief) learns the account is disabled. That is less than the credential already gives them.
- A disabled account still uses quota and storage until a deletion mechanism exists.
- The pause can stretch a recovery wait past ADR 0008's 30-day maximum, by the time the account spent disabled.
- Every session load gains a join to `auth_accounts` (by primary key).

### Risks

- **Restoring an old backup re-enables an account** that was disabled after the backup was taken. The panel's user list shows the state, and the admin must disable the account again. This ADR does not change backups.
- **In-flight vault writes** (§4, race): at most one request per session already authenticated may still commit after the disable. Test 12 covers sessions, not that write.
- **Expectation risk.** An admin may believe disabling "locks the data". The confirm page (§7) and `docs/self-hosting.md` must say that synced devices keep what they have (§2).

## Alternatives considered

- **Plain `401 unauthorized` everywhere.** It hides the most, but only from someone who already holds the credentials. It sends the web vault into its "session ended" path and native clients into re-auth, and it pushes users toward recovery. Rejected.
- **Refuse at `login/start` or `device-auth/start`** (before any proof). That would be an enumeration oracle (CRYPTO.md §5.9). Rejected.
- **Put the flag in the signed account state.** The server cannot sign it, and it is a service decision, not a key fact (§2). Rejected.
- **Only block at `session::load`, keeping the sessions.** Rows the user can no longer use would linger, and `sessions/list` after an enable would show stale sessions. Rejected; the join is kept only as a backstop.
- **Cancel the pending recovery at disable** (delete the row). Simpler, but it adds a clearing path to ADR 0045 point 3 and loses a recovery the owner may have started legitimately. This is open question 1's alternative.
- **Keep the wait running while disabled.** It lets the wait run out unseen (§5). Rejected.
- **A free-text reason, or "disabled until".** Free text could hold personal data, and ADR 0085 fixes `detail` per action. "Until" adds a scheduler for no M3 need. Rejected for now.
- **Disable equals delete, or starts a deletion clock.** Against the owner's brief. Rejected.

## Open questions for the owner

1. **A recovery pending at disable time: pause the wait (as drafted), or cancel it?** Cancelling would delete the row, adding a clearing path that would supersede ADR 0045 point 3, and the user would have to start again. **Recommendation:** pause (§5). It keeps a legitimate recovery and still gives the owner's devices the remaining time to cancel.
2. **Show `account_disabled` after full authentication (as drafted), or answer `unauthorized` everywhere?** **Recommendation:** `account_disabled` at the check point (§3). It tells nothing to anyone without the credentials, and it stops users from chasing a "wrong password" into a recovery.

## References

- [docs/reviews/2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md); raw findings [G06-15](../reviews/2026-10-25-raw/G06.md), [G10-17](../reviews/2026-10-25-raw/G10.md).
- [ADR 0008](0008-account-recovery.md), [ADR 0020](0020-partial-supersession.md), [ADR 0023](0023-logical-backup-format.md), [ADR 0028](0028-api-v1-http-conventions.md), [ADR 0045](0045-recovery-pending-notification.md), [ADR 0048](0048-per-account-storage-quota.md), [ADR 0060](0060-admin-panel-stack-boundary.md), [ADR 0075](0075-session-listing-and-ending.md) (Accepted).
- [ADR 0061](0061-notify-websocket-protocol.md), [ADR 0064](0064-share-api-storage-lifecycle.md), [ADR 0068](0068-alias-identity-model.md), [ADR 0085](0085-admin-authentication-bootstrap.md), [ADR 0087](0087-invite-only-signup-tokens.md), [ADR 0090](0090-per-account-security-event-log.md), [ADR 0091](0091-revoked-device-rotation-race.md), [ADR 0092](0092-rotation-size-limits.md) (Proposed).
- [CRYPTO.md §5.9](../CRYPTO.md#59-account-enumeration); [THREAT_MODEL.md](../THREAT_MODEL.md) §7.19; [ROADMAP §4.9](../ROADMAP.md).
