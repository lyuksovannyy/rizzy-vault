# ADR 0031: Retiring old OPAQUE setups

- Status: Proposed
- Date: 2026-10-01
- Deciders: project owner
- Milestone: M1
- Supersedes: [ADR 0028](0028-api-v1-http-conventions.md) item 3 in part (one new `409` code, point 3), on acceptance.

## Context

[CRYPTO.md §5.8](../CRYPTO.md#58-loss-or-rotation-of-the-server-opaque-secrets) rotates `server_setup` in four steps. Step 4 reads: "After a grace period set by the admin, delete #1. Accounts that never logged in during the grace period take the device or recovery path." [ADR 0003](0003-authentication-opaque.md) point 8 points there; ADR 0022 point 10 only removes ADR 0003 point 10 (On-device mode stores no record) and changes nothing here. Step 4 cannot be built as written (survey of the code at `2057d15`, V):

- **Nobody can delete.** The server never writes the secrets file ([ADR 0010](0010-server-shape.md) §4); only one-off admin commands do, with the server stopped. No ADR names such a command, `docs/self-hosting.md` §5 records the gap, and `rizzy-server`'s docs list it as not built.
- **No clock and no length.** "A grace period set by the admin" names no start, no default and no setting. The DB records a setup (`auth_opaque_setups.created_at_ms`) only at the first server start after `secrets rotate`.
- **Step 3 has no trigger.** Nothing tells a client its record is on an old setup: `LoginFinishResponse` and `DeviceAuthFinishResponse` carry no such flag. The commit for a same-password re-registration exists (`commit_change`, allowed over a device session), but no client calls it for this. So today no account ever moves, and step 4 would cut off every account that existed before the rotation.
- **Re-adding.** A record whose setup is missing from the file already takes the fake-record path of §5.9 at login (`login.rs`), and the startup check allows such records. But a later secrets file that holds the old setup again (an old secrets backup) silently brings it back.
- **A race.** `reregister_start` and signup (`register_start`) start under the current setup and the commit labels the record with the setup current *at commit time*. A `secrets rotate` and restart in between labels a record built under #1 as #2, and that account's OPAQUE login fails for good (V, `change.rs` `replaced_credential`, `signup.rs`).
- **Password and SK changes keep nothing old.** `auth_credentials` has one row per account, replaced atomically under the credential-replacement rule ([CRYPTO.md §11](../CRYPTO.md#11-flows), §11.5 step 5). There is no old *registration* to retire after a password or SK change; only old *setups* need retiring.

## Decision

1. **What is stored per setup.** The secrets file keeps `server_setup` per `setup_id` ([CRYPTO.md §5.11](../CRYPTO.md#511-server-side-encryption-not-zero-knowledge), [ADR 0028](0028-api-v1-http-conventions.md) item 13; unchanged). `auth_opaque_setups` gains one nullable column, `retired_at_ms`, in a new migration (and so a new schema version for [ADR 0023](0023-logical-backup-format.md) backups). A setup row is **never deleted**: it is the tombstone that keeps a retired setup retired, and `auth_credentials.setup_id` references it. The setup's **successor time** is the smallest `created_at_ms` of a row with a higher `setup_id`; the current setup (highest id) has none.
2. **Transparent re-registration (§5.8 step 3) gets its trigger.** `LoginFinishResponse` and `DeviceAuthFinishResponse` gain `reregister: bool`, true when the account's record names a setup other than the current one. It is sent only after KE3 or the device signature verified, so it leaks nothing to an unauthenticated prober (§5.9). A client that receives it, and holds the typed password in this unlock, runs the same-password re-registration (`password_epoch` and `kdf_id` unchanged, `state_seq + 1`) over that session, at most once per unlock. A client that has no typed password (a keystore unlock, M3/M7) does it at the next typed unlock. The flag carries no `kdf_id` and no setup: the client's allow-list and preferred `kdf_id` apply as always (§6).
3. **The setup a registration used is the one stored.** `RegisterStartResponse` (signup) and `ReregisterStartResponse` gain `setup_id: u32`; the client echoes it in `RegisterFinishRequest` and in `CommitChangeRequest` with a `registration_upload`, and the server labels the record with the **echoed** id. Order at commit: first the byte-identical-repeat check (ADR 0028 "Retry after an unknown outcome", rows "Commit" and "Register finish"; a repeat of an applied commit is success whatever its `setup_id`), then the setup check. The server accepts an echoed id that the secrets file loads and the DB has not retired, current or not: an ordinary rotation leaves resends byte-identical, and point 2 moves the record later. It refuses a retired or unknown id with a new code, `409 setup_retired`, distinct from `state_conflict` so that the client never takes its CAS resend path (`on_state_conflict`, which would resend the same `registration_upload`). A client that lies only mislabels its own record.
4. **Who configures the grace period.** The admin, per run of the command in point 5: `--grace-days N`, default **90**, any value 0–3650. 0 retires at once, for a setup known to be leaked; the command then asks for no further confirmation but prints the cost (point 5). There is no server setting: the server never acts on the grace period by itself.
5. **Exactly when a setup stops being accepted.** `rizzy-vault secrets retire-setups [--grace-days N]` runs like `secrets rotate`: the server stopped, the secrets mount writable, the SQLite writer lock or the PostgreSQL instance lock held exclusively. It selects every setup that is not the current one, not yet retired, and whose successor time is at least N days before now. For each it prints `setup_id`, the successor time and the number of `auth_credentials` rows that still name it (ids and counts only, no account names). Then, in this order:
   1. One DB transaction: set `retired_at_ms = now` on the selected rows, only where it is still NULL (an earlier retirement keeps its time); delete every `auth_login_states` row (60 s TTL; a login started under a retired setup must not finish).
   2. Write the secrets file without **every** setup the DB marks retired: this run's selection and any earlier retirement still in the file (`fsutil::replace_private`, as `secrets rotate` does). If none is in the file, it writes nothing.

   A setup stops being accepted at the **first server start after step 2**. Until then a running server cannot exist (the lock), so there is no window in which one process accepts it and another does not.
6. **Crash safety.** The startup check, and `restore`'s `check_dump`, refuse a secrets file that holds a setup the DB marks retired ("run `secrets retire-setups` again"). So a crash between steps 1 and 2 fails closed, and re-running the command with any `--grace-days` completes it, since step 2 drops every retired setup and step 1 never rewrites a retirement time. The same check stops an old secrets backup from reviving a retired setup. Restoring a DB backup taken *before* the retirement, with the retired setup missing from the file, is allowed, as today.
7. **The accounts still on it.** Their `auth_credentials` row stays (rotations without a re-registration read it, and it holds `E_srv`), but OPAQUE login for them takes the fake-record path already coded, indistinguishable from an unknown name (§5.9). They recover access as step 4 says: an enrolled device unlocks locally, authenticates with its device key and re-registers with the typed password (point 2; the device session suffices), or the user runs recovery ([§11.9](../CRYPTO.md#119-recovery-with-the-emergency-kit)), which registers under the current setup.
8. **Sessions and pending changes.** Existing sessions, OPAQUE or device, stay valid until they end: a leaked server setup lets nobody log in as the user (that needs the password and the SK), so it gives no reason to end them. Pending login states are deleted (point 5). A pending signup or credential change (§11 "Secrets before commit") resends byte-identically after a restart, as today, through any rotation (point 3). Only if its setup was retired meanwhile, and the commit was not applied, does the server answer `setup_retired`. The client then reruns `RegisterStart`/`ReregisterStart` with the same `pw_in` (a device that restarted gets it at the next typed unlock of the pending password), and rebuilds only the OPAQUE `registration_upload` and `E_srv'` (the new export key gives a new `server_unlock_key`). It keeps the pending record's SK, account key, pending `E_local'`, `device_salt`, `E_dev`, and every other object of the request byte for byte, the signed `account-state` included (its layout, [CRYPTO.md §10.2](../CRYPTO.md#102-ed25519-signatures-and-signed-statements), covers neither the record nor `E_srv`), and replaces the persisted request in that record before it resends.
9. **The account lock.** Retirement touches no account row, so it takes no account lock; the exclusive lock of point 5 covers it. The re-registration of point 2 is an ordinary `commit_change`: account lock, compare-and-swap on `state_seq`, and deletion of the account's pending login states, as today.
10. **What the worker does.** Once per run, read only: for each non-current, non-retired setup, count the records that name it, and when its successor time is more than 90 days old (the default of point 4) log `opaque_setup_retirable` with the `setup_id` and the count, at most once a day. It never deletes, retires or writes the secrets file.
11. **Tests.** Unit: successor time; selection by grace (0, exact boundary, current never selected); `reregister` true only for a non-current setup and only after KE3; echoed `setup_id`: a loaded non-current one accepted and stored as echoed, a retired or unknown one refused with `setup_retired`, and a byte-identical repeat of an applied commit accepted before that check; the client maps `setup_retired` to the registration restart, never to `on_state_conflict`. Integration (SQLite, in-process): rotate, restart, log in, re-register over a device session, the record moves to #2; `retire-setups` prints counts, marks rows, drops the setup, deletes login states; an account still on #1 gets a login answer shaped like an unknown name's and recovers via device and via recovery; restart with the old file refused; crash after step 1 with `--grace-days 0`, then a re-run with the default 90 drops the setup and keeps its first `retired_at_ms`; a pending password and an SK change cross a `secrets rotate` and restart (resent byte-identically, accepted) and a `retire-setups --grace-days 0` and restart (refused `setup_retired`, rebuilt, committed, SK and account key unchanged); `restore` with a revived setup refused. Fuzz: the existing `server_secrets_file` target covers the file; no new parser.

## Consequences

### Positive
- §5.8 steps 3 and 4 become buildable and testable, and the rotation/registration race is closed.
- A retired setup cannot come back from an old secrets backup.

### Negative
- Wire changes (six response and request fields: two `reregister`, four `setup_id`; and one error code) and one schema migration, before v1.0 under ADR 0028's rule.
- Web-only users who did not log in during the grace period need their recovery code, and the login only says "wrong password".

### Risks
- **Malicious server.** It can always skip retirement (it is the server and holds every setup), retire early (a denial of service it can already cause by deleting records), or set `reregister` on every login: this costs the client one Argon2id and one `state_seq` per unlock and gains nothing, because the record is built with the client's own `kdf_id` and `pw_in` (the SK still blocks offline guessing, §5.5). It cannot learn a password or the SK from a re-registration. The client must not re-register more than once per unlock, and restarts a pending registration after `setup_retired` at most once per commit attempt (then fails with an error); a server that keeps answering it only blocks the change, which it can do anyway.
- **Old secrets backups** still hold a retired setup; a leaked one is a leaked setup. Operators make a new secrets backup after `retire-setups`.

## Alternatives considered

- **The worker deletes the setup.** It cannot: the server never writes the secrets file (ADR 0010 §4).
- **A server setting for the grace period.** The grace period only matters when the command runs, and a second place to set it invites the two to disagree.
- **Delete the stale credential rows.** Breaks rotations that read the held row and gives nothing the missing setup does not.
- **End sessions authenticated under the retired setup.** Sessions do not record their setup, and a setup leak does not let anyone authenticate as the user.

## Open questions for the owner

1. **Grace default 90 days, range 0–3650.** Recommendation: yes; 0 allowed for a known leak.
2. **Wire changes before v1.0** (points 2–3). Recommendation: make them now, with the minimum client versions of ADR 0002 point 5.
3. **Refusal code for a stale `setup_id`.** Recommendation: a new `409 setup_retired` (point 3), not `state_conflict`, which the client already reads as "re-fetch and resend the same request".
4. **Should `retire-setups` also refuse when more than some share of accounts would be cut off?** Recommendation: no; print the count and let the admin decide.

## On acceptance

CRYPTO.md §5.8, "Rotating `server_setup`", steps 3 and 4, are replaced. Current text:

> 3. A successful login against a #1 record triggers a transparent re-registration under #2. This costs one extra Argon2id, once.
> 4. After a grace period set by the admin, delete #1. Accounts that never logged in during the grace period take the device or recovery path.

New text:

> 3. After a successful OPAQUE login or device authentication against a #1 record, the server answers `reregister = true`, and a client holding the typed password re-registers under #2 with the same password (one extra Argon2id, once). Registrations echo the `setup_id` they started under, and the server labels the record with it; it refuses a retired or unknown one with `setup_retired` ([ADR 0031](adr/0031-retiring-old-opaque-setups.md)).
> 4. `rizzy-vault secrets retire-setups --grace-days N` (default 90), with the server stopped, marks every non-current setup whose successor was recorded at least N days ago as retired in the DB and removes it from the secrets file. From the next start its records take the fake-record path ([§5.9](#59-account-enumeration)) and their accounts take the device or recovery path. The server refuses a secrets file that holds a retired setup.

CRYPTO.md §11, "Secrets before commit", last paragraph. Current text:

> On restart with a pending record, the client fetches `account-state`: if the server holds the new state it finalises, otherwise it resends the same request. The server treats a repeat of an already-applied commit (byte-identical new state) as success.

New text:

> On restart with a pending record, the client fetches `account-state`: if the server holds the new state it finalises, otherwise it resends the same request. The server treats a repeat of an already-applied commit (byte-identical new state) as success, checked before anything else. If the request's OPAQUE setup was retired meanwhile, the server answers `setup_retired`; the client then reruns the registration with the same `pw_in`, replaces only the OPAQUE upload and `E_srv` in the persisted request, keeps every other object and secret of the pending record, and resends ([ADR 0031](adr/0031-retiring-old-opaque-setups.md) point 8).

CRYPTO.md §11.1 step 8, third server bullet: "records the `setup_id`" becomes "records the `setup_id` echoed from step 4.2's answer (refused with `setup_retired` if retired or unknown)". §11.5 step 3 gains: "The client echoes the `setup_id` of `ReregisterStartResponse` in the commit." ADR 0028 item 3's `409` list gains `setup_retired` (the owner sets ADR 0028's status line to "Partially superseded by ADR 0031 (item 3 in part)").

Also on acceptance: `docs/self-hosting.md` §5 loses its "Gap" note and gains the command; ADR 0003 point 8's link stands.

## References

- [CRYPTO.md](../CRYPTO.md) §5.5, §5.8, §5.9, §5.11, §11, §11.5, §11.9; [THREAT_MODEL.md](../THREAT_MODEL.md) AST-14, INV-50, INV-59
- [ADR 0003](0003-authentication-opaque.md), [ADR 0010](0010-server-shape.md) §2, §4, [ADR 0022](0022-server-mode-only.md), [ADR 0023](0023-logical-backup-format.md), [ADR 0028](0028-api-v1-http-conventions.md)
- Code at `2057d15` (V): `rizzy-domain-auth` `login.rs`, `change.rs`, `signup.rs`, `secrets.rs`; `rizzy-server` `admin.rs`; `rizzy-storage` migration `0001_auth_initial.sql`
