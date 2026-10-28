# ADR 0108: An exit from an interrupted recovery whose new master password is lost (`rv recovery abandon`)

- Status: Accepted
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M1

## Context

The 2026-10-25 gap review ([summary](../reviews/2026-10-25-adr-gap-review.md), row D8: "ADR 0046 has no exit when the user can't type the new master password of an interrupted recovery (`device forget` refuses stage 3; INV-71 forbids a new kit)") records finding **G05-13** (major, [raw](../reviews/2026-10-25-raw/G05.md)). Its evidence, quoted:

- [ADR 0046](0046-recovery-pending-device-stage.md) (Accepted, implemented) §3 step 1: "Ask for the new master password just chosen in this attempt … A wrong password answers `ClientError::WrongPasswordOrSecretKey` locally". Every later step of §3 — the device-auth short-circuit, the OPAQUE-login probe, the resend and the abandon of step 5 — runs only after that unlock ("Unlock first — every later step needs it").
- [THREAT_MODEL.md](../THREAT_MODEL.md) INV-71: "Before it generates a second, different Emergency Kit … it must first learn, through ADR 0046 §3, that the first attempt's commit did not reach the server".
- Code (V, this branch at `f3492b2`): `crates/rizzy-cli/src/recover.rs` `resume` asks "New master password chosen in the unfinished recovery" and calls `record.unlock_recovery_pending(&password)?` before anything else; `crates/rizzy-cli/src/commands.rs` `device forget` returns `Err(e @ CliError::Client(ClientError::RecoveryPending))`, commented "a stage-3 record may hold the only device state of a recovery the server applied; it is settled by `rv recovery complete`, never removed unsettled". ADR 0046 §2 "Finding the record" sends every `rv recovery complete` for that server to the resume before a login name or recovery code is asked, and the fresh flow's guard refuses an account whose cache file exists (`CliError::AlreadyEnrolled`).

So a user who confirmed the new Emergency Kit, chose a new master password, lost the answer of the commit (a crash, a network failure) and then cannot type that password has no way out on this computer: the stage-3 record cannot be settled, no `rv` command removes it, and it blocks every new recovery attempt. That is a dead end for exactly the user recovery exists for.

What the user still holds without the new password, and what the server can be asked (all V unless marked):

1. **The kit of the unfinished attempt.** `confirm_kit` runs before the pre-commit write (ADR 0046 §2), so the user was shown, and confirmed, the new Secret Key and the new recovery code — call that code **R′**. The stored `pending_commit` body is a `CommitChangeRequest` (`crates/rizzy-proto/src/change.rs`) whose `recovery` field `rizzy-client`'s recovery builds as `Some(RecoveryRegistration)` (`crates/rizzy-client/src/recovery.rs`, `recovery: Some(recovery)`), and `RecoveryRegistration.recovery_token_hash` is `H_rec′ = SHA-256(recovery_auth_token(R′))` (CRYPTO.md §11.1 step 5; `server_hash` in `crates/rizzy-core/src/keys/derive.rs`). The body is stored in cleartext (ADR 0026 §3; it is a request the server reads). So **R′ can be checked locally, with no round trip and no password**.
2. **The code the attempt started from**, **R**, from the old kit: the user typed it to start this recovery.
3. **`recovery/start` answers which code is current.** `recovery_start` (`crates/rizzy-domain-auth/src/recovery.rs`) succeeds only when `SHA-256(token)` equals the stored `H_rec`, recovery is enabled and the recovery row does not lag the signed state; it answers `Unauthorized` alike otherwise (CRYPTO.md §5.9). With a valid code it returns the open pending recovery (`opened: false`) or opens one; ADR 0028's retry table makes the repeat a success. A recovery commit replaces `H_rec` (`crates/rizzy-domain-auth/src/change.rs` module table: "`recovery_epoch + 1` (new code) | `E_rec` and `H_rec`"), and recovery codes come only from the client's CSPRNG (CRYPTO.md §4.2, "Recovery code | 16 B | CSPRNG"), so the server holds `H_rec′` only if this attempt's commit landed, and holds R's hash only while it has not.
4. **A commit still in transit.** `account/commit` over a recovery-only session reloads the session under the account lock in its own transaction (`commit_change`: `lock_account`, then `session::reload`), and a missing or expired session row answers `Unauthorized` (`session::load_by_hash`). But `recovery_complete` issues a new recovery-only session (`RECOVERY_SESSION_TTL_MS`, 10 minutes) **without ending earlier ones**: only a recovery commit and a cancellation call `session::end_kind(…, SessionKind::Recovery)`. A copy of the stored commit already sent — a crashed `rv`'s last request held by a buffering reverse proxy, for example (whether and how long a proxy holds a request body: U) — can therefore still land up to 10 minutes after the session it rides was issued, even after a new attempt has started. Fact 3 says only "not landed *yet*".

What binds: [ADR 0008](0008-account-recovery.md) point 4 (using the code issues a new Secret Key and a new code, a new kit; the old kit is assumed lost) and point 5 (a valid code opens a pending recovery, every enrolled device and the account email are notified, any enrolled device can cancel); ADR 0046 §2 (stage 3, the pre-commit write, the entry-point search, INV-71), §3 (the resume; its step 5 is the one way a stage-3 record is removed today) and §5 (crash-injection tests); ADR 0026 §1 (the recovery code is never persisted) and §3 (`pending_commit`); ADR 0028 item 3 (error codes) and its "Retry after an unknown outcome" table, Recovery row; ADR 0045 (a recovery start notifies by pull; unchanged); CRYPTO.md §11 "Secrets before commit", §11.9, §5.9. Wave-1 drafts touching this area, all Proposed and none required here: [ADR 0088](0088-device-state-record-grammar.md) (the device-state grammar, stage 3 included; this ADR adds no field), [ADR 0090](0090-per-account-security-event-log.md) (security event log; it would see this ADR's probes as ordinary recovery starts — its exact event list not checked for this draft, U), [ADR 0091](0091-revoked-device-rotation-race.md) (lists `recovery/start` among endpoints; no interaction found).

## Decision

### What this ADR supersedes

Per [ADR 0020](0020-partial-supersession.md) point 9, exactly these parts, each replaced in full by the text given; nothing else in those ADRs changes.

1. **[ADR 0046](0046-recovery-pending-device-stage.md) §2, the "Proposed INV-71" paragraph, its sentence** "Before it generates a second, different Emergency Kit for the same account, it must first learn, through §3, that the first attempt's commit did not reach the server." becomes:
   > Before it generates a second, different Emergency Kit for the same account, it must first learn that the first attempt's commit is settled: through §3; or, after [ADR 0108](0108-interrupted-recovery-exit.md)'s `rv recovery abandon` removed the record, through the new attempt's own successful `recovery/complete`, which no earlier recovery-only session outlives (INV-122). A durable client removes a stage-3 record only in §3 step 5, or in `rv recovery abandon` after the server accepted the recovery code of that record's own kit or the code the attempt started from (ADR 0108 §2); never on a refusal, a timeout or an answer it cannot read.
2. **ADR 0046 §3 step 1, its last sentence** "A wrong password answers `ClientError::WrongPasswordOrSecretKey` locally; no round trip is spent." becomes:
   > A wrong password answers `ClientError::WrongPasswordOrSecretKey` locally; no round trip is spent, and the record stays. `rv` then adds that a user who cannot type this password leaves the attempt with `rv recovery abandon` ([ADR 0108](0108-interrupted-recovery-exit.md)).
3. **[ADR 0028](0028-api-v1-http-conventions.md), the "Retry after an unknown outcome" table, its Recovery row**, becomes:
   > | Recovery | `recovery/start`, `recovery/complete`, `recovery/cancel` | start returns the pending recovery; complete may be repeated with the same code until the recovery commits, and each complete that issues a recovery-only session ends every earlier recovery-only session of the account in the same transaction ([ADR 0108](0108-interrupted-recovery-exit.md) §1, INV-122); cancel reports whether one was pending; start and complete count against the rate limit | CRYPTO.md §11.9 |

### 1. Server: one live recovery-only session per account (INV-122)

In `AuthService::recovery_complete` (`crates/rizzy-domain-auth/src/recovery.rs`), inside the write transaction that already holds the account lock, after the pending-recovery and waiting-period checks succeed and **before** `session::create(…, SessionKind::Recovery, …)`, call `session::end_kind(tx.conn(), account, SessionKind::Recovery)`. Nothing else changes: same request, same response, same errors, same rate-limit hits, no new table or column, no migration.

**Proposed INV-122** (server-side; provisional number, the owner renumbers at acceptance). *A `recovery/complete` that issues a recovery-only session ends every other recovery-only session of the account in the same transaction, so at most one is live per account; a commit over an earlier one, wherever it is in transit, answers `unauthorized` once a later `recovery/complete` has been answered.* This follows from both transactions taking `lock_account` and `commit_change` reloading its session under it (V, code); that the lock serialises the two transactions on both storage backends is [ADR 0011](0011-storage.md) "Transactions and concurrency" (L: read through the code comments that cite it, not re-read for this draft).

Effect on ADR 0046 §3 step 4: its fresh session now also kills any earlier in-transit send of the same attempt; the resend is byte-identical anyway, so the outcome list of step 4 is unchanged.

### 2. `rv recovery abandon`

Grammar: `rv recovery abandon --server <origin> --name <login-name> --confirm`, with the global `--account <id>` honoured. `--server` and `--name` as for `rv recovery complete`; `--confirm` is required.

Steps, in this order:

0. **Arguments.** Without `--confirm`: `CliError::Usage("rv recovery abandon removes the unfinished recovery from this computer: pass --confirm")`, exit 2, nothing opened, nothing sent.
1. **Find the record.** The same search as ADR 0046 §2 (`enrolled_accounts`, open each, keep the stage-3 records whose `server_origin` equals `--server`). None: `CliError::NoUnfinishedRecovery` ("no unfinished recovery for this server is saved on this computer"), exit 1. More than one and no `--account`: `CliError::SeveralAccounts` (existing). Take `AccountLock` (held by another `rv`: `CliError::InUse`), reopen, and re-check `stage = 3`; any other stage: `NoUnfinishedRecovery`. A stage-1 or stage-2 record is never touched. Holding the lock to the end also means no `rv` on this computer sends the stored commit meanwhile.
2. **Read R′'s hash.** Parse `pending_commit.request` through `rizzy-proto` as `CommitChangeRequest`; take `recovery.recovery_token_hash`. Missing row, unparsable body or `recovery = None`: `ClientError::CacheCorrupt`, record kept.
3. **Ask for R′** (secret prompt): "Recovery code from the Emergency Kit made by the unfinished recovery (leave empty if you do not have it)". Non-empty: parse as `RVR1-` (format and check-character errors as for every recovery-code prompt), derive `auth_token()`, compare with `matches_server_hash` (`crates/rizzy-core/src/keys/derive.rs`, constant time). Mismatch: `CliError::BadInput("this is not the recovery code of the unfinished recovery's Emergency Kit")`, exit 1, **no request sent**, record kept.
4. **Probe A — did it land?** Only for a verified R′: `POST recovery/start {login_name, recovery_auth_token(R′)}`.
   - **`200` `RecoveryStartResponse`:** the server's `H_rec` is `H_rec′`, so this attempt's commit landed (Context fact 3). The server now holds a pending recovery for R′ (opened now, or the one already open). Remove the record (step 6) and print, with `available_at_ms` as an ISO-8601 UTC time: "The unfinished recovery had reached the server: the Emergency Kit it made is the valid one, and its new master password was set. A recovery with that kit's code is now pending. After <time>, run `rv recovery complete --server <origin> --name <login>` and type that kit's recovery code. Then revoke the device <device-id>, which this computer can no longer use." Stop; probe B does not run.
   - **`unauthorized`:** `H_rec′` is not current (not landed, or landed and later replaced, or recovery switched off). Go to probe B.
   - **Anything else** (`rate_limited`, `invalid_request`, a network error, `BadAnswer`, `internal`, an unknown code): print ADR 0046's `STILL_UNSETTLED` note, return that error, record kept.
5. **Probe B — had it not landed?** Ask for R (secret prompt): "Recovery code of the Emergency Kit this recovery started from". Empty: `CliError::RecoveryNotSettled` (below). Otherwise parse and `POST recovery/start {login_name, recovery_auth_token(R)}` (R cannot be checked locally: nothing derived from it is stored, ADR 0026 §1).
   - **`200`:** the server's `H_rec` is still R's, so this attempt's commit had not landed when the server answered. Remove the record (step 6) and print: "The unfinished recovery had not reached the server and was removed from this computer. Keep its Emergency Kit until a new recovery finishes: until then, a copy of its commit still in transit could make it the valid one, and `rv recovery complete` would then refuse the old code. A recovery with the old code is pending; after <time>, run `rv recovery complete --server <origin> --name <login>`."
   - **`unauthorized`:** neither code is current, or R was mistyped, or `--name` is wrong. `CliError::RecoveryNotSettled` ("the server accepted neither recovery code; the unfinished recovery is kept on this computer"), exit 1, record kept byte for byte. Rerunning with corrected input is the retry.
   - **Anything else:** as in probe A.
6. **Remove.** Exactly ADR 0046 §3 step 5: `abandon` in `recover.rs` (`db.close()`, then `delete_account_files` under the lock). No other write precedes it, and no secret is generated anywhere in this command.
7. **Output and exit.** Both removals exit 0. The sentences above go to standard error (`env.ui.note`); standard output gets one line, `landed <available_at_ms>` after probe A's `200` or `not-landed <available_at_ms>` after probe B's `200`, the decimal ms value as `rv recovery start` already prints it, so a script can tell the branches apart without parsing prose. Every refusal exits 1 (2 for the usage error of step 0) and prints nothing on standard output. No message, error or `Debug` output carries either code, the stored body or any part of `H_rec′` (CLAUDE.md "Never log secrets").

The `unauthorized` of probe A is never read as "not landed": only probe B's `200` is. A `recovery/start` with a valid code has the side effects any recovery start has (a pending recovery, its notice to enrolled devices per ADR 0045, the rate-limit hit, any ADR 0090 entry): in both success cases that pending recovery is the user's next step, so nothing is undone.

**Crash and retry.** The only durable write is step 6, the same single-step removal as ADR 0046 §3 step 5, so a crash leaves the record either whole or gone. A crash after a probe's `200` and before step 6 leaves the record; a rerun repeats the same probe, which ADR 0028's Recovery row answers with the same pending recovery (`opened: false`, the same `available_at_ms`), and then removes it. An unknown outcome of a probe leaves the record and possibly an opened pending recovery, which the rerun's repeat returns. Inside step 6, `delete_account_files` (`crates/rizzy-cli/src/commands.rs`) unlinks the cache file first, then any rollback journal, then the lock file: a crash after the first unlink leaves no cache file, so `enrolled_accounts` (which lists only cache files) finds no record and the removal is complete for every later command; a leftover journal or lock file is the same leftover any `rv device forget` crash leaves today (that `AccountLock::acquire` reuses a stale lock file: U, not re-read for this draft). The crash points the tests inject are therefore exactly two: after the deciding probe's answer and before step 6, and after step 6's first unlink.

**Error surface.** Two new `CliError` variants, both exit 1 and both carrying no secret: `NoUnfinishedRecovery` and `RecoveryNotSettled`, with the messages above. No new `/api/v1` error code, endpoint, field or wire message; no device-state field, cache-file key, record version or migration. `RECORD_VERSION` and the ADR 0026/0088 grammar are untouched.

### 3. Every case, and why INV-71 holds

Let C1 be the unfinished attempt's commit, K1 its kit (code R′), and K0 the old kit (code R).

| Situation | Abandon's answer | Record | What later generates a kit |
|---|---|---|---|
| C1 landed, user has R′ | A `200` | removed | a recovery from K1 (R′), after the wait; C1 is the live state, nothing unconfirmed remains |
| C1 landed, user lacks R′ | B `unauthorized` | kept | nothing: the only ways in are the new password (resume) or another enrolled device |
| C1 not landed, user has R′ | A `unauthorized`, B `200` | removed | a new attempt with R, gated by its own `recovery/complete` |
| C1 not landed, user lacks R′ | B `200` | removed | the same |
| C1 not landed, pending recovery since cancelled | B `200` (opens a new pending recovery) | removed | the same; C1 can never land (`commit_change` refuses a recovery commit with no pending recovery) |
| C1 in transit, lands after B's `200` and before the new attempt's `recovery/complete` | — | already removed | none: that `recovery/complete` answers `unauthorized` (`H_rec` replaced); the user was told to keep K1 |
| C1 in transit, arrives after the new attempt's `recovery/complete` answer | — | already removed | the new attempt's kit; C1 is refused (`unauthorized`, INV-122) |
| Mistyped R′ | local `BadInput` | kept | — |
| Mistyped R, wrong `--name`, recovery off | B `unauthorized` | kept | — |
| Network, rate limit, `internal`, bad answer | that error | kept | — |

A second kit is generated only by a later `rv recovery complete` after its `recovery/complete` succeeded. That success means the code it used is current — so C1 either never landed, or landed and is the state that code belongs to — and, by INV-122, no session C1 could ride survives it. So C1 is settled before the second kit exists, which is INV-71 as restated above.

### 4. What does not change

ADR 0046 §1–§3 otherwise, the resume order, `device forget`'s refusal (it still never removes a stage-3 record: it checks nothing with the server), the web vault (kind 4 holds no stage 3), the recovery cryptography and envelopes, the waiting period and its admin setting.

## Consequences

### Positive

- The dead end of G05-13 closes with no new secret, no new format and no new endpoint: one CLI command and one server call.
- In the landed case the user is told the truth — which kit is valid — and the next step (the pending recovery) is already running.
- INV-122 also removes a latent window from ADR 0046 §3 itself: an earlier send of the same attempt can no longer land after a resend's fresh session.

### Negative

- Probes are real recovery starts: they notify enrolled devices, may open a pending recovery, and count against the per-name rate limit.
- In the landed case the abandoned device's certificate stays on the account until revoked; `rv` names it but cannot revoke it itself.
- Two clients completing the same recovery at once (`rv` and a web vault, both with R) now end each other's sessions; the later one wins. Rare, and each side's own flow already handles an `unauthorized` commit.

### Risks

- **Account binding of probe B.** `recovery/start`'s answer carries no account id, so probe B binds to the record's account only through `--name`. A user with two accounts on one server who types the other account's name and code would remove this record on a `200`. The loss is a record unusable without its forgotten password; INV-71 still holds, because the next kit is still gated by its own `recovery/complete`.
- **Removing the record forecloses remembering the password later on this computer.** Accepted: the record is removed only on a definitive answer, and in the landed case the user holds K1 (its Secret Key and code).
- A corrupt stage-3 record (step 2's `CacheCorrupt`) still has no exit; out of scope, as it is for ADR 0046.
- **A kept record blocks more than its own account.** ADR 0046 §2's search (`pending_recovery` in `recover.rs`) hands the first stage-3 record whose `server_origin` matches to the resume, whatever login name is typed, so while this command keeps a record ("neither code accepted"), `rv recovery complete` against that server is blocked on this computer for every account, not only this one (V, code). The residual case is narrow — C1 landed and a later credential change then replaced R′ too, which needed a session on the account — but it is a dead end on this computer. Open question 3.

## Alternatives considered

- **Let `device forget` remove a stage-3 record after a warning.** Rejected: no server answer, so C1 may be live while the user is told nothing — exactly the "removed unsettled" the code comment forbids.
- **A read-only "which code is current" endpoint.** Rejected for M1: a new wire message and a new oracle for a stolen kit, where `recovery/start` already answers the question with side effects the user wants anyway (open question 2).
- **Probe with `recovery/complete` instead of `recovery/start`.** Rejected: it fails during the waiting period (`recovery_waiting`), releases `E_rec` and the account objects, and issues a session only to drop it.
- **No server change; rely on the 10-minute TTL.** Rejected as the default: the client keeps no time on disk, so it cannot know when the window closes and could only tell the user to wait an unstated time. Open question 1.

## Open questions for the owner

1. **INV-122 (server change) or a client-only exit?** Recommendation: accept INV-122. Without it, a new attempt within 10 minutes of C1's last send can generate a kit that C1 then voids — recoverable (the user still holds K1, and the new attempt's own resume abandons) but a literal breach of INV-71.
2. **Accept that the probes are real recovery starts** (notification, rate limit, an opened pending recovery) rather than adding a read-only endpoint? Recommendation: yes.
3. **No `--force` for the "neither code accepted" case?** Recommendation: no forced removal in M1. A user with neither the password nor a current code has no recovery left that the record could block for *this* account; the cost is the cross-account block of the Risks section, which is narrow (it needs a second credential change after C1 landed). If the owner wants it closed, the smallest safe follow-up is to make ADR 0046 §2's search match the typed login name's account rather than only the origin — a separate erratum, not part of this ADR. A forced removal can be added later if support cases show a need.
4. **Probe order: R′ first, then R.** Recommendation: keep. R′ is checked locally, so a mistyped R′ never reaches the server, and in the landed case a verified R′ is the only probe that can answer `200`; asking for R first would spend one rate-limited `unauthorized` round trip in exactly that case before reaching the conclusive probe. Both `200`s are conclusive on their own, so the order changes cost, never the outcome.

## On acceptance (not made now)

- ADR 0046's status line gains "Partially superseded by ADR 0108 (§2 INV-71 sentence; §3 step 1 last sentence)", and ADR 0028's gains "ADR 0108 (retry table, Recovery row)", appended per ADR 0020 point 9.
- THREAT_MODEL.md §8: INV-71's row text as superseded part 1 above, its test column extended with the abandon tests below; a new INV-122 row (number final at acceptance).
- CRYPTO.md §11.9 step 3: add "Each `/recovery/complete` that issues a recovery-only session ends every earlier one of the account in the same transaction (INV-122)."
- The README index row and CLAUDE.md's list of Accepted ADRs, as the owner keeps them. No sealing purpose or settings tag is used; if implementation ever needs one, it is "next free at acceptance". No migration; should implementation find one needed, its number is "next free at implementation".

## Implementation plan, with tests

1. **`rizzy-domain-auth`**: the one call of §1. Domain tests: `a_second_recovery_complete_ends_the_first_recovery_session` (a commit over S1 after S2 was issued answers `Unauthorized`; the same body over S2 commits); the existing "a recovery commit ends every recovery session" behaviour kept.
2. **`rizzy-client`**: `recovery::stored_recovery_token_hash(body: &[u8]) -> Result<[u8; 32], ClientError>` (parse through `rizzy-proto`, `CacheCorrupt` on any failure); unit tests for a well-formed body, `recovery = None` and a truncated body. The `proto_json` fuzz target already covers the parse.
3. **`rizzy-cli`**: `args.rs` `Some("abandon")` → `Command::RecoveryAbandon { server, name, confirm }`; `recover.rs` `abandon_command` (§2 steps 0–6), the stage-3 search returning every match for the origin, the two `CliError` variants, the note of superseded part 2 in `resume`, and the module docs (the sentence "every other command, `rv device forget` included, refuses a stage-3 record" gains "except `rv recovery abandon`"). A test-only `abandon_until_the_removal` stops after the deciding probe, in the style of ADR 0046's `prepare`.
4. **Crash-injection tests** (`crates/rizzy-cli/tests/account.rs`; `recovery_until_the_commit` leaves the stage-3 record as in ADR 0046 §5; a server with a zero wait):
   - *not landed, no R′*: empty R′, R accepted → no row left; a fresh `rv recovery complete` succeeds; K1's credentials are refused.
   - *landed, R′*: the stored body is first committed over its session (the lost-answer case); abandon with R′ → removed, no R prompt consumed, a pending recovery exists; `rv recovery complete` with R′ then succeeds.
   - *landed, no R′*: empty R′, R refused → `RecoveryNotSettled`, cache file byte-identical, exit 1.
   - *wrong R′*: against a stopped server → `BadInput`, not `Network` (proves no round trip), record kept.
   - *in transit, lands first*: abandon via R, then the stored body over S1 → applied; a fresh `rv recovery complete` with R → `unauthorized`, no kit confirmation consumed, no cache file created.
   - *in transit, arrives late*: abandon via R; the fresh flow's `recovery/complete` answered; then the stored body over S1 → `unauthorized`; the new attempt completes and its kit is the live one.
   - *crash before the removal*: `abandon_until_the_removal`, drop, rerun → same outcome; one pending recovery, `available_at_ms` unchanged.
   - *crash after the first unlink*: the cache file removed by hand-written test setup with the journal and lock file left in place, as step 6 would leave them → `rv recovery abandon` answers `NoUnfinishedRecovery`, and a fresh `rv recovery complete` is not blocked by `AlreadyEnrolled`.
   - *output*: each removal exits 0 with exactly one standard-output line, `landed <ms>` or `not-landed <ms>`, `<ms>` equal to the probe's `available_at_ms`; each refusal prints nothing on standard output.
   - *refusals*: no `--confirm` → exit 2, nothing sent; no stage-3 record → `NoUnfinishedRecovery`; a stage-1 record is never removed; a lock held by another `rv` → `InUse`; server stopped during probe A or B → `Network`, record kept; `device forget` still refuses stage 3 (existing test).
   - `tests/cli.rs`: the argument grammar, and that no message or `Debug` output contains either code.
5. Package-scoped checks (`cargo test -p rizzy-domain-auth -p rizzy-client -p rizzy-cli --locked`, clippy), then the full gate of CLAUDE.md before any push.

## References

- [ADR 0046](0046-recovery-pending-device-stage.md), [ADR 0026](0026-client-device-state-and-cache.md), [ADR 0028](0028-api-v1-http-conventions.md), [ADR 0020](0020-partial-supersession.md), [ADR 0045](0045-recovery-pending-notification.md), [ADR 0011](0011-storage.md); Proposed: [ADR 0088](0088-device-state-record-grammar.md), [ADR 0090](0090-per-account-security-event-log.md), [ADR 0091](0091-revoked-device-rotation-race.md).
- [CRYPTO.md](../CRYPTO.md) §4.2, §5.9, §11 "Secrets before commit", §11.1, §11.9; [THREAT_MODEL.md](../THREAT_MODEL.md) INV-71.
- [Gap review 2026-10-25](../reviews/2026-10-25-adr-gap-review.md) D8; [raw G05](../reviews/2026-10-25-raw/G05.md) G05-13.
- Code at `f3492b2`: `crates/rizzy-cli/src/{recover,commands,args,error}.rs`, `crates/rizzy-domain-auth/src/{recovery,change,session}.rs`, `crates/rizzy-proto/src/{change,recovery,auth}.rs`, `crates/rizzy-core/src/keys/derive.rs`, `crates/rizzy-client/src/recovery.rs`, `crates/rizzy-cli/tests/account.rs`.
