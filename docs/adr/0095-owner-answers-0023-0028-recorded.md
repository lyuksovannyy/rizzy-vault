# ADR 0095: The owner's answers to ADRs 0023–0028, recorded from their acceptance commits, and the ADR 0026, 0027 and 0028 text they contradict

- Status: Accepted
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M1 (`rizzy-client` cache and `rv` removal flow, `rizzy-server` configuration and `429` answers; every decision below is already shipped code, so this ADR changes no behaviour)
- Supersedes: on acceptance, in part: [ADR 0026](0026-client-device-state-and-cache.md) (§3 in part, §4 in part, §5 in part); [ADR 0027](0027-export-payload.md) (§6 in part); [ADR 0028](0028-api-v1-http-conventions.md) (item 10 in part). §2 names the exact parts and gives their replacement text ([ADR 0020](0020-partial-supersession.md) point 9).

## Context

**Trigger.** On 2026-10-25, after the ten-reviewer ADR gap review ([docs/reviews/2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md), theme **C3**), the owner said "start": begin fixing the gaps. This ADR fixes C3, which merges findings **G03-7**, **G03-10**, **G03-13** ([raw/G03.md](../reviews/2026-10-25-raw/G03.md)) and **G04-1** ([raw/G04.md](../reviews/2026-10-25-raw/G04.md)).

**The rule that was not followed.** [docs/adr/README.md](README.md) line 23: "The owner's answers to "Open questions for the owner" go into the Decision section first." For ADRs 0023–0028 the answers were given only in the acceptance commit messages. Each acceptance commit changed only the status line of each ADR (V: `git show --stat`, one changed line per ADR file), and every later commit to these six files changed only line 3, the status line (V: `git diff <acceptance commit> HEAD` per file, at `262bbd0`). So no ADR file records any answer, and each "Open questions for the owner" section still reads as open.

**The commits** (V: `git log --all` over the six files, `git show`; each carries the owner's own `Signed-off-by: lyuksovannyy`, which only a human adds, [ADR 0017](0017-licensing.md) Decision 4). Quoted verbatim:

| Commit | Date | ADRs | Message text that records the answers |
|---|---|---|---|
| `c04cfb4` | 2026-09-29 | 0023, 0024 | "The owner set ADR 0023 (logical backup format) and ADR 0024 (rustix to disable core dumps, INV-60) to Accepted on 2026-09-29, open questions answered as recommended." |
| `676aa7d` | 2026-09-29 | 0025 | "The owner set ADR 0025 to Accepted on 2026-09-29, open questions answered as recommended." |
| `90b9239` | 2026-09-30 | 0026, 0027, 0028 | "The owner set ADR 0026 (client device state and encrypted cache), ADR 0027 (export payload and plaintext export) and ADR 0028 (/api/v1 HTTP conventions) to Accepted on 2026-09-30, every open question answered as recommended: an older local state alarms, goes read-only and needs re-enrolment; verified unsent edits are uploaded byte-identically before removal; plaintext JSON import is in M1 (ROADMAP §4.2 import row); plaintext export needs EXPORT PLAINTEXT, never overwrites and has no bypass; trashed items stay in exports; exports over 16 MiB are refused; Retry-After on 429; an http origin is refused except loopback." |

"Answered as recommended" makes each recommendation, word for word as the ADR's open question states it, the owner's answer. §1 quotes each one.

**Where the answers contradict the binding text** (V, files at `262bbd0`):

- **ADR 0026, answers 5 and 6 (G03-10).** Answer 5 adds alarm kind 4 and drops the served head from §4 step 1; §3 still lists alarm kinds 1–3 only, §4 step 1 still moves `next_device_seq` past "own head in the last Fetch", and §4 step 7 still ends "what the client then does is open question 5". Answer 6 uploads verified unsent rows before removal; §5 still says "the client uploads nothing more" and "While an alarm is active the app refuses removal". The code follows the answers: `Alarm::DeviceStateOutdated` is persisted as key byte 4 (`crates/rizzy-client/src/store/rows.rs:278–315`, "kind 4 by the owner's decision on open question 5"); "The server's head is unsigned, so it only raises the alarm: it never moves `next_device_seq`" (`crates/rizzy-client/src/sync.rs:279–287`); removal is refused under alarms 1–3 and allowed under alarm 4 (`crates/rizzy-cli/src/commands.rs:1756–1799`, `:1801–1869`); `Device::upload_unsent` uploads the unacknowledged rows "byte for byte, before the device is removed (ADR 0026 §5, owner decision on open question 6)" (`crates/rizzy-cli/src/device.rs:2339–2381`; `crates/rizzy-client/src/sync.rs:2966–2975`). An implementer cannot follow the ADR text and the code at once, and alarm byte 4 is a persistent-format value with no binding text.
- **ADR 0027, answer 4 (G03-13).** §6's heading reads "Reading plaintext JSON back (binds only if open question 4 is answered yes)" and its first paragraph "If the answer is no, this section is dropped". The answer was yes, but nothing in ADR 0027 says so, and Accepted [ADR 0055](0055-m3-item-type-field-keys.md) (References, line 106) still describes §6 as binding "only if ADR 0027's own open question 4 is answered yes". The code ships §6 (`Format::RizzyPlaintextJson`, fuzz target `fuzz/fuzz_targets/import_rizzy_json.rs`), and ROADMAP §4.2 (line 81) lists "**our plaintext JSON export**" as an M1 import.
- **ADR 0028, answer 6 (G04-1).** Item 10 says "CRYPTO.md §2's origin parser also admits `http`, the server does not refuse it today, browsers ignore HSTS there, and such an origin is for local testing only (open question 6)." The code refuses it: `origin_is_https_or_local` (`crates/rizzy-server/src/config.rs:693–719`) and `ConfigError::InsecureOrigin` (`:553`, `:584–587`, `:739–741`), tested by `an_http_origin_is_refused_unless_it_is_local` (`:1149–1196`). [CRYPTO.md §2](../CRYPTO.md#2-conventions) (line 72) and `docs/self-hosting.md` (line 110) already describe the refusal; only the ADR text is stale.

**Where they agree** (G03-7): every answer to ADRs 0023, 0024 and 0025, answers 1–4 of ADR 0026, answers 1–3, 5 and 6 of ADR 0027, and answers 1–5 of ADR 0028 match the Decision text or add to a point it leaves silent. §1 shows each comparison.

What binds: [ADR 0020](0020-partial-supersession.md) points 4 and 9 (an Accepted ADR's text is never edited; a change to it is a new ADR that names the parts and writes out the replacing text). CLAUDE.md: never change an ADR's status; a drafted ADR is Proposed.

## Decision

### 1. The answers, recorded

Each row quotes the open question's recommendation verbatim (the answer, by the commit's "as recommended"; a parenthesis in the middle column paraphrases a question whose recommendation is a bare "yes" or "no") and says how it compares with the Decision text. When this ADR is Accepted, the answers below bind as its Decision text, dated by their acceptance commits.

**ADR 0023, answered 2026-09-29 (`c04cfb4`).**

| OQ | Recommendation = answer | Decision text |
|---|---|---|
| 1 | "no; document `age` and backup-tool encryption. Revisit with M8's scheduled encrypted backups." | Agrees: §2, "**Confidentiality is out of scope.**" ADR 0071 (Accepted, M8) later added the encrypted format, as the answer foresaw. |
| 2 | "accept for M1; the attachments ADR (M3) revisits it." | Agrees: §3, `MAX_BACKUP_FILE_LEN` = 2 GiB. (Whether the M3 attachments ADR revisited it is G03-6, not this ADR's subject.) |
| 3 | "the advisory lock; PostgreSQL restore stays refused until it lands." | Agrees: §5 step 1, the **instance lock**. The code names an `InstanceLock` (`crates/rizzy-server/src/admin.rs:186`); its completeness was not re-checked here. |
| 4 | "refuse, as `Database::restore` does today; migrating dumps needs per-migration dump transforms." | Agrees: §5 step 3. |

**ADR 0024, answered 2026-09-29 (`c04cfb4`).**

| OQ | Recommendation = answer | Decision text |
|---|---|---|
| 1 | "this ADR." | Agrees: Context, second paragraph, and the alternative "An `## Amendments` entry in ADR 0009". |

**ADR 0025, answered 2026-09-29 (`676aa7d`).**

| OQ | Recommendation = answer | Decision text |
|---|---|---|
| 1 | "exact (§3 check 4)." | Agrees: §3 check 4, "`cursor[d]` = head h(V, d)". |
| 2 | "`state_conflict`." | Agrees: §3 checks 3 and 4, §2 step 5. |
| 3 | "yes; revisit with M3 data." (5 client attempts, no server hold) | Agrees: §2 step 5, "After 5 attempts that only rebuilt, stop" (code: `crates/rizzy-client/src/rotation.rs:125`). |
| 4 | "no." (healing does not fill a row at an older `vault_key_epoch` after a rotation) | The Decision is silent; the answer adds this restriction. It is consistent with §3 check 2 and with [ADR 0032](0032-healing-rotation-after-backup.md) (Accepted), under which healing never raises `vault_key_epoch`. |
| 5 | "yes." (commit body limit = upload limit) | Agrees: §1 "Body limit". ADR 0028 item 7 reads it as the response size for `recovery/complete` (ADR 0028 answer 5 below). |
| 6 | "allow it under §3 check 2's `>` rule, after the client heals (§2 step 2), so a stolen device can be revoked after a restore. …" | Agrees: §2 step 2, §3 check 2. |
| 7 | "the heads, which keep that session off the vault endpoints. Until decided, the §11.9 default rotation stays blocked." | Agrees: §1 "Recovery" (code: `crates/rizzy-proto/src/recovery.rs:63–80`, `heads`). |
| 8 | "drop, so a planted wrap cannot block a revocation." | Agrees: §2 step 3 (code: `crates/rizzy-client/src/rotation.rs:31–32`). |

**ADR 0026, answered 2026-09-30 (`90b9239`).**

| OQ | Recommendation = answer | Decision text |
|---|---|---|
| 1 | "in each leaf for M1; revisit in M3 when `rizzy-ffi` arrives." | Agrees: Negative, "Two sqlx executors (`rv`, `rizzy-ffi`) run the same schema"; no `rizzy-client-sqlite` crate exists (V, `crates/`). |
| 2 | "not in M1; add it only if M3 shows load failures that removal handles badly, since every kept part must itself still verify." | Agrees: §5, "There is **no "reset local data" that keeps the enrolment**". |
| 3 | "yes; retention is ADR 0012 §5's." (ops of trashed items are kept like any other) | Agrees: no rule of the ADR treats them differently. |
| 4 | "yes." (`$XDG_DATA_HOME`, `~/Library/Application Support`, `%LOCALAPPDATA%`, overridable by `RIZZY_CLI_DATA_DIR`) | The Decision names no directory; the answer adds it, as the code does (`crates/rizzy-cli/src/paths.rs:13–16`, `:58`). |
| 5 | "drop the head from step 1; add alarm kind 4 "device state older than this device's history", raised on either signal of step 7, read-only, resolved only by removal and re-enrolment (§5 must then allow removal under this one alarm); in M1 never re-sign the unsent edits under new dots." | **Contradicts** §3 (the alarm kinds), §4 step 1, §4 step 7 (last sentence) and §5 (removal under an alarm). Superseded by §2 parts A–D. |
| 6 | "when `E_local` and `E_dev` open and the own rows verify, upload the `own` 1 and 3 rows byte-identically before deleting (no new dot is signed); otherwise warn and delete." | **Contradicts** §5 ("the client uploads nothing more"). Superseded by §2 part D. |

**ADR 0027, answered 2026-09-30 (`90b9239`).**

| OQ | Recommendation = answer | Decision text |
|---|---|---|
| 1 | "yes; a user's own copy of the vault should hold them." (trashed items are exported, and imported as trashed) | Agrees: §1 "What is exported", §2 step 3. |
| 2 | "yes; revisit with a chunked format if needed." (refuse over 16 MiB) | Agrees: §1 "Too large". |
| 3 | "yes." (CSV formula cells written as is, with the warning) | Agrees: §4 "No cell rewriting". |
| 4 | "yes, as its own fuzzed format (§6), since the JSON form is complete. …" | §6 binds. Its conditional first sentence is superseded by §2 part E, so that ADR 0027's status line points here. The ROADMAP edit the question asked for is already made (ROADMAP §4.2, line 81). |
| 5 | "carried; ADR 0018 §6 keeps such values harmless, and a round trip stays complete." | Agrees: §6 "Writes" (`check_carried`, `WriteMode::Import`). |
| 6 | "yes." (the warning wording, the `EXPORT PLAINTEXT` phrase, no bypass and no `--force`) | Agrees: §5 (partly superseded later by [ADR 0034](0034-export-reauth-and-plaintext-hold.md), which keeps the phrase and the no-bypass rule). |

**ADR 0028, answered 2026-09-30 (`90b9239`).**

| OQ | Recommendation = answer | Decision text |
|---|---|---|
| 1 | "yes, whole seconds, from the bucket's backoff; it tells an attacker nothing the refusal does not." | The Decision is silent; §3 below states the rule the code follows. |
| 2 | "no; require it from v1.0 (item 14)." | Agrees: item 14 (code: `crates/rizzy-server/src/http/headers.rs:166–180`). |
| 3 | "no in M1; `X-Forwarded-For` is what the shipped Caddy example sets." | Agrees: item 11, "`Forwarded` (RFC 7239) is not read." |
| 4 | "decide with the web vault (M1 step 5), as a dependency change under CLAUDE.md." | Recorded. The Decision chooses no generator; G04-2 reports that none has been chosen yet, which is not this ADR's subject. |
| 5 | "confirm this reading, and correct ADR 0025's wording in a later ADR (ADR 0020 point 9) if the owner wants the text to match." | Agrees: item 7 (code: `crates/rizzy-server/src/http/api.rs:83`). The optional ADR 0025 rewording is G04-3, not done here. |
| 6 | "refuse it at startup unless the host is a loopback address or `localhost`, so that "the public origin is HTTPS" (item 10) is enforced, not only documented." | **Contradicts** item 10 ("the server does not refuse it today"). Superseded by §2 part F. |

### 2. What this ADR supersedes

Six parts, each quoted word for word and each replaced in full by the text after it. Nothing else in ADRs 0026, 0027 and 0028 changes. No earlier supersession names any of these parts: in ADR 0026, ADR 0046 replaces the §2 notation block, a §2 parsing sentence, the §3 `pending_commit` sentence and the §4 step 5 parenthetical; ADR 0051 the §3 `cache_meta` line; ADR 0056 a §1 sentence and the §3 sentence "It learns no item content (G-1)."; ADR 0057 a §1 table row and §4 step 5. In ADR 0028, [ADR 0049](0049-web-role-route-table.md) replaces item 10's first sentence and [ADR 0052](0052-icon-proxy-role.md) only its CSP `img-src` wording (V: each ADR's "What this ADR supersedes").

**A. ADR 0026 §3, the bullet that begins "`account_objects.kind`:", its first sentence:**

> `account_objects.kind`: 1 bundle (key `u64 bundle_seq`), 2 `account-state` (key empty; the newest verified only), 3 `ACCOUNT_SETTINGS` (key `u64 settings_seq`), 4 device certificate (key `device_id`), 5 device revocation (key `device_id`), 6 `E_id` (key `u32 identity_epoch`), 7 alarm (key `u8 kind`: 1 rollback, 2 fork, 3 unconfirmed identity change; bytes: the conflicting signed statements).

Replaced by:

> `account_objects.kind`: 1 bundle (key `u64 bundle_seq`), 2 `account-state` (key empty; the newest verified only), 3 `ACCOUNT_SETTINGS` (key `u64 settings_seq`), 4 device certificate (key `device_id`), 5 device revocation (key `device_id`), 6 `E_id` (key `u32 identity_epoch`), 7 alarm (key one byte, `u8 kind`: 1 rollback, 2 fork and 3 unconfirmed identity change, whose bytes are the conflicting signed statements, each as `bytes(x)`; 4 device state outdated (§4 step 7), whose bytes are empty). An alarm row whose key is not exactly one byte from 1 to 4 fails the load (§5 (d)); a new alarm kind is a new cache format (§5).

**B. ADR 0026 §4 step 1, its third sentence:**

> `next_device_seq` is the larger of its stored value and 1 + max(highest own `device_seq` held, own head in the last Fetch); it never decreases, and without a restore it leaves no gap (ADR 0012 §2).

Replaced by:

> `next_device_seq` is the larger of its stored value and 1 + the highest own `device_seq` held. The own head a Fetch serves is unsigned and never moves it: a served own head above the highest own `device_seq` held raises alarm 4 instead (step 7). It never decreases, and without a restore it leaves no gap (ADR 0012 §2).

**C. ADR 0026 §4 step 7, its last sentence:**

> The server refuses the second record at a stored dot (ADR 0021 §9 "Already stored"); what the client then does is open question 5.

Replaced by:

> The server refuses the second record at a stored dot (ADR 0021 §9 "Already stored"). Each of these signals means the file is such an older copy: after a Fetch, an own head above the highest own `device_seq` held, a served own record this device does not hold, or a served own record at a held dot with other bytes; after an upload, a `record_conflict` answer at an own dot. On any of them the client writes alarm 4 ("device state outdated", §3) in the transaction that persists that answer (step 4), and every vault of the account goes read-only. From then on it signs no new bytes for any dot and never re-signs an unsent edit under a new dot, and no flow clears the alarm: it is resolved only by removing this device and enrolling anew (§5).

**D. ADR 0026 §5, the bullet that begins "A cache that fails to load is never dropped silently", its third and fourth sentences:**

> The only recovery is "remove this device": the client uploads nothing more, and the file is deleted, which loses every own op the server never acknowledged, and the app says so first (open question 6); the next use is a new enrolment (CRYPTO.md §11.2) with a new `device_id`, so no dot can repeat, and the old `device_id` is revoked from another device. While an alarm is active the app refuses removal and names the alarm; a file deleted by hand is a new device with the first-Fetch trust every new device has.

Replaced by:

> The only recovery is "remove this device". When the cache unlocks and loads (§4 step 5), alarm 4 raised or not, the client first uploads its unacknowledged own rows (`own` 1 and 3) byte-identically: per vault, after one Fetch that gives it a restore generation, the ops in chain order and then the snapshots, each request's rows committed as sent before it goes to the host (§4 step 1), stopping at the first answer that acknowledges nothing more (a conflict or a `stale_epoch`). No new dot, signature or re-issue is made. If the upload cannot run (no network, a refused authentication), nothing more is tried. The app then says how many own ops and snapshots the server has not acknowledged and will be lost; when the cache does not unlock or load, so that nothing could be verified or uploaded, it says that any such edits will be lost. It asks for confirmation (`rv`: the typed word `FORGET`) and only then deletes the file. The next use is a new enrolment (CRYPTO.md §11.2) with a new `device_id`, so no dot can repeat, and the old `device_id` is revoked from another device. While alarm 1, 2 or 3 is raised, or an alarm row whose key this build does not know, the app refuses removal and names the alarm; alarm 4 does not block removal, which is its only resolution. The alarm rows are cleartext (§3), so this check needs no key: a cache that does not unlock is refused removal by the same rule, and only a file that cannot be read as a cache at all (§5 (a)) holds no alarm to keep. A file deleted by hand is a new device with the first-Fetch trust every new device has.

**E. ADR 0027 §6, the first sentence under its heading:**

> If the answer is no, this section is dropped and M1 reads back only the encrypted export (§2).

Replaced by:

> Open question 4 was answered yes on 2026-09-30 ([ADR 0095](0095-owner-answers-0023-0028-recorded.md) §1): this section binds, and M1 reads back both the encrypted export (§2) and the plaintext JSON of §3 (ROADMAP §4.2 import row).

The heading's own condition, "binds only if open question 4 is answered yes", is met by that answer. A heading is not a part that ADR 0020 point 9 can name apart from its section, so it stays.

**F. ADR 0028 item 10, the sentence:**

> CRYPTO.md §2's origin parser also admits `http`, the server does not refuse it today, browsers ignore HSTS there, and such an origin is for local testing only (open question 6).

Replaced by:

> CRYPTO.md §2's origin parser also admits `http`, but the server refuses to start with an `http` `RIZZY_ORIGIN` unless its host, after the parser's canonicalisation, is exactly `localhost` (no subdomain, no longer name) or a loopback address (`127.0.0.0/8` or `::1`); any other `http` origin is refused like an invalid setting, with `ConfigError::InsecureOrigin` ("RIZZY_ORIGIN must be an https:// origin; http:// is accepted only for localhost or a loopback address, for local testing"). Browsers ignore HSTS on such an origin, and it is for local testing only (open question 6, answered 2026-09-30).

### 3. What this ADR adds: `Retry-After` (ADR 0028 answer 1)

ADR 0028 item 3 lists `rate_limited` 429 and says nothing about `Retry-After`; answer 1 adds it. This section states the rule the code follows (`crates/rizzy-server/src/http/api.rs:222–233`, `:641–706`; tests `error_answers_are_uniform_and_a_429_carries_retry_after` and `retry_after_rounds_up_to_whole_seconds`, `:1455–1520`). It adds to item 3 and supersedes nothing:

1. Every `429 rate_limited` answer under `/api/` carries one `Retry-After` header whose value is a decimal count of whole seconds (the `delay-seconds` form; never an HTTP date).
2. The value is the time the refusal names: the remaining backoff of the rate-limit bucket that refused, or, where the recovery waiting period refused ([CRYPTO.md §11.9](../CRYPTO.md#119-recovery-with-the-emergency-kit) step 2), the rest of that period. It is rounded **up** to whole seconds and is at least 1, so that a client that waits as told never retries inside the backoff.
3. A `429` whose refusal names no time (a request that found no large-body slot within item 7's 10 s wait, and the cap on web-vault certificates) carries `Retry-After: 10` (`RETRY_AFTER_FALLBACK_SECS`, the length of the slot wait).
4. No other status carries `Retry-After`. The value discloses nothing the refusal does not: the backoff and the waiting period are the server's own policy for that bucket or recovery.

The `icons/fetch` `429` is [ADR 0052](0052-icon-proxy-role.md)'s and is not changed here.

### 4. What this ADR does not change

- No status line. Moving ADRs 0026, 0027 and 0028 to "Partially superseded by ADR 0095" is the owner's act on acceptance (CLAUDE.md; ADR 0020 points 3, 4 and 9).
- ADRs 0023, 0024 and 0025: nothing in them contradicts an answer, so no part of them is superseded and their files stay as they are. Their record is §1. A reader of those files finds no link to this ADR, and ADR 0020 point 4 allows no other edit that would add one, so this ADR's index title names them.
- ADR 0055's References sentence about ADR 0027 §6 stays as written. With answer 4 recorded, its condition is met and the sentence is accurate; a References entry is not Decision text.
- The code. Every replacement above describes what `rizzy-client`, `rv` and `rizzy-server` already do (Context). Their doc comments that cite "the owner's decision on open question N" stay correct under ADR 0020 point 9's References rule.

### 5. On acceptance (doc edits, not made in this change)

1. The owner sets ADR 0026's status line to end "…; [ADR 0095](0095-owner-answers-0023-0028-recorded.md) (§3 in part, §4 in part, §5 in part)", ADR 0027's to end "…; [ADR 0095](0095-owner-answers-0023-0028-recorded.md) (§6 in part)" and ADR 0028's to end "…; [ADR 0095](0095-owner-answers-0023-0028-recorded.md) (item 10 in part)". The README rows of 0026, 0027, 0028 and 0095 mirror them, and CLAUDE.md's list of Accepted ADRs gains 0095.
2. [THREAT_MODEL.md](../THREAT_MODEL.md) §8: the test column of INV-25 gains "An older copy of the device state raises alarm 4 and stays read-only after a restart; the served own head moves no counter (`a_stale_answer_reissues_and_an_older_file_raises_the_alarm`, `crates/rizzy-client/src/tests/store.rs`; `an_older_copy_of_the_device_state_raises_the_alarm_and_ends_in_re_enrolment`, `crates/rizzy-cli/tests/e2e.rs`)", and that of INV-27 gains "A lying own head never moves `next_device_seq`, so no gap is signed (the same `rizzy-client` test)".
3. [CRYPTO.md](../CRYPTO.md): none. §2 (line 72) already states the `http` refusal of §2 part F.
4. [ROADMAP.md](../ROADMAP.md): none. §4.2 (line 81) already lists the plaintext JSON import of §2 part E.
5. `docs/self-hosting.md`: none required (line 110 already states the refusal); it may add one sentence on `Retry-After` (§3).

### 6. Implementation plan and tests

The behaviour exists. The plan adds the tests that the replacement text names and that do not exist today (V: `grep` over `crates/rizzy-client/src/tests` and `crates/rizzy-cli/tests` at `262bbd0`), as one `test(client,cli)` change after acceptance:

1. **Alarm key bytes** (`rizzy-client`, `src/tests/store.rs`): a cache whose alarm row key is `[0]`, `[5]`, `[]` or `[4, 0]` fails the load as corrupt; `[4]` with empty bytes loads as `Alarm::DeviceStateOutdated`; the row `(7, [4], [])` round-trips through the row codec as a known-answer value.
2. **Removal under an unknown alarm** (`rv` e2e, next to `forget_uploads_unsent_edits_first_and_is_refused_under_an_alarm`): an alarm row with key `[9]` makes `device forget` refuse, with and without the password, and the file stays.
3. **Removal under alarm 4 uploads first** (`rv` e2e): after an older copy raises alarm 4 while the device holds an `own = 1` row the server lacks, `device forget` uploads it byte-identically (the server then serves the same statement and body bytes), reports zero left and deletes the files; with an own row at a dot the server holds with other bytes, the upload stops at the conflict, nothing is re-signed, and the lost count is reported.
4. **Upload conflict at an own dot** (`rizzy-client`): a `record_conflict` answer at an own dot sets `own_conflict`, leaves the row unchanged and makes no new signature, and the host's changeset for that answer holds the alarm-4 write.
5. Kept as they are: `an_http_origin_is_refused_unless_it_is_local` (`rizzy-server` `config.rs`), the two `Retry-After` tests (`http/api.rs`), and the alarm-4 tests named in §5 item 2.

**A code gap found while checking, outside this ADR's decision.** The extension's durable device (`crates/rizzy-wasm/src/device.rs`, ADR 0036 device kind 2) writes no alarm row of any kind: `crates/rizzy-wasm/src` uses none of `Alarm`, `alarm_write` or `Write::ClearAlarm` (V, `grep`), and its sync ends with `device_state_outdated` after only an in-memory `set_read_only(true)` (`crates/rizzy-wasm/src/sync.rs:320–326`). ADR 0026 §4 step 4 ("An alarm is written in the transaction that detects it and cleared only by the flow that resolves it, so a restart never lifts read-only mode"), which this ADR leaves unchanged, binds that client too. It is reported for a code fix, not decided here. The extension also has no "remove this device" flow (V: no such call in `apps/extension/src` or `packages/core/src`).

## Consequences

### Positive

- The binding text of ADRs 0026, 0027 and 0028 matches the owner's answers and the shipped code; an implementer who reads the ADRs builds what `rv` and `rizzy-server` do.
- Alarm byte 4, a persistent-format value, gets binding text.
- Every answer to ADRs 0023–0028 is in an ADR file, dated and tied to its commit.

### Negative

- The answers live in a separate file, and ADRs 0023–0025 carry no link to it (§4).
- A reader of ADR 0026 must combine five partial supersessions (ADRs 0046, 0051, 0056, 0057 and this one) to get its binding text.

### Risks

- If the owner meant an "as recommended" answer differently from the recommendation quoted, the record is wrong. The quotes are verbatim, and the code was built from the same reading, so a difference would show here, before acceptance.
- Other tracks draft ADRs 0088–0099 in parallel and may name a neighbouring sentence of ADR 0026 §3–§5 or ADR 0028 item 10. Two drafts that name the same sentence must be reconciled before either is accepted.

## Alternatives considered

- **Edit the answers into ADRs 0023–0028.** Forbidden: ADR 0020 point 4 and CLAUDE.md allow no edit to an Accepted ADR's Decision.
- **An `## Amendments` entry in each ADR.** ADR 0020 point 4 allows amendments only for changes an ADR provides for, and none of these does.
- **One erratum per ADR.** Six ADRs for one cause; the answers share three commits, and one record is easier to check.
- **Supersede ADR 0027 §6 in full** to drop its conditional heading. It would restate nine bullets to change no meaning; part E is the smallest part that both records the answer and links ADR 0027 to this ADR through its status line.
- **Change the code to match the old text** (no alarm 4, the served head in step 1, no upload at removal). It reverses the owner's answers and reopens the gap INV-27 closes: a lying server could push the counter up and leave a gap.

## Open questions for the owner

1. **The `Retry-After` details of §3.** Answer 1 said "from the bucket's backoff". The code also sends the rest of the recovery waiting period, rounds up with a minimum of 1 s, and sends 10 s where the refusal names no time. Accept these as §3 states them? Recommendation: yes. Each keeps a client from retrying too early, and no value says more than the refusal does.

## References

- [ADR 0020](0020-partial-supersession.md) points 3, 4, 9; [docs/adr/README.md](README.md) line 23.
- [ADR 0023](0023-logical-backup-format.md), [ADR 0024](0024-core-dump-disabling-rustix.md), [ADR 0025](0025-rotation-vault-half.md), [ADR 0026](0026-client-device-state-and-cache.md), [ADR 0027](0027-export-payload.md), [ADR 0028](0028-api-v1-http-conventions.md); [ADR 0032](0032-healing-rotation-after-backup.md), [ADR 0034](0034-export-reauth-and-plaintext-hold.md), [ADR 0046](0046-recovery-pending-device-stage.md), [ADR 0049](0049-web-role-route-table.md), [ADR 0051](0051-equivalence-list-version-persistence.md), [ADR 0052](0052-icon-proxy-role.md), [ADR 0055](0055-m3-item-type-field-keys.md), [ADR 0056](0056-local-index-recently-used-search.md), [ADR 0057](0057-device-state-v2-keystore.md).
- [THREAT_MODEL.md](../THREAT_MODEL.md) INV-25, INV-27; [CRYPTO.md](../CRYPTO.md) §2, §11.2, §11.9; [ROADMAP.md](../ROADMAP.md) §4.2.
- Gap review: [2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md) C3; [G03](../reviews/2026-10-25-raw/G03.md) G03-7, G03-10, G03-13; [G04](../reviews/2026-10-25-raw/G04.md) G04-1.
- Commits `c04cfb4`, `676aa7d`, `90b9239` (V, `git show`).
- Code (V, at `262bbd0`): `crates/rizzy-client/src/store/{rows,load,mod}.rs`, `crates/rizzy-client/src/sync.rs`, `crates/rizzy-client/src/tests/store.rs`, `crates/rizzy-cli/src/{commands,device,paths}.rs`, `crates/rizzy-cli/tests/e2e.rs`, `crates/rizzy-server/src/{config.rs,http/api.rs,http/headers.rs}`, `crates/rizzy-wasm/src/{device,sync}.rs`.
- RFC 9110 §10.2.3, `Retry-After` (L: general knowledge, not re-read for this ADR).
