# ADR 0098: Security keys: per-account and per-key limits, the six `webauthn` endpoints and `pending_id` (erratum to ADRs 0077 and 0028)

- Status: Proposed
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M3 (`rizzy-domain-auth`, `rizzy-proto`, `rizzy-server`, web vault)
- Supersedes: on acceptance, in part: [ADR 0077](0077-webauthn-rs-integration-fixes.md) (§2 "Where", fifth sentence; §5, first sentence; §9 entry 15) and [ADR 0028](0028-api-v1-http-conventions.md) (item 1, first sentence, in the text [ADR 0052](0052-icon-proxy-role.md) gave it). §6 names the parts and gives their replacement text ([ADR 0020](0020-partial-supersession.md) point 9).

## Context

**Trigger.** On 2026-10-25 a ten-reviewer gap review of every ADR was committed ([docs/reviews/2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md); raw findings in [2026-10-25-raw/](../reviews/2026-10-25-raw/)). Afterwards, the same day, the owner told the team to "start" fixing the gaps. This ADR answers theme **D5**: "No cap on security keys per account, although the login state carrying every credential is refused above 64 KiB. The code picked 32 on its own; list/remove endpoints and `pending_id` are defined only in code." It covers raw findings **G08-6** and **G06-11**. Route: erratum.

[ROADMAP §4.3](../ROADMAP.md#43-cryptography--authentication-m0m1-audited-in-m8) lists "2FA: TOTP, WebAuthn/FIDO2 security keys" as a Must, with WebAuthn in M3. The feature is [ADR 0058](0058-webauthn-2fa-second-factor.md), as changed by [ADR 0077](0077-webauthn-rs-integration-fixes.md) (crate integration) and [ADR 0082](0082-security-keys-user-presence-only.md) (touch only). It is built and integrated ([docs/HANDOFF.md](../HANDOFF.md) §1: "Migration **0008** … six endpoints; login prompt plus Settings → Security keys").

**G08-6: the 64 KiB state limit has no limits under it.** ADR 0077 §2 "Where": "A row whose `state_format` the binary does not know, or whose `state` exceeds 64 KiB, is refused on read (bounded input, fail closed); the ceremony restarts." The login state is the facade's `SecurityKeyAuthentication`, which holds `ast: AuthenticationState`, whose first field is `credentials: Vec<Credential>`: the full record of every allowed key (V, `webauthn-rs` 0.5.5 `src/interface.rs` lines 350–352; `webauthn-rs-core` 0.5.5 `src/interface.rs` lines 48–54). The stored `security_key` keeps whatever attestation the crate parsed (ADR 0077 §5). So the state grows with the number of keys and with the size of each. No Accepted text limits either. Where the state comes out larger than 64 KiB, it is written and then refused on every read, and the restart builds the same state again: the second factor fails closed for good, with no defined error code and no defined way out.

**What the code does today** (V, all read in this worktree):

- `crates/rizzy-proto/src/limits.rs` lines 160–168: `MAX_WEBAUTHN_CREDENTIAL_ID_LEN = 1023` ("`WebAuthn` Level 3 §5.1 caps `rawId` at 1023 bytes"); `MAX_WEBAUTHN_CREDENTIALS = 32`, commented "Count limit (this crate's choice): security keys one account may enrol (ADR 0058). It bounds `excludeCredentials` and `allowCredentials`, and the list an account sees."; `MAX_WEBAUTHN_LABEL_LEN = 64`, "Byte limit (this crate's choice)".
- `crates/rizzy-domain-auth/src/webauthn.rs` line 91: `MAX_STORED_JSON_LEN = 64 * 1024`, "The largest stored ceremony state or `SecurityKey` read back (ADR 0077 §2: 64 KiB)". Lines 148–153: `decode_json` returns `None` for an unknown format or `json.len() > MAX_STORED_JSON_LEN`, for the state *and* for stored `security_key` values. ADR 0077 sets the 64 KiB bound for the state only.
- The same file, lines 343–346 (`webauthn_enrol_start`) and 451–458 (`enrol_confirm_locked`): `keys.len() >= MAX_WEBAUTHN_CREDENTIALS` → `AuthError::Conflict`. A duplicate credential id and an id longer than 1,023 bytes also give `Conflict`. No size check on the `security_key` JSON before it is inserted (lines 459–472).
- The same file, lines 244–263 (`put_state`): the state is written with no length check. Lines 584–605 (`webauthn_login_challenge`): the state is built from every stored key.
- `crates/rizzy-domain-auth/src/error.rs` lines 100–107: "`Conflict` and `SignupRefused` answer `invalid_request` and `unauthorized` (no Accepted ADR names a code for them)"; `Self::InvalidRequest | Self::Conflict | Self::KeyAlgorithm => ErrorCode::InvalidRequest`; `PossibleClone` → `unauthorized`.

**How large the state can get.** I computed these sizes from the 0.5.5 serde shapes (V for the shapes, read in the crate sources; I did not measure them by running the crate). A stored `security_key` is `{"cred":{…}}`: the credential id and the challenge as unpadded base64url (`base64urlsafedata` 0.5.5 `HumanBinaryData`, `URL_SAFE_NO_PAD`), the COSE key, the counter, `transports`, three flags, `registration_policy`, four extension states and `attestation`/`attestation_format`. The committed fixtures (`crates/rizzy-domain-auth/tests/auth/fixtures/webauthn_security_keys_0_5_5.json`, 32-byte ids) are 559 and 561 bytes. With every variable field at its largest except an attestation chain (a 1,023-byte id, all six transports, a TPM metadata block), one key is about 2,113 bytes. The login state is `{"ast":{"credentials":[C1,…,Cn],"policy":"discouraged","challenge":"<43 chars>","appid":null,"allow_backup_eligible_upgrade":false}}`. Each `Ci` is a stored `security_key` without its 9-byte `{"cred":…}` wrapper, and the fixed part is 158 bytes plus the n−1 commas. So 32 keys of about 2,113 bytes come to about 67.4 KiB, already above the limit. A key that keeps a parsed attestation certificate chain (`ParsedAttestationData::Basic`/`AttCa`/`AnonCa`, each certificate kept as DER in base64url, `webauthn-rs-core` `src/interface.rs` lines 486–498) can alone come near the 64 KiB request limit of `WebauthnJson`. Conveyance is `"none"` (ADR 0077 §5). Mainstream browsers then replace the statement with `"none"` (L, W3C WebAuthn Level 3 §5.1.3), so honest keys stay small. A client that holds a fresh OPAQUE session can still send any statement the crate verifies, a self-made certificate chain included.

**G06-11: endpoints and `pending_id` exist only in code.** ADR 0058 points 1–3 and ADR 0077 define enrolment and assertion. They never define listing keys, removing a key (or whether removal needs a fresh OPAQUE session, without which a stolen session could strip the second factor), the label rule, or how the client learns `pending_id` from a bare `{"error":"second_factor_required"}`. The code decides each of these:

- `crates/rizzy-proto/src/webauthn.rs` lines 6–20: the six-row endpoint table, and "`pending_id` is the login's own `login_id` (ADR 0058 point 3), so no new field is needed in the error body (ADR 0028 item 3). `webauthn/login/challenge` answers `not_found` when there is no such row".
- `crates/rizzy-server/src/http/api.rs` lines 44–49 (module table), 531–576 (`SessionNeed`: `webauthn/login/challenge` none, `webauthn/login/finish` optional, the four others `NotRecovery`), 587–596 (body limit 0 for `enrol/start` and `list`), 731–739 (`webauthn_possible_clone` logged as a security event).
- `crates/rizzy-proto/src/http.rs` lines 135–145: the six path constants.
- `crates/rizzy-domain-auth/src/webauthn.rs` lines 506–533 (`webauthn_remove`): a fresh OPAQUE session, no assertion and no other proof; `not_found` when no row was deleted. By contrast `totp_disable` (`totp.rs` lines 286–301) asks for a fresh OPAQUE session *and* a current code. Every OPAQUE session of an account with 2FA has passed its second factor at login, re-authentications included: `login.rs` lines 294–303 run `check_second_factor` on every `login/finish` before `issue_login`.
- [ADR 0028](0028-api-v1-http-conventions.md) item 1 freezes the endpoint list for `v1` by resource. Its binding first sentence, in the text ADR 0052 gave it and as ADR 0075 §1 and ADR 0081 §0 entry 5 extend it, has no `webauthn` resource, and ADR 0028's status line names neither ADR 0058 nor ADR 0077.

**ADR 0082's change touches only the policy.** ADR 0082 replaced ADR 0077 §2's first paragraph (the feature list) and §7 (user verification). Stored keys now carry `"registration_policy":"discouraged"` and the login state `"policy":"discouraged"`; the sizes above use those values. ADR 0082 names no limit, endpoint or `pending_id` rule, and this ADR changes nothing it decided. The sentence of ADR 0077 §2 that this ADR replaces (the fifth sentence of "Where") is not one ADR 0082 names.

**Process.** A change to Accepted Decision text is a new Proposed ADR naming the parts (CLAUDE.md, ADR 0020 point 9). Nothing has been released: `git tag` lists no tag in this repository (V). So no deployed server holds rows under rules other than the shipped code's.

## Decision

### 1. The six endpoints, as shipped

All six are `POST` under `/api/v1/webauthn/`, with JSON bodies of `rizzy-proto::webauthn` types, and follow every ADR 0028 rule (errors item 3, body limits item 7, headers item 10). `WebauthnJson` is the browser's or the crate's options or credential JSON as *text*: printable ASCII and spaces, at most 64 KiB (`WebauthnJsonRule`), parsed only inside `rizzy-domain-auth`. `Id` is 16 bytes base64url. A credential id is 1 to 1,023 bytes, base64url without padding.

| Path | Request → response | Session (HTTP layer; domain) | Refusals: code (status) |
|---|---|---|---|
| `webauthn/enrol/start` | no body (body limit 0) → `{"enrolment_id": Id, "options": WebauthnJson}` | any non-recovery session; a fresh OPAQUE session | `not_found` (404) when this server's origin cannot be a relying party; `fresh_session_required` (403); `invalid_request` (400) when the account holds 32 keys; `unauthorized` (401) for a recovery-only session |
| `webauthn/enrol/confirm` | `{"enrolment_id", "label", "credential": WebauthnJson}` → 204 | as `enrol/start` | `not_found`; `fresh_session_required`; `unauthorized` for an unknown, expired, used or other-account enrolment, or a response the ceremony refuses; `invalid_request` for a credential that is not WebAuthn JSON, a key that is not ES256 (ADR 0077 §6), a credential id already enrolled on the account or longer than 1,023 bytes, the 33rd key (§2) and a key above the per-key limit (§2) |
| `webauthn/list` | no body (body limit 0) → `{"credentials": [{"credential_id", "label", "created_ms"}]}`, at most 32 entries, oldest first | any non-recovery session (OPAQUE or device) | `unauthorized` for a recovery-only session |
| `webauthn/remove` | `{"credential_id"}` → 204 | any non-recovery session; a fresh OPAQUE session | `fresh_session_required`; `not_found` when the account holds no key with that id |
| `webauthn/login/challenge` | `{"pending_id": Id}` → `{"options": WebauthnJson, "totp": bool}` | none | `not_found` when there is no live pending row for `pending_id` (the account holds no key, the row expired or was used) or the server cannot be a relying party |
| `webauthn/login/finish` | `{"pending_id": Id, "credential": WebauthnJson}` → `LoginFinishResponse` | optional, exactly as `login/finish` (a re-authentication from a session) | `unauthorized` for an unknown, expired or used pending row or state, an assertion the ceremony refuses, a key no longer enrolled, and a counter refusal (INV-83, also logged as the security event `webauthn_possible_clone`); `invalid_request` for a credential that is not WebAuthn JSON; `rate_limited` (429) past the per-account bucket (10 assertions per 15 minutes with backoff, cleared by a success); `credentials_stale` (409) as for `login/finish` |

- **Requests reject unknown fields; responses ignore them.** Request types are `deny_unknown_fields`. `totp` defaults to `false` when absent.
- **Label.** 1 to 64 bytes of UTF-8 (`MAX_WEBAUTHN_LABEL_LEN`), no character for which Rust's `char::is_control` holds, no leading or trailing white space (`str::trim`). It is stored as given, without Unicode normalisation. It is personal metadata (threat model §3.4): `Debug` prints only its length, and it is never logged.
- **Removal needs a fresh OPAQUE session** (`Session::require_fresh_opaque`, 5 minutes, CRYPTO.md §5.10), like enrolment. A device-authenticated session or a stolen bearer token alone cannot remove a key. No assertion is asked: the fresh session already passed the second factor at login, and the commonest reason to remove a key is that it is lost (Open question 2). Removing the last key turns the security-key factor off. TOTP, if enrolled, stays. A login state issued before the removal is refused at `login/finish` (ADR 0077 §2 rule 4: the account's current rows decide).
- **List.** It shows `credential_id`, `label` and `created_ms` only; no counter, flags or attestation leaves the server. The list parser refuses more than 32 entries.

### 2. Limits

- **Keys per account: at most 32** (`MAX_WEBAUTHN_CREDENTIALS`, `rizzy-proto::limits`, as shipped). The count is checked under the account lock both at `enrol/start` and at `enrol/confirm`. Two enrolments started before the 32nd is confirmed therefore cannot both land.
- **Size of one stored key: at most 1,984 bytes** of `security_key` JSON (new `MAX_WEBAUTHN_SECURITY_KEY_LEN = 1_984`, in `rizzy-domain-auth::webauthn`). At `enrol/confirm`, after the crate accepts the attestation and after the ES256 check, the server serialises the `SecurityKey`. If the result is longer than 1,984 bytes it answers `invalid_request` and writes no row. The enrolment state has then been taken, so a retry needs a new `enrol/start`.
- **Ceremony state: at most 65,536 bytes**, now on write as well as on read. Before writing either state (`enrol/start`, `login/challenge`), the server checks its JSON length. If it is over 65,536 bytes, the server answers `internal` (500), logs the fixed message "webauthn state exceeds its limit" (no account, id or size), and writes nothing. The transaction rolls back, so a pending row stays live until its own expiry. The read rule is unchanged (§6 entry 1).
- **Why these numbers.** 1,984 = (65,536 − 2,048) / 32: the 64 KiB limit, less 2 KiB for the login state's own fields, shared by 32 keys. The login state of 32 keys, each at the limit, is at most 158 + 32 × (1,984 − 9) + 31 = 63,389 bytes, 2,147 bytes under the limit. So the write check of the login state can only fail for rows stored before this ADR. The enrolment state (`SecurityKeyRegistration`) holds the existing credential ids, not the keys. With at most 31 existing ids of at most 1,023 bytes (1,364 base64url characters each), it stays under 44 KiB. So it cannot fail either. 1,984 bytes take every field at its largest except an attestation chain, as long as the credential id is at most about 920 bytes. A key whose id is longer than that, or that keeps an attestation certificate chain, may be refused. Open question 1 holds the trade-off.
- **Stored keys are read up to 64 KiB, as shipped.** `decode_security_key` keeps its 64 KiB read bound: it only guards the parser. A row written before this ADR is not refused on read for being above 1,984 bytes, so no account loses a key that works.
- **Live state rows per account.** At most one enrolment state: `enrol/start` deletes the account's earlier enrolment states in the same transaction, as shipped. At most one login state per pending row: a new `login/challenge` replaces the previous one. Every pending row needs a verified KE3, so the login buckets of INV-7 bound how many exist, and each expires 60 s after it was demoted.

### 3. `pending_id` is the login's `login_id`

When `login/finish` (KE3 verified) answers `second_factor_required` for an account that holds at least one security key, the server keeps the second-factor-pending row of ADR 0058 point 3, named by the `login_id` that `login/start` returned and `login/finish` echoed. No error body carries it: the body stays `{"error":"second_factor_required"}` (ADR 0028 item 3 unchanged). The client:

1. sends `webauthn/login/challenge` with `pending_id` = its own `login_id`;
2. on `not_found`, treats the account as TOTP-only (or the 60 s as spent) and restarts the OPAQUE login, with a TOTP code if the user has one;
3. on success, runs `navigator.credentials.get` with `options`, may offer TOTP instead when `totp` is `true` (a code restarts the OPAQUE login with it), and sends `webauthn/login/finish`.

The pending row lives 60 s from the demotion. A later `login/challenge` replaces the state but does not extend the row. `login/finish` takes the pending row and the state once, whatever the outcome. A refused finish needs a new OPAQUE login.

### 4. Crash and retry behaviour

- **`enrol/start`** commits the state, or nothing. A client that loses the answer calls `enrol/start` again: the new state replaces the old.
- **`enrol/confirm`** takes the state and inserts the key in one transaction under the account lock. A refusal (`unauthorized`, `invalid_request`) commits the deletion of the state. An internal failure rolls back, and the state is then deleted in a second transaction (`settle_single_use`, as shipped). A client that loses a 204 and retries gets `unauthorized`. It must then call `webauthn/list`: if the key is listed, the enrolment succeeded.
- **`remove`** is one delete under the lock. A retry after a lost 204 gets `not_found`. The client treats `not_found` after an unanswered `remove` as done and re-lists.
- **`login/challenge`** may be repeated within the pending row's 60 s. **`login/finish`** is not retryable: the row and the state are single-use, and a lost answer means a new login.
- **Server crash.** Every row above is in `auth_` tables (ADR 0010 §5). No state is in memory. `worker` deletes expired pending and challenge rows, and expiry is also checked on read.

### 5. Client rules

- Clients must disable "Add a security key" while `webauthn/list` shows 32 keys, and say why ("At most 32 security keys. Remove one to add another."). An `invalid_request` from `enrol/confirm` after a successful browser ceremony is shown as "This security key cannot be added", never as a crash.
- The label field limits input to 64 UTF-8 bytes and trims white space before sending (the web vault's `SecurityKeysSection.tsx` does both today).

### 6. What this ADR supersedes

Under [ADR 0020](0020-partial-supersession.md) point 9, each part named below stops binding when this ADR is Accepted. The text given replaces it and binds as Decision text of this ADR. Every part not named stays binding. Where an ADR 0077 §9 entry is named, the whole entry is replaced, so that the part of ADR 0058 it rewrites keeps exactly one binding text (the convention of ADR 0082 §2). About 180 of ADR 0077's roughly 4,130 Decision words are replaced, well within ADR 0020 point 4's limit. ADR 0058 is not named: list, removal, the limits and the `pending_id` rule add to its points 1–3 without contradicting them. ADR 0082 is not named: no part of it changes.

**[ADR 0077](0077-webauthn-rs-integration-fixes.md)**

1. *§2 "Where", fifth sentence* ("A row whose `state_format` the binary does not know, or whose `state` exceeds 64 KiB, is refused on read (bounded input, fail closed); the ceremony restarts.") is replaced by: "A state is never written above 64 KiB (65,536 bytes of JSON): the server checks its length before the row is written and, if it is longer, answers `internal`, logs a fixed message and writes nothing; [ADR 0098](0098-security-key-limits-and-endpoints.md) §2's limits of 32 keys per account and 1,984 bytes per stored `security_key` keep every state of keys enrolled under them below that bound. A row whose `state_format` the binary does not know, or whose `state` exceeds 64 KiB, is refused on read (bounded input, fail closed); the ceremony restarts."
2. *§5, first sentence* ("ADR 0058 point 2, its owner answer 3 and its closing sentence are replaced (§9 entries 12, 15 and 16): no CA list is configured, …, and a valid one is accepted whatever its format; what the crate parsed stays inside `security_key` (stripping it would need `danger-credential-internals`).") is replaced by: "ADR 0058 point 2, its owner answer 3 and its closing sentence are replaced (§9 entries 12, 15 and 16): no CA list is configured, so conveyance is `"none"` and no statement is chained to a root; if a statement in another format arrives, the crate verifies it on its own terms and refuses one that fails or is unsupported, and a valid one is accepted whatever its format, as long as the stored `security_key` fits [ADR 0098](0098-security-key-limits-and-endpoints.md) §2's limit of 1,984 bytes; what the crate parsed stays inside `security_key` (stripping it would need `danger-credential-internals`)."
3. *§9 entry 15* is replaced by: "15. *Owner answer 3* is replaced by: "3. No attestation statement is chained to a root, and no CA list is held. A statement in a format other than `"none"` is checked by `webauthn-rs` against its own signature and format rules; a registration whose statement fails them, or whose format the crate does not support, is refused. A valid one is accepted whatever its format, unless the stored `security_key` would exceed 1,984 bytes ([ADR 0098](0098-security-key-limits-and-endpoints.md) §2), and what the crate parsed is kept inside the stored `security_key`.""

**[ADR 0028](0028-api-v1-http-conventions.md)**

4. *Item 1, first sentence*, in the text ADR 0052 ("What this ADR supersedes", first bullet) gave it and as ADR 0075 §1 and ADR 0081 §0 entry 5 extend it, is replaced by: "The endpoints of `rizzy-server` `http/api.rs` (module table), under `/api/v1/`, grouped by resource (`register`, `login`, `device-auth`, `account`, `devices`, `healing`, `recovery`, `totp`, `webauthn` ([ADR 0098](0098-security-key-limits-and-endpoints.md) §1), `vault`, `attachments` ([ADR 0054](0054-attachments-envelope-and-api.md) §6), and the resources that [ADR 0075](0075-session-listing-and-ending.md) (`sessions`) and [ADR 0081](0081-multiple-vaults-personal-and-shared.md) (`directory`, and the `vault/members/` verbs under `vault`) add), verb last (`start`, `finish`, `commit`, …), plus the endpoints that the `icons` role's own router and listener serve outside `http/api.rs`, never combined with `api` or `web` ([ADR 0010](0010-server-shape.md) §2): `POST /api/v1/icons/fetch`, resource `icons`, verb `fetch` ([ADR 0052](0052-icon-proxy-role.md)), and the breach-check endpoint `POST /api/v1/icons/breach-range` ([ADR 0053](0053-hibp-breach-check-egress.md) item 1); the count is whatever the `http/api.rs` module table holds, and that table is the authoritative list." This adds `webauthn` and keeps the additions of ADRs 0052, 0075 and 0081 unchanged. It also names `attachments` and the breach-check endpoint, which ADRs 0054 and 0053 added without naming this item (the breach-check path is the one `rizzy-proto` `http::paths` ships, V). The second sentence of item 1 (`POST` for everything, `GET` only for `devices/grants`) and the rest of the item stand. Item 3 is not superseded: every refusal above uses an existing code. Under ADR 0002 point 5 the change is additive: older clients never call these endpoints.

### 7. On acceptance (documentation edits, not made in this change)

1. **Status lines and index.** The owner adds "[ADR 0098](0098-security-key-limits-and-endpoints.md) (§2 "Where" in part, §5 in part, §9 entry 15)" to ADR 0077's status line and "[0098](0098-security-key-limits-and-endpoints.md) (item 1 in part)" to ADR 0028's, and updates both index rows and this ADR's row.
2. **[CRYPTO.md §11.17](../CRYPTO.md#1117-webauthn-2fa-m3).** The opening line adds "and [ADR 0098](adr/0098-security-key-limits-and-endpoints.md)". A new bullet **"Limits, management and the pending login (ADR 0098)"** says: at most 32 keys per account; at most 1,984 bytes of stored `security_key`; ceremony state never written or read above 64 KiB; list and removal endpoints, removal under a fresh OPAQUE session; `pending_id` is the login's `login_id`.
3. **[THREAT_MODEL.md](../THREAT_MODEL.md) INV-106.** The "Verified by" cell adds: "a 33rd key and a key above 1,984 bytes refused with `invalid_request`; 32 keys at the limit give a login state of at most 65,536 bytes that verifies; a state over 64 KiB is never written ([ADR 0098](adr/0098-security-key-limits-and-endpoints.md) §8)."
4. **ROADMAP.md:** no change (no scope change).
5. **Code comments.** `rizzy-proto::limits` drops "(this crate's choice)" from `MAX_WEBAUTHN_CREDENTIALS` and `MAX_WEBAUTHN_LABEL_LEN` and cites this ADR. `rizzy-domain-auth::error` stops saying "no Accepted ADR names a code" for `Conflict` on the webauthn paths.

### 8. Implementation plan and tests

Code changes (small: the endpoints, the count limit, the label rule and `pending_id` are already as specified):

1. `rizzy-domain-auth::webauthn`: add `MAX_WEBAUTHN_SECURITY_KEY_LEN = 1_984`. In `enrol_confirm_locked`, refuse a `to_json(&key)` longer than that with a new `AuthError::KeyTooLarge` that maps to `invalid_request` (alongside `KeyAlgorithm`). In `put_state`, refuse a state longer than `MAX_STORED_JSON_LEN` with `AuthError::Internal("webauthn state exceeds its limit")` before the insert.
2. `rizzy-proto::limits` and `rizzy-domain-auth::error`: the doc comments of §7 item 5.
3. Web vault `SecurityKeysSection.tsx`: the 32-key rule and messages of §5.

Tests (`crates/rizzy-domain-auth/tests/auth/webauthn.rs`, software authenticator as today):

- A 33rd key: refused at `enrol/start` with `invalid_request`. Two enrolments started at 31 keys: the second confirmation is refused with `invalid_request`, and the account holds 32.
- Per-key boundary: a credential id length chosen so that the stored JSON is exactly 1,984 bytes is accepted; one byte more is refused with `invalid_request`, and no row is written. The test asserts the JSON length it reaches, so a crate change that moves the boundary fails loudly.
- Bound by construction: a unit test asserts `MAX_WEBAUTHN_CREDENTIALS * MAX_WEBAUTHN_SECURITY_KEY_LEN + 2_048 <= MAX_STORED_JSON_LEN`. An integration test enrols 32 keys at 1,984 bytes, checks that the stored login state is at most 65,536 bytes, and completes an assertion with the 32nd key.
- Legacy rows: rows inserted by SQL with `security_key` of 3,000 bytes, enough that the login state exceeds 64 KiB: `login/challenge` answers `internal`, no state row exists afterwards, and the pending row is still live.
- `remove`: needs a fresh OPAQUE session (`fresh_session_required` from a device session and from an OPAQUE session older than 5 minutes); `not_found` for an unknown id and for another account's id; an assertion from a removed key, against a state issued before the removal, gives `unauthorized`.
- `pending_id`: after `second_factor_required`, `login/challenge` with the `login_id` succeeds; with any other id, or after 60 s, or after a finish, it answers `not_found`.
- `list`: oldest first; `unauthorized` for a recovery-only session; `rizzy-proto` refuses a 33-entry answer.
- Server (`crates/rizzy-server/src/http/api.rs` tests): the six paths, their `SessionNeed` and body limits match §1's table.
- Web e2e (`apps/web/e2e`): with 32 keys listed, the add control is disabled and shows the message.

## Consequences

### Positive

- A second server or client implementer gets the same endpoints, the same limits and the same `pending_id` rule from the ADRs alone.
- No account can reach a login state the server refuses on every read. The one remaining failure (rows from before this ADR) has a fixed code and leaves no state behind.
- The 64 KiB read bound on stored keys, which the code applied on its own, is now written down. So is its limited role: it guards the parser, nothing more.

### Negative

- A key that keeps an attestation certificate chain, or whose credential id is longer than about 920 bytes, cannot be enrolled. The user gets `invalid_request` and must use another key.
- `invalid_request` is the code for every enrolment refusal, the 33rd key included. Clients must check the count from `webauthn/list` to word the reason.

### Risks

- A `webauthn-rs` version that adds fields to `Credential` makes each stored key larger. Such a change is already a new `security_key_format` under a new ADR (ADR 0077 §4); the boundary test above makes it visible.
- I have not verified the claim that browsers replace a statement with `"none"` (L). If a common browser or key keeps a chain under `"none"` conveyance, users of that key are refused. The signal is enrolment reports of `invalid_request` with a working key.

## Alternatives considered

- **No per-key limit, only 32 keys (the shipped code).** Rejected: as computed in Context, 32 large keys exceed 64 KiB even without an attestation chain, and one key with a chain can do it alone.
- **A lower count with a larger per-key limit (for example 16 keys × 4,032 bytes).** It would admit keys with one or two attestation certificates, at the cost of fewer keys. Open question 1.
- **Raising the 64 KiB state limit.** Rejected: it is ADR 0077's bounded-input rule for a field the server parses on every login; making it larger only moves the failure.
- **A new error code (for example `limit_reached`) for the 33rd key.** Rejected: it adds a row to ADR 0028 item 3's closed table for a case the client can see from `webauthn/list` before it asks.
- **Removal from any session.** Rejected: a stolen bearer token or a device session could then strip the second factor. Removal is a 2FA change, like enrolment, which needs a fresh OPAQUE session.
- **A `pending_id` field in the `second_factor_required` error body.** Rejected: ADR 0028 item 3 fixes the body as `{"error":"<code>"}` only. The `login_id` is already a 16-byte server-chosen value that only the client that ran the login holds.

## Open questions for the owner

1. **Count against size.** Keep 32 keys × 1,984 bytes (refuses keys that keep an attestation chain or have very long ids), or move to 16 keys × 4,032 bytes (admits a chain of one or two certificates)? *Recommendation:* 32 × 1,984. Conveyance is `"none"`, so honest keys under mainstream browsers carry no chain. The 32-key limit is what the code and the list type already ship. And a user with more than 16 keys is more plausible than a key that needs its chain kept.
2. **Proof at removal.** `totp/disable` asks for a current TOTP code on top of the fresh OPAQUE session; `webauthn/remove`, as shipped, asks for nothing more. Should removal also require an assertion from one of the account's keys? *Recommendation:* no, keep it as shipped. The fresh session already passed the second factor at login (`login.rs` lines 294–303). An assertion from the key being removed would block the commonest case, a lost key. An assertion from any remaining key would block removal of the last key, which is then lost. The residual case is an attacker who holds a fresh OPAQUE session, and that attacker already got through the second factor.

## References

- [ADR 0058](0058-webauthn-2fa-second-factor.md) points 1–3; [ADR 0077](0077-webauthn-rs-integration-fixes.md) §2, §4, §5, §9, §10; [ADR 0082](0082-security-keys-user-presence-only.md) §1–§2; [ADR 0028](0028-api-v1-http-conventions.md) items 1, 3, 7; [ADR 0052](0052-icon-proxy-role.md) "What this ADR supersedes"; [ADR 0053](0053-hibp-breach-check-egress.md) item 1; [ADR 0054](0054-attachments-envelope-and-api.md) §6; [ADR 0075](0075-session-listing-and-ending.md) §1; [ADR 0081](0081-multiple-vaults-personal-and-shared.md) §0 entry 5; [ADR 0020](0020-partial-supersession.md) points 4 and 9; [ADR 0010](0010-server-shape.md) §5; [ADR 0002](0002-own-protocol.md) point 5.
- [CRYPTO.md](../CRYPTO.md) §5.10, §11.17; [THREAT_MODEL.md](../THREAT_MODEL.md) INV-7, INV-83, INV-106, §3.4.
- Review: [2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md) D5; raw [G08](../reviews/2026-10-25-raw/G08.md) G08-6, [G06](../reviews/2026-10-25-raw/G06.md) G06-11.
- Code (V, read in this worktree): `crates/rizzy-proto/src/{limits.rs,webauthn.rs,http.rs,wire.rs}`, `crates/rizzy-domain-auth/src/{webauthn.rs,error.rs,login.rs,totp.rs,config.rs,session.rs,lib.rs}`, `crates/rizzy-server/src/http/api.rs`, `crates/rizzy-domain-auth/tests/auth/fixtures/webauthn_security_keys_0_5_5.json`, `apps/web/src/views/SecurityKeysSection.tsx`.
- `webauthn-rs` 0.5.5 `src/interface.rs`; `webauthn-rs-core` 0.5.5 `src/interface.rs`, `src/constants.rs` (`CHALLENGE_SIZE_BYTES = 32`); `webauthn-rs-proto` 0.5.5 `src/options.rs`, `src/extensions.rs`; `base64urlsafedata` 0.5.5 `src/human.rs` (V, local cargo registry). The JSON sizes are computed from these shapes, not measured (stated where used).
- W3C Web Authentication Level 3 §5.1 (`rawId` at most 1,023 bytes) and §5.1.3 (the client may replace a statement when conveyance is `"none"`) (L).
