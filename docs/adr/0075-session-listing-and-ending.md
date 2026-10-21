# ADR 0075: Session management: listing and ending sessions under `/api/v1/sessions`

- Status: Proposed
- Date: 2026-10-21
- Deciders: project owner
- Milestone: M3
- Supersedes: [ADR 0028](0028-api-v1-http-conventions.md) item 1 in part (four new endpoints under one new resource, `sessions`; Decision §1), on acceptance.

## Context

[ROADMAP §4.3](../ROADMAP.md#43-cryptography--authentication-m0m1-audited-in-m8) has the row "S | Session/device management: list devices, revoke, force logout | M3". [THREAT_MODEL](../THREAT_MODEL.md#13-security-goals) G-12 reads: "Users can list and revoke devices and sessions, rotate the password, Secret Key and account key, and see new device enrollments."

**What already exists** (V, read at `e1040e2`):

- **Devices: list and revoke.** `rv device list` and `rv device revoke` run [CRYPTO.md §11.8](../CRYPTO.md#118-device-revocation) over `POST /api/v1/devices/suspend` and `account/commit`. Suspension is [ADR 0012](0012-sync-engine.md) §6 phase 1: it needs a fresh OPAQUE re-authentication of another durable device, and the server then "rejects the device's uploads and device authentication and ends its sessions". `devices/unsuspend` lifts it. The web vault's Devices pane lists devices but cannot revoke: CRYPTO.md §11's flow table says "Device revocation (§11.8) | yes | no" for kinds 1–3 and kind 4. These two parts of the row are covered by Accepted decisions.
- **Sessions: neither listed nor ended on request.** [ADR 0028](0028-api-v1-http-conventions.md) item 1 freezes the 27 endpoints of `rizzy-server` `http/api.rs` for `v1`. Before v1.0 they change only under [ADR 0002](0002-own-protocol.md) point 5. None of the 27 lists sessions or ends one. [CRYPTO.md §5.10](../CRYPTO.md#510-sessions-after-authentication) covers token issuance, the device-auth challenge and request signing only. A new endpoint about sessions is a protocol change, so it needs an Accepted ADR (docs/adr/README.md, "The ADR-first rule": "protocol: authentication, sessions"). This is that ADR.
- **The session store.** In [`session.rs`](../../crates/rizzy-domain-auth/src/session.rs), `auth_sessions` holds `token_hash` (`SHA-256(token)`, INV-8), a unique 16-byte `session_id`, `account_id`, an optional `device_id`, `session_kind` (1 `Opaque`, 2 `Device`, 3 `Recovery`), `created_at_ms`, `expires_at_ms` and the request-counter window. An OPAQUE session carries a `device_id` only when it is a re-authentication from a device session of the same account (`login.rs`). The TTLs come from configuration and are not fixed by an ADR: OPAQUE 1 h and device 1 h by default, recovery-only 10 min (CRYPTO.md §11.9 step 3). An OPAQUE session counts as fresh for `FRESH_SESSION_MS` = 5 min.
- **How sessions end today: only as side effects.** Expiry, and `worker`'s `sessions_delete_expired` sweep. Suspension and a committed revocation (`end_device`). Credential replacement ([CRYPTO.md §11](../CRYPTO.md#11-flows), `change.rs`): a password bump ends every OPAQUE and recovery-only session (`end_kind`), and an identity change ends every OPAQUE session except the caller's (`end_kind_except`). A recovery commit ends every session (`end_all`). `recovery/cancel` ends the recovery-only sessions. The storage primitives are `end_all`, `end_device`, `end_kind` and `end_kind_except`. There is no query that lists sessions, and no delete by `session_id` or by token hash.
- **Clients.** Sessions are never persisted ([ADR 0026](0026-client-device-state-and-cache.md) §1: "Sessions live in memory; each process run device-authenticates again"), so every `rv` command opens a new device session, and that session lives on the server until its TTL. The web vault's lock "means a new OPAQUE login to continue" (`apps/web/src/autolock.ts`). The old token is dropped in memory but stays valid on the server until it expires. `LoginFinishResponse` does not carry a `session_id`, so the web vault does not know its own session's id. `DeviceAuthFinishResponse` does carry one.

**Forces.**

- **A device session is cheap to re-open.** It is signed ([CRYPTO.md §5.10](../CRYPTO.md#510-sessions-after-authentication); ADR 0002 owner decision 2), so its bearer token alone is useless. An unlocked enrolled device re-authenticates with its key whenever it wants (§11.3 step 2.1), with no Argon2id run and no prompt. Ending a device session without suspending the device therefore achieves nothing: the device logs straight back in. Suspension is the control that works, and it already has its gate.
- **An OPAQUE session is a bearer token**: the web vault's session, and an OPAQUE re-authentication. Whoever holds the token has API access as the user (AST-12: "download ciphertext, delete data"). The case "force logout" exists for is a web vault left open on a shared computer, or a copied token. Today only a password change ends such a session, and that is far too heavy.
- **Threat model.** INV-7: rate limits must not become a lockout weapon. Its test reads: a flood of unauthenticated attempts "does not block re-authentication, rotation or revocation from an enrolled device". INV-8: tokens are stored only as hashes. INV-48 and §7.6 "I": errors are uniform, and every endpoint gets an authorization test (IDOR). INV-52: no token or id goes in a URL. AR-9: server-enforced controls hold only against an honest server.
- **Process.** ADR 0028 item 1 is frozen for `v1`. [ADR 0020](0020-partial-supersession.md) point 9 allows a supersession limited to the parts it names. ADR 0002 point 5 governs a `v1` change before v1.0. [ADR 0061](0061-notify-websocket-protocol.md) (Proposed) adds `AuthService::session_is_live` for `notify` sockets.
- **Out of scope.** [ADR 0022](0022-server-mode-only.md) point 5 assigns to "the device-management ADR" in M3 the revoked-device rotation race ([ADR 0006](0006-key-hierarchy.md) "Risks"; [CRYPTO.md §11.6](../CRYPTO.md#116-key-rotation) "Known limitation"; AR-18). That race is about signed statements and identity keys, not about sessions, and this ADR does not settle it (open question 1).

## Decision

### 1. What this ADR supersedes

The parts below are named under ADR 0020 point 9. Nothing else in any Accepted ADR changes.

- **[ADR 0028](0028-api-v1-http-conventions.md) item 1, first sentence, in part.** The endpoint count and the resource list grow. To the 27 endpoints and nine resources this ADR adds the four endpoints of §2, under a tenth resource, `sessions`. Proposed ADR [0052](0052-icon-proxy-role.md) also changes this sentence. The count is therefore whatever the `http/api.rs` module table holds once every accepted change has landed, and the table stays the authoritative list. The rest of item 1 stands: `POST` for everything, `GET` only for `devices/grants`, and the reason given there.
- **Not superseded.** Every error in this ADR uses an existing code, so item 3 is unchanged. Items 4 and 5 (bearer token, request signing), item 7 (body limits) and every other item also apply unchanged.
- **ADR 0002 point 5.** The change is additive: an older client never calls these endpoints. It therefore needs no raise of the minimum client versions in `/api/meta`, only the changelog entry point 5 asks for. From v1.0 it would count as additive under point 3.

### 2. Endpoints

| Method, path | Request → response | Session |
|---|---|---|
| `POST /api/v1/sessions/list` | no body → `SessionListResponse` | OPAQUE or device |
| `POST /api/v1/sessions/current/end` | no body → 204 | any (OPAQUE, device or recovery-only) |
| `POST /api/v1/sessions/end` | `EndSessionRequest` → 204 | fresh OPAQUE or device (§4; checked by the domain) |
| `POST /api/v1/sessions/others/end` | no body → 204 | fresh OPAQUE or device (§4; checked by the domain) |

- The four path constants go in `rizzy-proto` `http::paths`: `SESSIONS_LIST`, `SESSIONS_CURRENT_END`, `SESSIONS_END` and `SESSIONS_OTHERS_END`.
- Paths follow item 1's pattern: resource first, verb last, as in `devices/grants/ack`.
- `list` is a read with no body. It is still `POST` with an empty body, as `recovery/cancel` and `totp/enrol/start` are, so `devices/grants` stays the one `GET`.
- A `session_id` travels in a body only, never in a path or query (INV-52).
- The default body limit (`MAX_BODY_LEN`) applies.
- Over a device session, every one of these requests is signed like any other (item 5). The empty-body ones are signed over `SHA-256` of the empty body.

### 3. `rizzy-proto` types

The new module is `rizzy_proto::session`:

```rust
/// Body of `sessions/end`.
#[serde(deny_unknown_fields)]
pub struct EndSessionRequest {
    pub session_id: Id, // 16 bytes, base64url (22 characters)
}

#[serde(rename_all = "snake_case")]
pub enum SessionKindView {
    Opaque,   // "opaque": OPAQUE login or re-authentication (bearer token)
    Device,   // "device": device-authenticated, every request signed
    Recovery, // "recovery": the recovery-only session of CRYPTO.md §11.9 step 3
    #[serde(other)]
    Unknown,  // parse-only, for a newer server; the server never sends it
}

pub struct SessionView {
    pub session_id: Id,
    pub kind: SessionKindView,
    /// The device of a device session, or the durable device an OPAQUE re-authentication
    /// was bound to. Absent for a plain OPAQUE login (the web vault).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<Id>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    /// True for exactly one entry: the session that made this request.
    pub current: bool,
}

pub struct SessionListResponse {
    pub sessions: Vec<SessionView>, // at most MAX_SESSIONS_LISTED = 256; more is a parse error
    #[serde(default)]
    pub truncated: bool,            // true when the account has more live sessions
}
```

- **What a `SessionView` must not carry:** the token, its hash or anything derived from it; the request-counter window; and any field the server does not already store. That rules out source address, user agent and "last used" (Alternatives; open question 2). `session_id` is not a credential. It is a request-signing input, useless without the device key, and only the session's own account sees it.
- `MAX_SESSIONS_LISTED` (256) goes in `rizzy_proto::limits`. Parsing a longer list fails, like the other bounded lists.
- Request types refuse unknown fields, as every `rizzy-proto` request does. Response types ignore unknown fields.
- The `proto_json` fuzz target gains `EndSessionRequest` and `SessionListResponse`. The checked-in OpenAPI description is regenerated.

### 4. Who may call what

- **R1. `sessions/list`.**
  - The caller's session must be `Opaque` or `Device`. A recovery-only session gets `401 unauthorized`: it "covers the recovery commit only" (`SessionKind::Recovery`).
  - No freshness is needed. The call reads metadata of the caller's own account, which the caller could already act on.
  - It returns the account's unexpired sessions (`expires_at_ms > now`). Rows that have expired but are not yet swept are left out.
  - The list is newest first (`created_at_ms` descending, then `session_id` bytes ascending), with at most 256 entries, and `truncated` set when there are more.
  - `current` is set on the caller's row.
- **R2. `sessions/current/end`** (sign-out). Any session kind may call it, with no freshness. It deletes the caller's row by token hash. A repeat with the same token gets `401 unauthorized`, because the token no longer exists. Clients read `401` on this call as "already ended".
- **R3. `sessions/end`** (end one session).
  - **The caller** must be one of two things. The first is a fresh OPAQUE session (`Session::is_fresh_opaque`, `FRESH_SESSION_MS` = 5 min, the same rule as CRYPTO.md §11 "Replacing credentials"). The second is a device session of a device that `Devices::usable_durable` accepts (kinds 1–3, not suspended, not revoked, not expired). A recovery-only caller gets `401 unauthorized`. Any other caller gets `403 fresh_session_required`.
  - **The target** is the `session_id` of an unexpired session of the caller's account. Any other id gets `404 not_found`. An id of another account answers exactly like an unknown id (§7.6 "I").
  - A target of kind `Device` gets `400 invalid_request` (§5).
  - A target that is the caller's own session is ended, as R2 would end it.
- **R4. `sessions/others/end`.** The caller rule is R3's. The call ends every `Opaque` and `Recovery` session of the account except the caller's, and no `Device` session (§5). It answers `204` even when nothing was ended.
- **R5. Atomicity.** R2–R4 run in one write transaction under the account lock (`lock_account`), and the caller's session is re-read inside it (`session::reload`), as `suspend_device` does. A caller whose session ended concurrently cannot act. An end and a concurrent credential change are serialised.
- **R6. The web vault (kind 4)** may call all four endpoints. Under R3 and R4 it can end only OPAQUE and recovery-only sessions. It never ends a device session and never suspends anything. CRYPTO.md §11's flow table therefore stays as it is: ending a session is not device revocation, and kind 4 still cannot revoke.

*Why freshness for R3 and R4, but not for R1 and R2:* it gives an asymmetry in the owner's favour. A copied web token older than 5 minutes cannot end the owner's sessions, while the owner's fresh login can end the thief's. A device session counts as fresh because each of its requests is signed with the device key, which needs a local unlock (§5.10). That proof is at least as strong as a fresh OPAQUE login. It also means an enrolled device never depends on the login buckets an attacker can flood (INV-7, §7).

### 5. Device sessions: suspension is the force logout of a native device

- This API ends no `Device` session. On an unlocked device, ending one makes the device re-authenticate on its next request, so the user would believe they had logged the laptop out when they had not. That is worse than offering nothing.
- Device sessions end only through the existing paths: suspension (`end_device`, §11.8 step 0) and revocation commits, with their existing gates. A device session's owner can still sign itself out with R2.
- In a session list, a client shows a `Device` row of another device with "Suspend or revoke this device" for a durable caller (`rv device revoke`). The web vault shows "Use another of your devices to suspend or revoke it", as the Devices pane already says. Neither offers "End".
- R3 refuses a device target with `invalid_request` rather than `204`, so a client bug shows up instead of passing as a silent success.

### 6. What the ended token's next request gets

- The row is deleted in the transaction that ends the session. No tombstone is kept.
- The next request with that token gets `401 unauthorized`, byte for byte the same answer as an unknown or expired token (`session::load`; ADR 0028 item 3; INV-48). There is no new code and no "ended by whom" marker.
- A state-changing flow that re-reads its session inside its own transaction (`session::reload`, for example in `change.rs`, `device.rs` and `totp.rs`) and is still in flight fails with `401`. A read that was authenticated before the end may still complete.
- **Web vault.** A `401` on any request other than `login/*`, `recovery/*` and the sign-out call means the session has ended. The vault locks, which clears decrypted state as auto-lock does, and shows "This session has ended. Log in again."
- **Native clients.** On a `401`, a native client re-runs device authentication once. That is existing behaviour. Under this ADR a device session ends only by its own sign-out (R2), so a native client never has to recover from another session's end.
- **`notify` sockets.** If [ADR 0061](0061-notify-websocket-protocol.md) is accepted, a socket closes at its next `session_is_live` check (≤ 30 s). This ADR does not depend on ADR 0061.
- **Clients end their own sessions.** The web vault calls `sessions/current/end` on lock and on sign-out, best effort: a failure is ignored and not retried, and the token then lapses at its TTL. Whether `rv` does the same when a command exits is open question 3.

### 7. Rate limits

There is no new `BucketKind`. The four endpoints are authenticated and guess nothing secret: a `session_id` has 128 random bits, and R3 looks it up only within the caller's own account. Each call costs one indexed query on `auth_sessions_account` (at most 257 rows for `list`) or one delete. A caller with a session can do much more expensive things already.

Freshness is obtained through the existing buckets: a web login uses `LoginNameSource` and `LoginName`, a native OPAQUE re-authentication uses `Reauth`. Because a device session satisfies R3 without OPAQUE, a login flood never stops an enrolled device from ending web sessions. That carries INV-7's guarantee over to this feature. The web vault, which has only OPAQUE, can be held off by such a flood. That residual is the same as for its password change today (Consequences).

### 8. Notices

- **The server sends none.** No Accepted ADR provides a channel in M3 (ADR 0045 and ADR 0061 are Proposed), and an unsigned notice is suppressible anyway (AR-9).
- **The acting client confirms locally.** For example: "Other sessions ended. Anyone who knows your master password and Secret Key can log in again: if you think someone does, change your password." A password change already ends every OPAQUE session (§11.5 step 5).
- **The ended client** shows §6's message.
- **Later.** A "session ended" event is a candidate for the per-account security event log (THREAT_MODEL §7.6 "R") once that log has an ADR. This ADR does not decide it.

### 9. Clients

- **Web vault.** The Devices pane gains a Sessions section.
  - **Rows:** "Web or password login" (OPAQUE, no `device_id`); "Password re-check on device …" (OPAQUE with `device_id`); "Device …" (`Device`); and "Account recovery in progress" (`Recovery`). The recovery row says to cancel the recovery from an enrolled device, because `recovery/cancel` is the real control there: a thief holding the kit can repeat `recovery/complete` until the commit (§11.9 step 3).
  - **Actions:** "End" on every non-current OPAQUE or recovery row, and "End all other sessions".
  - **Without freshness**, the pane first runs a login (the §11.5 step 1 pattern). It switches to the new session and ends the old one with R2.
- **`rv` parity.** `rv` always holds a device session, so R3 and R4 need no password.
  - `rv session list` prints the id, kind, device label, creation and expiry, and marks the current session.
  - `rv session end <id>` accepts a unique prefix of a listed id, as `device revoke` does.
  - `rv session end --others` ends every other non-device session.
  - `docs/rv.md` documents the three commands.
- **The extension** may use the endpoints. Nothing in M3 requires it to.

### 10. Server implementation

- **`rizzy-domain-auth`** gains four `AuthService` methods: `list_sessions`, `end_current_session`, `end_session` and `end_other_sessions`. Each takes the authenticated `Session` and `now_ms`.
- **New queries** (both engines, bound parameters only, `auth_` tables only, `cargo xtask check-tables`). There is no schema change and no migration.
  - `sessions_list_account.sql`: `SELECT session_id, device_id, session_kind, created_at_ms, expires_at_ms FROM auth_sessions WHERE account_id = $1 AND expires_at_ms > $2 ORDER BY created_at_ms DESC, session_id ASC LIMIT $3`, with `$3` = 257 so that `truncated` can be detected.
  - `session_get_by_id.sql`: `session_kind` and `expires_at_ms` by (`account_id`, `session_id`). R3 uses it to tell a device target from a missing one.
  - `session_delete_id.sql`: delete by (`account_id`, `session_id`) (R3).
  - `session_delete.sql`: delete by `token_hash` (R2).
- **Existing primitives:** R4 is `end_kind_except(Opaque, caller)` followed by `end_kind_except(Recovery, caller)`. `end_all`, `end_device` and `end_kind` stay as they are, and none of these endpoints uses them.
- **`rizzy-server`.** Four routes in `http/api.rs`, and four rows in its module table with the Session column of §2.
- **Docs in the change that accepts this ADR.** CRYPTO.md §5.10 gains an "Ending sessions" bullet that points here. CRYPTO.md §11's flow table, THREAT_MODEL G-12 and ROADMAP stay unchanged.

### 11. Tests

**Domain** (`crates/rizzy-domain-auth/tests/auth/sessions.rs`):

1. `list` returns only the caller's account. It leaves out rows that are expired but not yet swept, keeps the order of R1 and sets `current` exactly once. With 257 live sessions it returns 256 entries and `truncated`. `device_id` is present for device sessions and bound OPAQUE sessions, and absent for a plain login. A recovery-only caller gets `Unauthorized`.
2. `current/end` works for each kind. Afterwards `authenticate_request` with the token answers `Unauthorized`, and so does a repeat of the call.
3. `end`:
   - Callers: a fresh OPAQUE caller is accepted. An OPAQUE caller older than `FRESH_SESSION_MS` gets `FreshSessionRequired`. A device caller is accepted. A recovery-only caller gets `Unauthorized`.
   - Targets: a device target gets `InvalidRequest`. Another account's session, an unknown id and an expired id each get `NotFound`, and the three answers are indistinguishable. The caller's own id ends the caller.
4. `others/end` ends every OPAQUE and recovery-only session except the caller's. It leaves every device session, including the caller's own device's. It answers `Ok` when there is nothing to end.
5. Race: one session ends another between authentication and the commit of a password change made with it. The commit fails with `Unauthorized` and writes nothing.
6. INV-7: with `LoginName` in backoff from an unauthenticated flood, a device session's `others/end` succeeds.
7. A serde snapshot of `SessionView` pins its exact field names, so a token-derived field cannot slip in unreviewed.

**HTTP** (`rizzy-server`):

- Each route accepts `POST` only: `GET` gets `405 invalid_request`.
- A device session without a signature gets `401`.
- An ended token's `401` is byte-identical, status, headers and body, to an unknown token's.
- An oversized body gets `413`, and an unknown request field gets `400`.
- The module-table rows match the router.

**`rizzy-proto`:** round-trips; 257 entries are refused; an unknown kind parses as `Unknown`; the `proto_json` fuzz target covers the new types; the OpenAPI check passes.

**Clients:**

- `rv` integration tests cover `session list`, `session end <prefix>` and `session end --others`.
- A web Playwright e2e test opens two web sessions and ends one from the other. The ended tab locks with §6's message at its next request.
- Lock calls `current/end`.

**`notify`:** if ADR 0061 is accepted, the socket of an ended session closes within one check interval.

## Consequences

### Positive

- G-12's "list and revoke … sessions" gets a defined, testable mechanism, and ROADMAP's "force logout" has a meaning for each session type: R2–R4 for web and OPAQUE sessions, suspension for native devices.
- A web vault left open elsewhere can be ended without changing the password. A lock or sign-out now kills the token on the server instead of leaving it valid for up to an hour.
- Enrolled devices can see web logins (`sessions/list`), which partly covers the "web vault session started" notice of CRYPTO.md §11.4 that nothing delivers today.
- No cryptography, no schema change, no new error code and no new rate-limit bucket. The change reuses the existing end primitives and freshness rule.

### Negative

- `v1` gains four endpoints, which means a larger frozen surface and a changelog entry.
- A web vault more than 5 minutes past its login must log in again before it can end other sessions.
- `rv` opens a device session per command, and each lives for the TTL, so `rv session list` shows several `rv` sessions unless open question 3 is answered yes. Those rows cannot be ended from elsewhere (§5).
- The web vault makes one more request on lock.
- Ending a native device needs suspension, which kind 4 cannot do. A user with only a web vault and a lost laptop still needs another durable device, as today.
- The web vault can be held off by a login flood (§7).

### Risks

- **AR-9:** a malicious server can hide sessions from the list or ignore an end. The list is the server's word, not proof. The UI must not present it as one.
- **Users may treat "end session" as the cure for a leaked password.** Whoever knows the password and Secret Key logs back in. The confirmation text (§8) must point to a password change and rotation.
- **If clients start persisting device sessions** (a change to ADR 0026), ending a device session might become meaningful. §5 would then need a new ADR.
- **If users cannot recognise their sessions from kind, device and time alone,** they will want source address or user agent, and that is a new persistent field and more server-side metadata (open question 2). The signal would be user reports of sessions they cannot identify.

## Alternatives considered

- **`GET /api/v1/sessions` and `DELETE /api/v1/sessions/{id}`** (resource-style REST). This puts an id in URLs and access logs (INV-52) and adds a second method against item 1's one-method rule. ADR 0028 already rejected this style for the same reasons.
- **One `sessions/end` endpoint with a `scope` field** (`current`, `one`, `others`). It saves two paths, but one route would then carry three authorization rules. Separate routes make each rule visible in the `api.rs` Session column and keep each test small.
- **Letting `sessions/end` end device sessions,** from any caller or from durable callers only. The device re-authenticates on its next request, so this gives false assurance (§5), and the effective control, suspension, already exists with the right gate.
- **Making "end" on a device row suspend the device.** This duplicates `devices/suspend`. Done from the web vault, it would let kind 4 suspend, against CRYPTO.md §11's flow table and ADR 0012 §6's gate.
- **No freshness for `end` and `others/end`.** A stale copied token could then keep logging the owner out. Freshness costs the web vault at most one re-login.
- **A fresh OPAQUE login for device callers too,** as suspension requires. It adds a password prompt and puts native devices behind the `Reauth` bucket, for no gain: ending sessions changes no key, and device sessions are signed. Suspension needs more because it shuts a device out of the account.
- **A separate list handle instead of `session_id`.** This needs a new column. `session_id` is not a credential (§3) and is shown only to its own account.
- **Storing source address, user agent or last-used time.** These are new persistent fields under [ADR 0011](0011-storage.md), and more metadata on the server about where and when the user connects. A last-used time would also cost one write per request. Deferred to open question 2.
- **Idempotent `204` for an unknown `session_id`.** This hides typos (an `rv` prefix that matches nothing would print success). `404` reveals nothing beyond the caller's own account.
- **Returning a count from `others/end`.** It is small, but item 2's empty success keeps the answer trivial, and a client that wants a count lists first.

## Open questions for the owner

1. **Who settles the revoked-device rotation race** that ADR 0022 point 5 gives to "the device-management ADR" (ADR 0006 "Risks", CRYPTO.md §11.6 "Known limitation", AR-18)? *Recommendation:* a separate ADR. That race is about signed statements and identity-key confirmation. This ADR is wire and authorization only, and mixing the two would hold this one back behind a cryptographic review.
2. **Should sessions record display metadata** (source address, user agent or last-used time)? *Recommendation:* not in M3. Kind, device, creation and expiry identify web logins well enough, and every extra field is metadata the server keeps about the user's whereabouts. Revisit only if users report sessions they cannot recognise.
3. **Should `rv` end its own session with `sessions/current/end` when a command exits** (best effort, no retry)? *Recommendation:* yes. It costs one request per command and keeps the list and the server's live tokens down to what is actually in use.
4. **Is the 5-minute OPAQUE freshness of R3 and R4 the right window,** or should the web vault get a longer one for ending sessions only? *Recommendation:* keep 5 minutes, the existing `FRESH_SESSION_MS`. One constant is easier to reason about, and a longer window weakens the asymmetry of §4.

## References

- [ROADMAP §4.3](../ROADMAP.md#43-cryptography--authentication-m0m1-audited-in-m8), row "Session/device management".
- [THREAT_MODEL](../THREAT_MODEL.md): G-12 (§1.3), AST-12, §7.6, [§8](../THREAT_MODEL.md#8-security-invariants) INV-7, INV-8, INV-48, INV-52, [§9](../THREAT_MODEL.md#9-accepted-risks-and-out-of-scope) AR-9 and AR-18.
- [CRYPTO.md](../CRYPTO.md): [§5.10](../CRYPTO.md#510-sessions-after-authentication); [§11](../CRYPTO.md#11-flows) (flow table, "Replacing credentials"); [§11.3](../CRYPTO.md#113-unlock-on-an-enrolled-device); [§11.4](../CRYPTO.md#114-web-vault); [§11.5](../CRYPTO.md#115-master-password-or-secret-key-change); [§11.6](../CRYPTO.md#116-key-rotation); [§11.8](../CRYPTO.md#118-device-revocation); [§11.9](../CRYPTO.md#119-recovery-with-the-emergency-kit).
- ADRs: [0002](0002-own-protocol.md) points 3 and 5; [0006](0006-key-hierarchy.md) "Risks"; [0011](0011-storage.md); [0012](0012-sync-engine.md) §6; [0020](0020-partial-supersession.md) point 9; [0022](0022-server-mode-only.md) point 5; [0026](0026-client-device-state-and-cache.md) §1; [0028](0028-api-v1-http-conventions.md) items 1–5 and 7; [0045](0045-recovery-pending-notification.md) (Proposed); [0052](0052-icon-proxy-role.md) (Proposed); [0061](0061-notify-websocket-protocol.md) (Proposed).
- Code (V, `e1040e2`): [`session.rs`](../../crates/rizzy-domain-auth/src/session.rs), `device.rs` (`suspend_device`, `revoker`), `change.rs` (session ends on commit), `recovery.rs` (`recovery_cancel`), `ratelimit.rs` (`BucketKind`), `config.rs` (TTLs, `FRESH_SESSION_MS`), `crates/rizzy-storage/migrations/*/0001_auth_initial.sql` (`auth_sessions`), [`http/api.rs`](../../crates/rizzy-server/src/http/api.rs) (module table), `apps/web/src/views/DevicesPane.tsx`, `crates/rizzy-cli/src/args.rs` (`device` commands).
