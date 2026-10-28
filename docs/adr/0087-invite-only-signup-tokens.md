# ADR 0087: Invite-only signup: invite tokens, issuance, delivery and redemption

- Status: Accepted
- Date: 2026-10-24
- Deciders: project owner
- Milestone: M3 (`rizzy-domain-auth`, `rizzy-storage`, `rizzy-server` admin panel and operator CLI, `rizzy-client`, `rizzy-wasm`, web vault, `rv`)
- Supersedes: [ADR 0048](0048-per-account-storage-quota.md) (§1 in part: its settings sentence, the binding text of [ADR 0028](0028-api-v1-http-conventions.md) item 12's settings clause, gains `RIZZY_SIGNUP` value `invite`, the default), on acceptance; §10.1 gives the part and its replacement. It answers [ADR 0060](0060-admin-panel-stack-boundary.md) open question 6.

## Owner answers (2026-10-25)

The owner's words, verbatim: "0087. agreed"

Every recommendation in the open questions stands:

1. **Operator CLI first.** `rizzy-vault invite …` (§11) ships in phase A, ahead of the admin panel.
2. **Default `invite`.** The default `RIZZY_SIGNUP` moves from `closed` to `invite` in phase A, with a
   release note. §10.1's replacement text carries `default invite`, and ADR 0086 §1.1's built-in default for
   `signup_mode` is `invite`.
3. **No unbound invites at v1.0.** Every invite is bound to a login name (§3); revisit with M10 org
   onboarding.

## Context

**The owner's words, verbatim (2026-10-24):** "Invite-Only Signup Token ADR (ADR 0060 Question 6):
Required before an 'Invite-only' option can be added to the signup screen. Specifies invite token
generation, secure storage, delivery via SMTP, redemption lifecycle, expiration/revocation, and
enumeration-resistant rejection (CRYPTO.md §5.9)."

**Scope.** [ROADMAP §4.9](../ROADMAP.md#49-server-self-hosting--ops-m1-onward), Should, M3: "Admin panel
(user list, disable user, invite-only signup, SMTP settings for notifications)". ADR 0060 §4 fixes the
panel's stack and boundary and a signup screen offering only `SignupMode::{Closed, Open}`: "Invite-only
signup is not a toggle on that enum: it needs token generation, storage, delivery, redemption, expiry and
revocation, checked against CRYPTO.md §5.9's enumeration resistance … The invite screen ships once that
mechanism has its own Accepted ADR (open question 6)." Its owner answers 3, 5 and 6 make the panel's
screens wait for three ADRs: admin authentication (ADR 0085), settings persistence (ADR 0086) and this one.
ADR 0085 and ADR 0086 are being drafted in parallel and are not Accepted; this ADR names the seam it needs
from each (§4, §10) and decides nothing that belongs to them.

**Where SMTP sits.** Outbound *notification* mail is pre-v1.0: the ROADMAP row above (M3, Should) and the
`worker` row of [ADR 0022](0022-server-mode-only.md) §2 ("SMTP relay for notification mail, if configured
(M3)"). Everything inbound — the `smtp` role, profile B and ROADMAP §4.8 — is after v1.0 (owner decision
of 2026-10-22), and sending mail from aliases is Won't for v1.0 (ROADMAP §4.8). No Accepted ADR decides an
outbound mail client (crate, TLS policy) or where SMTP settings live: proposed
[INV-86](../THREAT_MODEL.md#8-security-invariants) seals an SMTP password under the reserved server-only
purpose `0x0103` ([CRYPTO.md §5.11](../CRYPTO.md#511-server-side-encryption-not-zero-knowledge),
[§8.4](../CRYPTO.md#84-aad-and-purposes)), which has no name and no ctx yet; ADR 0086 is the expected home.

**What CRYPTO.md says.** [§5.9](../CRYPTO.md#59-account-enumeration) "Registration": "Registration is an
enumeration oracle ("name taken"), and RFC 9807 says to rate-limit it. The M1 default is invite-only signup:
an admin-issued invite token, bound to a login name. Open signup is opt-in, rate-limited per IP …".
[§11.1](../CRYPTO.md#111-signup-server-mode) step 1 has the user enter "invite token (if the server requires
one)", and step 4.2 sends `POST /api/v1/register/start {invite, login_name, account_id, M1}`. Neither
fixes the token's format, storage, issuance, delivery or lifecycle.

**What the code does today** (read on 2026-10-24, V):

- `crates/rizzy-server/src/config.rs`: `SignupMode { Closed, Open }`, `RIZZY_SIGNUP`, default `Closed`;
  its doc comment says invite-only waits for "the M3 admin API".
- `crates/rizzy-domain-auth/src/config.rs`: `SignupPolicy { Closed, Invite(Box<dyn InviteVerifier>), Open }`
  with `InviteVerifier::admits(&self, token: &str, login_name: &LoginName) -> bool`, documented as "must
  bind the token to the name, compare in constant time, and never log the token". Nothing implements it.
- `crates/rizzy-proto`: `RegisterStartRequest.invite: Option<InviteToken>`, where `InviteToken` is a
  zeroizing, Debug-redacted `SecretText` of at most 256 printable ASCII bytes ("Its format is not
  specified"). `RegisterFinishRequest` has no invite field and `deny_unknown_fields`.
- `crates/rizzy-domain-auth/src/signup.rs`: `register_start` parses the name, checks the policy (before
  any rate limit), charges the per-source, per-(name, source) and per-name buckets, reserves the name by
  inserting an `auth_accounts` row with no credential for the client-chosen `account_id`, and answers
  `Conflict` for a name held by another id. `register_finish` does not look at the policy; inside one
  write transaction under `lock_account` it treats a byte-identical repeat as success, then stores
  everything. `AuthError::SignupRefused` answers the `unauthorized` code. `lib.rs` lists "when an
  unfinished signup's name reservation is released" as undecided.
- Session tokens are 32 CSPRNG bytes stored only as `SHA-256(token)` (`session.rs` `token_hash`;
  CRYPTO.md §5.10, INV-8). `base64ct = "=1.8.3"` is already a workspace dependency (used by
  `rizzy-server` for the secrets file).
- Clients: the web vault's `SignupView` has an optional "Invite (if this server asks for one)" field;
  `rv signup --invite` prompts for the token on the terminal, as does the signup restart in
  `rizzy-cli/src/device.rs`.

**Threats and invariants.** [INV-7](../THREAT_MODEL.md#8-security-invariants) (no account-existence
oracle; backoff per (account identifier, source) and a per-account cap on login and registration
attempts, never a hard lockout); INV-8 (bearer tokens stored hashed); INV-48 (no secrets in logs);
[INV-69](../THREAT_MODEL.md#8-security-invariants) and [THREAT_MODEL §7.19](../THREAT_MODEL.md#719-admin-panel-and-admin-api-m3)
(admin panel: separate admin authentication with a second factor, escaped rendering, strict CSP, CSRF;
"R": "Every admin action goes into the affected users' security event log, without secrets").
[ADR 0010](0010-server-shape.md) §5 (short-lived auth state in the database, purged by `worker`),
[ADR 0011](0011-storage.md) (the `auth_` table prefix, SQLite and PostgreSQL),
[ADR 0028](0028-api-v1-http-conventions.md) (error bodies and headers).

## Decision

**Supersedes:** one Accepted sentence, ADR 0048 §1's settings list (the binding text of ADR 0028 item 12's
settings clause), to let `RIZZY_SIGNUP` take `invite` (§10.1). No wire type changes: the token travels in the existing
`RegisterStartRequest.invite` field and every refusal uses the existing `SignupRefused` → `unauthorized`
mapping. The persistent additions are one table (§15) and one signup-mode value (§10).

### 1. Token format

- **Generation.** 32 bytes from the server's CSPRNG, through the injected `CryptoRng` exactly as session
  tokens are made (`session.rs` `create`). The bytes live in a `Zeroizing` buffer; the type redacts
  `Debug`.
- **Text form.** Unpadded base64url (RFC 4648 §5, V): exactly 43 characters from `[A-Za-z0-9_-]`, decoded
  with `base64ct`'s canonical `Base64UrlUnpadded` decoder (no new dependency), which refuses non-zero
  trailing bits, so every token has one text form (L: base64ct's canonical-decoding behaviour, verified by
  a test at implementation). No prefix, no version byte, no checksum.
- **Parsing at the server.** The wire rule (`InviteTokenRule`: ≤ 256 printable ASCII) is unchanged; the
  domain decodes the value and anything that is not exactly 43 canonical characters decoding to 32 bytes
  is refused like any other bad invite (§7), never as `invalid_request`. Only a value the wire rule itself
  rejects (over 256 bytes, or a non-printable byte) still fails deserialisation with `invalid_request`, as
  every malformed body does; that reveals nothing about invites or names.

### 2. Storage: hash only

- The database holds `token_hash = SHA-256(token_bytes)` over the 32 decoded bytes (not the text), with the
  same function as session tokens. It is the lookup key (§15, `UNIQUE`).
- No pepper, HMAC or slow hash: the token is 256 uniform bits, so a database reader cannot guess it
  offline — the INV-8 argument for session tokens, unchanged.
- The token itself is never stored, logged (INV-48), put in an error, a URL path or query string, a
  redirect, or a cookie. Nothing is sealed: purpose `0x0103` is untouched and no new purpose is allocated.
- Because only the hash is kept, an invite link is shown exactly once (§4). A lost link is revoked and
  reissued.

### 3. Binding to a login name

Every invite is bound to exactly one login name, normalised by the CRYPTO.md §2 function at issuance, as
§5.9 and the `InviteVerifier` contract already say. Redemption under any other name is refused (§7). This
is what makes invite-only signup enumeration-resistant: a stranger without a valid invite never reaches a
name lookup, and an invite holder can try only the one name the admin chose.

Issuance refuses a name that (a) belongs to an account with a credential, (b) is reserved by an unfinished
signup, or (c) already has an open invite (§9) that has not expired. The admin sees which; admins can list
users anyway (ROADMAP §4.9). An *expired* open invite for the name is closed in the issuance transaction
(`revoked_at_ms = now`, `revoked_kind`/`revoked_admin_id` = the issuer's actor, ADR 0085 §8.1).

### 4. Issuance

- **Who.** An admin signed in to the admin panel under ADR 0085 (on the `RIZZY_ADMIN_LISTEN` listener,
  ADR 0060 §2), or the operator through the server CLI (§11; it ships in phase A, ahead of the admin panel, owner answer 1). Nothing on the public
  listener issues invites; there is no JSON admin API (ADR 0060).
- **Inputs.** Login name (required); lifetime from a fixed list — 1 hour, 24 hours, **7 days (default)**,
  30 days — no "never"; an optional note of at most 200 characters, plain text, for the admin's own
  bookkeeping (e.g. who it is for). The note is admin-only: never sent to the invitee, never logged,
  always rendered escaped (INV-69).
- **Cap.** At most 1,000 open, unexpired invites per instance; issuance beyond it is refused with a
  message. This bounds table growth from a compromised or careless admin session.
- **Output: the invite link**, `<RIZZY_ORIGIN>/#invite=<token>&name=<login_name>`. Both values are in the
  fragment, which browsers do not send to the server, so neither reaches proxy or access logs. The name is
  percent-encoded (`+` as `%2B`, `@` as `%40`) so a `URLSearchParams` reader does not turn `+` into
  a space; the token needs no encoding.
- **Shown once.** The `POST` that issues the invite answers `200` with the page that shows the link — no
  redirect carrying the token — with `Cache-Control: no-store` and the ADR 0028 / ADR 0060 headers
  (`Referrer-Policy: no-referrer`, `ADMIN_CSP`). The link sits in a read-only text field the admin
  selects and copies: `ADMIN_CSP` has `script-src 'none'`, so there is no copy button. Reloading or
  going back does not show it again.

### 5. Delivery: copy link first, email when outbound SMTP exists

- **Ships first: copy link.** The admin copies the link (§4) and delivers it out of band (in person, a
  messenger). This needs nothing beyond this ADR and ADR 0085, and it is how the operator CLI works (§11).
- **Then: email.** The issue form offers "Send by email" only when outbound SMTP is configured. It lands
  only once (a) ADR 0086 is Accepted with SMTP settings, and (b) an Accepted ADR fixes the outbound mail
  sender: the SMTP client crate under CLAUDE.md's dependency rules, the TLS policy, and the name and ctx
  of purpose `0x0103`. If ADR 0086 decides all of (b), that is enough; this ADR does not.
- **The email.** Plain text: the server origin, the link, the login name and the expiry time. No note, no
  HTML, no tracking. The recipient address is used for that one send and is not stored — not in
  `auth_invites`, not in logs — and the row records only `emailed_at_ms`. If the send fails, the page
  shows the link once instead, with the failure, so the token is never lost and never kept.
- **Residual.** An emailed link is a bearer secret in a mailbox. The name binding, the expiry, single use
  and revocation bound it; a reader of the mailbox who redeems first gets the account, and the admin sees
  "redeemed" for an invite the invitee never used.

### 6. Redemption inside the existing signup flow

The token travels once, in `RegisterStartRequest.invite`. `register_finish` carries no token: the invite is
tied to the `account_id` at start and consumed at finish.

**`register_start`, mode `invite`**, in this order:

1. Parse the login name with the §2 function; a malformed name is `invalid_request`, as today (the
   format rule is public and says nothing about other names).
2. Charge the per-source, per-(name, source) and per-name buckets, as for `open` today (§8). A rate-limited
   request answers `rate_limited` whatever its invite.
3. Decode the token (§1); hash it; read the invite row by `token_hash`. Admit only if the row exists, its
   bound name equals the request's name (compared in constant time), `expires_at_ms > now`, and it is
   neither revoked nor redeemed. Otherwise `SignupRefused`. No write happens on a refusal.
4. In one write transaction, re-check the row and reserve: `lock_account` on the request's `account_id`
   and on the invite's current `pending_account_id` if there is one (in byte order, so two starts cannot
   deadlock), then:
   - If the bound name is held by an account that is neither the request's `account_id` nor the invite's
     pending account, answer `SignupRefused` (never `Conflict` in this mode).
   - If the invite is pending for another `account_id` that has no credential (a client that lost its
     state, e.g. a reloaded web vault), delete that uncredentialed `auth_accounts` row and reserve for the
     new id. This relies on no other row referencing an account before `register_finish` commits its
     credential (true of `signup.rs` as read; re-verified at implementation, and the delete is refused if
     any row does). If that account has a credential, the invite was redeemed in between: `SignupRefused`.
   - Set `pending_account_id` and `pending_at_ms` with an `UPDATE … WHERE` that repeats every condition
     of step 3 and the old `pending_account_id`, and require exactly one row; else roll back with
     `SignupRefused`.
   - A repeat for the same name and `account_id` is allowed, as today. An `account_id` already used by
     another name stays `Conflict`: ids are client-chosen random 128-bit values and say nothing about names.

**`register_finish`**, in its existing transaction under `lock_account`:

1. The byte-identical repeat check runs first, as today, so a retried finish after a lost response
   succeeds even though its invite is already redeemed (ADR 0028 "Register finish").
2. Mode `closed`: `SignupRefused`.
3. Mode `invite`: `UPDATE auth_invites SET redeemed_at_ms = now, redeemed_account_id = account WHERE
   pending_account_id = account AND redeemed_at_ms IS NULL AND revoked_at_ms IS NULL AND expires_at_ms >
   now`; exactly one row or roll back with `SignupRefused`. The credential and every other object commit in
   the same transaction, so an invite is redeemed if and only if its account exists.
4. Mode `open`: a pending invite for this account, if any, is consumed the same way; none is required.

Single use follows: the invite names one pending account at a time, a second start moves it, the first
account's finish then finds no row and fails, and redemption is one guarded update in the account's
creation transaction. Revocation or expiry between start and finish wins; the clock is read at both steps.

The domain change: `SignupPolicy::Invite(Box<dyn InviteVerifier>)` becomes a unit variant handled inside
`AuthService` with the store, and the `InviteVerifier` trait is deleted — a `bool` predicate cannot make the
reservation and redemption atomic. This is internal API, not wire.

### 7. Enumeration-resistant rejection

Every invite failure answers the same `SignupRefused`: the same HTTP status, body
(`401` `{"error":"unauthorized"}`, ADR 0028 point 3) and headers, with no `Retry-After`. The causes, all
indistinguishable to the client: no token, a malformed token, an unknown token, a token bound to another
name, an expired, revoked or redeemed invite, a bound name taken in between, an invite moved to another
pending account, and signup mode `closed`.

- **Login names.** In mode `invite` the name lookup happens only after an invite for that exact name was
  admitted, so a caller without one learns nothing about any name (CRYPTO.md §5.9). The holder learns only
  about the name the admin bound.
- **Timing.** Every refusal after step 2 costs one SHA-256 and one indexed read and writes nothing. Mode
  `closed` refuses before the lookup, so `closed` and `invite` may differ in timing; that tells a prober the
  mode, which is not a secret (the web vault always offers the invite field), and nothing about names or
  invites.
- **Logs.** The server logs a refusal at `debug` with a cause category and the `invite_id` when one was
  found — never the token, its hash, the note or the bound name.
- **Messages.** Web vault and `rv` show one text: "This server did not accept the signup. The invite may be
  wrong, used, expired or revoked, or the server is not taking signups. Ask your admin for a new invite."

### 8. Rate limits

- Redemption: the existing three signup buckets (`signup_per_source`, `signup_per_name_source`,
  `signup_per_name`, current defaults) are charged on every `register_start` in modes `invite` and `open`,
  refused invites included, before the invite lookup (§6 step 2). This follows INV-7 literally ("registration
  attempts" get per-(identifier, source) backoff and a per-account cap) and changes today's order, where the
  policy check comes first and a refused invite costs nothing. Residual in §Risks.
- No per-invite bucket: 256-bit tokens cannot be guessed online, and the per-source bucket bounds the load.
- Issuance: no rate limit beyond the 1,000-open cap (§4); the issuer is an authenticated admin or the
  operator.

### 9. Lifecycle: expiry, revocation, cleanup

States, derived from the row: **open** (not pending, not terminal), **pending** (`pending_account_id` set),
**redeemed**, **revoked**, and **expired** (`expires_at_ms <= now` and not redeemed or revoked).

- **Revocation.** An admin (panel) or the operator (CLI) revokes an open or pending invite:
  `revoked_at_ms`, `revoked_kind`, `revoked_admin_id`. It takes effect at once for both start and finish (§6). A redeemed invite
  cannot be revoked; the account exists, and disabling it is ADR 0060's disable-user screen.
- **Worker** (ADR 0010 §5, the "expired auth state" sweep):
  - releases the reservation of an expired or revoked invite whose pending account has no credential, by
    deleting that `auth_accounts` row, so a reissued invite can use the name;
  - deletes invite rows 365 days after they became terminal (`redeemed_at_ms`, `revoked_at_ms`, or
    `expires_at_ms` for one never used). The row is the audit record until then (§12).
- Changing the signup mode does not touch invites.

### 10. Signup mode `invite`

- The mode has three values: `closed`, `invite`, `open`. `RIZZY_SIGNUP` accepts `invite`, which changes
  Accepted text (§10.1).
- **Persistence and precedence** belong to ADR 0086: the mode is its `signup_mode` key, whose §1.1 row reserves
  `invite` for this ADR and whose parser accepts it, from the table and from `RIZZY_SIGNUP` alike, once this
  ADR is Accepted and implemented. ADR 0086's rule decides how `RIZZY_SIGNUP` and the stored value combine.
  This ADR adds only the value.
- **Default `invite`** (owner answer 2). The default moves from `closed` to `invite` in phase A, with a
  release note, matching §5.9's "default is invite-only"; with no invite issued it refuses everyone, like
  `closed`. ADR 0086 §1.1's built-in default for `signup_mode` is `invite`, and §10.1's replacement text
  states it.
- **Admin signup screen.** ADR 0060 §4's signup-mode screen gains the "Invite-only" option, once this ADR is
  Accepted and the code exists, and an Invites screen (§13). Neither lands before ADR 0085 is Accepted
  (ADR 0060 owner answer 5).

#### 10.1 What this ADR supersedes

One Accepted sentence ([ADR 0020](0020-partial-supersession.md) point 9).

1. **[ADR 0048](0048-per-account-storage-quota.md) §1, its last sentence**, the settings list, which ADR 0048's
   table names as its replacement of [ADR 0028](0028-api-v1-http-conventions.md) item 12's settings clause and
   which is therefore the binding text of that clause. Word for word:

   > Settings `RIZZY_ROLES`, `RIZZY_ORIGIN`, `RIZZY_LISTEN` (default `127.0.0.1:8080`), `RIZZY_DATA_DIR` (`/data`), `RIZZY_DATABASE_URL`, `RIZZY_SECRETS_FILE` (`/run/rizzy-secrets/secrets.json`), `RIZZY_SIGNUP` (`closed`|`open`), `RIZZY_TRUSTED_PROXIES`, `RIZZY_LOG_LEVEL`, `RIZZY_WORKER_INTERVAL_SECS`, `RIZZY_MAX_UPLOAD_BYTES`, `RIZZY_ACCOUNT_QUOTA_BYTES`.

   Replacement, in full (with the default `invite`, owner answer 2):

   > Settings `RIZZY_ROLES`, `RIZZY_ORIGIN`, `RIZZY_LISTEN` (default `127.0.0.1:8080`), `RIZZY_DATA_DIR` (`/data`), `RIZZY_DATABASE_URL`, `RIZZY_SECRETS_FILE` (`/run/rizzy-secrets/secrets.json`), `RIZZY_SIGNUP` (`closed`|`invite`|`open`, default `invite`), `RIZZY_TRUSTED_PROXIES`, `RIZZY_LOG_LEVEL`, `RIZZY_WORKER_INTERVAL_SECS`, `RIZZY_MAX_UPLOAD_BYTES`, `RIZZY_ACCOUNT_QUOTA_BYTES`.

Nothing else in ADR 0048 or ADR 0028 changes: ADR 0048 §1's other sentences (the quota setting) and ADR 0028
item 12's other clauses stay binding. [ADR 0066](0066-share-email-otp-verification.md) (Proposed) also
supersedes this settings sentence, quoting ADR 0028's older text; whichever of the two is accepted later
restates the other's change in its replacement.

### 11. Operator CLI (server binary)

Beside the existing `rizzy-vault secrets …` and `backup` subcommands (`rizzy-server/src/cli.rs`,
`admin.rs`):

- `rizzy-vault invite create --name <login> [--expires 1h|24h|7d|30d] [--note <text>]` prints the invite
  link once on stdout and nothing else; nothing reaches the log. `RIZZY_ORIGIN` is required.
- `rizzy-vault invite list` prints id, name, state, times, issuer and note — never a token or hash.
- `rizzy-vault invite revoke <invite_id>`.

They run against the live database (no exclusive lock: one insert or update each; verified at
implementation against `backup`'s non-exclusive open), with the §3/§4 checks, `issued_kind = 'cli'` and
`issued_admin_id = NULL` (`revoked_*` likewise), and the ADR 0085 §9.3 audit row of §12. Someone with shell access to the host already holds the database and the secrets file, so
this adds no new authority. It ships in phase A, ahead of the admin panel (owner answer 1).

### 12. Audit

- The `auth_invites` row is the record: issuer, creation, expiry, email time, pending account, redemption
  (time and account), revocation (time and revoker).
- One structured `info` log line per issue, revoke and redeem: `invite_id`, the actor (ADR 0085 §8.1's kind and
  admin id, or the redeeming `account_id`) and the time. No token, hash, note or email address.
- **Admin audit log:** ADR 0085 §9.3's fixed list carries `invite_issued` and `invite_revoked` (actor `panel` or
  `cli`, from the panel and from `rizzy-vault invite` alike) and `invite_redeemed` (actor `system`,
  `target_account_id` the new account), each with the `invite_id` as detail and written in the transaction of
  the action it records. This is no longer conditional on a later ADR.
- **Per-account security event log:** ADR 0090 (Proposed). Once it is Accepted, the redemption is the new
  account's first entry, naming the issuer; this ADR does not define that entry's format.

### 13. Admin panel screens (ADR 0060 `http/admin_panel/`)

Server-rendered Askama pages, native form `POST`s with ADR 0060's CSRF token and typed, size-limited forms
(`forms.rs`), on the admin listener only, behind ADR 0085's session. Paths are relative to the panel root
ADR 0085 sets:

| Method and path | Does |
|---|---|
| `GET /invites` | List: name, note, state, created, expires, issuer; open and pending first. Escaped. |
| `GET /invites/new` | Form: name, lifetime (radio, default 7 days), note, and "Send by email" with an address field once §5's email phase exists. |
| `POST /invites` | Issue (§3, §4); `200` with the shown-once page, or the form again with an error. |
| `GET /invites/{invite_id}/revoke` | Confirm page. |
| `POST /invites/{invite_id}/revoke` | Revoke; `303` to `/invites`. |
| signup-mode screen (ADR 0060 §4) | Gains the "Invite-only" radio. |

`invite_id` is a random 16-byte id in lowercase hex, separate from the token, so URLs, logs and the list
never carry a secret.

### 14. Clients

- **One link parser**, in `rizzy-client` (`invite_link`), exposed through `rizzy-wasm` and used by `rv`:
  input at most 1 KiB; accepts a full link (`https://…/#…`) or a bare fragment or a bare token; the
  fragment holds only the keys `invite` (43 base64url characters) and optionally `name` (valid under the
  §2 function after percent-decoding), each at most once; anything else fails the whole parse. Returns the
  token as a secret type and the name. Fuzzed (§17).
- **Web vault.** At start-up, before any network request, if `location.hash` parses as an invite fragment,
  the vault removes it with `history.replaceState(null, "", location.pathname + location.search)` and
  opens `SignupView` with the name filled in and the invite held in memory only (no `localStorage`, no
  `sessionStorage`); the field shows "Invite from link" with a "Clear" action instead of the token. A
  fragment that does not parse is removed and ignored. The manual field stays and accepts a token or a
  pasted link. Refusals show §7's text. (L: the vault does not route by fragment today; checked at
  implementation.)
- **`rv`.** `rv signup --invite` keeps the terminal prompt (tokens never go on argv, `args.rs`) and the
  prompt accepts a token or a link. If the link names a login name that differs from `--name`, `rv` stops
  before any network request. The signup restart prompt in `device.rs` gets the same parser.
- `SignupInput` and the wire are unchanged.

### 15. Table `auth_invites`

One migration in each of `migrations/sqlite` and `migrations/postgres`, `NNNN_auth_invites.sql` with the next
free number at implementation. SQLite shown;
PostgreSQL uses `BYTEA`, `BIGINT` and the same checks.

```sql
CREATE TABLE auth_invites (
    invite_id           BLOB    NOT NULL PRIMARY KEY CHECK (length(invite_id) = 16),
    token_hash          BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    login_name          TEXT    NOT NULL CHECK (length(login_name) BETWEEN 1 AND 254),
    note                TEXT    CHECK (length(note) <= 200),
    issued_kind         TEXT    NOT NULL CHECK (issued_kind IN ('panel', 'cli')),
    issued_admin_id     BLOB    CHECK (length(issued_admin_id) = 16),
    created_at_ms       INTEGER NOT NULL CHECK (created_at_ms >= 0),
    expires_at_ms       INTEGER NOT NULL CHECK (expires_at_ms > created_at_ms),
    emailed_at_ms       INTEGER CHECK (emailed_at_ms >= 0),
    pending_account_id  BLOB    CHECK (length(pending_account_id) = 16),
    pending_at_ms       INTEGER CHECK (pending_at_ms >= 0),
    redeemed_at_ms      INTEGER CHECK (redeemed_at_ms >= 0),
    redeemed_account_id BLOB    CHECK (length(redeemed_account_id) = 16),
    revoked_at_ms       INTEGER CHECK (revoked_at_ms >= 0),
    revoked_kind        TEXT    CHECK (revoked_kind IN ('panel', 'cli')),
    revoked_admin_id    BLOB    CHECK (length(revoked_admin_id) = 16),
    CHECK ((pending_account_id IS NULL) = (pending_at_ms IS NULL)),
    CHECK ((redeemed_at_ms IS NULL) = (redeemed_account_id IS NULL)),
    CHECK ((revoked_at_ms IS NULL) = (revoked_kind IS NULL)),
    CHECK ((issued_kind = 'panel') = (issued_admin_id IS NOT NULL)),
    CHECK ((revoked_kind IS NOT NULL AND revoked_kind = 'panel') = (revoked_admin_id IS NOT NULL)),
    CHECK (redeemed_at_ms IS NULL OR revoked_at_ms IS NULL)
) STRICT;
-- At most one open (not redeemed, not revoked) invite per name; issuance closes an expired one first (§3).
CREATE UNIQUE INDEX auth_invites_open_name ON auth_invites (login_name)
    WHERE redeemed_at_ms IS NULL AND revoked_at_ms IS NULL;
CREATE INDEX auth_invites_pending ON auth_invites (pending_account_id)
    WHERE pending_account_id IS NOT NULL;
CREATE INDEX auth_invites_expiry ON auth_invites (expires_at_ms);
```

`issued_kind`/`issued_admin_id` and `revoked_kind`/`revoked_admin_id` follow ADR 0085 §8.1's actor encoding,
the one ADR 0085's audit log and ADR 0086's settings use: `panel` with the acting admin's `admin_id`, or `cli`
with `NULL`; no foreign key, so the record outlives the admin. Account ids carry no foreign key either, so the
record outlives a deleted account until the 365-day purge. The note is personal data an admin typed.

**Backup.** `auth_invites` is in the logical backup: [ADR 0023](0023-logical-backup-format.md)'s `TABLES` gains it
at the end of the `auth_` block (no foreign key, so any position is valid), which bumps the dump's schema
version as any migration does; [ADR 0071](0071-encrypted-db-backup-format.md) only wraps the dump. Inclusion is
per table, not implied by the `auth_` prefix. It is in because the row is the invite's audit record (§12) and
because a restore without it would silently void every open invite. A restore rolls invites back with the
accounts: an invite redeemed after the backup is open again, together with the name its account no longer
holds, and the admin revokes it if it should not be used twice.

### 16. Proposed invariant

**INV-108** (this ADR's number, the next free one after ADR 0085's INV-107; ADR 0086 adds none;
provisional until acceptance, as for the 2026-10-11 batch): "An invite
token is 32 CSPRNG bytes, stored only as SHA-256 and never logged. It admits exactly one signup, under the
one login name it was issued for, before its expiry and unless revoked; it is redeemed in the same
transaction that creates the account. Every refused invite gets the same answer as a closed server, and in
invite-only mode no login-name lookup happens before an invite for that name is admitted."

### 17. Implementation plan

Phases (each a separate PR, in order; phase B and C wait as stated):

| Phase | Waits for | Contents |
|---|---|---|
| A. Mechanism and operator CLI | This ADR Accepted | Migration; `rizzy-domain-auth` `invite` module (issue, list, revoke, redeem; §6 changes in `signup.rs`; `SignupPolicy::Invite` unit variant; trait deleted); worker sweep; `RIZZY_SIGNUP=invite` and the default `invite` (release note); `rizzy-vault invite`; `rizzy-client` `invite_link`, `rizzy-wasm` binding, web vault fragment handling, `rv` prompt |
| B. Admin panel screens | ADR 0085 and ADR 0086 Accepted | `http/admin_panel/invites.rs`, `templates/admin/invites_*.html`, the "Invite-only" option on the signup screen |
| C. Email delivery | ADR 0086 SMTP settings and the outbound-mail decision (§5) | "Send by email", `emailed_at_ms`, fallback to shown-once |

Tests:

- **Known-answer vectors** (`rizzy-domain-auth` tests, beside the existing token tests; CRYPTO.md §15):
  - token bytes `00 01 02 … 1f` → text `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8` → `token_hash`
    `630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd`;
  - 32 zero bytes → `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` →
    `66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925`;
  - refused: 42 and 44 characters, padding `=`, `+` or `/`, a non-canonical last character (`…Hh9`).
  (Vectors computed with Python `hashlib`/`base64` on 2026-10-24; re-check with the Rust code.) There is
  no sealed format, so no sealing KAT.
- **Domain integration tests** (`rizzy-domain-auth/tests/auth/invites.rs`, SQLite and PostgreSQL like the
  existing suite): issue and redeem; refused for each §7 cause, asserting the identical `AuthError` and
  no write; wrong name; expiry at start and at finish; revoke between start and finish; restart with a new
  `account_id` replaces the pending reservation; two concurrent finishes for one invite, exactly one
  account; finish repeat after redemption is success; mode switches `invite` ↔ `open` ↔ `closed` between
  start and finish; the three buckets charged on refused invites; issuance refusals (§3) and the 1,000
  cap; worker release and 365-day purge.
- **HTTP tests** (`rizzy-server`): status, headers and body byte-identical across every §7 cause and mode
  `closed`; the token never appears in captured logs (a log-capture test like the existing secrets ones).
- **Fuzz targets** (`fuzz/fuzz_targets`): `invite_token` (the domain decoder), `invite_link` (the
  `rizzy-client` parser), and `admin_invite_form` (the issue and revoke form parsers in `forms.rs`).
- **Property test**: `invite_link` round-trips every valid (token, name) pair, including names with `+`
  and `@`.
- **Operator CLI tests**: create prints only the link; list never prints a token; revoke of an unknown id.
- **Web e2e** (Playwright, `apps/web/e2e`): opening an invite link fills the name, removes the fragment
  before the first request, and signs up; reusing the link shows §7's text; an axe check of the signup
  view with an invite loaded (`a11y.ts`).
- **Admin panel e2e + axe** (phase B): list, issue form, shown-once page (reload does not show the link),
  revoke confirm; axe on each page; a check that every page carries `ADMIN_CSP`, no `<script>`, and
  `Cache-Control: no-store` on the shown-once page; CSRF refusal on both `POST`s.
- **`rv`**: signup with a link at the prompt, and the name-mismatch stop.

### 18. On acceptance

Documentation edits, made by whoever records the acceptance (not by this draft):
[CRYPTO.md §5.9](../CRYPTO.md#59-account-enumeration) "Registration" and §11.1 step 1 point here for the
token mechanism; THREAT_MODEL §8 gains INV-108 (§16) and §7.19 "I"/"S" names it; [ADR 0048](0048-per-account-storage-quota.md)'s
status line, "Accepted" or whatever it holds then, gains "[ADR 0087](0087-invite-only-signup-tokens.md) (§1 in part)" (ADR 0020
point 9, semicolon-separated after any earlier entry); ADR 0023's `TABLES` gains `auth_invites` (§15);
`config.rs` and `rizzy-proto` `limits.rs` drop "format not specified" / "admin API is M3" in the
implementing PR; README's index status; CLAUDE.md's Accepted list.

## Consequences

### Positive

- Invite-only signup works with no wire change and no new dependency; old clients already send the token.
- Hash-only storage: a database leak exposes no usable invite.
- Name binding removes the registration name oracle for anyone without an invite.
- Single use and revocation are transactional, on both SQLite and PostgreSQL.
- The copy-link path does not wait for SMTP.

### Negative

- A link is shown once; a lost link means revoke and reissue.
- The default changes from `closed` to `invite` (owner answer 2): an instance that never set `RIZZY_SIGNUP`
  starts in `invite` after the upgrade. It refuses everyone until an invite is issued, as before; the release
  note says so.
- The admin must choose the invitee's login name.
- Charging buckets on refused invites changes today's order and lets a prober who knows a bound name slow
  that invitee's signup.
- A second `register_start` with a valid invite takes the reservation from the first, so two people sharing
  one link race; the first to finish wins.

### Risks

- **Bucket DoS on a known name** (§8): exponential backoff, never a lockout (INV-7); the admin can reissue
  under another name.
- **Mailbox compromise** (§5): bounded by binding, expiry, single use and revocation.
- **Unproven parallel ADRs:** the actor columns follow ADR 0085 §8.1 and §10 follows ADR 0086's
  `signup_mode` key; a revision of either while Proposed is absorbed by a revision of this ADR.

## Alternatives considered

- **Unbound invites** (the invitee picks the name): friendlier, but every invite holder gets a rate-limited
  name oracle again, against §5.9's "bound to a login name". Not at v1.0 (owner answer 3); revisit with M10
  org onboarding.
- **Keeping `closed` as the default:** the draft carried a second §10.1 replacement text without a default
  (`RIZZY_SIGNUP` (`closed`|`invite`|`open`)), for the case the owner kept `closed`. Dropped: the owner
  chose the default `invite` (owner answer 2), which behaves like `closed` until an invite is issued.
- **Peppered HMAC or a slow hash of the token:** no gain for a 256-bit uniform secret; one more key to
  rotate. Rejected, as for session tokens.
- **Sealing the token (`0x01` envelope) so it can be shown again:** turns a database plus data-key
  compromise into usable invites, and needs a new purpose. Rejected.
- **Self-contained signed tokens** (expiry and name inside, server signature): needs a signing key, and
  revocation and single use need a table anyway. Rejected.
- **Token also in `RegisterFinishRequest`:** a wire change and a second copy of the secret on the wire, for
  nothing the pending binding (§6) does not already give. Rejected.
- **Token in the query string** (`?invite=`): reaches the server, proxies and logs. Rejected for the fragment.
- **A prefix such as `rvi_`** for secret scanners: helps detect leaks in repositories, which invite links
  rarely reach; costs a format rule. Not adopted; can be added by a later ADR with a version change.
- **Email only:** blocks invite-only signup on the outbound mail decision. Rejected for copy-link first.
- **Multi-use invites** (N signups per link): reopens the name oracle and needs per-use accounting. Out of
  scope; an org feature at M10 if wanted.

## Open questions for the owner

1. **Ship the operator CLI (`rizzy-vault invite …`, §11) in phase A, ahead of the admin panel?** It makes
   invite-only signup usable as soon as this ADR is Accepted, without waiting for ADR 0085, and gives
   headless deployments a path. It is an extra surface beyond the ROADMAP row's wording.
   *Recommendation:* yes. The operator already holds the database and the secrets file.
   **Answered 2026-10-25: yes** (owner answer 1).
2. **Change the default `RIZZY_SIGNUP` from `closed` to `invite`?** Behaviour is unchanged until an invite is
   issued, and it matches CRYPTO.md §5.9. *Recommendation:* yes, in phase A, with a release note.
   **Answered 2026-10-25: yes** (owner answer 2): §10.1's replacement carries `default invite`, and ADR 0086
   §1.1's built-in default for `signup_mode` is `invite`.
3. **Allow unbound invites (the invitee chooses the name) as an admin option?** *Recommendation:* no for
   v1.0 (§Alternatives); revisit with M10 org onboarding. **Answered 2026-10-25: no** (owner answer 3).

No open questions remain.

## References

- [ADR 0060](0060-admin-panel-stack-boundary.md) §1, §2, §4, open question 6, owner answers 3, 5, 6
- [ADR 0085](0085-admin-authentication-bootstrap.md) (admin authentication, Proposed: §8.1's actor encoding, §9.3's audit actions), [ADR 0086](0086-instance-settings-persistence.md) (settings persistence, Proposed: the `signup_mode` key), ADR 0090 (the per-account security event log, Proposed)
- [ADR 0048](0048-per-account-storage-quota.md) §1 (the settings sentence, §10.1); [ADR 0020](0020-partial-supersession.md) point 9; [ADR 0023](0023-logical-backup-format.md) (`TABLES`)
- [Gap review of 2026-10-25](../reviews/2026-10-25-adr-gap-review.md), findings G09-22 to G09-25
- [ADR 0010](0010-server-shape.md) §1, §5; [ADR 0022](0022-server-mode-only.md) §2; [ADR 0011](0011-storage.md);
  [ADR 0028](0028-api-v1-http-conventions.md) point 3 and its "Register finish" row; [ADR 0071](0071-encrypted-db-backup-format.md)
- [ADR 0008](0008-account-recovery.md), [ADR 0058](0058-webauthn-2fa-second-factor.md),
  [ADR 0077](0077-webauthn-rs-integration-fixes.md), [ADR 0082](0082-security-keys-user-presence-only.md):
  the account-side second factors, unaffected; the admin's second factor is ADR 0085's
- [CRYPTO.md](../CRYPTO.md) §2, §5.9, §5.10, §5.11, §8.4, §11.1, §15
- [THREAT_MODEL.md](../THREAT_MODEL.md) §7.19, INV-7, INV-8, INV-48, INV-69, INV-86
- [ROADMAP.md](../ROADMAP.md) §4.8, §4.9
- RFC 4648 §5 (base64url, V); RFC 9807 (OPAQUE, via CRYPTO.md §5.9, L)
