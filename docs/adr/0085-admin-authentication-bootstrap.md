# ADR 0085: Admin authentication: operator accounts, the bootstrap token, mandatory TOTP and admin sessions

- Status: Proposed
- Date: 2026-10-24
- Deciders: project owner
- Milestone: M3 (`rizzy-domain-auth`, `rizzy-storage`, `rizzy-server` `http/admin_panel/` and CLI)
- Supersedes: none

## Context

**The owner's words, verbatim (2026-10-24):** "Admin Authentication & Bootstrap ADR (ADR 0060 Question
5): Specifies session authentication for /admin, initial single-use bootstrap token generation and
redemption on first boot, and mandatory admin 2FA (TOTP / WebAuthn). Currently,
crates/rizzy-server/src/admin_panel/auth.rs is empty awaiting this decision."

(The path in the repository is `crates/rizzy-server/src/http/admin_panel/auth.rs`, and the file does not
exist yet: `http/admin_panel/` holds only `mod.rs`, whose module docs say none of ADR 0060's `auth.rs`,
`forms.rs` or templates is built (V, branch `wip/adr-0085`).)

[ROADMAP §4.9](../ROADMAP.md#49-server-self-hosting--ops-m1-onward), Should, M3: "Admin panel (user
list, disable user, invite-only signup, SMTP settings for notifications)". Same section, Must, M1:
"Rate limiting, lockout/backoff on auth, security headers, CSP on web vault". The panel's SMTP settings
are that M3 row, before v1.0; what ROADMAP §4.8 moves after v1.0 (owner decision of 2026-10-22) is the
M6 mail-receiving work and the `smtp` deployment profile, not outbound notification mail. Nothing in
this ADR depends on mail either way.

[ADR 0060](0060-admin-panel-stack-boundary.md) (Accepted 2026-10-22) fixes what renders the panel and
where it lives, and leaves this mechanism open. Its binding facts for this ADR:
- Server-rendered Askama pages in `rizzy-server` `http/admin_panel/`, served only by a second listener
  on `RIZZY_ADMIN_LISTEN` (default `127.0.0.1:8081`, loopback), never merged into the public router.
  Today that listener answers `404` to everything (V, `http/admin_panel/mod.rs`).
- `ADMIN_CSP` is `default-src 'none'; script-src 'none'; style-src 'self'; img-src 'self'; form-action
  'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'`: **the panel runs no script.**
- No JSON admin API at M3; forms submit natively and a POST re-renders the page.
- Owner answer 5: "Admin login, bootstrap-token redemption and the second factor get their own ADR.
  `admin_panel/auth.rs` stays empty, and no screen behind it merges, until that ADR is Accepted."
  Answers 3 and 6 hold the settings schema and invite-only signup for two sibling ADRs (drafted in
  parallel as 0086 and 0087). This ADR decides only who may log in and how.

[THREAT_MODEL §7.19](../THREAT_MODEL.md#719-admin-panel-and-admin-api-m3) and
[INV-69](../THREAT_MODEL.md#8-security-invariants) (M3) fix the goals: "The admin panel and admin API
authenticate admins separately from user accounts and require a second factor. The first-run bootstrap
token lives in the secrets file (mode 0600), is shown once and is never logged. The admin UI renders every
user-controlled string as text, has its own strict CSP, and rejects cross-site requests (SameSite cookies
plus a CSRF token). Every admin action, including a change to the recovery waiting period, goes into the
affected users' security event log." §7.19 "S" names the threat: "Theft of the first-run bootstrap token
from logs, container output or a world-readable file; password-only admin login." A malicious admin is
[A3](../THREAT_MODEL.md#a3-malicious-instance-admin); this ADR is about outsiders reaching admin powers.

What exists (V, this branch):
- **The bootstrap token.** [CRYPTO.md §5.11](../CRYPTO.md#511-server-side-encryption-not-zero-knowledge)
  lists "the first-run bootstrap token (threat model INV-69)" in the secrets file.
  `ServerSecrets::generate` (`rizzy-domain-auth/src/secrets.rs`) fills it with
  `BOOTSTRAP_TOKEN_LEN` = 32 bytes from the injected CSPRNG at `rizzy-vault secrets init`, with the
  comment "No Accepted ADR fixes it". `admin.rs`: it "is generated into the file by `secrets init` and
  never printed or logged: its only reader is the M3 admin API, which defines how it is shown once".
  `Debug` redacts it. [ADR 0010](0010-server-shape.md) §4: the server "never writes the secrets file.
  State that changes at run time, such as a used bootstrap token, is recorded in the DB."
  [ADR 0047](0047-opaque-secrets-operator-commands.md) step 5 (Accepted): a whole-loss `invalidate`
  mints **no** fresh bootstrap token, because a silent one "would re-arm first-run admin bootstrap";
  its open question 5 leaves the path back to "whatever [the M3 admin panel] provides".
- **TOTP** (`rizzy-domain-auth/src/totp.rs`, [ADR 0008](0008-account-recovery.md),
  [CRYPTO.md §11.15](../CRYPTO.md#1115-totp-m1)): 20-byte secrets sealed as `SERVER_TOTP_SECRET`
  0x0100, ctx `account_id ‖ u32 totp_credential_seq`; two-step enrolment (start, confirm with a code);
  `rizzy-core` `TotpParams::verify` over steps −1, 0, +1 in constant time, accepted only above the last
  accepted step. Table `auth_totp_credentials` references `auth_accounts (id)`.
- **WebAuthn** ([ADR 0058](0058-webauthn-2fa-second-factor.md), [ADR 0077](0077-webauthn-rs-integration-fixes.md),
  [ADR 0082](0082-security-keys-user-presence-only.md); `rizzy-domain-auth/src/webauthn.rs`):
  user-presence-only security keys; "`rp_id` is the host of the configured canonical origin and the only
  allowed origin is that origin itself" (INV-84); a server whose origin host is an IP cannot be a relying
  party. The ceremony needs `navigator.credentials` in the browser, which is script.
- **Rate limits** (`rizzy-domain-auth/src/ratelimit.rs`, [ADR 0010](0010-server-shape.md) §5, INV-7):
  DB-kept buckets keyed by a kind byte and SHA-256 of the counted fields, exponential backoff, "never a
  hard lockout".
- **Argon2id** is pinned (`argon2 =0.6.0`) and wrapped by `rizzy-core` `kdf::argon2id`;
  [CRYPTO.md §6.1](../CRYPTO.md#61-parameter-table) `kdf_id` 1 = m 65 536 KiB, t 3, p 4, "M1 default and
  floor", 32-byte output outside OPAQUE.
- **Server-only purposes** 0x0100–0x0106 are taken or reserved: 0x0100–0x0102 in CRYPTO.md §8.4, 0x0103
  SMTP credentials (INV-86; named `SERVER_SMTP_CREDENTIAL` by ADR 0086, Proposed), 0x0104 (ADR 0066,
  Proposed), 0x0105 (ADR 0071), 0x0106 (ADR 0072, Proposed). The next free id is **0x0107**.
- **Transport.** The server speaks HTTP/1.1 in clear; "TLS is the reverse proxy's" (`server.rs`). ADR
  0060 §2: compose examples do not publish the admin port, and the docs tell operators to reach it "only
  over a tunnel or VPN".
- **Sessions** ([CRYPTO.md §5.10](../CRYPTO.md#510-sessions-after-authentication)): a random 32-byte token,
  only `SHA-256(token)` stored (INV-8). Vault sessions are bearer headers, "never a query parameter or
  cookie" (ADR 0028 item 4, INV-52); the public listener reads no cookie.
- **No per-account security event log exists** in code or in any Accepted ADR: ADR 0075 calls it a
  candidate "once that log has an ADR". ADR 0090 (Proposed, drafted in parallel) is that ADR (§9.4).
- **Migrations:** the number is the next free one at implementation.

ADR 0020 point 5 requires an Accepted ADR for "authentication and session protocols" and for a schema
change before code. This is that ADR for admin login.

## Decision

**Supersedes: none.** It fills ADR 0060 §1's named `auth.rs` and `forms.rs` and answers ADR 0060 open
question 5 and ADR 0047 open question 5. No Accepted text changes.

### 1. Who the admin is, and the trust model

1. **An admin is an operator account, not a vault account.** Admin accounts live in their own tables
   (§8), with their own login names, passwords, second factors and sessions. A vault account never
   becomes an admin and an admin account has no vault, no OPAQUE record, no account key and no device.
   The same login name may exist in both namespaces; nothing links them.
2. **The admin panel is not zero knowledge, and says so.** The server sees the admin password in the
   clear when it is submitted (it is hashed at rest, §2), seals the admin TOTP secret under its own
   `server_data_key` (protection against a DB-only reader, nothing more: CRYPTO.md §5.11's own words),
   and holds every admin session. Whoever controls the server process or holds the secrets file with
   the database can act as admin. That is acceptable because the admin panel guards no vault plaintext:
   ADR 0060 §2 keeps every vault route, session and ciphertext off the admin listener, so a stolen admin
   login gives A3's powers (list, disable, signup policy, SMTP, recovery wait), never decryption.
3. **Host access outranks the panel.** An operator with a shell on the host and the secrets file can
   always regain the panel (§7). The panel's authentication defends against everyone else who can reach
   the admin listener: a tunnel or VPN peer, another local user, a page the admin visits (CSRF, DNS
   rebinding), a misconfigured proxy that exposes the port.
4. **At M3 an instance has at most one admin account.** The bootstrap creates it; `admin reset`
   replaces it. The tables allow several (`admin_id` keys), but adding admins, admin roles and admin
   WebAuthn are later ADRs (open question 2).

### 2. Admin credentials: an Argon2id hash, not OPAQUE

- **Name.** The CRYPTO.md §2 login-name function (ASCII-lowercased, 1–254 bytes of `[a-z0-9._+@-]`),
  applied at bootstrap and at login, before any lookup.
- **Password rules.** `NFC(password)` as UTF-8 (CRYPTO.md §2), the "New passwords" rules (non-empty, no
  unassigned code point), at least 12 code points, at most 1 024 bytes after NFC. A longer or invalid
  value is refused before any hashing.
- **Storage.** `hash = Argon2id(NFC(password), salt, kdf_id = 1, 32)` with a fresh 16-byte random
  `salt` from the injected CSPRNG: CRYPTO.md §6.1 `kdf_id` 1 exactly (m 65 536 KiB, t 3, p 4), through
  `rizzy-core` `kdf::argon2id`, never from numbers held in the DB. The row stores `pw_kdf_id`,
  `pw_salt` (16) and `pw_hash` (32). Verification recomputes and compares with `subtle` in constant
  time. No pepper: a keyed hash would be a new derivation from `server_data_key` for little gain, since
  every reader of the hash who also holds the secrets file has the panel anyway (§1.3).
- **Unknown name.** Login runs the same Argon2id over a fixed dummy salt and answers exactly as a wrong
  password does, so the admin name is not probed for free.
- **Cost bound.** At most 2 admin Argon2id computations run at once on the admin listener (a semaphore,
  128 MiB); a request that cannot get a permit within 5 s gets a plain `503` page and counts against
  its rate-limit buckets anyway.
- **Why not OPAQUE.** (a) ADR 0060's Accepted `ADMIN_CSP` forbids script, and an OPAQUE client in the
  browser is script (the wasm client); a script-free panel was the point of ADR 0060. (b) OPAQUE's
  benefit, the server never seeing the password, buys nothing here: the server is the thing the admin
  administers and already holds every admin power (§1.2). (c) It would need a second `server_setup`
  or a domain-separated use of the vault one, either a new crypto decision. The cost of this choice: a
  password reaches server memory (zeroizing types, never logged) and the transport must protect it
  (§5.1).

### 3. The bootstrap token

1. **Generation stays where it is:** `rizzy-vault secrets init` writes 32 random bytes into the secrets
   file (mode 0600), as implemented. "Generation on first boot" in the owner's words is that step of a
   first installation; the server process itself cannot generate it, because it never writes the
   secrets file (ADR 0010 §4) and the token would otherwise exist only in a log (open question 1).
2. **Arming, TTL.** At start-up, a server running the `api` role whose database holds **no** admin
   account and whose secrets file carries a token inserts `auth_admin_bootstrap(token_hash =
   SHA-256(token), armed_at_ms = now, expires_at_ms = now + 24 h)` if no row has that hash. A row
   already present is left as it is: restarting never extends the window. The token is redeemable only
   while its row is unredeemed and `now < expires_at_ms`. After expiry the way back is `admin reset`
   (§7). The server logs one line, `admin bootstrap armed, expires <RFC 3339 time>`, never the token.
3. **Hashed at rest.** The DB holds only `SHA-256(token)`. The secrets file holds the value, as
   CRYPTO.md §5.11 and INV-69 require; anyone who can read that file already holds every server key.
4. **How it reaches the operator.** Only through `rizzy-vault admin bootstrap-token` (new CLI, §7):
   - It reads the secrets file and the DB (the read-only reader on SQLite, as `backup` does), and
     refuses when an admin account exists, the row is redeemed or expired, or no token is in the file.
   - It writes the token, base64url without padding (43 characters), **only to a terminal**: it refuses
     when stdout is not a TTY (so a pipe, `docker logs`, a CI log or systemd's journal never receives
     it), and prints nothing else to stdout. The expiry time goes to stderr.
   - The server never prints, logs, renders or returns the token, and its `Debug` stays redacted.
   - "Shown once" (INV-69) means: shown only on this explicit request, to a terminal, and dead after one
     redemption. The command cannot stop a file-holder from reading the file again, and does not try.
5. **Redemption is single-use and only on full success.** §6's bootstrap flow verifies the token in
   step 1 without consuming it, and consumes it in step 2 in **one transaction** with creating the admin
   account and its confirmed TOTP credential: `UPDATE auth_admin_bootstrap SET redeemed_at_ms …
   WHERE token_hash = ? AND redeemed_at_ms IS NULL AND expires_at_ms > now` must touch exactly one row,
   and no admin account may exist; otherwise the whole transaction rolls back. Two racing bootstraps:
   the first to confirm wins, the other gets the generic failure page. An abandoned step 1 consumes
   nothing.
6. The token comparison is `subtle` constant time against the in-memory secrets value; a malformed
   field (not 43 base64url characters) is refused before it.

### 4. Mandatory second factor: TOTP at M3

1. **Every admin account has a confirmed TOTP credential**, from the moment it exists: the bootstrap
   cannot finish without one (§6), and no code path removes the last one. There is no password-only
   admin login, no "remember this device" and no admin recovery codes; the break-glass path is §7.
2. **The existing code path, a new purpose.** Secrets, URIs and verification are `totp.rs` and
   `rizzy-core` `TotpParams` unchanged: 20 random bytes, SHA-1, 6 digits, 30 s, steps −1/0/+1,
   accepted only above `last_accepted_step`, which only a fully successful login, account change or
   enrolment advances, in its transaction (§9.2 gives the order). The sealing is CRYPTO.md
   §5.11's construction with a **new server-only purpose `SERVER_ADMIN_TOTP_SECRET` 0x0107** (this
   ADR's number; ADR 0086 uses the reserved 0x0103 and ADR 0087 seals nothing, so no sibling claims
   another id), subkey label `server/admin-totp-secret`, ctx `admin_id (16)
   ‖ u32 totp_credential_seq`. Not 0x0100: its ctx names a vault `account_id`, and a separate purpose
   keeps a DB writer from moving a sealed secret between a vault account and an admin.
   `totp_credential_seq` counts the admin's enrolments from 1, as for accounts.
3. **The enrolment page** shows the secret as base32 text and as the `otpauth://` URI in a read-only
   text field (no QR code at M3: drawing one needs a new crate, and the CSP allows only same-origin
   images). The page is `Cache-Control: no-store`. The secret is never shown again.
4. **WebAuthn for admins is not at M3.** Two Accepted constraints rule it out: `ADMIN_CSP` forbids the
   script that `navigator.credentials` needs (ADR 0060 §1), and the relying-party id is the public
   origin's host (INV-84) while the panel is reached at a loopback or tunnel origin, often an IP literal,
   which cannot be a relying party at all. It needs its own ADR (an admin origin setting, a CSP
   exception for one same-origin script); open question 2.

### 5. Transport, the admin session and CSRF

1. **Supported access.** The admin listener stays plain HTTP. The panel is supported over (a) a
   loopback origin (`http://127.0.0.1:<port>`, `http://[::1]:<port>`, `http://localhost:<port>`),
   directly or through an SSH tunnel or port forward, or (b) HTTPS terminated by a proxy the operator
   runs on a private network. Plain HTTP to a non-loopback address is unsupported: the password and
   TOTP code would cross a network in clear, and browsers drop `Secure` cookies there, so login cannot
   complete (point 6 detects it and says so). Browsers treat loopback origins as secure contexts and keep
   `Secure` cookies on them (L: MDN "Secure contexts" and `Set-Cookie`; checked per browser in the e2e
   suite, §10).
2. **Host check (DNS rebinding).** Every request under `/admin` whose `Host` is not an IP literal, `localhost`
   or a name listed in the new setting `RIZZY_ADMIN_HOSTS` (comma-separated host names, default empty)
   gets a plain-text `421` naming the setting, before routing. A rebinding page on another name can
   then neither read the panel nor post to it. The metrics endpoint that ADR 0060 owner answer 4 puts
   on this listener is outside `/admin` and not affected (scrapers often address it by a service name).
3. **The session.** On a successful login or bootstrap the server issues a fresh random 32-byte token
   (never reused from a pre-auth value: no fixation) and stores `SHA-256(token)` in
   `auth_admin_sessions` with a fresh random 32-byte `csrf_token`, `created_at_ms`,
   `last_seen_at_ms` and `expires_at_ms = created + 8 h`. Cookie:
   `Set-Cookie: rizzy_admin=<43 base64url>; Path=/admin; HttpOnly; Secure; SameSite=Strict`, no
   `Domain`, no `Max-Age` (it dies with the browser session; the server enforces the timeouts).
   - **Idle timeout 15 min, absolute 8 h.** A request after either ends the session (row deleted) and
     redirects to login. `last_seen_at_ms` is written at most once a minute.
   - **At most 5 sessions per admin**; a sixth evicts the oldest.
   - **Bound to the admin listener.** Only the admin router reads the cookie or the table; the public
     listener reads no cookie (INV-52) and has no `/admin` route (ADR 0060 §2). A token presented
     anywhere else is meaningless.
   - **Logout** is a CSRF-protected `POST /admin/logout` that deletes the row and expires the cookie. A
     password change or TOTP re-enrolment deletes every other session of that admin.
4. **CSRF.** Every state-changing request is a `POST` (no `GET` changes state) and passes all of:
   - `Content-Type: application/x-www-form-urlencoded`, body at most 16 KiB, parsed by §9's form parser;
   - `Sec-Fetch-Site`, when present, equal to `same-origin`; `Origin`, when present, not `null`, and
     either with the same host and port as `Host` or with a host listed in `RIZZY_ADMIN_HOSTS` (a TLS
     proxy that rewrites `Host` to the upstream address, as nginx does by default (L), then still works);
   - a hidden `csrf` field equal, in constant time, to the session's `csrf_token` (synchronizer token).
   - **Before login** (bootstrap and login forms) there is no session: the `GET` sets
     `rizzy_admin_pre=<43 base64url random>; Path=/admin; HttpOnly; Secure; SameSite=Strict;
     Max-Age=900` and puts the same value in the hidden field; the `POST` requires both and equal
     (double submit). Both cookies are deleted on success. Residual: a double-submit cookie can be
     planted by a sibling subdomain; the admin origin is loopback or the operator's own host (Consequences, Risks).
   A failed check answers `403` with a fixed page and changes nothing.
5. **Headers.** Every admin answer keeps ADR 0060's `ADMIN_CSP` and common headers and adds
   `Cache-Control: no-store` (pages carry CSRF tokens and, once, a TOTP secret). Successful POSTs answer
   `303 See Other` (post/redirect/get); failures re-render the form with `400`, `401`, `403` or
   `429` and keep no submitted secret in the page.
6. **Cookie refused.** A login or bootstrap `POST` that arrives without `rizzy_admin_pre` gets a fixed
   page: "Your browser did not keep the panel's cookie. Open the panel over a loopback address or
   HTTPS." It never loops silently.

### 6. Flows and routes

All under `RIZZY_ADMIN_LISTEN`; every other path stays the listener's plain `404`.

| Route | Does |
|---|---|
| `GET /admin/` | No admin account: `303` to `/admin/bootstrap`. No valid session: `303` to `/admin/login`. Else the panel's start page (ADR 0060 screens, each gated on 0086/0087 as ADR 0060 says). |
| `GET /admin/bootstrap` | The form: token, admin name, password, password again. `404` once an admin exists. |
| `POST /admin/bootstrap` | Step 1. Checks CSRF, rate limits, the token (not consumed), name and password rules; hashes the password; generates the TOTP secret; stores `auth_admin_enrolments` (pending admin id, name, hash, sealed secret, `expires_at_ms = now + 15 min`) under the SHA-256 of a random enrolment id set as cookie `rizzy_admin_enrol` (same attributes, `Max-Age=900`); renders the TOTP page. |
| `POST /admin/bootstrap/confirm` | Step 2. Checks CSRF and the enrolment cookie, verifies the code against the pending secret, then in one transaction: consumes the token (§3.5), creates the admin and the confirmed TOTP row (`last_accepted_step` set), deletes the enrolment, writes the audit row, creates the session. A wrong code re-renders the TOTP page (at most 5 tries per enrolment, then it is deleted). |
| `GET /admin/login`, `POST /admin/login` | One form: name, password, TOTP code, and an optional login pass (§7). One answer for every failure ("Name, password or code is wrong"), the same page and status, with Argon2id always run once the attempt is admitted; the checks run in §9.2's order. Success: new session, a fresh known-browser cookie (§9.2), `303` to `/admin/`. |
| `POST /admin/logout` | Ends the session. |
| `GET /admin/account` | Change password; replace the TOTP credential. |
| `POST /admin/account/password` | Current password + current code + new password twice. Ends the other sessions. |
| `POST /admin/account/totp`, `POST /admin/account/totp/confirm` | Current password + current code, then a new secret confirmed by a code from it, as bootstrap step 1–2; the old credential is deleted in the confirming transaction, never before. |
| `GET /admin/static/admin.css` | ADR 0060 §3's CSS, the only static file. |

Signup, user, SMTP and recovery-wait screens are ADR 0060's and its siblings'; each requires a valid
session and §5.4's CSRF check, through one extractor in `auth.rs` that every protected handler takes.

### 7. CLI: display and break-glass

Three new `rizzy-vault admin …` subcommands in `crates/rizzy-server/src/admin.rs` and `cli.rs` (the CLI
module ADR 0060 §1 keeps apart from `http/admin_panel`):

- `rizzy-vault admin bootstrap-token`: §3.4. Exit code 0 only when it printed a token.
- `rizzy-vault admin login-pass`: the break-glass for a login flood (§9.2), with the server running.
  Refused when no admin account exists. It writes a fresh 32-byte random pass, base64url without
  padding (43 characters), only to a terminal, by §3.4's rules (refuses a non-TTY stdout, prints
  nothing else to stdout, expiry to stderr), and stores `SHA-256(pass)` in `auth_admin_login_passes`
  with `expires_at_ms = now + 15 min`, replacing any earlier pass. It writes against the live database
  as ADR 0087 §11's `invite` commands do (one insert, no exclusive lock) and appends a
  `login_pass_issued` audit row (actor `cli`). The pass replaces neither the password nor the code: it
  only admits one login attempt past the flood (§9.2). Exit code 0 only when it printed a pass.
- `rizzy-vault admin reset --confirm` (bare flag, as ADR 0047): the break-glass for a lost password,
  a lost authenticator or an expired bootstrap. It takes the exclusive instance lock like `restore` and
  `secrets rotate` (the server must be stopped), then in this order:
  1. writes a fresh 32-byte token into the secrets file through `fsutil::replace_private`, every other
     field unchanged (the CLI may write the file; the server never does);
  2. in one transaction deletes every row of `auth_admin_accounts`, `auth_admin_totp`,
     `auth_admin_sessions`, `auth_admin_enrolments` and `auth_admin_bootstrap`, clears the admin
     rate-limit buckets, and appends an `admin_reset` audit row (actor `cli`).
  A crash between 1 and 2 leaves the old admin working and an unarmed token; running it again finishes.
  It prints no secret; it tells the operator to start the server and run `admin bootstrap-token`.
  This is the explicit operator act ADR 0047 step 5 leaves the bootstrap path to, never automatic.

### 8. Tables

One new migration, `NNNN_auth_admin.sql` for SQLite and PostgreSQL (the next free number at
implementation), in ADR 0011's `auth` domain. Columns are given in the
SQLite dialect of `0001_auth_initial.sql`, `STRICT`, all times `_ms` since the epoch.

| Table | Columns | Notes |
|---|---|---|
| `auth_admin_accounts` | `admin_id` BLOB(16) PK random; `name` TEXT UNIQUE; `pw_kdf_id` INTEGER = 1; `pw_salt` BLOB(16); `pw_hash` BLOB(32); `created_at_ms`; `password_changed_at_ms` | In backups. |
| `auth_admin_totp` | `admin_id` FK CASCADE; `totp_credential_seq` ≥ 1; `data_key_id`; `sealed_secret` (0x0107 envelope); `last_accepted_step`; `created_at_ms`; PK (`admin_id`, `totp_credential_seq`) | In backups. Covered by the data-key re-seal and the start-up "unknown `data_key_id`" check, like `auth_totp_credentials`. |
| `auth_admin_enrolments` | `enrolment_hash` BLOB(32) PK; `kind` (`bootstrap` \| `replace_totp`); `admin_id`; `name` (bootstrap only); `pw_salt`, `pw_hash` (bootstrap only); `totp_credential_seq`; `data_key_id`; `sealed_secret`; `failed_codes`; `expires_at_ms` | Short-lived, not in backups; `worker` deletes expired rows. |
| `auth_admin_sessions` | `token_hash` BLOB(32) PK; `admin_id` FK CASCADE; `csrf_token` BLOB(32); `created_at_ms`; `last_seen_at_ms`; `expires_at_ms` | Not in backups; `worker` deletes expired rows. |
| `auth_admin_bootstrap` | `token_hash` BLOB(32) PK; `armed_at_ms`; `expires_at_ms`; `redeemed_at_ms` NULL; `redeemed_by` `admin_id` NULL | In backups (a restore must not re-arm a redeemed token). |
| `auth_admin_audit` | `seq` INTEGER PK ascending; `at_ms`; `actor_kind` (`panel` \| `cli` \| `system`); `actor_admin_id` NULL (§8.1); `action` TEXT from §9.3's fixed list; `target_account_id` NULL; `detail` TEXT ≤ 256 bytes, fixed per action; `source` TEXT NULL (the client address the HTTP layer resolves; `NULL` for `cli` and `system`) | In backups. Append-only: no code path updates or deletes a row. |
| `auth_admin_known_browsers` | `token_hash` BLOB(32) PK; `admin_id` FK CASCADE; `created_at_ms`; `last_used_at_ms`; `expires_at_ms` (`created + 90 days`) | Not in backups; `worker` deletes expired rows. At most 5 per admin, the oldest evicted. |
| `auth_admin_login_passes` | `pass_hash` BLOB(32) PK; `expires_at_ms`; `failed_attempts` | Not in backups; at most one row; `worker` deletes expired rows. |

Rate limits reuse `auth_rate_limits` with new bucket kinds (§9.2). ADR 0023's `TABLES` list gains the
four backed-up tables in foreign-key order; that bumps the dump's schema version as any migration does.

#### 8.1 One actor encoding for the admin tables of ADRs 0085, 0086 and 0087

Every column pair that records who did something, here and in the sibling drafts, has one shape:

- `<role>_kind` TEXT, `CHECK (<role>_kind IN ('panel', 'cli'))`: `panel` is an admin acting through
  the panel, `cli` the operator acting through a `rizzy-vault` command on the host. `NOT NULL` for a
  role every row has (`actor`, `updated`, `issued`); for a role that may not have happened yet
  (`revoked`), `NULL` exactly when the role's time column is (`revoked_at_ms`), checked in SQL.
- `<role>_admin_id` BLOB NULL, `CHECK (<role>_admin_id IS NULL OR length(<role>_admin_id) = 16)`, and
  `CHECK ((<role>_kind = 'panel') = (<role>_admin_id IS NOT NULL))` (written so that a `NULL` kind
  also requires a `NULL` id): the acting `admin_id` for `panel`,
  `NULL` for `cli` (a host shell is not an admin account and has no id). No foreign key: the value
  outlives `admin reset` and the admin's removal, so who changed what is never erased.

The pairs are `actor_kind`/`actor_admin_id` in `auth_admin_audit`, which alone also allows the kind
`system` (an event the server records for nobody's action, with `NULL` id: `invite_redeemed`);
`updated_kind`/`updated_admin_id` in ADR 0086's `auth_instance_settings`; and
`issued_kind`/`issued_admin_id` and `revoked_kind`/`revoked_admin_id` in ADR 0087's `auth_invites`. No
other encoding (free text such as `operator-cli`, a bare nullable id) is used for an actor.

### 9. Rate limits, audit log, logging, parsing

1. **No hard lockout** (INV-7's rule carried over): nothing an outsider sends may stop the operator
   from logging in with the right password and code. A refusal of everyone would let anyone who
   reaches the listener lock the operator out, leaving only `admin reset`; §1.3's adversaries (a
   tunnel or VPN peer, another local user, a misconfigured proxy) can reach it. So limits that refuse
   before Argon2id apply only to attempts that carry no proof of an earlier success, and a correct
   login always has a lane that a flood cannot fill.
2. **Lanes and buckets** (`ratelimit.rs`, new kinds). The lane is chosen before any Argon2id, by a
   SHA-256 lookup:
   - **Known browser.** Each fully successful login sets
     `rizzy_admin_known=<43 base64url>; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=7776000`
     (90 days), a fresh random 32-byte value whose SHA-256 goes to `auth_admin_known_browsers`; the
     value it arrived with, if any, is deleted (one use per value). A password change, a TOTP
     replacement and `admin reset` delete every known browser of the admin. An attempt with a valid
     cookie is counted only in its own bucket, `admin_login_known` per cookie (5 attempts per 15 min,
     then backoff from 60 s doubling to 1 h), never in the per-source or the global bucket. An unknown,
     expired or malformed cookie value is ignored and the attempt takes the ordinary lane. This is the
     "device cookie" defence against lockout (L: OWASP, "Slow Down Online Guessing Attacks with Device
     Cookies", not re-read for this draft).
   - **Login pass.** A form whose optional pass field matches the live `auth_admin_login_passes` row
     (constant-time compare of the SHA-256) takes the same reserved lane. The pass is deleted by a full
     success, by its expiry, or after 5 failed attempts. It is how the operator logs in from a new
     browser during a flood (§7).
   - **Ordinary** (everything else): `admin_login_source` per client address, 5 attempts per 15 min,
     then backoff from 60 s doubling to 1 h; and `admin_login_global` per instance, 20 failed attempts
     per hour, then backoff from 60 s doubling to 1 h. A blocked ordinary attempt answers `429`
     without running Argon2id. Success clears the per-source bucket, never the global one.
   - **Argon2id cost** stays bounded in every lane: the ordinary lane shares §2's 2 permits, and the
     reserved lane has 1 permit of its own (at most 3 × 64 MiB at once). Only a valid cookie or pass,
     which an outsider does not have, reaches the reserved permit.
   - **Order of the checks** (one answer for every failure, §6): form and CSRF (§5.4); lane lookup;
     the lane's buckets (blocked: `429`); an Argon2id permit (§2); Argon2id over the admin's salt, or
     the dummy salt for an unknown name; the TOTP code, **only when the password matched**; then, only
     on full success, in one transaction: `last_accepted_step` advanced, the session created, the
     known-browser value replaced and the lane's bucket cleared. A wrong password never checks the code
     and never spends a TOTP step. A failure counts in the lane's bucket and, in the ordinary lane, in
     the global one.
   - **Bootstrap:** `admin_bootstrap_source` per client address with the per-source numbers above. There
     is no global bootstrap bucket: the token is compared (§3.6) before any Argon2id, so an attempt
     without the token costs no Argon2id, and a 256-bit token is not guessed online; a flood cannot
     let the 24 h window expire unredeemed.
   - **Account changes:** each TOTP-carrying `/admin/account/*` POST counts in a bucket of its
     session (5 per 15 min, then backoff), never in the per-source or global buckets.
   - Behind a TLS proxy (§5.1(b)) every request may share the proxy's address, so the per-source bucket
     can act like a second global one; the reserved lane is why that is no lockout either. Whether ADR
     0028 item 11's `RIZZY_TRUSTED_PROXIES` applies to the admin listener is open question 4.
3. **Audit log** (`auth_admin_audit`, append-only, never a secret), one row per action, actor per
   §8.1. The list is fixed:
   - this ADR, panel: `bootstrap_redeemed`, `login_succeeded`, `login_failed` (no name stored, so a
     mistyped password never lands there; a `429` writes no row), `logout`, `password_changed`,
     `totp_replaced`;
   - this ADR, CLI: `admin_reset`, `login_pass_issued`;
   - ADR 0060's user screens: one action per screen (for example `user_disabled` with
     `target_account_id`);
   - ADR 0086's settings, panel or CLI (`rizzy-vault settings set|reset`): `setting_changed`, detail the
     key and, for a plain key, `old→new` in canonical text; for a sealed key (`smtp_password`) the key
     and `set` or `cleared`, never the value;
   - ADR 0087's invites, panel or CLI (`rizzy-vault invite create|revoke`): `invite_issued` and
     `invite_revoked`, detail the `invite_id` in hex; and `invite_redeemed` (actor `system`,
     `target_account_id` the new account, detail the `invite_id`), written in the redemption's
     transaction.
   Every CLI command that changes admin state, settings or invites writes its row like the panel does.
   Rate limits bound the failed-login rows. An audit write is in the transaction of the action it
   records: no action without its row. The panel shows the log read-only, newest first, 50 per page.
   Retention and export are a later decision.
4. **Not the per-account security event log.** INV-69's "goes into the affected users' security event
   log" is ADR 0090 (Proposed, drafted in parallel): that log, its rows
   and who reads them. `auth_admin_audit` is the admin's side only. A screen that touches users (disable
   user, the recovery wait) writes ADR 0090's rows as well as its audit row, in the same transaction,
   and merges only once ADR 0090 is Accepted; the login screens here touch no user and do not wait for
   it.
5. **Logs** (INV-48): the access-log line stays ADR 0060's fixed route name `admin`. No log line, error
   message, panic message or `Debug` output carries a password, TOTP secret or code, the bootstrap
   token, a session, pre-auth, enrolment or CSRF token, or a form body. Secret values travel in
   `Zeroizing` types with redacted `Debug`.
6. **Parsing** (CLAUDE.md "untrusted input"): `forms.rs` parses `application/x-www-form-urlencoded`
   into a typed struct per form: a fixed field set, each field once, unknown or duplicate fields
   refused, per-field byte caps (name 254, password 1 024 before NFC, code 6 digits, token, login pass
   and CSRF 43), whole body 16 KiB; the cookie parser takes only `rizzy_admin`, `rizzy_admin_pre`,
   `rizzy_admin_enrol` and `rizzy_admin_known`, each 43 base64url characters, and ignores others. Neither panics. Whether the
   urlencoded decoding is our own code or the `form_urlencoded` crate already in `Cargo.lock` is the
   implementing PR's call under CLAUDE.md's dependency rules.

### 10. Implementation plan

| Step | Crate / files | Content |
|---|---|---|
| 1 | `rizzy-core` | `SERVER_ADMIN_TOTP_SECRET` 0x0107 and the label `server/admin-totp-secret` beside the existing server purposes; KAT vectors (below). No new code path otherwise. |
| 2 | `rizzy-storage` | Migration `NNNN_auth_admin.sql` (both engines), queries, `TABLES` update, engine-parity tests. |
| 3 | `rizzy-domain-auth` | `admin.rs`: `AdminService` with `bootstrap_arm`, `bootstrap_start`, `bootstrap_confirm`, `login` (lanes and check order of §9.2), `session` (check/touch/end), `change_password`, `totp_replace_start/confirm`, `login_pass_issue`, `reset`; reuse of `totp.rs` internals; new rate-limit kinds; clock and RNG injected. |
| 4 | `rizzy-server` | `http/admin_panel/auth.rs` (session extractor, login, bootstrap, account routes, known-browser cookie), `forms.rs` (CSRF, parser), `templates/admin/{login,bootstrap,totp,account,audit}.html`, Host check, `no-store`; `server.rs` arming at start-up; `config.rs` `RIZZY_ADMIN_HOSTS`; `cli.rs`/`admin.rs` `admin bootstrap-token`, `admin login-pass`, `admin reset --confirm`; `worker` cleanup. |
| 5 | docs | Deploy docs: reaching the panel (tunnel or HTTPS), first-boot steps, `admin reset`. |

No new dependency is expected (Argon2id via `rizzy-core`, `subtle`, `sha2`, the TOTP code; Askama
arrives with ADR 0060's implementing PR).

**Tests.**
- **KAT** (CRYPTO.md §15): the `server/admin-totp-secret` subkey derivation for `data_key_id` 1, and a
  0x0107 envelope with a fixed `admin_id`, seq, key and nonce, added to `rizzy-core`'s test vectors;
  an Argon2id `kdf_id` 1 32-byte vector over a fixed password and salt as the admin hash's KAT; a
  negative test that a 0x0100 envelope does not open as 0x0107 and that a swapped `admin_id` fails.
- **Fuzz:** `admin_form` (every form struct from arbitrary bodies) and `admin_cookie` (the `Cookie`
  header parser) in `fuzz/fuzz_targets/`, with the size caps asserted.
- **Unit and integration** (`rizzy-domain-auth`, `rizzy-server` HTTP tests on both engines): token
  single use, expiry, no extension on restart, the confirm race (two enrolments, one admin), redemption
  refused once an admin exists; TOTP replay refused (same step twice); idle and absolute timeouts and
  the 5-session cap with an injected clock; CSRF refusals (missing, wrong, other session's token,
  `Sec-Fetch-Site: cross-site`, foreign `Origin`, `Origin: null`, wrong content type, oversize body);
  `421` on a foreign `Host`; cookie attributes exactly as §5.3; `no-store` on every page; one failure
  page and status for unknown name, wrong password and wrong code; rate-limit backoff and `429` without
  Argon2id; the Argon2id semaphore; `admin reset` crash-and-rerun; the public listener answers `404`
  to every admin route even with a valid admin cookie.
- **No lockout** (§9.1, INV-107): with the global bucket saturated by failed attempts from many
  sources and the 2 ordinary permits held, a correct login from a known browser succeeds, and so does
  one from a new browser carrying a `login-pass`; a forged, expired or reused known-browser value takes
  the ordinary lane and gets `429`; a password change ends every known browser; a wrong password never
  checks the code and leaves `last_accepted_step` unchanged; a flood of wrong bootstrap tokens never
  runs Argon2id. Every audit action of §9.3 is written once, with §8.1's actor columns, for the panel
  and the CLI paths.
- **INV-48 / INV-69 canary:** a run at the most verbose log level through bootstrap, login, password
  change, TOTP replacement and reset, then a search of every log line, HTTP response and DB row for the
  token, the passwords and the TOTP secret (raw, hex, base64, base32); `bootstrap-token` refuses a
  non-TTY stdout.
- **DB inspection:** `pw_hash` is not the password, `sealed_secret` is a 0x0107 envelope, sessions and
  the token appear only as SHA-256.
- **Askama escaping:** an adversarial admin name rendered escaped (ADR 0060 §3's test, extended).
- **e2e** (Playwright, beside `apps/web/e2e/`): first boot (token from the CLI, bootstrap, TOTP code
  computed from the shown secret, landing page), logout and login, wrong-code failure, a cross-site form
  post refused, the cookie kept over `http://127.0.0.1` and `http://localhost` in Chromium and Firefox;
  `expectAccessible` (axe-core, WCAG 2.1 AA, as `a11y.ts`) on the bootstrap, TOTP, login, account and
  audit pages, and keyboard-only completion of the bootstrap.

### 11. On acceptance

- [CRYPTO.md](../CRYPTO.md) §5.11 gains `SERVER_ADMIN_TOTP_SECRET` 0x0107 with its ctx; §8.4 gains its
  row; §4.3's server-subkey row names `admin-totp-secret`; §6.1 notes the admin password hash as a use of
  `kdf_id` 1 with a 32-byte output and a random 16-byte salt.
- [THREAT_MODEL.md](../THREAT_MODEL.md) §8 gains INV-107 (this ADR's number; ADR 0087 is INV-108 and ADR
  0086 adds none, provisional until acceptance as for the 2026-10-11 batch): "Admin passwords are stored
  only as Argon2id `kdf_id` 1 hashes with a random 16-byte salt; admin TOTP secrets only as 0x0107
  envelopes; admin session tokens, known-browser values, login passes and the bootstrap token only as
  SHA-256 in the DB. The bootstrap token is redeemed at most once, only within 24 h of arming and only
  together with a confirmed second factor; no server code path prints, logs or renders it. Failed
  admin logins from any number of sources never refuse a login from a known browser or one carrying
  a login pass." Verified by §10's tests. §7.19 "S" links this ADR.
- ADR 0028 item 12 is not edited; `RIZZY_ADMIN_HOSTS` follows `RIZZY_ADMIN_LISTEN`'s naming, as ADR
  0060 did.
- `secrets.rs`'s "No Accepted ADR fixes it" comment on `BOOTSTRAP_TOKEN_LEN` points here.

## Consequences

### Positive

- The panel gets a login with no script, no new crypto construction and, as far as can be seen now, no
  new dependency: Argon2id at the CRYPTO floor, the existing TOTP code, CRYPTO.md §5.11 sealing, §5.10's
  hashed random tokens.
- The bootstrap token never reaches a log or container output, is useless after one complete bootstrap
  and after 24 h, and only a confirmed second factor spends it.
- A lost admin credential is recoverable by the person who should be able to recover it (shell and
  secrets file) and by nobody else; ADR 0047's open question 5 gets its answer.

### Negative

- The server sees the admin password; OPAQUE's guarantee is given up for the admin (§2's reasons).
- TOTP only at M3: admins who want a security key wait for a later ADR.
- One admin per instance at M3; shared administration means sharing one credential.
- `admin reset` needs the server stopped; an expired bootstrap token (24 h) costs a restart.
- Argon2id at 64 MiB per attempt makes login a little slow and caps concurrency at 2 ordinary
  attempts plus 1 in the reserved lane.
- Two more small tables and a 90-day cookie. A stolen known-browser value gives its holder the
  reserved lane only: it still needs the password and the code, and it is spent by one use.
- During a flood, the first login from a new browser needs host access (`admin login-pass`).

### Risks

- An operator exposes the admin listener publicly, or over plain HTTP on a network. Mitigations: the
  `Secure` cookie fails closed on plain non-loopback HTTP (§5.6 says why), mandatory TOTP and the rate
  limits; the deploy docs say so plainly (ADR 0060 Risks).
- Double-submit pre-auth CSRF is weaker than a server-side token against a cookie planted by a sibling
  host; acceptable for loopback and dedicated hosts, revisit if the panel ever gets a shared parent
  domain.
- A browser that stops keeping `Secure` cookies on `http://localhost` would break loopback login; the
  e2e test catches it, and the answer would be HTTPS on loopback, a later ADR.
- Numbers: this ADR is INV-107 and 0x0107, ADR 0087 is INV-108, and ADR 0086 adds no invariant and
  uses the reserved 0x0103. If another ADR is accepted first and takes one of them, the owner
  renumbers at acceptance (the 2026-10-11 batch precedent).

## Alternatives considered

- **OPAQUE for admins.** Lost on §2's reasons: it needs script, which `ADMIN_CSP` forbids, and protects
  the password from the one party that already holds every admin power.
- **Reuse a vault account flagged as admin.** Lost: INV-69 requires separate credentials, and the
  panel would then read vault sessions, which ADR 0060 §2 keeps off the admin listener.
- **The server generates and prints the token at first start.** Lost: it lands in container output and
  journals, the exact §7.19 "S" threat, and the server cannot write it to the secrets file.
- **No bootstrap token: the CLI creates the admin with a password and TOTP secret.** Simpler, but the
  TOTP secret and password would pass through a terminal and shell history, the CLI would need the TOTP
  confirmation loop, and it contradicts INV-69's Accepted token.
- **A token valid until used (no TTL).** Lost: a forgotten install with an unredeemed token in an old
  backup of the secrets file stays redeemable forever.
- **Signed (HMAC) CSRF tokens.** Lost: a new derivation from `server_data_key` where a stored random
  synchronizer token is enough.
- **A hard lockout after N failures.** Lost: anyone who reaches the listener could lock the operator out.
- **A global bucket that refuses every attempt** (this draft's first version). Lost after the
  2026-10-25 gap review (G09-14): it is a hard lockout in effect, since 20 bad attempts an hour from
  rotating sources keep the operator's own attempts at `429` before the password is checked.
- **Only a concurrency limit, no refusing global bucket.** Lost: a flood keeps both Argon2id permits
  busy and the operator's attempt times out at `503`, again a lockout; the reserved lane is still needed.
- **Exempt loopback sources.** Lost: another local user and a proxy on the host are §1.3's
  adversaries, and behind a local proxy every request is loopback.
- **Admin recovery codes.** Lost: the operator has `admin reset`, and recovery codes would be one more
  long-lived secret to protect.

## Open questions for the owner

1. **Is "generation on first boot" satisfied by `secrets init` generating the token, with the server
   arming it (24 h TTL) at its first start?** The server cannot write the secrets file (ADR 0010 §4)
   and must not print the token (INV-69). *Recommendation:* yes, as §3.
2. **WebAuthn for admins (and more than one admin) in a later ADR, TOTP-only at M3?** Admin WebAuthn
   needs a script exception to ADR 0060's `ADMIN_CSP` and an admin relying-party origin distinct from
   INV-84's public one. *Recommendation:* yes, TOTP-only at M3; draft the WebAuthn ADR when the panel
   ships, together with adding admins.
3. **INV-69's per-user security event log** is ADR 0090 (Proposed). *Recommendation:* accept it before
   the disable-user and recovery-wait screens merge (§9.4); the login screens here do not wait for it.
4. **Does ADR 0028 item 11 (`RIZZY_TRUSTED_PROXIES`, `X-Forwarded-For`) apply to the admin listener,
   or does it need its own `RIZZY_ADMIN_TRUSTED_PROXIES`?** It decides the client address of the
   per-source bucket and the audit `source` behind §5.1(b)'s proxy. *Recommendation:* a separate
   setting, default empty (the peer address), so trusting a proxy for the admin listener never makes
   the public listener trust it; §9.2's reserved lane keeps either choice from locking the operator out.
5. **The known-browser cookie: 90 days, 5 per admin, one use per value?** *Recommendation:* yes; a
   shorter life only sends the operator to `login-pass` more often during a flood.

## References

- [ADR 0060](0060-admin-panel-stack-boundary.md) (§1, §2, §3, owner answers 3, 5, 6),
  [ADR 0010](0010-server-shape.md) (§1, §4, §5), [ADR 0011](0011-storage.md),
  [ADR 0020](0020-partial-supersession.md) (point 5), [ADR 0023](0023-logical-backup-format.md),
  [ADR 0028](0028-api-v1-http-conventions.md) (items 4, 12), [ADR 0008](0008-account-recovery.md),
  [ADR 0047](0047-opaque-secrets-operator-commands.md) (step 5, open question 5),
  [ADR 0058](0058-webauthn-2fa-second-factor.md), [ADR 0077](0077-webauthn-rs-integration-fixes.md),
  [ADR 0082](0082-security-keys-user-presence-only.md), [ADR 0075](0075-session-listing-and-ending.md).
- [CRYPTO.md](../CRYPTO.md) §2, §5.9, §5.10, §5.11, §6.1, §8.4, §11.15, §15.
- [THREAT_MODEL.md](../THREAT_MODEL.md) §7.19, A3, INV-7, INV-8, INV-48, INV-52, INV-69, INV-84, INV-86.
- [ADR 0086](0086-instance-settings-persistence.md) and [ADR 0087](0087-invite-only-signup-tokens.md) (Proposed siblings: §8.1's
  actor columns, §9.3's actions), ADR 0090 (Proposed: the per-account security event log).
- [Gap review of 2026-10-25](../reviews/2026-10-25-adr-gap-review.md), findings G09-14 to G09-19 and G09-24.
- [ROADMAP.md](../ROADMAP.md) §4.8 (post-v1.0 note), §4.9.
- RFC 9106 (Argon2), RFC 6238 (TOTP), RFC 6265 and draft-ietf-httpbis-rfc6265bis (`SameSite`,
  `Secure` on loopback) (L, not re-read for this draft); W3C Fetch Metadata (`Sec-Fetch-Site`) (L);
  MDN "Secure contexts" (L); OWASP CSRF Prevention and Session Management cheat sheets (idle/absolute
  timeouts, double-submit weaknesses) (L); NIST SP 800-63B (re-authentication intervals) (L).
