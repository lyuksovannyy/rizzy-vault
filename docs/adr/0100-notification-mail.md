# ADR 0100: Notification mail: the account email address, the `worker` sender and its outbox, and the recovery notices of ADR 0008 decision 5

- Status: Proposed
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M3 (`rizzy-proto`, `rizzy-storage` migration and backup `TABLES`, `rizzy-domain-auth`, `rizzy-server` (`api`, `worker`), `rizzy-client`/`rizzy-wasm`, web vault, extension, `rv`)
- Supersedes: on acceptance, in part: [ADR 0028](0028-api-v1-http-conventions.md) (item 1, first sentence, in part). §1 names the part ([ADR 0020](0020-partial-supersession.md) point 9).

## Context

**Trigger.** The ADR gap review of 2026-10-25 ([docs/reviews/2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md)) lists as major gap **M2**: "**Outbound notification mail and an account email address.** | ADR 0008 decision 2 (recovery without 2FA relies on it), CRYPTO §11.9, ROADMAP M3. The only design (0066) is Proposed, post-v1.0, and keeps the SMTP password unsealed, against INV-86." Raw findings G01-10, G05-10, G10-16 and G07-1 ([docs/reviews/2026-10-25-raw/](../reviews/2026-10-25-raw/)). The owner said "start" on 2026-10-25, after the review; this ADR is that work for M2.

**The evidence, quoted.**

- [ADR 0008](0008-account-recovery.md) (Accepted, Partially superseded by ADR 0022 at point 7 only) decision 5: "A valid code opens a *pending* recovery, and every enrolled device and the account email (if mail is configured) are notified." Point 6 step 7: "The server ends every session and notifies all devices and the account email." Owner decision 2: "**Require the current 2FA factor during recovery** → No. Recovery is the last resort, often after losing the phone that holds the TOTP. Notification of every enrolled device and the account email is the safeguard."
- G01-10: "For an account with no enrolled device (web-vault-only, the M1 norm for many users), the only safeguard against a kit thief during the 72 h wait is the email that nobody can send: no Accepted ADR defines outbound mail, its trigger or its content, and none defines an 'account email' attribute to send it to."
- [ADR 0045](0045-recovery-pending-notification.md) (Accepted) Consequences: "the email half of ADR 0008 decision 5 stays a separate, unbuilt channel this ADR does not touch." Its pull-based notice reaches a device only when that device talks to the server.
- [CRYPTO.md §11.9](../CRYPTO.md#119-recovery-with-the-emergency-kit) step 2: "It notifies every enrolled device, and the account email if the server has mail configured. *Mechanism today* … there is no push and no mail channel yet." Step 6: "notifies every device and the account email that 'this account was recovered'."
- G05-10: "no Accepted ADR defines the sender, the account-email field, or its enumeration review; the only plan is an Open question in Proposed ADR 0086, and ROADMAP's M3 'SMTP settings for notifications' admin row has no ADR behind it."
- G10-16: "Notification mail: M3 promises it, and Accepted ADR 0008 relies on it, but no Accepted ADR defines the sender."
- G07-1: "SMTP password in `RIZZY_SMTP_URL` contradicts Accepted ADR 0060 answer 2 / INV-86." [ADR 0066](0066-share-email-otp-verification.md) (Proposed, share recipients, after v1.0) widens ADR 0028 item 12 so that "`RIZZY_SMTP_URL` (`smtp://`, `smtps://` or `smtp+starttls://`, with an optional user and password)" carries the relay password, while [ADR 0060](0060-admin-panel-stack-boundary.md) (Accepted) answer 2 says "Yes, SMTP credentials reuse Algorithm 0x01 under the server-only purpose `0x0103` (INV-86)", and [THREAT_MODEL](../THREAT_MODEL.md#8-security-invariants) INV-86 says "An SMTP password is sealed at rest with CRYPTO.md §5.11's Algorithm 0x01 server-side envelope, under the server-only purpose `0x0103`".

**What already exists and is reused, not redefined.**

- [ADR 0010](0010-server-shape.md) §1 (Accepted) gives the `worker` role the outbound column "SMTP relay for notification mail, if configured (M3)" and `api` the outbound column "none"; one active `worker` per database (§2, advisory lock).
- [ADR 0086](0086-instance-settings-persistence.md) (Proposed) §1.1 defines the `smtp_host`, `smtp_port`, `smtp_tls` (`starttls` | `tls`, "no plaintext mode; certificate verification always on"), `smtp_username`, `smtp_from` and sealed `smtp_password` rows of `auth_instance_settings`, §5 the `SERVER_SMTP_CREDENTIAL` envelope (purpose `0x0103`, ctx bound to host, port, TLS mode and user), §3 live reload, and §7: "the `smtp_*` keys, `SERVER_SMTP_CREDENTIAL` and the SMTP screen are fixed by this ADR but are implemented only together with the Accepted ADR that defines outbound notification mail." Its open question 4 recommends "a short notification-mail ADR at M3 for ADR 0010's `worker` outbound … reading only these rows". This is that ADR.
- [ADR 0090](0090-per-account-security-event-log.md) (Proposed) §3 event kinds: 13 `recovery_started`, 14 `recovery_cancelled`, 15 `recovery_session_opened`, 16 `recovery_completed`, and the alert-class kinds 4, 8, 11, 12, 24 and 27. Its rule "Nothing before KE3 … codes 13 and 15 only after `H_rec` matched" is the enumeration rule this ADR reuses.
- [CRYPTO.md §5.9](../CRYPTO.md#59-account-enumeration): login resists enumeration; registration is an oracle and is rate-limited. [CRYPTO.md §5.11](../CRYPTO.md#511-server-side-encryption-not-zero-knowledge): the server-side sealing construction. [ADR 0028](0028-api-v1-http-conventions.md) item 3: the closed error-code table; item 1: the endpoint list.
- [ROADMAP §4.9](../ROADMAP.md#49-server-self-hosting--ops-m1-onward), Should, M3: "Admin panel (user list, disable user, invite-only signup, SMTP settings for notifications)". ROADMAP principle 5: "Email is a module, not the core. The password manager must be fully usable with the mail subsystem disabled"; INV-43: "The vault builds and runs fully with the mail subsystem disabled."
- The workspace already ships `rustls` =0.23.46 (`ring`), `tokio-rustls` =0.26.6 and `webpki-roots` =1.0.10 (Cargo.toml, V; the comment there scopes `tokio-rustls` to `rizzy-cli` today).

**Forces.** The mail is the only out-of-band warning a web-only user gets during the recovery wait, so it must be reliable (retries, crash safety) but it is advisory and must never become a way in (ADR 0008 point 8: "No email-based reset of anything … Email is only a notification channel"). A DB-only reader must not gain the SMTP password (INV-86) and should not gain the address-to-account link. Mail must not open an enumeration oracle. A mail must carry no secret and no link, so a phishing mail that contains a link is recognisably not ours. An instance without SMTP must keep working, with the recovery wait unchanged.

## Decision

### 1. What this ADR supersedes

The part below is named under ADR 0020 point 9. Nothing else in any Accepted ADR changes.

- **[ADR 0028](0028-api-v1-http-conventions.md) item 1, first sentence, in part** (as already superseded in part by [ADR 0052](0052-icon-proxy-role.md), [ADR 0075](0075-session-listing-and-ending.md) §1 and [ADR 0081](0081-multiple-vaults-personal-and-shared.md) §0 point 5). The replacing text:

  > "The endpoints of the `rizzy-server` `http/api.rs` module table, which is the authoritative list, under `/api/v1/`, grouped by resource — the nine of the first release (`register`, `login`, `device-auth`, `account`, `devices`, `healing`, `recovery`, `totp`, `vault`) and each resource an Accepted ADR adds, among them `sessions` (ADR 0075), `directory` (ADR 0081) and `account-email` (ADR 0100) — verb last (`start`, `finish`, `commit`, `list`, `remove`, …), plus one endpoint outside `http/api.rs`: `POST /api/v1/icons/fetch`, resource `icons`, verb `fetch`, served by the `icons` role's own router and listener, never combined with `api` or `web` (ADR 0010 §2; ADR 0052)."

  The rest of item 1 stands: `POST` for everything. If [ADR 0090](0090-per-account-security-event-log.md) is accepted first, its replacing sentence and this one are merged at acceptance into one sentence naming `security-events` and `account-email`; neither ADR's other text changes. Item 3 is not superseded: every refusal here uses an existing code.
- **Not superseded, and why.**
  - ADR 0008 decision 5, point 6 step 7, point 8 and owner decision 2: this ADR is the "account email (if mail is configured)" they name. Email stays a notification channel only; nothing here resets, unlocks or authenticates anything.
  - ADR 0045 and INV-70: unchanged. The pull notice stays the device channel; mail is added next to it.
  - ADR 0010 §1: the `worker` outbound cell already allows exactly this; `api` still never dials SMTP.
  - ADR 0028 item 12: no new `RIZZY_*` setting. SMTP configuration is ADR 0086's rows only; no secret enters the environment.
  - ADR 0023: `TABLES` gains one table (§4.1) through a migration, which ADR 0023 provides for. The outbox (§5.1) is transient delivery state, kept out of `TABLES` in the same way ADR 0023 keeps out sessions, login states and device challenges.
  - ADR 0011 rule 5: both tables are `auth_` tables owned by `rizzy-domain-auth`; `worker` calls functions that crate exports, never raw SQL.
- **ADR 0002 point 5.** Every wire change is additive: one new resource, one new optional `AccountView` field, one new optional field in the `recovery/start` success response. An older client never calls the new endpoints and ignores the new fields (`AccountView` already ignores unknown fields; the implementation checks the `recovery/start` response type does too, and if it does not, this ADR's field waits for the next minimum-version raise).

**Dependencies.** The SMTP half (§5–§7) is implemented only after ADR 0086 is Accepted (its §7 waits for this ADR; this ADR reads its rows). The account-email half (§3–§4) needs nothing but this ADR. The security-event entries of §3.5 need ADR 0090 Accepted; until then the address change is still mailed to the old address.

### 2. Which events send mail (M3)

A mail is queued **in the same database transaction** as the state change that triggers it (§5.2), only for an account that has a **verified** address (§3), and only when mail is configured at that moment (§7). Each trigger is defined by the domain function, so it does not depend on ADR 0090 being implemented; the 0090 kind is the cross-reference.

| Template | Name | Tier | Trigger (same transaction as…) | ADR 0090 kind | Dedupe `event_ref` |
|---|---|---|---|---|---|
| 1 | `email_verify` | E | `account-email/start` storing a pending address; sent to the **pending** address | — | pending version (§3.2) |
| 2 | `email_changed` | E | `account-email/finish` replacing an existing verified address; sent to the **old** address | 29 (provisional) | address version |
| 3 | `email_removed` | E | `account-email/remove` deleting a verified address; sent to the **removed** address | 30 (provisional) | address version |
| 10 | `recovery_started` | R | `recovery_start` opening a pending recovery | 13 | `opened_at_ms` |
| 11 | `recovery_cancelled` | R | `recovery_cancel` closing a pending recovery | 14 | `opened_at_ms` |
| 12 | `recovery_session_opened` | R | the **first** successful `recovery_complete` of a pending recovery (repeats dedupe away) | 15 | `opened_at_ms` |
| 13 | `recovery_completed` | R | `commit_change` over a recovery-only session closing the pending recovery | 16 | `opened_at_ms` |
| 20 | `device_enrolled` | S | a certificate stored for a new durable device id | 4 | `state_seq` |
| 21 | `credentials_changed` | S | `commit_change` with `password_bumped`, not over a recovery-only session (template 13 covers that) | 8 | `state_seq` |
| 22 | `recovery_code_changed` | S | `commit_change` with `RecoveryTransition::NewCode`, not over a recovery-only session | 11 | `state_seq` |
| 23 | `recovery_disabled` | S | `commit_change` with `RecoveryTransition::Disabled` | 12 | `state_seq` |
| 24 | `recovery_wait_shortened` | S | an admin change that lowers the account's effective recovery wait (ADR 0086 §4) | 24 (alert case only) | `at_ms` |
| 25 | `second_factor_reset_by_admin` | S | the admin second-factor reset | 27 | `at_ms` |

- **Tier R** (recovery) is the M3 minimum and is never suppressed by a per-account cap (§6). **Tier E** (address) is bounded by the endpoint limits of §6. **Tier S** (security alerts) is subject to the per-account cap. A template whose trigger path does not exist yet (24 and 25 need the admin panel of ADRs 0085/0086) ships with that path. Codes 4–9, 14–19, 26–99 are unassigned; 100–199 are reserved for share mail (§10); a new template or tier needs an Accepted ADR.
- **No per-kind opt-out at M3.** The only way to stop mail is to remove the address (§3.4) (open question 3).
- **Enumeration (CRYPTO §5.9).** No mail and no outbox row is ever written for an unauthenticated request that has not passed KE3 or the `H_rec` comparison: unknown login names, wrong passwords and wrong recovery codes write nothing, exactly as ADR 0090's "Nothing before KE3" rule. The enqueue is an insert inside a transaction those flows already run only on success, and the success responses already differ from the failure response, so it adds no oracle. The address is never a lookup key, never unique across accounts (two accounts may share one), and no endpoint answers "address taken", so there is no address oracle.

### 3. The account email address

#### 3.1 Optional, one per account, never a credential

An account has **zero or one verified address** and **zero or one pending address**. Neither is required at signup or ever. The address is used only as a mail recipient: it is never a login name, a lookup key, a second factor, a recovery path or an input to any key. It is never shown to a recovery-only session, so a kit thief does not learn which mailbox to attack.

#### 3.2 Address grammar (version 1)

ASCII only at M3 (no SMTPUTF8). `local@domain`, total 6–254 bytes. `local`: 1–64 bytes, RFC 5322 dot-atom: `atext` characters (`A–Z a–z 0–9 ! # $ % & ' * + - / = ? ^ _ ` { | } ~`) and single dots, not first or last (no quoted strings, no comments). `domain`: the `smtp_host` DNS-name rule of ADR 0086 §1.1 (ASCII-lowercased A-labels, no trailing dot) with at least two labels; IP literals refused. Normalisation: the domain is lowercased, the local part is kept byte-for-byte (L: RFC 5321 leaves local-part case to the receiving host). The parser is the one function both endpoints, the outbox renderer and the fuzz target `mail_address` use; anything else is `invalid_request`.

#### 3.3 Verification by code, not by link

1. `POST /api/v1/account-email/start {address}`. Needs a **fresh OPAQUE session** (`FRESH_SESSION_MS`, 5 minutes, the existing rule; a web vault login or a native re-authentication); a stale OPAQUE session or a device session gets `403 fresh_session_required` (the domain's existing freshness answer); a recovery-only session gets `401 unauthorized`, refused before the domain as on the existing "OPAQUE or device" rows (`http/api.rs` module docs). Mail not configured (§7): `400 invalid_request`. Limits (§6) exceeded: `429 rate_limited`. On success, in one transaction: the server draws an **8-digit decimal code** uniformly from the OS RNG (rejection sampling over `u32`), replaces any pending address, sets `pending_expires_at_ms = now + 30 min`, `pending_attempts = 0`, increments `pending_version`, and queues template 1 to the pending address. Response `{"pending_expires_at_ms": u64}`. Starting with the address already verified is allowed (a resend to check delivery) and changes nothing until finished.
2. `POST /api/v1/account-email/finish {code}`. Any OPAQUE or device session of the account (the code proves the mailbox; the start already proved the password). `code` is exactly 8 ASCII digits, else `invalid_request`. No pending address, or expired: `409 state_conflict`. Wrong code: `pending_attempts + 1` and `400 invalid_request`; the fifth wrong code clears the pending address in the same transaction and answers `state_conflict`. The comparison is constant-time over the 8 bytes. Right code, in one transaction: the pending address becomes the verified address, `address_version + 1`, `verified_at_ms = now`, the pending columns are cleared, and if a **different** verified address existed, template 2 is queued to the old address (when mail is not configured nothing is queued, and the change still happens). Response `{}`.
3. The verified address stays in force until a new one is finished; a pending change never stops notices to the current address.

#### 3.4 Removal and change notices

- `POST /api/v1/account-email/remove {}`: fresh OPAQUE session only (as §3.3 step 1). Clears the verified and pending addresses in one transaction, `address_version + 1`, and queues template 3 to the removed address when one was verified and mail is configured. Works when mail is not configured (nothing is sent). Idempotent: no address is `{}` too.
- **Why a fresh session for start and remove:** redirecting or deleting the address is the first step of an attacker who wants the later recovery to go unnoticed; a stolen bearer or device token alone must not do it. Anyone who has the password and Secret Key can already do worse, so no delay is added.
- **The old address is told** (templates 2 and 3); the new address is never named to the old one.

#### 3.5 Security events (ADR 0090, provisional)

If ADR 0090 is Accepted, three kinds are appended to its §3 table, codes **next free at acceptance** (28, 29, 30 if 0090 is accepted as drafted): `notification_email_set` (info; first verified address), `notification_email_changed` (alert), `notification_email_removed` (alert); actor of the request; no address in the log (the log is for the account's sessions, but it is retained and exported with the account and needs no address to be useful).

#### 3.6 `AccountView` field

`AccountView` gains the optional `notification_email` object, returned to the account's OPAQUE and device sessions, **never** to a recovery-only session:

```json
{"mail_configured": true, "address": "a@example.org", "pending_address": null, "pending_expires_at_ms": null}
```

`mail_configured` is §7's test at request time. Like `pending_recovery` it is advisory, unsigned and server-set (INV-70's trust class): UI input only.

### 4. Storage of the address

#### 4.1 Table `auth_account_email` (in `TABLES`)

```sql
CREATE TABLE auth_account_email (
    account_id            BLOB    NOT NULL PRIMARY KEY REFERENCES auth_accounts (id) ON DELETE CASCADE,
    address_sealed        BLOB,              -- SERVER_ACCOUNT_EMAIL, kind 1; NULL = no verified address
    address_version       INTEGER NOT NULL DEFAULT 0,
    verified_at_ms        INTEGER,
    pending_sealed        BLOB,              -- kind 2: address and code; NULL = none pending
    pending_version       INTEGER NOT NULL DEFAULT 0,
    pending_expires_at_ms INTEGER,
    pending_attempts      INTEGER NOT NULL DEFAULT 0,
    data_key_id           INTEGER NOT NULL,  -- server_data_key that sealed the non-NULL blobs
    start_window_ms       INTEGER NOT NULL DEFAULT 0,
    start_count           INTEGER NOT NULL DEFAULT 0,
    last_start_ms         INTEGER NOT NULL DEFAULT 0
);
```

(PostgreSQL: `BYTEA` and `BIGINT`.) A row with both blobs NULL may be deleted by the writer that empties it. The migration number is the **next free at implementation**.

#### 4.2 Sealed at rest: `SERVER_ACCOUNT_EMAIL`

The existing CRYPTO §5.11 construction, unchanged; this section names a purpose and fixes ctx and plaintext, as ADR 0086 §5 does for the SMTP credential.

- **Purpose** `SERVER_ACCOUNT_EMAIL`, number **next free at acceptance** in the server-only range `0x0100–0x01FF`; subkey label `server/account-email`; current `server_data_key`, its id recorded; Algorithm 0x01; no client allow-list contains it.
- **ctx** (CRYPTO §2 encodings): `u8 kind ‖ u16 len(account_id) ‖ account_id`, then for kind 3 also `‖ mail_id` (16 bytes). Kinds: 1 verified address, 2 pending address, 3 outbox payload (§5.1). A DB writer cannot move a blob to another account, another role or another mail.
- **Plaintext, format 1:** kind 1: `u8 1 ‖ str(address)`; kind 2: `u8 1 ‖ str(address) ‖ str(code)`; kind 3: `u8 1 ‖ str(recipient) ‖ str(code)` (`code` empty except template 1). Framed and padded exactly as ADR 0086 §5 frames `SERVER_SMTP_CREDENTIAL` (following the owner's answer to ADR 0086 open question 3). A reader refuses any other format byte.
- **Why seal:** the server needs the address only to send, never to search, so it can be sealed; a DB-only reader (a leaked dump, a DB host) then learns which accounts have an address, not the address. Restoring a backup needs the same `server_data_key` the TOTP secrets and SMTP credential already need.
- **Known-answer vector:** one per kind, added to CRYPTO §15's server-sealing vectors.

### 5. The sender

#### 5.1 Table `auth_mail_outbox` (not in `TABLES`)

```sql
CREATE TABLE auth_mail_outbox (
    mail_id          BLOB    NOT NULL PRIMARY KEY,   -- 16 random bytes
    account_id       BLOB    NOT NULL REFERENCES auth_accounts (id) ON DELETE CASCADE,
    template         INTEGER NOT NULL,               -- §2
    template_version INTEGER NOT NULL,               -- 1 for every M3 template
    tier             INTEGER NOT NULL,               -- 1 R, 2 E, 3 S
    event_ref        INTEGER NOT NULL,               -- §2 dedupe column
    at_ms            INTEGER NOT NULL,               -- the event time shown in the mail
    value_ms         INTEGER,                        -- template 10: available_at_ms; 1: pending_expires_at_ms
    payload_sealed   BLOB,                           -- kind 3; NULL once settled
    data_key_id      INTEGER NOT NULL,
    state            INTEGER NOT NULL DEFAULT 0,     -- 0 queued, 1 sent, 2 failed
    attempts         INTEGER NOT NULL DEFAULT 0,
    next_attempt_ms  INTEGER NOT NULL,
    lease_until_ms   INTEGER NOT NULL DEFAULT 0,
    expires_at_ms    INTEGER NOT NULL,
    settled_at_ms    INTEGER,
    last_error       INTEGER,                        -- §5.4 class
    UNIQUE (account_id, template, event_ref)
);
CREATE INDEX auth_mail_outbox_due ON auth_mail_outbox (state, tier, next_attempt_ms);
```

The login name is read from `auth_accounts` at render time. The migration number is the **next free at implementation**. The outbox is excluded from `TABLES`: a restored instance never sends a mail queued before the dump.

#### 5.2 Enqueue

`rizzy-domain-auth` exposes `mail::enqueue(tx, account_id, template, event_ref, at_ms, value_ms, now)`, called inside the trigger's transaction. It writes nothing when mail is not configured (§7), when the account has no verified address (template 1 uses the pending one), or when the per-account cap refuses (§6). An insert that hits the `UNIQUE` key is ignored (`ON CONFLICT DO NOTHING`): that is the idempotency rule, so a repeated `recovery_complete` yields one template-12 mail per pending recovery. `expires_at_ms`: template 1 = `pending_expires_at_ms`; Tier R and templates 2–3 = `now + 7 days`; Tier S = `now + 24 h`. `next_attempt_ms = now`. When `worker` is co-resident, `api` publishes a `rizzy-bus` wake-up after commit; correctness never depends on it (same shape as ADR 0066 §3).

#### 5.3 Delivery loop (`worker` only)

On each `RIZZY_WORKER_INTERVAL_SECS` tick and on a wake-up, `worker`:

1. Reads the ADR 0086 `smtp_*` rows (live, §3 there). Not configured, or `smtp_password` does not unseal: logs one warning per tick naming the cause, sends nothing, leaves rows as they are.
2. Expires: every queued row with `expires_at_ms <= now` becomes `state = 2`, `last_error = 7` (expired), `payload_sealed = NULL`.
3. **Claims** up to 50 due rows (`state = 0`, `next_attempt_ms <= now`, `lease_until_ms <= now`), ordered by tier (R, E, S) then `next_attempt_ms`, also bounded by the instance cap (§6): in one transaction, `attempts + 1`, `lease_until_ms = now + 5 min`. The claim commits **before** any byte goes to the network.
4. Opens one SMTP session (§5.5) for the batch and, per row, unseals the payload, renders the template (§8) and sends it.
5. Settles each row in its own transaction: accepted (2xx after the DATA terminator) → `state = 1`; permanent → `state = 2`; transient → stays 0 with `next_attempt_ms = now + min(30 s × 2^(attempts − 1), 30 min)` and `lease_until_ms = 0`. Every settle to 1 or 2 sets `settled_at_ms` and `payload_sealed = NULL`.
6. Deletes rows with `settled_at_ms <= now − 30 days` (the dedupe window).

**Crash and retry.** A crash before the claim commits sends nothing and loses nothing. A crash after the claim and before the settle leaves the row leased; it is retried when the lease lapses (5 minutes), so delivery is **at least once**: a duplicate is possible only when the crash falls between the relay's acceptance and the settle commit. Every attempt of one row uses the same `Message-ID` (§8), so the duplicate is recognisable (U: whether a given mail client collapses it). There is no attempt cap other than expiry. Only one `worker` is active per database (ADR 0010 §2), so claims do not race; the lease is crash recovery, not concurrency control.

#### 5.4 Error classes (stored in `last_error`, logged by number)

| Class | Meaning | Kind |
|---|---|---|
| 1 | connect failed or reset | transient |
| 2 | TLS: handshake, certificate, or STARTTLS not offered | transient (a configuration fix must still deliver) |
| 3 | AUTH refused or no supported mechanism | transient |
| 4 | 4xx reply | transient |
| 5 | 5xx reply to `MAIL FROM`, `RCPT TO` or DATA | permanent |
| 6 | timeout (§5.5) | transient |
| 7 | expired before acceptance | permanent |
| 8 | payload or login name unreadable, or render refused (§8) | permanent |

The reply text of the relay is never stored or logged (it can echo the address).

#### 5.5 SMTP transport

- **TLS is required, always.** `smtp_tls = tls`: implicit TLS from the first byte. `smtp_tls = starttls`: plain connect, `EHLO`; if the reply does not list `STARTTLS`, the session ends with class 2 before any other command, then `STARTTLS`, handshake, `EHLO` again. No command after the greeting other than `EHLO` and `STARTTLS` is sent in clear; `AUTH` is never sent before TLS.
- **TLS stack:** `rustls` with the `ring` provider already in the tree, TLS 1.2 and 1.3, certificate verification against `webpki-roots` for the server name `smtp_host` (an IP literal is verified against the certificate's IP SAN, L). No private CA and no "accept invalid certificates" switch at M3 (open question 4).
- **AUTH:** only when `smtp_username` is set: `PLAIN`, else `LOGIN`; any other set is class 3. The password lives in a zeroizing buffer for the session only.
- **Envelope:** `EHLO` name = the domain of `smtp_from`; `MAIL FROM:<smtp_from>`; one `RCPT TO` per message.
- **Timeouts:** connect 10 s; each reply 30 s; the whole message 60 s; the whole batch 5 minutes (rows not reached are released, not failed).
- **Client crate:** a vetted SMTP client, recommended `lettre` (U: version, maintenance, advisories and the exact feature names unverified here), in `rizzy-server` only, `default-features = false`, its rustls feature only, never `native-tls` or `openssl`; the ADR 0009-style justification and `cargo deny check` go with the implementation PR, as ADR 0066 §3 already proposes.

### 6. Rate limits

| Limit | Value | Over the limit |
|---|---|---|
| `account-email/start` per account | 5 per fixed 24 h window (`start_window_ms`), and ≥ 60 s after `last_start_ms` | `429 rate_limited`, nothing queued |
| Wrong codes per pending address | 5 | pending cleared, `409 state_conflict` |
| Tier S mails per account | 10 per 24 h (counted from outbox rows with `tier = 3` and `at_ms > now − 24 h`) | not queued; one warning log line with the account-free counter |
| Tier R and E per account | no cap beyond dedupe and the limits above (each pending recovery yields at most 3 mails: 10 and 11, or 10, 12 and 13; `recovery/start` is already limited per name) | — |
| Instance, all tiers | 50 per tick and 1000 per rolling hour (rows settled to 1 in the last hour) | rows wait, in tier order, until expiry |

These numbers are constants in `rizzy-domain-auth` `config.rs` next to the existing limits; changing one is an ADR amendment.

### 7. When mail is not configured

"Mail configured" means: ADR 0086's `smtp_*` group is complete (its "Groups" rule), read at the point of use. Then:

- **Nothing is queued** (§5.2); a later configuration never sends old events. `account-email/start` answers `invalid_request`; `finish` and `remove` work.
- **The recovery wait applies unchanged** (ADR 0008 decision 5): mail never shortens, lengthens or gates it.
- **`recovery/start` success response** gains `"email_notice": bool`, true iff a template-10 row was written. When false, the web vault, the extension and `rv` show: "No email will be sent about this recovery: this server does not send mail, or the account has no confirmed email address. The waiting period still applies." It appears only after the code matched, so it tells a kit thief nothing about accounts they cannot open, and nothing they could change.
- **Settings screens** (web vault, `rv account email`) show, when `mail_configured` is false: "This server does not send email. Security notices reach you only on your signed-in devices." An existing address is kept and shown as "saved, not in use".
- **No notifiable channel.** An account with no usable durable device and no verified address (or mail off) gets a persistent settings warning: "If someone uses your Emergency Kit, nothing will warn you during the waiting period." (open question 5).
- INV-43 and ROADMAP principle 5 hold: no mail code path is required for any vault function.

### 8. Templates (format: template id + `template_version`)

- Compiled-in, English, `text/plain; charset=utf-8`, quoted-printable, at most 8 KiB rendered. Headers: `From: <smtp_from>` (no display name), `To: <recipient>`, the fixed `Subject` below (ASCII), `Date`, `Message-ID: <hex(mail_id)@domain of smtp_from>`, `MIME-Version: 1.0`, `Auto-Submitted: auto-generated` (RFC 3834, L). No `Reply-To`, no `List-Unsubscribe`, no HTML, no images, no tracking.
- **No secret and no link:** no vault data, key, password, Secret Key, recovery code, token, session id, device id or IP address; no URL, scheme, path or host of the server. The single exception is template 1's 8-digit code. User-controlled text is limited to the login name, in the body only; a parameter with any C0/C1 control or U+2028/2029 refuses the render (class 8). Times are UTC, `YYYY-MM-DD HH:MM UTC`, floored to the minute.
- A wording change that keeps the parameters is a new `template_version` by ADR amendment; a queued row renders with the version it was queued with, and the renderer keeps every version it may still meet (≤ 7 days).
- **Footer F** (every template): "This message was sent automatically by your rizzy-vault server. rizzy-vault messages never contain links and never ask for your master password, Secret Key or recovery code. Do not reply."

Bodies, version 1 (`{login}` = login name, `{at}` = `at_ms`, `{value}` = `value_ms`):

| # | Subject | Body (then a blank line and F) |
|---|---|---|
| 1 | rizzy-vault: confirm your email address | Someone signed in to the rizzy-vault account "{login}" asked to send security notices to this address. Your confirmation code is {code}. Enter it in rizzy-vault before {value}. If you did not ask for this, ignore this message; this address receives nothing more unless the code is entered. |
| 2 | rizzy-vault: notification address changed | Security notices for the rizzy-vault account "{login}" go to a different address since {at}. This address receives no further notices. If you did not change it, sign in to rizzy-vault, change your master password and review your devices. |
| 3 | rizzy-vault: notification address removed | Security notices for the rizzy-vault account "{login}" were turned off at {at}. If you did not do this, sign in to rizzy-vault, change your master password and review your devices. |
| 10 | rizzy-vault: account recovery started | A recovery of the rizzy-vault account "{login}" was started at {at} with its recovery code (Emergency Kit). Unless it is cancelled, it can be completed from {value}, and whoever completes it gets everything in the account. If this was not you, cancel it now on a device where you are signed in to rizzy-vault, then replace your Emergency Kit: someone has your recovery code. |
| 11 | rizzy-vault: account recovery cancelled | The pending recovery of the rizzy-vault account "{login}" was cancelled at {at} from one of its devices. If this was not you, someone has your recovery code and access to one of your devices: replace your Emergency Kit and review your devices. |
| 12 | rizzy-vault: recovery code used | The waiting period has ended and the recovery code of the rizzy-vault account "{login}" was used at {at} to open the account. If this was not you, treat everything stored in the account as exposed and contact your server's administrator. |
| 13 | rizzy-vault: account recovered | The rizzy-vault account "{login}" was recovered at {at}: a new master password, Secret Key and recovery code were set, and every session was ended. If this was not you, you have lost control of the account; contact your server's administrator. |
| 20 | rizzy-vault: new device added | A new device was added to the rizzy-vault account "{login}" at {at}. If this was not you, revoke it from another device and change your master password. |
| 21 | rizzy-vault: sign-in credentials changed | The master password or Secret Key of the rizzy-vault account "{login}" was changed at {at}. If this was not you, contact your server's administrator. |
| 22 | rizzy-vault: recovery code replaced | The recovery code of the rizzy-vault account "{login}" was replaced at {at}; the old Emergency Kit no longer works. If this was not you, change your master password. |
| 23 | rizzy-vault: account recovery turned off | Recovery with an Emergency Kit was turned off for the rizzy-vault account "{login}" at {at}. If this was not you, change your master password. |
| 24 | rizzy-vault: recovery waiting period shortened | Your server's administrator shortened the recovery waiting period of the rizzy-vault account "{login}" at {at}. |
| 25 | rizzy-vault: second factor reset | Your server's administrator removed the second factor of the rizzy-vault account "{login}" at {at}. If you did not ask for this, contact them. |

Template 10 with `value_ms <= at_ms` (a 0 wait) says "it can be completed immediately" instead of "from {value}". If open question 1 is answered yes, templates 10's "on a device where you are signed in" becomes "on a signed-in device or in the web vault" (version 2).

### 9. Invariant (proposed INV-116, provisional)

"Outbound mail is a notification channel only. It is sent only by `worker`, only over TLS with certificate verification, only to an address the account verified (template 1 excepted), and never for a request that has not passed KE3 or the `H_rec` comparison. A mail carries no secret other than template 1's single-use code, no link and no server URL. The account email is sealed at rest, is never a lookup key, a login name or a factor, and is never shown to a recovery-only session. An instance without SMTP queues no mail and keeps the recovery wait unchanged." Verified by: §11's renderer, transport, enumeration and mail-off tests.

### 10. How ADR 0066 must align (listed, not edited)

Before ADR 0066 is accepted, it must be revised to:

1. Drop `RIZZY_SMTP_URL` and `RIZZY_SMTP_FROM` and its supersession of ADR 0028 item 12 (settings list and secret-boundary passage); read ADR 0086's `smtp_*` rows and `SERVER_SMTP_CREDENTIAL` instead (resolves G07-1, INV-86).
2. Use this ADR's §5.5 transport (TLS required, STARTTLS mandatory, timeouts, crate and feature rules) and §5.4 error classes; one SMTP client in the tree.
3. Either queue through `auth_mail_outbox` with templates 100–199, or keep its own share-domain table but with §5.3's claim-before-send, lease, backoff, expiry and settle rules; in both cases its sends count against §6's instance cap.
4. Parse recipient addresses with §3.2's grammar (one parser, one fuzz target).
5. Follow §8's template rules (fixed, versioned, plain text, no link, the code the only secret).
6. Restate "mail not configured" as §7's test.
7. Decide whether `recipient_emails` on the `shares` row is sealed like §4.2 or stays in clear, with the reason.

## Consequences

### Positive

- ADR 0008 owner decision 2's safeguard exists for web-only accounts: a recovery start, its use and its completion reach the account's mailbox within one `worker` tick, with retries for 7 days.
- One SMTP configuration with one sealed password (ADR 0086, INV-86); no secret in the environment; ADR 0066 has a concrete target to align to.
- No enumeration oracle: no address uniqueness, no mail before KE3 or `H_rec`, no address shown to a recovery-only session.
- A DB-only reader does not learn addresses; a restored dump never replays stale mail.
- Mail stays optional (INV-43); an instance without SMTP behaves as today, and says so to the user.

### Negative

- New wire surface (three endpoints, two fields), two tables, one sealing purpose with vectors, one new dependency (the SMTP client), and fixed English templates.
- A web-only user who gets template 10 cannot cancel the recovery today (ADR 0008 decision 5: "Any enrolled device can cancel"); the mail warns but the remedy needs a device (open question 1).
- At-least-once delivery: a rare duplicate after a crash.
- No bounce handling (no inbound mail at M3): a dead address is noticed only by the user.
- Operators whose relay has no valid public certificate (a local relay, a private CA) cannot send at M3.

### Risks

- **Mail is advisory and spoofable.** Anyone can send a mail that looks like ours; "never a link, never asks for secrets" is the user-facing rule that makes ours distinguishable. The user must not rely on the absence of mail.
- **The relay and the mailbox provider learn** that an account had a recovery or a new device, and when (metadata to a third party chosen by the admin). Templates name the login name; an admin who considers that sensitive can leave mail off.
- **A compromised server** can suppress or fake mail; the threat model already treats the server as able to skip the recovery wait (CRYPTO §11.9 step 3); nothing here is a trust input.
- **Session-holder plus fresh password** can remove the address before a recovery; this is no worse than what such an attacker can already do (change credentials), and the old address is told.

## Alternatives considered

- **Address in clear in `auth_accounts`.** Simpler, and ADR 0066 stores share recipients in clear. Rejected: the address is never searched, so sealing costs little and keeps the address-to-account link from a DB reader.
- **Verification by link.** The usual pattern. Rejected: "no links" is the anti-phishing rule, and a link would be a bearer token in a mailbox and in proxy logs.
- **Unique addresses / address as login.** Rejected: creates an enumeration oracle and an email-based identity ADR 0008 point 8 rules out.
- **Send from `api` synchronously.** Rejected: ADR 0010 gives `api` no outbound; a slow relay would stall requests; no retry after a crash.
- **Hand-written SMTP client over the existing `tokio-rustls`.** Fewer dependencies, but SMTP framing, dot-stuffing and AUTH are easy to get subtly wrong. Not chosen; kept as a fallback if the crate review fails.
- **Allow STARTTLS-optional or plaintext to localhost.** Rejected: a downgrade sends the relay password in clear; ADR 0086 already fixes "no plaintext mode".
- **Including the server host in the body.** Helps users with several instances, but mail clients turn a bare host into a link (L). Rejected for M3.
- **Refuse to open a recovery when the account has no notifiable channel** (G01-10's alternative). Not chosen: it would lock out exactly the users recovery exists for; open question 5.

## Open questions for the owner

1. **Should a fresh OPAQUE session (web vault) be able to cancel a pending recovery?** Today only an enrolled device can (ADR 0008 decision 5, ADR 0045 point 4), so template 10 cannot offer a web-only user a remedy. *Recommendation:* yes, through a separate small ADR that supersedes those two parts; anyone with the master password and Secret Key can already log in, so it gives an attacker nothing new. Template 10 then moves to version 2.
2. **Milestone and order.** *Recommendation:* M3, with ADR 0086 accepted first (or together); ship templates 1–3 and 10–13 first, Tier S with its trigger paths. The ROADMAP §4.9 row already names "SMTP settings for notifications" at M3; if the owner wants recovery mail treated as a Must rather than a Should, that is a ROADMAP edit.
3. **Tier S at M3, without per-kind opt-out?** *Recommendation:* yes; the set is small (alerts only), capped at 10 per day, and removing the address is the opt-out. A per-tier toggle can follow.
4. **Relays without a publicly trusted certificate (private CA, local relay).** *Recommendation:* not at M3. If asked for, a later ADR adds a CA-file setting on ADR 0030 Decision 4's pattern; never plaintext and never "skip verification".
5. **Accounts with no notifiable channel.** *Recommendation:* keep ADR 0008 owner decision 2 as is and show the §7 warning; do not refuse recovery.

## On acceptance (doc edits, not made now)

1. ADR 0028's status line gains "; [ADR 0100](0100-notification-mail.md) (item 1 in part)"; its README row likewise (the owner's act).
2. CRYPTO.md §11.9 steps 2 and 6: replace the "no mail channel yet" sentences with a pointer to this ADR; §5.11 gains `SERVER_ACCOUNT_EMAIL` with its number (next free) and §15 its vectors; §5.9 gains a paragraph on the account email (§2's enumeration rule).
3. THREAT_MODEL.md §8.7 (Mail) gains INV-116 (or the next free number); §7.9 (worker) and §7.19 gain the mail rows; the INV-43 row notes that mail-off is tested by §11 test 9.
4. ADR 0090 §3 gains the three kinds of §3.5, if it is Accepted.
5. ADR 0086 open question 4 is answered by pointing to this ADR.
6. ROADMAP §4.9 SMTP row links this ADR.
7. ADR 0066 is revised per §10 before its own acceptance.

## Implementation plan

1. `rizzy-proto`: `account-email` request and response types, the `AccountView.notification_email` object and `recovery/start`'s `email_notice`. Tests: serde round trip; an old reader ignores the new fields.
2. `rizzy-storage`: one migration (next free number) for both tables; `TABLES` gains `auth_account_email` only. Tests: dump and restore keep the email row and drop the outbox; FK cascade on account deletion.
3. `rizzy-domain-auth` `mail` module: address parser (fuzz target `mail_address`), sealing purpose (KAT per kind), the three endpoints' domain functions, `enqueue` inside the trigger transactions, caps, `claim`/`settle`/`expire`/`prune`, renderer. Tests: golden output per template and version; renderer output contains no `://`, no `www.` and no digit run of 8 except template 1; control characters refused; dedupe (two `recovery_complete` calls, one row); unknown name and wrong code write no row; fifth wrong code clears; rate limits; recovery-only session sees no address.
4. `rizzy-server`: routes, the `worker` loop and the transport. Tests against an in-process test SMTP server with a test root store injected only under `cfg(test)`: STARTTLS absent → no `AUTH` sent, class 2; bad certificate → class 2; 4xx then 250 → one delivery after backoff; 5xx → failed; kill between claim and settle → resent once with the same `Message-ID`; expiry; tier order and instance cap; logs contain no address, code or login name (INV-48 canary).
5. Clients: web vault and extension settings (set, confirm, remove, mail-off text, no-channel warning), recovery start text from `email_notice`; `rv account email set|confirm|remove`; e2e for each.
6. `lettre` (or the fallback) admitted with its justification and `cargo deny check` passing.
7. Mail-off: the INV-43 CI job and a test that an instance without `smtp_*` rows runs recovery with the unchanged wait and `email_notice = false`.

## References

- [ADR 0008](0008-account-recovery.md), [ADR 0010](0010-server-shape.md), [ADR 0011](0011-storage.md), [ADR 0020](0020-partial-supersession.md), [ADR 0023](0023-logical-backup-format.md), [ADR 0028](0028-api-v1-http-conventions.md), [ADR 0045](0045-recovery-pending-notification.md), [ADR 0060](0060-admin-panel-stack-boundary.md), [ADR 0066](0066-share-email-otp-verification.md) (Proposed), [ADR 0085](0085-admin-authentication-bootstrap.md) (Proposed), [ADR 0086](0086-instance-settings-persistence.md) (Proposed), [ADR 0090](0090-per-account-security-event-log.md) (Proposed)
- [CRYPTO.md](../CRYPTO.md) §2, §5.9, §5.11, §11.9, §15; [THREAT_MODEL.md](../THREAT_MODEL.md) INV-43, INV-48, INV-69, INV-70, INV-86; [ROADMAP.md](../ROADMAP.md) §4.9
- Review: [2026-10-25 gap review](../reviews/2026-10-25-adr-gap-review.md) M2; raw G01-10, G05-10, G07-1, G10-16
- External, not verified here: RFC 5321/5322 address and reply-code semantics (L), RFC 3834 `Auto-Submitted` (L), rustls IP-SAN verification (L), `lettre` (U), mail-client handling of duplicate `Message-ID`s and of bare host names (U/L)
