# ADR 0061: notify role: WebSocket connect authentication and message envelope

- Status: Accepted
- Date: 2026-10-11
- Deciders: project owner
- Milestone: M3

## Context

[ROADMAP §4.9](../ROADMAP.md#49-server-self-hosting--ops-m1-onward) lists "Push/live sync (WebSocket) so clients update without polling" for M3. [ADR 0010](0010-server-shape.md) §1 names the `notify` role for this ("WebSocket/SSE wake-up signals to connected clients. No mobile push") but fixes neither the connect handshake nor the message bytes. §3 fixes only the *inter-process* leg: `notify` learns of changes through PostgreSQL `LISTEN/NOTIFY`, and "messages carry only IDs, as in 'account X changed'." Neither §1 nor §3 is superseded by [ADR 0022](0022-server-mode-only.md) §1 (that table names only the `api` and `worker` rows), so both stand as Accepted text this ADR builds on.

[THREAT_MODEL](../THREAT_MODEL.md) §7.8 already assigns the shape: S → "subscriptions are authenticated; the token is never in the URL" (INV-52); T → "signals carry no data; clients sync and verify"; I → "signals and pushes carry no content" (INV-54); D → "connection exhaustion" mitigated by "per-account connection caps," with no number. That is the gap ROADMAP and THREAT_MODEL leave for this ADR: pick the construction that proves the session on a WebSocket, fix the server→client frame, and give D a number.

Nothing here is new cryptography. The only session credential that exists is CRYPTO.md §5.10's 32-byte bearer token (`SHA-256` stored; carried as `Authorization: Bearer <43 base64url chars>`, [ADR 0028](0028-api-v1-http-conventions.md) item 4) and, for native clients (kinds 1–3, `SessionKind::Device`), the `device-request` statement over method, path-and-query and body hash with a replay-windowed counter ([ADR 0028](0028-api-v1-http-conventions.md) item 5, `Rizzy-Request-Counter` / `Rizzy-Request-Signature`). `rizzy-domain-auth`'s `AuthService::authenticate_request` (`crates/rizzy-domain-auth/src/device.rs:372`) already verifies both forms and already refuses a `Device`-kind session that carries no signature. This ADR reuses that function unchanged for both client kinds at connect time; it decides only how each kind feeds it at WS-connect time, and how a live socket is revalidated afterward.

`axum` is pinned at 0.8.9 with `features = ["http1", "tokio"]` (`Cargo.toml:101`, V) — no `ws` feature yet.

## Decision

### 1. Transport: WebSocket, not SSE — narrows ADR 0010 §1 and ADR 0028 item 1

**What this ADR supersedes** (ADR 0020 point 9):

| Part, quoted | Replaced by |
|---|---|
| ADR 0010 §1 roles table, `notify` row | the row given under "Replacing text" below |
| ADR 0028 item 1 ("Paths and methods"), the sentence: "`POST` for everything, including reads that carry a body; `GET` (and `HEAD`) only for `GET /api/v1/devices/grants`." | "`POST` for everything, including reads that carry a body; `GET` (and `HEAD`) only for `GET /api/v1/devices/grants` and `GET /api/v1/notify` (the WebSocket upgrade, §2)." |

**Replacing text — ADR 0010 §1 roles table, `notify` row** (same six columns as the original table):

| Role | Does | DB access | Inbound | Outbound | From |
|---|---|---|---|---|---|
| `notify` | WebSocket wake-up signals to connected clients, per [ADR 0061](0061-notify-websocket-protocol.md). No mobile push (open question 6) | yes (sessions) | public, through the proxy | none | M3 |

This supersession leaves item 1's first sentence untouched: "The 27 endpoints of `rizzy-server` `http/api.rs` (module table)…" still counts only that table's routes. `/api/v1/notify` is served by the `notify` role's own router (ADR 0010 §1), not an entry in `http/api.rs`, so the 27-endpoint count is unaffected.

*Why SSE is dropped, not merely deprioritized:* `EventSource`, the browser API for SSE, cannot set an `Authorization` header and cannot send any client→server byte after connecting (it is receive-only; web-platform fact, L, not independently re-verified in this session). An SSE-based `notify` could therefore only prove the session through the connect URL or a cookie, which INV-52 and ADR 0028 item 4 forbid. The browser `WebSocket` constructor has the same no-custom-header limit, but, unlike SSE, it is bidirectional, so the client can send one frame after the upgrade (same L tag). §2 depends on that asymmetry. The `notify`-row change is a few words out of ADR 0010's 2,127-word Decision; the superseded ADR 0028 sentence is one clause of its 3,026-word Decision (`wc -w`, 2026-10-11, V) — both far under ADR 0020 point 9's half limit, so partial supersessions, not full successors.

### 2. Connect and authentication

Two paths, chosen by whether the upgrade request carries an `Authorization` header — not by client kind, so the server need not know the kind before authenticating:

- **Header path (native clients, `SessionKind::Device` or `Opaque`).** The client sends the ordinary `GET /api/v1/notify` upgrade request with `Authorization: Bearer <token>` and, when its session is `Device`-kind, `Rizzy-Request-Counter` / `Rizzy-Request-Signature` computed exactly as for any other request, over `method = "GET"`, `path_and_query = "/api/v1/notify"`, `body = b""`. The handler calls `AuthService::authenticate_request` with those values **before** calling axum's `WebSocketUpgrade::on_upgrade`, exactly as every other `/api/v1` route does. A failure returns a plain `401 {"error":"unauthorized"}` (ADR 0028 item 5's "one answer") and the socket never upgrades. No new construction, no new header.
- **First-frame path (the web vault, kind 4, always `Opaque`-kind sessions — `CRYPTO.md §5.10`).** Browsers' `WebSocket` constructor sets no custom header, so the token cannot travel on the upgrade request. The server completes the 101 upgrade unauthenticated, then requires exactly one text frame, within 5 s, of the JSON shape `{"token":"<base64url bearer token>"}` (the same `SessionToken` encoding `Authorization: Bearer` already uses — no new wire type). The handler calls `AuthService::authenticate_request(token, None, …)` unchanged; it already returns `Ok` for an `Opaque` session and `Err(Unauthorized)` for a `Device` session with no signature, so a native client cannot use this path by mistake.
- **One close code for every auth failure**, mirroring ADR 0028 item 5: missing, malformed or oversized first frame (cap: 256 bytes, parsed with a dedicated fuzz target, `fuzz/fuzz_targets/notify_auth_frame.rs`), a missing/unknown/expired/revoked token, a missing or bad device signature, a replayed counter, a `Recovery`-kind session (excluded — its sole purpose is the 10-minute recovery commit, CRYPTO.md §11.9 step 3; it gains nothing from a wake-up socket), a timeout, or any client frame other than the one auth frame, a pong, or a close — all close with code 4001 and no text, before the token is logged (INV-48). A distinct code 4002 closes the account's oldest open socket when §4's cap is hit; this is not a secrecy-relevant distinction, since it says nothing about token validity.
- **No per-message signing after the first frame.** The socket carries no further client→server command (nothing to sign); the server only pushes §3 frames and ordinary ping/pong.
- **Revocation.** `notify` does not subscribe to a new "session ended" signal. Every open socket re-runs a periodic validity check every 30 s through a new method, `AuthService::session_is_live(token, now_ms) -> Result<(), AuthError>`. It is new public surface, not a reuse of `authenticate_request`: the signature-free, kind-independent lookup already exists as `session::load` (`crates/rizzy-domain-auth/src/session.rs:177`, `pub(crate)` — the exact lookup `authenticate_request`'s no-signature branch calls internally, `crates/rizzy-domain-auth/src/device.rs:379-381`), but it is private to `rizzy-domain-auth` and `notify` lives in `rizzy-server`, so this ADR adds a thin wrapper that calls it and discards the `Session`, applying no kind check. That check matters: `authenticate_request(token, None, …)` itself returns `Err(Unauthorized)` whenever the loaded session's kind is `Device` (lines 383-387), so calling `authenticate_request` on a periodic tick — rather than the new wrapper — would force-close every native-client socket at its first 30 s revalidation, since no fresh signature is ever produced over an already-open socket (no per-message signing, above). `session_is_live` is therefore kind-independent by construction: it never reaches the signature-verifying branch of `authenticate_request` (used only once, at connect, in the header path above) and never the kind check the no-signature branch applies. The socket closes with 4001 the moment `session_is_live` reports the session row gone, expired or revoked. `worker` already purges expired session rows (`crates/rizzy-server/src/worker.rs` step 1, `AuthService::purge_expired`); this reuses that same store as the single source of truth instead of adding a second one.
- **Unauthenticated-socket exhaustion.** Because the first-frame path leaves a socket open before it is attributed to any account, the server also caps, server-wide, the count of upgraded-but-not-yet-authenticated sockets (recommend 500) and per source IP (recommend 20), on top of §4's per-account cap; either limit refuses the upgrade with `429 {"error":"rate_limited"}`, reusing ADR 0028 item 8's capacity-refusal code for a wait that cannot be granted a slot, rather than adding a status outside item 3's closed error-code set.
- **Dependency.** `ws` is added to `axum`'s features in `[workspace.dependencies]` (`Cargo.toml:101`), pulling `tokio-tungstenite`. It is not a cryptographic dependency (ADR 0009 does not apply); `cargo deny check` and `cargo xtask check-deps` cover it like any other feature addition.

### 3. Message envelope

One JSON text frame per event, server → client only:

```json
{"scope": "account" | "vault" | "devices", "id": "<base64url 16-byte id>"}
```

- `scope: "account"`, `id = account_id`: the signed `account-state` advanced (ADR 0026 kind 2) — settings, bundle, or a pending-recovery field such as ADR 0045 (this batch) proposes.
- `scope: "vault"`, `id = vault_id`: the vault's op log advanced (ADR 0012 §1, §3). Coarser than `rizzy-bus::Event::CompactionQueued`, which also carries `item: ItemId` (`crates/rizzy-bus/src/lib.rs:144`) — the `item_id` is dropped here on purpose: "this vault changed" is all a client needs to re-run ADR 0012 §7 Freshness, and forwarding the item id would be a server-chosen hint the client must not need to trust anyway.
- `scope: "devices"`, `id = account_id`: a device certificate or revocation changed (ADR 0012 §6).
- **No other field, ever** (INV-54): no ciphertext, no count, no size, no `device_seq`, no timestamp. A client that receives a frame does exactly what a background refresh already does — Fetch and verify (ADR 0012 §7) — and never trusts the frame's claim.
- **Forward compatibility.** `scope` is an open set of short lowercase identifiers. This ADR fixes `account`, `vault` and `devices` for M1–M3. A later milestone may add one more value through a dated `## Amendments` entry to this ADR (as ADR 0009's crate table already does for itself), provided the new value still carries only an id. M6's mail-arrived signal ([ROADMAP §4.8](../ROADMAP.md#48-aliases--email-receiving-m6), "real-time notification of new mail") is such an amendment, reusing §2's connect-auth unchanged.
- **Event source.** `rizzy-bus::Event` (`crates/rizzy-bus/src/lib.rs:140`, `#[non_exhaustive]`) gains three M3 variants, each the named consumer its own doc comment calls for ("a kind is added in the same change as the domain code that consumes it, with the ADR that names that consumer," line 41): `OpStored { account, vault }` (`rizzy-domain-vault`, published after the same commit ADR 0021's compaction queue entry is — the module's "Ops stored" line, 52, already anticipates this exact consumer), `AccountStateChanged { account }` (published wherever ADR 0026 kind 2's `account-state` row advances — settings, bundle, or ADR 0045's pending-recovery field), and `DevicesChanged { account }` (published after ADR 0012 §6's revocation commit; the module's "Device revoked" line, 50–51, is this ADR naming that subscriber). `Event::account()` (line 157) already reads the account id off any of them; `notify` turns each straight into the frame above with no further logic.
- **Profile C.** The PostgreSQL `LISTEN/NOTIFY` payload between `api` and `notify` (ADR 0010 §3; not yet defined, `crates/rizzy-bus/src/lib.rs:7-8, 59`) carries the identical two-field `{scope, id}` shape, so one encoding serves the in-process bus and the cross-process channel. The channel name and `NOTIFY` framing stay an implementation choice of `rizzy-bus`'s PostgreSQL backend, not a new persistent format.
- **Coalescing.** `notify` debounces repeated events for the same `(scope, id)` within 200 ms into one frame, so a burst of ops does not become an externally observable count (INV-54's spirit).

### 4. Per-account connection cap (THREAT_MODEL §7.8, "D")

**Proposed invariant** (THREAT_MODEL §8; allocated as INV-87 across the 2026-10-11 batch in ADR-number order. Provisional: the allocation was made across the 2026-10-11 batch in ADR-number order; if ADRs are accepted out of order, the owner renumbers at acceptance.):

> **Proposed INV-87.** The `notify` role enforces a configurable cap, `notify_max_connections_per_account` (default 20), on concurrently authenticated sockets per account. A connection that would exceed it closes the account's oldest open socket (close code 4002) before accepting the new one. The cap is attributed only after §2's authentication succeeds.

Default 20: generous for one account's realistic concurrent surfaces at the personal/family scale ADR 0010 targets (desktop app, a browser extension open in several tabs, mobile app, one or two web-vault tabs) without bounding memory per `notify` process.

### On acceptance

None of these edits is made now (ADR 0020 point 9); the owner makes them in the change that accepts this ADR.

1. **Status lines.** ADR 0010's gains a semicolon-separated entry after its existing one: "Partially superseded by [ADR 0022](0022-server-mode-only.md) (§1 in part); [ADR 0061](0061-notify-websocket-protocol.md) (§1 in part)". ADR 0028's gains one after its two existing entries: "Partially superseded by [ADR 0031](0031-retiring-old-opaque-setups.md) (item 3 in part); [ADR 0032](0032-healing-rotation-after-backup.md) (item 3 in part); [ADR 0061](0061-notify-websocket-protocol.md) (item 1 in part)".
2. **[docs/adr/README.md](README.md).** A new index row for 0061 (Status: Accepted, Milestone: M3); the Status cells of rows 0010 and 0028 follow point 1.
3. **THREAT_MODEL.md §8.** Proposed INV-87 is added with this ADR's text.
4. **CRYPTO.md.** No edit: this ADR adds no construction CRYPTO.md owns (Context).

## Consequences

### Positive

- Reuses `AuthService::authenticate_request` unchanged for both client kinds at connect time (§2); no new signing construction, no new token type. The periodic revalidation ("Revocation", §2) cannot reuse it — the signature-free lookup it would need is crate-private (`session::load`) — so it adds one small method, `AuthService::session_is_live`, kept kind-independent on purpose.
- The web vault's existing CSP needs no change: `connect-src 'self'` (`crates/rizzy-server/src/http/security.rs`) already covers a same-origin `wss://` connection under the Fetch spec.
- One frame shape serves the client-facing socket and the cross-process LISTEN/NOTIFY leg.
- THREAT_MODEL §7.8's "D" row gets an enforceable number without editing THREAT_MODEL.md directly.

### Negative

- A revoked or logged-out session can still receive content-free wake-up frames for up to 30 s after ADR 0012 §6 ends it (bounded by INV-54 to zero content).
- A new non-crypto dependency (`tokio-tungstenite`, via axum's `ws` feature) and three new numeric limits (first-frame deadline, two connection caps) to tune in production.
- `notify` now holds two authentication code paths at connect time, plus a new `AuthService::session_is_live` method for periodic revalidation — one small addition to `rizzy-domain-auth`'s public surface, though all three terminate in the same session store.

### Risks

- If a future client kind needs custom headers on a browser-hosted connection, only the Fetch-based pattern `Sec-WebSocket-Protocol` carrying a one-time, server-issued, URL-safe nonce (never the bearer token itself) would avoid reopening INV-52; not needed now.
- A `notify` process that mis-handles the 200 ms debounce could, in principle, let timing approximate a count; the mitigation is a fixed debounce window, not a variable one.

## Alternatives considered

- **SSE instead of WebSocket.** Rejected in §1: `EventSource` cannot send the bearer token anywhere but the URL, which INV-52 forbids outright.
- **`Sec-WebSocket-Protocol` carrying the token.** Rejected: subprotocol values are visible in browser devtools' Network panel and in reverse-proxy access logs the same way a query string is, which is the exact exposure INV-52 names for URLs.
- **Device-request signature inside the first JSON frame**, so every client kind (including the web vault) proves possession the same way. Rejected: the web vault's sessions are always `Opaque`-kind and hold no device signing key (CRYPTO.md §5.10), so there is nothing to sign; requiring it would need a new, weaker per-session secret just for this socket.
- **Re-running full `authenticate_request` every 30 s for revocation.** Rejected in §2: it only works for `Opaque`-kind sessions, since the no-signature branch rejects any live `Device`-kind session outright, and no fresh signature exists to pass it after connect. This is why §2 adds `AuthService::session_is_live` instead of reusing `authenticate_request` or exposing crate-private `session::load` directly.

## Open questions for the owner

1. Is 20 the right default for `notify_max_connections_per_account`? *Recommendation:* yes, as a starting value revisited with M3 usage data, the pattern ADR 0012 owner decision 3 already uses.
2. Close oldest socket on cap, or refuse the new connection? *Recommendation:* close oldest — a client that opens a 21st socket is more likely a reconnect storm (stale tabs) than an attacker, and the newest connection is the one the user is looking at.
3. Server-wide (500) and per-IP (20) caps on unauthenticated, upgraded-but-unauthenticated sockets. *Recommendation:* accept as starting values; same revisit rule as question 1.

## References

- [ROADMAP §4.8](../ROADMAP.md#48-aliases--email-receiving-m6) ("real-time notification of new mail"), [ROADMAP §4.9](../ROADMAP.md#49-server-self-hosting--ops-m1-onward) ("Push/live sync")
- [THREAT_MODEL](../THREAT_MODEL.md) §7.8, INV-48, INV-52, INV-54
- [ADR 0010](0010-server-shape.md) §1, §3, §5; [ADR 0012](0012-sync-engine.md) §1, §3, §6, §7; [ADR 0020](0020-partial-supersession.md) point 9; [ADR 0021](0021-server-compaction.md); [ADR 0022](0022-server-mode-only.md) §1; [ADR 0026](0026-client-device-state-and-cache.md); [ADR 0028](0028-api-v1-http-conventions.md) items 1, 3, 4, 5, 8; ADR 0045 (sibling, M1, not yet filed — cited by number only for `scope: "account"`, not duplicated here)
- [CRYPTO.md](../CRYPTO.md) §5.10, §9.6
- Code (V, HEAD 5a78bb5): `crates/rizzy-domain-auth/src/device.rs:61-68, 372-401` (`RequestParts`, `authenticate_request`, its no-signature branch and `Device`-kind rejection); `crates/rizzy-domain-auth/src/session.rs:39-51, 177-179` (`SessionKind`, the crate-private `load` that §2's new `AuthService::session_is_live` wraps); `crates/rizzy-bus/src/lib.rs:43-59, 140-162` (`Event`, extension note, PG payload gap); `crates/rizzy-server/src/worker.rs:1-8` (`AuthService::purge_expired`, step 1); `crates/rizzy-server/src/http/security.rs:33-36` (`WEB_CSP`'s `connect-src 'self'`); `Cargo.toml:101` (axum features, confirms no `ws` yet)
