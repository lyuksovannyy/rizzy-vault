# ADR 0028: `/api/v1` HTTP conventions

- Status: Proposed
- Date: 2026-09-29
- Deciders: project owner
- Milestone: M1

## Context

[ADR 0002](0002-own-protocol.md) point 3 fixes `/api/v1/`, the unversioned `GET /api/meta`, `410 Gone` with a machine-readable code for a removed version, the `Rizzy-Client: <platform>/<version>` header with `client_too_old`, JSON over HTTPS with base64url binary fields ([CRYPTO.md §9.6](../CRYPTO.md#96-encoding-for-transport-and-storage)), and the types in `rizzy-proto`. [CRYPTO.md §5.10](../CRYPTO.md#510-sessions-after-authentication) fixes the bearer token (32 random bytes, stored as `SHA-256`) and the `device-request` signature over "the method, the path and query, and `SHA-256(request body)`", with a per-session `request_counter` accepted once in a sliding window of 64. CRYPTO.md §11 calls its paths "illustrative; the API specification owns them".

Everything else was chosen by the code and reported as a pre-v1.0 choice (V, 3087233): `rizzy-server` `lib.rs` "Wire and format details this crate decides", `http/{api,headers,security,web}.rs`, `config.rs`, `secrets_file.rs`, `secrets_backup.rs`, `server.rs` (`ServeLimits`); `rizzy-proto` `lib.rs` "Left open", `error.rs`, `meta.rs`. Clients (`rv` now, the web vault in M1 step 5, the extension in M2) need these fixed before they ship ([ADR 0002](0002-own-protocol.md) point 5: store-distributed clients update slowly). [ADR 0025](0025-rotation-vault-half.md) (Accepted) §1 moves `account/commit` and `recovery/complete` to the upload limit; for `recovery/complete` what grows is the response (the wraps), not the request (item 7).

Forces: [THREAT_MODEL](../THREAT_MODEL.md) §7.6 (uniform errors, body limits, "XFF trusted only from configured proxies", backoff per (account, source)), §7.7, INV-48, INV-49, INV-52; [ADR 0010](0010-server-shape.md) (TLS at the operator's reverse proxy, roles, secrets mount).

## Decision

The fifteen choices below are frozen for `v1` as described. Until v1.0 they change only under ADR 0002 point 5 (a server release that raises the minimum client versions); from v1.0, only additively. Items 11–15 are the operator's interface, not the client's: a rename keeps the old name working, with a logged warning, for two server releases.

1. **Paths and methods.** The 27 endpoints of `rizzy-server` `http/api.rs` (module table), under `/api/v1/`, grouped by resource (`register`, `login`, `device-auth`, `account`, `devices`, `healing`, `recovery`, `totp`, `vault`), verb last (`start`, `finish`, `commit`, …). `POST` for everything, including reads that carry a body; `GET` (and `HEAD`) only for `GET /api/v1/devices/grants`. *Why:* a request body never goes in a URL, so no id list, cursor or token reaches a URL or an access log (INV-52); one method keeps the signing rule simple.
2. **Success.** `200` with `Content-Type: application/json` and a `rizzy-proto` response body; `204 No Content`, no body, for the "empty success" rows. "No body" requests are `POST` with an empty body. *Why:* the empty success carries nothing to parse.
3. **Errors.** Every error under `/api/` is `{"error":"<code>"}` with this status: `invalid_request` and `client_too_old` 400; `unauthorized` and `second_factor_required` 401; `fresh_session_required` 403; `not_found` 404 (also an unknown `/api/` path, and a role not running); `state_conflict`, `stale_epoch`, `record_conflict`, `prev_seq_mismatch` 409; `api_version_gone` 410; `payload_too_large` 413; `rate_limited` 429; `internal` 500. A method a route does not serve is `405` with `invalid_request`. No message, no echo of input (§7.6 "I", INV-48). Clients read an unknown code as `unknown` and branch on the code, never on the status. *Why:* one table, one body shape; the status lets proxies and `curl` users see the class.
4. **Bearer token.** `Authorization: Bearer <43 base64url characters>`, the scheme name case-insensitive, nothing else accepted; never a query parameter or cookie (INV-52). *Why:* the standard header; no cookie means no ambient credential and no CSRF surface.
5. **Request signing.** `Rizzy-Request-Counter`: the `u64` counter in decimal, 1–20 digits, no sign, no leading zero; `Rizzy-Request-Signature`: the 82-byte signature container as 110 base64url characters. Both or neither. The signed `method` is the request method as sent (upper case); `path_and_query` is the request-target in origin form exactly as received, query included. Reverse proxies must pass the path and query unchanged and serve the API at the origin's root. Any header or signature failure is `401 unauthorized`. *Why:* the `Rizzy-` prefix matches `Rizzy-Client`; a proxy that rewrites the path would break every signature, so the rule is stated rather than guessed.
6. **Order of checks.** The session is checked from headers alone before any body byte is read, so an anonymous request never gets the large limit or a large-body slot (no route without a session has the upload limit, item 7); then the body limit and deadline; then signature; then parsing (unknown fields refused); then the domain. *Why:* §7.6 "D".
7. **Body limits.** 1 MiB for every endpoint; `RIZZY_MAX_UPLOAD_BYTES` (default 32 MiB, minimum 32 MiB, maximum 256 MiB) for the session-gated `vault/upload`, `vault/heal` and `account/commit` (the last per ADR 0025 §1; the code still has 1 MiB for it); 0 for the body-less endpoints. `recovery/complete` has no session, and its request is the fixed-size `RecoveryRequest`, so its **request** stays at 1 MiB, outside the large-body slots; ADR 0025 §1's limit is read as applying to its response (open question 5). `Content-Length` above the limit is refused before reading; a body past it is `413`. `rizzy-proto` limits hold the 256 MiB maximum as `MAX_UPLOAD_BODY_LEN`, which clients use as their own cap ([ADR 0026](0026-client-device-state-and-cache.md) §3). *Why:* sized for one maximal record (a 16 MiB envelope with a 1.5 MiB statement) and for ADR 0025's wrap sets; an anonymous large body would let anyone hold every slot (§7.6 "D").
8. **Slow and concurrent bodies.** Read deadline = 30 s + limit ÷ 64 KiB/s (46 s for 1 MiB); a missed deadline or an aborted body is `400 invalid_request`. At most 8 large-limit requests at once; a request that waits 10 s for a slot is `429 rate_limited`. *Why:* caps large bodies held at once at 8 × the upload limit (256 MiB at the default, 2 GiB at the 256 MiB maximum, which the operator's sizing must cover) and bounds slow-loris bodies.
9. **Listener.** HTTP/1.1 in clear on the listener, TLS at the reverse proxy (ADR 0010); header-read and keep-alive idle timeout 10 s; at most 1024 connections; shutdown grace 30 s. No response compression under `/api/`. *Why:* §7.6 "D"; compressing responses that hold tokens next to request-controlled bytes invites BREACH-style length oracles.
10. **Response headers.** Every response: `Strict-Transport-Security: max-age=31536000` (no `includeSubDomains`, no `preload`: the operator's other hosts are not ours to pin), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, and `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, except the web role's pages, which carry `WEB_CSP` of `http/security.rs` (`'self'` only, `'wasm-unsafe-eval'`, no inline script or style, `object-src`, `base-uri`, `form-action` `'none'`, `require-trusted-types-for 'script'`). API responses add `Cache-Control: no-store`. No CORS headers: the web vault is same-origin; the extension's access is the M2 ADR's. *Why:* INV-49, §7.7.
11. **Rate-limit source and trusted proxies.** The source is the peer address, or, when the peer is in `RIZZY_TRUSTED_PROXIES`, the first address from the right of all `X-Forwarded-For` lines that is not a trusted proxy. Elements are read from the right only, up to 16 lines and 1024 bytes counted from the right; the client-controlled part left of the found address is never read. **Amended:** when the peer is a trusted proxy and the header is missing, or a malformed element, the read bound or the left end comes before an untrusted address, the request is `400 invalid_request`; it never falls back to the proxy's address, whose bucket every user behind it shares (the code falls back today). IPv4-mapped IPv6 is read as IPv4. A source is the IPv4 address or the IPv6 /64. `Forwarded` (RFC 7239) is not read. The buckets and numbers stay `rizzy-domain-auth`'s. *Why:* §7.6 "S"; one subscriber holds a whole /64, so per-address buckets would give 2^64 of them.
12. **Configuration.** The file is named by `--config <path>` or `RIZZY_CONFIG`, from the command line or the environment only, never from the file itself. Settings `RIZZY_ROLES`, `RIZZY_ORIGIN`, `RIZZY_LISTEN` (default `127.0.0.1:8080`), `RIZZY_DATA_DIR` (`/data`), `RIZZY_DATABASE_URL`, `RIZZY_SECRETS_FILE` (`/run/rizzy-secrets/secrets.json`), `RIZZY_SIGNUP` (`closed`|`open`), `RIZZY_TRUSTED_PROXIES`, `RIZZY_LOG_LEVEL`, `RIZZY_WORKER_INTERVAL_SECS`, `RIZZY_MAX_UPLOAD_BYTES`; from the environment or a `NAME=value` file (64 KiB, `#` comments, no quoting; unknown, repeated or malformed lines refused); environment over file, `--roles` over both; `--roles` and `--config` are the only flags. No secret on the command line. *Why:* ADR 0010's names and mounts; a typo must fail, not pass.
13. **Secrets file.** JSON, unknown members refused, ≤ 256 KiB, mode 0600, outside the data directory: `{"format":1,"setups":[{"setup_id","server_setup"}],"enum_key","data_keys":[{"data_key_id","key"}],"current_data_key_id","bootstrap_token"?}`, binary as base64url. The secrets backup file mirrors §11.14: `{"format":"rizzy-vault-secrets-backup","version":1,"kdf_id","backup_salt","backup_id","created_at","data"}`. *Why:* exactly CRYPTO.md §5.11's list, in the file shape CRYPTO.md already uses.
14. **`GET /api/meta`.** `{"server_version":"x.y.z","api_versions":["v1"],"min_client_versions":[{"platform","version"}]}`, unauthenticated, unknown members ignored by clients. **Amended:** the server now reads `Rizzy-Client` (platform ≤ 32 bytes of `[a-z0-9-]`, one of `web`, `cli`, `extension`, `macos`, `windows`, `linux`, `ios`, `android`; version ≤ 64 bytes of `[0-9A-Za-z.+-]`, compared by SemVer 2.0.0 precedence, and a version that is not SemVer counts as below any minimum) and answers `400 client_too_old` when the platform has a minimum above the version; a missing or malformed header is served normally in M1 (so `curl` works) and refused from v1.0 (open question 2). Clients always send it. *Why:* ADR 0002 point 3; today the header is ignored and the minimum list is empty.
15. **Web role paths.** `/` and `/index.html` (`GET`, `HEAD`); every other path outside `/api/` is a plain-text `404`; nothing is read from disk. *Why:* §7.7 "E".

`rizzy-proto` keeps the constants for items 1, 4, 5, 7 and 14 (it may, once this is Accepted), so clients and server share them. A header test pins items 3, 5, 10 and 14; `server_headers` fuzzes items 4, 5 and 11.

## Consequences

### Positive

- Clients can be built against a written contract; `rv`, the web vault and the extension agree by construction.
- Nothing that names an account, device or cursor can land in a URL or access log.

### Negative

- `POST` reads are not cacheable and not idempotent to intermediaries; retries are the client's decision.
- Operators whose proxy strips a path prefix must serve rizzy-vault at a host's root.
- Items 7, 11 and 14 need code changes (the commit limit; refusing a missing or malformed `X-Forwarded-For` from a trusted proxy, with `server_headers` fuzz and unit tests; reading `Rizzy-Client`).
- A proxy that does not set `X-Forwarded-For` breaks every request once it is listed in `RIZZY_TRUSTED_PROXIES`; that is the operator's configuration error, and it fails closed.

### Risks

- If `v1` must change before v1.0, every store-distributed client has to update (ADR 0002 point 5); signal: an M2 extension review delay longer than a week.

## Alternatives considered

- **Resource-style REST** (`GET /vaults/{id}/ops?cursor=`). Puts ids and cursors in URLs and logs (INV-52), for no gain.
- **`426 Upgrade Required` for `client_too_old`.** RFC 9110 ties it to the `Upgrade` header; `400` with the code says the same without that meaning.
- **Signing a normalised path.** Would need a normalisation rule both sides implement identically; signing the bytes received is simpler and fails closed.
- **HSTS with `includeSubDomains; preload`.** Would pin hosts the operator may not control.

## Open questions for the owner

1. **`Retry-After` on `429`.** Recommendation: yes, whole seconds, from the bucket's backoff; it tells an attacker nothing the refusal does not.
2. **Require `Rizzy-Client` before v1.0?** Recommendation: no; require it from v1.0 (item 14).
3. **`Forwarded` (RFC 7239).** Recommendation: no in M1; `X-Forwarded-For` is what the shipped Caddy example sets.
4. **OpenAPI generator** (ADR 0002 point 3, "chosen in M1"). Recommendation: decide with the web vault (M1 step 5), as a dependency change under CLAUDE.md.
5. **ADR 0025 §1 and `recovery/complete`.** Its text gives the endpoint the upload limit; item 7 reads that as the response size and keeps the anonymous request at 1 MiB. Recommendation: confirm this reading, and correct ADR 0025's wording in a later ADR (ADR 0020 point 9) if the owner wants the text to match.

## References

- [ADR 0002](0002-own-protocol.md) points 3–5, [ADR 0010](0010-server-shape.md) §1, §4, §5, [ADR 0025](0025-rotation-vault-half.md) §1; [CRYPTO.md](../CRYPTO.md) §5.10, §5.11, §9.6, §10.2, §11, §11.14; [THREAT_MODEL.md](../THREAT_MODEL.md) §7.6, §7.7, INV-48, INV-49, INV-52.
- Code (V, 3087233): `crates/rizzy-server/src/{lib,config,secrets_file,secrets_backup,server}.rs`, `crates/rizzy-server/src/http/{mod,api,headers,security,web}.rs`; `crates/rizzy-proto/src/{lib,error,meta,limits}.rs`.
- RFC 9110 (HTTP semantics), RFC 6797 (HSTS), RFC 7239 (`Forwarded`) (L: general knowledge, not re-read for this ADR).
