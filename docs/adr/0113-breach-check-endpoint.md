# ADR 0113: Breach-check endpoint: path, JSON shapes, error codes, size caps, caching and the \`icons\` settings (erratum to ADRs 0053 and 0048)

- Status: Accepted
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M3

## Context

[ADR 0053](0053-hibp-breach-check-egress.md) (Accepted 2026-10-22) routes the Watchtower breach check ([ROADMAP §4.5](../ROADMAP.md#45-design-ui--ux--1password-feel-m3), Should, M3: "breached passwords via HIBP k-anonymity (only 5-char SHA-1 prefix leaves the device)") through the \`icons\` role. It fixes the digest flow (item 1), the one hardcoded upstream (item 2), the cache (item 4), the separate switch (item 5) and the per-source limit (item 8). It does not fix the wire contract. The 2026-10-25 gap review ([docs/reviews/2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md), row **M12**; raw finding **G05-25** [major] in [G05.md](../reviews/2026-10-25-raw/G05.md)) says so:

> "The ADR fixes the digest but not the wire contract every client (web, extension, rv, M3 native) must speak: path (\`POST /api/v1/icons/breach-range\` was invented), request/response JSON, the code for an upstream failure, the response byte/entry caps for an untrusted upstream body, cache TTL, and the setting names added to ADR 0028 item 12's frozen list. These were implementation choices, still owner-open since 2026-10-21; a second client implementation cannot be built from the text."

The code says the same of itself:

- \`crates/rizzy-proto/src/limits.rs\`: "Byte limit (this crate's choice): one upstream breach-check range response" (\`MAX_BREACH_RANGE_LEN\`) and "Count limit (this crate's choice): entries in one breach-check range response" (\`MAX_BREACH_RANGE_ENTRIES\`).
- \`crates/rizzy-server/src/config.rs\` module docs: "The names \`RIZZY_BREACH_CHECK\` and \`RIZZY_ICON_CACHE_DIR\` and the bounds are this crate's choice, reported to the owner."
- [docs/HANDOFF.md](../HANDOFF.md) (quoted by G05-25): "Judgment calls for the owner: the path name; the \`{"range":…}\` response; upstream failure answers 500; the setting names".

Two parts of ADR 0053's binding text also disagree with what shipped:

- **Item 8** says the limit falls back "to a conservative global cap where a trustworthy client IP is unavailable". The code (\`crates/rizzy-server/src/http/icons.rs\`, step 1) follows [ADR 0028](0028-api-v1-http-conventions.md) item 11 as amended instead: "when the peer is a trusted proxy and the header is missing, or a malformed element …, the request is \`400 invalid_request\`; it never falls back to the proxy's address". The global bucket exists, but only for a full source table (\`crates/rizzy-icon-proxy/src/limit.rs\`: "When the table is still full, a request is charged to one **global** bucket").
- **The proposed INV-77 paragraph** says "one pinned, config-named upstream host". The code compiles the host in (\`crates/rizzy-icon-proxy/src/breach.rs\`: "The host is compiled in, never taken from a request or a setting (ADR 0053 item 2)"), item 2 itself says "one hardcoded hostname", and the INV-77 row the acceptance wrote into [THREAT_MODEL §8](../THREAT_MODEL.md#8-security-invariants) already reads "one hardcoded upstream host, \`api.pwnedpasswords.com\`" (raw finding G05-28).

The settings sentence is the third gap. ADR 0028 item 12's settings clause, as replaced by [ADR 0048](0048-per-account-storage-quota.md) §1's last sentence, is the closed list of \`RIZZY_*\` names. \`config.rs\` reads names the list lacks: \`RIZZY_ADMIN_LISTEN\`, \`RIZZY_RECOVERY_WAIT_HOURS\`, \`RIZZY_BREACH_CHECK\`, \`RIZZY_ICON_CACHE_DIR\`, and ADR 0052 point 5's \`RIZZY_ICON_CACHE_TTL_SECS\` and \`RIZZY_ICON_CACHE_MAX_BYTES\` (ADR 0052 names them; the list does not). Three Proposed ADRs restate the same sentence: [ADR 0087](0087-invite-only-signup-tokens.md) §10.1 (\`invite\`), [ADR 0066](0066-share-email-otp-verification.md) (\`RIZZY_SMTP_URL\`, \`RIZZY_SMTP_FROM\`) and ADR 0106 (\`RIZZY_SOURCE_URL\`; on branch \`wip/adr-0106\`, not yet in this tree).

Everything in the Decision below was read from the code at \`f3492b2\` (V: \`crates/rizzy-proto/src/{breach,limits,http}.rs\`, \`crates/rizzy-icon-proxy/src/{breach,cache,limit,connect,allow}.rs\`, \`crates/rizzy-server/src/{config,server}.rs\`, \`crates/rizzy-server/src/http/{icons,api,mod,security}.rs\`, \`crates/rizzy-client/src/breach.rs\`, \`crates/rizzy-core/src/breach.rs\`, \`packages/core/src/index.ts\`, \`deploy/Caddyfile\`, \`fuzz/fuzz_targets/breach_range.rs\`). Facts about the upstream are the implementing change's reading of haveibeenpwned.com/API/v3 on 2026-10-22, recorded in CRYPTO.md §11.16; this session did not re-read that page, so they are **L** here.

## Decision

The endpoint is specified as shipped. Where the code was silent, the decision is the code's behaviour, written down. Nothing here changes code.

### 1. Path, role and routing

1. \`POST /api/v1/icons/breach-range\` (\`rizzy_proto\` constant \`ICONS_BREACH_RANGE\`). No session, no bearer token, no cookie, no \`Rizzy-Client\` requirement; the server ignores any it receives.
2. It is served only by the \`icons\` role, on that role's \`RIZZY_LISTEN\` listener, never by \`api\` (ADR 0053 item 1, [ADR 0010](0010-server-shape.md) §1–§2). The reverse proxy sends the path prefix \`/api/v1/icons/\` to the \`icons\` listener (\`deploy/Caddyfile\`: \`reverse_proxy /api/v1/icons/* {$RIZZY_ICONS_UPSTREAM:rizzy-vault:8080}\`).
3. The route is registered only when \`RIZZY_BREACH_CHECK=on\` (§6). When it is off, every method on the path is answered by the role's fallback, \`404 {"error":"not_found"}\`, before any rate-limit charge or body read. When it is on, a method other than \`POST\` is \`405 {"error":"invalid_request"}\` ([ADR 0028](0028-api-v1-http-conventions.md) item 3). When the \`icons\` role does not run at all, the proxy's target answers; with the compose default that is the \`api\` process, whose fallback answers an unknown \`/api/\` path \`404 not_found\` (ADR 0028 item 3: "also an unknown \`/api/\` path, and a role not running").

### 2. Request

4. Body: the JSON object \`{"prefix":"<P>"}\`, nothing else (\`BreachRangeRequest\`, \`#[serde(deny_unknown_fields)]\`). \`P\` is exactly 5 characters, each in \`0\`–\`9\` or \`A\`–\`F\` (uppercase only; \`5baa6\` is refused). A missing \`prefix\`, any other member, a duplicate \`prefix\` member, a non-string value, a wrong length, a lowercase or non-hex character, an empty body, or a body that is not JSON is \`400 invalid_request\`. JSON whitespace is allowed (serde_json). Known answer: the request for \`password\` is \`{"prefix":"5BAA6"}\`.
5. \`P\` is the first 5 characters of the uppercase hex SHA-1 of \`UTF-8(NFC(password))\`, as ADR 0053 item 1 and [CRYPTO.md §11.16](../CRYPTO.md#1116-breach-check-hibp-k-anonymity-m3) fix. An empty password is not checked: the client sends nothing.
6. \`Content-Type\` is not checked by the server; clients send \`application/json\`. \`Content-Length\`, when present, must be one well-formed value (otherwise \`400\`); over 1 MiB is \`413 payload_too_large\` before the body is read.
7. Body cap and deadline: ADR 0028 items 7–8 unchanged, 1 MiB (\`BODY_LIMIT\`), read deadline 30 s + 1 MiB ÷ 64 KiB/s = 46 s; past the cap \`413 payload_too_large\`; a missed deadline or an aborted body \`400 invalid_request\`.

### 3. Response

8. Success: \`200\`, \`Content-Type: application/json\`, \`Cache-Control: no-store\`, the role's common security headers, and the body \`{"range":"<R>"}\` (\`BreachRangeResponse\`). \`R\` is the upstream's range body, byte for byte, as one JSON string (CR and LF appear as \`\r\n\` escapes). Clients ignore unknown members of the response object.
9. Grammar of \`R\` (\`rizzy_proto::breach::parse_range\`), checked by the server before it caches or relays and again by every client when it deserialises:

   \`\`\`text
   range  = "" / line *( CRLF line ) [ CRLF ]
   line   = suffix ":" count
   suffix = 35( %x30-39 / %x41-46 )        ; uppercase hex, the digest after the prefix
   count  = 1*20DIGIT                       ; decimal, value at most 2^64 - 1, leading zeros allowed
   \`\`\`

   The empty string is a valid range (no entries). A lone \`CRLF\`, a bare \`LF\`, a lowercase suffix, a suffix of another length, an empty or non-digit count, or a count above \`u64::MAX\` is malformed.
10. Caps: \`R\` is at most **524,288 bytes** (\`MAX_BREACH_RANGE_LEN\`, 512 KiB, measured on the text before JSON escaping) and at most **8,192 entries** (\`MAX_BREACH_RANGE_ENTRIES\`). A client refuses a response past either cap, or with a malformed \`R\`, as it refuses any malformed answer: the check is "unavailable".
11. Padding: the server always asks the upstream for padding (§5), so \`R\` holds count-\`0\` entries. A count-\`0\` entry is "not found". The client compares every suffix with its own 35-character suffix in constant time, with no early exit (\`BreachDigest::count_in\`); if several entries match (a malformed but grammatical range), the last one's count wins. The verdict is the upstream's word relayed by a server the threat model does not trust: advice to the user, never a security decision (\`crates/rizzy-client/src/breach.rs\`; this is as far as this ADR goes on G05-26).

### 4. Errors

12. Every error is ADR 0028 item 3's \`{"error":"<code>"}\`, no message, no echo of input. No new code.

    | Status | Code | When |
    |---|---|---|
    | 400 | \`invalid_request\` | §2 refusals; a trusted proxy without a usable \`X-Forwarded-For\` (§7) |
    | 404 | \`not_found\` | breach check off (§1.3); \`icons\` role not running |
    | 405 | \`invalid_request\` | breach check on, method other than \`POST\` |
    | 413 | \`payload_too_large\` | body or declared \`Content-Length\` over 1 MiB |
    | 429 | \`rate_limited\` | §7; with \`Retry-After\` |
    | 500 | \`internal\` | any upstream failure (§5): resolve, refused address, connect, TLS, HTTP, a status other than \`200\`, a malformed or oversized or encoded body, the 10 s budget; or a failure to serialise the answer |

13. Order of checks: source (§7) → rate limit → body (§2.6–§2.7) → parse (§2.4) → range (cache, then upstream). So a refused body still costs a token, and a malformed request never reaches the cache or the upstream.
14. Clients treat \`rate_limited\` as "try again after \`Retry-After\` seconds" and every other failure, including a non-JSON answer from a proxy, as "breach check unavailable" (\`packages/core/src/index.ts\`, \`breachCheckUnavailable\`). They keep only \`200\` answers, in memory only, never on disk, bounded per session (web core: 512 prefixes).

### 5. Upstream fetch

15. One request per cache miss: \`GET /range/<P>\` to \`api.pwnedpasswords.com\` (\`UPSTREAM_HOST\`, \`RANGE_PATH\`), compiled in, never from a request or a setting (ADR 0053 item 2, INV-77). HTTP/1.1 over TLS 1.3 only, ALPN \`http/1.1\`, certificate verified against the hostname with \`rizzy-icon-proxy\`'s own TLS configuration (CRYPTO.md §3, "Transport (\`rizzy-icon-proxy\`)"). Port 443 only; no plain-HTTP fallback (the favicon path's port-80 retry does not apply).
16. Connection: resolve \`(host, 443)\` once with the OS resolver within 5 s (\`RESOLVE_TIMEOUT\`), at most 32 answers (\`MAX_ADDRESSES\`); take the first address the INV-51 allow-list accepts, refuse if none; TCP to exactly that address within 5 s (\`CONNECT_TIMEOUT\`), never resolving again.
17. Request headers, exactly: \`Host: api.pwnedpasswords.com\`, \`User-Agent: rizzy-vault\` (no version, nothing per instance), \`Add-Padding: true\`, \`Connection: close\`. No \`Accept-Encoding\`, no other header. (Upstream behaviour, L: it refuses a request without a \`User-Agent\`, and with \`Add-Padding\` pads every answer to 800–1,000 lines of count-\`0\` entries.)
18. Answer accepted only if: status \`200\` (no redirect is followed); every \`Content-Encoding\` value, if any, is \`identity\` (case-insensitive), so no decompression ever runs; a \`Content-Length\`, if present, parses and is at most 524,288; the body, read through a 524,288-byte limit, is UTF-8 and satisfies §3.9–§3.10. Anything else is a failure (§4) and is **not cached**.
19. Budget: the whole fetch, including the wait for a fetch slot, connect, TLS, request and body, has **10 s** (\`FETCH_BUDGET\`). At most **8** upstream fetches run at once per \`icons\` process (\`MAX_CONCURRENT_FETCHES\`); further misses wait for a slot inside their own budget. Concurrent misses for the same prefix are not coalesced: each fetches.

### 6. Caching and the settings

20. Cache entry: \`breach-<P>.txt\` in \`RIZZY_ICON_CACHE_DIR\`, holding \`R\` exactly; keyed by prefix only, shared by all users, nothing per request or per user written (ADR 0053 item 4, INV-77). It shares the directory, the TTL and the byte cap with favicon entries (ADR 0052 point 5): an entry older than \`RIZZY_ICON_CACHE_TTL_SECS\` by file modification time is a miss; before each write the oldest files are removed until the new entry fits under \`RIZZY_ICON_CACHE_MAX_BYTES\`; writes are a temporary file renamed over the final name. A cached file over 524,288 bytes is a miss without being read; a cached entry that no longer parses is removed and fetched again; a failed cache write still serves the answer.
21. Settings, read by \`config.rs\` in every role (an invalid value refuses the start of any role) and used only by \`icons\`:

    | Setting | Values | Default |
    |---|---|---|
    | \`RIZZY_BREACH_CHECK\` | \`off\` or \`on\`, exactly (case-sensitive); anything else refuses the start | \`off\` |
    | \`RIZZY_ICON_CACHE_DIR\` | a non-empty path; created if missing when \`icons\` starts, the start refused if it cannot be | \`/cache\` |
    | \`RIZZY_ICON_CACHE_TTL_SECS\` | whole seconds, 60 to 31,536,000 (365 days) | 1,209,600 (14 days) |
    | \`RIZZY_ICON_CACHE_MAX_BYTES\` | whole bytes, at least 1,048,576 (1 MiB), no maximum | 268,435,456 (256 MiB) |

    \`RIZZY_BREACH_CHECK\` is ADR 0053 item 5's separate switch (owner answer 2). The last two are ADR 0052 point 5's names, restated, not changed. The \`icons\` role's other rules stay as ADR 0010 and \`config.rs\` have them: it runs alone, and refuses to start with \`RIZZY_DATABASE_URL\` set or with the secrets file or the SQLite database visible.

### 7. Rate limit

22. Per source, before any body byte is read: a GCRA token bucket of **30 per minute, burst 10** (\`PER_MINUTE\`, \`BURST\`; ADR 0052 owner answer 5). The breach check has **its own bucket**, separate from the favicon endpoint's bucket with the same numbers. The source is ADR 0028 item 11's: the peer address, or the first non-proxy address from the right of \`X-Forwarded-For\` when the peer is in \`RIZZY_TRUSTED_PROXIES\`; an IPv4 address or an IPv6 /64. A trusted peer with no usable header is \`400 invalid_request\`, never charged to the proxy's address.
23. At most 65,536 sources are tracked (\`MAX_SOURCES\`); refilled buckets are dropped first; when the table is still full, the request is charged to one global bucket with the same rate. Counters are in memory only. With several \`icons\` replicas the effective limit multiplies, as ADR 0052 point 6 accepts.
24. \`429\` carries \`Retry-After\`: the bucket's wait rounded up to whole seconds, at least 1.

### 8. Logging

25. The access line (method, route template \`/api/v1/icons/breach-range\`, status, duration); on an upstream failure one \`warn\` line \`breach_upstream_failed\` with \`route\` and \`reason\` from the fixed set \`resolve\`, \`refused_address\`, \`connect\`, \`tls\`, \`http\`, \`status\`, \`malformed\`, \`timeout\`; ADR 0028 item 8's \`body_read_timeout\` / \`client_aborted\` lines with the route only. Never the prefix, the range, a header, an address or a body. \`HashPrefix\`, \`RangeBody\` and \`BreachService\` print no content from \`Debug\`.

### 9. What this ADR supersedes

#### 9.1 ADR 0053 Decision item 8, in full

Replacement, in full:

> 8. **Per-source rate limiting.** [ADR 0010 §1](0010-server-shape.md) gives \`icons\` inbound traffic as "public, through the proxy": the new endpoint is reachable by anyone who reaches the proxy, not only this instance's users. [THREAT_MODEL A15](../THREAT_MODEL.md#a15-other-users-and-the-anonymous-internet) already lists "Using the \`icons\` role as an open proxy" as a capability of that adversary and "The role is rate-limited" as its existing mitigation for favicon fetches. This endpoint has the same limit, 30 per minute with a burst of 10, in its own per-source bucket, charged before the body is read ([ADR 0113](0113-breach-check-endpoint.md) §7). The source is [ADR 0028](0028-api-v1-http-conventions.md) item 11's: the peer address, or the client named by a trusted proxy's \`X-Forwarded-For\`; when a trusted proxy names no usable client, the request is \`400 invalid_request\`, never charged to the proxy's address. One global bucket with the same rate takes the requests that arrive while the in-memory source table is full. See Risks.

#### 9.2 ADR 0053, the "Proposed INV-77" paragraph under "On acceptance", in full

Replacement, in full (it matches the INV-77 row already in THREAT_MODEL §8):

> **Proposed INV-77** (allocated across the 2026-10-11 batch in ADR-number order. Provisional: if ADRs are accepted out of order, the owner renumbers at acceptance.): *The \`icons\` role's breach-check traffic connects only to one hardcoded upstream host, \`api.pwnedpasswords.com\`, over HTTPS, under the same SSRF allow-list and DNS pinning as INV-51; clients send only a 5-hex-char SHA-1 prefix in the request payload, with no account identity, session token or item id in that payload (IP- and timing-level correlation through the shared proxy is a separately accepted risk, not covered by this invariant); the endpoint is rate-limited per source alongside the existing favicon-fetch limit; responses are cached by prefix with no per-user log; and the role keeps the no-DB-credentials, no-server-secrets properties ADR 0010 §2 already requires of it.*

ADR 0053's other items, its supersession of ADR 0010 §1, its owner answers and its Consequences stay binding unchanged. Items 1, 2, 4 and 5 are not contradicted by the code; §1–§6 above add the detail they left to the implementation.

#### 9.3 ADR 0048 §1, last sentence (the binding text of ADR 0028 item 12's settings clause)

Word for word:

> Settings \`RIZZY_ROLES\`, \`RIZZY_ORIGIN\`, \`RIZZY_LISTEN\` (default \`127.0.0.1:8080\`), \`RIZZY_DATA_DIR\` (\`/data\`), \`RIZZY_DATABASE_URL\`, \`RIZZY_SECRETS_FILE\` (\`/run/rizzy-secrets/secrets.json\`), \`RIZZY_SIGNUP\` (\`closed\`|\`open\`), \`RIZZY_TRUSTED_PROXIES\`, \`RIZZY_LOG_LEVEL\`, \`RIZZY_WORKER_INTERVAL_SECS\`, \`RIZZY_MAX_UPLOAD_BYTES\`, \`RIZZY_ACCOUNT_QUOTA_BYTES\`.

Replacement, in full, if none of ADRs 0087, 0066 and 0106 is Accepted when this ADR is:

> Settings \`RIZZY_ROLES\`, \`RIZZY_ORIGIN\`, \`RIZZY_LISTEN\` (default \`127.0.0.1:8080\`), \`RIZZY_DATA_DIR\` (\`/data\`), \`RIZZY_DATABASE_URL\`, \`RIZZY_SECRETS_FILE\` (\`/run/rizzy-secrets/secrets.json\`), \`RIZZY_SIGNUP\` (\`closed\`|\`open\`), \`RIZZY_TRUSTED_PROXIES\`, \`RIZZY_LOG_LEVEL\`, \`RIZZY_WORKER_INTERVAL_SECS\`, \`RIZZY_MAX_UPLOAD_BYTES\`, \`RIZZY_ACCOUNT_QUOTA_BYTES\`, \`RIZZY_BREACH_CHECK\` (\`off\`|\`on\`), \`RIZZY_ICON_CACHE_DIR\` (\`/cache\`), \`RIZZY_ICON_CACHE_TTL_SECS\` (14 days), \`RIZZY_ICON_CACHE_MAX_BYTES\` (256 MiB) ([ADR 0113](0113-breach-check-endpoint.md) §6).

**Coordination with ADRs 0087, 0066 and 0106 (all Proposed).** Whichever is accepted later restates the earlier ones' additions, as ADR 0087 §10.1 and ADR 0106 §7.2 already say. If any is Accepted before this ADR, this ADR's replacement is the sentence above with that ADR's addition made, exactly:

- ADR 0087 Accepted earlier: \`RIZZY_SIGNUP\` (\`closed\`|\`open\`) becomes \`RIZZY_SIGNUP\` (\`closed\`|\`invite\`|\`open\`), or \`RIZZY_SIGNUP\` (\`closed\`|\`invite\`|\`open\`, default \`invite\`) if the owner accepted ADR 0087's open question 2.
- ADR 0066 Accepted earlier: \`RIZZY_SMTP_URL\`, \`RIZZY_SMTP_FROM\` are inserted after \`RIZZY_ACCOUNT_QUOTA_BYTES\`. (ADR 0066 quotes ADR 0028's older clause, without \`RIZZY_ACCOUNT_QUOTA_BYTES\`; ADR 0048's setting stays.)
- ADR 0106 Accepted earlier: \`RIZZY_SOURCE_URL\` (default: this build's upstream source, [ADR 0106](0106-agpl-source-url.md) §1–§2) is inserted after those, before \`RIZZY_BREACH_CHECK\`.

With all three earlier (and ADR 0087's open question 2 answered "no"), the replacement is, in full:

> Settings \`RIZZY_ROLES\`, \`RIZZY_ORIGIN\`, \`RIZZY_LISTEN\` (default \`127.0.0.1:8080\`), \`RIZZY_DATA_DIR\` (\`/data\`), \`RIZZY_DATABASE_URL\`, \`RIZZY_SECRETS_FILE\` (\`/run/rizzy-secrets/secrets.json\`), \`RIZZY_SIGNUP\` (\`closed\`|\`invite\`|\`open\`), \`RIZZY_TRUSTED_PROXIES\`, \`RIZZY_LOG_LEVEL\`, \`RIZZY_WORKER_INTERVAL_SECS\`, \`RIZZY_MAX_UPLOAD_BYTES\`, \`RIZZY_ACCOUNT_QUOTA_BYTES\`, \`RIZZY_SMTP_URL\`, \`RIZZY_SMTP_FROM\`, \`RIZZY_SOURCE_URL\` (default: this build's upstream source, [ADR 0106](0106-agpl-source-url.md) §1–§2), \`RIZZY_BREACH_CHECK\` (\`off\`|\`on\`), \`RIZZY_ICON_CACHE_DIR\` (\`/cache\`), \`RIZZY_ICON_CACHE_TTL_SECS\` (14 days), \`RIZZY_ICON_CACHE_MAX_BYTES\` (256 MiB) ([ADR 0113](0113-breach-check-endpoint.md) §6).

If this ADR is Accepted first, ADR 0087's, ADR 0066's and ADR 0106's replacements, when accepted, keep "\`RIZZY_BREACH_CHECK\` (\`off\`|\`on\`), \`RIZZY_ICON_CACHE_DIR\` (\`/cache\`), \`RIZZY_ICON_CACHE_TTL_SECS\` (14 days), \`RIZZY_ICON_CACHE_MAX_BYTES\` (256 MiB) ([ADR 0113](0113-breach-check-endpoint.md) §6)" at the end of the list. List order carries no meaning. None of the four holds a secret, so ADR 0028 item 12's secret-boundary passage is untouched.

ADR 0048 §1's other sentences and ADR 0028 item 12's other clauses ("; from the environment or a \`NAME=value\` file …", the secret boundary, the *Why*) stay binding.

### 10. What this ADR does not decide

- **\`RIZZY_ADMIN_LISTEN\` and \`RIZZY_RECOVERY_WAIT_HOURS\`.** \`config.rs\` reads both and the settings list lacks both, but neither is a breach or icon setting. This ADR does not add them; the ADR that does follows the coordination rule of §9.3 and keeps this ADR's four names.
- **The accepted-risk row for IP and timing correlation** (G05-27) and the website-icons opt-in ([ADR 0099](0099-website-icons-opt-in.md), Proposed, which drafts that AR row for hosts and breach prefixes alike). Nothing here conflicts with ADR 0099: it gates the favicon requests, not this endpoint.
- **No new invariant.** INV-77 covers the endpoint; INV-126 is not used.

## Consequences

### Positive

- A second client (extension, \`rv\`, M3 native) can be built from §1–§8 alone, and the server's choices stop being "this crate's choice".
- ADR 0053's text agrees with the code and with THREAT_MODEL's INV-77 row; the settings list names every \`icons\` setting \`config.rs\` reads.
- No code change: the shipped behaviour, its tests and its fuzz target (\`breach_range\`) already match.

### Negative

- An upstream outage is \`500 internal\`, the same code as a server bug. Clients cannot tell them apart and show "unavailable" for both. A distinct code would reopen ADR 0028 item 3's closed table (Open question 1).
- A cached range can be up to 14 days old by default: a password breached and published within that window reads "not found" until the entry expires (Open question 2).
- The endpoint relays bodies of up to 512 KiB to anyone within the rate limit; at 30 per minute a source can pull at most about 15 MiB per minute of cached ranges per replica.

### Risks

- The 512 KiB and 8,192 caps sit far above the about 50 KB answers seen in practice (L: the upstream publishes no maximum). If the upstream ever pads beyond them, every check reads "unavailable" until a code change raises the caps; the failure is safe (no false "not found"), and the \`malformed\` log reason names it.
- A malicious server can hide or invent a breach (§3.11). Unchanged from ADR 0053; the client presents the verdict as advice.

## Alternatives considered

- **\`GET /api/v1/icons/breach-range/<P>\`** (the upstream's shape). Rejected: a path segment lands in proxy access logs, which INV-77's "no per-user log" cannot reach; a \`POST\` body does not.
- **Relaying \`text/plain\` as the upstream sends it.** Rejected: every \`/api/\` answer is JSON with the uniform error body (ADR 0028 item 3); one JSON string keeps the text unmodified and the client parser shared.
- **Parsing server-side and returning a JSON array of entries.** Rejected: ADR 0053 item 1 says "relayed back unmodified", and the client must re-check the format anyway, since it does not trust the server.
- **A separate breach cache directory and TTL.** Not taken: ADR 0010 §4 gives \`icons\` one cache volume and ADR 0052 point 5 one TTL and cap; Open question 2 asks whether the TTL should differ.

## On acceptance

The change that accepts this ADR makes these edits. None is made now.

- ADR 0053's status line names this ADR (item 8; the "Proposed INV-77" paragraph); ADR 0048's names it (§1, last sentence). The owner sets both.
- This ADR's README row moves to the owner's status.
- [CRYPTO.md §11.16](../CRYPTO.md#1116-breach-check-hibp-k-anonymity-m3): the **Request** and **Response** bullets gain "(\`POST /api/v1/icons/breach-range\`, [ADR 0113](adr/0113-breach-check-endpoint.md))" and the caps 512 KiB / 8,192 entries.
- [THREAT_MODEL §7.11](../THREAT_MODEL.md), the I row: "rate-limited per source" gains "in its own bucket ([ADR 0113](adr/0113-breach-check-endpoint.md) §7)". The INV-77 row needs no edit.
- \`crates/rizzy-proto/src/limits.rs\`: "this crate's choice" on \`MAX_BREACH_RANGE_LEN\` and \`MAX_BREACH_RANGE_ENTRIES\` becomes "[ADR 0113] §3"; \`crates/rizzy-server/src/config.rs\`: "The names … are this crate's choice, reported to the owner" becomes a reference to ADR 0113 §6. Doc comments only.
- [docs/HANDOFF.md](../HANDOFF.md): the breach-check "Judgment calls for the owner" line is closed with this ADR's number.
- [docs/self-hosting.md](../self-hosting.md): no edit; its settings table already lists all four §6 settings with these defaults and bounds (checked at `f3492b2`).

## Implementation plan

The endpoint shipped; the work is tests that pin the contract where none does today, then the doc edits above. Each test below is added only where an existing one does not already cover it.

1. \`rizzy-proto\` (\`breach.rs\` tests): a duplicate \`prefix\` member is refused; \`""\` parses to no entries and \`"\r\n"\` is malformed; a count of \`18446744073709551615\` passes and \`18446744073709551616\` fails; a range of exactly 8,192 entries passes and 8,193 fails.
2. \`rizzy-icon-proxy\` (\`breach.rs\` tests): the request carries exactly the four headers of §5.17 and no \`Accept-Encoding\`; \`Content-Encoding: gzip\` and a \`Content-Length\` over 524,288 are refused before the body is read and are not cached; a \`301\` is refused and not followed; a cached file over the cap is a miss.
3. \`rizzy-server\` (\`http/icons.rs\` tests): with the breach check off, \`GET\` on the path is \`404 not_found\` (not \`405\`) and charges no token; a \`429\` carries \`Retry-After\` ≥ 1; a \`200\` carries \`Cache-Control: no-store\`.
4. \`rizzy-server\` (\`config.rs\` tests): \`RIZZY_BREACH_CHECK=On\` refuses the start of the \`api\` role too; an empty \`RIZZY_ICON_CACHE_DIR\` refuses; TTL 59 and 31,536,001 refuse, 60 and 31,536,000 pass; max bytes 1,048,575 refuses.
5. \`cargo test -p rizzy-proto -p rizzy-icon-proxy -p rizzy-server --locked\`, \`cargo check --manifest-path fuzz/Cargo.toml --locked --bins\`, then the full gate.

## Open questions for the owner

1. **Upstream failure: \`500 internal\`, or a new \`503\` code?** Recommendation: keep \`500 internal\` (§4). ADR 0028 item 3's table is closed on purpose, clients already map every non-\`rate_limited\` failure to "unavailable", and the \`breach_upstream_failed\` log line tells the operator which it was. A new code would be an ADR 0028 change for no client-visible gain.
2. **Should breach ranges have their own, shorter cache TTL?** Today they share \`RIZZY_ICON_CACHE_TTL_SECS\` (default 14 days) with favicons. Recommendation: keep one TTL for now. A shorter one (for example 24 hours, a new \`RIZZY_BREACH_CACHE_TTL_SECS\`) narrows the stale window but sends more prefixes upstream; the upstream's update cadence was not checked (U). Revisit if the owner wants fresher answers.

## References

- [ADR 0053](0053-hibp-breach-check-egress.md) items 1–8, owner answers; [ADR 0052](0052-icon-proxy-role.md) points 5–6, owner answer 5; [ADR 0010](0010-server-shape.md) §1–§4; [ADR 0028](0028-api-v1-http-conventions.md) items 3, 7, 8, 11, 12; [ADR 0048](0048-per-account-storage-quota.md) §1; [ADR 0020](0020-partial-supersession.md) point 9.
- Proposed: [ADR 0087](0087-invite-only-signup-tokens.md) §10.1, [ADR 0066](0066-share-email-otp-verification.md), ADR 0106 (branch \`wip/adr-0106\`), [ADR 0099](0099-website-icons-opt-in.md).
- [CRYPTO.md §11.16](../CRYPTO.md#1116-breach-check-hibp-k-anonymity-m3); [THREAT_MODEL](../THREAT_MODEL.md) INV-51, INV-77, A15, §7.11.
- Gap review: [2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md) M12; [raw G05](../reviews/2026-10-25-raw/G05.md) G05-25 (also G05-26, G05-28).
- Upstream API: haveibeenpwned.com/API/v3, "Searching by hash range" and "Add-Padding" (L: read by the implementing change on 2026-10-22, not re-read here).
