# ADR 0104: Metrics endpoint: `GET /metrics` on the admin listener, a closed Prometheus metric set, and an optional scrape token

- Status: Accepted
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M3
- Supersedes: [ADR 0048](0048-per-account-storage-quota.md) §1, its last sentence (the settings list, the binding text of [ADR 0028](0028-api-v1-http-conventions.md) item 12's settings clause), in part, on acceptance. §11 below quotes it and gives the full replacement.

## Context

**Trigger.** The 2026-10-25 ADR gap review ([summary](../reviews/2026-10-25-adr-gap-review.md), row M6: "**Metrics endpoint content and access.** | ROADMAP M3; ADR 0060 answer 4 places it | G06-16, G10-20"). The owner said "start" on 2026-10-25, after the review.

- **G06-16 [major]** ([raw](../reviews/2026-10-25-raw/G06.md)): "The M3 metrics endpoint is placed on the admin listener by owner answer 4 but no ADR says what it serves or who may read it." It goes on: "Metrics can leak per-account metadata (request counts, sizes, timings: THREAT_MODEL §3.4 material) … Its path, authentication, metric set and label rules (no account ids or login names) are undecided." Its suggested fix: "path, no-auth or token, a closed metric list with no per-account labels, and a canary test (INV-48) over its output."
- **G10-20 [major]** ([raw](../reviews/2026-10-25-raw/G10.md)): "'Metrics endpoint (Prometheus)', M3, has no ADR for what it exposes … per-account or per-route counters, timing histograms and label cardinality can leak who uses the instance and when. These are metadata the zero-knowledge goals care about. Where it listens is decided; what it may reveal is not." It notes that THREAT_MODEL has no metrics row or invariant.

**What is already decided (binding).**

- [ROADMAP](../ROADMAP.md) §4.9: "| S | Metrics endpoint (Prometheus) | M3 |": a Should, M3, Prometheus named.
- [ADR 0010](0010-server-shape.md) §1 (Accepted): "**Admin API and metrics** bind a separate listener. The reverse proxy does not expose it by default."
- [ADR 0060](0060-admin-panel-stack-boundary.md) (Accepted) §2: `admin_listen` defaults to `127.0.0.1:8081`, "never `0.0.0.0`", always binds while the `api` role runs, and "Compose examples do not publish `admin_listen`'s port". Owner answer 4: "The M3 metrics endpoint shares `admin_listen`."
- [THREAT_MODEL](../THREAT_MODEL.md) §7.14: "Exposes internal endpoints (admin, metrics). | Admin and metrics on a separate listener, not proxied by default." §7.12's SSRF row already lists the "admin and metrics listener" as an internal target the `icons` role must not reach (INV-51).

**What the code does today.** `crates/rizzy-server/src/http/admin_panel/mod.rs` serves a plain-text `404` for every path, and its module doc says "the metrics endpoint that answer 4 places on this listener has no ADR deciding what it serves". `crates/rizzy-server/tests/admin_listener.rs` asserts that `GET /metrics` on the admin listener is that `404` under `ADMIN_CSP`. No metrics code exists. [HANDOFF](../HANDOFF.md) lists "`metrics-exporter-prometheus` or hand-rolled" as an open instrumentation choice.

**Related Proposed text (not binding).** [ADR 0085](0085-admin-authentication-bootstrap.md) §5 point 2 adds a `Host` check for `/admin` only and says "The metrics endpoint that ADR 0060 owner answer 4 puts on this listener is outside `/admin` and not affected (scrapers often address it by a service name)." This ADR makes its own rule for `/metrics` (§4) and does not depend on ADR 0085. [ADR 0087](0087-invite-only-signup-tokens.md) and [ADR 0066](0066-share-email-otp-verification.md) (both Proposed) supersede the same settings sentence this ADR does (§11). [ADR 0090](0090-per-account-security-event-log.md) (Proposed) is a per-account event log; nothing in it is exported here.

**Forces.**

- *Metadata.* [THREAT_MODEL §3.4](../THREAT_MODEL.md#34-what-the-server-holds-by-sync-mode) lists what the server holds. Its metadata rows ("Item IDs, op counts, ciphertext sizes, timestamps | Visible"; "Per-device version vectors and cursors"; "IPs, user agents, connection times | Logs"; "Domains requested from `icons`"; "Account identifier") are exactly what a careless exporter would turn into labels. A scraped series also escapes the server's own log retention: it lives as long as the operator's Prometheus keeps it.
- *Cardinality.* A label value taken from a request (a path, a `Host`, a user agent) is both a leak and an unbounded series count; Prometheus memory grows with the number of series (L: Prometheus documentation, "Instrumentation" and "Metric and label naming", not re-read for this draft).
- *Who reads it.* The scraper is often a different, less trusted principal than the instance admin (a shared monitoring stack). It must learn nothing that the admin panel gates.
- *Existing rules.* INV-48 (logs hold no secrets), INV-73 (the access log names a fixed route template, never a path), the access-log `RouteName` mechanism (`http/mod.rs`), no `unwrap`/`panic!` in non-test code, untrusted input size-limited.

## Decision

### 1. Path, listener, switch

1. One endpoint: `GET /metrics` on the admin listener (`RIZZY_ADMIN_LISTEN`, ADR 0060 §2). It exists only in a process whose admin listener binds, that is one running the `api` role. Processes running only `web`, `worker` or `icons` serve no metrics at M3 (open question 1).
2. A new setting `RIZZY_METRICS`, `off` (default) or `on`; any other value refuses startup with a message naming the setting. With `off`, `/metrics` is the admin listener's existing plain-text `404` (the current `admin_listener.rs` assertion stays true). With `on`, §4 applies.
3. The public listener (`RIZZY_LISTEN`) never serves metrics: `/metrics` there stays the web role's `404` (INV-73 route table) or, without the `web` role, the plain `404`; `/api/metrics` and the like are the API's `404 not_found`. No `/api/v1` endpoint exposes any metric.
4. The match is on the request path, byte for byte `/metrics`; the query string is ignored and never read. `/metrics/`, `/Metrics` and `/metrics/x` are the listener's `404`.

### 2. Format (versioned)

1. **Prometheus text exposition format, version 0.0.4** (L: Prometheus "Exposition formats" documentation, not re-read for this draft). `Content-Type: text/plain; version=0.0.4; charset=utf-8`. No OpenMetrics, no protobuf; the `Accept` header is ignored; no compression (`Accept-Encoding` ignored).
2. Headers besides `Content-Type`: `Cache-Control: no-store`, plus what every admin-listener answer carries (`ADMIN_CSP` and the common headers, ADR 0060). Status `200`.
3. **Byte layout.** UTF-8, `\n` line ends, no blank lines, no trailing whitespace, the body ends with `\n`. For each family in §3's table order: `# HELP <name> <help>` (the help text in the table, verbatim), then `# TYPE <name> <type>`, then its samples. Samples of a family appear in the table's label-value order (the first label varies slowest). No timestamps on samples. Label pairs are written `name="value"` in the column order of the table, comma-separated, no spaces. A histogram's samples are its `_bucket` lines in `le` order, then `_sum`, then `_count`.
4. **Numbers.** Counters and integer gauges: unsigned decimal, no sign, no exponent, no leading zeros (`0` for zero). Histogram `le` values: the exact strings of §3 row 6. `_sum` in seconds: the stored microsecond total divided by 10⁶, written with exactly six decimals (`12.000345`).
5. **Schema version.** The family set, names, types, help texts, label names and label value sets of §3 are *metrics schema 1*, exported as `rizzy_metrics_schema 1`. Adding, removing or renaming a family, a label or a label value, or changing a type or a bucket, needs a new ADR and bumps the number by one. An API endpoint added to `Endpoint::ALL` adds a `route` value (§3 row 5) and so bumps it too; the ADR that adds the endpoint says so.

### 3. The closed metric set (schema 1)

Every family below, and nothing else, is exported. Every series listed is present in every answer from process start, initialised to `0` (gauges to their current value), so **the set of series in the output is a function of the build alone**, never of traffic, data or configuration. That is itself a privacy rule: a series appearing cannot reveal that some route was used for the first time.

| # | Name | Type | Labels and their closed values | Value | Help text (verbatim) |
|---|---|---|---|---|---|
| 1 | `rizzy_metrics_schema` | gauge | none | `1` | `Metrics schema version (ADR 0104).` |
| 2 | `rizzy_build_info` | gauge | `version`: `env!("CARGO_PKG_VERSION")` | `1` | `Server build.` |
| 3 | `process_start_time_seconds` | gauge | none | Unix seconds at process start, whole seconds | `Start time of the process since unix epoch in seconds.` |
| 4 | `rizzy_role_active` | gauge | `role`: `api`, `web`, `worker`, `icons` | `1` if this process runs the role, else `0` (`icons` is always `0`: it runs alone) | `Roles this process runs.` |
| 5 | `rizzy_http_requests_total` | counter | `route`: the route table *R* below; `status_class`: `1xx`, `2xx`, `3xx`, `4xx`, `5xx` | requests answered | `HTTP requests answered, by fixed route name and status class.` |
| 6 | `rizzy_http_request_duration_seconds` | histogram | none (`le` only): `0.005`, `0.01`, `0.025`, `0.05`, `0.1`, `0.25`, `0.5`, `1`, `2.5`, `5`, `10`, `+Inf` | public-listener requests, request start to response head | `Public listener request duration.` |
| 7 | `rizzy_http_requests_in_flight` | gauge | none | public-listener requests in progress | `Public listener requests in progress.` |
| 8 | `rizzy_api_errors_total` | counter | `code`: `client_too_old`, `api_version_gone`, `invalid_request`, `payload_too_large`, `unauthorized`, `second_factor_required`, `fresh_session_required`, `rate_limited`, `not_found`, `state_conflict`, `stale_epoch`, `record_conflict`, `prev_seq_mismatch`, `setup_retired`, `credentials_stale`, `quota_exceeded`, `internal` | uniform error bodies sent under `/api/` | `API error responses, by error code.` |
| 9 | `rizzy_worker_leader` | gauge | none | `1` while this process holds the worker leader lock, else `0` | `Whether this process is the worker leader.` |
| 10 | `rizzy_worker_runs_total` | counter | none | completed worker runs (one per `worker_run` log line) | `Completed worker runs.` |
| 11 | `rizzy_worker_last_run_timestamp_seconds` | gauge | none | Unix seconds of the last completed run, `0` before the first | `End time of the last completed worker run.` |
| 12 | `rizzy_worker_work_total` | counter | `kind`: `auth_rows_purged`, `totp_rows_resealed`, `totp_reseal_failures`, `epochs_ended`, `items_compacted`, `bodies_deleted`, `snapshots_dropped`, `compaction_failures` | sum of that field over all `worker_run` lines | `Worker work done, by kind.` |

Row 8's values are every `rizzy_proto::error::ErrorCode` variant in declaration order, by wire name, except the decode-only `unknown`. Row 12's values are the `worker_run` log line's fields (`crates/rizzy-server/src/worker.rs`) in that line's order.

**Route table *R*** (row 5), in this order: every `Endpoint::ALL` path in `Endpoint::ALL` order (`crates/rizzy-server/src/http/api.rs`; 42 today, for example `/api/v1/register/start`), then `/api/meta`, `web`, `unmatched`, `method_not_allowed`, `admin`, `metrics`. These are exactly the access log's `route` values (`RouteName`, INV-73), which are already fixed compile-time strings. A response whose `RouteName` is not in *R* (a future bug) is counted as `unmatched`, never as a new series. `admin` and `metrics` are the admin listener's; every other value is the public listener's.

**Semantics.**

- Row 5 counts every answered request on both listeners, once, in the shared `access_log` middleware (`http/mod.rs`), with the same route name and status that log line records. `status_class` is the status's hundreds digit; a status outside 100–599 cannot be produced by the server and would be counted as `5xx`.
- Rows 6 and 7 cover the public listener only (the admin listener's traffic is the scraper and the operator). Row 7's increment is paired with a drop guard, so a request future cancelled by a client disconnect or a timeout still decrements it. Row 6 observes the same duration the access log's `duration_ms` measures, stored in microseconds.
- Row 8 is incremented in the one place the uniform error body is built (`failure_response` and `rate_limited_response` in `http/api.rs`), by the code's wire name.
- Rows 9–12 move only in a process running the `worker` role; elsewhere they stay `0`. Rows 10–12 are updated from the same `WorkerReport` that writes the `worker_run` log line, at the same moment.
- Rows 2 and 3 carry nothing that `GET /api/meta` does not already publish (the version) or a process listing does not show (the start time).

### 4. Access

1. **Token (optional).** A new setting `RIZZY_METRICS_TOKEN_SHA256`: exactly 64 lowercase hex characters, the SHA-256 of the scrape token's ASCII text. Any other form refuses startup with a message naming the setting. The setting holds a verifier, not a secret: the token has 256 bits of entropy, so its hash cannot be inverted, and it is the same kind of value as the session-token hashes the server already keeps (THREAT_MODEL §3.4 "Session tokens | Hashes only"). ADR 0028 item 12's "no setting holds a key" stays true.
2. **Token format.** 32 bytes from the OS RNG, encoded base64url without padding: exactly 43 characters of `[A-Za-z0-9_-]`. A new CLI subcommand `rizzy-vault metrics-token` generates one and prints exactly two lines to stdout, `token: <43 chars>` and `RIZZY_METRICS_TOKEN_SHA256=<64 hex>`; it writes nothing to disk or to the log. The operator puts the token in the scraper (Prometheus `authorization: { type: Bearer, credentials_file: ... }`, L: Prometheus `scrape_config` documentation) and the hash in the server's configuration. Rotation is replacing the setting and restarting; there is one token at a time.
3. **Checking a request** with the token set, in this order, before any metric is read:
   1. Exactly one `Authorization` header, at most 256 bytes, of the form `Bearer ` followed by exactly 43 base64url characters. Anything else, or no header, answers `401`.
   2. SHA-256 of those 43 ASCII bytes, compared with the configured digest using `subtle::ConstantTimeEq`. A mismatch answers `401`.
   3. No `Host` check: the token defeats DNS rebinding (a rebinding page does not know it), and scrapers address the listener by service names.
4. **Without a token**, a request passes only when its `Host` header is an IP literal or `localhost`, each with or without a port, ASCII case-insensitive; otherwise `421`. This keeps a DNS-rebinding page in an operator's browser from reading the endpoint through a name it controls.
5. **Startup refusals.** With `RIZZY_METRICS=on`, a non-loopback `RIZZY_ADMIN_LISTEN` (`!addr.ip().is_loopback()`) and no `RIZZY_METRICS_TOKEN_SHA256`, the server refuses to start with "RIZZY_METRICS=on with a non-loopback RIZZY_ADMIN_LISTEN needs RIZZY_METRICS_TOKEN_SHA256". `RIZZY_METRICS_TOKEN_SHA256` set while `RIZZY_METRICS=off` is accepted and unused, with one warning log line naming the setting, never its value.
6. **Methods.** Only `GET`. Any other method on `/metrics` answers `405` with `Allow: GET`. `HEAD` is not served.
7. **Error answers.** All plain text under the admin-listener headers, never JSON (the admin listener has no API, ADR 0060 §2): `401` with body `unauthorized\n` and `WWW-Authenticate: Bearer realm="rizzy-metrics"`; `421` with body `misdirected request: use an IP address or localhost, or set RIZZY_METRICS_TOKEN_SHA256\n`; `405` with body `method not allowed\n`; `404` with the existing body `not found\n`. No body echoes the presented token or `Host`.
8. **Logging.** Each `/metrics` request writes the one access-log line, route `metrics`. The `Authorization` header, the token, the digest and the `Host` value are never logged (INV-48). The CLI never logs the token.
9. **Rate.** No rate limit: a scrape reads atomics only, takes no lock across an `.await`, runs no database query and does no I/O beyond writing the body.

### 5. What may never be a metric (the rule behind §3)

No family, label name or label value derived from: an account (id, login name, email, alias), a device, a vault, an item, a share, an attachment, a session; a request's path beyond *R*, its query, `Host`, user agent, IP or any other header; a domain or URL (the `icons` role, INV-51, INV-77); a byte count or size of stored data; a per-account count of anything (items, devices, bytes, ops); a key, an epoch or a rotation event. Instance-wide totals of stored data (account count, bytes stored) are excluded too (alternative 4). Label values are `&'static str` from compile-time tables: no `String`, no `format!` into a label.

### 6. Cardinality and size limits

- `route` values: at most 96 (a `const` assertion over *R*'s length). With 48 today, row 5 has 240 series.
- Total samples: at most 1024 (asserted in a unit test). Schema 1 has 290: rows 1–4, 7; row 5, 240; row 6, 14; row 7, 1; row 8, 17; rows 9–12, 11.
- Every label value matches `^[A-Za-z0-9_./+-]{1,64}$` (asserted); `version` is SemVer and matches it.
- Each output line at most 256 bytes; the whole body at most 128 KiB (asserted). The body is rendered into one pre-sized buffer.

### 7. Implementation shape

- **Hand-rolled, no new crate.** A new module `crates/rizzy-server/src/metrics.rs` holds one `Metrics` struct of `AtomicU64` fields and fixed arrays (one counter per *R* × `status_class` pair, per code, per worker kind, per histogram bucket), created once at startup and shared through the routers' state. `fn render(&self, start_secs: u64, version: &str, roles: Roles) -> Vec<u8>` writes §2's layout. A global recorder (the `metrics` facade with `metrics-exporter-prometheus`) is not used: any `counter!("...", "label" => value)` anywhere in the code would add a series at run time, which is the leak §5 forbids, and the closed set could not be checked at compile time.
- `sha2` and `subtle` become dependencies of `rizzy-server` from `[workspace.dependencies]` (both already pinned, `sha2 =0.11.0` and `subtle =2.6.1`, and already in the lockfile through `rizzy-core`, `rizzy-domain-auth` and `rizzy-client`). No new crate enters the lockfile. If `cargo xtask check-deps` allow-lists crate edges, the edge is added in the same change.
- **Consistency of one answer.** Each atomic is loaded once (`Relaxed`) per render. Histogram buckets are stored per bucket, not cumulatively; the renderer sums them into the cumulative `le` series and writes `_count` as the `+Inf` cumulative from the same loads, so `_count` always equals the `+Inf` bucket within one answer. `_sum` may lag or lead by in-flight observations; that is accepted.
- **Crash and restart.** Nothing is persisted: no table, no file, no migration. On restart every counter starts from `0` and `process_start_time_seconds` changes; Prometheus treats a decrease as a counter reset (L: Prometheus `rate()` documentation). A scrape is an idempotent `GET`; a failed scrape is retried by the scraper and changes nothing. Counters use wrapping `fetch_add`; at one increment per nanosecond a `u64` wraps after 584 years.
- **Several processes.** Each `api` process exports its own counters; nothing is aggregated across replicas and no `instance` label is added (the scraper adds it).

### 8. Threat-model check: every family against THREAT_MODEL §3.4

| Family | §3.4 row it touches | Why it adds nothing the operator does not already hold |
|---|---|---|
| 1, 2, 3, 4 | none | Build and process facts; the version is public in `/api/meta`. |
| 5 | "IPs, user agents, connection times — Logs" | An aggregate of the access log's `route` and `status` fields, without the IP, user agent or time of any one request. Coarser than the log. |
| 6, 7 | same | Instance-wide and unlabelled; no per-route timing, so no per-endpoint timing profile. An attacker can time its own requests directly, so the histogram is no new oracle. |
| 8 | same | The error code is already in each response and its log line; `unauthorized` volume is a brute-force signal the operator should see. |
| 9–12 | "Encrypted op log … compacted"; "Item IDs, op counts, ciphertext sizes, timestamps — Visible" | Instance-wide totals of the `worker_run` log line's fields; no item, vault or account id. |

None of the families touches the rows for account identifiers, OPAQUE records, wrapped keys, public keys, snapshots, grants, version vectors, shares, aliases, mail, 2FA secrets, WebAuthn keys, recovery state, attachment sizes or `icons` requests.

**Residual, stated plainly.** On an instance with one or a few users, rows 5 and 8 at a 15-second scrape interval are those users' activity timeline: when they log in, sync, or start a recovery. The access log already holds this in more detail, but the scraper's retention, not the server's log retention, governs the copy. Hence `RIZZY_METRICS=off` by default, and the operator docs say so (open question 2 asks whether *R* should be coarser).

### 9. New invariant (provisional number)

**INV-119** (provisional; re-checked against the other drafts' numbers at acceptance): "The metrics endpoint exports exactly ADR 0104's closed family set of the current metrics schema. Every label value comes from a compile-time table; none is derived from an account, device, vault, item, share, session, request path beyond the fixed route names, header, IP, domain or stored-data size, and the set of series depends only on the build. It is served only on the admin listener, only when `RIZZY_METRICS=on`, and only to a request carrying the scrape token or, without a token, addressed by an IP literal or `localhost`." Milestone M3. Check: §12 tests 1–4 and the canary extension (test 5).

### 10. Operator documentation (ships with the code)

The operator docs gain a "Metrics" section: enabling it, generating the token, a Prometheus `scrape_config` example over a private network or tunnel, §8's residual, and that the compose examples still do not publish the admin port. The implementing change names the file.

### 11. What this ADR supersedes

One Accepted sentence ([ADR 0020](0020-partial-supersession.md) point 9).

1. **[ADR 0048](0048-per-account-storage-quota.md) §1, its last sentence**, the settings list, which ADR 0048 names as its replacement of [ADR 0028](0028-api-v1-http-conventions.md) item 12's settings clause and which is therefore the binding text of that clause. Word for word:

   > Settings `RIZZY_ROLES`, `RIZZY_ORIGIN`, `RIZZY_LISTEN` (default `127.0.0.1:8080`), `RIZZY_DATA_DIR` (`/data`), `RIZZY_DATABASE_URL`, `RIZZY_SECRETS_FILE` (`/run/rizzy-secrets/secrets.json`), `RIZZY_SIGNUP` (`closed`|`open`), `RIZZY_TRUSTED_PROXIES`, `RIZZY_LOG_LEVEL`, `RIZZY_WORKER_INTERVAL_SECS`, `RIZZY_MAX_UPLOAD_BYTES`, `RIZZY_ACCOUNT_QUOTA_BYTES`.

   Replacement, in full:

   > Settings `RIZZY_ROLES`, `RIZZY_ORIGIN`, `RIZZY_LISTEN` (default `127.0.0.1:8080`), `RIZZY_DATA_DIR` (`/data`), `RIZZY_DATABASE_URL`, `RIZZY_SECRETS_FILE` (`/run/rizzy-secrets/secrets.json`), `RIZZY_SIGNUP` (`closed`|`open`), `RIZZY_TRUSTED_PROXIES`, `RIZZY_LOG_LEVEL`, `RIZZY_WORKER_INTERVAL_SECS`, `RIZZY_MAX_UPLOAD_BYTES`, `RIZZY_ACCOUNT_QUOTA_BYTES`, `RIZZY_METRICS` (`off`|`on`, default `off`), `RIZZY_METRICS_TOKEN_SHA256` (64 lowercase hex characters, unset by default).

   **Ordering with ADRs 0087 and 0066.** Both (Proposed) also replace this sentence. Whichever is accepted later replaces the sentence binding at that time, and its replacement keeps every addition the earlier one made. If ADR 0087 is accepted first with its plain replacement, this ADR's replacement at acceptance is, in full:

   > Settings `RIZZY_ROLES`, `RIZZY_ORIGIN`, `RIZZY_LISTEN` (default `127.0.0.1:8080`), `RIZZY_DATA_DIR` (`/data`), `RIZZY_DATABASE_URL`, `RIZZY_SECRETS_FILE` (`/run/rizzy-secrets/secrets.json`), `RIZZY_SIGNUP` (`closed`|`invite`|`open`), `RIZZY_TRUSTED_PROXIES`, `RIZZY_LOG_LEVEL`, `RIZZY_WORKER_INTERVAL_SECS`, `RIZZY_MAX_UPLOAD_BYTES`, `RIZZY_ACCOUNT_QUOTA_BYTES`, `RIZZY_METRICS` (`off`|`on`, default `off`), `RIZZY_METRICS_TOKEN_SHA256` (64 lowercase hex characters, unset by default).

   In any other order (ADR 0087's default-`invite` variant, or ADR 0066 first), the replacement is the sentence binding at acceptance with the two `RIZZY_METRICS*` entries appended at its end, written out in full in the acceptance commit.

Nothing else is superseded. ADR 0048 §1's other sentences and ADR 0028 item 12's other clauses (the secret boundary among them) stay binding. ADR 0010 §1's "Admin API and metrics bind a separate listener" and ADR 0060 owner answer 4 are fulfilled, not changed. `RIZZY_ADMIN_LISTEN` itself is not in the sentence today (ADR 0060's precedent; `config.rs`: "its name follows `RIZZY_LISTEN`'s"); this ADR does not fix that pre-existing omission.

### 12. Tests

1. **Exact set (golden).** A `metrics.rs` unit test: a fresh `Metrics`, rendered with start time `0`, version `0.0.0-test` and roles `api` only, equals the committed file `crates/rizzy-server/tests/fixtures/metrics-schema-1.txt` byte for byte. Any change to the set fails this test; the golden, the schema number and an ADR change together.
2. **The series set is traffic-independent.** Integration test: start the server with `RIZZY_METRICS=on`; scrape; run signup, login, a sync push and pull, an `invalid_request` error, a request to an unknown `/api/` path and a web-role path; scrape again. Both answers have the same list of `name{labels}` keys in the same order; only values differ, and the expected counters moved (for example `rizzy_http_requests_total{route="/api/v1/login/finish",status_class="2xx"}` is at least 1).
3. **Limits.** Unit tests: *R*'s length at most 96 (also a `const` assertion); the sample count at most 1024; every label value matches §6's pattern; every line at most 256 bytes; the body at most 128 KiB; every `RouteName` value the routers can set is in *R* (iterating `Endpoint::ALL` and the fixed names, as the existing INV-73 test does).
4. **Format.** A line-level checker in the test (no new crate): each family has one `# HELP` and one `# TYPE` line before its samples; names match `^[a-z_][a-z0-9_]*$`; histogram buckets are cumulative and non-decreasing, with `_count` equal to the `+Inf` bucket; the body ends with `\n`. `promtool check metrics` (U: availability on the CI runners not checked) is run by hand once in the implementing change and its result reported.
5. **Canary (INV-15 and INV-48 extended).** The existing canary run also fetches `/metrics` (with a token) after its flows and searches the body for every canary value: the login name, device names, vault and item ids, the client IP, a unique user agent, a unique `Host` sent to the public listener, and a unique path segment it requested (`/api/v1/zz-canary-<random>`, which must be counted as `unmatched`), each raw, hex and base64. None may appear.
6. **Access.** Integration tests in `tests/admin_listener.rs`:
   - `RIZZY_METRICS` unset: `/metrics` on the admin listener is the existing `404` (current assertion kept).
   - `on`, loopback, no token: `Host: 127.0.0.1:<port>`, `Host: localhost` and `Host: [::1]:<port>` answer `200` with §2's `Content-Type`, `Cache-Control: no-store` and `ADMIN_CSP`; `Host: evil.example` answers `421`.
   - `on` with a token: no header, `Basic …`, a 42- or 44-character token, a wrong token, two `Authorization` headers and a 257-byte header each answer `401` with `WWW-Authenticate`; the right token with `Host: rizzy:8081` answers `200`.
   - `POST /metrics` answers `405` with `Allow: GET`; `/metrics/` answers `404`; `/metrics?x=1` answers `200`.
   - The public listener: `/metrics` answers `404` with roles `api,web`, with `api` only and with `web` only.
   - Startup: `on` with `RIZZY_ADMIN_LISTEN=0.0.0.0:8081` and no token refuses, and stderr names `RIZZY_METRICS_TOKEN_SHA256`; a 63-character or uppercase hash refuses naming the setting; `RIZZY_METRICS=yes` refuses naming the setting.
   - Logs: across these requests the log holds the route `metrics` and never the token, the digest or the `Host` values sent.
7. **CLI.** `rizzy-vault metrics-token` prints two lines; the token matches `^[A-Za-z0-9_-]{43}$`; the hex is the SHA-256 of the token's ASCII bytes; no file is created in the data directory; two runs give different tokens.
8. **Worker.** With `--roles api,worker`, after one worker run `rizzy_worker_runs_total` is `1`, `rizzy_worker_leader` is `1`, and each `rizzy_worker_work_total{kind}` equals the matching field of the `worker_run` log line.

## Consequences

- **Positive.** The M3 Should row gets a bounded, checkable surface. The scraper learns aggregate health only; no account, device, item, path, host or IP can reach a label, by construction (static tables) and by test (golden and canary). The default changes nothing for existing deployments. No new crate, no migration, no persistent format, no wire format visible to clients.
- **Negative.** A hand-rolled exporter is a few hundred lines we maintain, and every new endpoint bumps the schema and the golden. Per-route counters on a tiny instance are a user's activity timeline kept under the scraper's retention (§8 residual). There are no per-route latency histograms, no process memory or CPU metrics (node-exporter or cAdvisor cover those), no database metrics, and no metrics from `web`-only, `worker`-only or `icons` processes at M3. No `HEAD`. One token at a time; rotation needs a restart.
- **Neutral.** The `Host` rule here differs from ADR 0085 §5 point 2 (Proposed) by design: `/admin` uses `RIZZY_ADMIN_HOSTS`, `/metrics` uses the token. If both are accepted, the admin router applies ADR 0085's check under `/admin` only and this ADR's check on `/metrics` only.

## Alternatives considered

1. **The `metrics` facade with `metrics-exporter-prometheus`** (U: maintainer, advisories and transitive tree not checked). Rejected: a global recorder lets any call site add a family or a label at run time, the leak §5 forbids; it also brings its own HTTP listener or upkeep task and needs a dependency review.
2. **Metrics on the public listener behind the token.** Rejected: contradicts ADR 0010 §1, ADR 0060 owner answer 4 and THREAT_MODEL §7.14.
3. **A mandatory token always.** Rejected for the loopback case: a scraper on the same host is the common setup and the `Host` rule covers rebinding. The token is required whenever the listener is not loopback (§4 point 5).
4. **Instance totals (`rizzy_accounts`, `rizzy_stored_bytes`, `rizzy_devices`).** Rejected for schema 1: they tell a less trusted scraper the instance's size and growth, which the admin panel gates behind admin login. A later ADR may add them if the owner wants.
5. **Per-route duration histograms.** Rejected: 48 × 14 series, and a per-endpoint timing profile per scrape; one unlabelled histogram answers "is the server slow".
6. **OpenMetrics text.** Not chosen: Prometheus scrapes the 0.0.4 text format (L), and one format keeps the golden simple.
7. **The token in the secrets file.** Rejected: it changes the secrets-file format (ADR 0028 item 13) for a value whose hash is enough.

## Open questions for the owner

1. **Metrics from processes without the `api` role** (`web`-only, `worker`-only, `icons`)? They have no admin listener (ADR 0060 §2). *Recommendation:* not at M3. A deployment that runs `worker` separately reads its `worker_run` log line; a later ADR can give those roles a listener if split deployments become common.
2. **Granularity of `route`:** per endpoint (*R*, 48 values) or coarse groups (`auth`, `sync`, `vault`, `attachments`, `meta`, `web`, `other`)? *Recommendation:* per endpoint, as drafted: it equals the access log's field, which the operator already holds, and it is what makes alerts useful (failed logins, upload errors). The §8 residual is handled by the `off` default and the docs.

## On acceptance

Not made now; each is the owner's act or done in the acceptance commit.

1. This ADR's status becomes Accepted, and [README](README.md) row 0104 follows.
2. ADR 0048's status line gains "; [ADR 0104](0104-metrics-endpoint.md) (§1 in part)", appended after any earlier entry, and README row 0048 repeats it. §11's replacement text is written out in full per its ordering rule if ADR 0087 or ADR 0066 was accepted first.
3. [THREAT_MODEL](../THREAT_MODEL.md): §8 gains INV-119 (§9's text; the number re-checked against the batch). §7.19 gains an Information-disclosure row: "Metrics reveal accounts, hosts or per-user activity. | Closed static metric set, no per-account labels, admin listener only, off by default, token or loopback `Host`. | INV-119". §3.4 gains a row: "Aggregate request, error and worker counters | Exposed on the admin listener's `/metrics` when `RIZZY_METRICS=on` | ADR 0104; the scraper's retention applies".
4. [HANDOFF](../HANDOFF.md)'s dependency row "`metrics-exporter-prometheus` or hand-rolled" is resolved as hand-rolled.
5. CLAUDE.md's list of Proposed and Accepted ADRs is updated by the lead, not by this change.
6. Migrations: none. Sealing purposes: none. Settings-schema tags: none (both settings are `RIZZY_*` configuration, not ADR 0011 settings rows); if the owner prefers a stored setting instead, its tag is "next free at acceptance".

## Implementation plan

Each step is its own commit; the CLAUDE.md gate runs before any push.

1. `config.rs`: parse `RIZZY_METRICS` and `RIZZY_METRICS_TOKEN_SHA256`, add both to `KEYS`, implement §4 point 5's refusals, with unit tests.
2. `metrics.rs`: the `Metrics` struct, *R* and the other static tables, `render`, the golden file, tests 1, 3 and 4.
3. Wire the counters: `access_log` (rows 5–7, with the in-flight drop guard), `failure_response` and `rate_limited_response` (row 8), `worker.rs` (rows 9–12); tests 2 and 8.
4. `http/admin_panel/mod.rs`: the `GET /metrics` handler with §4's checks and error answers; update the module doc; add `sha2` and `subtle` to `rizzy-server`'s `Cargo.toml` from the workspace; test 6.
5. `cli.rs`: `rizzy-vault metrics-token`; test 7.
6. The canary extension (test 5).
7. The operator docs (§10).

## References

- [ROADMAP](../ROADMAP.md) §4.9 "Metrics endpoint (Prometheus)", M3.
- [ADR 0010](0010-server-shape.md) §1; [ADR 0060](0060-admin-panel-stack-boundary.md) §2 and owner answer 4; [ADR 0028](0028-api-v1-http-conventions.md) items 3, 12 and 13; [ADR 0048](0048-per-account-storage-quota.md) §1; [ADR 0049](0049-web-role-route-table.md); [ADR 0020](0020-partial-supersession.md) point 9.
- Proposed: [ADR 0085](0085-admin-authentication-bootstrap.md) §5; [ADR 0087](0087-invite-only-signup-tokens.md) §10.1; [ADR 0066](0066-share-email-otp-verification.md); [ADR 0090](0090-per-account-security-event-log.md).
- [THREAT_MODEL](../THREAT_MODEL.md) §3.4, §7.12, §7.14, §7.19; INV-15, INV-48, INV-51, INV-73, INV-77.
- Review: [2026-10-25 gap review](../reviews/2026-10-25-adr-gap-review.md) row M6; raw findings [G06](../reviews/2026-10-25-raw/G06.md) G06-16 and [G10](../reviews/2026-10-25-raw/G10.md) G10-20.
- External, not re-read for this draft (all L): the Prometheus documentation pages "Exposition formats" (text format 0.0.4 and its `Content-Type`), "Metric and label naming", "Instrumentation", `scrape_config`'s `authorization` block, and `rate()`'s handling of counter resets.
