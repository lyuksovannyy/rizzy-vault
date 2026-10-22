# ADR 0049: Web role: a fixed, enumerable route table (compiled-in assets + share links)

- Status: Accepted
- Date: 2026-10-11
- Deciders: project owner
- Milestone: M1

## Context

[ADR 0028](0028-api-v1-http-conventions.md) item 15 (Accepted; not yet superseded in any part) fixes: "**Web role paths.** `/` and `/index.html` (`GET`, `HEAD`); every other path outside `/api/` is a plain-text `404`; nothing is read from disk. *Why:* §7.7 "E"." [THREAT_MODEL §7.7](../THREAT_MODEL.md#77-web-role-m1) row E reads: "Path traversal in static serving; framing the vault (clickjacking)." → "Assets served from memory, with no filesystem path built from the request. `frame-ancestors 'none'`, HSTS, `nosniff`." (INV-49).

The shipped code already serves more than item 15's two paths. [ADR 0010](0010-server-shape.md) §4 (Accepted; not superseded in this part) decided the `web` role would embed "web assets" (plural) under the `embed-web` feature, because the vault's CSP forbids inline script and [ADR 0013](0013-shared-client-core.md) §4 runs the core in a dedicated Worker, which needs a script URL of its own — the vault cannot run from `/` and `/index.html` alone. `crates/rizzy-server/src/http/web.rs` implements this today: a fixed, compile-time `ASSETS` table (`/assets/app.js`, `/assets/style.css`, `/assets/core-worker.js`, `/assets/rizzy_core_bg.wasm`), mirrored by `apps/web/assets.ts`'s `EMBEDDED_FILES` and checked by `test/assets.test.ts`, matched by exact string against `uri.path()` with no disk access; `crates/rizzy-server/src/http/mod.rs`'s `fallback` routes every non-`/api/` request to it. The module's own docs say this plainly: "This reading is reported to the owner: item 15 needs an amendment (a new ADR, ADR 0020 point 9) naming the asset paths." (V, read 2026-10-11, HEAD 5a78bb5.) `test/assets.test.ts` only checks that `web.rs`'s `ASSETS` and `assets.ts`'s `EMBEDDED_FILES` name the same paths as each other; nothing ties either list to an ADR, so today a contributor can add a fifth embedded file to both lists (and `vite.config.ts`) and the table grows with no amendment and no owner review.

A second deviation is coming from the same source. [CRYPTO.md §11.10](../CRYPTO.md#1110-public-share-link-creation-m5) step 6 (M5) fixes the share link as `https://<server>/s/<b64url(share_id)>#1<flag><b64url(share_secret)>`: a `web`-role path outside `/, /index.html` whose last segment varies per share. §11.11 step 1 has the recipient page read `location.hash` and call `history.replaceState` — the page itself is a constant static bundle; `share_id` is never read server-side to pick a different response, only passed back to `POST /api/v1/shares/<id>/open` by client script. [THREAT_MODEL §7.16](../THREAT_MODEL.md#716-share-recipient-page-m5) row D and open question Q-4 (same-origin vs. a second host) bear on it; [ADR 0014](0014-ui-stack.md) names `apps/share` but leaves Q-4 open.

Fixing the asset table and the share-link path as two separate narrow amendments to item 15 would, over time, let two ADRs each claim to supersede the same item with different replacement text — the exact risk the M5 batch's own report flags as a real risk of two incompatible fixes. [ADR 0020](0020-partial-supersession.md) point 9 lets one ADR supersede a named part once; nothing stops a second ADR from naming it again, so the discipline has to come from this ADR's own text. [ROADMAP §4.9](../ROADMAP.md#49-server-self-hosting--ops-m1-onward) ("security headers, CSP on web vault", Must, M1 — the row this task calls gap 24) and [§4.7](../ROADMAP.md#47-public-sharing-m5) ("Recipient view page that works without an account", Must, M5) are the scope rows; neither adds scope here, both are already Must/M1 and Must/M5.

## Decision

### What this ADR supersedes

- [ADR 0028](0028-api-v1-http-conventions.md) item 15, in full (the bullet and its "Why"), quoted above in Context. Replaced by "The route table" below.
- [ADR 0028](0028-api-v1-http-conventions.md) item 10, its first sentence in full (the smallest whole sentence ADR 0020 point 9 allows): "Every response: `Strict-Transport-Security: max-age=31536000` (no `includeSubDomains`, no `preload`: the operator's other hosts are not ours to pin), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, and `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, except the web role's pages, which carry `WEB_CSP` of `http/security.rs` (`'self'` only, `'wasm-unsafe-eval'`, no inline script or style, `object-src`, `base-uri`, `form-action` `'none'`, `require-trusted-types-for 'script'`)." Replaced by: "Every response: `Strict-Transport-Security: max-age=31536000` (no `includeSubDomains`, no `preload`: the operator's other hosts are not ours to pin), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, and `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, except every response the web role's route table (ADR 0049) answers — a page, an embedded asset, or this table's own `404`/`405` — which carries `WEB_CSP` of `http/security.rs` (`'self'` only, `'wasm-unsafe-eval'`, no inline script or style, `object-src`, `base-uri`, `form-action` `'none'`, `require-trusted-types-for 'script'`) instead." The rest of item 10 (`Cache-Control: no-store` on API responses, the HSTS rationale, no CORS) is untouched.

Nothing else in ADR 0028 changes.

### The route table

The `web` role answers only from a route table fixed at compile time and matched against the request-target's path byte for byte: no decoding, no normalisation (consistent with item 5's rule for the `/api/` router — a different router, same discipline). A row is one of:

- a **literal path**, matched exactly (`/`, `/index.html`, each asset path); or
- a **fixed prefix plus exactly one path segment** whose value must not select which bytes are served, must not reach the filesystem, must not build a redirect target or any string echoed into a response, and must not be written to a log (matching [THREAT_MODEL §7.7](../THREAT_MODEL.md#77-web-role-m1) row I's INV-33 and `http/mod.rs`'s existing discipline of logging a fixed route template, never the raw path). A row that needs more than that — content keyed by the segment, a second filesystem read, a lookup against untrusted state before responding, or logging the segment's value — needs a new ADR, not an addition to this table.

**The M1 table:**

| Row | Methods | Serves |
|---|---|---|
| `/`, `/index.html` | GET, HEAD | the web vault's `index.html` under `embed-web`; [ADR 0010](0010-server-shape.md) §4's fixed placeholder page otherwise |
| `/assets/app.js` | GET, HEAD | the built JS entry point; not served (`404`) without `embed-web` |
| `/assets/style.css` | GET, HEAD | the built stylesheet; not served (`404`) without `embed-web` |
| `/assets/core-worker.js` | GET, HEAD | the core's dedicated Worker script ([ADR 0013](0013-shared-client-core.md) §4); not served (`404`) without `embed-web` |
| `/assets/rizzy_core_bg.wasm` | GET, HEAD | the core's wasm module; not served (`404`) without `embed-web` |

These four paths are `http/web.rs`'s `ASSETS` table, mirrored by `apps/web/assets.ts`'s `EMBEDDED_FILES`. Adding, removing or renaming an embedded-asset path is itself a change to this table and needs an amendment under "Extending the table" below, the same as any other row; `apps/web/test/assets.test.ts` only pins that `web.rs`'s `ASSETS` and `assets.ts`'s `EMBEDDED_FILES` agree with each other, not that either one matches this ADR.

A request matching no row, outside `/api/`, **must** answer a plain-text `404`, whatever the method. A request to a matched row with a method the row does not serve **must** answer a plain-text `405` (reusing item 3's `405` status code for an unserved method, not item 3's `/api/` JSON body shape; this fixes `web.rs`'s "this crate's reading" as the Decision). Every response this table answers — a page, an asset, the `404` or the `405` — carries `WEB_CSP` (`http/security.rs`), matching `web::respond`'s existing, unconditional `add_web_csp` call; this is the Decision that replaces ADR 0028 item 10's page-only exception, named under "What this ADR supersedes" above. This ADR does not decide whether a future share-page row needs a different policy; that is [ADR 0065](0065-share-page-origin-csp.md)'s question. Nothing is read from disk at request time: every served byte is compiled in or generated at build time, unchanged from ADR 0010 §4.

**Dependent-part check (ADR 0020 point 9).** Two further unnamed parts of ADR 0028 touch the web role:
- Item 5 (signed request-target, the 27-path `/api/` router) is untouched, unchanged in meaning: a prefix row in this table is no part of that router or of any signed message.
- Item 3's `405` sentence ("A method a route does not serve is `405` with `invalid_request`") is cited only as precedent for reusing the `405` status code. That sentence is distinct from item 3's `409` code-table sentence, which ADR 0028's status line already shows partially superseded by [ADR 0031](0031-retiring-old-opaque-setups.md) and [ADR 0032](0032-healing-rotation-after-backup.md) (each adds a `409` code; both say the rest of item 3 is read against the table so amended) — the `405` sentence itself is untouched by either. Item 3's own rule is scoped to `/api/`'s JSON `{"error":"<code>"}` body, so it does not itself govern the web role. The web role's plain-text `405`, stated above under "The route table", is this ADR's own Decision; it reuses item 3's status code but not item 3's JSON-body rule.

### Extending the table

This ADR provides for its own amendment ([ADR 0020](0020-partial-supersession.md) point 4): a row is added to this table only by an Accepted ADR that names it in the shape above. The PR that accepts that ADR appends a dated `## Amendments` entry here stating the new row (one or more rows, literal or single-segment), so the whole table stays readable in one place. The amendment **records** the row; it does not **authorize** it — the authorizing decision (what the row serves, its CSP, its origin) is made in that ADR, under ADR 0020 point 5's security-boundary gate, same as any other web-role change. No addition supersedes ADR 0028 item 15 again, and none supersedes this ADR. [ADR 0064](0064-share-api-storage-lifecycle.md) is expected to add the `/s/<share_id>` prefix row and its asset rows this way, once it and [ADR 0065](0065-share-page-origin-csp.md) fix what `share_id` is checked against and what the page's CSP is; this ADR fixes only the mechanism and the M1 contents.

### Proposed invariant

**INV-73** (allocated across the 2026-10-11 batch, in ADR-number order, from the next free id after INV-69. Provisional: the allocation was made across the 2026-10-11 batch in ADR-number order; if ADRs are accepted out of order, the owner renumbers at acceptance.). *Text, for the owner to add to [THREAT_MODEL.md §8.8](../THREAT_MODEL.md#88-server-and-operations) on acceptance — not edited by this ADR:* "The `web` role serves a response only from a route table fixed at compile time: a literal path, or a fixed prefix with exactly one path segment that does not select response content, is not read from the filesystem, is not echoed into a response or a redirect, and is not written to a log. Every other path outside `/api/` answers `404`. Nothing is read from disk at request time." *From:* M1. *Verified by:* `http/web.rs`'s existing exact-match test (`only_the_listed_paths_are_served`), extended to any future prefix row, plus a test on `http/mod.rs`'s access-log line (or `fallback`) asserting the logged route stays a fixed template (`RouteName`), never the request path, for any row this table gains.

## Consequences

### Positive

- Code already running (the `embed-web` asset table) gets the Accepted ADR the ADR-first rule (ADR 0020 point 5, "security boundaries") requires before it, closing a gap `web.rs`'s own module docs already flagged.
- One mechanism covers the shipped deviation and the M5 share link, so the batch has exactly one ADR superseding item 15, matching the instruction to keep it that way.
- Future additions (the M5 share link, and any later one) are a recorded amendment plus their own authorizing ADR, not a fresh partial supersession of ADR 0028 or of this ADR.

### Negative

- A reader of ADR 0028 item 15 must also open this ADR for its live text, and, once amended, must read the amendment log here too.
- The table can grow over several ADRs' amendments; a reader has to track which ADR authorized which row, not just this file's current table.
- ADR 0028's status line gains a second named part on acceptance (`Partially superseded by ADR 0049 (item 10 in part, item 15)`), alongside its existing partial supersessions by ADR 0031 and ADR 0032.

### Risks

- An amendment that reads the dynamic segment for anything beyond the stated bound (content selection, filesystem access, redirect, echo or logging) would violate INV-73 silently if reviewed loosely. Mitigation: the amendment provision above requires the authorizing ADR to state the row in this exact shape, and `http/web.rs`'s test (plus the access-log test) is extended with each addition.

## Alternatives considered

- **Two narrow partial supersessions of item 15** (one for the shipped assets, one later for the share link). Rejected: the exact risk this task flags — two ADRs each naming item 15 with different replacement text.
- **A full successor to ADR 0028.** Rejected: one bullet of fifteen changes; restating all fifteen fails ADR 0020 point 9's own reasoning for using partial supersession at all.
- **Leave item 15 as literal text and treat the shipped asset routes and the coming share link as undocumented exceptions.** Rejected: that is the current state, and it is exactly what the ADR-first rule (ADR 0020 point 5) forbids for a security boundary.
- **An open-ended route table (regex or arbitrary wildcard paths).** Rejected: defeats the build-time-enumerable goal and §7.7 "E"'s mitigation ("no filesystem path built from the request"); the single-segment, non-selecting form is the narrowest rule that still fits the share link.

## Open questions for the owner

1. **Is naming item 15 in full plus item 10's first sentence the right granularity, or should ADR 0028 get a broader "web role" amendment instead?** *Recommendation:* the narrow route named here — item 15 in full, plus item 10's first sentence (its `WEB_CSP` exception, widened to the whole table) — as done above: ADR 0020 point 9 names a whole bullet or a whole sentence as the smallest part, and the dependent-part check shows nothing else in ADR 0028's web-role text needs to change.
2. **Future table rows: amendment to this ADR, or a fresh supersession each time?** *Recommendation:* amendment, as specified under "Extending the table" — that is what provides for ADR 0064 to add `/s/<share_id>` without touching item 15 or this ADR's status line again.
3. **INV-73's number.** Resolved: allocated as INV-73, the batch's proposed INV ids reconciled in ADR-number order (0045–0074); confirm at acceptance in case an ADR lands out of order.

## References

- [ADR 0028](0028-api-v1-http-conventions.md) items 3, 5, 10, 15; [ADR 0010](0010-server-shape.md) §4; [ADR 0020](0020-partial-supersession.md) points 4, 5, 9; [ADR 0013](0013-shared-client-core.md) §4; [ADR 0014](0014-ui-stack.md) (share page, Q-4 open); [ADR 0031](0031-retiring-old-opaque-setups.md), [ADR 0032](0032-healing-rotation-after-backup.md) (item 3's `409` code-table sentence, already partially superseded; the `405` sentence is not)
- [THREAT_MODEL.md](../THREAT_MODEL.md) §7.7 rows E, I; §7.16 row D; INV-49, INV-33, Q-4
- [CRYPTO.md](../CRYPTO.md) §11.10 step 6, §11.11 steps 1, 4
- [ROADMAP.md](../ROADMAP.md) §4.7, §4.9
- Code (V, read 2026-10-11, HEAD 5a78bb5): `crates/rizzy-server/src/http/web.rs`, `crates/rizzy-server/src/http/mod.rs` (`fallback`, `access_log`), `apps/web/assets.ts`, `apps/web/test/assets.test.ts`, `apps/web/vite.config.ts`
- Sibling ADRs (same batch, M5): [ADR 0064](0064-share-api-storage-lifecycle.md) (Share API, storage, lifecycle — expected to add the `/s/<share_id>` row), [ADR 0065](0065-share-page-origin-csp.md) (recipient page origin and CSP — decides whether a future share-page row departs from this ADR's table-wide `WEB_CSP`)
