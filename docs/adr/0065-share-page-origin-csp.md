# ADR 0065: Share recipient page origin and CSP

- Status: Accepted
- Date: 2026-10-11
- Deciders: project owner
- Milestone: M5

## Context

[ROADMAP §4.7](../ROADMAP.md#47-public-sharing-m5) (M5, Must) includes the row this ADR covers: "Recipient view page that works without an account." [CRYPTO.md §11.10](../CRYPTO.md#1110-public-share-link-creation-m5) step 6 already fixes the link grammar: `https://<server>/s/<b64url(share_id)>#1<flag digit><b64url(share_secret)>`. [§11.11](../CRYPTO.md#1111-public-share-link-opening-m5) fixes the opening protocol: read `location.hash`, strip it with `history.replaceState`, send `Referrer-Policy: no-referrer`, derive `pp_key` in wasm (~0.3 s) when a passphrase flag is set, and POST `/api/v1/shares/<id>/open` only after an explicit click. None of that is reopened here.

[THREAT_MODEL Q-4](../THREAT_MODEL.md#10-open-questions-for-the-owner) is open: serve `/s/<share_id>` and rendered mail from a second hostname, so an XSS there cannot reach web-vault storage? Its current recommendation is "require a second hostname when M5 ships." [ADR 0014](0014-ui-stack.md)'s Context table still lists the share page as "possibly on a separate origin (Q-4)" — Context text, unedited by this ADR regardless of outcome (ADR 0020 point 4).

Two Accepted texts already point toward one origin. [ADR 0010](0010-server-shape.md) §1's `web` role row (not touched by [ADR 0022](0022-server-mode-only.md)'s partial supersession, which replaced only the `api` and `worker` rows) reads: "Serves the web vault and the share page from assets embedded in the binary." [ADR 0014](0014-ui-stack.md) §2 already treats a share snapshot as "untrusted rich content," rendered only inside the one reviewed sandboxed-frame helper (`packages/ui`), without `allow-scripts` or `allow-same-origin`, and requires `apps/share` to be framework-free TypeScript with no raw-HTML sinks — the same lint rules that bind the web vault. [INV-35](../THREAT_MODEL.md#8-security-invariants) already forbids such content from ever reading vault storage or keys.

**The actual code.** `crates/rizzy-server/src/http/web.rs` serves `/` and `/index.html` from a compile-time table (`lookup`), nothing read from disk, no path built from the request (THREAT_MODEL §7.7 "E"). Its module doc already flags that [ADR 0028](0028-api-v1-http-conventions.md) item 15 needs an amendment to name more paths — the gap [ADR 0049](0049-web-role-route-table.md) (Proposed, this batch) closes with a build-time-enumerable route table. `web::respond` calls `security::add_web_csp` unconditionally on every response (`web.rs` line 149); `security::add_common` sets `Referrer-Policy: no-referrer` on every response server-wide already, not just the web vault's (`security.rs` line 48, V). `WEB_CSP` (`security.rs` lines 33–36) is `default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; manifest-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'`.

**The cost a second hostname buys.** [CRYPTO.md §11.4](../CRYPTO.md#114-web-vault) "Storage": the web vault persists the Secret Key in IndexedDB on its origin when the user opts in ("this is my browser"); [§4.2.1](../THREAT_MODEL.md#421-the-web-vault-delivery-problem) and [Q-21](../THREAT_MODEL.md#10-open-questions-for-the-owner) already name that this removes 2SKD's offline-guessing protection against an active server. Same-origin means a bug that lets injected script run on `/s/<id>` — past ADR 0014 §2's lint, review and sandboxing, which this ADR does not weaken — can read that same IndexedDB value. A second hostname would contain such a bug to an origin holding nothing of value. M5's payload is the owner's own chosen, bounded fields ([ADR 0063](0063-share-snapshot-format.md), this batch); M6 mail rendering is arbitrary sender-controlled HTML at a much larger attack surface and raises the identical question.

## Decision

**1. Same origin, for M5.** `/s/<share_id>` answers Q-4: it is served from the same hostname, same `web` role, same binary as the web vault — no second DNS name, no second TLS certificate. ADR 0010 §1's `web` row needs no replacement text; it already reads this way. Mail rendering (M6) is not decided here; Q-4 is revisited then, not on a timer, when the content stops being owner-curated and bounded.

**2. The CSP floor for `/s/<share_id>`.** The response must carry a CSP that is no looser than:

| Directive | Value | Why |
|---|---|---|
| `default-src` | `'none'` | nothing loads unless named below |
| `script-src` | `'self' 'wasm-unsafe-eval'` | wasm runs `pp_key` and the AEAD open (CRYPTO.md §11.11 steps 2 and 5); no inline script |
| `style-src` | `'self'` | the token CSS import (ADR 0014 §2) |
| `connect-src` | `'self'` | the `POST /api/v1/shares/<id>/open` call |
| `worker-src` | `'self'` | if the core runs in a dedicated worker here, as the web vault's does (ADR 0013 §4); `apps/share`'s exact wiring is not decided by this ADR |
| `img-src`, `font-src`, `manifest-src` | `'self'` | no third-party origins (ADR 0014 §2) |
| `object-src`, `base-uri`, `form-action` | `'none'` | no plugin content, no base-tag or form hijack |
| `frame-ancestors` | `'none'` | the share page is not embeddable |
| `require-trusted-types-for` | `'script'` | same hardening as the vault |

`WEB_CSP` as written on 2026-10-11 satisfies every row exactly, so the share route reuses that constant; this ADR adds no `SHARE_CSP`. The floor above is the binding rule, not "whatever `WEB_CSP` says": the proposed header test checks these directives by value, not `response_csp == WEB_CSP`, so a later change that widens `WEB_CSP` for a vault-only reason fails that test and forces a decision instead of silently loosening the share page too.

**One consequence named now, not deferred:** under `default-src 'none'` with no `frame-src` directive, an `<iframe srcdoc="…">` still renders (there is no URL to fetch, so nothing for `frame-src` to gate), but a `blob:` URL loaded into a frame is blocked. ADR 0014 §2's sandboxed-frame helper may do either. This CSP floor permits only its `srcdoc` branch on the share route; using the `blob:` branch here needs `frame-src 'self'` added in that change, which is not granted by this ADR.

**3. Route mechanics (one sentence; the wiring itself is ADR 0049's).** `/s/<share_id>` is one fixed pattern matched against `share_id`'s fixed grammar ([ADR 0063](0063-share-snapshot-format.md)) and dispatched to one compiled document for every id, so it keeps `web.rs`'s "nothing read from disk, no path built from the request" property (THREAT_MODEL §7.7 "E") the same way the asset table does.

**4. Proposed invariant** (allocated as **INV-90** across the 2026-10-11 batch, in ADR-number order, M5. Provisional: the allocation was made across the 2026-10-11 batch in ADR-number order; if ADRs are accepted out of order, the owner renumbers at acceptance.):

> The share recipient page writes nothing to, and reads nothing from, `localStorage`, `IndexedDB` or any other persistent browser storage on its origin.

This is a constraint on **our own code**, checked by a lint rule plus a Playwright assertion next to `web_csp_meets_inv_49`'s pattern — it gives review and CI something mechanical to hold the share page to. It is **not** an XSS mitigation: injected script that defeats ADR 0014 §2's sandboxing can still call the same storage APIs the lint would have stopped our own code from calling. The remembered-SK exposure in Context is the risk this invariant does not remove; ADR 0014 §2's rules remain the only backstop against that script running at all.

**What this ADR does not decide (scope, so as not to duplicate siblings):** the route-table entry and HTTP wiring ([ADR 0049](0049-web-role-route-table.md)); the snapshot's plaintext layout and link grammar, already fixed by CRYPTO.md §11.10 and owned by [ADR 0063](0063-share-snapshot-format.md); the Share API, storage and lifecycle ([ADR 0064](0064-share-api-storage-lifecycle.md)); Send-style text sharing ([ADR 0067](0067-send-style-share.md)), which reuses this CSP and origin unchanged since it is served from the same route.

### On acceptance

The change that accepts this ADR makes these edits (none made now):

- **[THREAT_MODEL.md](../THREAT_MODEL.md) Q-4**, Recommendation cell → "Decided 2026-10-11 ([ADR 0065](0065-share-page-origin-csp.md)): same origin for M5. `/s/<share_id>` is served by the `web` role under the CSP floor ADR 0065 fixes; INV-35 and the proposed share-storage invariant (ADR 0065) are the isolation mechanism. A separate origin is revisited at M6, when mail rendering raises the identical question over sender-controlled, not owner-curated, content."
- **[THREAT_MODEL.md](../THREAT_MODEL.md) §7.1 "E"**, Mitigation cell → "The origin serves the web vault and, from M5, the share recipient page under the same CSP ([ADR 0010](0010-server-shape.md) §1, [ADR 0065](0065-share-page-origin-csp.md)). The share page itself touches no persistent browser storage (proposed INV-90); what it renders is sandboxed (ADR 0014 §2, INV-35). Mail (M6) is not yet in scope."
- **[THREAT_MODEL.md](../THREAT_MODEL.md) §7.16 "Share recipient page (M5)" row E**, Mitigation cell → "Same-origin CSP floor ([ADR 0065](0065-share-page-origin-csp.md) point 2); sandboxed rendering, no `allow-scripts`/`allow-same-origin` (ADR 0014 §2). Proposed INV-90 binds our own code only, not injected script, so it is not counted as a mitigation for this row (ADR 0065 point 4)." The Threat cell ("Share content runs script on the vault origin") and the Inv. column (INV-35) are unchanged — this ADR replaces the "separate origin ([Q-4])" plan that cell currently names, so leaving it as-is would contradict the Decision ([ADR 0020](0020-partial-supersession.md) point 7).
- **[THREAT_MODEL.md](../THREAT_MODEL.md) §8.5 "Sharing"**, new row after INV-35 — ID `INV-90`; Invariant "The share recipient page writes nothing to, and reads nothing from, `localStorage`, `IndexedDB` or any other persistent browser storage on its origin."; From `M5`; Verified by "Lint rule plus a Playwright assertion next to `web_csp_meets_inv_49`'s pattern." This is the row every other share invariant (INV-32 through INV-35) already has; without it, Decision point 4's invariant is declared in this ADR but never enters the table it needs to live in to be regression-tested.

## Consequences

### Positive
- No second DNS name or certificate for self-hosters; one less thing profile A/B/C compose files and docs must cover.
- No code change to `security.rs` or `web.rs`'s header path: `add_web_csp` and `add_common` already apply to every `web`-role response, including this one.
- Consistent with how ADR 0010 §1 already reads.

### Negative
- A bug that lets injected script run on `/s/<id>` — a defect in ADR 0014 §2's enforcement, not something this ADR weakens — can read the vault origin's IndexedDB, including an opted-in remembered Secret Key (CRYPTO.md §11.4). A second hostname would have contained that to an origin holding nothing.
- The CSP floor's `blob:`-frame branch is unavailable on this route without a further change; that constrains which implementation of ADR 0014 §2's helper the share page can ship first.

### Risks
- **M6 signal.** Mail rendering is arbitrary sender-controlled HTML, a materially larger attack surface than M5's owner-curated fields. That is the trigger for re-opening Q-4 for mail, independent of whether M5's answer is later revisited.
- **INV-90 drifts from WEB_CSP silently** if the header test is written as an equality check instead of the directive-by-directive check this ADR specifies; the test must assert the floor, not identity.

## Alternatives considered

- **Second hostname** (THREAT_MODEL Q-4's standing recommendation). Contains a share-page script bug to a worthless origin, but costs every self-hoster a DNS name and certificate for content that is, at M5, owner-curated and already sandboxed. Revisited at M6.
- **Storage-partitioning tricks on one hostname** (`Origin-Isolation`, cookie partitioning) without a second registrable domain. Does not create a separate origin under the same-origin policy (scheme + host + port); rejected as not meeting Q-4's goal.
- **A wildcard subdomain of the vault's own domain** (e.g. `share.<domain>`) is in substance the "second hostname" option with one certificate (wildcard or SAN) instead of two; it is the fallback if the owner rejects option 1, not evaluated further here.

## Open questions for the owner

1. **Accept same origin for M5, as recommended?** *Recommendation: yes*, for the DNS/certificate cost it avoids while M5's content stays owner-curated and bounded.
2. **Order against ADR 0049.** ADR 0049's route table needs one row that meets this ADR's CSP floor and proposed INV-90. *Recommendation:* accept this ADR before or together with ADR 0049; ADR 0049's `/s/<share_id>` row cites it rather than restating the floor.
3. **INV-90's exact number.** Resolved: allocated as INV-90, the batch's proposed INV ids reconciled in ADR-number order; confirm at acceptance in case an ADR lands out of order.

## References

- [ROADMAP](../ROADMAP.md) §4.7 (row "Recipient view page that works without an account")
- [THREAT_MODEL](../THREAT_MODEL.md) Q-4, §4.2.1, §7.1 "E", §7.16 "Share recipient page (M5)" row E, §7.7 "E", §8.5 INV-35 (and new INV-90), §8.8 INV-49, Q-21
- [CRYPTO.md](../CRYPTO.md) §11.4 ("Storage"), §11.10, §11.11
- [ADR 0010](0010-server-shape.md) §1, [ADR 0014](0014-ui-stack.md) §2 and Context (share-page row), [ADR 0020](0020-partial-supersession.md) points 4, 7, 9, [ADR 0022](0022-server-mode-only.md) §1, [ADR 0028](0028-api-v1-http-conventions.md) item 15
- Sibling ADRs in this batch (not duplicated): [ADR 0049](0049-web-role-route-table.md) (route table), [ADR 0063](0063-share-snapshot-format.md) (snapshot layout, link grammar), [ADR 0064](0064-share-api-storage-lifecycle.md) (API, storage, lifecycle), [ADR 0067](0067-send-style-share.md) (Send-style text share)
- `crates/rizzy-server/src/http/web.rs` (V, read 2026-10-11): `respond`, `lookup`, module doc on ADR 0028 item 15's gap
- `crates/rizzy-server/src/http/security.rs` (V, read 2026-10-11): `WEB_CSP`, `add_common`, `add_web_csp`, `web_csp_meets_inv_49`
