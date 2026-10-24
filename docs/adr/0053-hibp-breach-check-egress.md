# ADR 0053: Watchtower/HIBP breach-check egress route

- Status: Accepted
- Date: 2026-10-11
- Deciders: project owner
- Milestone: M3

## Context

[ROADMAP §4.5](../ROADMAP.md#45-design-ui--ux--1password-feel-m3) lists, Should, M3: "Watchtower-style health: weak, reused, old passwords; missing 2FA where site supports it; breached passwords via HIBP k-anonymity (only 5-char SHA-1 prefix leaves the device)". The row fixes the privacy property (5-char prefix only) but not how that prefix reaches the Have I Been Pwned (HIBP) range API, a third party outside our trust boundary. [THREAT_MODEL §3.1](../THREAT_MODEL.md#31-asset-and-actor-inventory)'s "External services" row already lists the HIBP range API as reached from M3, and the §3.2 diagram already draws "icon origins, HIBP, DNS, ACME" together in ZONE N, but no trust boundary names the HIBP leg on its own.

Two routes exist for a client to learn whether a candidate password's hash prefix is in HIBP's corpus:
- **Client-side.** The client calls HIBP directly over HTTPS. For the web vault this needs a new `connect-src` origin, which [ADR 0014](0014-ui-stack.md) §2's "No third-party origins" rule forbids and [INV-49](../THREAT_MODEL.md#8-security-invariants)'s header test checks. The extension and native/CLI clients carry their own CSP or none, so this block is specific to the web vault, not universal.
- **Server-side.** The server fetches the range for the client. [ADR 0010](0010-server-shape.md) §1 already runs this shape of traffic for favicons: the `icons` role (crate `rizzy-icon-proxy`, [ROADMAP §4.1](../ROADMAP.md#41-foundations--project-hygiene-m0); not yet in `crates/` today — the `Role` enum (`crates/rizzy-server/src/config.rs` L202, doc comment at L200: "Only the M1 roles exist in this build") has only `Api`, `Web` and `Worker` variants, no `Role::Icons`; `Roles::parse`'s own doc comment (L244) says "`notify` and `icons` (M3) and `smtp` (M6) are refused: this build has no such role", and its match arm for the string `"icons"` (L263) returns `ConfigError::RoleNotInThisBuild("icons")` without ever constructing a `Role` value — V, read 2026-10-11) holds no DB credentials, has no DB path, and reaches only the internet under an SSRF allow-list of globally routable unicast addresses on ports 80/443 ([INV-51](../THREAT_MODEL.md#8-security-invariants)). ADR 0052 (this batch, Proposed, M3) builds that role's DNS-pinned fetch and allow-list mechanism; this ADR does not restate it, only adds one more fixed destination.

The primitive is already cleared for this use: [ADR 0009](0009-crypto-dependency-policy.md)'s crate table scopes `sha1` 0.11.0 to "HOTP/TOTP only... and HIBP range queries from M3", and [CRYPTO.md §3](../CRYPTO.md#3-primitives) repeats it, both tagged "SHA-1 appears only where an external standard fixes it, never in a construction of ours". What is undecided is the transport; the digest flow itself is now fixed in this ADR's Decision (item 1), not left open.

**The trade-off a reviewer will raise.** Routing server-side means the `icons` role process sees a 5-hex-char SHA-1 prefix of a candidate password string. [CRYPTO.md Goal 1](../CRYPTO.md#1-goals-non-goals-and-rules) says the server "never sees a master password, a password-equivalent, the Secret Key, or any key that can decrypt vault data." A prefix of an *item* password is not literally the master password and decrypts nothing, but it is new information the server did not have before. Paired with a later DB-plus-backup breach ([A1](../THREAT_MODEL.md#a1-passive-server-compromise-db-or-backup-theft)) and `icons`' own traffic, it is one more fact an attacker could correlate. This is [Open question 1](#open-questions-for-the-owner), not decided here.

## Decision

**Recommended: route server-side through the `icons` role's existing egress, not a client-side CSP exception.**

1. **Transport, and the fixed digest flow.** Clients (web vault, extension, desktop, CLI) compute the candidate item password's SHA-1 digest locally over `UTF-8(NFC(password))`, render it as **uppercase hex**, and send only its first **5 hex characters (20 bits)** as the prefix to a new endpoint on the `icons` role, reached as favicon requests are (ADR 0010 §4: `icons` joins only the `edge` network, through the reverse proxy). The request payload carries no account identity, session token or item id — [Open question 1](#open-questions-for-the-owner) covers what that does and does not rule out. The response (the upstream's suffix:count list) is relayed back unmodified; the client compares each returned suffix against its own digest's remaining 35 hex characters with `subtle::ConstantTimeEq` (`ct_eq`, [CRYPTO.md §2](../CRYPTO.md#2-conventions)), holding the password string and the computed digest in zeroizing buffers for the duration of the check. Encoding, normalization, hex case, prefix length and comparison method are fixed **here**, in the binding Decision, not deferred to an open question or an implementing PR, so known-answer vectors ([CRYPTO.md §15](../CRYPTO.md#15-testing)) can be written against something fixed.
2. **Upstream destination.** The HIBP range host and path are a second fixed allow-list entry alongside favicon hosts (ADR 0052): one hardcoded hostname over HTTPS (443) only, never plain HTTP, resolved and SSRF-checked exactly as INV-51 already requires. Unlike a favicon URL, this hostname is not user- or domain-supplied, so it carries none of the "attacker picks the target" risk INV-51 was written for; DNS rebinding against a fixed hostname is still real, so the same check applies unchanged. The exact host, path and headers are U — not read from a primary source in this read-only session — and are confirmed in the implementing PR.
3. **No new credentials, no new DB path.** The endpoint runs inside the same no-DB-credentials, no-server-secrets process ADR 0010 §2 already requires of `icons`.
4. **Caching.** Responses are cached by prefix in the cache volume ADR 0010 §4 already gives `icons`, shared across users with no per-request, per-user log, mirroring favicon fetches' "anonymous shared cache, no per-user logs" property.
5. **A separate on/off switch, inside the same role.** `icons` is off by default (ADR 0010 owner decision 5, [Q-11](../THREAT_MODEL.md#10-open-questions-for-the-owner)); tying breach-check to that same switch would silently disable Watchtower whenever an operator opts out of favicons for unrelated reasons. Breach-check gets its own flag inside the `icons` role process, default off, set independently. See [Open question 2](#open-questions-for-the-owner).
6. **No CSP change.** [ADR 0014](0014-ui-stack.md) §2's "No third-party origins" rule and [INV-49](../THREAT_MODEL.md#8-security-invariants)'s CSP header test are untouched.
7. **No new cryptographic construction.** Fixing the encoding, case, prefix length and comparison in item 1 parameterizes an existing, externally-specified lookup, it does not invent one: [CRYPTO.md §3](../CRYPTO.md#3-primitives)'s `sha1` row already holds this exact posture for TOTP ("SHA-1 appears only where an external standard fixes it, never in a construction of ours") and names HIBP range queries in the same line. Neither TOTP's nor this flow's use of HMAC/SHA-1 is on [CRYPTO.md §1](../CRYPTO.md#1-goals-non-goals-and-rules) rule 2's list of our compositions, and item 1 adds nothing to it.
8. **Per-source rate limiting.** [ADR 0010 §1](0010-server-shape.md) gives `icons` inbound traffic as "public, through the proxy": the new endpoint is reachable by anyone who reaches the proxy, not only this instance's users. [THREAT_MODEL A15](../THREAT_MODEL.md#a15-other-users-and-the-anonymous-internet) already lists "Using the `icons` role as an open proxy" as a capability of that adversary and "The role is rate-limited" as its existing mitigation for favicon fetches; this endpoint inherits that limit, applied per source IP (falling back to a conservative global cap where a trustworthy client IP is unavailable), the same pattern `smtp`'s `resolve` call uses ([INV-44](../THREAT_MODEL.md#8-security-invariants)). See Risks.

### What this ADR supersedes

- **ADR 0010 §1, the role table, the `icons` row — in part.** Full replacement text:

  | Role | Does | DB access | Inbound | Outbound | From |
  |---|---|---|---|---|---|
  | `icons` | Fetches favicons, re-encodes them, caches them; proxies HIBP k-anonymity range queries by prefix and caches the responses | **no** | public, through the proxy | the internet only | M3 |

  Only the "Does" cell changes; every other cell keeps its original text and meaning.

Nothing else in ADR 0010 is named, so it stays binding as written. ADR 0014 §2 and INV-49 are not named and stay binding unchanged — this ADR creates no CSP exception.

### On acceptance

The change that accepts this ADR makes these edits. None is made now.

- **THREAT_MODEL §3.2 diagram:** extend TB-8's label ("`icons` to internet") to cover the HIBP leg, or add a TB-8a.
- **THREAT_MODEL §3.1**, the "External services" row: the HIBP cell gains a reference to proposed INV-77.
- **THREAT_MODEL §3.1**, the `icons` row: its "Holds keys or plaintext" cell gains "and password-hash prefixes" beside "sees domains".
- **THREAT_MODEL §3.4**, "What the server holds" table (the source for the M3 transparency page, [ROADMAP §4.5](../ROADMAP.md#45-design-ui--ux--1password-feel-m3)): a new row, "Password-hash prefixes requested from `icons`" / "Seen by the `icons` role if enabled" / proposed INV-77.
- **THREAT_MODEL §2**, AST-13: the metadata line gains "password-hash prefixes requested from `icons`" beside the existing "domains requested from the icons role".
- **THREAT_MODEL §7.11**, the `icons` STRIDE table: the I row's mitigation gains "and HIBP prefixes" beside "no per-user logs"; the per-source rate limit (Decision item 8) is noted against the same row.
- **CRYPTO.md:** a new §11.16 "Breach check (HIBP k-anonymity, M3)" lands in the change that accepts this ADR, transcribing the flow Decision item 1 already fixes — the [ADR 0038](0038-equivalent-domain-list.md) pattern of fixing the construction in the ADR and writing it up on acceptance, not the [ADR 0041](0041-p256-crate-approval.md) pattern of deferring an undecided flow to the implementing PR (this ADR leaves no flow undecided).

**Proposed INV-77** (allocated across the 2026-10-11 batch in ADR-number order. Provisional: the allocation was made across the 2026-10-11 batch in ADR-number order; if ADRs are accepted out of order, the owner renumbers at acceptance.): *The `icons` role's breach-check traffic connects only to one pinned, config-named upstream host over HTTPS, under the same SSRF allow-list and DNS-pinning as INV-51; clients send only a 5-hex-char SHA-1 prefix in the request payload, with no account identity, session token or item id in that payload (IP- and timing-level correlation through the shared proxy is a separately accepted risk, not covered by this invariant); the endpoint is rate-limited per source alongside the existing favicon-fetch limit; responses are cached by prefix with no per-user log; and the role keeps the no-DB-credentials, no-server-secrets properties ADR 0010 §2 already requires of it.*

### Owner answers at acceptance (2026-10-22)

The owner accepted this ADR as drafted; the recommendations of "Open questions for the owner" stand:

1. Yes, a password-hash prefix reaching the `icons` role is acceptable under CRYPTO.md Goal 1. This rests on the Decision's no-account-identity, rate-limit (item 8) and no-per-user-log rules, which are load-bearing. IP and timing correlation through the shared proxy is an accepted residual risk.
2. There are two role flags: `icons` keeps its favicon switch, and breach-check gets its own. Both are off by default.

Of the "On acceptance" edits, all are made in the accepting change: THREAT_MODEL.md §2 (AST-13), §3.1 (the `icons` and "External services" rows), §3.2/§3.3 (TB-8's label is extended, not split into a TB-8a), §3.4 (a new row), §7.11 (the I row) and INV-77 in §8.8. CRYPTO.md gains the breach-check section. It is numbered §11.16 as drafted. ADR 0058 also asked for a §11.16, so its section is numbered §11.17. ADR 0010's status line names this ADR for the `icons` row of its §1 role table, which "What this ADR supersedes" replaces in part. The known-answer vectors (CRYPTO.md §15) and the exact upstream host, path and headers (item 2, U) land with the implementation.

## Consequences

### Positive

- One audited egress discipline (allow-list, DNS pinning, no DB credentials, no per-user logs, now a per-source rate limit) covers both favicon and HIBP traffic, instead of that mechanism plus a second, client-specific CSP carve-out.
- The instance's IP, not each user's, reaches HIBP; users checking the same prefix share one cached answer.
- The web vault's CSP stays exactly as narrow as ADR 0014 §2 and INV-49 already made it.
- Reuses ADR 0052's fetch/cache/allow-list code instead of writing a second one.

### Negative

- Makes the breach-check feature depend on the `icons` role existing and being reachable (the separate flag in Decision item 5 limits, but does not remove, this coupling).
- The `icons` role process now sees a password-prefix fact it did not see before; see the Context trade-off and Open question 1.
- One more fixed external dependency (HIBP's availability and API shape) in a role that was previously only a favicon fetcher.

### Risks

- **Not implementable until ADR 0052 is Accepted and `rizzy-icon-proxy` exists.** If 0052 is rejected or changes substantially, this ADR's Decision is revisited.
- **An anonymous caller uses the new endpoint as it already can the favicon fetch.** [THREAT_MODEL A15](../THREAT_MODEL.md#a15-other-users-and-the-anonymous-internet) already names "Using the `icons` role as an open proxy" and rate-limits the role for exactly this; Decision item 8 extends that limit, per source, to the new endpoint. A caller who ignores the limit anyway still consumes the instance's own egress, cache volume and CPU and fills the shared cache for no benefit to that instance's users; whether abuse can also exhaust HIBP's *own*, separately rate-limited quota depends on thresholds HIBP does not publish to us — U, same tag this ADR already gives HIBP's limits in the References.
- **HIBP's host, path or rate limits change.** Mitigated by keeping the destination one named config value behind the allow-list entry, and by an "unavailable" UI state rather than a hard failure.
- **A later reviewer reads the prefix as a password-equivalent** under CRYPTO.md Goal 1 and asks for the client-side route after all. Open question 1 exists for exactly this.

## Alternatives considered

- **Client-side CSP exception for the web vault (the option this ADR rejects).** Needs ADR 0014 §2 amended, a new `connect-src` origin, and a separate decision for the extension's own CSP. Costs a second audited egress surface for no privacy gain over the proxy route.
- **Route through the `api` role instead of `icons`.** Rejected: `api` holds DB credentials and session state; adding internet egress there widens exactly the blast radius ADR 0010's isolation (G-11, INV-44, INV-51) exists to avoid.
- **No server involvement; link out to HIBP's own site.** Rejected: not integrated Watchtower UX; ROADMAP §4.5 asks for the check inside the health report.
- **Self-host the full compromised-password corpus.** Rejected for M3: gigabytes of data needing its own update pipeline, out of scope for a personal self-hosted instance.

## Open questions for the owner

1. **Is a password-prefix fact reaching the `icons` role acceptable under CRYPTO.md Goal 1's "never sees a master password or a password-equivalent"?** *Recommendation: yes*, with the no-account-identity, rate-limited (item 8) and no-per-user-logging rules in the Decision treated as load-bearing, re-argued here on a corrected basis:
   - **The math, corrected.** A 5-hex-char prefix is 20 bits of a 160-bit SHA-1 digest: it is a filter, not a disclosure, ruling the candidate's digest into 1 of 2^20 (1,048,576) buckets on average — not 1/16th, which is the narrowing from a single hex digit (4 bits). [CRYPTO.md §2](../CRYPTO.md#2-conventions)/[§3](../CRYPTO.md#3-primitives) have no precedent for a 1/16 figure; that number in an earlier draft of this ADR was wrong and is corrected here, not merely restated. Against a client-generated high-entropy password the residual 20-bit-narrowed space is still infeasible to invert; against a weak, dictionary-guessable password, prefix-plus-dictionary is a real, if small, narrowing the server did not have before — this is new information in kind, not merely "weaker than existing metadata," and the recommendation below rests on that honest framing, not on a claim this ADR has not verified.
   - **What "no account identity" does and does not cover.** The Decision strips identity from the request *payload* only. [THREAT_MODEL §3.3 TB-3](../THREAT_MODEL.md#33-trust-boundaries) places the reverse proxy inside the server trust zone, seeing all client traffic including session tokens, and [§7.11](../THREAT_MODEL.md#711-icons-role-m3)'s own I row already names "(requests, IPs, timing)" as a leak for the `icons` role: a breach-check call made moments before or after an authenticated vault request, from the same IP through the same proxy, is correlatable to that account by timing and source address alone, with no explicit account id in the payload. This ADR records that as an accepted residual risk under the existing I-row mitigation plus item 8's rate limit, not as a new mechanism — it adds no batching, jitter or other correlation-specific control, which would need its own decision.
   - A no on either point reverses the route to client-side, which then needs its own ADR 0014 §2 amendment.
2. **One role flag or two?** *Recommendation: two* — `icons` keeps its existing favicon switch, and breach-check gets its own, both off by default, so an operator can run either without the other. A single combined switch is simpler to document; take that instead if the coupling in Negative consequences is acceptable.

## References

- [ROADMAP](../ROADMAP.md) §4.5 (row "Watchtower-style health"), §4.1 (`rizzy-icon-proxy`)
- [THREAT_MODEL](../THREAT_MODEL.md) §2 (AST-13), §3.1 ("External services", the `icons` row), §3.2 (diagram), §3.3 (TB-3), §3.4 (the M3 transparency-page source table), §7.11 (`icons` STRIDE), [A1](../THREAT_MODEL.md#a1-passive-server-compromise-db-or-backup-theft), [A15](../THREAT_MODEL.md#a15-other-users-and-the-anonymous-internet), [INV-44](../THREAT_MODEL.md#8-security-invariants), [INV-49](../THREAT_MODEL.md#8-security-invariants), [INV-51](../THREAT_MODEL.md#8-security-invariants), [Q-11](../THREAT_MODEL.md#10-open-questions-for-the-owner)
- [CRYPTO.md](../CRYPTO.md) §1 (Goal 1, rule 2), §2 (`ct_eq`, NFC), §3 (sha1 row), §11 (flows §11.1–§11.15, no breach-check entry yet; V, section scan 2026-10-11), §15 (testing)
- [ADR 0009](0009-crypto-dependency-policy.md) (sha1 approval, "HIBP range queries from M3"), [ADR 0010](0010-server-shape.md) §1, §2, §4, [ADR 0014](0014-ui-stack.md) §2, [ADR 0020](0020-partial-supersession.md) point 9, [ADR 0038](0038-equivalent-domain-list.md) (fixed-construction-in-ADR precedent), [ADR 0041](0041-p256-crate-approval.md) (deferred-bookkeeping precedent, distinguished above, not followed for the flow itself)
- ADR 0052 (this batch, Proposed, M3): the icon-proxy fetch/cache/allow-list mechanism this ADR extends. Filename not linked: not yet committed at drafting time.
- `crates/rizzy-server/src/config.rs` L200–202 (the `Role` enum: `Api`/`Web`/`Worker` only, doc comment "Only the M1 roles exist in this build", no `Icons` variant), L244 (`Roles::parse`'s doc comment naming `icons` as refused), L263 (the `"icons"` match arm returning `ConfigError::RoleNotInThisBuild`, never constructing a `Role`; V, read 2026-10-11)
- HIBP API host, path shape and rate limits: U, not read from a primary source in this session; confirmed in the implementing PR.
