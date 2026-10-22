# ADR 0044: Equivalence-group member rules: no IP literals, registrable domains only

- Status: Accepted
- Date: 2026-10-11
- Deciders: project owner
- Milestone: M2

## Context

[ADR 0038](0038-equivalent-domain-list.md) §1 calls a group's members "registrable domains... each in normalized A-label form," but no code enforces that word. `EquivalenceGroup::new`/`::decode` (`crates/rizzy-match/src/equivalence.rs`) run every member through [`normalize_domain`](../../crates/rizzy-match/src/normalize.rs) (`idna` domain-to-ASCII — no concept of an IP address or the PSL) and accept whatever comes back. Two gaps, pinned as `#[ignore]`d probes in `adr0037_differential/main.rs` (`equivalence_group_can_contain_an_ip_literal_looking_domain_string`, `such_a_group_lets_an_ip_literal_page_match_an_unrelated_domain_uri`, V: read 2026-10-11):

- **IP-literal members.** `"192.168.1.1"` is accepted as an ordinary domain. [`NormalizedUrl::parse`](../../crates/rizzy-match/src/normalize.rs) already treats an IP literal as its own registrable domain (`rizzy-match`'s own implementation choice, not specified by [ADR 0037](0037-url-matching-and-autofill-rules.md) — §2 point 7 only says the registrable domain is "computed from the IDNA A-label host against the compiled-in PSL snapshot," with no IP-literal case; see `adr0037_differential/main.rs`'s "Not covered by this harness" note), so a group pairing an IP literal with an unrelated domain lets a page reached by that literal match a saved URI at the unrelated domain under *Base domain* (flagged `Equivalence`, warned, not refused).
- **Non-registrable-domain members.** A bare suffix (`"co.uk"`) and a subdomain (`"mail.example.com"`) are both accepted; neither is checked against [`suffix::registrable_domain`](../../crates/rizzy-match/src/suffix.rs), the function `NormalizedUrl` itself uses for the page and URI sides of every match.

ADR 0038 has no clause on decoder leniency separate from §1 — the `group` record is the decode contract — so one named part covers both. `GLOBAL_LIST`/`LIST_SIGNING_PUBLIC_KEY` are both `None` (`compiled.rs`): no signed list has shipped, so tightening now breaks nothing. Owner's call: reject both kinds, in the shared code the global list and (ADR 0038 §5) a user group build on.

## Decision

### What this ADR supersedes ([ADR 0020](0020-partial-supersession.md) point 9)

- **ADR 0038 §1**, the `group` record's domain-member line: "`u16 m ‖ m × str(domain)` — registrable domains in the group, 2 ≤ m, each in normalized A-label form (ADR 0037 §2), sorted bytewise, no duplicates." Replaced in full by: *"`u16 m ‖ m × str(domain)` — each `domain` equal to its own registrable domain as `NormalizedUrl::parse` computes one (eTLD+1 under the compiled-in PSL snapshot, or the host itself when it contains no dot), and never a host `url::Host::parse` classifies as `Ipv4`/`Ipv6`; 2 ≤ m, each in normalized A-label form (ADR 0037 §2), sorted bytewise, no duplicates."* Nothing else in ADR 0038 is touched; it stays binding.

### The rule, per member, in both `EquivalenceGroup::new` and `::decode`

1. **No IP literal.** `url::Host::parse(domain)` (L: public since `url` 2.x — the same classification `NormalizedUrl::parse` already runs via `parsed.host()`) must not return `Host::Ipv4`. Reusing the `url` crate's parser, not a dotted-quad regex, also catches the octal/hex/decimal IPv4 notations the differential harness already probes elsewhere. (An IPv6 literal cannot reach this check at all: `normalize_domain`'s `AsciiDenyList::URL` already denies `:`, `[` and `]` — V, `idna` 1.1.0 `uts46.rs` line 346 — so `EquivalenceGroup::new`'s existing `normalize_domain` call rejects it first, as `DomainError::Invalid`, with no change needed here.)
2. **Registrable domain, exactly.** Define `registrable(domain)` the same way [`NormalizedUrl::parse`](../../crates/rizzy-match/src/normalize.rs) computes a host's own registrable domain (`normalize.rs:132-147`): `suffix::registrable_domain(domain)`, or `Some(domain.to_owned())` when `domain` has no dot (never an IP literal here — rule 1 already rejects those). The rule: `registrable(domain) == Some(domain.to_owned())`. Rejects a bare multi-label suffix (`"co.uk"` → `None`) and, new here, a **subdomain** like `mail.example.com` (`Some("example.com")`, not itself); accepts a dotless single-label member like `"nas"` (`Some("nas")`). `modes::registrable_gate` (V, `modes.rs:161-174`) always calls `EquivalenceView::same_group` with `page.registrable_domain()`/`uri.registrable_domain()` — computed by that same fallback, never a full host — so a subdomain member can never equal either side of any match (permanently unreachable), while a bare intranet hostname like `nas` is fully reachable and must not be rejected. Rejecting the subdomain case turns a silent no-op into a loud error at the point a reviewer can still act on it, which is also the reading ADR 0038 §1's "registrable domain" already states.

Both map to the existing `EquivalenceListError::Malformed` — no new variant. `Malformed` already covers "a domain that is not a valid A-label"; an IP literal or a non-registrable string is one more shape in that category, the same way a duplicate or an out-of-range count are not split out today.

### Where this applies

- **`EquivalenceGroup::new`/`::decode`**: the one place the rule lives.
- **The xtask signing tool** (`crates/xtask/src/equivalence_list.rs`): already calls `EquivalenceGroup::new` per line, so it inherits the rule — a bad entry fails the build, never reaches signing.
- **User-defined groups, once [ADR 0042](0042-account-settings-matching-layout.md) lands** (Proposed, reference only): ADR 0042 §4 reuses `EquivalenceGroup::new`/`::decode` "as-is," so it inherits this rule too. ADR 0042 §4 also proposes its own public-suffix refusal "before building a `user_group`" — once this ADR is Accepted that check is redundant with, not contradicted by, `EquivalenceGroup::new`'s own rejection (Open questions, 1).

### A PSL bump that turns a signed member into a suffix

Reject the whole list, not skip the group. If a PSL update (ADR 0037 §3) makes a shipped, validly signed member no longer equal its own registrable domain, `EquivalenceGroup::decode` rejects that group, failing `decode_ctx` before `verify_strict` runs, so [`compiled::global_list`](../../crates/rizzy-match/src/compiled.rs) returns `Err(EquivalenceListError::Malformed)`, not `Ok(None)` — `compiled.rs`'s own no-list case (`compiled.rs:55`) only covers `GLOBAL_LIST`/`LIST_SIGNING_PUBLIC_KEY` being absent, not a decode/verify failure on a list that is compiled in. **`rizzy-client`, once it exists, MUST map that `Err` the same way: empty global groups, user-defined groups only** — a binding requirement this ADR imposes on that future caller, not a description of existing behaviour. This matches ADR 0038's own rejection of per-entry signatures as "partial-trust complexity a single list-level signature avoids" (Alternatives, bullet 3) — `decode_ctx` has no per-group recovery path, and building one for this case alone would reopen exactly that. Mitigation is process, not code: a PSL bump (ADR 0037 §3) re-runs the equivalence-list builder against the new snapshot in the same review, the way `cargo xtask check-deps` already treats PSL data.

### INV-38 / INV-39 interaction

No mechanism changes. The new checks run inside `decode_ctx`'s structural pass, before `verify_strict` (`EquivalenceList::verify`'s existing order) — orthogonal to INV-39's signature/freshness check. They tighten what INV-38's "equivalence group" may itself contain, closing the IP-literal loophole in `NormalizedUrl`'s own carve-out, without touching the registrable-domain gate INV-38 names.

### Tests required

- Un-ignore and flip both pinned probes: assert `is_err()`/`NoMatch`.
- Ordering: reject a dotless decimal/octal IPv4 notation (e.g. `"2130706433"`) — rule 1 must catch it before rule 2's dotless fallback could otherwise accept it as its own registrable domain.
- `new`/`decode`: reject an IPv4 and an IPv6 literal; reject `"co.uk"` (unchanged) and, new, `"mail.example.com"`; accept `"example.com"` unchanged and, new, a dotless single-label member like `"nas"`.
- `decode`: a hand-built wire group with such a member (bypassing `new`) is rejected the same way; `verify_never_panics` keeps covering this structurally.
- xtask builder: a source line naming either shape fails the build step.

### Migration

None: no signed list has shipped, so no existing data this rule could invalidate.

## Consequences

### Positive
- Closes both pinned findings; `EquivalenceGroup` enforces the word ADR 0038 §1 already used.
- One rule, one place: the global list, the xtask builder and (per ADR 0042) user groups all inherit it with no duplicated logic.

### Negative
- A PSL bump can now invalidate a previously valid signed list — a new coupling between the PSL and equivalence-list release steps.

### Risks
- Depends on the same compiled-in PSL snapshot ADR 0037 §3/AR-15 already accepts can be stale — not a new risk, the existing one surfacing in one more place.

## Alternatives considered

- **Skip the malformed group, keep the rest of the list.** Rejected: reopens the partial-trust complexity ADR 0038 rejected for per-entry signatures.
- **New error variants (`IpLiteral`, `NotRegistrableDomain`).** Rejected for now: no caller branches on cause; `Malformed` already covers every other per-domain shape violation.
- **Allow subdomains as members.** Rejected: not what ADR 0038 §1 says, and does not widen matching given `same_group`'s exact-string comparison.

## Open questions for the owner

1. **Should ADR 0042, on acceptance, drop its own §4 public-suffix check?** *Recommendation:* yes — `EquivalenceGroup::new` already refuses a bare suffix and a subdomain for every caller once this ADR is Accepted; leave the call to whoever finalises ADR 0042.
2. **Tie a PSL bump to an equivalence-list re-check in CI?** *Recommendation:* fold into the existing `cargo xtask check-deps` PSL review; implementation detail, not a security gate.

## On acceptance

This ADR makes none of these edits. The owner makes them in the change that accepts it, following the pattern of ADRs 0038 and 0042:

- **ADR 0038**'s status line → `Partially superseded by [ADR 0044](0044-equivalence-group-member-rules.md) (§1 in part)`.
- **[docs/adr/README.md](README.md)**: row 0038's Status cell updates to match; row 0044's Status → Accepted.
- **[CLAUDE.md](../../CLAUDE.md)**: the "As of" sentence drops 0044 from the Proposed list and its date moves forward.

## References

- [ADR 0020](0020-partial-supersession.md) point 9; [ADR 0037](0037-url-matching-and-autofill-rules.md) §2, §4; [ADR 0038](0038-equivalent-domain-list.md) §1, §5; [ADR 0042](0042-account-settings-matching-layout.md) §4 (Proposed, reference only)
- [THREAT_MODEL.md](../THREAT_MODEL.md) [A6](../THREAT_MODEL.md#a6-phishing-site-and-autofill-abuse), [INV-38, INV-39](../THREAT_MODEL.md#8-security-invariants)
- Code read 2026-10-11 (V): `crates/rizzy-match/src/{equivalence.rs,normalize.rs,compiled.rs,suffix.rs,error.rs}`, `crates/xtask/src/equivalence_list.rs`, `crates/rizzy-match/tests/adr0037_differential/main.rs`
- The `url` crate's `Host::parse` (L: public since 2.x, not independently re-verified here — confirm in the implementation PR)
