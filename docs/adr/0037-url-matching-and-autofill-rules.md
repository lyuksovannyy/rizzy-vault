# ADR 0037: URL matching and autofill rules

- Status: Accepted
- Date: 2026-10-07
- Deciders: project owner
- Milestone: M2

## Context

[ROADMAP §4.4](../ROADMAP.md#44-url-matching--autofill-m2) states the problem precisely: "`youtube.com`, `youtu.be`, `m.youtube.com`, `accounts.google.com` all belong to the same login; `evil-youtube.com` must **never** match. Over-matching is a phishing vulnerability, not a convenience bug." Its Musts for M2: URL normalisation (scheme, IDNA/punycode, trailing dots, ports, default paths); registrable-domain matching via the Public Suffix List (PSL); equivalent-domain groups, global and user-defined, with the ability to disable a global group ([ADR 0038](0038-equivalent-domain-list.md) is the companion ADR for the list itself); per-URI match mode (*Base domain*, *Host*, *Starts with*, *Exact*, *Regex*, *Never*); the security rules (no HTTPS→HTTP fill, no cross-origin iframe fill by default, gesture-only fill); a visible warning on an equivalence-only match.

**What already binds.**
- [THREAT_MODEL](../THREAT_MODEL.md) [A6](../THREAT_MODEL.md#a6-phishing-site-and-autofill-abuse) names the exact mitigations this ADR must deliver, and [INV-36](../THREAT_MODEL.md#8-security-invariants) to [INV-39](../THREAT_MODEL.md#8-security-invariants) are the testable statements: gesture-only fill (INV-36); no HTTPS-saved credential into HTTP, nothing into cross-origin iframes by default, nothing into hidden/invisible fields (INV-37); PSL-based registrable-domain matching that **every** mode narrows and never widens, checked before *Starts with* and *Regex* in particular (INV-38); a signed, versioned equivalence list with no downgrade (INV-39).
- [ADR 0018](0018-item-record-encoding.md) (Accepted) §7 already reserves the field key `uri/<id>/match` (Enum, SortKey siblings `/value`, `/order`) on the Login item type, with the note: "`match` is reserved for M2: absent means the account default, and the M2 ADR assigns its values. M1 clients carry it and never write it (owner decision 2)." This ADR is that M2 ADR; it assigns the enum values, it does not supersede ADR 0018, which explicitly delegated this.
- [CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes) and [INV-14](../THREAT_MODEL.md#8-security-invariants) name where the *account-level* settings live: "account-level match defaults, equivalence groups and autofill rules" in the signed `account-state`/`ACCOUNT_SETTINGS`, per ADR 0018 owner decision 2's amendment (ADR 0018 "On acceptance" item 2).
- [ADR 0016](0016-workspace-layout.md) §3 already plans the crate: `rizzy-match`, M2, "URL normalisation, PSL (the `psl` crate), signed equivalence lists," depending only on `rizzy-core`, no I/O, builds for wasm32 — an R1 crate under [ADR 0016](0016-workspace-layout.md) §4's rules, so it never touches the network, filesystem or clock, and the PSL snapshot and the signed equivalence list ship as data compiled into the client, not fetched at runtime.
- [ADR 0014](0014-ui-stack.md) §2: the extension's content script is framework-free TypeScript that "detects login fields, and positions and injects the extension-origin iframe," "performs the fill the user chose," and "reports submitted credentials to the background for save/update." Matching itself does not run in the content script; it runs in the background/long-lived context (this ADR, §5), which is where `rizzy-match` lives per [ADR 0036](0036-browser-extension-architecture-and-key-custody.md).
- [ADR 0019](0019-native-clients.md) §2.2 (Safari) is explicitly **not** in scope for M2 or M3; it needs its own key-custody ADR first and is deferred to M7 or later per ROADMAP §4.4.

## Decision

### 1. Where the code lives

`rizzy-match` ([ADR 0016](0016-workspace-layout.md) §3), not `rizzy-core`. It is an R1 crate (no I/O, builds for wasm32, [ADR 0016](0016-workspace-layout.md) §4 R1) that depends only on `rizzy-core` for shared primitives (none of its own crypto: matching needs no secret-dependent comparison beyond the signature check on the equivalence list, which is an Ed25519 verify through `rizzy-core`'s existing API). It compiles the PSL snapshot and the signed equivalence list in as build-time data (`include_bytes!` or an equivalent build step), never fetched over the network from inside the crate. Every client (web vault, extension, CLI, and later desktop/mobile) calls the same `rizzy-match` functions through `rizzy-client`.

### 2. URL normalisation

Given a raw URL string (from an item's `uri/<id>/value`, or from the page the user is on):
1. **Parse** with a URL parser already in the dependency tree or added for this purpose (candidate: the `url` crate, a de facto standard; not a crypto dependency, so it follows ordinary `cargo deny` review, not [ADR 0009](0009-crypto-dependency-policy.md)'s checklist). Reject input that does not parse as an absolute URL.
2. **Scheme.** Lowercase. Only `http` and `https` are matchable; anything else (`ftp:`, `ssh:`, …) never matches and is never filled ([INV-42](../THREAT_MODEL.md#8-security-invariants) already bans opening or filling non-`http(s)` schemes from item fields).
3. **Host.** IDNA-processed to its A-label (punycode) form for matching and comparison. **The `idna` crate must be pinned at `1.0` or later**, because of RUSTSEC-2024-0421 ([THREAT_MODEL](../THREAT_MODEL.md) A6, already citing this). Lowercase after IDNA processing. A trailing dot on the host is stripped before comparison (`example.com.` ≡ `example.com`).
4. **Mixed-script IDN hosts are displayed in punycode**, never as decoded Unicode, in any UI that shows the matched host (fill confirmation, equivalence warning, item editor): this is the mitigation [A6](../THREAT_MODEL.md#a6-phishing-site-and-autofill-abuse) already names for homograph attacks.
5. **Port.** Default ports (80 for `http`, 443 for `https`) are omitted from the normalised form; any other port is kept and is part of the comparison for *Host*, *Starts with* and *Exact* modes, but never part of the registrable-domain computation.
6. **Path and query.** Dropped for every mode except *Starts with* (keeps the path prefix) and *Regex* (matches against the full normalised URL, scheme and all, per [INV-38](../THREAT_MODEL.md#8-security-invariants)).
7. **Registrable domain (eTLD+1).** Computed from the IDNA A-label host against the compiled-in PSL snapshot ([§3](#3-public-suffix-list)). `a.b.example.co.uk` → `example.co.uk`.

The output of normalisation is a small `NormalizedUrl` struct: scheme, A-label host, port-or-default, registrable domain, path (kept only when a mode needs it), the original string for *Regex* and for display.

### 3. Public Suffix List

- **Source.** The Mozilla Public Suffix List (publicsuffix.org), the same list every major browser and the `psl` crate ship. This is the list [ADR 0016](0016-workspace-layout.md) §3 already names for `rizzy-match`.
- **Rust crate.** The `psl` crate ([ADR 0016](0016-workspace-layout.md) §3's own wording). Its exact version and release cadence are **unverified (U)** at the time of writing; the approval PR that adds it to `rizzy-match`'s dependencies pins an exact version in `[workspace.dependencies]` and records it like any other dependency ([CLAUDE.md](../../CLAUDE.md) "Justify every new crate"). It is not a cryptographic dependency and does not go through [ADR 0009](0009-crypto-dependency-policy.md)'s checklist, but a corrupted or malicious PSL snapshot is a direct phishing vector, so the data file itself is treated like the equivalence list for integrity purposes (next bullet).
- **Snapshot and update.** The PSL snapshot compiled into a release is pinned to a specific upstream commit or release tag, recorded in `rizzy-match`'s source (a comment with the commit hash and fetch date) so a reviewer can diff it. It updates in an ordinary dependency-bump PR, reviewed like any other change to compiled-in security data: a diff of added/removed suffixes is in the PR description. There is no runtime fetch and no admin-configurable PSL source — a server-supplied PSL would reopen exactly the downgrade class [§5](../THREAT_MODEL.md#5-server-controlled-parameter-attacks) of THREAT_MODEL exists to close.
- **Verification.** The build step that embeds the PSL snapshot computes its SHA-256 and asserts it against a constant in the source, so an accidental or tampered snapshot file fails the build loudly rather than shipping silently. There is no cryptographic signature on the PSL snapshot itself (unlike the equivalence list, [ADR 0038](0038-equivalent-domain-list.md)): the PSL is public, machine-generated from public submissions, and comes to us only through our own reviewed dependency-bump PRs, which is the control.
- **Staleness.** [THREAT_MODEL](../THREAT_MODEL.md) AR-15 already accepts that clients that never update carry an old PSL and old list; nothing in this ADR changes that acceptance.

### 4. Match modes

The per-URI match mode is the Enum value of `uri/<id>/match` ([ADR 0018](0018-item-record-encoding.md) §7), assigned here as ADR 0018 owner decision 2 anticipated:

| Value | Mode | Rule |
|---|---|---|
| `0x0000` | *(absent / account default)* | Uses the account-level match default from `ACCOUNT_SETTINGS` ([§6](#6-account-level-settings)); M1 items that never wrote this field read as `0x0000` |
| `0x0001` | **Base domain** (the fallback default when no account default is set) | Matches when the page's registrable domain equals the URI's registrable domain, or they are in the same equivalence group ([ADR 0038](0038-equivalent-domain-list.md)) |
| `0x0002` | **Host** | Matches when the page's full host (not just registrable domain) equals the URI's host exactly, after normalisation. No equivalence-group widening |
| `0x0003` | **Starts with** | Matches when the page's normalised URL (scheme + host + port + path) starts with the URI's normalised URL **and** the registrable-domain check of [§5](#5-security-rules) passes first |
| `0x0004` | **Exact** | Matches when the full normalised URL is byte-equal |
| `0x0005` | **Regex** | The URI's `value` is a user-authored regular expression; it matches when it matches the page's full normalised URL **and** the registrable-domain check passes first (so an unanchored pattern cannot escape the registrable domain, [INV-38](../THREAT_MODEL.md#8-security-invariants)) |
| `0x0006` | **Never** | This URI is never offered for autofill matching (still shown and editable in the item) |
| `0x0007`–`0xFFFF` | unassigned | A new mode needs a line in this table via an ADR update, like any other ADR 0018 enum extension |

**Narrowing only ([INV-38](../THREAT_MODEL.md#8-security-invariants)).** Every mode above *Never* first passes the registrable-domain check: the page's registrable domain must equal the URI's registrable domain, or be in an equivalence group with it ([ADR 0038](0038-equivalent-domain-list.md)), or the match fails outright regardless of what the mode's own rule would otherwise say. *Starts with* `https://bank.com` therefore never matches `https://bank.com.evil.example/`, because `bank.com.evil.example`'s registrable domain is `evil.example`, not `bank.com`. An unanchored *Regex* against a foreign host fails the same gate before the regex ever runs.

### 5. Security rules

Each rule below is a `rizzy-match` function, not a convention left to callers, so the extension, web vault and any future client enforce it identically:
- **No HTTPS → HTTP fill.** A URI saved as `https://…` is never offered as a match against a page served over plain `http://` (INV-37). An HTTP-saved URI may still match an HTTPS page (the common case of a site that redirects to HTTPS).
- **Gesture-only fill (INV-36).** `rizzy-match` only *computes candidates*; it never triggers a fill. The caller (the extension's background/content-script pair) fills only in response to a trusted user gesture (a click on a candidate in the inline menu or popup), never on page load, never from a background timer.
- **No cross-origin iframe fill by default (INV-37).** Matching and filling run against the top frame's origin; a same-origin iframe is treated as the top frame. A cross-origin iframe gets no automatic candidate list. This is a hard default for M2; relaxing it for same-registrable-domain iframes is a later, explicitly reviewed change, not an implicit consequence of *Base domain* matching.
- **No hidden/invisible field fill.** Enforced by the extension's content script (visibility and topmost checks, [ADR 0036](0036-browser-extension-architecture-and-key-custody.md) §5; [THREAT_MODEL](../THREAT_MODEL.md) A7), not by `rizzy-match` itself, which has no DOM access.
- **Equivalence-only match warning.** When the only reason a candidate matched is an equivalence group (global or user-defined) rather than an exact registrable-domain equality, `rizzy-match`'s result for that candidate carries a flag (`matched_via: Equivalence(group_id)`), and the fill UI **must** show a visible notice naming the matched site and the saved site before the user confirms the fill. A plain registrable-domain match or better never carries this flag.
- **Exact host shown.** The fill UI always displays the page's exact normalised host (punycode form if mixed-script), never only "this site," so a user can notice an unexpected match.

### 6. Account-level settings

Per [CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes) and [INV-14](../THREAT_MODEL.md#8-security-invariants), these live in the signed `account-state`/`ACCOUNT_SETTINGS`, never trusted from the server outside that signed object:
- **Account-level match default.** The mode a URI with `uri/<id>/match = 0x0000` falls back to. Defaults to *Base domain* (`0x0001`) when the account has never set one.
- **Equivalence-group overrides.** Which global groups ([ADR 0038](0038-equivalent-domain-list.md)) the account has disabled, and the account's own user-defined groups. `ACCOUNT_SETTINGS`' freshness (`settings_seq`, `settings_hash` in `account-state`) means a server cannot silently reinstate a disabled group or an old equivalence list version without a client catching it ([§5.3](../THREAT_MODEL.md#53-unbound-items-and-settings)).

### 7. User-defined equivalence groups and disabling a global group

User-defined groups and per-group disable flags are account settings ([§6](#6-account-level-settings)); their storage format and the global list's own format, signing and governance are [ADR 0038](0038-equivalent-domain-list.md)'s. `rizzy-match`'s matching function takes the merged view (global list minus disabled groups, plus user groups) as a plain input and has no opinion on where it came from.

### Owner answers at acceptance (2026-10-07)

The owner accepted this ADR with the recommendations of "Open questions for the owner": the URL parser is the `url` crate, subject to the usual dependency review in the change that adds it; an unanchored regex gets a warning in the editor but can be saved; the PSL snapshot is bumped on every release and whenever upstream moves.

## Consequences

### Positive

- One matching implementation (`rizzy-match`) for every client, so a phishing-relevant bug is fixed once.
- Narrowing-only match modes make the registrable-domain check unconditional: a future mode cannot accidentally widen past it, because the gate sits outside the per-mode dispatch.
- No runtime PSL or equivalence-list fetch means no new server-controlled downgrade surface.

### Negative

- *Base domain* matching, the default, still autofills on any subdomain, including a dangling-CNAME subdomain takeover of the real site (residual risk already accepted in [THREAT_MODEL](../THREAT_MODEL.md) A6; *Host* mode is the user's escape hatch).
- Pinning the PSL snapshot means a brand-new registrable suffix (a new shared-hosting TLD arrangement) is not recognised until the next release ([THREAT_MODEL](../THREAT_MODEL.md) AR-15).
- A user-authored regex mode is a footgun: a loose pattern narrowed only by the registrable-domain gate can still match more than the user intended within that domain (for example every subdomain and path). The UI should warn when a regex has no anchors, but that is a usability detail for the M2 implementation, not a security gate this ADR can remove.

### Risks

- `psl` crate abandonment or a long gap between PSL upstream updates and our dependency bumps. Signal: a dependency-bump PR more than, say, 90 days stale against upstream. Mitigation: routine Dependabot review already covers it.
- IDNA processing bugs (homograph handling, bidi text) are a standing phishing surface independent of this ADR; the `idna` 1.0+ pin is the only mitigation adopted here.

## Alternatives considered

- **Fetch the PSL and equivalence list from the server at runtime.** Rejected outright: it reopens the exact downgrade class [§5](../THREAT_MODEL.md#5-server-controlled-parameter-attacks) of THREAT_MODEL is built to close — a malicious server could simply omit entries that would otherwise warn the user, or add ones that widen matching.
- **Put matching in `rizzy-core` directly.** Rejected: `rizzy-core` is reserved for crypto, envelopes and item models ([ADR 0016](0016-workspace-layout.md)); `rizzy-match` already exists as the planned crate for exactly this, keeping the audit scope of `rizzy-core` narrow.
- **Allow *Starts with* and *Regex* to bypass the registrable-domain gate for power users.** Rejected: this is the precise over-matching vulnerability ROADMAP §4.4 opens with. Users who want a broader net already have equivalence groups (governed, [ADR 0038](0038-equivalent-domain-list.md)) as the reviewed path.
- **Allow iframes to inherit the top frame's match candidates for same-registrable-domain iframes.** Deferred, not rejected: it is a plausible M3+ convenience, but it needs its own explicit review of cross-origin framing risk and is out of scope for the M2 baseline.

## Open questions for the owner

1. **URL parser crate.** *Recommendation:* the `url` crate (de facto standard, used across the Rust ecosystem); confirm in the M2 implementation PR with the usual dependency-review notes, since it was not independently verified for this ADR (**U**).
2. **Default auto-lock-equivalent for the regex-mode warning UI.** Whether an unanchored user regex should warn or simply be allowed. *Recommendation:* warn in the editor when the pattern lacks `^`/`$` anchors, but do not block saving it — this is a product/UX decision, not a security gate.
3. **PSL update cadence.** *Recommendation:* bump on every rizzy-vault release at minimum, and whenever Dependabot or a manual check shows the upstream PSL has moved; no stricter SLA is proposed for M2.

## References

- [ROADMAP](../ROADMAP.md) §4.4
- [THREAT_MODEL.md](../THREAT_MODEL.md) [A6](../THREAT_MODEL.md#a6-phishing-site-and-autofill-abuse), §5.3, [INV-36](../THREAT_MODEL.md#8-security-invariants) to INV-39, AR-15, RUSTSEC-2024-0421
- [CRYPTO.md](../CRYPTO.md) §8.4, [INV-14](../THREAT_MODEL.md#8-security-invariants)
- [ADR 0014](0014-ui-stack.md) §2, [ADR 0016](0016-workspace-layout.md) §3–§4, [ADR 0018](0018-item-record-encoding.md) §7 (owner decision 2), [ADR 0036](0036-browser-extension-architecture-and-key-custody.md), [ADR 0038](0038-equivalent-domain-list.md)
- Mozilla Public Suffix List, publicsuffix.org (L, not re-fetched for this ADR); the `psl` and `idna` Rust crates (U, version and audit status not independently verified for this ADR — confirm in the M2 implementation PR)
