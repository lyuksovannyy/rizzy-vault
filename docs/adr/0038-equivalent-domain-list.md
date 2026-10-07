# ADR 0038: Equivalent-domain list: format, signing and governance

- Status: Proposed
- Date: 2026-10-07
- Deciders: project owner
- Milestone: M2

## Context

[ROADMAP §4.4](../ROADMAP.md#44-url-matching--autofill-m2), Must, M2: "**Equivalent domain groups**: curated global list (e.g. `youtube.com, youtu.be, youtube-nocookie.com`; `google.com, google.co.uk, …`; `apple.com, icloud.com`), shipped with clients, versioned and signed." Must, M2: "User-defined equivalence groups + ability to disable a global group." Should, M2: "Community-contributed equivalence list via PRs with review rules (both domains provably same owner)." [ADR 0037](0037-url-matching-and-autofill-rules.md) is the companion ADR for how matching *uses* a merged equivalence view; this ADR is the list's own format, signing, distribution and governance.

**What already binds and constrains this ADR.**
- [THREAT_MODEL](../THREAT_MODEL.md) [A6](../THREAT_MODEL.md#a6-phishing-site-and-autofill-abuse), "Equivalence list governance": every entry needs proof of common ownership and review by two maintainers; the list is signed with a dedicated key, versioned, and shipped inside client releases; clients reject an unsigned list or an older version ([INV-39](../THREAT_MODEL.md#8-security-invariants)); users can disable any global group; rules against over-broad groups (no third-party-hostable domains unless the PSL already splits them; per-ccTLD-variant ownership proof; scheduled re-checks, with a lapsed-then-re-registered domain removed).
- [THREAT_MODEL](../THREAT_MODEL.md) [Q-10](../THREAT_MODEL.md#10-open-questions-for-the-owner): "Governance for the equivalence list with one maintainer... and who holds the list-signing key?" Recommendation already on record: "Use a dedicated offline list key, separate from release keys. Until there is a second maintainer, ship only groups with public proof of common ownership, and keep the global list small." [ROADMAP §6](../ROADMAP.md#6-risks--hard-truths) risk 4: "Every entry in the global equivalence list is a potential phishing vector. Entries need proof of common ownership and review by two maintainers."
- [ADR 0016](0016-workspace-layout.md) §3: `rizzy-match` ships the "signed equivalence lists" compiled in, no runtime fetch (R1, no I/O).
- [CRYPTO.md §1](../CRYPTO.md#1-goals-non-goals-and-rules) Rule 2 lists every non-standard composition this project uses and states "Nothing else may be invented. A new construction needs an ADR first, and joins this list." A **signed equivalence list** is a new signed-statement type outside that list; this ADR is the ADR that adds it, and the list gains a line "On acceptance."
- [AST-16](../THREAT_MODEL.md#2-assets) already names "equivalence-list signing key" among release credentials that need protecting at the level of a code-signing key, and A10's mitigations already say "the equivalence-list key is separate from the release keys ([Q-10](../THREAT_MODEL.md#10-open-questions-for-the-owner))."

## Decision

### 1. List format

A canonical, fixed binary layout, per [CRYPTO.md §2](../CRYPTO.md#2-conventions) ("Anything that is signed... uses the fixed binary layouts in this document, never a serde-derived encoding"), so the signed bytes cannot drift with a serde crate upgrade:

```
equivalence_list
  u16 format_version = 1
  u32 list_version                         strictly increasing across every published list
  u64 published_at_ms                      informational only; not security-relevant
  u16 n ‖ n × group                        groups, sorted by group_id, no duplicate group_id
  ed25519_signature (64 B)                 over LABEL("sig/equivalence-list") ‖ 0x00 ‖ everything above

group
  16  group_id                             random, assigned once, never reused or reassigned
  u16 m ‖ m × str(domain)                  registrable domains in the group, 2 ≤ m, each in
                                            normalized A-label form (ADR 0037 §2), sorted bytewise,
                                            no duplicates
  u8  flag_third_party_hostable            0 normally; 1 only for a domain the PSL already splits
                                            per registrant (ADR 0037 §3), recorded so review can
                                            see the exception was intentional (Context, A6 rule 1)
```

- **Why not JSON or TOML.** Same reasoning as [ADR 0018](0018-item-record-encoding.md) §1: a signed object uses the canonical layout so two client versions, or a client and the signing tool, never disagree about what was signed.
- **A human-editable source exists separately.** Maintainers author and review a plain-text or TOML source file in the repository that produces this canonical format through a build step; that source is what PR review reads and is **not** itself signed or shipped. The signing step runs over the canonical binary form only, offline, by whoever holds the list-signing key ([§3](#3-signing-key-and-process)).
- **`group_id` is random**, not derived from the domains, so renaming or correcting a domain inside a group does not change its identity, and a client's "disabled groups" setting ([ADR 0037](0037-url-matching-and-autofill-rules.md) §6) survives a domain-spelling fix.

### 2. Versioning and distribution

- **Monotonic `list_version`.** Every published list has a strictly higher `list_version` than the one before it. Clients persist the highest `list_version` they have ever accepted (alongside the other monotonic state [INV-25](../THREAT_MODEL.md#8-security-invariants) already tracks) and reject a list with an equal or lower version ([INV-39](../THREAT_MODEL.md#8-security-invariants)).
- **Shipped inside client releases**, compiled into `rizzy-match` exactly like the PSL snapshot ([ADR 0037](0037-url-matching-and-autofill-rules.md) §3): no runtime fetch, no server-supplied list. A server that tried to serve its own equivalence list would be rejected outright by R1's no-I/O rule even existing in `rizzy-match`; the list only ever arrives as build-time data reviewed in this repository's own release process.
- **No out-of-band update channel for M2.** Updating the list means a new client release. An in-app "equivalence list update without a full release" channel (comparable to a browser's safe-browsing list push) is a plausible post-M2 idea but is explicitly deferred (see Alternatives) to avoid adding a second signed-update mechanism alongside the release process in the same milestone.

### 3. Signing key and process

- **A dedicated, offline Ed25519 keypair**, generated and held separately from every release-signing credential in [AST-16](../THREAT_MODEL.md#2-assets) (code-signing certificates, store accounts, tag-signing keys). This directly answers [Q-10](../THREAT_MODEL.md#10-open-questions-for-the-owner) as recommended there.
- **Public key pinned in `rizzy-match`'s source**, compiled into every client, the same way a certificate pin would be. There is no key-rotation mechanism in M2; rotating the list-signing key is a new client release that ships a new pinned public key and a `format_version` bump if the verification path changes, reviewed with the same care as a crypto-dependency change even though the primitive itself (Ed25519 verify, `verify_strict`, [ADR 0009](0009-crypto-dependency-policy.md)) is already in `rizzy-core`.
- **Who signs.** Today, with one maintainer (the owner), the owner holds the key and signs each published list offline, after the review rounds in [§4](#4-review-rules). [ADR 0020](0020-partial-supersession.md)'s general two-maintainer-approval rule for crypto/auth/format ADRs (carried from ADR 0001 owner decision 1) does not yet bind here either, for the same single-maintainer reason; this ADR records that the **two-maintainer review rule for individual list entries** ([§4](#4-review-rules)) applies regardless and becomes real review, not a formality, the moment a second maintainer exists.
- **Compromise response.** If the list-signing key is suspected compromised, the response is the same shape as [AST-16](../THREAT_MODEL.md#2-assets)'s general one: generate a new keypair, ship it in the next release with a bumped `format_version` if needed, and treat every list "signed" after the suspected compromise date as untrusted until re-signed.

### 4. Review rules for list entries

Reused, formalised, from [THREAT_MODEL](../THREAT_MODEL.md) A6 "Equivalence list governance":
1. **Proof of common ownership**, for every entry, before it is merged into the human-editable source. Acceptable proof: shared WHOIS registrant or organisation, a cross-referencing statement published on both domains (for example a security.txt or a support article naming the other domain), or equivalent public evidence. "Looks like a harmless addition next to a big brand" is explicitly **not** proof; the reviewer's job is to find the ownership link, not to judge plausibility (THREAT_MODEL A6, restated).
2. **Two-maintainer review** once a second maintainer exists. Until then, the owner's own review is recorded in the PR with the ownership evidence cited, so the record exists for a later second reviewer to audit retroactively.
3. **No domains that third parties can host content on**, unless the PSL already splits that suffix into separate registrable domains per registrant (`flag_third_party_hostable = 1` is the explicit, reviewed exception, never silently assumed).
4. **ccTLD variants proven per variant.** `brand.com` and `brand.co.uk` need ownership proof for each pairing, not an assumption that one brand owns every ccTLD variant of its name.
5. **Scheduled re-checks.** Every group is re-verified on a recurring schedule (recommended: every release cycle at minimum, more often if the list grows); a domain that has lapsed is removed, because a re-registered lapsed domain is an attacker's domain, not the original owner's.
6. **Small list, high bar.** With one maintainer, the list stays deliberately short: well-known multi-domain brands with clear public ownership evidence (the ROADMAP examples: `youtube.com`/`youtu.be`/`youtube-nocookie.com`; `google.*` variants; `apple.com`/`icloud.com`), not a crowd-sourced long tail.

### 5. User-defined groups and disabling a global group

- **Format reused.** A user-defined group has the same shape as a global `group` record ([§1](#1-list-format)), minus the signature (it is the user's own account data, not a shipped artifact). It lives in `ACCOUNT_SETTINGS` ([ADR 0037](0037-url-matching-and-autofill-rules.md) §6), encrypted under the account key, authenticated by the signed `account-state`'s freshness commitment exactly as every other security-relevant setting is ([INV-14](../THREAT_MODEL.md#8-security-invariants)).
- **Disabling a global group.** `ACCOUNT_SETTINGS` carries a set of disabled `group_id`s. `rizzy-match`'s merged view ([ADR 0037](0037-url-matching-and-autofill-rules.md) §7) is: every global group not in that set, plus every user-defined group, with no further widening between them (a user group cannot re-enable a disabled global group by duplicating its domains under a new `group_id` — that is allowed, because it is the user's own explicit choice, which is exactly what "user-defined" means, but it is visible to the user as their own data, not silently inherited).
- **No community review for user-defined groups.** They are the account owner's own risk; [§4](#4-review-rules) applies only to the shipped global list.

## Consequences

### Positive

- One canonical, signed artifact per release, reviewed like any other security-relevant shipped data; no server in the loop at all for this list.
- `group_id` stability means a user's disabled-groups setting survives routine corrections to the list's domain spelling or added domains in an existing group.
- The two-maintainer rule is written down now, before a second maintainer exists, instead of being invented under pressure later.

### Negative

- No way to patch a demonstrably bad entry (a lapsed, re-registered domain someone exploited) faster than a full client release, until a future out-of-band channel exists (deferred, see Alternatives).
- A single offline signing key is a single point of failure; losing it means every future list needs a new pinned public key shipped in a release, the same cost as any key-pin rotation.
- The canonical binary format needs its own small encoder/decoder in `rizzy-match`, on top of the human-editable source's build step — more code than "ship a JSON file," in exchange for the format guarantee [§1](#1-list-format) explains.

### Risks

- **A malicious or careless second-maintainer review approves a bad entry.** Mitigation: the ownership-proof requirement and the scheduled re-check catch a stale entry even if the initial review missed it; ROADMAP risk 4 already names this as the standing risk class, not something this ADR removes.
- **The pinned public key itself could need rotation** if the signing workstation is compromised, with no fallback key pre-provisioned. Signal: any suspicion of key exposure. Mitigation: treat it exactly like any other release-credential incident ([AST-16](../THREAT_MODEL.md#2-assets)).
- **List growth outpaces one-maintainer review capacity** if community PRs ([ROADMAP §4.4](../ROADMAP.md#44-url-matching--autofill-m2), Should) arrive faster than they can be verified. Mitigation: §4 point 6, keep the bar high and the list short until there is real reviewer capacity.

## Alternatives considered

- **An out-of-band, faster-than-release update channel** (a small signed-blob fetch endpoint, similar to a browser safe-browsing list). Deferred, not rejected: it is a reasonable post-M2 improvement, but it is a second signed-artifact-distribution mechanism to design, build and audit, and the Should-level "community PR" item does not need it to ship in M2. Revisit if a real incident shows the release cadence is too slow to react to a lapsed-domain exploit.
- **JSON or TOML as the signed wire format**, with the human-editable source and the shipped artifact being the same file. Rejected for the reason [§1](#1-list-format) gives: a signed object must use a canonical layout CRYPTO.md §2 already mandates for every other signed artifact in this project.
- **Per-entry signatures instead of one signature over the whole list.** Rejected: it would let a client accept a subset of entries independently, which reintroduces exactly the kind of partial-trust complexity a single list-level signature avoids, for no governance benefit (entries are reviewed and published together anyway).
- **No dedicated list key; sign with the same key used for release artifacts.** Rejected per [Q-10](../THREAT_MODEL.md#10-open-questions-for-the-owner)'s own recommendation: a compromised list key should not also mean a compromised release channel, and vice versa.

## Open questions for the owner

1. **Re-check schedule cadence.** *Recommendation:* re-verify every group at least once per release cycle; more often is better but not mandated by this ADR.
2. **Where the offline signing key is held** (hardware token, air-gapped machine, etc.) is an operational decision, not a cryptographic one. *Recommendation:* at minimum the same tier of protection as the tag-signing key in [AST-16](../THREAT_MODEL.md#2-assets).
3. **Community PR process mechanics** (a GitHub issue template demanding ownership evidence, a labeled review queue) are implementation detail for the M2 PR, not an ADR decision. *Recommendation:* defer to the M2 implementation, following §4's rules.

## On acceptance

This ADR makes none of these edits. The owner makes them in the change that accepts it, following the pattern of ADRs 0018, 0019 and 0022:
- **[CRYPTO.md §1](../CRYPTO.md#1-goals-non-goals-and-rules) Rule 2** gains a new composition line: "the signed equivalence list ([ADR 0038](0038-equivalent-domain-list.md)): a detached Ed25519 signature over the canonical list bytes under `LABEL("sig/equivalence-list")`."
- **[CRYPTO.md §4.3](../CRYPTO.md#43-derivations)** gains the signature-message label `sig/equivalence-list` in the label registry, next to the other `sig/<type>` entries.
- No Accepted ADR is superseded, in whole or in part: this is new ground ([ADR 0016](0016-workspace-layout.md) §3 already named "signed equivalence lists" as `rizzy-match`'s job without specifying the format, so this ADR fills a gap rather than changing a decision).

## References

- [ROADMAP](../ROADMAP.md) §4.4, §6 (risk 4)
- [THREAT_MODEL.md](../THREAT_MODEL.md) [A6](../THREAT_MODEL.md#a6-phishing-site-and-autofill-abuse), [AST-16](../THREAT_MODEL.md#2-assets), [A10](../THREAT_MODEL.md#a10-compromised-ci-or-release-credentials), [INV-39](../THREAT_MODEL.md#8-security-invariants), [Q-10](../THREAT_MODEL.md#10-open-questions-for-the-owner)
- [CRYPTO.md](../CRYPTO.md) §1 (Rule 2), §2, §4.3, §10.2
- [ADR 0009](0009-crypto-dependency-policy.md) (Ed25519 pin, already covers the signature primitive used here), [ADR 0016](0016-workspace-layout.md) §3, [ADR 0018](0018-item-record-encoding.md) §1 (canonical-encoding precedent), [ADR 0020](0020-partial-supersession.md), [ADR 0037](0037-url-matching-and-autofill-rules.md)
