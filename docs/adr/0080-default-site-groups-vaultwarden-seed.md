# ADR 0080: Default site groups: seeding the signed global equivalence list from Vaultwarden's `global_domains.json`

- Status: Proposed
- Date: 2026-10-23
- Deciders: project owner
- Milestone: M2

## Context

**The owner's instruction (2026-10-23, verbatim):** "create as well manager's default site groups that are available by default and grab one from vaultwarden".

"Site groups" are this project's equivalence groups. "Default site groups that are available by default" are the groups of the **signed global equivalence list** ([ADR 0038](0038-equivalent-domain-list.md)). The client compiles that list in, and it is active for every account unless the account turns a group off ([ADR 0038](0038-equivalent-domain-list.md) §5, [ADR 0042](0042-account-settings-matching-layout.md) §3). The ROADMAP rows this serves are [§4.4](../ROADMAP.md#44-url-matching--autofill-m2):
- Must, M2: "**Equivalent domain groups**: curated global list (...), shipped with clients, versioned and signed".
- Must, M2: "User-defined equivalence groups + ability to disable a global group".
- Should, M2: "Community-contributed equivalence list via PRs with review rules (both domains provably same owner)".

[ROADMAP §6](../ROADMAP.md#6-risks--hard-truths) risk 4: "Every entry in the global equivalence list is a potential phishing vector."

**What binds this ADR.**
- **[ADR 0038](0038-equivalent-domain-list.md) (Accepted, §1 in part superseded by ADR 0044):**
  - The canonical signed wire format, with `group_id` random, assigned once and never reused.
  - A human-editable source in the repository, compiled and signed by a build step (§1).
  - A strictly increasing `list_version`. Clients "reject a list with an equal or lower version" (§2).
  - A dedicated offline Ed25519 list-signing key held by the owner, with its public key pinned in `rizzy-match` (§3).
  - Review rules 1–6 (§4): proof of common ownership, two-maintainer review once a second maintainer exists, no third-party-hostable domains unless the PSL splits them, ccTLD variants proven per variant, re-checks at least every release cycle with lapsed domains removed, and "small list, high bar".
  - User groups and disabling a global group (§5).
- **[ADR 0044](0044-equivalence-group-member-rules.md) (Accepted):** every member equals its own registrable domain under the compiled-in PSL. It is never an IP literal, 2 ≤ m, and it is in A-label form, sorted, with no duplicates. A PSL bump that turns a shipped member into a suffix rejects the whole list.
- **[ADR 0051](0051-equivalence-list-version-persistence.md) (Accepted):** each device persists `highest_equivalence_list_version` in `cache_meta` and raises it only when a verified list is strictly newer. The web vault keeps no cache and always passes `0`.
- **[ADR 0042](0042-account-settings-matching-layout.md) (Accepted):**
  - `ACCOUNT_SETTINGS` tag `0x0001` carries the disabled global ids (≤ 1,024) and the user groups (≤ 64, each 2–64 domains).
  - An absent tag means "no disabled groups", so every global group is on by default.
- **[THREAT_MODEL](../THREAT_MODEL.md):**
  - [A6](../THREAT_MODEL.md#a6-phishing-site-and-autofill-abuse) "Equivalence list governance": "Every entry needs proof of common ownership and review by two maintainers".
  - [Q-10](../THREAT_MODEL.md#10-open-questions-for-the-owner): one maintainer, so "ship only groups with public proof of common ownership, and keep the global list small".
  - [AST-16](../THREAT_MODEL.md#2-assets): the list-signing key is a release credential.
  - [INV-39](../THREAT_MODEL.md#8-security-invariants): a signed list whose version is "strictly higher than the last one accepted".
  - [INV-75](../THREAT_MODEL.md#8-security-invariants): the persisted floor never decreases.

**What exists today (V, code read at `35d7079`).**
- `crates/rizzy-match/src/compiled.rs`: `GLOBAL_LIST = None`, `LIST_SIGNING_PUBLIC_KEY = None`. No signed list ships yet.
- The source file is [`data/equivalence/groups.txt`](../../data/equivalence/groups.txt):
  - Its format is hand-written: `group_id (32 hex) | third_party_hostable (0|1) | domain,domain,...`, with `#` comments.
  - It holds three unreviewed starter groups: youtube.com/youtu.be/youtube-nocookie.com, google.com/google.co.uk/google.de and apple.com/icloud.com.
- `cargo xtask equivalence-list <source> <seed-file> <list-version> <published-at-ms>` (`crates/xtask/src/equivalence_list.rs`) does three things:
  - It parses the source through `EquivalenceGroup::new`, which applies the ADR 0044 rules.
  - It builds the list with `EquivalenceList::new`, which sorts by id.
  - It signs with the raw 32-byte seed and writes the wire bytes to stdout ([docs/equivalence-list.md](../equivalence-list.md)).
- The web vault's matching pane already lists global groups with a per-group "Turn off" or "Turn on" button (`apps/web/src/views/MatchingPane.tsx`, `GlobalGroupRow`). It shows "This build ships no signed global list yet" while the list is empty.

**Upstream facts (V, read 2026-10-23).**
- **Vaultwarden's file.** <https://raw.githubusercontent.com/dani-garcia/vaultwarden/main/src/static/global_domains.json>:
  - Read at Vaultwarden `main` = `b71cb7a832080d9fdfdd97bcccf065307cf73236`. The file last changed in `dde63e209e00e4e1a02d8e43175976386a31c53b` (2026-03-29, "Misc Updates (#7027)").
  - SHA-256 `3f2c8a39c8c1a8dd9a8c9f4c6b14201afd7113d4fea2b22a27e1847e95e7933a`, 15,910 bytes.
  - It is a JSON array of 91 objects `{type, domains, excluded}`, with 436 domain entries (435 distinct: `sonyentertainmentnetwork.com` is in both type 42 and type 84). `excluded` is `false` everywhere.
  - Vaultwarden generates the file with `tools/global_domains.py` from Bitwarden server's `src/Core/Utilities/StaticStore.cs` and `src/Core/Enums/GlobalEquivalentDomainsType.cs`. `type` is that enum's value. In Vaultwarden, `excluded` is per-user state, the counterpart of our ADR 0042 disabled set.
- **The origin.** The file's content is group-for-group identical to bitwarden/server at `41ae9acb7b92fc8eef0b73c6cfa6eb2106a326f2` (2026-03-02).
- **Upstream has since cut the list.** bitwarden/server [PR #8404](https://github.com/bitwarden/server/pull/8404) (`e1f32b96a33f0f5d63170690f0b83cce0b901d36`, merged 2026-09-29) says: "69 entries cut from StaticStore.GlobalDomains, 22 live". The enum members stay, marked `// deprecated`.
  - The 22 remaining groups (186 domains) are identical, member for member, to the same `type` in Vaultwarden's file: Google 0, Apple 1, Merrill 6, Microsoft 10, PayPal 14, Amazon 18, Comcast 36, Alibaba 41, Autodesk 45, Facebook 51, Disney 54, Turbotax 62, Ebay 64, MorganStanley 69, Airbnb 72, StackExchange 74, Docusign 75, Ubiquiti 80, Yandex 83, Proton 85, Atlassian 89 and Twitter 91.
  - Vaultwarden `main` has not synced this change yet.
- **Licences.**
  - Vaultwarden is AGPL-3.0-only (`Cargo.toml` `license = "AGPL-3.0-only"`; `LICENSE.txt` is the AGPL v3 text).
  - Bitwarden server's `LICENSE.txt` says: "The default license throughout the repository is AGPL v3.0 unless the header specifies another license. Bitwarden Licensed code is found only in the /bitwarden_license directory". Both source files are under `src/Core/` and carry no licence header, so they are AGPL-3.0.
  - The same file grants no rights in Bitwarden's trademarks.
  - rizzy-vault is AGPL-3.0-only ([ADR 0017](0017-licensing.md)), so the licences are compatible.
  - Whether a list of domain names is copyrightable at all is not settled here (U, not legal advice). This ADR treats the data as AGPL-licensed and attributes it.

**Mechanical checks of the upstream file against ADR 0044 (V, run 2026-10-23 with throwaway scripts that are not committed).**
- **Method.**
  - (a) A Python eTLD+1 implementation over the pinned PSL snapshot (`psl` 2.1.240 `data/rules.txt`), plus IP-literal, A-label, case, size and duplicate checks.
  - (b) A cross-check with the real code. Each group became a one-line `groups.txt` with a random id, and was fed to `cargo xtask equivalence-list` built from this worktree.
  - Both agree.
- **88 of 91 groups pass and 3 fail.** Each failure comes from exactly one member:

  | Upstream group (`type`) | Failing member | Why (ADR 0044) |
  |---|---|---|
  | Amazon (18) | `amazon.com.be` | Not its own registrable domain. The PSL lists `be` but not `com.be`, so the registrable domain is `com.be`. Who holds `com.be` is not established here (U). |
  | Alibaba (41) | `net.cn` | A bare public suffix (ICANN section). Anyone can register `<x>.net.cn`. |
  | Shopify (63) | `myshopify.com` | A bare public suffix (PSL private section, one name per shop). Without it the group has one member, so the whole group fails. |

- **No other failures.** There are no IP literals, no non-ASCII members, no case or whitespace problems, and no duplicate within a group. Every group has 2–53 members, within `MAX_GROUP_DOMAINS` = 64. The whole 91-group file fails at its first bad line, Amazon.
- **The tool's error is unhelpful.** `cargo xtask equivalence-list` only reports "line N: equivalence list is malformed". It names neither the member nor the rule.

**The A6 rule-3 screen (third-party-hostable domains the PSL does not split; V for "not in PSL 2.1.240", U for each service's current hosting model):**
- **Atlassian (89):**
  - `atlassian.net` serves customer tenant sites at `<tenant>.atlassian.net`.
  - `statuspage.io` serves customer status pages.
  - `jira.com` is a legacy tenant host that now redirects to `atlassian.com`.
- **Zendesk (44):** `zendesk.com` serves customer help centres with customer-editable themes.
- **X10Hosting (77):** `x10hosting.com` is a free web host.
- None of these is in PSL 2.1.240.

**The lapse and hijack screen (A6 rule 5) (V for the DNS and RDAP observations of 2026-10-23, U for every claim about a company's history).**
- **Method.**
  - `dig` NS and A for all 435 domains.
  - RDAP creation date and registrar for about 120 suspect domains.
  - For a gTLD, a lapse followed by re-registration resets the creation date. None of the gTLD domains checked has a creation date later than its brand's own era, so there is **no evidence of a lapse and re-registration**.
  - The risk actually observed is different: defunct brands whose domains may have been sold or parked, and groups whose members no longer share one owner.
- **Signals:**
  - **Uv (56):**
    - `myuv.com` sits on parking nameservers (`ns1/ns2.parklogic.com`), answers no HTTP, and is held at a retail registrar.
    - `uvvu.com` is at a retail registrar.
    - The UltraViolet service is defunct (U).
  - **Chart (27):** `chart.io` is registered (MarkMonitor, expires 2028) but has no NS delegation. Chartio is defunct (U).
  - **Yandex (83, one of upstream's 22):** `yandex.ua` has no NS delegation (the .ua servers answer NOERROR with no data). Its RDAP record was not obtained.
  - **Cnet (8):**
    - `com.com` and `search.com` are at a retail registrar, while the other CNET domains are at CSC.
    - The members are generic premium names, and the brand has been sold more than once (U).
  - **Diapers (16):** 11 generic dictionary names (`wag.com`, `look.com`, `vine.com`, `casa.com`, …) of a business that was shut down (U). They are still at MarkMonitor, but their current use is unknown.
  - **Members that may no longer share an owner (U):**
    - Skysports (53): `skybet.com` and `skyvegas.com`, since Sky Betting & Gaming left Sky.
    - Xiami (60): `xiami.com` (Alibaba, service closed) next to `alipay.com` (Ant Group).
    - Yahavo (57): Bank Yahav next to Bank Hapoalim.
    - Disney (54, one of upstream's 22): `disneymoviesanywhere.com` redirects to `moviesanywhere.com`, a multi-studio service (V for the redirect, U for who owns it).
    - CedarFair (79): 13 park domains of a merged company.
  - **Defunct or merged brands with no current hijack signal but no current ownership proof either.** These include `piperlime.com`, `overture.com`, `sprintpcs.com`, `nextel.com`, `shld.net` (no A record), `seedonk.com` (at a retail registrar, no A record), `tiberiumalliance.com` (no A record), `play4free.com` and `usecfo.com` (no HTTP answer).
  - Every group above except Yandex and Disney is among the 69 groups upstream has already cut.

**The equal-version defect (V, code and tests at `35d7079`).** It surfaces as soon as any list ships:
- ADR 0038 §2 rejects "a list with an equal or lower version", and `EquivalenceList::verify` returns `NotNewer` when `list_version <= highest_accepted_version` (`crates/rizzy-match/src/equivalence.rs` line 436).
- ADR 0051 persists that floor, and `rizzy-wasm`'s `DeviceSession::from_parts` (`crates/rizzy-wasm/src/device.rs` line 547) calls `startup_equivalence_groups` at every unlock.
- The result:
  1. The first unlock after install accepts list *v* and persists floor *v*.
  2. Every later unlock re-verifies the **same** compiled-in list *v*, gets `NotNewer`, and runs with **no global groups** until a release with list *v*+1 arrives.
- `crates/rizzy-client/src/matching.rs`, test `a_newer_list_raises_the_floor_and_the_same_list_never_does_again`, asserts exactly this: `groups_and_new_floor(known_answer_list(1), 1) == (Vec::new(), None)`.
- Today this is masked only by `GLOBAL_LIST = None`.
- It defeats "available by default" on every host with a cache. The web vault, which always passes floor 0, is unaffected.
- The downgrade INV-39 guards against is an *older* list. A compiled-in list re-verified at startup always arrives at the version it was accepted at.

## Decision

### 1. "Default site groups" are the signed global list, on by default and individually switchable

- **No new mechanism.** The default site groups are the groups of the ADR 0038 global list. They are compiled into `rizzy-match` and become active for every account with no user action: ADR 0042 §3's absent tag means an empty disabled set, and ADR 0038 §5's merged view is "every global group not in that set, plus every user-defined group".
- **Each group can be turned off and back on per account.** This is the existing ADR 0042 disabled set (≤ `MAX_DISABLED_GROUPS` = 1,024, comfortably above the seed's 22 groups) and the existing web UI.
- Matching through any group stays flagged `Equivalence` and warned, as ROADMAP §4.4 requires ("Visual warning when filling on a domain matched only via equivalence group") and ADR 0037 already specifies.
- **No pre-seeding of user-defined groups.** See Alternatives: user groups are the account owner's own unreviewed data, are never updated by a release, and cannot be cleaned up when a domain lapses.

### 2. Source of the seed and the subset taken

- **The source is Vaultwarden's `global_domains.json`**, as the owner instructed, pinned to Vaultwarden `b71cb7a832080d9fdfdd97bcccf065307cf73236` (SHA-256 `3f2c8a39…7933a`). Its recorded origin is bitwarden/server `41ae9acb…`.
- **The subset is the 22 groups upstream still maintains** (bitwarden/server `e1f32b96…`, PR #8404). This is the recommendation of [Open question 1](#open-questions-for-the-owner).
  - The 69 cut groups are not imported.
  - Any of them can still be proposed later through the normal ADR 0038 §4 process (the `equivalence-group` issue template).
  - The 22 are the "well-known multi-domain brands" of ADR 0038 §4 point 6, so this seed stays within "small list, high bar" without superseding it.
- **These members are removed before import:**
  - `amazon.com.be` and `net.cn`: ADR 0044.
  - `atlassian.net`, `statuspage.io` and `jira.com`: ADR 0038 §4 point 3 (third-party-hostable, not PSL-split). `flag_third_party_hostable = 1` is not available to them, because the PSL does not split these names.
  - `yandex.ua`: not delegated, and no ownership evidence is available.
- **Members that must find their evidence in the import PR or be dropped:**
  - `disneymoviesanywhere.com` (it redirects to a multi-studio service).
  - Every ccTLD variant: Amazon 18, eBay 23, Airbnb 53 and Yandex 21 after the removals.
  - See §3.
- **Merging with the starter groups.**
  - Upstream's Apple group equals the starter Apple group, which keeps its existing id `1e683ea6…`.
  - Upstream's Google group (`youtube.com, google.com, gmail.com`) and the two starter groups would put `youtube.com` and `google.com` into two global groups each. They merge into **one** Google group under the starter Google id `ad39c37c…`: `google.com, gmail.com, youtube.com, youtu.be, youtube-nocookie.com, google.co.uk, google.de`, the ccTLDs subject to per-variant proof.
  - The starter YouTube id `8ce962df…` is retired and never used again. It never shipped, so no client has seen it.
- **No domain may appear in more than one global group.** This is a new source-level review rule, enforced by `cargo xtask equivalence-list`. Overlap makes "turn this group off" misleading, because the other group still matches.
  - The rule is a check in the build tool, **not** a wire or decode rule, so ADR 0038 §1 is not touched.
  - It also catches upstream's `sonyentertainmentnetwork.com` duplicate if those groups are ever proposed.
- **Result if every remaining member finds its evidence:** 22 groups and 184 domains. A trial build with the real `cargo xtask equivalence-list` and a throwaway key (V, 2026-10-23) parses, builds and signs it into 3,226 wire bytes, against `MAX_LIST_LEN` = 1 MiB.
- **Imported fields.** Upstream `type` values are **not** used as `group_id`s. ADR 0038 §1 requires 16 random bytes, so each new group gets a fresh CSPRNG id, and the upstream `type` and enum name are recorded in a comment on that group's line for later diffing. `excluded` is not imported.

### 3. Governance for the seed batch, and the rule from then on

- **No waiver of ADR 0038 §4 for the seed.** This is the recommendation of Open question 2. The seed is one PR that follows §4 exactly as a single-maintainer change already may (§4 point 2: the owner's own review, evidence cited, auditable later). For each group it records:
  1. **Provenance:** the upstream type and name, and the fact that upstream still kept the group in its 2026-09 keep/cut review. This is context, **not** proof.
  2. **Ownership evidence per member (rule 1)**, of a kind §4 point 1 already accepts: "a cross-referencing statement published on both domains ... or equivalent public evidence". Usable evidence includes:
     - a support or legal page on the main domain naming the other domain;
     - the brand's own country-site directory linking each ccTLD (one page can cover many variants for rule 4, provided every variant is linked from it and serves the same sign-in);
     - for gTLDs, an RDAP registrar and creation date consistent with the brand's own corporate registrar.

     Registrant names are mostly redacted today, so RDAP alone is supporting evidence, not proof.
  3. **The rule-3 and rule-5 screens:** the DNS and RDAP observation and its date.
  4. **The next re-check:** the next release cycle, per ADR 0038's owner answer.

  A member with no evidence is dropped, not waived.
- **The evidence lives in the repository.** It goes in `data/equivalence/EVIDENCE.md`, one section per group, rather than only in a PR description. A later second maintainer can then audit the seed retroactively (§4 point 2) without depending on a forge.
- **The two-maintainer rule.** Nothing changes. ADR 0038 §3 and §4 point 2 already cover the single-maintainer period, and THREAT_MODEL A6's two-reviewer rule becomes real review "the moment a second maintainer exists". This ADR adds one step: **when a second maintainer joins, the seed batch is the first thing they review**, retroactively, group by group.
- **Upstream is never synced in bulk after the seed.** At each scheduled re-check (§4 point 5), the maintainer diffs the shipped list against bitwarden/server's current `StaticStore.cs`:
  - An upstream **removal** of a group or member we ship triggers re-verification of that entry before the next release. A removal is a signal of a lapse, a sale or a divestiture.
  - An upstream **addition** is only a candidate for a normal §4 proposal.
  - Vaultwarden's file is a lagging mirror of the same data and is not consulted separately.

### 4. Source file, provenance and attribution placement

- **The source stays `data/equivalence/groups.txt`**, in its existing hand-written line format (the one the xtask parses). It gets:
  - a header block naming the upstream (URLs, both commits and the file's SHA-256);
  - one comment line per imported group (`# upstream: Bitwarden GlobalEquivalentDomainsType.<Name> = <type>; evidence: EVIDENCE.md#<anchor>`).

  No TOML and no new dependency (ADR 0038 §1's fallback stands).
- **The licence notice goes in `THIRD_PARTY_NOTICES.md`**, in a new section shaped like the EFF wordlist section. It gives:
  - the material (`data/equivalence/groups.txt`, the groups derived from upstream, compiled into `rizzy-match` and therefore into every client);
  - the authors (the Bitwarden server contributors, via Vaultwarden);
  - the sources and commits;
  - the licence (AGPL-3.0, compatible with ADR 0017's AGPL-3.0-only);
  - the changes (the subset, the removed members, the merged Google group, fresh ids);
  - the trademark note: no Bitwarden marks are used beyond attribution.
- **The signed `list.bin` gets no separate notice.** It is a build product of `groups.txt`.

### 5. Signing and the first version

- **The owner signs offline with the dedicated ADR 0038 §3 key.** This is the recommendation of Open question 3, and the existing [docs/equivalence-list.md](../equivalence-list.md) §1–§4 procedure: CI never signs, and the seed never enters the repository. The first signed list has **`list_version` = 1**. `published_at_ms` is the signing time and is informational.
- **What clients do.**
  - Every client starts with floor 0. That is ADR 0051's value for a fresh cache, a cache created before this list, and the web vault.
  - Every client therefore accepts version 1 on first start.
  - A cache-backed client then persists floor 1 (ADR 0051 §3) and, with §6 below, keeps accepting the same compiled-in list on every later start.
  - Every later published list takes a strictly higher version.
  - A list that fails to verify or decode leaves the client with user groups only. That is ADR 0044's rule, unchanged.
- **The alternative, an interim development key, is weaker and is recorded only as an alternative.** Its consequences:
  - It would protect nothing against A10 (a compromised repository or CI): whoever holds the key can sign any list.
  - Replacing it later means a client release with a new pinned key.
  - The owner's first list must still take a version above every dev-key list, because floors are per device and do not care which key signed.

### 6. Accept a list whose version equals the persisted floor

`EquivalenceList::verify` accepts `list_version >= highest_accepted_version` and rejects only a **lower** version.
- The floor write is unchanged: `groups_and_new_floor` still raises the floor only on `list_version > highest_accepted_version`, so an equal version writes nothing (ADR 0051 §3, §4).
- The downgrade protection of INV-39 and INV-75 is intact: an older build's older list is still refused.
- An equal version can only be the same list, re-verified from the same build. A *different* list carrying the same version would need the owner's offline key to sign two lists with one version, and the procedure forbids that ([docs/equivalence-list.md](../equivalence-list.md) §3: "strictly greater than every previously published version"). The xtask cannot check it, because it keeps no history.
- **`list_version` 0 is reserved and never published.** The floor value 0 means "nothing accepted yet" (ADR 0051), so with `>=` a version-0 list would always pass. `cargo xtask equivalence-list` refuses version 0, and `verify` rejects it as `NotNewer` regardless of the floor.
- **This must land before the first signed list ships.** Otherwise the seed is active for exactly one session per device.

### 7. What this ADR supersedes ([ADR 0020](0020-partial-supersession.md) point 9)

| Part, quoted | Replaced by |
|---|---|
| [ADR 0038](0038-equivalent-domain-list.md) §2, first bullet, the words "and reject a list with an equal or lower version ([INV-39](../THREAT_MODEL.md#8-security-invariants))" | "and reject a list with a lower version; a list whose version equals the persisted value is the same list re-verified (for example the compiled-in list at the next start) and is accepted without raising the persisted value ([ADR 0080](0080-default-site-groups-vaultwarden-seed.md) §6)" |

Nothing else in ADR 0038, ADR 0044, ADR 0051 or ADR 0042 is superseded, and each stays binding.
- ADR 0051 already says a floor is raised only by a strictly newer list, and that `NotNewer` comes from "a build whose compiled-in `GLOBAL_LIST` is older than the stored floor". Both remain true.
- **Conditional supersession, only if the owner chooses the alternatives:**
  - If Open question 2 is answered "waive for the seed", this ADR also supersedes, for the seed batch only, ADR 0038 §4 point 1 ("Proof of common ownership, for every entry, before it is merged into the human-editable source") and point 4 ("ccTLD variants proven per variant"). The replacement: "for the seed batch of ADR 0080 only, upstream provenance plus the ADR 0080 §3 screens stand in for per-entry ownership proof; every later change follows point 1 and point 4 unchanged".
  - If Open question 1 is answered "whole list", it also supersedes ADR 0038 §4 point 6 ("Small list, high bar...") for that batch.
  - The drafter does not recommend either.

### 8. Tests and enforcement required

- **`rizzy-match`:**
  - `verify` with floor = version gives `Ok`, with floor = version + 1 gives `NotNewer`, and with floor = version − 1 gives `Ok`. These reuse the existing known-answer list wire.
  - A property test over `(list_version, floor)` checks that the list is accepted ⇔ `list_version >= floor && list_version >= 1`.
  - A version-0 list is rejected at floor 0.
  - Once the list ships: the compiled `GLOBAL_LIST` verifies under `LIST_SIGNING_PUBLIC_KEY` at floor 0 and at its own version, decodes to the expected group count, and every member passes ADR 0044.
- **`rizzy-client`:**
  - The test above is renamed and flipped: a restart with floor = version keeps the groups and writes nothing.
  - An older list at a higher floor is still refused (INV-75).
- **xtask:**
  - A test parses the committed `data/equivalence/groups.txt`, so a PSL bump that breaks a member fails `cargo test` in the PR (ADR 0044 "A PSL bump that turns a signed member into a suffix": "Mitigation is process, not code").
  - New checks for no domain in two groups, and an error message that names the member and the rule.
- **Fuzz:** the existing `equivalence_list` target gets the signed seed as a corpus entry. No new target is needed: no new parser is added.
- **Web and extension e2e:**
  - The matching pane shows the seeded groups on by default.
  - Turning one off persists across a reload and stops an equivalence-only offer.
  - The equivalence warning is shown for a seeded group.
  - The axe audit and the keyboard-only walk cover the longer global-group list.

## Consequences

### Positive

- The owner's request is met with the machinery already Accepted and implemented: the format, the signing tool, ADR 0042's switches and ADR 0051's floor. There is no new wire format, persistent format or construction.
- The seed starts from data a large password-manager vendor reviewed and cut in 2026-09, rather than its stale pre-cut copy. Six risky members and all 69 stale groups stay out.
- The equal-version defect is found and fixed before it could ship, and it would have silently disabled the feature after the first unlock.
- Provenance and evidence are committed in the repository, so A6's audit trail survives the single-maintainer period.

### Negative

- The owner must gather evidence for about 184 members before signing. The ccTLD-heavy groups (Airbnb 53, eBay 23, Amazon 18, Yandex 21) are most of that work.
- The list is larger than the three ROADMAP examples. The phishing surface (ROADMAP §6 risk 4) grows with each member, and each needs a re-check every release cycle.
- The web pane's `groupLabel` joins every domain. A 53-domain group needs a summarised label, for example "airbnb.com and 52 more", and a disclosure. This is UI work, with an a11y check.
- This ADR rewords ADR 0038 §2 and, on acceptance, the text of INV-39 and INV-75.

### Risks

- **A member lapses or is sold between re-checks.** Its new owner then receives autofill for every member of the group: this is THREAT_MODEL A6. The mitigations:
  - the per-release re-check, with the upstream diff of §3 as an extra early signal;
  - the per-account switch;
  - the equivalence-only warning.

  A signal that the cadence is too slow: any member found parked, re-registered (a creation date newer than the previous check) or redirecting to an unrelated owner.
- **A PSL bump turns a shipped member into a suffix.** Per ADR 0044 the whole list is then rejected. The xtask test of §8 catches this in the PSL-bump PR.
- **Licence reading.** If the data were found to carry obligations beyond AGPL attribution, the notice placement would need revisiting (U).

## Alternatives considered

- **Import all 91 groups as Vaultwarden ships them.** This is the literal reading of "grab one from vaultwarden". Rejected:
  - 3 groups fail ADR 0044 as they stand.
  - At least 5 members are third-party-hostable.
  - Several groups show parking, missing delegation or divergent ownership.
  - Upstream itself cut 69 of the 91 in 2026-09.
  - It contradicts ADR 0038 §4 point 6 and THREAT_MODEL Q-10's "keep the global list small". It would need a named supersession of that point.
- **A narrower subset: only the three ROADMAP groups plus Apple and Google from upstream.** It is the safest option, but it ignores the owner's instruction to take the upstream list. It stays available if the evidence work proves too heavy (Open question 1).
- **Pre-seed user-defined groups in each new account's `ACCOUNT_SETTINGS` instead of shipping a global list.** Rejected:
  1. User groups are exempt from review because they are the account owner's own explicit choice (ADR 0038 §5). Writing unreviewed upstream data there in the user's name hides its origin.
  2. They are end-to-end encrypted account data. No release can update or remove a lapsed domain from them, so A6 rule 5 becomes unenforceable.
  3. Existing accounts would need a migration write.
  4. Twenty-two groups would use a third of `MAX_USER_GROUPS` (64).
  5. Every new account would start with a signed settings write (`settings_seq` 1) it never asked for.
  6. There would be no signature and no INV-39 version guarantee.
- **An interim development signing key instead of the owner's offline key.** Rejected as the default (§5): it gives no protection against a compromised repository or CI. It remains available as Open question 3.
- **For §6, accept an equal version only if the list bytes match a persisted hash.** Rejected: it needs a new `cache_meta` key, which means a persistent-format change superseding ADR 0051, to guard against a case only the owner's own key can produce.
- **Use upstream `type` numbers as group ids.** Rejected: ADR 0038 §1 requires 16 random bytes that are never reused.

## Open questions for the owner

1. **Which subset becomes the seed?** The options:
   - (a) The 22 groups upstream still maintains, minus the members of §2, and minus any member that finds no evidence in the import PR.
   - (b) All 91 groups as Vaultwarden ships them, minus the ADR 0044 failures. This needs the conditional supersession of ADR 0038 §4 point 6.
   - (c) Only Google and Apple.

   **Recommendation: (a).**
2. **How does the seed batch meet THREAT_MODEL A6?** The options:
   - (a) No waiver. Per-member evidence is recorded in `data/equivalence/EVIDENCE.md`, the owner reviews alone as ADR 0038 §4 point 2 already permits, and a second maintainer audits the batch retroactively.
   - (b) An explicit owner waiver of §4 points 1 and 4 for the seed batch only, with upstream provenance and the §3 screens standing in for proof.

   **Recommendation: (a).** Option (b) is weaker on exactly the A6 risk (a member with no ownership proof) and needs the conditional supersession in §7. Either way, every later change follows §4 unchanged.
3. **Who signs the first list?** The options:
   - (a) The owner, offline, with the dedicated key (ADR 0038 §3).
   - (b) An interim development key, flagged as weaker, to be replaced by the owner's key in a later release.

   **Recommendation: (a).** A list signed with a key held in CI or on a development machine adds nothing over an unsigned list against A10, and it complicates the version sequence.
4. **Equal-version acceptance (§6).** The decision rewords INV-39 ("strictly higher than the last one accepted") to "not lower than the last one accepted; an equal version is the same list re-verified". The anti-downgrade goal is kept.

   **Recommendation: accept §6 as drafted.** The alternative, storing a hash, costs a persistent-format change for no security gain.
5. **Should the attribution also appear on the clients' notices or about screens?** Today these carry the EFF wordlist attribution.

   **Recommendation: yes.** Add one line next to the EFF attribution: "Default site groups derived from the Bitwarden server's equivalent-domains list via Vaultwarden, AGPL-3.0". It costs little and errs on the side of the licence. `THIRD_PARTY_NOTICES.md` alone may suffice (U, not legal advice).

## On acceptance

This ADR makes none of these edits. The owner makes them in the change that accepts it:
- ADR 0038's status line becomes "Partially superseded by [ADR 0044](0044-equivalence-group-member-rules.md) (§1 in part), [ADR 0080](0080-default-site-groups-vaultwarden-seed.md) (§2 in part)", and its index row in [README.md](README.md) changes to match.
- [THREAT_MODEL](../THREAT_MODEL.md):
  - A6's mitigation "a list whose version is not strictly higher than the last one they accepted" changes to "a list whose version is lower than the last one they accepted".
  - INV-39 changes to "... and a version not lower than the last one accepted (an equal version is the same list re-verified)". Its test column changes "a list with the same version" to "a list with the same version (accepted, no floor write)".
  - INV-75's test text changes "a list at or below the stored floor is refused" to "a list below the stored floor is refused; one equal to it is accepted without a write".
- [docs/equivalence-list.md](../equivalence-list.md) "Status today" and §2 describe the seed, `EVIDENCE.md` and the upstream re-check diff.
- CLAUDE.md's ADR status sentence moves 0080 from Proposed to Accepted.

## References

- [ROADMAP](../ROADMAP.md) §4.4 (rows "Equivalent domain groups", "User-defined equivalence groups + ability to disable a global group", "Community-contributed equivalence list", "Visual warning"), §6 risk 4
- [THREAT_MODEL](../THREAT_MODEL.md) [A6](../THREAT_MODEL.md#a6-phishing-site-and-autofill-abuse), [A10](../THREAT_MODEL.md#a10-compromised-ci-or-release-credentials), [AST-16](../THREAT_MODEL.md#2-assets), [Q-10](../THREAT_MODEL.md#10-open-questions-for-the-owner), [INV-39, INV-75](../THREAT_MODEL.md#8-security-invariants)
- [ADR 0017](0017-licensing.md), [ADR 0020](0020-partial-supersession.md), [ADR 0037](0037-url-matching-and-autofill-rules.md), [ADR 0038](0038-equivalent-domain-list.md), [ADR 0042](0042-account-settings-matching-layout.md), [ADR 0044](0044-equivalence-group-member-rules.md), [ADR 0051](0051-equivalence-list-version-persistence.md)
- [docs/equivalence-list.md](../equivalence-list.md), [`data/equivalence/groups.txt`](../../data/equivalence/groups.txt), `crates/xtask/src/equivalence_list.rs`, `crates/rizzy-match/src/compiled.rs`, `crates/rizzy-match/src/equivalence.rs`, `crates/rizzy-client/src/matching.rs`, `crates/rizzy-wasm/src/device.rs`, [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md)
- Vaultwarden `src/static/global_domains.json` and `tools/global_domains.py` at `b71cb7a832080d9fdfdd97bcccf065307cf73236` (V, read 2026-10-23); `Cargo.toml` licence `AGPL-3.0-only` (V)
- bitwarden/server `src/Core/Utilities/StaticStore.cs` and `src/Core/Enums/GlobalEquivalentDomainsType.cs` at `41ae9acb7b92fc8eef0b73c6cfa6eb2106a326f2` and `e1f32b96a33f0f5d63170690f0b83cce0b901d36`; `LICENSE.txt`; [PR #8404](https://github.com/bitwarden/server/pull/8404) (V, read 2026-10-23)
- Public Suffix List as shipped in `psl` 2.1.240 `data/rules.txt` (V); DNS (`dig`) and RDAP (Verisign, rdap.org, Identity Digital) observations of 2026-10-23 (V for the observations, U for any inference about a company's history)
