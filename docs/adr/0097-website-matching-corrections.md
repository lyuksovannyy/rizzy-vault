# ADR 0097: Website matching corrections: the compared URL, the *Regex* mode, and reading ACCOUNT_SETTINGS independently of the reader's PSL

- Status: Proposed
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M2
- Supersedes: on acceptance, in part: [ADR 0037](0037-url-matching-and-autofill-rules.md) (§2 in part, §4 in part), [ADR 0042](0042-account-settings-matching-layout.md) (§2 in part, §4 in part, §8 in part), [ADR 0044](0044-equivalence-group-member-rules.md) ("Where this applies" in part; owner answer 1). §1 names the exact parts ([ADR 0020](0020-partial-supersession.md) point 9).

## Owner answers (2026-10-25)

The owner's words, verbatim: "0097. agreed"

1. **Dotless names: Option B.** A dotless single-label name such as `nas` is refused in user groups, as
   today's code does, and stays accepted in the signed global list. §1 and §5 carry only this option; Option A
   moves to Alternatives considered.
2. **Engine approved.** `regex-lite =0.1.9` as a new normal dependency of `rizzy-match`, with the
   `MATCH_EXTERNAL_ALLOW` entry `regex-lite@0.1` (§3.3).

## Context

**Trigger.** On 2026-10-25 a ten-reviewer gap review of every ADR was committed ([docs/reviews/2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md), raw findings in [2026-10-25-raw/](../reviews/2026-10-25-raw/)). After it, the owner's instruction was: "start". This ADR fixes the website-matching rows of that review: **C6** (G04-17), **D7** (G05-1, G05-2), **C7** (G05-7) and **M11** (G04-16). It also closes G05-8 and G05-4, because they sit in the sentences D7 replaces. Every quote below was checked against the files at `262bbd0` (V).

### C6 (G04-17): three readings of "which parts of the URL are compared"

- [ADR 0037](0037-url-matching-and-autofill-rules.md) §2 point 6: "**Path and query.** Dropped for every mode except *Starts with* (keeps the path prefix) and *Regex* (matches against the full normalised URL, scheme and all, per INV-38)." Read literally, *Exact* loses its path, and *Starts with*/*Regex* keep the query.
- ADR 0037 §4 row `0x0004`: "**Exact** | Matches when the full normalised URL is byte-equal". Row `0x0003`: "(scheme + host + port + path)".
- ADR 0037 §2, the output sentence: "path (kept only when a mode needs it), the original string for *Regex* and for display". That is a third reading: *Regex* would run on the raw input, query included.
- The code follows a fourth, consistent rule. `crates/rizzy-match/src/normalize.rs:85-88`: "Query and fragment are dropped unconditionally, for every mode, including *Regex*". `normalized_string()` (`normalize.rs:228-242`) is `scheme://host[:port]path`. *Exact* compares it byte for byte and *Starts with* by prefix (`modes.rs:217-220`). *Host* compares host and port (`modes.rs:216`). `NormalizedUrl` has no raw-string field (`normalize.rs:64-90`). The test `query_and_fragment_are_dropped` (`normalize.rs:352-355`) pins `https://example.com/path?x=1#frag` → `https://example.com/path`.
- The path is the `url` crate's serialisation. A probe against the pinned `url =2.5.8` (V, run 2026-10-25) gave: `https://EXAMPLE.com/a/../B/%7e/%7E/é?q=1#f` → host `example.com`, path `/B/%7e/%7E/%C3%A9`. So dot segments are resolved, non-ASCII is percent-encoded, and existing escapes keep their case. `https://ex<TAB>ample.com/lo<LF>gin` → path `/login`. The normalised URL is therefore always ASCII.

### D7 (G05-1, G05-2; also G05-8, G05-4): a PSL update can make the whole ACCOUNT_SETTINGS record unreadable

- ADR 0042 §2: "**Rejected outright** (same severity as failed decryption): … or any violation inside a *recognised* tag (§3). … so a reject blocks further settings writes until resolved." §8 lists "a public-suffix domain" among the negative vectors. §4 is headed "Validation on write".
- The code checks the PSL on **read**. `MatchingSettings::decode` (`crates/rizzy-match/src/settings.rs:303-309`) calls `EquivalenceGroup::decode` (`equivalence.rs:255-260`: canonical `normalize_domain` form plus ADR 0044's `is_valid_member`, which consults `suffix::registrable_domain`). It then calls `is_valid_user_group` (`settings.rs:143-155`). `AccountSettingsRecord::decode` (`crates/rizzy-client/src/settings.rs:188-190`) maps any matching error to `InvalidServerResponse` for the whole record.
- The same record now holds tag `0x0002`, the vault directory ([ADR 0081](0081-multiple-vaults-personal-and-shared.md) §A2), and tag `0x0004`, the identity-generator defaults (ADR 0042, Amendments, 2026-10-24). A user group that was valid when it was written can name a domain that a later PSL snapshot lists as a suffix; private-section additions such as new hosting platforms are routine. A client with that newer snapshot then loses the directory and the identity defaults, while older clients still read the same record. The IDNA tables behind `normalize_domain` are reader-compiled data too, so the same applies to them (inference from `idna`'s UTS 46 processing; not observed in practice, U).
- The bytes are not attacker-controlled. The envelope opens under the account key and its SHA-256 equals the `settings_hash` in the verified `account-state` (`settings.rs:319-341`). So the bytes were written by one of the account's own clients, and "same severity as failed decryption" sends the user looking for a server attack that did not happen.
- "Until resolved" has no resolution path (G05-2). Falling back to the §3 defaults would silently turn back on the global groups the user disabled. That widens matching, which INV-38 is about.
- G05-4: §2 calls `format_version ≠ 1` "rejected outright", while §8 says "(parked, not rejected)". The code parks it (`settings.rs:172-174`, `SettingsUpdateRequired`).

### C7 (G05-7): a dotless name in a user group

- [ADR 0044](0044-equivalence-group-member-rules.md) rule 2 "accepts a dotless single-label member like `"nas"` … a bare intranet hostname like `nas` is fully reachable and must not be rejected". Owner answer 1 then says ADR 0042 §4's check "stays binding, alongside the `EquivalenceGroup::new` rule that now covers the same inputs".
- The two do not cover the same inputs. ADR 0042 §4 asks that the domain "equals its own PSL registrable domain", and a dotless name never does. The code says so: "the first check adds, for a user group, only the refusal of a dotless name" (`rizzy-match/src/settings.rs:27-30`; `is_own_registrable_domain` is `is_valid_member(domain) && domain.contains('.')`, `settings.rs:143-145`). So for user groups, where intranet names actually occur, the two Accepted texts give opposite answers. Which one should hold is an owner question (Open question 1; answered 2026-10-25: Option B).

### M11 (G04-16): *Regex* names no engine, dialect, semantics or limits, and is not built

- ROADMAP §4.4: "| M | Per-URI match mode: *Base domain* (default), *Host*, *Starts with*, *Exact*, *Regex* (advanced), *Never* | M2 |" (ROADMAP line 130).
- ADR 0037 §4 row `0x0005`: "The URI's `value` is a user-authored regular expression; it matches when it matches the page's full normalised URL **and** the registrable-domain check passes first". Owner answers (2026-10-07): "an unanchored regex gets a warning in the editor but can be saved". The Negative consequences say "The UI should warn when a regex has no anchors". Unanchored patterns are therefore searched: a pattern may match anywhere in the URL.
- The code stubs it. `modes.rs:100-104`: "No regex crate is named by ADR 0037"; `decide` returns `MatchOutcome::NotSupported` (`modes.rs:197`). `rizzy-client`'s `Skipped::RegexNotSupported` (`matching.rs:195-196`) and the web item editor ("Regex matching is not evaluated by this build yet", `apps/web/src/views/ItemEditor.tsx:736-738`) report it. The web editor can already store `0x0005` on a URI (`apps/web/src/fields.ts:186`).
- **A gap the review did not name: the gate has no URI-side domain.** The registrable-domain gate compares the page's registrable domain with the saved URI's (`modes.rs:161-174`). The client obtains the latter by parsing `uri/<id>/value` as a URL (`rizzy-client/src/matching.rs:264`). If `value` is a regular expression, as row `0x0005` says, it does not parse, so no gate can run and INV-38 cannot hold. [ADR 0018](0018-item-record-encoding.md) §7 also says `value` "is the URL as entered", and the item's "open website" action ([INV-42](../THREAT_MODEL.md#8-security-invariants)) and its icon use it.
- **The candidate engine** is `regex-lite` 0.1.9 (V, sources read from the crates.io archive and the index on 2026-10-25):
  - MIT OR Apache-2.0, repository `rust-lang/regex`, authors "The Rust Project Developers" and Andrew Gallant;
  - no normal dependencies; `#![forbid(unsafe_code)]` (`src/lib.rs:854`);
  - "all regex searches in this crate have worst case `O(m * n)` time"; a `size_limit` builder option (default 10 MiB, `src/nfa.rs:20`) and a `nest_limit` option (default 50, `src/hir/mod.rs:115`);
  - no look-around, no backreferences and no Unicode classes. A probe gave "look-around is not supported", "backreferences are not supported" and "Unicode character classes are not supported".
  - The `Regex` type needs the `string` feature: a build with `features = ["std"]` alone fails with "could not find `RegexBuilder`" (V, probe).
  - No advisory for `regex-lite` is in the local RustSec database (as of 2026-10-24). The `regex` crate has RUSTSEC-2022-0013, patched in 1.5.5 (V).
- **The dependency probe** used a scratch copy of this tree at `262bbd0` with `regex-lite = { version = "=0.1.9", default-features = false, features = ["std", "string"] }` added to `rizzy-match` (V, 2026-10-25). Results: `cargo deny check` gave "advisories ok, bans ok, licenses ok, sources ok"; `cargo check -p rizzy-match --target wasm32-unknown-unknown --locked` passed; `cargo tree` shows `regex-lite` as a leaf. `cargo xtask check-deps` would fail until `MATCH_EXTERNAL_ALLOW` (`crates/xtask/src/rules.rs:327`) lists it. Under [ADR 0016](0016-workspace-layout.md) that is a rules-table change that "Review must treat … as security changes". `regex-lite` is not a cryptographic crate, so [ADR 0009](0009-crypto-dependency-policy.md)'s checklist does not apply; HANDOFF gap 29 says the same.
- **Measured cost** (V, x86_64 release build on this host; wasm32 is slower, by an unmeasured factor, U), with case-insensitivity on, against a 4,096-byte haystack:
  - the largest pattern that fits `size_limit = 32 KiB` (for example `[a-z]{0,361}b`) takes about 17–20 ms;
  - at 64 KiB, about 34–40 ms; at 256 KiB, about 96–142 ms. The cost grows roughly linearly with the limit.
  - A realistic pattern, `^https://example\.com/(login|signin)(/.*)?$`, compiles under a 4 KiB limit.

## Decision

### 1. What this ADR supersedes

Under [ADR 0020](0020-partial-supersession.md) point 9. Each replacing text binds as Decision text of this ADR once it is Accepted; nothing else in the three ADRs changes. The ADR 0042 §4 and ADR 0044 entries carry **Option B** (owner answer 1): a dotless name is refused in user groups. The Option A texts are kept under Alternatives considered only as a record; they bind nothing.

| Part, quoted | Replaced by |
|---|---|
| [ADR 0037](0037-url-matching-and-autofill-rules.md) §2, point 6 ("**Path and query.** Dropped for every mode except *Starts with* (keeps the path prefix) and *Regex* (matches against the full normalised URL, scheme and all, per INV-38).") | "6. **Path, query and fragment.** The query (`?…`) and the fragment (`#…`) are dropped from both the saved URI and the page, for every mode. The path is kept exactly as the `url` crate serialises it for an `http(s)` URL: the WHATWG URL Standard's dot segments are resolved, characters outside the path percent-encode set are percent-encoded, existing percent-escapes are kept as written (no decoding, no case change), and an empty path reads as `/`. The **normalised URL** is the ASCII string `scheme "://" host [":" port] path`, with the host of point 3 and the port of point 5. *Exact* compares the normalised URLs of the page and the saved URI byte for byte. *Starts with* matches when the page's normalised URL starts with the saved URI's, compared as bytes, not by path segment. *Regex* runs its pattern on the page's normalised URL ([ADR 0097](0097-website-matching-corrections.md) §3). *Base domain* uses only the registrable domain (point 7), and *Host* only the host and port." |
| ADR 0037 §2, the sentence "The output of normalisation is a small `NormalizedUrl` struct: scheme, A-label host, port-or-default, registrable domain, path (kept only when a mode needs it), the original string for *Regex* and for display." | "The output of normalisation is a small `NormalizedUrl` struct: scheme, A-label host, the port when it is not the scheme's default, registrable domain, and path. Point 6's normalised URL is computed from these fields. The struct holds no query, no fragment and no copy of the raw input. A UI that displays a saved URI shows the item's own `uri/<id>/value`." |
| ADR 0037 §4, the table row whose first cell is "`0x0005`" | "\| `0x0005` \| **Regex** \| The URI's `value` is the site's URL, normalised and gated like every other mode's; the pattern is the separate attribute `uri/<id>/pattern` ([ADR 0097](0097-website-matching-corrections.md) §3). The URI matches when, in this order, the HTTPS→HTTP rule (§5) and the registrable-domain check against `value` pass, and then the pattern, compiled by `regex-lite` with ASCII case-insensitivity and ADR 0097 §3's limits, finds a match anywhere in the page's normalised URL (§2 point 6). Use `^` and `$` to anchor it to the whole URL. A missing, empty, oversized, non-ASCII or uncompilable pattern never matches. The gate runs before the pattern, so even an unanchored pattern cannot reach another registrable domain ([INV-38](../THREAT_MODEL.md#8-security-invariants)) \|" |
| [ADR 0042](0042-account-settings-matching-layout.md) §2, the bullet "**Rejected outright** (same severity as failed decryption): …" (from "wrong/truncated lengths" to "blocks further settings writes until resolved.") | "- **Unreadable record, parked record, unreadable section.** These bytes already opened under the account key and matched the `settings_hash` of the verified `account-state`, so one of the account's own clients wrote them. A problem in them is never reported as a server failure. (a) **Unreadable record** (`settings_unreadable`): wrong or truncated outer lengths, trailing bytes, `n` above `MAX_SETTINGS_ENTRIES`, an entry over `MAX_SETTINGS_ENTRY_LEN`, tags not strictly ascending (a duplicate tag included), or tag `0x0000` or `0xFFFF`. No setting is read from it; matching uses the fail-closed view of [ADR 0097](0097-website-matching-corrections.md) §4.3; every other operation that needs a setting returns `settings_unreadable`; no settings write is built. (b) **Parked record** (`settings_update_required`): `format_version ≠ 1`. Like an unknown `item_schema_version`, it forces an update. No setting is read, matching uses the same fail-closed view, and no settings write is built, so a client never overwrites a record it does not understand. (c) **Unreadable section**: a recognised tag whose value breaks that tag's own layout. Only that section is unusable. Its value is kept byte for byte and written back unchanged on every whole-record write (§5); every other tag reads and writes normally; an edit of that section returns `settings_unreadable` until the section is reset, for the tags where ADR 0097 §4.5 allows a reset. A rule that depends on data compiled into the reader, namely the Public Suffix List snapshot or the IDNA tables, is never a layout rule: a stored user group that fails one is kept and ignored for matching, not rejected (ADR 0097 §4.2)." |
| ADR 0042 §4, the bullet "**Public suffix refused (gap closed; a validity floor, not a governance rule).** …" | "- **Public suffix and dotless names refused (a validity floor, not a governance rule).** Before building a `user_group`, the client checks every normalised domain against [ADR 0044](0044-equivalence-group-member-rules.md)'s member rules (`rizzy_match::equivalence::is_valid_member`). These refuse an IP literal and any domain that is not its own registrable domain: a bare suffix such as `co.uk` or `github.io`, or a subdomain such as `mail.example.com`. The client also refuses a domain without a dot (`nas`, `localhost`). A single-label name resolves through the device's DNS search domains, so it can name a different host on each network; an item that needs such a host holds it as one more URI. A refusal returns `equivalence_domain_rejected`. These are structural checks on what a `user_group` may hold. They do not reinstate [ADR 0038](0038-equivalent-domain-list.md) §4's review process (ownership proof, two-maintainer sign-off, scheduled re-checks), which §5 already, and still, exempts user groups from, and they do not supersede ADR 0038 §5. They run when a group is written, never when a stored record is read ([ADR 0097](0097-website-matching-corrections.md) §4.2). `flag_third_party_hostable` is forced to `0x00` for the same reason: that flag records a *reviewed* exception (ADR 0038 §4 point 3), and no user group has one." |
| ADR 0042 §8, the second sentence ("Negative (one violation each): truncated entry, … `format_version ≠ 1` (parked, not rejected).") | "Negative (one violation each), with the outcome: truncated entry, duplicate tag, oversize entry, too many entries: each an unreadable record (`settings_unreadable`); a duplicate `group_id`, a one-domain user group, user groups out of `group_id` order, a domain longer than 253 bytes, domains out of byte order, `match_default` out of range: each an unreadable section `0x0001`, with tags `0x0002` and `0x0004` of the same record still read; `format_version ≠ 1`: parked (`settings_update_required`). Inert, not rejected (the record decodes, the group is kept byte for byte and is absent from the `EquivalenceView`): a user group holding a public-suffix domain, a subdomain, a domain not in canonical A-label form, an IP literal or a dotless name, or with `flag = 1` ([ADR 0097](0097-website-matching-corrections.md) §4.2)." |
| [ADR 0044](0044-equivalence-group-member-rules.md) "Where this applies", the third bullet ("**User-defined groups, once [ADR 0042](0042-account-settings-matching-layout.md) lands** (Proposed, reference only): …") | "- **User-defined groups ([ADR 0042](0042-account-settings-matching-layout.md), Accepted).** A user group is built with `EquivalenceGroup::new` (through `rizzy_match::settings::user_group`), so it inherits rules 1 and 2 when it is written. ADR 0042 §4 adds one refusal for user groups only: a dotless single-label name (`nas`), which rule 2 accepts in the signed global list. This is deliberate, not redundant: a dotless name resolves through the device's DNS search domains, and an item reaches a dotless host without a group by holding one more URI. When a user group is *read* back from `ACCOUNT_SETTINGS`, rules 1 and 2 and the dotless refusal never reject it: a stored group that fails one of them under the reader's PSL snapshot or IDNA tables is kept byte for byte and ignored for matching ([ADR 0097](0097-website-matching-corrections.md) §4.2). The signed global list keeps this ADR's strict decode, whole-list rejection included." |
| ADR 0044 "Owner answers at acceptance (2026-10-22)", answer 1 ("ADR 0042's own §4 public-suffix check becomes redundant. … so this stays open.") | "1. ADR 0042's own §4 check is not redundant. Besides the bare suffix and the subdomain that `EquivalenceGroup::new` already refuses, it refuses a dotless single-label name, which this ADR's rule 2 accepts. [ADR 0097](0097-website-matching-corrections.md) keeps that refusal for user groups and spells it out in ADR 0042 §4. Rule 2 is unchanged for the signed global list." |

ADR 0037 §2 point 5 (ports), §4 rows `0x0003` and `0x0004`, "Narrowing only" and ADR 0037's owner answers stay binding as written. Point 6's definition gives their "normalised URL" its meaning. The owner answer "an unanchored regex gets a warning in the editor but can be saved" stays binding; §3.6 defines "unanchored".

### 2. The compared URL, per mode

This is the code's current behaviour (`normalize.rs`, `modes.rs`), stated as the rule. No code changes for it.

| Mode | Scheme | Host | Port | Path | Query | Fragment | Comparison |
|---|---|---|---|---|---|---|---|
| *Base domain* | – | registrable domain only | – | – | – | – | gate only |
| *Host* | – | yes | yes (non-default only) | – | – | – | host and port equal |
| *Starts with* | yes | yes | yes | yes | dropped | dropped | byte prefix of the normalised URL |
| *Exact* | yes | yes | yes | yes | dropped | dropped | byte equality of the normalised URL |
| *Regex* | yes | yes | yes | yes | dropped | dropped | pattern search on the page's normalised URL |
| *Never* | – | – | – | – | – | – | never matches |

- Every mode except *Never* runs the HTTPS→HTTP rule and then the registrable-domain gate first (ADR 0037 §4–§5, unchanged). The gate compares registrable domains, so "–" in the Scheme column does not switch the HTTPS→HTTP rule off.
- **The query is dropped on purpose.** Login pages carry volatile parameters (`?next=…`, `?session=…`). Keeping them would make *Exact* match almost nothing. The dropped query never widens a match past the scheme, host, port and path the user saved.
- **The editor shows it.** When a saved `value` has a query or a fragment, the item editor shows "The part after ? or # is ignored for matching". This is a usability rule of the M2 editor, not a security gate.

### 3. *Regex* mode

#### 3.1 Where the pattern lives

A new item field key, `uri/<id>/pattern`. ADR 0018 §7 says "A new key needs a line in the ADR that ships it, never a version bump", and this is that line:

| Key | Value | Types | Notes |
|---|---|---|---|
| `uri/<id>/pattern` | Text | Login | The pattern of a URI whose effective mode is *Regex* (`0x0005`), ADR 0097 §3. Ignored in every other mode. A content attribute, shown, any writer |

- `uri/<id>/value` stays the URL as entered, as ADR 0018 §7 says. It supplies the URI-side scheme for the HTTPS→HTTP rule and the registrable domain for the gate, as in every other mode. It also still drives "open website" (INV-42) and the icon.
- Clients from before this ADR carry `pattern` verbatim as an unknown key (ADR 0018 §11). `rizzy-core`'s key classifier gains the entry: Text, Login, `Writers::Any`, `Concealment::Shown`.
- When the user switches a URI's mode away from *Regex*, the editor writes `Cleared` to `pattern` in the same op. A hidden pattern therefore never keeps a list element alive.
- An account default of *Regex* (ADR 0042 §3 allows `match_default = 0x0005`) applies each URI's own `pattern`. A URI without one never matches.

#### 3.2 Evaluation order

For one saved URI whose effective mode (`MatchMode::resolve`) is *Regex*:

1. `NormalizedUrl::parse(value)`. On failure, `Skipped::UriDidNotNormalize`, as today.
2. The HTTPS→HTTP rule (`value`'s scheme against the page's). If it blocks: `NoMatch`.
3. The registrable-domain gate (page against `value`; equivalence groups apply as in every mode and set `matched_via` the same way). If it fails: `NoMatch`. **The pattern is not even compiled for a page on another registrable domain.**
4. If the page's normalised URL is longer than `MAX_URL_LEN` (4,096 bytes, `rizzy-match/src/error.rs:15`): `NoMatch`, without compiling or running the pattern.
5. The per-call budget (§3.4). If it is spent: `MatchOutcome::RegexBudgetExceeded`.
6. Pattern validity (§3.3), which compiles the pattern. If it fails: `MatchOutcome::InvalidPattern`.
7. `Regex::is_match(page_normalised_url)`, a search: the pattern may match anywhere unless it anchors itself. `true` gives `MatchOutcome::Match(matched_via)`, `false` gives `NoMatch`.

The pattern runs against the page only, never against the saved `value`.

#### 3.3 Engine, dialect and limits

- **Engine.** `regex-lite`, pinned `=0.1.9` in `[workspace.dependencies]` with `default-features = false, features = ["std", "string"]`, a normal dependency of `rizzy-match` only. `MATCH_EXTERNAL_ALLOW` gains `"regex-lite@0.1"`. The owner approved both (owner answer 2, 2026-10-25). A version bump is an ordinary dependency PR. It re-runs this ADR's vectors (§6) and its description lists the upstream changelog entries. There is no ADR 0009 checklist: this is not a cryptographic crate.
- **Dialect.** `regex-lite`'s syntax: Rust `regex` syntax without look-around, backreferences or Unicode classes. It supports inline flags (`(?i)`, `(?-i)`, `(?x)`, …), `\A`, `\z` and `\b`. Without the `m` flag, `^` and `$` match only at the start and end of the haystack. No other dialect (ECMAScript, PCRE) is accepted or translated.
- **Builder.** Exactly this:

  ```rust
  RegexBuilder::new(pattern)
      .case_insensitive(true)
      .size_limit(PATTERN_SIZE_LIMIT)
      .nest_limit(PATTERN_NEST_LIMIT)
      .build()
  ```

  No other option is set. Case-insensitivity is ASCII-only in `regex-lite`, which is enough because the haystack is ASCII (§2). A pattern can switch it off with `(?-i)`.
- **Constants** (new, in `rizzy_match::error`):
  - `MAX_PATTERN_LEN = 1_024` bytes;
  - `PATTERN_SIZE_LIMIT = 32_768`: the measured worst case is about 20 ms per evaluation natively on a 4 KiB haystack (Context);
  - `PATTERN_NEST_LIMIT = 32`;
  - `MAX_REGEX_EVALUATIONS = 32` (§3.4).

  Changing any of them is not a format change. Once this ADR is Accepted, it takes an owner-approved amendment of this ADR, with a new measurement.
- **Validity.** A pattern is valid exactly when all of these hold:
  - it is present and not `Cleared`;
  - it has 1 to `MAX_PATTERN_LEN` bytes;
  - every byte is printable ASCII (`0x20`–`0x7E`). A non-ASCII literal could never match the ASCII haystack; the editor message says to use the `xn--` form;
  - the builder above returns `Ok`.

  Validity is decided by `rizzy_match::pattern::compile(&str) -> Result<Pattern, PatternError>`, with `PatternError::{Empty, TooLong, NotAscii, Invalid}`. `Invalid` covers every builder error (syntax, size limit, nesting limit), because `regex-lite`'s `Error` exposes only a message, and a message is not a stable classifier. The editor (§3.6) and `decide` call the same function. No error carries the pattern text.

#### 3.4 Per-call budget

The budget lives in `rizzy-match`, in a `pattern::RegexSession` that `rizzy-client`'s `decide_candidates` creates once per call and passes to every `decide`. One session takes at most `MAX_REGEX_EVALUATIONS` (32) *Regex* URIs past step 5 of §3.2, in the order given; a URI counts when it reaches step 5, whether its pattern then turns out valid or not. Identical pattern strings within one session share one compilation (the session caches compiled patterns by string). Each further *Regex* URI that reaches step 5 is reported as `Skipped::RegexBudgetExceeded`, and the call adds one warning line: "matching: more than 32 Regex URIs for this site; the rest were not evaluated". Only URIs that already passed the gate count, so the budget limits the cost of one site's items, and patterns written by a shared-vault member (M9) for other sites cost nothing. The session is dropped at the end of the call: no compiled pattern is kept between calls, and nothing new is stored.

#### 3.5 API changes

- **`rizzy-match`:**
  - `MatchOutcome::NotSupported` is removed; `MatchOutcome::InvalidPattern` and `MatchOutcome::RegexBudgetExceeded` are added.
  - `modes::decide` gains two parameters, `pattern: Option<&str>` (the URI's raw `uri/<id>/pattern`) and `regex: &mut pattern::RegexSession`. Both are ignored for every mode but *Regex*. `decide` itself runs steps 2–7 of §3.2, so no caller can compile a pattern before the gate has passed.
  - `EffectiveMode::Regex` passes the same gates as every other mode (`GatedMode` gains `Regex`).
- **`rizzy-client`:**
  - `ItemUri` gains `pattern: Option<&'a str>`.
  - `Skipped::RegexNotSupported` is replaced by `Skipped::RegexInvalid` (from `InvalidPattern`; warning "matching: a saved URI's Regex pattern is invalid and was skipped") and `Skipped::RegexBudgetExceeded` (from `RegexBudgetExceeded`).
  - Saving an item with an invalid pattern on a *Regex* URI returns the new `ClientError::RegexInvalid`, code `regex_invalid`.
- **wasm and TypeScript.** `rizzy-wasm` and the TypeScript bindings carry `pattern` alongside `value`.

#### 3.6 Editor rules

- Selecting *Regex* shows a "Pattern" input next to the "Website" (`value`) input. Both are required.
- **Before saving**, the editor calls `pattern::compile`. An invalid pattern cannot be saved (`regex_invalid`), and the message names the `PatternError` kind.
- **Unanchored warning.** Strip any leading inline-flag groups matching `\(\?[imsUxR-]*\)`. If what remains does not begin with `^` or `\A`, the pattern is unanchored. The editor then shows "This pattern can match anywhere in the address, on any page of this site" and still allows saving (ADR 0037 owner answer).
- **A synced pattern this client finds invalid** (written by a client with another `regex-lite` version) is kept verbatim. The editor shows it as invalid and never rewrites it without a user edit.

#### 3.7 Migration and imports

- **No migration.** A URI already stored with `match = 0x0005` has no `pattern`, so it never matches, as it does today under `NotSupported`.
- **Imports are unchanged.** The Bitwarden importer does not map match modes (`rizzy-import/src/bitwarden.rs:21`).
- **Export.** The plaintext export carries `uri/<id>/pattern` like any other field key (L: its key/value shape, `rizzy-client/src/export/plaintext.rs:34-36`). How CXF export treats a *Regex* URI is not decided here (U, not checked).

### 4. Reading ACCOUNT_SETTINGS independently of the reader's PSL

#### 4.1 Severities

ADR 0042 §2 as replaced (§1) defines three outcomes for a record that opened and matched `settings_hash`: an unreadable record, a parked record and an unreadable section. §4.2 adds a fourth, below the section level, for tag `0x0001` only: an **inert user group**. Decryption failure, a missing envelope or a hash mismatch stay `invalid_server_response` (or `rollback`) as today. Those are the server's failures.

#### 4.2 Tag `0x0001`: structural rules and content rules

**Structural rules.** `MatchingSettings::decode` applies only these. Breaking one makes section `0x0001` unreadable. None of them consults compiled-in data:

- truncated or trailing bytes;
- `match_default` outside `0x0001..=0x0006`;
- `d > 1,024` or `u > 64`;
- disabled ids not strictly ascending;
- user groups not strictly ascending by `group_id`;
- `m` outside `2..=64`;
- a domain string that is not UTF-8, is empty, or is longer than 253 bytes (`MAX_HOST_LEN`);
- domains within a group not strictly ascending bytewise;
- a flag byte other than `0x00` or `0x01`.

**Content rules.** A writer checks these on a group's domains and flag (ADR 0042 §4, ADR 0044 rules 1–2). They are evaluated when the record is read, but never reject it:

- every domain is in canonical form (`normalize_domain(d) == d`);
- no domain is an IP literal;
- every domain is its own registrable domain;
- every domain contains a dot (owner answer 1, Option B);
- the flag is `0x00`.

A group that fails any content rule is **inert**:

- it is kept as its exact wire bytes and counts towards `u`;
- it is written back byte for byte on every whole-record write;
- it is left out of `EquivalenceView`, so it never widens a match;
- it is listed by a new `MatchingSettings::inert_groups()` with its reasons: `NotCanonical`, `IpLiteral`, `NotRegistrable` or `Dotless` for each failing domain, and `ThirdPartyFlag` for the group's flag;
- inertness is recomputed on every read, so a later PSL snapshot can make the group active again with no write.

Settings → Website matching shows an inert group as "Ignored for matching", with its reason (for `NotRegistrable`: "`<domain>` is not a registrable domain for this version of rizzy-vault"), and offers Delete. Editing it is Delete followed by Add, with the ordinary write-time checks. `Debug` still shows counts only.

The signed global list is not affected. ADR 0044's strict decode and whole-list rejection on a PSL bump stay binding for it.

#### 4.3 The fail-closed matching view

While section `0x0001` is unreadable, or the record is unreadable or parked:

- `rizzy-client` builds the account default as *Never*;
- it uses an empty `EquivalenceView`: no global group and no user group, so no group the user disabled comes back;
- a URI with its own explicit mode still matches through the plain registrable-domain gate.

`decide_candidates` adds one warning: "matching: the account's matching settings are unreadable; site groups are off and URIs on the account default are not offered". The fill UI links that warning to Settings → Website matching. *Never*, rather than *Host*, is the default because the stored default could have been *Exact* or *Never*. Any fallback wider than the user's own choice would widen matching.

#### 4.4 Writes never lose a tag

- A whole-record write (ADR 0042 §5) re-emits byte for byte every unknown tag, every unreadable section and every inert group.
- An edit that needs an unreadable section returns `settings_unreadable` and builds nothing: `SettingsEdit::SetMatchDefault`, `AddUserGroup`, `RemoveUserGroup`, `DisableGlobalGroup` and `EnableGlobalGroup` for `0x0001`; `SetIdentityDefaults` for `0x0004`; every vault-directory change for `0x0002`.
- An edit of another, readable section proceeds normally. For example, `SetIdentityDefaults` succeeds while `0x0001` is unreadable and carries `0x0001`'s bytes unchanged.
- An unreadable or parked record blocks every settings write.

#### 4.5 Resolution: resetting an unreadable section

- **The new edit.** `SettingsEdit::ResetSection(tag)` is allowed for tag `0x0001` and tag `0x0004` only, and only while that section is unreadable. In any other case it returns `invalid_input`. It is an ordinary whole-record write under the existing CAS (ADR 0042 §5), through `PendingSettingsChange`:
  - **`0x0001`** writes the §3 default section, the 6 bytes `00 01 00 00 00 00`: *Base domain*, no disabled groups, no user groups.
  - **`0x0004`** removes the tag, so the generator's built-in defaults apply (ADR 0079).
- **Confirmation.** The host shows a confirmation before it submits the reset. For `0x0001` it reads: "Global site groups you turned off will be on again. Your own site groups will be deleted. The account default becomes Base domain." Only an explicit button press submits it; nothing resets on its own.
- **Crash and retry.** A CAS `Restart` redoes the edit on the newer record, as every settings edit does (`settings.rs:415`). If another device has repaired the section in the meantime, the redo finds it readable and returns `invalid_input` with nothing written. A reset therefore never overwrites a readable section. A crash after submit is covered by the existing commit and pending-change handling; the `state_seq` CAS makes a double apply impossible.
- **Not covered.** No reset is offered for an unreadable record, a parked record, tag `0x0002` (the vault directory, [ADR 0081](0081-multiple-vaults-personal-and-shared.md); a reset could drop vaults from it), tag `0x0003` or an unknown tag. Those keep today's behaviour, with the new error code.

#### 4.6 Error codes

- **New:** `ClientError::SettingsUnreadable`, code `settings_unreadable`, Display "the account's settings could not be read; another device may have written them incorrectly". It carries no setting value.
- **Unchanged:** `settings_update_required`, `equivalence_domain_rejected`, `settings_limit_reached`, `invalid_server_response` (now only for decryption, a missing envelope and `settings_seq` mismatches).

### 5. Dotless names in user groups

A dotless single-label name such as `nas` is refused in a user group at write time, and the refusal is spelled out (owner answer 1, Option B; §1 carries the texts). Today's code already does this, so it needs no code change beyond doc comments. A stored group that breaks the rule is inert, never a reject (§4.2), which satisfies D7.

### 6. Implementation plan and tests

Each step is one Conventional Commit and passes the CLAUDE.md gate. None of them starts before this ADR is Accepted.

1. **`docs(match)`/`test(match)`: the compared URL.** Update the doc comments in `normalize.rs` and `modes.rs` to cite ADR 0097 §2. Add vectors:
   - *Exact*: saved `https://example.com/login?x=1` against `https://example.com/login?y=2` → `Match`; against `https://example.com/login/` → `NoMatch`.
   - *Starts with*: saved `https://example.com/login?x=1` against `https://example.com/login/step?z` → `Match`; saved `https://example.com/log` against `https://example.com/login` → `Match` (byte prefix, documented).
   - *Regex*: pattern `x=1` against page `https://example.com/login?x=1` → `NoMatch`; pattern `^https://example\.com/login$` against the same page → `Match`.
   - Fragment and dot-segment vectors from the Context probe.
2. **`feat(core)`: `uri/<id>/pattern`.** Add the classifier entry and its tests: writers accept it, and it is Login-only. Normative vector: a Login create with a *Regex* URI.
3. **`feat(match)`: *Regex* evaluation.**
   - Dependency: the workspace pin, `MATCH_EXTERNAL_ALLOW` and THIRD_PARTY_NOTICES, with `cargo deny check` and `cargo xtask check-deps` green.
   - Code: the `pattern` module and the `decide` change.
   - Tests:
     - **INV-38:** `value` `https://example.com/`, pattern `.*`, page `https://evil.example/` → `NoMatch`.
     - **Order:** an invalid pattern on a foreign page → `NoMatch`, the same pattern on the same site → `InvalidPattern`. This proves the gate runs before compilation.
     - **HTTPS→HTTP:** `value` `https://…` against an `http://` page → `NoMatch`.
     - **Equivalence:** `value` `https://youtube.com/`, page `https://youtu.be/x`, pattern `^https://youtu\.be/` → `Match(Equivalence)`.
     - **Limits:** 1,024 bytes accepted and 1,025 refused; empty, non-ASCII, `\p{L}`, look-around and backreference → `InvalidPattern`; `[a-z]{5000}` (size limit) and 40 nested groups (nesting limit) → `InvalidPattern`.
     - **Case:** `^HTTPS://EXAMPLE\.COM/` matches; `(?-i)^HTTPS://` does not.
     - **Haystack:** a page URL over 4,096 bytes → `NoMatch`.
     - **Property:** `decide` never panics on an arbitrary pattern and page, and a *Regex* `Match` implies the gate passed.
     - **Harness:** the `adr0037_differential` oracle evaluates *Regex*.
     - **Fuzz:** a new target `match_regex` (`fuzz/Cargo.toml`) with an arbitrary pattern and page. It must not panic, and an evaluation stays under 4,096 haystack bytes.
4. **`feat(client)`/`feat(web)`/`feat(extension)`: the pattern in the UI and bindings.**
   - `ItemUri.pattern`, the `Skipped` variants, `regex_invalid`, one `RegexSession` per `decide_candidates` call, and the unanchored check (`rizzy_match::pattern::is_anchored`).
   - The web editor's Pattern input, with `Cleared` on a mode change.
   - wasm and TypeScript bindings.
   - Tests: the budget (33 same-site *Regex* URIs → 32 evaluated plus one warning); unit tests for the editor helpers; one extension e2e that fills on a *Regex* URI.
5. **`fix(match)`: inert user groups.**
   - Code: split `EquivalenceGroup`'s decode into a structural pass and the member rules. `MatchingSettings` holds stored groups as `(raw bytes, Option<EquivalenceGroup>)`; encode writes raw bytes for inert groups. The global list keeps the strict path.
   - Vectors:
     - **Valid at write, suffix at read:** a hand-encoded group `{example.com, github.io}` → the section decodes, the group is inert, it is absent from the view, and re-encoding gives identical bytes.
     - One inert vector per content rule.
     - Every structural rule → `Err`.
     - **Property:** encode → decode → encode is the identity, inert groups included.
6. **`fix(client)`: section isolation, the fail-closed view and the reset.**
   - Code: `AccountSettingsRecord` keeps an unreadable recognised tag as raw bytes with an `Unreadable` state; the fail-closed view; `settings_unreadable`; `ResetSection`.
   - Tests:
     - an unreadable `0x0001` with valid `0x0002` and `0x0004` → the directory and identity defaults are read, matching is fail-closed, `SetIdentityDefaults` writes `0x0001`'s bytes unchanged, and `SetMatchDefault` returns `settings_unreadable`;
     - `ResetSection(0x0001)` writes `00 01 00 00 00 00` and keeps the other tags;
     - a `ResetSection` on a readable section → `invalid_input`;
     - a CAS `Restart` after another device repaired the section → `invalid_input` and no write;
     - an outer framing error → `settings_unreadable`, never `invalid_server_response`.
   - Fuzz: update `fuzz/fuzz_targets/client_account_settings.rs`. The allowed failures become `settings_unreadable` and `settings_update_required`; inert groups and unreadable sections survive every edit byte for byte.

## Consequences

### Positive

- One rule for the compared URL. It matches the code and the existing tests, and a second client implementation has nothing left to guess.
- *Regex* becomes buildable under INV-38. The gate has a real URI-side domain, a pattern on another site costs nothing, and the engine is linear-time, has no dependencies, is `forbid(unsafe_code)` and is checked by `cargo deny`.
- A PSL or IDNA update can no longer take the vault directory or the identity defaults down with the matching settings. A broken section has a user-visible, confirmed way out, and no fallback widens matching.
- Reports are accurate: a client-written settings problem is `settings_unreadable`, not "the server's answer failed verification".

### Negative

- A new dependency, and a new key in `rizzy-match`'s allow-list. This ADR is the review ADR 0016 asks for.
- *Regex* URIs need two inputs, a website and a pattern. That differs from Bitwarden, where the URI field itself holds the pattern. Bitwarden *Regex* URIs would need a mapping if their import is ever added.
- `regex-lite` searches are slower than `regex`'s. The budget and size limit bound that cost, but the bound was measured natively only.
- The fail-closed view stops suggestions for every URI on the account default until the user resets or repairs the section. That is acceptable only because §4.2 removes the routine cause, PSL drift.
- Devices with different PSL snapshots can disagree on whether a user group is inert (AR-15, unchanged).
- `Exact` cannot tell two query strings apart.

### Risks

- **Panics.** `regex-lite`'s documentation says panics are "incredibly rare" but possible, and in wasm a panic aborts the call. Mitigations: the fuzz target and pattern length cap of §6; the crate is in OSS-Fuzz per its own docs (L). Signal: a fuzz crash, which pins the version and gets a new ADR if the crate must change.
- **Limits calibrated on one x86_64 host.** Signal: the extension's matching latency on low-end hardware. Lowering `PATTERN_SIZE_LIMIT` is an edit to §3.3.
- **An unreadable tag `0x0002` or record** still has no reset path, so a buggy writer could lock vault-directory changes. Signal: any `settings_unreadable` report from the field. The fix is a separate ADR on ADR 0081's directory.

## Alternatives considered

- **Keep the query for *Exact*, *Starts with* and *Regex*.** Rejected: volatile parameters would make *Exact* useless; the code and tests already drop it; and INV-38 already says patterns run against the *normalised* URL.
- **Full-match *Regex* semantics** (an anchored `\A(?:p)\z`). Rejected: the owner's answer at ADR 0037's acceptance assumes that unanchored patterns exist and can be saved with a warning; users anchor with `^` and `$` when they want to. A probe also showed that wrapping is fragile: `(?x)a #` compiles on its own but not wrapped, because the comment swallows the closing parenthesis.
- **Keep the pattern in `value` and take the domain from its literal prefix.** Rejected: `regex-lite` exposes no syntax tree, so we would write our own literal-prefix parser for every pattern shape. "Open website" and icons would also break, and ADR 0018 §7's "`value` is the URL as entered" would stop holding.
- **The `regex` crate.** Rejected for now: a larger closure (`regex-automata`, `regex-syntax`, optional `aho-corasick`/`memchr`), Unicode tables in the wasm bundle, and a speed we do not need for haystacks of at most 4 KiB.
- **ECMAScript `RegExp` in the extension.** Rejected: it backtracks (ReDoS), it is absent from the CLI and web-vault core, and ADR 0037 §1 asks for one `rizzy-match` implementation in every client.
- **Fall back to the §3 defaults when tag `0x0001` cannot be read.** Rejected: it re-enables disabled global groups and so widens matching (G05-2).
- **Use the last known good settings from the cache.** Rejected: the ADR 0026 cache holds only the current object (`SettingsCache` is keyed on the current `settings_seq`, `settings.rs:344-352`). Keeping history would be a new persistent format.
- **Keep the PSL check on read, but reject only tag `0x0001`.** Rejected: a routine PSL bump would still switch a user's matching settings to fail-closed with no fault of theirs.
- **Option A of the draft's open question 1: accept a dotless name such as `nas` in user groups too.** Rejected by the owner (owner answer 1, 2026-10-25) for Option B. It would have changed today's behaviour, and a single-label name resolves through DNS search domains and can name a different host on each network, so linking one by equivalence to other sites widens that ambiguity. Kept for the record, the three §1 rows would have carried these texts instead:
  - **ADR 0042 §4, the "Public suffix refused" bullet:** "- **Member rules (a validity floor, not a governance rule).** Before building a `user_group`, the client checks every normalised domain against [ADR 0044](0044-equivalence-group-member-rules.md)'s member rules (`rizzy_match::equivalence::is_valid_member`). These refuse an IP literal and any domain that is not its own registrable domain: a bare suffix such as `co.uk` or `github.io`, or a subdomain such as `mail.example.com`. A dotless single-label name such as `nas` is accepted, as it is in the signed list. A refusal returns `equivalence_domain_rejected`. These are structural checks on what a `user_group` may hold. They do not reinstate [ADR 0038](0038-equivalent-domain-list.md) §4's review process (ownership proof, two-maintainer sign-off, scheduled re-checks), which §5 already, and still, exempts user groups from, and they do not supersede ADR 0038 §5. They run when a group is written, never when a stored record is read ([ADR 0097](0097-website-matching-corrections.md) §4.2). `flag_third_party_hostable` is forced to `0x00` for the same reason: that flag records a *reviewed* exception (ADR 0038 §4 point 3), and no user group has one."
  - **ADR 0044 "Where this applies", third bullet:** "- **User-defined groups ([ADR 0042](0042-account-settings-matching-layout.md), Accepted).** A user group is built with `EquivalenceGroup::new` (through `rizzy_match::settings::user_group`), so rules 1 and 2 are exactly the domain rules a user group obeys when it is written; ADR 0042 §4 adds none of its own, so a dotless name such as `nas` is accepted. When a user group is *read* back from `ACCOUNT_SETTINGS`, rules 1 and 2 never reject it: a stored group that fails one of them under the reader's PSL snapshot or IDNA tables is kept byte for byte and ignored for matching ([ADR 0097](0097-website-matching-corrections.md) §4.2). The signed global list keeps this ADR's strict decode, whole-list rejection included."
  - **ADR 0044 owner answer 1:** "1. ADR 0042's own §4 public-suffix check is replaced by [ADR 0097](0097-website-matching-corrections.md): a user group's domains obey exactly this ADR's rules 1 and 2, so a dotless single-label name such as `nas` is accepted in a user group, as in the global list."

  Option A would also have dropped §4.2's "every domain contains a dot" rule and the `Dotless` reason, and needed one more §6 step (`fix(match)`: `is_own_registrable_domain` becomes `is_valid_member`; test: `user_group(id, ["nas", "nas.example"])` → `Ok`).

## Open questions for the owner

1. **May a user-defined equivalence group contain a dotless intranet name such as `nas`? (C7, G05-7)** ADR 0044 rule 2 says such a name "must not be rejected". ADR 0042 §4, read through the PSL, refuses it in user groups, and the code does so today. Owner answer 1 of ADR 0044 was given in the belief that the two agree. Option B: refuse it in user groups and keep it for the global list; Option A: accept it in user groups too. *Recommendation:* Option B.
   **Answered 2026-10-25: Option B** (owner answer 1). §1 carries its texts; Option A is under Alternatives considered.
2. **Approve `regex-lite =0.1.9` as a new normal dependency of `rizzy-match`, with the `MATCH_EXTERNAL_ALLOW` entry `regex-lite@0.1`.** CLAUDE.md asks for a justification of every new crate, and ADR 0016 treats an allow-list change as a security change. Context gives the facts: licence, maintainers, zero dependencies, `forbid(unsafe_code)`, no advisories, `cargo deny check` passing, and a wasm32 build. *Recommendation:* approve. If the owner prefers the full `regex` crate instead, only the engine bullet and the allow-list entry of §3.3 change; the dialect is a superset, the limits stay the same, and the vectors stay the same.
   **Answered 2026-10-25: approved** (owner answer 2): `regex-lite =0.1.9` and the `MATCH_EXTERNAL_ALLOW` entry `regex-lite@0.1`.

No open questions remain.

## On acceptance

This ADR makes none of these edits. The owner makes them in the change that accepts it:

1. **ADR 0037** status line: `Partially superseded by [ADR 0097](0097-website-matching-corrections.md) (§2 in part, §4 in part)`.
2. **ADR 0042** status line: append `; [ADR 0097](0097-website-matching-corrections.md) (§2 in part, §4 in part, §8 in part)` after the ADR 0081 entry.
3. **ADR 0044** status line: `Partially superseded by [ADR 0097](0097-website-matching-corrections.md) ("Where this applies" in part; owner answer 1)`.
4. **docs/adr/README.md:** the Status cells of rows 0037, 0042 and 0044 follow items 1–3, and row 0097's becomes `Accepted`.
5. **THREAT_MODEL.md**, INV-38: the sentence "Regexes are matched against the full normalised URL." becomes "Regexes are searched, ASCII case-insensitively, in the page's normalised URL (scheme, host, non-default port and path; never the query or fragment), only after the gate has passed against the URI's own `value`, under the limits of ADR 0097 §3." The test column gains "a valid-at-write user group that the reader's PSL lists as a suffix is ignored, not rejected (ADR 0097 §4.2)".
6. **THREAT_MODEL.md** A6 "Mitigations": the bullet "Registrable domains come from the PSL (eTLD+1)." gains "A PSL update never makes a stored settings record unreadable; a user group that no longer passes is ignored for matching (ADR 0097 §4)."
7. **CRYPTO.md §8.4** "Account-settings plaintext" paragraph: add "Reading it follows ADR 0097 §4: a record or section that fails its layout is `settings_unreadable` (never a server failure), and a user group that fails a PSL- or IDNA-dependent rule is kept and ignored."
8. **CRYPTO.md §15 item 1(A)** lists this ADR's vectors (§6 steps 1, 3, 5 and 6). They land with the implementation, which writes them.
9. **ROADMAP.md:** no edit. The M2 *Regex* row is unchanged in scope.
10. **CLAUDE.md**'s ADR status sentence, if it lists Proposed ADRs: updated by the lead, not by this ADR.

## References

- [ADR 0016](0016-workspace-layout.md) (R1 allow-list), [ADR 0018](0018-item-record-encoding.md) §7, §11, [ADR 0020](0020-partial-supersession.md) point 9, [ADR 0026](0026-client-device-state-and-cache.md), [ADR 0037](0037-url-matching-and-autofill-rules.md) §1–§6, [ADR 0038](0038-equivalent-domain-list.md) §4–§5, [ADR 0042](0042-account-settings-matching-layout.md) §2–§8 and Amendments, [ADR 0044](0044-equivalence-group-member-rules.md), [ADR 0079](0079-identity-generator.md), [ADR 0081](0081-multiple-vaults-personal-and-shared.md) §A2
- [THREAT_MODEL.md](../THREAT_MODEL.md) [A6](../THREAT_MODEL.md#a6-phishing-site-and-autofill-abuse), [INV-38, INV-42, INV-102, AR-15](../THREAT_MODEL.md#8-security-invariants); [CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes); [ROADMAP §4.4](../ROADMAP.md#44-url-matching--autofill-m2)
- Review: [2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md) rows C6, C7, D7, M11; raw findings G04-16, G04-17 ([G04.md](../reviews/2026-10-25-raw/G04.md)), G05-1, G05-2, G05-4, G05-7, G05-8 ([G05.md](../reviews/2026-10-25-raw/G05.md))
- Code read at `262bbd0` (V): `crates/rizzy-match/src/{normalize,modes,settings,equivalence,error}.rs`, `crates/rizzy-client/src/{settings,matching,error}.rs`, `crates/rizzy-core/src/item/schema.rs`, `crates/xtask/src/rules.rs`, `crates/rizzy-import/src/bitwarden.rs`, `apps/web/src/{fields.ts,views/ItemEditor.tsx}`, `fuzz/fuzz_targets/client_account_settings.rs`
- `regex-lite` 0.1.9 (V: crates.io index entry and the published archive's `Cargo.toml`, `src/lib.rs`, `src/nfa.rs`, `src/hir/mod.rs`, `src/string.rs`, read 2026-10-25); RustSec advisory database, local copy dated 2026-10-24 (V)
- Probes run 2026-10-25 outside the repository (V): `url =2.5.8` serialisation; `regex-lite` syntax, size-limit and timing; `cargo deny check` and a wasm32 `cargo check` of `rizzy-match` with the dependency added in a scratch copy
