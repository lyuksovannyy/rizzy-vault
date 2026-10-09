# ADR 0042: ACCOUNT_SETTINGS plaintext: canonical layout and the M2 matching section

- Status: Proposed
- Date: 2026-10-08
- Deciders: project owner
- Milestone: M2

## Context

[ADR 0037](0037-url-matching-and-autofill-rules.md) §6–§7 (Accepted) puts the account-level match
default, the account's disabled global equivalence groups and its user-defined groups in the
signed `account-state`/`ACCOUNT_SETTINGS` ([CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes),
[INV-14](../THREAT_MODEL.md#8-security-invariants)). [ADR 0038](0038-equivalent-domain-list.md)
§5 fixes the *shape* of a user-defined group (the signed global list's `group` record,
[§1](0038-equivalent-domain-list.md#1-list-format), minus the signature) and says it "lives in
`ACCOUNT_SETTINGS`". Neither ADR, CRYPTO.md, nor any code fixes the **bytes** of the
`ACCOUNT_SETTINGS` plaintext itself.

**What already exists (code read 2026-10-08).**
- `Purpose::AccountSettings = 0x0014`: symmetric, M1, **Unpadded** — no Padmé frame, so the AEAD
  plaintext is the content directly (`purpose.rs:183,288`). AAD is `account_id ‖ u64 settings_seq`
  (`AccountSettingsCtx`, `purpose.rs:734`).
- `rizzy_proto::objects::AccountSettings { settings_seq: u64, envelope }`, carried in
  `CommitChangeRequest.account_settings` next to a new `account_state` (`objects.rs:139,
  change.rs:81,110`).
- `AccountState` carries `settings_seq: u64` and `settings_hash = SHA-256(envelope)` (zero while
  `settings_seq = 0`); `AccountState::matches_settings` is the freshness check
  [INV-25](../THREAT_MODEL.md#8-security-invariants) already requires
  (`statements.rs:486-490,649-660`) — nothing new needed here.
- `rizzy-client` treats the plaintext as an **opaque blob**: `rotation::reencrypt_settings`
  decrypts and re-seals the same bytes on key rotation without inspecting them
  (`rotation.rs:1341-1380`); `store/load.rs:174-185` round-trips it through the local cache
  ([ADR 0026](0026-client-device-state-and-cache.md)) the same way. No reader or writer of the
  *content* exists anywhere, and the only test vector encrypts `random_vec(rng, 120)`
  (`test_vectors/envelopes.rs:174`) — the gap, committed.
- `rizzy-match` already has `EquivalenceGroup`, `GroupId`, `EquivalenceList`, `EquivalenceView`
  (`crates/rizzy-match/src/equivalence.rs`) and normalisation/PSL lookup (`normalize.rs`,
  `suffix.rs`) a user-defined group must reuse. `EquivalenceGroup::new` enforces 2..=64 distinct
  normalised domains but **does not** reject a domain that is itself a public suffix
  (`co.uk`) — nothing in the tree does.

Per [CLAUDE.md](../../CLAUDE.md), a persistent format needs an Accepted ADR before the M2 UI that
edits these settings can merge.

## Decision

### 1. Crate placement

- **Outer, generic record** (§2): `rizzy-client` (new `settings` module), the shared client core
  ([ADR 0013](0013-shared-client-core.md)) that already owns `AccountSettings` and plays this
  role for items ([ADR 0018](0018-item-record-encoding.md) §2). Reuses `rizzy_core::encoding`
  (`Reader`, `put_u8/u16/u32`, `bytes`/`str`, [CRYPTO.md §2](../CRYPTO.md#2-conventions)).
- **Matching payload** (§3): `rizzy-match`, next to `EquivalenceGroup`/`GroupId`/`EquivalenceView`,
  reused directly. `rizzy-client` already depends on `rizzy-match` for every match decision
  ([ADR 0037](0037-url-matching-and-autofill-rules.md) §1); no new dependency edge
  ([ADR 0016](0016-workspace-layout.md)). No new crate, no new crypto. Both modules stay no-I/O,
  wasm32-safe (ADR 0016 R1).

### 2. Outer record: versioned, tagged, extensible

```
account_settings_plaintext
  u16 format_version = 1
  u16 n ‖ n × entry            n ≤ 256 (MAX_SETTINGS_ENTRIES), sorted by tag, no duplicate tag
entry
  u16 tag
  bytes(value)                 u32(len) ‖ value; len ≤ MAX_SETTINGS_ENTRY_LEN (§4)
```

`format_version` is the *only* version field for this layout; it plays the same role
`item_schema_version` plays for items ([ADR 0018](0018-item-record-encoding.md) §11) and is not
given a second name anywhere in this ADR.

- **Absent object.** While `settings_seq = 0` there is no envelope; every setting reads as its
  default (§3), unchanged.
- **Tag registry.** `0x0000` invalid. `0x0001` = matching settings (§3). `0x0002`–`0xFFFE`
  unassigned — a new setting gets a line here by ADR amendment, **no version bump**, same
  pattern as [ADR 0018](0018-item-record-encoding.md) §7's field keys. `0xFFFF` reserved, never
  assigned.
- **Forward compatibility.** An unrecognised tag's `bytes(value)` is kept verbatim and re-emitted
  unchanged on the next whole-record write (§5); never dropped, never fails parsing because of it.
- **Rejected outright** (same severity as failed decryption): wrong/truncated lengths, trailing
  bytes, duplicate tag, `format_version ≠ 1` (parked and reported "update required", like an
  unknown `item_schema_version` — a forced update), or any violation inside a *recognised* tag
  (§3). There is no cross-device merge to fall back on (one account's own clients write this, not
  a vault), so a reject blocks further settings writes until resolved.

### 3. Tag `0x0001`: matching settings

```
matching_settings
  u16 match_default            ADR 0037 §4 enum, 0x0001..=0x0006 only (0x0000, 0x0007+ invalid)
  u16 d ‖ d × group_id (16 B)  disabled global ids, sorted, no duplicates, d ≤ 1,024
                                (MAX_DISABLED_GROUPS, new, independent of the list's own MAX_GROUPS)
  u16 u ‖ u × user_group       sorted by group_id, no duplicate group_id, u ≤ 64 (MAX_USER_GROUPS)
user_group                     ADR 0038 §1 "group", minus the signature (ADR 0038 §5)
  16  group_id                 random, client-assigned at creation, stable
  u16 m ‖ m × str(domain)       2 ≤ m ≤ 64 (MAX_GROUP_DOMAINS, reused), A-label, sorted, no dups
  u8  flag_third_party_hostable always 0x00 for a user group (§4)
```

- **Absent tag** = `match_default = 0x0001` (Base domain), no disabled groups, no user groups —
  the ADR 0037 §6 default.
- **Why `d ≤ 1,024`, not the list's `MAX_GROUPS` (4,096).** Reusing `MAX_GROUPS` as-is would let
  "disable every global group" alone (4,096 × 16 B = 65,536 B) consume the entire entry budget
  before a single user group is added — a one-click, entirely realistic action. `d` is capped
  independently, far above any global list ADR 0038 §4 point 6 ("small list, high bar") will
  plausibly ever reach, while leaving room in the entry (§4) for real user-group data.
- `user_group` reuses `EquivalenceGroup::encode`/`decode` as-is (`equivalence.rs:141-201`); no
  second codec for the same shape.
- `rizzy-client` builds `EquivalenceView::new(global, &disabled_set, &user_groups)` straight from
  the parsed tag, exactly as [ADR 0038](0038-equivalent-domain-list.md) §5 and
  [ADR 0037](0037-url-matching-and-autofill-rules.md) §7 already specify.

### 4. Validation on write, and size limits (new code)

- **Normalisation.** Every typed domain goes through `rizzy_match::normalize::normalize_domain`
  before `EquivalenceGroup::new` — the path the global list's own tooling uses, so a user group
  and a page's registrable domain compute identically.
- **Public suffix refused (gap closed; a validity floor, not a governance rule).** Before
  building a `user_group`, `rizzy_match::suffix` must confirm the normalised domain equals its own
  PSL registrable domain; a bare suffix (`co.uk`, `github.io`) is refused. This is a structural
  validity check — a bare suffix is not a "registrable domain" at all, the type `user_group`'s
  domains are declared to hold — not a reinstatement of [ADR 0038](0038-equivalent-domain-list.md)
  §4's *review process* (ownership proof, two-maintainer sign-off, scheduled re-checks), which §5
  already, and still, exempts user groups from. It does not supersede ADR 0038 §5 (see
  [On acceptance](#on-acceptance)). `flag_third_party_hostable` is forced to `0x00` for the same
  reason: that flag records a *reviewed* exception (ADR 0038 §4 point 3) no user group has.
- **Limits.** `MAX_SETTINGS_ENTRY_LEN = 1_048_576` (1 MiB, the same order of magnitude as ADR
  0038's own `MAX_LIST_LEN`), sized to hold `d`'s worst case (65,538 B, §3) comfortably alongside
  realistic user-group data — not the simultaneous theoretical maximum of every limit at once
  (`d` and `u` both maxed with maximum-length domains), which stays outside normal use and is not
  guaranteed to fit. `MAX_SETTINGS_ENTRIES = 256`, new in `rizzy-client`; `MAX_DISABLED_GROUPS =
  1,024` and `MAX_USER_GROUPS = 64`, new in `rizzy-match`; per-group domain count reuses
  `rizzy_match::error::MAX_GROUP_DOMAINS` (64), already defined for the signed list. The whole
  plaintext stays far under `rizzy-proto::limits::MAX_ENVELOPE_LEN` (16 MiB), unchanged.

### 5. Writing: whole-record replace, under the existing CAS

No new write mechanism. A settings change: (1) decrypt the current object (or start "absent" at
`settings_seq = 0`), parse per §2, keeping unrecognised tags untouched; (2) apply the edit to the
typed matching section and re-serialise the **whole** record — changed tag(s) plus every unknown
tag carried forward; (3) seal under the current account key at `settings_seq + 1`
(`AccountSettingsCtx` unchanged), compute `settings_hash = SHA-256(new envelope)`, submit a new
`account-state` (`state_seq + 1`) and the new `AccountSettings` in one `CommitChangeRequest` — the
same shape `reencrypt_settings`'s sibling already needs. (4) **Conflicts** use the existing
`account-state` CAS ([CRYPTO.md §10.2](../CRYPTO.md#102-ed25519-signatures-and-signed-statements),
`CasRetry`): only `state_seq`/`device_set_hash` differing is `Reapply`; `settings_seq` differing
is already `Restart` — no new case. **Rollback protection** is already
`matches_settings`/INV-25: an older, validly encrypted `ACCOUNT_SETTINGS` fails the hash check in
the `account-state` the client holds. This ADR gives the hashed bytes a meaning; it changes no
mechanism.

### 6. Reading

`rizzy-client` fetches `ACCOUNT_SETTINGS` exactly as today ([CRYPTO.md
§11.3](../CRYPTO.md#113-unlock-on-an-enrolled-device) step 2; the
[ADR 0026](0026-client-device-state-and-cache.md) cache, unchanged), decrypts and parses per §2
once, and exposes the match default and an `EquivalenceView` builder to `rizzy-match`. The web
vault and the extension both read through this one `rizzy-client` API, never the envelope
directly ([ADR 0037](0037-url-matching-and-autofill-rules.md) §1).

### 7. Migration

None. Every account's `settings_seq` is `0` today (no writer exists yet), so there is no legacy
plaintext. `format_version 1` is the first version any real account will hold.

### 8. Tests (new vectors)

Normative: an empty record; matching-only with no/with disabled-and-user groups; an unknown tag
preserved through decode→re-encode. Negative (one violation each): truncated entry, duplicate
tag, oversize entry, too many entries, duplicate `group_id`, a one-domain user group, a
public-suffix domain, `match_default` out of range, `flag = 1` in a user group, `format_version ≠
1` (parked, not rejected). Property: encode → decode → encode is the identity
([ADR 0018](0018-item-record-encoding.md) §12). The placeholder plaintext at `envelopes.rs:174`
is replaced by a real encoded record (see [On acceptance](#on-acceptance)).

## Consequences

### Positive
- `ACCOUNT_SETTINGS` content has a byte-exact meaning two client versions can agree on.
- Reuses every existing primitive (encoding helpers, `EquivalenceGroup`/`View`/PSL, the existing
  CAS and freshness mechanism) — no new crypto, wire object or crate.
- New settings join by tag, no version bump, no touch to this ADR's matching section.

### Negative
- `rizzy-client` gains a small hand-written codec beyond treating the plaintext as opaque.
- Whole-record replace means two concurrent edits race at the `account-state` CAS; the loser
  restarts and redoes its edit on the winner's full record — no field-level merge, unlike items.
- **The envelope is Unpadded (M1 choice, `purpose.rs:288`, unchanged here) and now carries a
  variable-length record.** Before this ADR the plaintext had no defined content, so this is the
  first point where envelope length correlates with something meaningful: roughly how many
  disabled/user groups the account has. The server already sees `settings_seq` and the ciphertext
  length; this adds a weak, coarse signal about equivalence-settings complexity, not which
  domains or group ids. See Open questions.

### Risks
- The public-suffix check depends on `rizzy-match`'s compiled-in PSL snapshot; a very new suffix
  might not be caught until the next release — the same residual risk ADR 0037 §3/AR-15 already
  accepts, not a new one.
- `MAX_USER_GROUPS`/`MAX_DISABLED_GROUPS` are judgement calls, not a UX study. Signal: users
  hitting them; raising either is not a version bump.

## Alternatives considered

- **ADR 0018's `(str field_key, bytes value)` item shape instead of numeric tags.** Rejected: no
  CRDT merge or history applies here; numeric tags are smaller and avoid item-style semantics.
- **JSON or another serde format.** Rejected for the reason ADR 0018 §1/ADR 0038 §1 give
  elsewhere: determinism should not depend on a serde crate version.
- **A separate envelope per setting category.** Rejected: multiplies the freshness/CAS surface
  THREAT_MODEL §5.3 treats as one risk; one envelope, one hash, one CAS is simpler.

## Open questions for the owner

1. **Settings-length side channel (Negative, above).** *Recommendation:* accept it, unchanged
   from the M1 Unpadded choice — the leaked signal (rough group count) is far weaker than what
   Unpadded already accepts for other settings-shaped purposes, and padding to fixed buckets is a
   bigger change than this ADR's scope. Revisit only if a future setting in this record is
   genuinely length-sensitive.
2. **`MAX_USER_GROUPS` / `MAX_DISABLED_GROUPS` / `MAX_SETTINGS_ENTRIES` values.**
   *Recommendation:* accept 64 / 1,024 / 256 (§3, §4); revisit with real usage.
3. **Error UX for a rejected public-suffix entry.** Implementation detail, not a security gate.
   *Recommendation:* defer to the M2 implementation PR.

## On acceptance

This ADR makes none of these edits. The owner makes them in the change that accepts it, following
the pattern of ADRs 0018 and 0038:

1. **No Accepted ADR is superseded, in whole or in part.** [ADR 0038](0038-equivalent-domain-list.md)
   §5's "owner's own risk; §4 applies only to the shipped global list" exempts user-defined groups
   from §4's *governance* process (ownership proof, two-maintainer review, scheduled re-checks).
   This ADR's public-suffix refusal and forced `flag_third_party_hostable = 0x00` (§4) are
   structural validity checks on what counts as a `user_group` at all, not a reinstatement of
   that review process — the same category of check `EquivalenceGroup::new` already applies to
   both global and user groups today (≥2 distinct domains). Like [ADR 0038](0038-equivalent-domain-list.md)
   itself did for [ADR 0016](0016-workspace-layout.md) §3, this is new ground filling a named gap,
   not a change to a decision.
2. **CRYPTO.md §8.4** gains a sentence naming this ADR for the `ACCOUNT_SETTINGS` plaintext
   layout, parallel to how [ADR 0018](0018-item-record-encoding.md) is named for `ITEM_OP`/
   `ITEM_SNAPSHOT` plaintexts.
3. **CRYPTO.md §15 item 1(A)** lists this ADR's vectors (§8). The committed vector at
   `crates/rizzy-core/src/test_vectors/envelopes.rs:174` is replaced: its plaintext changes from
   `random_vec(rng, 120)` to a real encoded `account_settings_plaintext`.

## References

- [ADR 0037](0037-url-matching-and-autofill-rules.md) §2, §4, §6, §7;
  [ADR 0038](0038-equivalent-domain-list.md) §1, §4, §5
- [ADR 0018](0018-item-record-encoding.md) §1, §2, §7, §10–§12 (canonical-layout, tag/field
  extensibility, size-limit and version-parking precedent)
- [ADR 0013](0013-shared-client-core.md), [ADR 0016](0016-workspace-layout.md) §3–§4,
  [ADR 0026](0026-client-device-state-and-cache.md)
- [CRYPTO.md](../CRYPTO.md) §2, [§8.4](../CRYPTO.md#84-aad-and-purposes),
  [§10.2](../CRYPTO.md#102-ed25519-signatures-and-signed-statements),
  [§11.3](../CRYPTO.md#113-unlock-on-an-enrolled-device), §11.6 step 3
- [THREAT_MODEL.md](../THREAT_MODEL.md) [A6](../THREAT_MODEL.md#a6-phishing-site-and-autofill-abuse),
  [§5.3](../THREAT_MODEL.md#53-unbound-items-and-settings),
  [INV-14, INV-25, INV-38, INV-39](../THREAT_MODEL.md#8-security-invariants)
- Code read 2026-10-08 (V): `rizzy-core/src/{envelope/purpose.rs, sign/statements.rs,
  test_vectors/envelopes.rs}`, `rizzy-proto/src/{objects,change}.rs`,
  `rizzy-client/src/{rotation,account,store/load}.rs`, `rizzy-match/src/{equivalence,error}.rs`
