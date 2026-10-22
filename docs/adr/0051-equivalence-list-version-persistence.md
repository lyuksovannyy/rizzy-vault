# ADR 0051: Persisting the highest accepted equivalence-list version

- Status: Accepted
- Date: 2026-10-11
- Deciders: project owner
- Milestone: M2

## Context

[ROADMAP §4.4](../ROADMAP.md#44-url-matching--autofill-m2), M2 Must: "Equivalent domain groups: curated global list ..., shipped with clients, versioned and signed." [ADR 0038](0038-equivalent-domain-list.md) §2 (Accepted) already requires the persistence this ADR adds: "Clients persist the highest `list_version` they have ever accepted ... and reject a list with an equal or lower version ([INV-39](../THREAT_MODEL.md#8-security-invariants))." No Accepted ADR gives that persistence a field, so the requirement is unimplemented. This is gap 27(b) of the M2 gap audit, under the ROADMAP §4.4 row above.

The gap is already named in code (V, HEAD 5a78bb5), `crates/rizzy-client/src/matching.rs`, `global_equivalence_groups`: it calls `rizzy_match::compiled::global_list(0)`, and its doc comment states: *"`highest_accepted_version` is always `0`. Persisting the caller's highest accepted `list_version` across launches (INV-39) is gap 27(b), which needs a new ADR: [ADR 0026]'s `cache_meta` format (Accepted) has no field for it, and CLAUDE.md requires an Accepted ADR for a persistent-format change."*

`rizzy_match::compiled::global_list` (`crates/rizzy-match/src/compiled.rs`), signature `pub fn global_list(highest_accepted_version: u32) -> Result<Option<EquivalenceList>, EquivalenceListError>`, and `EquivalenceList::verify` (`crates/rizzy-match/src/equivalence.rs`) already implement the check this field feeds: `verify` returns `EquivalenceListError::NotNewer` when `list.list_version <= highest_accepted_version`. Nothing here adds a construction; it supplies the one input that check has always needed and never had a durable source for.

[ADR 0026](0026-client-device-state-and-cache.md) §3 (Accepted) defines `cache_meta` as a `(k TEXT PRIMARY KEY, v BLOB NOT NULL)` table and enumerates exactly six keys in its schema comment: `format, server_origin, account_id, device_id, next_device_seq, hlc`. `crates/rizzy-client/src/store/rows.rs`'s `meta` module mirrors this as `meta::ALL`, a `[&str; 6]` array, and `crates/rizzy-client/src/store/load.rs` rejects a cache whose stored meta keys are not exactly that set ("Every key of this format, and no other"). Adding a seventh key is a persistent-format change under [CLAUDE.md](../../CLAUDE.md) "The ADR gate" and needs this ADR before it can be coded.

[ADR 0038](0038-equivalent-domain-list.md) §2 also fixes that the list "only ever arrives as build-time data reviewed in this repository's own release process": no runtime fetch, no server-supplied list. The no-downgrade check is therefore a property of one client build on one device, never a value the server asserts or that devices must agree on with each other.

This ADR is independent of [ADR 0042](0042-account-settings-matching-layout.md) (Proposed): that ADR's account-level equivalence overrides live in `ACCOUNT_SETTINGS` and are a different object, with different scope (per-account, server-synced, user policy), from the per-device floor this ADR persists.

## Decision

### What this ADR supersedes ([ADR 0020](0020-partial-supersession.md) point 9)

- **ADR 0026 §3**, the `cache_meta` table's definition line, quoted word for word: `cache_meta(k TEXT PRIMARY KEY, v BLOB NOT NULL)` -- format, server_origin, account_id, device_id, next_device_seq, hlc. Replaced in full by: `cache_meta(k TEXT PRIMARY KEY, v BLOB NOT NULL)` -- format, server_origin, account_id, device_id, next_device_seq, hlc, highest_equivalence_list_version. Nothing else in ADR 0026 is touched; it stays binding, including §2's device-state record and §5's "`cache_meta.format` = `u16` 1" (point 2 below), which this ADR does not supersede.

### 1. A new `cache_meta` key

`highest_equivalence_list_version`: the `u32` `list_version` ([ADR 0038](0038-equivalent-domain-list.md) §1), stored zero-extended as an 8-byte big-endian `BLOB`, decoded through the shared `u64_be` helper `crates/rizzy-client/src/store/floors.rs` already uses for `next_device_seq` and `hlc` — this key reuses that decode path rather than adding a narrower 4-byte one. The `u32::MAX` range check runs in the two places that touch this field: **`Floors::of_rows`** (`floors.rs:190-248`, the function that rehydrates `Floors` from a loaded cache's rows), which rejects a stored value above `u32::MAX` as `ClientError::CacheCorrupt`, same as its existing checks of `NEXT_DEVICE_SEQ`/`HLC`; and **`Pending::meta`**'s new match arm, which refuses a write above `u32::MAX` as `Refused`, same shape as its `HLC` arm. `crates/rizzy-client/src/store/rows.rs`'s `meta` module gains the constant and adds it to `meta::ALL` (now 7 entries); `load.rs`'s exact-key-set check and `mod.rs`'s `create_writes` both follow from that one change, writing `0` for a freshly created cache. **`Floors::of_rows` (`floors.rs:190-248`) gains a line reading this key from `rows.meta`, right beside the existing lines that set `floors.next_device_seq` (line 202) and `floors.hlc` (line 203)** — without this, the in-memory floor would reset to `0` on every process restart regardless of what is stored, and the very first write after a restart would be checked against `0` instead of the true floor, reproducing the downgrade INV-39 and this ADR exist to prevent. `floors.rs`'s `Floors` struct gains a `highest_equivalence_list_version: u64` field beside `next_device_seq` and `hlc` (widened for storage, range-checked to `u32` at the two points above), and `Pending::meta`'s key match gains one arm with the same shape as `meta::HLC`'s: refuse a changeset that would lower it or exceed `u32::MAX`, otherwise store it. This is `floors.rs`'s existing "never goes backwards" machinery picking up one more field, not a new mechanism — but only once `of_rows` is changed along with it, which is this point's own fix.

### 2. Cache format 2

`cache_meta.format` becomes `2`. [ADR 0026](0026-client-device-state-and-cache.md) §5's sentence "`cache_meta.format` = `u16` 1" names the format at that ADR's acceptance; its very next sentence ("Migrations are ordered SQL steps in `rizzy-client`, each run in one transaction with the format bump") already provides the generic bump mechanism this uses, so moving to format 2 is that machinery operating on the schema change this ADR adds, not a change to what §5 decided — no supersession of §5 is needed. The format-1 → format-2 migration adds the row with value `0` in the same transaction as the format bump; it reads, re-parses or re-encrypts nothing else, since the new value is never secret and has no relationship to any existing row.

### 3. When the value changes

A client writes this key only in the transaction of the host step named in point 4 (the same one that, per ADR 0026 §4 step 5, already loads the cache and populates `Floors::of_rows`), and only when that step's call to `global_equivalence_groups` (point 4) returns `Some(new_version)`. The write is admitted by `floors.rs`'s all-or-nothing check (point 1) before the host commits it — correctly, because `Floors::of_rows` is now rehydrating this field from the stored row (point 1's fix); without that fix the floor compared against would always be `0`, not the true stored value. On `Err` (bad signature, malformed, wrong key, or `NotNewer`) or on `Ok(None)` (no list compiled in), `global_equivalence_groups` returns `None` and the stored value is untouched. The value is never set from anything the server sends, never lowered, and never written outside this one path. **This makes `NotNewer` reachable where it is dead today:** once a list has shipped, installing or rolling back to a build whose compiled-in `GLOBAL_LIST` is older than the stored floor narrows matching to plain registrable-domain equality for that install, silently, until a newer build ships. That is the intended effect of the no-downgrade rule, not a bug this ADR introduces; whether it also needs a user-visible notice is the implementer's call under ADR 0037, not this ADR's.

### 4. When the value is read, and the mechanism that writes it

`rizzy_match::compiled::global_list` and `rizzy-client` (which re-exports this call as `global_equivalence_groups`) are both no-I/O under [ADR 0016](0016-workspace-layout.md) R1: neither can itself read a `cache_meta` row or emit a write. `global_equivalence_groups`'s signature changes from today's `pub fn global_equivalence_groups() -> Vec<EquivalenceGroup>` to:

```
pub fn global_equivalence_groups(
    highest_accepted_version: u32,
) -> (Vec<EquivalenceGroup>, Option<u32>)
```

It returns the groups (as today, `vec![]` when none is compiled in or verification fails) plus, only when `global_list(highest_accepted_version)` returns `Ok(Some(list))` whose `list.list_version()` is strictly greater than the input, `Some(list.list_version())` as the new floor for the host to persist (point 3); every other case returns `None` in the second slot. `EquivalenceList::list_version()` is not new: it already exists as a public, documented accessor (`crates/rizzy-match/src/equivalence.rs:253-257`, `#[must_use] pub const fn list_version(&self) -> u32`) and is already exercised by its own known-answer test (`equivalence.rs:605`) and by `xtask`'s key-rotation test (`crates/xtask/src/equivalence_list.rs:193`); `global_equivalence_groups` is simply its first production caller, not a new reader this ADR adds.

**The call site moves out of the per-decision hot path.** Today's only caller, `rizzy-wasm`'s `decide_match_candidates` (`crates/rizzy-wasm/src/matching.rs:271`), runs once per autofill decision on a per-page-visit path with no ADR-0026 write transaction in scope; calling the new signature there would mean a `cache_meta` read and a candidate write on every page visit. Instead, a host (the M2 extension's background/service-worker context, `rv`, or a future native leaf) calls `global_equivalence_groups` exactly once, at session or process startup, inside the same transaction that ADR 0026 §4 step 5 already opens to load the cache: it reads the stored floor via `Floors::next_device_seq`-style accessor (a new `Floors::highest_equivalence_list_version()`), calls `global_equivalence_groups`, and folds a returned `Some(new_version)` into that load transaction as one more `Write::Meta` before it commits (point 3). The resulting `Vec<EquivalenceGroup>` is cached in memory for the life of that session/process and passed into every later `decide_candidates`/`decide_match_candidates` call instead of being recomputed per decision — sound because a running process's compiled-in list cannot change mid-session. `decide_match_candidates` stops calling `global_equivalence_groups` itself; it takes the already-computed `global` slice as an added parameter. Exactly which host entry point performs this per leaf (the extension's service-worker startup, `rv`'s process startup, a future leaf's init) is left to the implementer; see Open questions.

### 5. Scope: local, not synced, one floor per account, none for the web vault

The value lives only in `cache_meta`, one row per local cache file, never in `account-state` or `ACCOUNT_SETTINGS`, and is never carried in any request or response. [ADR 0026](0026-client-device-state-and-cache.md) §3 is one SQLite file per account, so a device enrolled in several accounts holds one independent floor per account file; nothing here adds cross-account state. Each device tracks its own highest accepted version, because each device verifies its own compiled-in list from its own build; a newer client build on one device must be free to raise that device's floor without moving any other device's, and nothing here gives the server a value to tamper with. This is the opposite shape from `account-state`'s `settings_seq` ([INV-25](../THREAT_MODEL.md#8-security-invariants)), a single signed floor every device must agree on; conflating the two would be wrong on both sides. The web vault (`device_kind` 4) keeps no cache at all ([ADR 0026](0026-client-device-state-and-cache.md) §3, "The web vault keeps no cache"), so it has no field to hold this floor and re-verifies the server-served page's compiled-in list fresh every session, always from `highest_accepted_version = 0`. That is an existing gap this ADR does not widen or close: a web session that cannot keep any state between visits already trusts the server-delivered code each time ([AR-1](../THREAT_MODEL.md#9-accepted-risks-and-out-of-scope)), and a one-session equivalence-list floor would add no protection against the same server that could simply serve different code.

### Proposed invariant

No CRYPTO.md change: this reuses the `equivalence-list` signed statement and the `EquivalenceList::verify` check [CRYPTO.md §10.2](../CRYPTO.md#102-ed25519-signatures-and-signed-statements) and [ADR 0038](0038-equivalent-domain-list.md) §2 already define; no floor, parameter or construction moves. [THREAT_MODEL.md](../THREAT_MODEL.md) gains, at acceptance, the pattern [ADR 0038](0038-equivalent-domain-list.md) used for CRYPTO.md:

> **Proposed INV-75** (allocated across the 2026-10-11 batch in ADR-number order. Provisional: the allocation was made across the 2026-10-11 batch in ADR-number order; if ADRs are accepted out of order, the owner renumbers at acceptance.). A client's persisted `highest_equivalence_list_version` never decreases, and changes only immediately after that same client verifies, under INV-39, a global equivalence list whose `list_version` exceeds the stored value. A crash between verifying a list and persisting the new value causes at most a harmless re-verification of the same list on the next load, never acceptance of an older one.

### Owner answers at acceptance (2026-10-22)

The owner accepted this ADR as drafted; the recommendations of "Open questions for the owner" stand:

1. INV-75 keeps its number.
2. Cache format 2 is a mandatory migration (point 2), not an optional key that is zero when absent.
3. The extension's IndexedDB store and any native leaf use the same key name and encoding (ADR 0026 §3). No separate decision is needed.
4. The implementer names each leaf's host entry point in the PR that wires point 4. It needs no ADR.

Of the "On acceptance" edits, ADR 0026's status line, its index row and INV-75 (THREAT_MODEL.md §8.6) are made in the accepting change. CLAUDE.md's status sentence was already brought up to date by the owner's status change (24812c8).

## Consequences

### Positive

- Closes ROADMAP gap 27(b) and the gap `matching.rs`'s own doc comment already names; INV-39's no-downgrade rule becomes enforceable across restarts instead of only within one process (today a no-op, since `GLOBAL_LIST` is `None` and `highest_accepted_version` is always `0`; load-bearing the moment a real list ships).
- One additive `cache_meta` row, read and written at one well-defined point (startup, inside the existing load transaction), not on the autofill hot path. No change to the device-state record's wire format, no new crypto construction, no CRYPTO.md edit.
- Same local-device scope as the SK, `device_salt` and the rest of §1's "device-only" data: no new server-visible metadata.

### Negative

- Every existing format-1 cache runs one more migration step before this ADR's protection takes effect.
- `global_equivalence_groups` gains a second return value and a caller-visible "when to call it" contract (once at startup, not per decision) instead of being a trivial getter; every leaf's startup path has to be taught this, and `decide_match_candidates`'s signature grows a parameter.
- The extension (IndexedDB, M2) and any future native leaf (`rizzy-ffi`, M3) each implement the same key, the same startup call site shape, and the same write-only-on-verified-increase rule — the duplication ADR 0026 §3 already accepts for "two sqlx executors."

### Risks

- If a future out-of-band list-update channel ships ([ADR 0038](0038-equivalent-domain-list.md) §2 Alternatives, deferred), it writes through the same field and the same rule; nothing here blocks or needs to anticipate it further.
- A restored-from-backup cache (an older copy, [ADR 0026](0026-client-device-state-and-cache.md) §4 step 7, open question 5) carries an older `highest_equivalence_list_version`, which only ever makes the check more permissive for that device, never less; the same direction every other floor in that open question moves, and no worse.
- Moving the call to session/process startup means a list shipped in a build that never restarts (a long-lived service worker, a desktop app left open) is not picked up until the next restart; this is the same staleness every other compiled-in constant in that process already has, not a new risk this ADR introduces.

## Alternatives considered

- **Store it in the device-state record (§2) instead**, bumping `record_version` to 2. Rejected: that record is the tightly parsed, 4096-byte-capped, cryptographically sensitive blob (SK, `device_salt`, `E_dev`, `E_local`), and its one reserved version bump is already spoken for by `E_ks`/`ACCOUNT_KEY_FORWARD` (M3, ADR 0026 §2 "Not in v1"; the record-version-2 ADR for this is a sibling of this batch, not duplicated here). A public, non-secret monotonic counter belongs with `next_device_seq` and `hlc`, which already live in `cache_meta` for exactly this reason.
- **A synced field in `account-state` or `ACCOUNT_SETTINGS`.** Rejected: the check is a per-device property over client-compiled data the server never serves ([ADR 0038](0038-equivalent-domain-list.md) §2); syncing it would let one device's floor move another's, the wrong semantics, and would add a value to signed server state that buys no security benefit.
- **Leave it unpersisted (today's status quo).** Rejected: reopens exactly the downgrade [ADR 0038](0038-equivalent-domain-list.md) §2 and INV-39 require closed. Harmless only while no signed list has shipped.
- **A dedicated new table instead of `cache_meta`.** Rejected: `cache_meta` already exists for one-row scalar per-account counters; a new table would duplicate that pattern for a single `u32`.
- **Call `global_equivalence_groups` per autofill decision, as today, and have the wasm binding open its own transaction.** Rejected: `rizzy-wasm` and `rizzy-client` are no-I/O (ADR 0016 R1), so the host would still need a transaction per decision at the JS/native layer, turning every page visit into a write path for a value that only ever changes once per shipped build.

## Open questions for the owner

1. **The INV id.** Resolved: allocated as INV-75, the batch's proposed INV ids reconciled in ADR-number order; confirm at acceptance in case an ADR lands out of order.
2. **Mandatory migration versus an optional, absent-means-zero key.** *Recommendation:* the mandatory format-2 migration of point 2, not a silently-absent key: it keeps `store::load`'s "every key of this format, and no other" check exact and avoids a column whose presence depends on history.
3. **Extension and future-leaf parity.** *Recommendation:* the IndexedDB store (M2) and any native leaf (M3) use the identical key name and encoding; ADR 0026 §3 already requires "the same logical stores, keyed identically," so this needs no separate decision, only a note so the M2 extension work does not diverge from it.
4. **Which concrete host entry point, per leaf, calls `global_equivalence_groups` and performs the fold-in write (point 4).** This ADR fixes the shape — once, at startup, inside the existing load transaction — but not the exact call site in the extension's service worker, `rv`'s startup path, or a future native leaf's init. *Recommendation:* the implementer names it in the PR that wires point 4 for each leaf; it does not need its own ADR, since it is an implementation detail of a decision this ADR already makes.

## On acceptance

This ADR makes none of these edits. The owner makes them in the change that accepts it, following the pattern of ADRs 0038 and 0044:

- **ADR 0026**'s status line: append `; Partially superseded by [ADR 0051](0051-equivalence-list-version-persistence.md) (§3 in part)` to whatever that line reads at the moment of acceptance ([ADR 0020](0020-partial-supersession.md) point 9's semicolon-separated accumulation), never overwrite it outright. [ADR 0046](0046-recovery-pending-device-stage.md) (M1, Proposed, same batch) separately partially supersedes ADR 0026 §2 and a different sentence of §3; [ADR 0057](0057-device-state-v2-keystore.md) (M3, Proposed, same batch; the device-state record's own `record_version` bump, see Alternatives) separately partially supersedes §1 and §4 step 5. Whichever of this ADR, ADR 0046 and ADR 0057 lands last on an overlapping part must append to the others' entries on that line, in order of acceptance, not replace them.
- **[docs/adr/README.md](README.md)**: row 0026's Status cell updates to match; row 0051's Status → Accepted.
- **[THREAT_MODEL.md](../THREAT_MODEL.md)** §8.6 gains the invariant of "Proposed invariant" above, as INV-75, next to INV-36 to INV-39.
- **[CLAUDE.md](../../CLAUDE.md)**: the "As of" sentence is brought up to date.

## References

- [ADR 0026](0026-client-device-state-and-cache.md) §1, §2, §3, §4, §5 (device-state and cache; Accepted)
- [ADR 0038](0038-equivalent-domain-list.md) §1, §2, §3 (equivalence-list format, signing, distribution; Accepted)
- [ADR 0020](0020-partial-supersession.md) point 9 (partial supersession)
- [ADR 0042](0042-account-settings-matching-layout.md) (Proposed; independent, referenced only)
- [ADR 0046](0046-recovery-pending-device-stage.md) (M1, Proposed; this batch's sibling also partially superseding ADR 0026 §2 and a different sentence of §3); [ADR 0057](0057-device-state-v2-keystore.md) (M3, Proposed; this batch's sibling owning the device-state record's own version bump, not duplicated here)
- [THREAT_MODEL.md](../THREAT_MODEL.md) [INV-25, INV-39](../THREAT_MODEL.md#8-security-invariants), [AR-1](../THREAT_MODEL.md#9-accepted-risks-and-out-of-scope)
- [CRYPTO.md](../CRYPTO.md) [§2](../CRYPTO.md#2-conventions), [§10.2](../CRYPTO.md#102-ed25519-signatures-and-signed-statements)
- [ROADMAP.md](../ROADMAP.md) [§4.4](../ROADMAP.md#44-url-matching--autofill-m2)
- Code read 2026-10-11 (V), HEAD 5a78bb5: `crates/rizzy-client/src/matching.rs`; `crates/rizzy-client/src/store/{mod,rows,load,floors}.rs`; `crates/rizzy-match/src/{compiled,equivalence,error}.rs`; `crates/rizzy-wasm/src/matching.rs`; `crates/xtask/src/equivalence_list.rs`
