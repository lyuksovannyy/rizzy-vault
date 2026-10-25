# ADR 0109: Sync cursor past a held header: derived, never stored, rewound on lapse (erratum to ADR 0050)

- Status: Proposed
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M1
- Supersedes: [ADR 0050](0050-paged-fetch-tombstone-boundary.md) §2, last paragraph ("A held claim lives only…"), and [ADR 0012](0012-sync-engine.md) §7 "Fetch", first sentence, on acceptance. Nothing else.

## Context

The owner said "start" on 2026-10-25, after the ADR gap review ([2026-10-25 gap review](../reviews/2026-10-25-adr-gap-review.md)), and this ADR is one of the drafts that instruction triggered. It answers review row **D9** ("ADR 0050: the sync cursor advances past a held header, with no rule for falling back when the hold lapses or is lost on restart; possibly a permanent stall (not confirmed)"), raw finding **G05-21** [major] in [G05.md](../reviews/2026-10-25-raw/G05.md):

> Evidence: §2: "so that the chain's head and cursor advance past it instead of the walk ending in `Report::Gap`"; line 40: "A process restart before the hold resolves drops it: the next Fetch starts a fresh sequence from whatever cursor was last persisted."
>
> Why it is a gap: The Fetch cursor (ADR 0012 §7) is what the server serves from. If the advanced cursor is used (or persisted, ADR 0026) after a lapse or a mid-sequence restart, the bodiless header and its cover are never served again, so the held dot never settles and everything causally after it waits forever […]. The code adds an unstated rule (on lapse "the cursor entry drops below the first of them"); the ADR is silent on the rewind and on whether a persisted cursor may ever include a held link, so a second implementer can build the permanent-stall version.

The Accepted texts involved:

- [ADR 0012](0012-sync-engine.md) §7 "Fetch": *"A device sends its cursor: the highest `device_seq` it has per device, per vault."* It does not say what "has" means for a link that is accepted but not settled (a rejected-body link, or ADR 0050's held link), and it does not say whether the cursor is stored.
- [ADR 0050](0050-paged-fetch-tombstone-boundary.md) §2 (Accepted 2026-10-22): the held header "joins its device's chain as a link, […] so that the chain's head and cursor advance past it instead of the walk ending in `Report::Gap`", and *"A held claim lives only in the running `VaultSync` for the life of the current response sequence; ADR 0026's cache gains no new row. A process restart before the hold resolves drops it: the next Fetch starts a fresh sequence from whatever cursor was last persisted. Open question 1 covers the residual loss this can leave."* Its owner answer 1: "A held tombstone claim is not persisted across a restart: its loss is a known M1 limit, to revisit with M3 telemetry."
- [ADR 0026](0026-client-device-state-and-cache.md) §4 "What never goes backwards": no transaction may delete an `ops` row or replace its statement, "so each cursor and item-VV entry, recomputed from the held headers, only grows".

"Whatever cursor was last persisted" reads as if a cursor value were stored. That is the gap: if one is stored, and it is the value sent mid-sequence, it is above the held header, and the server (which serves "every op header after the cursor", ADR 0012 §7) never serves that header or its cover again.

### Verification: is the stall real?

Read at `f3492b2` (branch `wip/adr-0109`), 2026-10-25. All V (code and tests read, and a probe run).

1. **No cursor is stored anywhere.** The client's Fetch cursor is computed on every request: `VaultSync::cursor` (`crates/rizzy-client/src/sync.rs`, around line 847) maps `VaultLog::cursor` (`crates/rizzy-sync/src/causal.rs`, around line 741), which is computed from the in-memory chains. The cache rows (`crates/rizzy-client/src/store/rows.rs`) have no cursor column. The server does not record client cursors either (`crates/rizzy-domain-vault/src/lib.rs` line 102: "Per-device cursors […] are not recorded"; `rotation.rs` line 39: "The cursor is not stored").
2. **The cursor rule in code** (`VaultLog::cursor_entry`, causal.rs around line 749): a chain's entry is its head, unless some link at or after the chain's delivery frontier is in a "serve again" state (`LinkState::Rejected` or `LinkState::Lapsed`, `serves_again`, line 634) and its item's settled VV does not cover it; then it is that link's `vault_prev_seq`. A `LinkState::Held` link does not lower it ("A held link does not stop it", module docs line 92).
3. **Lapse rewinds in memory.** `VaultLog::end_holds` and `VaultLog::release_hold` turn a `Held` link not covered by then into `Lapsed` (causal.rs lines 986–988), so by point 2 the entry drops to just below the first of them, and the next Fetch serves it again with a cover. Module docs lines 132–136 say so.
4. **What is persisted during a hold.** Every accepted header, the held bodiless one included, is journaled as an `ops` row (`Write::PutOp`, sync.rs lines 1246–1253). A cover is journaled (`Write::PutSnapshot`) only when absorbed; a held cover goes to the in-memory `pending_covers` only (`keep_covers`, sync.rs lines 1535–1558). A held cover taken on a retry is journaled then.
5. **What a load computes.** `VaultSync::restore` replays the persisted served rows, with the persisted covers only, through `settle(…, complete = true, …)` (sync.rs lines 2852–2855). The held cover is not among them, so the held bodiless header is again an ordinary uncovered bodiless header: the chain walk ends before it, and the loaded cursor entry is the link before it.
6. **Existing test.** `tests::store::a_held_cover_is_not_persisted_and_a_taken_one_is` (`crates/rizzy-client/src/tests/store.rs` line 836): on a server paging two ops at a time, the live device's cursor for the writer is 2 with one held cover, and the reloaded device's is 0 ("A restart now loses the hold: the loaded device's cursor is before the held headers"). The test then continues with the *live* device only; it does not drive the reloaded one.
7. **Probe** (two throw-away tests added to `store.rs`, run with `cargo test -p rizzy-client --locked --lib`, both passed, then removed; not committed). (a) The reloaded device of point 6, fetching on, against the same compacting two-op-page server: page 1 cursor 2 with one held cover, page 2 cursor 3, cover absorbed, no reports, item Purged, and the cache loads to the live state. (b) A device reloaded after *every* page: for 8 pages the cursor went 2 before each restart and 0 after it, every time; no report, no wrong lifecycle, no refused write, and no progress.

**Verdict.** The permanent stall G05-21 describes is **not real in the current code**: a restart cannot leave a cursor above a held header, because no cursor is stored and the one a load computes treats the held header as the gap it is without its cover. The rule is real but stated only in code comments: ADR 0050 §2 says the cursor advances past a held link and never says when it comes back, and its last paragraph's "whatever cursor was last persisted" invites an implementer (a second client, a binding that caches the cursor for a faster cold start, a server that records cursors) to persist the sent value, which is exactly the stall. Probe (b) shows the separate, already-accepted limit of ADR 0050 owner answer 1: a device that restarts between every page never gets past a held header. That is a liveness limit, not a stall of stored state: the first uninterrupted response sequence from the cover's page to the page holding the recorded purge settles it.

So this ADR writes the code's rule down as a normative clarification. It changes no code, no wire format, no persistent format and no invariant.

## Decision

### 1. What this ADR supersedes

Under [ADR 0020](0020-partial-supersession.md) point 9, this ADR supersedes exactly two parts, quoted in full. Everything else in ADR 0050 and ADR 0012 stays binding.

- **ADR 0050 §2, last paragraph:** *"A held claim lives only in the running `VaultSync` for the life of the current response sequence; ADR 0026's cache gains no new row. A process restart before the hold resolves drops it: the next Fetch starts a fresh sequence from whatever cursor was last persisted. Open question 1 covers the residual loss this can leave."*

  Replaced by:

  "A held claim lives only in the running `VaultSync` for the life of the current response sequence; ADR 0026's cache gains no new row, and no persisted form records a hold, a held cover, a held or lapsed link state, or a cursor. While a hold is open, the cursor sent with the next page's Fetch passes the held link (so the sequence can reach the recorded purge); every other use of a cursor, and every cursor after a lapse or a load, does not. A hold lapses when the merge releases it for any reason other than a dominating absorbed cover, when the client gives it up under a cap, when the response sequence completes with it unresolved, or when a revocation rejects the link; at a lapse the chain's cursor entry falls to the `vault_prev_seq` of its first lapsed or rejected link that no settled snapshot covers, so the next Fetch, of the same sequence or a new one, serves that header and a cover again. A process restart, a lock, or anything else that rebuilds the `VaultSync` from the cache drops every open hold: the load recomputes the cursor from the persisted rows with only the persisted covers, so a header that only a held cover covered is an ordinary gap again and the cursor stops before it. The rules, the crash cases and the tests are in [ADR 0109](0109-sync-cursor-held-header.md) §2–§5; ADR 0050 open question 1 and its owner answer cover the residual loss (a device that restarts between every page never passes the held header)."

- **ADR 0012 §7 "Fetch", first sentence:** *"A device sends its cursor: the highest `device_seq` it has per device, per vault."*

  Replaced by:

  "A device sends its cursor: per device, per vault, one `device_seq`. It is the chain's head (the newest header linked into the chain; a link held under [ADR 0050](0050-paged-fetch-tombstone-boundary.md) §2 does not lower it, and only the next page of its own response sequence may carry a cursor past it), unless a link at or after the first undelivered one has a rejected body or a lapsed hold and its item's settled version vector does not cover it, in which case it is that link's `vault_prev_seq`, so the server serves the link again. The cursor is derived from the replica's chain state on every request and is never stored, on the client or the server ([ADR 0109](0109-sync-cursor-held-header.md) §2)."

  The three sub-bullets of that bullet ("It receives every op header after the cursor…", the compacted-body sub-bullet as ADR 0021 left it, and the wrap-set sub-bullet) are untouched.

### 2. The cursor rules

Terms: a chain, link, head, frontier and settled VV are as in `rizzy_sync::causal` and ADR 0012 §7. A link is **held** (ADR 0050 §2) while only a held cover covers it, **lapsed** once that hold ended unresolved, **rejected** when its body failed verification after it was accepted (ADR 0012 §4 step 1). A **response sequence** is every Fetch call from one up to and including the first page with `complete = true` (ADR 0050 §2).

- **C1, the entry.** For each chain, the cursor entry is `head`, unless there is a link L with `seq ≥ frontier` whose state is rejected or lapsed and whose dot the settled VV of its item does not cover; then it is `L.vault_prev_seq` for the first such L in chain order. A held link never lowers the entry. The cursor is the vector of all entries, the own device's included (unchanged from the code).
- **C2, derived, never stored.** The cursor is computed from C1 each time it is needed. No cache row, column, file, keychain entry, binding-side store or server table may hold a client's cursor value, or a hold, a held cover, or a held or lapsed state. A change to that is a persistent-format change and needs its own ADR (CLAUDE.md "The ADR gate"), which must keep C4.
- **C3, lapse.** A held link becomes lapsed, in memory, at the first of: the merge releasing the hold for a reason other than a dominating absorbed cover ("moot": a dominating cover settles the link, so it is no longer uncovered); a refusal of the retried cover for any reason other than `PurgeAboveCut`; the client declining a hold under a cap (today `rizzy_sync::causal::MAX_HELD_ITEMS` = 256 items, a code value not fixed by any ADR, review G05-22); the end of the response sequence with the hold unresolved (`VaultLog::end_holds` before `complete_fetch_reports`). A held link past a learned revocation cut-off is rejected instead (C1 treats both alike). By C1, the next Fetch after a lapse, whether the next page of the same sequence or a new sequence, carries an entry below the first lapsed link.
- **C4, load.** Loading a vault from the cache (ADR 0026 §4) replays the persisted served `ops` rows and the persisted absorbed covers, as one complete response (`complete = true`). No hold survives it, and no held cover is among its inputs. So, for every chain, the loaded cursor entry is at or below the `vault_prev_seq` of every persisted bodiless header (or rejected-body header) that no persisted cover covers. ADR 0026 §4's "each cursor […] entry, recomputed from the held headers, only grows" is read as a statement about this loaded cursor across committed transactions; the cursor sent during a sequence with an open hold may be above it, and that is not a breach of ADR 0026's floors.
- **C5, uses of the cursor while a hold is open.** Only the next page's Fetch request of the same response sequence may carry a cursor that passes a held link. A rotation half (`VaultSync` rotation, ADR 0012 §7 "The same cut-off applies to every rotation") and a healing request (ADR 0021 §9 "Healing request", "up to the device's cursor") are built only when no hold is open: the rotation path already refuses with `ClientError::SyncRequired` unless the last page was complete (V, sync.rs around line 2462); the healing request refuses with the existing `ClientError::FetchRequired` while a hold is open (whether the code already does is U, see §5 step 2). No new error code.
- **C6, the server.** The server serves a Fetch from the cursor in the request alone (ADR 0021 §4) and keeps no per-client cursor that could stand in for it. This is the current code (V, point 1) and adds no server work.

### 3. Crash and retry cases

Each case's expected outcome is binding; the tests of §5 check each.

| Crash point | Persisted afterwards | Next load and Fetch |
|---|---|---|
| Before the page with the cover is committed (the host's ADR 0026 §4 transaction for that step not done) | Nothing of that page | Cursor as before the page; the page is served again. |
| After the page with the held cover is committed, before the page with the recorded purge | The held bodiless header and every other accepted header of the page as `ops` rows; not the held cover | C4: the cursor stops before the held header; the next sequence serves it and a fresh cover again (probe 7a: settled after 2 pages). |
| After the page in which a retry took the held cover is committed | The purge's header and the taken cover (`PutSnapshot`) in the same step's changeset | The cover is a persisted absorbed cover; the load settles the link; the cursor passes it. |
| After a complete page with the hold unresolved (lapsed, gap reported) | As in row 2 | As in row 2; the gap is reported again at the end of the next sequence if the purge is still not served (for example a revoked author past its cut-off, ADR 0050 §4 regression case). |
| A restart after every page | As in row 2, page after page | No progress past the held header (probe 7b), no wrong state. ADR 0050 owner answer 1 accepts this as an M1 limit. |

A retry needs nothing from the client beyond a normal Fetch: the server's answer is a function of the request's cursor (C6), and every persisted row the server serves again is already held byte for byte, which `put_op` accepts as a no-op (`crates/rizzy-client/src/store/floors.rs` around line 706, V).

### 4. Formats, limits, error codes

No wire format, persistent format, version byte, error code, limit, invariant or setting is added or changed. INV-27 and proposed INV-74 (ADR 0050) are unchanged; C1–C6 are mechanism rules under them. No migration. `MAX_HELD_ITEMS` is not fixed here (G05-22 is a separate finding).

### 5. Implementation plan

Docs-only today. After acceptance, as one test-and-guard change (no new dependency; `proptest` is already a dev-dependency of both crates, V: `Cargo.toml` line 154, `crates/rizzy-sync/Cargo.toml` line 18, `crates/rizzy-client/Cargo.toml` line 34):

1. **Unit tests in `rizzy_sync::causal`:** C1 for each state: a held link does not lower the entry; the same link after `end_holds` and after `release_hold` lowers it to its `vault_prev_seq`; a lapsed link that a later absorbed cover covers no longer lowers it; two lapsed links in one chain give the first one's `vault_prev_seq`; a held link past a learned cut-off lowers it as rejected.
2. **Healing guard (C5):** check whether `VaultSync::healing_request` (`crates/rizzy-client/src/sync/heal.rs`) can be built while `pending_covers` is not empty; if it can, return `ClientError::FetchRequired` then, with a test.
3. **Restart tests in `rizzy-client`** (`src/tests/store.rs`): extend `a_held_cover_is_not_persisted_and_a_taken_one_is` to drive the reloaded device to `ItemLifecycle::Purged` and `assert_loads` (probe 7a), and add the restart-after-every-page case (probe 7b) asserting no progress, no reports before `complete`, and the item never shown in a state it does not have.
4. **Property test with injected restarts** (`rizzy-client`, proptest, the fake server of `src/tests`): generated histories of one to three writer devices, with purges and edits, uploaded and compacted; a reader fetching with a page length drawn from 1–4 ops; after each page, with a drawn probability, the reader is rebuilt from the cache rows (`load::load`); at most a drawn bound k of restarts, after which pages run uninterrupted. Properties: (P1) after every load, for every chain, the loaded cursor entry is at or below the `vault_prev_seq` of every persisted bodiless header no persisted cover covers (C4); (P2) after every page, the cursor the next request carries passes a link only if that link is settled or held (C1); (P3) once restarts stop, the reader converges to the writers' state within a bounded number of sequences (ADR 0012 §12 property 1); (P4) a dot is never reported as a gap at the end of a sequence that delivered its recorded purge (ADR 0050 INV-74); (P5) every cache file after every step loads (ADR 0026 §6 crash assertions).
5. **Server side:** a `rizzy-domain-vault` test that two identical Fetch requests from the same device, with a restart-sized gap between them, get identical pages (C6).

Each step runs under the workspace's normal gate (CLAUDE.md "Before any push").

## Consequences

- An implementer of a second client, a binding or a server has one written rule: the cursor is derived, never stored, passes a held link only for the next page of its own sequence, and falls back at a lapse or a load. The permanent-stall build G05-21 describes is excluded in text, not only by the current code's shape.
- No behaviour changes: the rule is the code's. The cost is two superseded sentences and the tests of §5.
- A cold start always recomputes the cursor by replaying the cached rows, and no faster start by storing a cursor is available without a new ADR. Trade-off: a large vault pays the replay on every load; it already does today (U: no measurement of the replay time was made).
- The liveness limit stays: a device that restarts between every page, or is killed in the background during every long paged Fetch, never passes a held header and keeps re-fetching the same pages. It costs bandwidth and leaves the affected device chain's later ops undelivered (INV-27's "nothing past the gap is applied" holds while it lasts), never wrong data. ADR 0050 owner answer 1 accepted this for M1, to revisit with M3 telemetry; this ADR does not reopen it.
- ADR 0026 §4's "each cursor […] entry […] only grows" is read under C4 as a statement about the loaded cursor. If the owner prefers that sentence corrected rather than read, that is an erratum candidate for [the errata list](../reviews/2026-10-25-errata-candidates.md).

## On acceptance

Not made now; the owner or the accepting change does them:

1. ADR 0050's status line: "Partially superseded by [ADR 0109](0109-sync-cursor-held-header.md) (§2 in part)"; its index row in [README.md](README.md) the same.
2. ADR 0012's status line and index row: add "[ADR 0109](0109-sync-cursor-held-header.md) (§7 in part)" to the existing list.
3. This ADR's status line and index row: Accepted, with the date.
4. CLAUDE.md's list of Accepted and Proposed ADRs, by the lead.
5. Review D9 / G05-21 marked resolved in the gap review, pointing here.
6. The `rizzy_sync::causal` and `rizzy_client::sync` module docs cite this ADR next to ADR 0050 §2 (part of the §5 change, not a docs-only edit).

## Open questions for the owner

1. **Is a clarification enough, or should held covers be persisted after all?** The verification found no stall, only the restart-every-page liveness limit you already accepted in ADR 0050 owner answer 1. Recommendation: clarification only, as drafted; keep the persist-or-not decision where answer 1 put it (M3 telemetry), since persisting a hold would add a cache row, a decrypted-cover lifetime across restarts and a new format version for no observed failure.
2. **C5's healing guard.** If step 2 of §5 finds that a healing request can be built mid-sequence, the guard is a (small) behaviour change in code. Recommendation: accept C5 as drafted, so the healing range never names a held header the device holds no cover for.

## References

- [ADR 0050](0050-paged-fetch-tombstone-boundary.md) §2, §4, owner answers; [ADR 0012](0012-sync-engine.md) §4, §7, §12; [ADR 0021](0021-server-compaction.md) §4, §9; [ADR 0026](0026-client-device-state-and-cache.md) §4, §6; [ADR 0018](0018-item-record-encoding.md) §3; [ADR 0020](0020-partial-supersession.md) point 9.
- [THREAT_MODEL.md §8](../THREAT_MODEL.md#8-security-invariants) INV-27, INV-74.
- [Gap review 2026-10-25](../reviews/2026-10-25-adr-gap-review.md) D9; raw finding G05-21 in [G05.md](../reviews/2026-10-25-raw/G05.md).
- Code at `f3492b2`: `crates/rizzy-sync/src/causal.rs` (`cursor`, `cursor_entry`, `serves_again`, `end_holds`, `release_hold`, `MAX_HELD_ITEMS`), `crates/rizzy-client/src/sync.rs` (`cursor`, `apply_fetch`, `keep_covers`, `restore`), `crates/rizzy-client/src/tests/store.rs`, `crates/rizzy-client/src/tests/paged_fetch.rs`.
