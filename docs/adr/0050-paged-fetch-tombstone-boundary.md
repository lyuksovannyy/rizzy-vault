# ADR 0050: Paged Fetch: tombstone covers that can span a page boundary

- Status: Accepted
- Date: 2026-10-11
- Deciders: project owner
- Milestone: M1
- Supersedes: [ADR 0021](0021-server-compaction.md) §4, "Covers" bullet (one bullet), and [ADR 0012](0012-sync-engine.md) §7 "Chain check after compaction", last sentence, on acceptance.

## Context

[ROADMAP §4.6](../ROADMAP.md#46-sync-modes-m4), Must: "Single sync engine... field-level merge, tombstones for deletes, conflicting edits kept as item history instead of dropped" and "**Server mode**: full encrypted vault + op log stored server-side; compaction of op log into snapshots." [ADR 0021](0021-server-compaction.md) §4 "Fetch" is the Accepted rule for what one page of a paged Fetch response carries; its last sentence is "Each page of a paged response carries its own covers." The implementation (`crates/rizzy-domain-vault/src/fetch.rs`, `page_ops`) goes further than that sentence says: a bodiless header never joins a page without every cover its own dot needs in the *same* page (V, read 2026-10-11).

That invariant is checked only in cleartext, version-vector terms: `o.device_seq ≤ clamped(S)[o.device_id]` (ADR 0021 §2, §4). It says nothing about a cover's *plaintext* content. A tombstone (ADR 0012 §5 "Purge") records, inside its encrypted body, the dot of the Purge op it resulted from (`purge_dot`; ADR 0018 §3 "Recorded purge": of all applied Purge ops of the item, any device, the one with the highest `(hlc, device_id, seq)` — not necessarily a purge by the device whose header is bodiless). The server never decrypts a snapshot (G-1), so it cannot know, and cannot align pages to, which dot a tombstone names. A tombstone can therefore be a wholly legitimate cover for one bodiless header — selected and bundled with that header in the same page, exactly as §4 requires — while its `purge_dot` names a different op, of the same device or another one, whose own header the server has simply not reached yet in that chain's walk, because a page stops inside one device's chain only (`fetch.rs` module docs) and the two dots fall in different pages, or different devices' chains, of the same response sequence.

On the client, `rizzy_sync::merge::ItemMerge::absorb_snapshot` cuts a snapshot's claim to the op headers the replica has verified (ADR 0018 §3) and returns `AbsorbOutcome::Refused(Refusal::PurgeAboveCut)` when even that cut's own `purge_dot` is not yet verified. Its own doc comment says this is meant to be transient: "its headers and bodies... remain usable once the gap closes and the causal layer's chain walk reaches them." But nothing retries it. `rizzy_client::sync::VaultSync::settle` (`crates/rizzy-client/src/sync.rs`) only counts it: `AbsorbOutcome::Refused(_) => outcome.refused_covers += 1`. Separately, `rizzy_sync::causal::VaultLog::commit`'s chain walk — the pass that actually accepts links (ADR 0012 §7 "Chain check after compaction", Accepted and untouched by ADR 0018's, ADR 0021's, ADR 0022's or ADR 0032's own supersession lists) — ends a device's walk, and reports `Report::Gap`, at the first bodiless header its item's settled VV does not cover; no later header of that walk becomes a link. Per INV-27, "nothing from that device past the gap is applied." Because the client's own cursor for that device does not move past the gap, the next Fetch call serves the same header and a freshly reselected cover again, hitting the same refusal — until, by accident of paging, some later page happens to also deliver and accept the `purge_dot`'s own header within one page, which §4 gives no guarantee of (a small operator-set `VaultDomain::with_page_bytes` budget, or enough competing devices and items ahead of it, can keep splitting the two indefinitely).

The result: an item that was purged, with any bodiless header anywhere in its history, can report a spurious "missing data" gap and make its author's whole device chain (every item that device touches, since `device_seq` is gap-free across the vault) wait on how the server happened to split that one Fetch, for as long as §4 is silent on it. ADR 0021's own Context covered two different failures (false gap from concurrent purges; lost server copy); this is a third, found while reading the Fetch/merge boundary for this ADR, not by running a reproduction in this session (code mechanism: V; "reproducible today" as stated to this ADR: not independently re-run here). No M1 server or client code shipped yet depends on the unpatched reading of §4 or §7, so this is a design correction, not a regression.

## Decision

### 1. What this ADR supersedes

Under [ADR 0020](0020-partial-supersession.md) point 9, this ADR supersedes exactly two parts, quoted in full.

- **ADR 0021 §4, the "Covers" bullet:** *"**Covers** (owner decision 1). For each item with a bodiless header in the response, the server takes that item's retained snapshots newest first. It adds each one that covers a bodiless header of the item in the response that the snapshots added so far cover by no author, or by one author other than its own. Each comes as its full record: header, envelope, signature and, if held, its wrap. Each page of a paged response carries its own covers."* Replaced by §2 below.
- **ADR 0012 §7 "Chain check after compaction", last sentence:** *"Anything else is reported as missing data, and nothing past the gap is applied."* Replaced by: "A header without a body, or whose body was rejected, that no snapshot covers is reported as missing data, and nothing past the gap in that device's chain is applied — except a header refused only as `Refusal::PurgeAboveCut` (ADR 0018 §3), which is instead linked into the chain provisionally, and only for that: chain walk and cursor advance past it, exactly as this ADR's §2 below sets out. Nothing causally dependent on the held dot is delivered while it is held, under the unchanged causal-delivery rule (ADR 0012 §4 step 2). The gap is reported, and nothing dependent on the held dot is ever applied, once the response sequence that served its cover completes without resolving it."

This is an invariant-level narrowing (INV-27, THREAT_MODEL §8.4), not only a mechanism change; see "On acceptance" and open question 3.

### 2. Covers across a page boundary

**Covers** (owner decision 1, unchanged). For each item with a bodiless header in the response, the server takes that item's retained snapshots newest first and adds each one that covers a bodiless header of the item in the response that the snapshots added so far cover by no author, or by one author other than its own. Each comes as its full record: header, envelope, signature and, if held, its wrap. Each page of a paged response carries its own covers, selected only from that page's own bodiless headers, exactly as before.

A cover selected this way may be a tombstone whose encrypted body names, as `purge_dot`, an op whose own header the server serves only in a later page of the same response sequence (every Fetch call sharing one cursor-advance loop, up to a page whose `complete` is `true`), or on a different device's chain than the bodiless header's own. This is not an integrity error, and the server logs none for it: it is a direct consequence of the server never decrypting a snapshot (G-1), and nothing here asks it to.

The client must not treat `Refusal::PurgeAboveCut` (ADR 0018 §3 "Snapshots are claims") from absorbing such a cover as final while the response sequence that served it could still deliver the claimed `purge_dot`'s own header. It holds the refusal: the bodiless header joins its device's chain as a link, in a new state distinct from `Bodiless` (parallel to how a `Rejected`-body link is already accepted and settled later, `rizzy_sync::causal`'s `LinkState`/`serve_again`), so that the chain's head and cursor advance past it instead of the walk ending in `Report::Gap`. This changes only chain linkage: the held dot is not added to the item's settled VV, so causal delivery of anything whose context names it still waits exactly as today (ADR 0012 §4 step 2), and a later, unrelated header of the same chain can itself become a link without being treated as finally missing. `ItemMerge::absorb_snapshot` is retried, unchanged, against the same verified cover whenever any device's chain in the vault log advances — any widening of `self.log`'s heads, not only the bodiless header's own device's — until it succeeds (the claim joins exactly as an ordinary absorption, ADR 0018 §3) or a later, dominating cover is absorbed instead, which makes the held one moot (ADR 0018 §3, "a dominated snapshot changes nothing"). A hold that is still unresolved once the response sequence completes (`complete = true` with nothing further to fetch) is reported now, exactly as `Report::Gap`/`Refusal::PurgeAboveCut` already are today.

Every other `Refusal` variant (`ValueNotInBody`, `ValueAtPurgeDot`, `WriteRecordedAsPurge`, `PurgeKeyContradicts`, `ContextNotFromPurges`) names a real protocol violation, not a paging artifact, and stays a final, immediately reported refusal; this ADR holds `PurgeAboveCut` only.

A held claim lives only in the running `VaultSync` for the life of the current response sequence; ADR 0026's cache gains no new row. A process restart before the hold resolves drops it: the next Fetch starts a fresh sequence from whatever cursor was last persisted. Open question 1 covers the residual loss this can leave.

**Proposed INV-74** (allocated across the 2026-10-11 batch in ADR-number order. Provisional: the allocation was made across the 2026-10-11 batch in ADR-number order; if ADRs are accepted out of order, the owner renumbers at acceptance.): A client holds, rather than finally reports, a `Refusal::PurgeAboveCut` for as long as the response sequence that served the cover could still deliver the claimed `purge_dot`'s own header to any device's chain in the vault log; it reports the gap, and withholds everything causally dependent on the held dot, only once that response sequence completes without delivering it.

**No cryptographic change.** The tombstone layout, its covered VV, the `ITEM_SNAPSHOT` AAD (CRYPTO.md §8.4) and the `snapshot` signature (CRYPTO.md §10.2) are untouched. This is a merge-ordering and chain-linkage rule inside already-Accepted constructions, not a new one; no CRYPTO.md floor moves.

### 3. Where the code lives

- `rizzy_sync::causal` (`crates/rizzy-sync/src/causal.rs`): a new `LinkState` (alongside `Ready`/`Waiting`/`Rejected`/`Bodiless`/`Delivered`/`Revoked`) for a bodiless header refused only as `PurgeAboveCut`; `VaultLog::commit`'s walk accepts it as a link instead of ending the walk with `Report::Gap`, and a retry entry point (parallel to `serve_again`) re-checks it whenever any device's chain in the log advances, or the response completes. Pure, no I/O, builds for `wasm32` (ADR 0016).
- `rizzy_sync::merge` (`crates/rizzy-sync/src/merge.rs`): `ItemMerge` keeps the refused cover pending per item, as a `(SnapshotHeader, SecretBytes)` pair — the same zeroizing type every other decrypted snapshot plaintext in this crate already uses (`WrittenSnapshot::data`, the `covers` parameter of `rizzy_client::sync::VaultSync::settle`) — discriminated by `Refusal::PurgeAboveCut` specifically; `absorb_snapshot`'s own contract and "Snapshots are claims" (ADR 0018 §3) are unchanged.
- `rizzy_client::sync::VaultSync::settle` (`crates/rizzy-client/src/sync.rs`): drives the retry after each page's commit widens `self.log`'s heads (any device, not only the held header's author), and converts a still-pending hold to the final report when `response.complete`.
- `rizzy_domain_vault::fetch` (`crates/rizzy-domain-vault/src/fetch.rs`): unchanged. Its "a bodiless header never joins a page without the cover its own dot needs" invariant already holds; this ADR only says that invariant cannot, and need not, extend to a cover's own encrypted claim.

No sibling ADR in this batch (0045–0074) touches this boundary; none is affected by or affects this change.

### 4. Tests

A deterministic two-page case, driven through `VaultDomain::with_page_bytes` set low enough to force the split: item I has an early op whose body is compacted behind a retained tombstone, and a later Purge op from the same device placed in the next page by exhausting `PAGE_MAX_OPS`/the page's byte budget between them. Before this ADR: the first page's `Report::Gap` is final and the device's chain never advances. After: `rizzy-domain-vault` tests fetch the same item over two small-budget pages against the real server code and check the hold resolves once the second page lands; `rizzy-sync`'s own generated histories (ADR 0021 §8) and the merge spike (`spikes/merge-model`) add this interleaving, **and a cross-device one** (the recorded purge authored by a different device than the bodiless header's own, the case ADR 0018 §3 "Recorded purge" allows and the Context's motivating scenario raises) — the purge op's chain segment one, two, and many pages, and one and several devices, after its cover. Regression: the response completes with the `purge_dot` never served (e.g., a revoked device past its cut-off) — the hold resolves to the same final, reported refusal as today. ADR 0012 §12 properties 1 (convergence) and 7 (gap detection), and ADR 0021 §8 property 3, run over all of it.

## Consequences

### Positive

- Closes a path to reporting a false, non-advancing "missing data" gap and stalling a whole device's chain for no reason but how one Fetch response happened to be paged — with no server change, no new wire field, no crate-boundary change, and no new cryptographic construction.
- Reuses "Snapshots are claims" (ADR 0018 §3) exactly as Accepted; the merge's own doc comment already described the intended behavior, this ADR just wires the retry up.

### Negative

- `ItemMerge` and `VaultLog` each carry one more pending state per item with a currently-held tombstone claim, for the life of the response sequence.
- Not persisted (open question 1): a restart mid-sequence still loses the specific claim, though the item's live state converges regardless, through the ordinary direct op-apply path, once the Purge op itself is later delivered (with or without its own body).

### Risks

- The hold's lifetime is the whole response sequence (every page up to `complete = true`), not one page, so `PAGE_MAX_OPS` does not bound how many distinct items can carry an unresolved hold at once. The bound this ADR takes instead: at most one held claim per item with a bodiless header refused as `PurgeAboveCut`, each at most one snapshot plaintext; past an explicit per-sequence cap on distinct held items (set with the implementation, e.g. in the low hundreds), a client reports the gap immediately instead of holding it, which is exactly today's Accepted behavior and adds no new vector beyond it.
- A stalled or faulty device whose chain never advances leaves the hold open until the response completes, same budget and same outcome as any other gap report today.
- The new `LinkState` widens `rizzy_sync::causal`'s state space; its property tests (§4 above) are the defense against a held claim being mistaken for a settled one.

## Alternatives considered

- **Server-side reordering**: have the server postpone a tombstone cover to the page that also carries its `purge_dot`'s header, or read ahead to detect the case. Needs the server to decrypt a tombstone to learn `purge_dot` (breaks G-1), or a second read pass that risks §4's "one consistent read" property, which this ADR leaves untouched. Rejected per the owner's steer toward client-side deferral.
- **Treat every `PurgeAboveCut` refusal as final** (today's behavior): simpler, but it is the bug, not a fix — a correctly served, correctly verified cover is thrown away and the device's chain stalls for a reason internal to paging.
- **Widen pages to never split one item's bodiless headers from its purge**: needs the server to know, in cleartext, which dot a tombstone names, which it cannot (G-1); without that it cannot know which pairs to keep together.

## On acceptance

The owner makes these edits in the change that accepts this ADR; this ADR makes none of them now.

1. **ADR 0012's status line** gains "; [ADR 0050](0050-paged-fetch-tombstone-covers.md) (§7 in part)", covering the "Chain check after compaction" last sentence named in §1.
2. **[docs/adr/README.md](README.md):** row 0012 repeats its status line; row 0050 becomes Accepted.
3. **[THREAT_MODEL.md](../THREAT_MODEL.md) §8.4, INV-27** gains, after its existing text: "A client may instead hold, rather than finally report, a bodiless header refused only as `Refusal::PurgeAboveCut` (ADR 0018 §3), for as long as the response sequence that served its cover could still deliver the claimed dot; nothing causally dependent on the held dot is applied until it settles or the gap is finally reported (ADR 0050 §2; proposed INV-74)." INV-74 is added to §8.4 in the same change.

## Open questions for the owner

1. Persist a held tombstone claim across a restart (a new ADR 0026 cache row), so a crash mid-sequence cannot lose it, versus accepting the loss as a known M1 limit. *Recommendation:* accept the loss for M1, parallel to ADR 0021's own "Known limits for M1" (owner decisions 7–8): the item's live state is unaffected, only the one snapshot's own claim is retried from scratch next sequence; revisit with M3 telemetry if it proves common rather than rare.
2. Whether the pending-claim bookkeeping belongs on `ItemMerge` (per item) or on `VaultLog` (per device chain), as sketched in §3. *Recommendation:* split as drafted — `VaultLog` decides when the chain may link past a held header, `ItemMerge` decides when its claim actually joins — since that mirrors the existing chain/item split (`self.chains` vs. `self.items`) the rest of `rizzy_sync::causal` already relies on.
3. **This narrows INV-27, an invariant, not only a mechanism** (ADR 0020 point 7: a conflict on a goal or invariant is a stop-and-ask, not a same-PR doc fix). *Recommendation:* accept the narrowing as "On acceptance" item 3 drafts it (hold, then report if unresolved — INV-27's gap-reporting guarantee still holds, only later), rather than leaving INV-27 unchanged and the override undocumented.

## References

- [ADR 0012](0012-sync-engine.md) §2 (dot, causal context), §4 step 2 ("deliver causally"), §5 ("Purge", tombstones, "Late ops after a purge"), §7 "Chain check after compaction" (superseded here, last sentence)
- [ADR 0018](0018-item-record-encoding.md) §3 "Recorded purge", "Absorbing a snapshot", "Snapshots are claims" (owner decision 14)
- [ADR 0020](0020-partial-supersession.md) point 7 (mechanism vs. invariant), point 9 (partial supersession)
- [ADR 0021](0021-server-compaction.md) §2 (terms), §4 (Fetch, superseded here), §7, §8, §9
- [THREAT_MODEL](../THREAT_MODEL.md) G-1, INV-24, INV-26, INV-27 (amended here), proposed INV-74
- [ROADMAP](../ROADMAP.md) §4.6
- [CRYPTO.md](../CRYPTO.md) §8.4, §10.2 (untouched; cited to show nothing there changes)
- `crates/rizzy-domain-vault/src/fetch.rs` (module docs, `page_ops`, `PAGE_MAX_OPS`, `PAGE_BYTES`, `VaultDomain::with_page_bytes`) (V, read 2026-10-11)
- `crates/rizzy-sync/src/causal.rs` (`VaultLog::plan_covers`, `commit`, `walk`, `waiting`, `record_absorbed`, `CoverPlan`, `LinkState`, `serve_again`, `missing_context`) (V, read 2026-10-11)
- `crates/rizzy-sync/src/merge.rs` (`ItemMerge::absorb_snapshot`, `Refusal`, `AbsorbOutcome`, `WrittenSnapshot::data: SecretBytes`) (V, read 2026-10-11)
- `crates/rizzy-client/src/sync.rs` (`VaultSync::settle`, `covers: &[(SnapshotHeader, SecretBytes)]`, `FetchOutcome::refused_covers`) (V, read 2026-10-11)
