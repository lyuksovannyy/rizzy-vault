# ADR 0021: Server-side compaction with concurrent snapshots

- Status: Proposed
- Date: 2026-09-26
- Deciders: project owner
- Milestone: M1 (server; Accepted before M1 step 3)
- Supersedes: [ADR 0012](0012-sync-engine.md) (§7 in part), on acceptance and only once [ADR 0020](0020-partial-supersession.md) (Record architecture decisions, with partial supersession) is Accepted. §1 lists the parts.

## Context

[ADR 0012](0012-sync-engine.md) §7 (Accepted) keeps the two newest snapshots per item, deletes the bodies of the ops the older one covers, and serves a bodiless header with "the newest snapshot of that item". A client counts a bodiless header only if a snapshot of that item covers its dot (ADR 0012 §7 "Chain check after compaction", INV-27).

Nothing makes the newer snapshot cover the older one. Covered VVs are concurrent when two devices purge an item at once, or pass the 32-op trigger in the same window. Two failures follow:
- **False gap.** Devices A and B purge concurrently and upload tombstone snapshots T_A, then T_B. The server deletes the body of A's purge op P_A behind T_A, the older, and serves T_B, which does not cover P_A. A device that was behind reports a gap on A's chain.
- **Lost server copy.** Laptop L uploads 33 late edits of a purged item and a live snapshot S_L. A tombstone snapshot T_2 that misses the edits makes S_L the older of the two newest, so the edits' bodies are deleted behind it. A second one, T_3, pushes S_L out. If L never returns, no server copy of the edits remains.

**Owner decisions** (2026-09-26, binding for this ADR):
- A small ADR, Accepted before M1 step 3, with exactly three server rules:
  1. delete an op body only when a retained snapshot the server keeps serving covers it;
  2. serve with each bodiless header a retained snapshot that covers it;
  3. never drop a snapshot that is the only cover of a deleted body.
- Covered VVs are cleartext, so the server can check all three.
- Changes to an Accepted ADR take effect by partial supersession under ADR 0020. Everything not named stays binding.
- The client-side merge edge cases are settled by an executable Rust spike, an exhaustive permutation model of ADR 0012 §12's properties, not by more prose.

Constraints:
- **What the server sees.** Each op header (vault, item, `device_id`, `device_seq`, `vault_prev_seq`, causal context) and each snapshot header with its covered VV, never a field value (ADR 0012 §3, §11; [THREAT_MODEL](../THREAT_MODEL.md) G-1). The covered VV is signed and bound into the `ITEM_SNAPSHOT` AAD (ADR 0012 §3; [CRYPTO.md §8.4](../CRYPTO.md#84-aad-and-purposes), [§10.2](../CRYPTO.md#102-ed25519-signatures-and-signed-statements)), so the server checks the VV every client verifies.
- **Upload order.** The server stores a device's ops in a vault only in chain order, under the account lock (ADR 0012 §7 "Upload"; [ADR 0011](0011-storage.md) "Transactions and concurrency").
- **Invariants.** INV-26: compaction discards only ops covered by a snapshot a client produced and signed. INV-27: a gap is reported, never skipped.
- **Roles and crates.** `worker` performs every deletion and can lag behind `api` ([ADR 0010](0010-server-shape.md) §1, §2). `rizzy-sync` holds "the compaction rules" (ADR 0012 §13). The server uses its header and VV types ([ADR 0016](0016-workspace-layout.md) §3).

## Decision

### 1. What this ADR supersedes

Under ADR 0020, this ADR supersedes exactly two passages of ADR 0012 §7:

| ADR 0012 §7 text, quoted | Replaced by |
|---|---|
| "Fetch": "An op whose body was compacted away comes as the signed header with its two hashes, plus the newest snapshot of that item." | §4 |
| "Snapshots and compaction": "The server keeps the two newest snapshots per item. It deletes only the **bodies** of the ops covered by the **older** of the two. So a faulty snapshot never destroys the only copy of anything, and nothing is deleted except behind a signed snapshot (INV-26)." | §3 |

Nothing else in ADR 0012 is touched by this ADR. That includes the rest of "Fetch", "Chain check after compaction", and the retention of every signed op header for the life of the vault.

### 2. Definitions

Every check uses cleartext the server already holds. A missing VV entry counts as 0.

- **Head** h(V, d): the `device_seq` of the last op of device d the server holds in vault V, the value its `vault_prev_seq` check uses (ADR 0012 §7). 0 if it holds none.
- **Clamped VV** of a snapshot S of an item in vault V: clamped(S)[d] = min(covered(S)[d], h(V, d)), computed once in the transaction that stores S, under the account lock. It is persisted with S in the canonical VV encoding (ADR 0012 §3), zero entries left out, and never sent.
- **Store sequence:** a per-vault `u64`, strictly increasing with each stored snapshot, assigned under the account lock. "Newest" and "oldest" mean by store sequence. A restore keeps the stored values and sets the counter above the restored maximum.
- **Retained:** stored. R3 (§3) drops a snapshot by deleting it.
- **Covers:** a retained snapshot S covers op o when o's header names S's vault and item, and o.`device_seq` ≤ clamped(S)[o.`device_id`].
  - Ops are stored in chain order, so **a snapshot never covers an op stored after it**, whatever its covered VV claims, up to `u64::MAX`.
  - Clamped ≤ covered, so a server cover also counts in the client's chain check (ADR 0012 §7).
- **Bodiless header:** an op whose body the server deleted. Its signed header, both hashes and signature stay for the life of the vault (ADR 0012 §7).

### 3. Retention and deletion

- **R1, delete (owner rule 1).** The server deletes an op's body when, and only when, the older of the item's two newest retained snapshots covers the op. With fewer than two retained snapshots it deletes nothing. It deletes the body only.
- **R3, retain (owner rule 3).** The item's two newest snapshots are always retained. An older snapshot stays while it is the only retained cover of some bodiless header. Every other older snapshot is dropped, tested oldest first and re-tested after each drop.
- **Nothing else** deletes a body or drops a snapshot. Account deletion (ADR 0011) and the switch to On-device mode (ADR 0012 §10 step 2) are unchanged.
- **Where it runs.**
  - `api` stores a snapshot with its clamped VV and store sequence, and queues the item. `api` never deletes or drops.
  - `worker` applies R1 and R3 to that item in one transaction under the account lock, recomputed from the current state (ADR 0010 §1).
  - `worker` lag delays deletion only. It never breaks R1 or R3.

Why the rules hold:
- **Owner rule 1.** R1 deletes only behind a retained snapshot, and R3 never leaves a bodiless header without one. §4 serves it.
- **Owner rule 3.** R3 never drops a sole cover.
- **Linear histories keep ADR 0012's rule.** When each snapshot's covered VV is ≥ that of the one stored before it, the retained set is the two newest, and R1 deletes what the older covers. The newer covers it too, so each deleted body lies in two retained snapshots, and one faulty snapshot does not destroy the only server copy.
- **Concurrent histories.** A body can be deleted behind one cover, and its server copy then rests on that snapshot alone (open question 1).
- **No cover, no deletion.** An op that the older of the two newest does not cover keeps its body: ops after that snapshot, ops stored after the snapshots that claim them, and every op of an item with fewer than two snapshots.

### 4. Fetch (owner rule 2)

A response to a cursor carries, besides what ADR 0012 §7 "Fetch" keeps:
- **Bodiless headers.** Each comes as its signed header with its two hashes.
- **Covers.** For each item with a bodiless header in the response, the server takes that item's retained snapshots newest first. It adds each one that covers a bodiless header of the item in the response that no snapshot added so far covers, until all are covered.
  - Each comes as its full record: header, envelope, signature and, if held, its wrap.
  - In a linear history the newest snapshot covers them all, so this is one snapshot, as under ADR 0012.
  - Each page of a paged response carries its own covers.
- **One consistent read.** The headers, bodies and snapshots of one response come from one read transaction: SQLite in WAL mode, a read-only `REPEATABLE READ` transaction on PostgreSQL (L: engine documentation, not re-read for this ADR). A response never holds a bodiless header without a retained snapshot that covers it.
- **A bodiless header without a retained cover** means a bug or a damaged database. The server serves the header alone and logs an integrity error naming the vault, item and dot, never content. The client's chain check reports missing data (ADR 0012 §7).

### 5. Cases

- **Concurrent purges.** The server cannot tell a tombstone snapshot from a live one, so the rules apply unchanged. T_A and T_B each stay retained as the only cover of their own purge op, and §4 serves both: no false gap. Once a snapshot that covers both purges is stored, R3 drops the oldest of the three.
- **Late edits from a device that never returns.** The edits' bodies go behind S_L while it is the older of the two newest, and R3 keeps S_L while it is their only cover. Once a device that applied the edits stores a snapshot covering them, and S_L is outside the two newest, R3 drops S_L.
- **Oversize items** ([ADR 0018](0018-item-record-encoding.md), Item-record encoding) write no snapshot. Nothing covers their ops, so every body stays.
- **Snapshots that claim dots the server does not hold** (restore healing, ADR 0012 §7; the M4 switch, ADR 0012 §10) are stored. The clamped VV limits their cover to ops held at that commit. How they reach a device that receives no bodiless header of the item is open question 4.

### 6. Storage bound

| Quantity | Bound |
|---|---|
| Retained snapshots per item | 2 in a linear history. Otherwise 2 plus each older snapshot that is the only cover of a bodiless header; an honest race adds one per concurrent writer until a later snapshot covers its ops. A faulty device can pin more (open question 2); the account storage quota bounds their bytes ([THREAT_MODEL](../THREAT_MODEL.md) A15, §7.6) |
| One snapshot | Plaintext ≤ 16 MiB ([CRYPTO.md §9.1](../CRYPTO.md#91-symmetric-envelope-algorithm-0x01)) |
| Op bodies kept per item | The ops the older of the two newest does not cover: about 33–65 under the 32-op trigger, as under ADR 0012. Every op of an item with fewer than two snapshots |
| Signed op headers | Unchanged: kept for the life of the vault, about 225 bytes plus 24 per causal-context entry (ADR 0012 §7) |
| Added per snapshot | Its clamped VV (2 bytes plus 24 per entry) and its store sequence (8 bytes) |

No new metadata: both values derive from covered VVs, heads and upload order, which the server already sees (ADR 0012 §11).

### 7. Where the code lives

- **`rizzy-sync`, module `compaction`:** pure functions for §2–§4. No I/O; it builds for wasm32 (ADR 0012 §13, ADR 0016).
  - Input: one item's retained snapshots (store sequence, clamped VV) and its op dots, each with a body flag. Output: the bodies to delete, the snapshots to drop, and the covers for a response.
- **`rizzy-domain-vault`:** the clamped-VV and store-sequence columns, in one forward migration per engine (ADR 0011 "Migrations"); the store transaction; Fetch; the compaction job.
- **`rizzy-server`** wires the job into `worker` (ADR 0010 §1).

### 8. Tests

The tests run in the ADR 0012 §12 harness, whose simulated server calls `rizzy-sync::compaction`. An independent brute-force checker, written from §2–§4 rather than from that module, checks the server properties.

- **Generated histories,** beyond ADR 0012 §12's: snapshots from several devices in every interleaving (the 32-op trigger, concurrent purges, late edits); a snapshot uploaded before ops it covers; snapshots that claim unheld dots, up to `u64::MAX`; oversize items; `worker` paused, then resumed; fetches from a cursor behind the head at every step.
- **Server properties,** after every step, whether or not `worker` has run:
  1. every bodiless header has a retained cover;
  2. no snapshot covers an op stored after it;
  3. every response carries, for each bodiless header, a snapshot whose clamped and covered VVs both cover it;
  4. after `worker` runs, every retained snapshot outside the two newest is the only retained cover of some bodiless header;
  5. in a linear history, the state after `worker` runs is ADR 0012's: the two newest retained, and the bodies the older covers deleted.
- **Client properties,** with compaction on: ADR 0012 §12 properties 1 (convergence), 2 (no silent loss) and 7 (gap detection). Against the honest server, no device reports missing data.
- **Named scenarios** (Context):
  - T_A then T_B, and T_B then T_A, with a device that was behind fetching after each upload. No gap is reported.
  - S_L with 33 late edits, two tombstone snapshots that miss them, L never returning, then a new device. The new device ends with the edits.
- **Storage,** on SQLite and PostgreSQL (ADR 0011): the store and compaction transactions; a Fetch racing a compaction never returns a bodiless header without a cover, over 1,000 runs; the restore drill checks server property 1.
- **Budget:** as in ADR 0012 §12.

### Settled by the merge spike

The owner moved these to the executable Rust spike [`spikes/merge-model`](../../spikes/merge-model/README.md), which lives outside `crates/` ([README](README.md), "The ADR-first rule") and runs §3–§4 as its simulated server. A counterexample to a server property reopens this ADR. Its "Results" (`integrated` preset, 2026-09-27) found none: §8 server properties 1–5 held in all 19 exhaustive families, run with the two-author R1 and R3 of open question 1. A rule beyond the owner's three, or one that changes an Accepted ADR, is an open question below. One line each:
- **Client absorption and merged snapshots** (families `absorb`, `snapshots`, `compaction`): the join, now [ADR 0018](0018-item-record-encoding.md) §3 "Absorbing a snapshot"; the merged-snapshot trigger is ADR 0018 open question 13. Nothing here changes.
- **Restore healing** (`restore`, `healing`, `oversize`, flavour `random-heal`): a healing request stores the headers above the server's heads, without their bodies only behind the request's snapshots, and other snapshots that claim unheld dots are refused (open question 4). The healer's snapshot can then be a header's only cover (open question 8).
- **Re-issued ops and re-uploads** (`reissue`, `random-reissue`, `random-reissue-norestore`): a byte-identical re-upload is "already stored" before the `vault_prev_seq` and stale-epoch checks, and a client never re-issues an op the server may have stored and served (open question 9; `item_key_id` is ADR 0018 open question 15).
- **Faulty-client snapshots** (`faulty`, `faulty-kinds`, `random-faults`, `random-faults-ops`, `random-faults-multi`): with §3's single cover a lying cover loses values silently (`faulty-kinds`: 1,532 of 150,720 schedules); two-author covers with ADR 0018's evidence merge (its open question 14) leave none with one faulty device outside restore healing (open question 1).
- **Pending or refused snapshots:** not exercised, since open question 2 adds no cap.
- **Revocation** (`revocation`, `rev-covers`, `rev-named`, `rev-unsent`, `rev-restore`, flavours `random-rev*`): the revoked device's ops within its cut-off stay, and its snapshots count as covers within it (open question 5). A revocation signed on a restored server is detected but not converged (open question 7).

### On acceptance

This ADR makes none of these edits.
1. **Order.** ADR 0020 is Accepted before this ADR or with it. This ADR is Accepted before any M1 step 3 code is merged (owner decision, 2026-09-26). M1 step 3 is the server step of the M1 plan, which includes op upload and Fetch (`docs/HANDOFF.md` at commit 434d0b3, removed in 6c23c51; V).
2. **ADR 0012 status line** (the owner's act): "Partially superseded by [ADR 0021](0021-server-compaction.md) (§7 in part)", after any earlier entry and separated from it by a semicolon, with any pointer entry ADR 0020 requires.
3. **[docs/adr/README.md](README.md)** (the owner's act): row 0012's Status cell repeats its status line; row 0021 becomes Accepted.
4. **No other edit.** INV-26 holds. ADR 0010 §1 (`worker` row), ADR 0011 and ADR 0016 §3 read through: they say only that bodies are deleted behind client-signed snapshots and that headers are kept. CRYPTO.md changes only if open question 5 is answered with a rule.

## Consequences

### Positive

- Owner rules 1–3 hold in every interleaving, checked from cleartext VVs and the server's own heads, with no plaintext.
- No false gap after concurrent purges. Late edits from a device that never returns keep a server copy.
- Linear histories behave exactly as under ADR 0012.
- A snapshot that claims future dots deletes nothing stored after it.
- One pure implementation in `rizzy-sync` serves both engines and the test harness.

### Negative

- A clamped VV and a store sequence per snapshot, and a `worker` job per snapshot upload.
- Under concurrency a body can be deleted behind one snapshot, which ADR 0012's rule avoided in linear histories (open question 1).
- A response can carry several snapshots of one item during a race.
- A live snapshot with a purged item's full encrypted state stays while it is the only cover of late edits.

### Risks

- **A faulty sole cover** loses the server copy of what it omits. The clients' own retained ops are then the only other copy, and the spike shows receivers losing values silently (open question 1).
- **Client-side trust.** A verified snapshot that claims dots nobody holds makes a client that absorbs it treat later ops of those dots as duplicates (ADR 0012 §4 step 3). The clamp protects server bodies only; the client rule is ADR 0018 open question 14.
- **Pinning.** A faulty device can pin snapshots through R3, up to the storage quota (open question 2).
- **Consistent reads** on PostgreSQL rest on `REPEATABLE READ` semantics (L). The race test of §8 is the check.

## Alternatives considered

- **Keep ADR 0012's rule.** False gap and lost server copy (Context).
- **Two covers per deleted body, dominance-based retention and a per-item cap** (the earlier draft of this ADR). It keeps "a faulty snapshot never destroys the only copy" under concurrency. It needs a cap, a raised cap after restores and pending-snapshot rules, and it pins leftover snapshots behind purges, including a live one with a purged item's full state. Open question 1.
- **Refuse a snapshot that does not dominate the retained ones.** It refuses honest concurrent snapshots, including the tombstone snapshots of concurrent purges.
- **Serve every covering snapshot.** No selection rule, but steady-state downloads double.
- **Cover by the unclamped covered VV.** A snapshot that claims future dots would delete the bodies of ops stored after it.
- **Keep every snapshot.** Storage grows with every snapshot.

## Open questions for the owner

1. **Two covers under concurrency.** Delete a body only when retained snapshots by two different authors cover it, so that no single device's snapshot holds the only server copy? The spike's rule (answer 4): R1 also requires retained covers by two different authors, R3 keeps an older snapshot while dropping it would leave a bodiless header covered by fewer than two authors, and Fetch serves covers by two authors for each bodiless header; f faulty devices need f + 1 authors. With §3 as written, a faulty sole cover loses values silently (`faulty-kinds`: 1,532 of 150,720 schedules; `random-faults`: 289 of 50,000 seeds); with the rule and ADR 0018 open question 14, no value is lost silently with one faulty device outside restore healing (open question 8). It goes beyond the owner's three rules and changes §6: an item snapshotted by one device only is never compacted. *Recommendation:* yes, reversing the earlier "no", which predates the spike; pinned leftover snapshots are the cost.
2. **A per-item cap on retained snapshots,** against a device that pins snapshots through R3. *Recommendation:* none in M1; the storage quota bounds the bytes. Revisit with M3 data and before M9 shared vaults.
3. **A per-item request for every retained snapshot,** for a served cover that fails verification or carries an `item_schema_version` the client cannot read. *Recommendation:* not in M1; the client reports missing data, or "update required" ([ADR 0002](0002-own-protocol.md) point 5).
4. **Delivering snapshots that claim dots the server lacks** (restore healing, the M4 switch) to devices that receive no bodiless header of the item. The spike (answer 2) answers it with a healing request that replaces ADR 0012 §7 "Healing a server rollback" step 4 and "Leaving read-only", and §5's "are stored". Evidence: `restore` (1,728 schedules) and `oversize` (17,040), no violation; `healing` (8,910), 2, both on the path of open question 7; ADR 0012 §7 read literally fails 785, 3,927 and 1,789 of them (answer 2's copy), and storing claims as §5 says loses a value silently in 23 `healing` schedules. *Recommendation:* adopt it before M1 step 3, in this ADR reopened beyond the owner's three rules or in a new small ADR, as a named partial supersession of ADR 0012 §7 under ADR 0020. The rule:
   - **Headers kept.** Clients keep every signed op header they receive or write, with both hashes and the signature, for the life of the vault (about 225 bytes plus 24 per causal-context entry per op), and every snapshot record they wrote or absorbed.
   - **Server behind.** A device finds the server behind when the server's `state_seq` is lower; or a head h(V, d) is below the device's cursor or item-VV entry for d, or, for the device itself, below its highest acknowledged `device_seq`; or the server lacks an item-key wrap the device got from it or had acknowledged. Each entry is capped at d's known revocation cut-off; the device leaves read-only once none holds.
   - **Step 4** is one request per vault, atomic under the account lock: every item-key wrap the server lacks, then per chain from h + 1 up to the device's cursor, capped at a known cut-off, every header it holds, with its body if it holds the body of a record the server stored before, else without it behind the request's fresh snapshot or a held snapshot sent verbatim. An oversize item gets no fresh snapshot (ADR 0018 open question 12).
   - **Server.** It stores a bodiless header only inside such a request whose snapshots cover it (clamped after the request's headers), else refuses the whole request, and skips the stale-epoch check for bodiless headers and records re-published verbatim. Outside a request it refuses a snapshot whose covered VV exceeds its heads, counting a revoked device's entry only up to its `last_accepted_device_seq`. §8 property 5 gains "and the headers a healing request stored without a body".
5. **Snapshots by revoked and kind-4 devices.** A snapshot header has no HLC, so CRYPTO.md §10.2 rule (c) and ADR 0012 §7's kind-4 upload check cannot be evaluated for one. *Recommendation:* accept a snapshot whose covered entry for its author is at most that device's last accepted `device_seq`; the server refuses new ones after revocation or expiry and keeps counting retained ones as covers. The spike (answer 5) confirms this for revoked devices (`revocation`, `rev-covers`, `rev-named`, `rev-unsent`: no violation; rejecting such a snapshot fails 4,823 `rev-covers` schedules under §3, with false gaps, in answer 5's copy) and adds three rules: the server refuses a snapshot whose covered entry for its author is above that author's head (implied by open question 4); the stale-epoch check does not apply to a revoked device's op with `device_seq` ≤ `last_accepted_device_seq`, whoever uploads it (a partial supersession of ADR 0012 §7 "Upload"); after a complete Fetch, a client whose cursor for a revoked device is below that device's `last_accepted_device_seq` reports missing data (INV-27; one vault per account in M1, per vault from M9). Kind-4 certificates were not modelled.
6. **The rotation cut-off** (ADR 0012 §6; [CRYPTO.md §11.6](../CRYPTO.md#116-key-rotation) step 9) for a snapshot, which has no `device_seq`. *Recommendation:* a snapshot is "beyond that cursor" when its clamped VV exceeds the cursor, so a snapshot that claims unheld dots never blocks a rotation.
7. **A revocation signed on a restored server.** When the restored server's head for a device is below ops some replica applied, the cut-off falls below them, replicas take ADR 0012 §6's remove-and-recompute path, and its "Only a misbehaving server can make a replica hold an op past the cut-off" is false. No answer converges it: every divergence is reported (a flagged item or ops held in the causal buffer), but 44 of the 1,876 random seeds on this path also lose a value silently (exhaustive: `healing` 2 schedules and `rev-restore` 2,541, all reported). *Recommendation:* for M1, count it as a misbehaving server for ADR 0012 §6, detected and not converged (answer 5), amend that sentence by partial supersession, and look for a restore rule that closes the silent cases before M9; the spike tested none.
8. **A faulty healer as the only cover.** A healing request stores a header without its body behind the healer's snapshot alone, so a faulty healer's later snapshot can be the only cover served, and receivers lose the value silently (`random-faults-ops` seed 6327). Open question 4's rule sends a held body where it can, and leaves an own op never acknowledged to the normal upload path; what stays single-author is a header whose body no device holds, where the healer's snapshot is the only record left anyway (142 of 2.6 million seeds, 101 silent). The options: clients keep every own op body for the life of the vault (`random-faults-ops`, 50,000 seeds: silent loss in 4 instead of 12); the server serves every retained cover of a single-author header (not measured); or the owner accepts it. *Recommendation:* accept it in M1, and revisit before M9 shared vaults, where the faulty author can be another member.
9. **Re-uploads and re-issues after a stale answer** (answer 3, with answer 2's mechanism). Evidence: `reissue` (23,218 schedules), no violation, 5,192 re-uploads answered "already stored"; in answer 3's copy, no dedup loses ops silently (564 schedules) and dedup after the stale-epoch check diverges (1,002); re-issuing an op the server may have stored gives two signed versions of one dot (`reissue`: 160 schedules, 26 divergent). It needs a server restore generation, which no ADR defines; the nearest is ADR 0012 §7's reconciliation epoch (INV-59). *Recommendation:* adopt both rules as a partial supersession of ADR 0012 §7 "Upload" under ADR 0020, and define the restore generation with them.
   - **Already stored.** An upload byte-identical to the record the server stores at that (`vault_id`, `device_id`, `device_seq`), or with that `snapshot_id`, is answered "already stored" before the `vault_prev_seq` and stale-epoch checks, and nothing is stored; a different record at a stored dot is refused as a conflict. The client treats "already stored" as an acknowledgement.
   - **Re-issue scope.** A client re-issues only an op the server rejected itself as stale, with the later old-epoch ops of its chain, and never one the server may have stored and served: one acknowledged, or one whose response was lost before the restore generation changed. It re-publishes such an op in a healing request (open question 4). A stale answer to a snapshot only discards and rewrites it.

## References

- [ADR 0002](0002-own-protocol.md) point 5; [ADR 0010](0010-server-shape.md) §1, §2; [ADR 0011](0011-storage.md) (transactions, migrations, backups); [ADR 0012](0012-sync-engine.md) §3, §4, §6, §7, §10–§13; [ADR 0016](0016-workspace-layout.md) §3
- [ADR 0018](0018-item-record-encoding.md) (Item-record encoding: canonical binary layout and the M1 item schema, Proposed); [ADR 0020](0020-partial-supersession.md) (Record architecture decisions, with partial supersession, Proposed)
- [THREAT_MODEL](../THREAT_MODEL.md) §7.6, A15, G-1, INV-26, INV-27
- [CRYPTO.md](../CRYPTO.md) §8.4, §9.1, §10.2, §11.6
- The M1 step list in `docs/HANDOFF.md` at commit 434d0b3, removed in commit 6c23c51 (V)
- PostgreSQL documentation, transaction isolation (`REPEATABLE READ`); SQLite documentation, WAL mode (L: not re-read for this ADR)
- The merge spike, [`spikes/merge-model/README.md`](../../spikes/merge-model/README.md), "Results" (`integrated` preset, run on 2026-09-27; figures as reported there, not re-run for this ADR)
