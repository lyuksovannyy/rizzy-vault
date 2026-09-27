# ADR 0021: Server-side compaction with concurrent snapshots

- Status: Accepted
- Date: 2026-09-27
- Deciders: project owner
- Milestone: M1 (server; Accepted before M1 step 3)
- Supersedes: [ADR 0012](0012-sync-engine.md) (§6 in part, §7 in part), on acceptance and only once [ADR 0020](0020-partial-supersession.md) (Record architecture decisions, with partial supersession) is Accepted. §1 lists the parts.

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

Under ADR 0020, this ADR supersedes exactly these parts of ADR 0012. The first two come from owner rules 1–3, the rest from owner decisions 4, 5, 7 and 9 (2026-09-27):

| ADR 0012 part, quoted | Replaced by |
|---|---|
| §7 "Fetch": "An op whose body was compacted away comes as the signed header with its two hashes, plus the newest snapshot of that item." | §4 |
| §7 "Snapshots and compaction": "The server keeps the two newest snapshots per item. It deletes only the **bodies** of the ops covered by the **older** of the two. So a faulty snapshot never destroys the only copy of anything, and nothing is deleted except behind a signed snapshot (INV-26)." | §3 |
| §7 "Upload", third sub-bullet, first sentence: "It rejects an op whose `vault_prev_seq` is not the last op it holds from that device in that vault." | §9 "Already stored" |
| §7 "Upload", fourth sub-bullet: "Under the account lock the server rejects an op or snapshot whose `vault_key_epoch` is below the vault's current epoch ("stale epoch"). The client then processes the new `account-state` ([CRYPTO.md §11.3](../CRYPTO.md#113-unlock-on-an-enrolled-device) steps 3–4), applies the writer rule and re-issues the edit with the same `device_seq`, which the server never stored." | §9 "Stale epoch" |
| §7 "Healing a server rollback", step 4: "**Its ops, and a fresh signed snapshot of each affected item.**" | §9 "Healing request" |
| §7 "Healing a server rollback", the read-only condition "(a lower `state_seq`, or a VV behind its own)", and "Leaving read-only": "The device leaves read-only once the server serves a state and VVs at least as new as its own." | §9 "Server behind" |
| §6, sixth bullet, first sentence: "Only a misbehaving server can make a replica hold an op past the cut-off." | §9 "Restored-server revocation" |

Nothing else in ADR 0012 is touched by this ADR. That includes the rest of "Upload", "Fetch" and "Healing a server rollback", "Chain check after compaction", and the retention of every signed op header for the life of the vault.

### 2. Definitions

Every check uses cleartext the server already holds. A missing VV entry counts as 0.

- **Head** h(V, d): the `device_seq` of the last op of device d the server holds in vault V, the value its `vault_prev_seq` check uses (ADR 0012 §7). 0 if it holds none.
- **Clamped VV** of a snapshot S of an item in vault V: clamped(S)[d] = min(covered(S)[d], h(V, d)), computed once in the transaction that stores S, under the account lock. It is persisted with S in the canonical VV encoding (ADR 0012 §3), zero entries left out, and never sent.
- **Store sequence:** a per-vault `u64`, strictly increasing with each stored snapshot, assigned under the account lock. "Newest" and "oldest" mean by store sequence. A restore keeps the stored values and sets the counter above the restored maximum.
- **Retained:** stored. R3 (§3) drops a snapshot by deleting it.
- **Covers:** a retained snapshot S covers op o when o's header names S's vault and item, and o.`device_seq` ≤ clamped(S)[o.`device_id`]. Its **author** is the device that signed it.
  - Ops are stored in chain order, so **a snapshot never covers an op stored after it**, whatever its covered VV claims, up to `u64::MAX`.
  - Clamped ≤ covered, so a server cover also counts in the client's chain check (ADR 0012 §7).
- **Bodiless header:** an op whose body the server deleted, or which a healing request stored without it (§9). Its signed header, both hashes and signature stay for the life of the vault (ADR 0012 §7).
- **Restore generation** (owner decision 9): one random 128-bit value per server database, drawn when the database is created and again by `rizzy-vault restore` after it loads the rows, in the step that opens the reconciliation epoch (INV-59). Nothing else changes it. It is random because a restore loads a dump older than the value it replaces ([ADR 0011](0011-storage.md) "Backups"). Every upload answer and Fetch response carries it. A client keeps, with each own op it sent without an answer, the value of its last response before the first send. The reconciliation epoch cannot serve: it ends once a newer state is verified or after an admin-set limit, and ADR 0012 gives clients no view of it.

### 3. Retention and deletion

- **R1, delete (owner rule 1, owner decision 1).** The server deletes an op's body when, and only when, the older of the item's two newest retained snapshots covers the op and retained snapshots by two different authors cover it. With fewer than two retained snapshots it deletes nothing. It deletes the body only.
- **R3, retain (owner rule 3, owner decision 1).** The item's two newest snapshots are always retained. An older snapshot stays while dropping it would lower the number of authors that cover some bodiless header to fewer than two. Every other older snapshot is dropped, tested oldest first and re-tested after each drop.
- **Nothing else** deletes a body or drops a snapshot. Account deletion (ADR 0011) is unchanged; ADR 0022 parks the switch to On-device mode (ADR 0012 §10 step 2).
- **Where it runs.** `api` stores a snapshot with its clamped VV and store sequence, and queues the item; it never deletes or drops. `worker` applies R1 and R3 to that item in one transaction under the account lock, recomputed from the current state (ADR 0010 §1). `worker` lag delays deletion only; it never breaks R1 or R3.

Why the rules hold:
- **Owner rules 1 and 3.** R1 deletes only behind a retained snapshot, and R3 never leaves a bodiless header without one, so it never drops a sole cover. §4 serves it.
- **One faulty device never holds the only server copy** of a deleted body: R1 needs covers by two authors, and R3 keeps two authors' covers of it. f faulty devices need f + 1 authors. A header a healing request stored without its body can have the healer's cover alone (owner decision 8).
- **Linear histories.** When each snapshot's covered VV is ≥ that of the one stored before it, R1 deletes what ADR 0012 deleted, the ops the older of the two newest covers, once two authors cover them. An item snapshotted by one device only is never compacted (owner decision 1).
- **No cover, no deletion.** An op keeps its body unless the older of the two newest and snapshots by two authors cover it: ops after that snapshot, ops stored after the snapshots that claim them, and every op of an item with fewer than two snapshots or authors.

### 4. Fetch (owner rule 2)

A response to a cursor carries, besides what ADR 0012 §7 "Fetch" keeps:
- **Bodiless headers.** Each comes as its signed header with its two hashes.
- **Covers** (owner decision 1). For each item with a bodiless header in the response, the server takes that item's retained snapshots newest first. It adds each one that covers a bodiless header of the item in the response that the snapshots added so far cover by no author, or by one author other than its own. Each comes as its full record: header, envelope, signature and, if held, its wrap. Each page of a paged response carries its own covers.
- **One consistent read.** The headers, bodies and snapshots of one response come from one read transaction: SQLite in WAL mode, a read-only `REPEATABLE READ` transaction on PostgreSQL (L: engine documentation, not re-read for this ADR). A response never holds a bodiless header without a retained snapshot that covers it.
- **A bodiless header without a retained cover** means a bug or a damaged database. The server serves the header alone and logs an integrity error naming the vault, item and dot, never content. The client's chain check reports missing data (ADR 0012 §7).

### 5. Cases

- **Concurrent purges.** The server cannot tell a tombstone snapshot from a live one, so the rules apply unchanged. P_A and P_B keep their bodies until snapshots by two authors cover them, and §4 serves covers for every bodiless header: no false gap. Once the two newest snapshots, by two authors, cover both purges, R1 deletes the purge bodies and R3 drops T_A and T_B.
- **Late edits from a device that never returns.** The edits keep their bodies until retained snapshots by two authors cover them, and R3 then keeps those covers, so a server copy remains whether or not S_L stays.
- **Oversize items** ([ADR 0018](0018-item-record-encoding.md), Item-record encoding) write no snapshot. Nothing covers their ops, so every body stays, except behind held snapshots a healing request re-publishes (§9).
- **Snapshots that claim dots the server does not hold** (restore healing, ADR 0012 §7) are refused outside a healing request (owner decision 4; §9 "Server acceptance"). ADR 0022 parks ADR 0012 §10's On-device → Server upload; an ADR that revives it decides how the upload meets this rule ([ADR 0018](0018-item-record-encoding.md) owner decision 16).

### 6. Storage bound

| Quantity | Bound |
|---|---|
| Retained snapshots per item | The two newest, plus each older one R3 keeps for two-author cover; an honest race adds one per concurrent writer until later snapshots by two authors cover its ops. A faulty device can pin more: no per-item cap in M1 (owner decision 2); the account storage quota bounds their bytes ([THREAT_MODEL](../THREAT_MODEL.md) A15, §7.6) |
| One snapshot | Plaintext ≤ 16 MiB ([CRYPTO.md §9.1](../CRYPTO.md#91-symmetric-envelope-algorithm-0x01)) |
| Op bodies kept per item | At least ADR 0012's (about 33–65 under the 32-op trigger): every op not covered by both the older of the two newest and snapshots by two authors. Every op of an item snapshotted by one device only (owner decision 1) |
| Signed op headers | Kept for the life of the vault, about 225 bytes plus 24 per causal-context entry (ADR 0012 §7), on the server and now on clients (§9 "Headers kept") |
| Added per snapshot | Its clamped VV (2 bytes plus 24 per entry) and its store sequence (8 bytes); per server database, the restore generation (16 bytes) |

No new metadata: the clamped VV and store sequence derive from covered VVs, heads and upload order, which the server already sees (ADR 0012 §11).

### 7. Where the code lives

- **`rizzy-sync`, module `compaction`:** pure functions for §2–§4. No I/O; it builds for wasm32 (ADR 0012 §13, ADR 0016). Input: one item's retained snapshots (store sequence, clamped VV, author) and its op dots, each with a body flag. Output: the bodies to delete, the snapshots to drop, and the covers for a response.
- **`rizzy-domain-vault`:** the clamped-VV and store-sequence columns, in one forward migration per engine (ADR 0011 "Migrations"); the store transaction; Fetch; the compaction job.
- **`rizzy-server`** wires the job into `worker` (ADR 0010 §1).

### 8. Tests

The tests run in the ADR 0012 §12 harness, whose simulated server calls `rizzy-sync::compaction`. An independent brute-force checker, written from §2–§4 rather than from that module, checks the server properties.

- **Generated histories,** beyond ADR 0012 §12's: snapshots from several devices in every interleaving (the 32-op trigger, concurrent purges, late edits); a snapshot uploaded before ops it covers; snapshots that claim unheld dots, up to `u64::MAX`; oversize items; restores followed by healing requests, re-uploads and revocations; `worker` paused, then resumed; fetches from a cursor behind the head at every step.
- **Server properties,** after every step, whether or not `worker` has run:
  1. every bodiless header has a retained cover;
  2. no snapshot covers an op stored after it;
  3. every response carries, for each bodiless header, a snapshot whose clamped and covered VVs both cover it;
  4. after `worker` runs, R3 keeps every retained snapshot outside the two newest;
  5. in a linear history, after `worker` runs, the bodiless headers are those R1 deletes behind the older of the two newest, and the headers a healing request stored without a body.
- **Client properties,** with compaction on: ADR 0012 §12 properties 1 (convergence), 2 (no silent loss) and 7 (gap detection). Against the honest server, no device reports missing data.
- **Named scenarios** (Context): T_A then T_B, and T_B then T_A, with a device that was behind fetching after each upload: no gap is reported. S_L with 33 late edits, two tombstone snapshots that miss them, L never returning, then a new device: the new device ends with the edits.
- **Storage,** on SQLite and PostgreSQL (ADR 0011): the store and compaction transactions; a Fetch racing a compaction never returns a bodiless header without a cover, over 1,000 runs; the restore drill checks server property 1. **Budget:** as in ADR 0012 §12.

### 9. Upload, restore healing and revocation (owner decisions 4–7, 9)

Each label that §1 names is the full text replacing that part of ADR 0012; the others are rules this ADR adds.
- **Headers kept.** Clients keep every signed op header they receive or write, with both hashes and the signature, for the life of the vault, and every snapshot record they wrote or absorbed.
- **Server behind.** A device finds the server behind when the server's `state_seq` is lower; or a head h(V, d) is below the device's cursor or item-VV entry for d, or, for the device itself, below its highest acknowledged `device_seq`; or the server lacks an item-key wrap the device got from it or had acknowledged. Each entry is capped at d's known revocation cut-off. The device leaves read-only once none holds.
- **Healing request.** Step 4 is one request per vault, atomic under the account lock: every item-key wrap the server lacks, then per chain from h + 1 up to the device's cursor, capped at a known cut-off, every header the device holds, with its body if it holds the body of a record the server stored before, else without it behind the request's fresh snapshot or a held snapshot sent verbatim. An own op never acknowledged takes the normal upload path unless the server may have stored and served it ("Stale epoch"). An oversize item gets no fresh snapshot: the request carries verbatim the held snapshots that cover its pruned ops, the ops they cover without their bodies, and every retained op with its body (ADR 0018 owner decision 12).
- **Server acceptance.** The server stores a bodiless header only inside a healing request whose snapshots cover it, clamped after the request's headers, else it refuses the whole request. Outside a request it refuses a snapshot whose covered VV exceeds its heads, counting a revoked device's entry only up to its `last_accepted_device_seq`.
- **Already stored.** An upload byte-identical to the record the server stores at that (`vault_id`, `device_id`, `device_seq`), or with that `snapshot_id`, is answered "already stored" before the `vault_prev_seq` and stale-epoch checks, and nothing is stored; the client treats it as an acknowledgement. A different record at a stored dot is refused as a conflict. Otherwise the server rejects an op whose `vault_prev_seq` is not the last op it holds from that device in that vault.
- **Stale epoch.** Under the account lock the server rejects an op or snapshot whose `vault_key_epoch` is below the vault's current epoch ("stale epoch"), except a bodiless header or a record re-published verbatim in a healing request, and a revoked device's op with `device_seq` ≤ `last_accepted_device_seq`, whoever uploads it. The client then processes the new `account-state` ([CRYPTO.md §11.3](../CRYPTO.md#113-unlock-on-an-enrolled-device) steps 3–4) and applies the writer rule. It re-issues, with the same `device_seq`, only an op the server rejected itself as stale, with the later old-epoch ops of its chain, and never one the server may have stored and served: one acknowledged, or one whose upload got no answer before the restore generation (§2) changed. It re-publishes such an op in a healing request. A stale answer to a snapshot only discards and rewrites it.
- **Revoked and kind-4 authors.** A snapshot by a revoked or kind-4 device is accepted only if its covered-VV entry for its author is at most that device's last accepted `device_seq`; the server refuses new ones after the author's revocation or expiry, and keeps counting retained ones as covers. The server refuses any snapshot whose covered-VV entry for its author is above that author's head. After a complete Fetch, a client whose cursor for a revoked device is below that device's `last_accepted_device_seq` reports missing data (INV-27; one vault per account in M1, per vault from M9).
- **Rotation cut-off** (ADR 0012 §6; [CRYPTO.md §11.6](../CRYPTO.md#116-key-rotation) step 9). A snapshot is "beyond that cursor" when its clamped VV exceeds the cursor, so a snapshot that claims unheld dots never blocks a rotation.
- **Restored-server revocation.** Only a misbehaving server can make a replica hold an op past the cut-off, and a revocation signed on a restored server whose head for the device is below ops some replica applied counts as one: detected and reported, not converged (owner decision 7).

### Settled by the merge spike

The owner moved the client-side edge cases to the executable Rust spike [`spikes/merge-model`](../../spikes/merge-model/README.md), which lives outside `crates/` ([README](README.md), "The ADR-first rule") and runs §3, §4 and §9 in its simulated server and clients. A counterexample to a server property reopens this ADR. Its "Results" (`integrated` preset, 2026-09-27) found none in 19 exhaustive families: §8 properties 1–5 hold, 4 and 5 in their two-author form (5 checked independently of `worker` after 2.9 million linear-history `worker` runs; in a linear history R1 reduces to "two authors cover", so a unit test pins the "older of the two newest" clause). The families behind each decision: 1 (`faulty`, `faulty-kinds`, `random-faults*`), 4 and 7 (`restore`, `healing`, `oversize`, `rev-restore`, `random-heal`), 5 (`revocation`, `rev-covers`, `rev-named`, `rev-unsent`), 9 (`reissue`, `random-reissue*`). Client absorption and merged snapshots are ADR 0018 §3 (`absorb`, `snapshots`, `compaction`).

### Owner decisions (2026-09-27)

The owner answered open questions 1–9 as recommended, reopening this ADR beyond its three server rules; the numbers are kept, and the question text is at commit 5ee91c6.
1. **Two covers under concurrency** → yes, reversing the earlier "no": R1, R3 and Fetch require covers by two different authors (§3, §4), and an item snapshotted by one device only is never compacted (§6).
2. **A per-item cap on retained snapshots** → none in M1; the storage quota bounds the bytes. Revisit with M3 data, before M9.
3. **A per-item request for every retained snapshot** → not in M1; the client reports missing data, or "update required" ([ADR 0002](0002-own-protocol.md) point 5).
4. **Snapshots that claim unheld dots** → the healing request, "Server behind" and "Server acceptance" (§9), replacing ADR 0012 §7 "Healing a server rollback" step 4, its read-only condition and "Leaving read-only" (§1) and this ADR's "are stored" (§5); §8 property 5 gains the headers a healing request stored without a body.
5. **Snapshots by revoked and kind-4 devices** → as recommended, with its three added rules (§9 "Revoked and kind-4 authors", "Stale epoch"); the stale-epoch exemption partly supersedes ADR 0012 §7 "Upload". Kind-4 certificates were not modelled.
6. **The rotation cut-off** → §9 "Rotation cut-off".
7. **A revocation signed on a restored server** → an accepted M1 limit: ADR 0012 §6's sentence is partly superseded (§9 "Restored-server revocation"). 44 of the spike's 1,876 random seeds on this path lose a value silently.
8. **A faulty healer as the only cover** → accepted for M1 (142 of 2.6 million random seeds, 101 silent).
9. **Re-uploads and re-issues after a stale answer** → "Already stored" and "Stale epoch" (§9), partly superseding ADR 0012 §7 "Upload", with the restore generation (§2).

Known limits for M1, accepted and each revisited before M9, when the faulty author can be another member ([THREAT_MODEL](../THREAT_MODEL.md) §9): decisions 7 and 8; lies about the content of ops whose bodies are compacted (undecidable; ADR 0018 "Settled by the merge spike" item 4); two or more colluding faulty devices exceed the bound. Until M9 every device is the owner's own.

### On acceptance

This ADR makes none of these edits.
1. **Order.** ADR 0020 is Accepted before this ADR or with it. This ADR is Accepted before any M1 step 3 code is merged (owner decision, 2026-09-26). M1 step 3 is the server step of the M1 plan, which includes op upload and Fetch (`docs/HANDOFF.md` at commit 434d0b3, removed in 6c23c51; V).
2. **ADR 0012 status line** (the owner's act): "Partially superseded by [ADR 0021](0021-server-compaction.md) (§6 in part, §7 in part)", after any earlier entry and separated from it by a semicolon, with any pointer entry ADR 0020 requires. It covers the seven parts §1 lists: the §6 misbehaving-server sentence; in §7, "Upload" (the `vault_prev_seq` sentence and the stale-epoch bullet), the "Fetch" sentence, the "Snapshots and compaction" bullet, and "Healing a server rollback" step 4, its read-only condition and "Leaving read-only".
3. **[docs/adr/README.md](README.md)** (the owner's act): row 0012's Status cell repeats its status line; row 0021 becomes Accepted.
4. **[CRYPTO.md](../CRYPTO.md)**: §10.2's kind-4 rule (c) and §11.8 step 4 gain the snapshot rule of §9 "Revoked and kind-4 authors" (owner decision 5). No other edit: INV-26 and INV-27 hold, THREAT_MODEL §9 carries the accepted limits, and ADR 0010 §1 (`worker` row), ADR 0011 and ADR 0016 §3 read through.

## Consequences

### Positive

- Owner rules 1–3 hold in every interleaving, checked from cleartext VVs and the server's own heads, with no plaintext.
- No false gap after concurrent purges. Late edits from a device that never returns keep a server copy.
- Outside restore healing, one faulty device never holds the only server copy of a body.
- A snapshot that claims future dots deletes nothing stored after it.
- One pure implementation in `rizzy-sync` serves both engines and the test harness.

### Negative

- A clamped VV and a store sequence per snapshot, a `worker` job per snapshot upload, and every op header kept on clients.
- An item snapshotted by one device only is never compacted, and R3 pins leftover snapshots until two authors cover (owner decision 1).
- A response can carry several snapshots of one item.
- A live snapshot with a purged item's full encrypted state stays while it is one of the two authors covering late edits.

### Risks

- **Accepted M1 limits** (Owner decisions, "Known limits for M1"): values can be lost silently, or replicas left unconverged, until the revisit before M9.
- **Client-side trust.** The clamp protects server bodies only. What a client does with a verified snapshot that claims dots nobody holds is ADR 0018 owner decision 14.
- **Pinning.** A faulty device can pin snapshots through R3, up to the storage quota (owner decision 2).
- **Consistent reads** on PostgreSQL rest on `REPEATABLE READ` semantics (L). The race test of §8 is the check.

## Alternatives considered

- **Keep ADR 0012's rule.** False gap and lost server copy (Context).
- **Two covers per deleted body, dominance-based retention and a per-item cap** (the earlier draft of this ADR). It needs a cap, a raised cap after restores and pending-snapshot rules. Owner decision 1 takes two covers, by different authors, without the rest; with one cover (this ADR before it), a faulty sole cover loses values silently.
- **Refuse a snapshot that does not dominate the retained ones.** It refuses honest concurrent snapshots, including the tombstone snapshots of concurrent purges.
- **Serve every covering snapshot.** No selection rule, but steady-state downloads double.
- **Cover by the unclamped covered VV.** A snapshot that claims future dots would delete the bodies of ops stored after it.
- **Keep every snapshot.** Storage grows with every snapshot.

## Open questions for the owner

None open: questions 1–9 are owner decisions 1–9 (2026-09-27), under the same numbers.

## References

- [ADR 0002](0002-own-protocol.md) point 5; [ADR 0010](0010-server-shape.md) §1, §2; [ADR 0011](0011-storage.md) (transactions, migrations, backups); [ADR 0012](0012-sync-engine.md) §3, §4, §6, §7, §10–§13; [ADR 0016](0016-workspace-layout.md) §3
- [ADR 0018](0018-item-record-encoding.md) (Item-record encoding: canonical binary layout and the M1 item schema, Proposed); [ADR 0020](0020-partial-supersession.md) (Record architecture decisions, with partial supersession, Proposed)
- [THREAT_MODEL](../THREAT_MODEL.md) §5.8, §7.6, §9, A15, G-1, INV-26, INV-27, INV-59
- [CRYPTO.md](../CRYPTO.md) §8.4, §9.1, §10.2, §11.3, §11.6, §11.8
- The M1 step list in `docs/HANDOFF.md` at commit 434d0b3, removed in commit 6c23c51 (V)
- PostgreSQL documentation, transaction isolation (`REPEATABLE READ`); SQLite documentation, WAL mode (L: not re-read for this ADR)
- The merge spike, [`spikes/merge-model/README.md`](../../spikes/merge-model/README.md), "Results" (`integrated` preset, run on 2026-09-27; figures as reported there, not re-run for this ADR)
