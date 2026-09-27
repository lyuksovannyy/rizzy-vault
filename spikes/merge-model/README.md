# merge-model: an executable model of the sync merge (spike)

## Purpose

[ADR 0018](../../docs/adr/0018-item-record-encoding.md) ("Settled by the merge spike") and
[ADR 0021](../../docs/adr/0021-server-compaction.md) ("Settled by the merge spike") leave merge
edge cases to "an executable Rust spike, an exhaustive permutation model of the ADR 0012 §12
properties". This is that spike. It explores op and snapshot delivery orders, exhaustively for
small scenario families and with seeded random schedules for larger ones, and checks
[ADR 0012](../../docs/adr/0012-sync-engine.md) §12 properties 1-3:

1. convergence to identical canonical state,
2. no silent loss,
3. permutation independence.

The questions it answers:

- **ADR 0018 item 1 / ADR 0021 bullet 1 (answer 1):** absorbing a snapshot whose covered VV is
  concurrent with the local VV, live or tombstone on either side, and when a replica writes a
  merged snapshot.
- **ADR 0018 item 2 / ADR 0021 bullet 2 (answer 2):** restore healing: which ops and snapshots a
  healing device re-publishes, and which VV "Healing a server rollback" and "Leaving read-only"
  compare.
- **ADR 0018 item 3 / ADR 0021 bullet 3 (answer 3):** ops (a Purge in particular) re-issued after
  a stale-epoch rejection, `item_key_id` included, and a byte-identical re-upload after a lost
  response.
- **ADR 0018 item 4 / ADR 0021 bullet 4 (answer 4):** verified but dishonest snapshots: one that
  omits a value, one that claims dots nobody holds, and the states ADR 0018 §5 accepts that no
  honest merge produces.
- **ADR 0021 bullet 6 (answer 5):** revocation of a device whose ops survive only inside another
  device's snapshot.

Each question was first answered in its own copy of this model. The rules the five answers chose
are now integrated here, with their conflicts resolved, as the `integrated` configuration.
[Results](#results) gives, per question, the rule, what it changes, the evidence, and what stays
open.

What this spike is not:

- It is spike code (ADR 0020 point 6; [docs/adr/README.md](../../docs/adr/README.md), "The
  ADR-first rule"). It lives outside `crates/`, has its own Cargo workspace (an empty
  `[workspace]` table), is never a dependency of anything, and CI does not run it.
- It uses `std` only, has no external crates and forbids `unsafe`.
- It encrypts nothing. Signatures, AEAD and key wraps are modelled as always valid, and a key
  wrap is modelled only as "this key id is known".
- Its proposed rules are proposals. Nothing here edits an ADR; the rule texts in Results are for
  the owner to place.

## What is modelled

| Part | Model |
|---|---|
| Item | One item. Field keys are short strings (`a`, `b`, `@lifecycle`). Values are small integers. |
| Devices | 2-5 devices. Each has an HLC, a gap-free `device_seq`, an item VV, a causal-delivery buffer, an outbox, retained ops, the newest-snapshot state, held snapshots and snapshot records, every signed op header it verified or wrote, a Fetch cursor, the item keys it knows, a known vault epoch and known revocations. |
| Ops | Field writes with `Active`, Trash, Restore and Purge (no writes). Each op carries a causal context equal to the author's VV, an HLC, `vault_key_epoch`, `key_id` and, on the first op under a fresh key, the wrap. |
| Merge | ADR 0012 §4 steps 1-4 on multi-value registers, history with deterministic pruning to N (default N = 2, `--hist`), §5 lifecycle ("Active wins" at display), and ADR 0018 §3 tombstones: the recorded purge, `c`, `item_key_id`, late values, "Applying" 1-3. Under `integrated` the same merge runs as a join (the evidence merge, answer 4), which equals it on every honest state. |
| Canonical state | A deterministic string (keys sorted bytewise, dots sorted, canonical VV). It stands in for ADR 0018 §4 `data` plus the covered VV; two states are equal when their strings are equal. |
| Snapshots | A device writes its state with covered VV = its VV (explicitly, or on the ADR 0012 §7 triggers: after a purge, the writer rule, or more than 32 ops; under answer 1 also after a concurrent absorption). A receiver absorbs through a pluggable `AbsorbStrategy` (`src/absorb.rs`) or the evidence merge. Whatever the strategy, an absorption whose result would lower the item VV is rejected and reported, never applied (ADR 0012 §7 "Freshness", INV-25). |
| Server | ADR 0012 §7 upload rules (revocation cut-off, suspension, `vault_prev_seq`, stale epoch), ADR 0021 §2-§4 (clamped VV, store sequence, R1, R3, Fetch covers), bodiless headers kept, a checkpoint and restore (rollback) with a restore generation. The answers' server rules are knobs: healing requests, refusal of unheld claims, two-author covers, the revoked author's rules. |
| Keys | Item key ids encode `created_vault_key_epoch`. Rotation and revocation bump the vault epoch. The CRYPTO.md §11.6 writer rule and reader rule are modelled, and so is the stale-epoch re-issue. |
| Faulty clients | A device can upload a verifying snapshot built by one of 14 fault kinds (`replica.rs` `Fault`): omissions, claims, the ADR 0018 §5 states no honest merge produces, and lies about a compacted op's kind, writes, `c` or `item_key_id`. Each passes the §5 parse rules. The author's own state and ops stay honest. |
| Revocation | ADR 0012 §6 in two phases: the revoker syncs, suspends (H = the server's head), fetches, then revokes with rotation. A lost device can be revoked. The §6 "removes the op and recomputes" path is modelled (knob `past-cutoff`). |
| Oversize | ADR 0018 §10, scaled down: a register holding more than `max_values` values makes the item oversize, and no snapshot is written. |

## ADR rule → code map

| Rule | Source | Code |
|---|---|---|
| Dot, VV, "covered" | ADR 0012 §2 | `types.rs` `Dot`, `VV::covers` |
| Canonical VV order | ADR 0012 §3 | `types.rs` `VV` (BTreeMap order) |
| HLC update, skew guard | ADR 0012 §2 | `replica.rs` `tick_local`, `tick_recv` |
| Causal context = author's VV | ADR 0012 §2 | `replica.rs` `author` |
| Op = one save; marker as a write to `@lifecycle` | ADR 0012 §3; ADR 0018 §3 "Op (a)", "Lifecycle" | `types.rs` `Op::writes_with_lifecycle` |
| Key wrap on the first op under a new item key (also after a snapshot carried it) | ADR 0012 §3 "Key wrap" | `replica.rs` `first_op_wrap` |
| Verify first: revocation cut-off | ADR 0012 §4 step 1; CRYPTO.md §11.8 step 4 | `replica.rs` `deliver`, `process_response`, `learn_revocation` |
| Deliver causally (context and `vault_prev_seq`) | ADR 0012 §4 step 2 | `replica.rs` `drain_pending` |
| Reader rule (wait for the key's wrap; a wrap arriving later releases the op) | CRYPTO.md §11.6 | `replica.rs` `drain_pending`, `process_response`; `absorb` for snapshots |
| Ignore duplicates | ADR 0012 §4 step 3 | `item.rs` `Item::apply`; `replica.rs` `deliver` |
| Write steps 4.1-4.3 | ADR 0012 §4 step 4 | `item.rs` `Item::apply` (live branch) |
| History, deterministic pruning to N | ADR 0012 §5; ADR 0018 §3 "History" | `item.rs` `Item::apply`, `prune` |
| Active wins (display) | ADR 0012 §5 "Trash" | `item.rs` `Item::shown` |
| Purge only on trashed items (writer) | ADR 0012 §5 | `replica.rs` `author` |
| No purge over an unapplied record | ADR 0018 §11 | `replica.rs` `author` |
| A Purge is never rejected | ADR 0018 §3 | `item.rs` `Item::apply` |
| First Purge on a live item | ADR 0018 §3 "Applying" 1 | `item.rs` `Item::apply` |
| Purge on a tombstone: `c` join, recorded purge, filter | ADR 0018 §3 "Applying" 2, "Recorded purge", "Context" | `item.rs` `Item::apply`, `PurgeRec::rank` |
| Other op on a tombstone: late values | ADR 0018 §3 "Applying" 3, "Late values" | `item.rs` `Item::apply` |
| `item_key_id` from the recorded purge's envelope | ADR 0018 §3 "Recorded purge" | `item.rs` `PurgeRec` |
| Canonical form, state hash | ADR 0018 §4 | `item.rs` `Item::canon` |
| Snapshot parse checks (rules 2, 3, 5-8, as far as the model's states reach them) | ADR 0018 §5 | `item.rs` `Item::validate_snapshot` |
| Oversize: no snapshot | ADR 0018 §10 | `item.rs` `Item::oversize`, `replica.rs` `write_snapshot` |
| Snapshot triggers | ADR 0012 §7; ADR 0018 §10 | `replica.rs` `author` |
| Writer rule (fresh item key, snapshot) | CRYPTO.md §11.6 | `replica.rs` `writer_key`, `author`, `write_snapshot` |
| Stale-epoch rejection, re-issue with the same seq | ADR 0012 §7 "Upload" | `server.rs` `store_op`; `world.rs` `upload_n`; `replica.rs` `reissue_outbox` |
| Upload in order, `vault_prev_seq` check | ADR 0012 §7 "Upload" | `world.rs` `upload_n`, `server.rs` `store_op` |
| Suspension, H, two-phase revocation | ADR 0012 §6; CRYPTO.md §11.8 | `world.rs` `exec` (`Act::Revoke`), `server.rs` `store_op` |
| Rotation cut-off | ADR 0012 §6; CRYPTO.md §11.6 step 9 | `world.rs` `rotation_refused`, `exec` (`Act::Rotate`, `Act::Revoke`) |
| ADR 0012 §6 remove and recompute, else flag | ADR 0012 §6 | `replica.rs` `learn_revocation`, `recompute_without` (base state `Replica::base`) |
| Clamped VV, store sequence | ADR 0021 §2 | `server.rs` `store_snap` |
| R1 delete, R3 retain | ADR 0021 §3 | `server.rs` `compact`, `needed` |
| Fetch: bodiless headers and covers | ADR 0012 §7 "Fetch"; ADR 0021 §4 | `server.rs` `fetch` |
| Server properties 1-5 | ADR 0021 §8 | `server.rs` `check_props` (3 in `fetch`) |
| Chain check after compaction: a bodiless header counts only against a snapshot the replica accepted | ADR 0012 §7; INV-27 | `replica.rs` `process_response` (two passes) |
| Freshness: an absorption that would lower the item VV is rejected, never applied | ADR 0012 §7 "Freshness"; INV-25 | `replica.rs` `absorb`; `check_mono` (P4, which must never fire) |
| Rollback detection, read-only, healing steps 2-4, leaving read-only | ADR 0012 §7 "Healing a server rollback"; THREAT_MODEL §5.8 | `world.rs` `server_behind`, `fetch`, `heal` |
| Restore keeps stored values and counter | ADR 0021 §2 | `world.rs` `exec` (`Act::RestoreServer`) |
| Properties 1-3 (+ ADR 0018 §12 form of 2) | ADR 0012 §12; ADR 0018 §12 | `check.rs` |
| Answer 1: merged snapshot after a concurrent absorption; the two-snapshot basis until then | ADR 0021 "Settled" bullet 1; ADR 0012 §6 | `replica.rs` `absorb`, `after_absorb`, `process_response` |
| Answer 1: absorbing is an HLC receipt | ADR 0012 §2 | `replica.rs` `after_absorb`; `item.rs` `max_hlc` |
| Answer 2: clients keep every signed op header and their snapshot records | ADR 0012 §7 (headers kept for the life of the vault) | `replica.rs` `headers`, `held_records`, `body_of` |
| Answer 2: the healing request (headers above the head, bodiless under the fresh snapshot, wraps, held covers; atomic; per-chain bodies first) | ADR 0012 §7 healing step 4, "Who may upload"; ADR 0021 §2-§3; ADR 0018 open question 12 | `world.rs` `heal_headers`, `heal_bodies`; `server.rs` `heal_request` |
| Answers 2 and 4: the healing request sends the body it holds of a record stored before, and leaves an own never-acknowledged op to the normal upload path | ADR 0012 §7 healing step 4; ADR 0021 §3 (two authors) | `world.rs` `heal_headers` (`heal_prefer_bodies`) |
| Answer 2: "server behind" compares both VVs, capped at cut-offs, and detects a lost wrap | ADR 0012 §7; ADR 0012 §6 | `world.rs` `server_behind` |
| Answer 2: refuse a snapshot that claims dots above the heads (a revoked device's entry capped at its cut-off) | ADR 0021 §5, open question 4 | `server.rs` `store_snap` |
| Answers 2 and 3: a stale answer to an op that may have been stored and served re-publishes it | ADR 0012 §7 "Upload" | `replica.rs` `must_republish`; `world.rs` `upload_n` |
| Answer 3: the author patches its state; covering unsent snapshots dropped; own-answer scope; wrap moved | ADR 0012 §7 "Upload"; ADR 0018 §3 "Recorded purge"; ADR 0012 §3 "Key wrap" | `replica.rs` `reissue_outbox`, `patch_local` |
| Answer 4: evidence merge (header clamp, supersession only by a verified header's context, absence is not evidence, a covered op body still merges) | ADR 0012 §2, §4 steps 3-4, §5; ADR 0018 §3 | `item.rs` `em_join`, `maximal`, `restrict`, `singleton`; `replica.rs` `absorb_evidence`, `apply_now`, `deliver` |
| Answer 4: refuse a snapshot an op body contradicts; report disputes; no snapshot while disputed | ADR 0018 §3 | `replica.rs` `absorb_evidence`, `learn_body`, `write_snapshot` |
| Answer 4: two-author covers (R1, R3, Fetch) | ADR 0021 §3-§4, open question 1 | `server.rs` `compact`, `needed`, `fetch`, `check_props` (SRV-6) |
| Answer 5: a revoked author's snapshot accepted if its own entry is within the cut-off | ADR 0012 §4 step 1; ADR 0021 open question 5 | `replica.rs` `absorb` |
| Answer 5: server refuses a snapshot claiming its author's unstored dots; no stale-epoch refusal for a revoked author's op within its cut-off | ADR 0021 §2, §5; ADR 0012 §7 "Upload" | `server.rs` `store_snap`, `store_op` |
| Answer 5: a revoked device's chain must reach its `last_accepted_device_seq` | ADR 0012 §7 chain check; INV-27 | `replica.rs` `process_response` |

## Configurations

Each configuration picks one reading per ambiguous passage (`src/config.rs`). Use `--config`, and
`--set key=value,...` to flip single knobs of a preset (keys in the first column).

| Knob (`--set` key) | `literal` | `literal-dominate` | `join` | `candidate` | `integrated` |
|---|---|---|---|---|---|
| Snapshot absorption, INV-25 applies to all (`absorb`) | replace + replay retained ops | take only a dominating snapshot | DVV join | DVV join | evidence merge (answer 4) |
| Merged snapshot after a concurrent absorption (`merged`) | no | no | no | no | yes (answer 1) |
| Absorbing is an HLC receipt (`hlc-absorb`) | no | no | no | no | yes (answer 1) |
| Author's state after a re-issue (`reissue`) | keep | keep | keep | patch | patch (answer 3) |
| Drop unsent snapshots covering a re-issued op (`snapdrop`) | no | no | no | yes | yes |
| What a stale answer re-issues (`scope`) | whole outbox | same | same | same | the rejected op and later ones (answer 3) |
| Move a fresh key's wrap to the first op under it after a re-issue (`movewrap`) | no | no | no | no | yes (answer 3) |
| Byte-identical re-upload (`dedup`) | "already stored" first | same | same | same | same |
| Stale answer to an op that may have been stored (`stale-sent`) | re-issue | re-issue | re-issue | re-issue | re-publish if acknowledged or lost before a restore (answers 2+3) |
| "Server behind" / "leave read-only" compares (`cmp`) | item VV | item VV | item VV | Fetch cursor | both, capped at cut-offs (answer 2) |
| Healing step 4 (`heal`) | own ops | own ops | own ops | own + retained ops | healing request (answer 2) |
| Per-chain re-publication of held bodies first (`bodies`) | no | no | no | no | yes (answer 2) |
| Healing request sends a held body rather than a bodiless header (`bodyfirst`) | no | no | no | no | yes (answers 2+4) |
| Verbatim re-published record vs stale-epoch check (`exempt`) | checked | checked | checked | checked | exempt (answer 2) |
| Snapshot claiming dots above the heads (`claims`) | stored | stored | stored | stored | refused, revoked entries capped (answers 2+5) |
| A lost wrap makes the server "behind" (`wraps`) | no | no | no | no | yes (answer 2) |
| Own op bodies kept for healing (`keepown`) | since newest snapshot | same | same | all | since newest snapshot |
| Server compaction rule (`server`) | ADR 0021 | ADR 0021 | ADR 0021 | ADR 0021 | two authors (answer 4) |
| Revoked author's snapshot (`revoked-snap`) | not checked | not checked | not checked | not checked | accepted within the cut-off (answer 5) |
| Ops past a cut-off (`past-cutoff`) | flag | flag | flag | flag | recompute, else flag (answer 5) |
| Server refuses a snapshot claiming its author's unstored dots (`author-head`) | no | no | no | no | yes (answer 5) |
| No stale-epoch refusal for a revoked author's op within its cut-off (`exempt-revoked`) | no | no | no | no | yes (answer 5) |
| A revoked device's chain must reach its cut-off (`chain-cutoff`) | no | no | no | no | yes (answer 5) |

`literal` and `literal-dominate` are the two literal readings of absorption. `join` changes only
absorption. `candidate` is the model's earlier candidate, before the five answers. `integrated`
switches on every rule the answers chose. Other values: `claims=refuse-strict` (answer 2's refusal
without the cap), `stale-sent=republish` (answer 2's rule alone), `server=none` (no compaction),
`revoked-snap=reject` (the literal reading), `faults=decidable|undetectable` (random faulty
flavours).

## Properties checked

Checked at quiescence. After each schedule, a drain runs: every active device uploads and
fetches, and `worker` runs, until nothing changes. `check.rs` holds the precise definitions.

- **U, the universe of ops:** the version the server stored last of every op it stored at some
  point, plus every op of a still-active device. Excluded are ops of a revoked device past its
  cut-off (cut-offs from the server and the active devices only), and ops a lost device never
  uploaded.
- **LOSS** (side condition): an op of U that no surviving party can supply any more (only lost
  devices and a restored-away server state had it). No rule can bring it back, so it is reported
  apart and left out of P2 and P1-ref, with the ops that causally depend on it.
- **P1:** all active devices hold the same canonical state. The kind says `[silent]` when some
  device that differs from the op-based state raised no report, `[reported]` otherwise, and names
  the fault classes stored when faulty snapshots were stored.
- **P1-ref:** that state equals the one a fresh replica reaches from U by ops alone.
- **P2, no silent loss:** at each active device, every value written by an op in U (the
  `@lifecycle` marker included) is accounted for:
  - it is a current value or a history entry;
  - it was superseded by a causally later write of the same key that the device applied, and its
    history group holds N entries ranked above it (deterministic pruning);
  - on a tombstone, it is a late value; or, through a real Purge in U that the device covers, `c`
    covers it, or it was superseded (ADR 0018 owner decision 9), or its key is `@lifecycle`;
  - it is reported: the op waits in the causal buffer, or an op there names its dot in its
    context (ADR 0012 §4 step 2), or a Gap at or below its seq, a rejection, a Dispute or a
    ClaimCut names it, or a Dispute names the tombstone's purge.
- **P3 (ops):** a fresh replica fed U in every order (all orders up to 6 messages, else a fixed
  number of seeded orders: 60 exhaustive, 30 random, 40 on replay), with duplicates, always
  reaches the same state.
- **P3-mixed:** the same with U plus every honest, untainted snapshot the server stored (tainted:
  its author had absorbed a faulty snapshot). It must also equal the P3 (ops) state.
- **P3-faulty** (answer 4): U plus every stored snapshot, faulty ones included, in every order,
  reaches one state (not necessarily the P3 state): the merge is a function of the set of records.
- **Answer checks** (printed next to P1-P3):
  - RT: the ops as stored produce the state of the ops as authored (a re-issue changes only the
    envelope);
  - FORK: no dot was stored in two signed versions;
  - KEY: no op the server never stored got past the stale-epoch check through an exemption;
  - RECOMP: the newest snapshot plus the retained ops rebuild the item (ADR 0012 §6);
  - HLC: an op's HLC is above that of every op its causal context covers (ADR 0012 §2), for
    authors whose clock is not skewed.
- **Side conditions:** P4 (INV-25; must never fire), GAP (missing data reported; ADR 0021 §8
  expects none against an honest server), DISPUTE (the evidence merge reported that two sources
  disagree), LIVE (stuck causal buffer, blocked upload, a device still read-only, a flagged item,
  a heal re-publish that stays blocked, a drain that hit its round cap), SRV (ADR 0021 §8 server
  properties 1-5, and SRV-6 under the two-author rule), PIN (more than two snapshots retained at
  quiescence under ADR 0021's rule; informational), NOTE (for example a snapshot rejected).
- **Run labels.** Three classes of run get a suffix on their P1-P3 kinds, so that each kind's
  minimal trace is one of its class:
  - "[... ADR 0012 §6 path]": a replica holds or flagged an op past a revocation cut-off, or some
    op's context covers such a dot (LIVE and GAP kinds too). Only a revocation signed on a
    restored server gets there;
  - "[a healed header's only covers are by a faulty author]": a Fetch served, or the server ends
    with, a header a healing request stored without its body whose covers were all written by
    devices that wrote faulty snapshots (the conflict of answers 2 and 4);
  - "[two or more faulty authors]": two devices stored faulty snapshots, beyond the f + 1 bound of
    two-author covers.
- **Cause breakdown.** Each report splits the schedules with a P1-P3 violation by what they
  contained: a restore, a revocation, a faulty snapshot, a re-issue.
- **Coverage counters** (printed per run) show which rules a family reaches: compaction,
  absorptions by kind, merged snapshots, healing requests, re-issues, faulty snapshots stored,
  evidence refusals and disputes, revocation paths.

## Exploration

- **Exhaustive** (`src/explore.rs`). A scenario is a setup prefix plus one program per actor
  (the devices, then the server). Every interleaving of the programs is run at *block*
  granularity. A block is a maximal run of local actions (Write, Trash, Restore, Purge,
  Snapshot, Faulty) that ends with one communicating action (Upload, UploadOnce, UploadSnaps,
  Fetch, Sync, SyncLost, Rotate, Revoke, Lose, or a server action).
  - Local actions touch only their device, and the injected wall clock is per device. Moving
    them to just before the device's next communicating action changes no outcome, so the block
    interleavings reach every outcome of the action-level interleavings. The report prints both
    counts.
  - The interleaving tree is split into subtrees at a shallow depth, which run on all cores and
    are merged in a fixed order. P3 caches are per thread, so the P3 set and replay counts vary
    with the thread count; everything else does not.
  - Scenario families are *enumerators*: each builds scenarios from small per-device option
    menus (`src/scenarios.rs`). A server action in a device's program runs as the server.
- **Random** (`src/random.rs`). For fixed seeds, the explorer builds a random scenario, a random
  action-level interleaving, and random delivery shuffles with duplicates inside each Fetch, all
  from xorshift64. Seeds run on all cores; each stays reproducible alone (`--seed-start S --seeds
  1`, `--events` prints its log, `--seed-list` lists the violating seeds). The flavours:
  - `random`: merge only; `random-ops`: plus rotation, lost responses, revocation and a restore;
    `random-faulty`: plus faulty snapshots (omission and claims);
  - `random-absorb` (answer 1): many snapshots and `worker` runs, a fresh device;
  - `random-heal` (answer 2): a backup and one or two restores in every run, lost and fresh
    devices;
  - `random-reissue` (answer 3): offline edits and purges across rotations, lost responses, some
    restores and revocations; `random-reissue-norestore` without restores and revocations;
  - `random-faults` (answer 4): every fault kind from one faulty device, a fresh device;
    `random-faults-ops` adds rotation, restores, revocation; `random-faults-multi` lets every
    device write faulty snapshots;
  - `random-rev` (answer 5): one revocation at a random point, sometimes of a lost device;
    `random-rev-compromised` adds snapshots claiming the revoked device's next dot;
    `random-rev-restore` adds a restore.
- **Traces.** For each distinct (property, kind), the shortest failing schedule is minimised
  greedily: steps are dropped one at a time while the same violation reproduces. It is then
  replayed with an event log, and the final states and the violation detail are printed.

## AMBIGUOUS

For each passage below, the model implements the most literal reading and marks the code with
`AMBIGUOUS N:`. Where a knob exists, the alternative is named.

1. **Snapshot absorption** is not defined by any ADR (ADR 0018 item 1). Literal reading A
   (`absorb=replace`): ADR 0012 §6's "recomputes the item from its retained ops and snapshots",
   applied to every snapshot. Literal reading B (`absorb=dominate`): take a snapshot only when it
   covers everything local. Answers 1 and 4: the join. INV-25 (Accepted) rejects any absorption
   whose result is below the highest VV accepted; it is not a knob. (`absorb.rs`, `config.rs`)
2. **A dominated snapshot** is a no-op. (`absorb.rs`, `replica.rs` `absorb`)
3. **"Its ops since its newest snapshot"** (ADR 0012 §6): "newest" is the last snapshot the
   device wrote or absorbed, and own ops are pruned the same way (knob `keepown`). Under answer 1,
   after a concurrent absorption the "newest snapshot" is the pair of the previous one and the
   absorbed one until the merged snapshot replaces both. (`replica.rs` `write_snapshot`, `absorb`)
4. **Healing step 4 "its ops"** means the device's own ops (knob `heal`). (`config.rs`, `world.rs`)
5. **"A VV behind its own" / "Leaving read-only"** compare the item VV with the server's heads,
   the own entry by the highest acknowledged seq (knob `cmp`). (`world.rs` `server_behind`)
6. **Healing order and the stale-epoch check.** The steps run in ADR order, and nothing exempts
   a re-published op from the stale-epoch check (knob `exempt`). (`world.rs` `heal`)
7. **Re-issue** keeps the op's HLC, causal context and writes; only `vault_key_epoch`, `key_id`
   and the wrap change. The author changes nothing in its own state (knob `reissue`).
8. **A stale snapshot in the outbox** is dropped; the writer rule's snapshot replaces it.
9. **The snapshot trigger** "first write under a fresh item key" covers rotation-fresh keys only.
10. **The item's "current" wrap** after two devices each made a fresh key is the key with the
    highest (created epoch, id). (`replica.rs` `current_key`)
11. **A byte-identical re-upload** of a stored op is answered "already stored" before the
    `vault_prev_seq` and stale-epoch checks; a different record at a stored dot is a conflict.
    Read literally (`dedup=none`) the `vault_prev_seq` check rejects the re-upload.
12. **Fetch processing order.** Covers are absorbed before bodies are delivered, in served order,
    and only a cover of a bodiless header that passed the first pass of the chain check.
13. **The Fetch cursor** never serves a device its own chain.
14. **ADR 0021 open question 5**, recommendation taken: the server refuses new snapshots from a
    revoked author. (`server.rs` `store_snap`)
15. **"A snapshot of that item, received now or already held"** (ADR 0012 §7 chain check) means
    one the replica accepted. (`replica.rs` `process_response`)
16. **Snapshot triggers** are evaluated when the device authors an op. The 32-op trigger is never
    reached in the explored families.
17. **A revoked author's snapshot** (ADR 0012 §4 step 1: the exception is for "a revoked
    device's op with device_seq <= last_accepted_device_seq"). A snapshot has no device_seq, so
    literally it is rejected (`revoked-snap=reject`). Answer 5 takes ADR 0021 open question 5's
    recommendation. The older presets keep the model's earlier behaviour (not checked).
18. **HLC on absorption.** ADR 0012 §2 applies the HLC rules "on local events and on receipt";
    no ADR says whether absorbing is a receipt. Literal: it is not (knob `hlc-absorb`).
19. **ADR 0012 §6 "If it cannot"**: recomputation is impossible when the replica's newest
    snapshot state already contains an op past the cut-off. Ops whose context covers a removed op
    stay in the causal buffer. (`replica.rs` `recompute_without`)
20. **INV-25 after a §6 recomputation**: the persisted highest VV is reset to the recomputed VV.
21. **The merged-snapshot trigger.** No ADR trigger covers absorption; literal: never (knob
    `merged`). (`replica.rs` `process_response`)
22. **A stale answer to an op that may have been stored** (ADR 0012 §7 "re-issues the edit ...,
    which the server never stored"). Literal: re-issued (knob `stale-sent`).
23. **What a stale answer re-issues** (ADR 0012 §7 "re-issues the edit"). Literal (the model's
    earlier reading): every old-epoch op in the outbox (knob `scope`).
24. **Where a fresh key's wrap sits after a re-issue.** Literal: where it was (knob `movewrap`).
25. **A snapshot claiming a revoked device's dot past its cut-off** is absorbed; the replica then
    takes the ADR 0012 §6 path. Under the evidence merge no dot without a verified header is
    taken, so such a claim is cut and reported. (`replica.rs` `absorb`)

## Model choices (not ADR readings)

- Only device 0 creates the item.
  - A Write on a tombstone models an editor that was open when the purge arrived, so its context
    covers `purge_dot`.
  - Trash, Restore and Purge are offered only for the lifecycle the device shows.
  - A read-only device writes nothing and revokes no one.
- A rotating device fetches first (ADR 0012 §6 cut-off). A revoking device syncs first
  (CRYPTO.md §11.8 step 0 needs an unlocked device with a fresh re-authentication), then
  suspends, fetches, and revokes with rotation in one step. A lost device can be revoked.
- A fresh key's wrap travels with the first uploaded record under it. If that record is dropped
  or refused, the wrap moves to the next record under the key.
- A healing device under `heal=own|retained` writes a fresh snapshot only when its VV changed
  since its last heal snapshot; the healing request (answer 2) always carries a fresh one.
- The healing request is one server call applied atomically, standing for one request under the
  account lock. The server takes the uploader's word that a record re-published verbatim was
  stored before; an honest client only re-publishes records it received or got acknowledged.
- The restore generation (answer 3's condition) is a server counter the restore raises; the
  client learns it with every answer.
- A faulty device's own state and ops stay honest; only the snapshots it writes lie. Taint is
  checker bookkeeping, not part of any record.
- After a stale-epoch re-issue, the writer-rule snapshot is written only when a re-issued op took
  a fresh item key, or to replace a dropped snapshot.
- Values are unique per scenario, so P2 matches by (dot, key).
- A SHA-256 state hash is replaced by string equality of the canonical form.

## Not modelled

- Cryptography, verification failures and item-schema parsing beyond the §5 rules the merge
  relies on.
- Multiple items and multiple vaults. ADR 0012 §7's "withheld op on another item" gap case needs
  a second item, and it is property 7, outside properties 1-3. The Fetch cursor and the item VV
  compare identically with one item; answer 2 did not test where they would differ.
- A revocation cut-off per vault (M9); `chain-cutoff` relies on M1's one vault per account.
- A client that lies in a healing request's "re-published verbatim" claim, and a third author
  with a majority rule for faulty snapshots.
- On-device mode (relay, TTL, pairing), web-vault certificates.
- Paged Fetch responses, `worker` running concurrently with a Fetch, and SQL isolation.

## How to run

The spike uses the repository's pinned toolchain (`rust-toolchain.toml`). Run it from the
repository root:

```sh
# Tests: unit checks of the ADR examples and the answers' rules, and quick family runs pinning
# the findings (~1 min on 10 cores).
cargo test --release --manifest-path spikes/merge-model/Cargo.toml

# Explorer: one family or flavour, every family (exhaustive), every flavour (random-all), or both
# (all). `random` alone is the merge-only flavour.
cargo run --release --manifest-path spikes/merge-model/Cargo.toml -- list
cargo run --release --manifest-path spikes/merge-model/Cargo.toml -- purges --config integrated
cargo run --release --manifest-path spikes/merge-model/Cargo.toml -- exhaustive --config integrated
cargo run --release --manifest-path spikes/merge-model/Cargo.toml -- random-all --config integrated --seeds 200000
```

| Option | Meaning |
|---|---|
| `--config literal\|literal-dominate\|join\|candidate\|integrated\|all` (or a comma list) | Pick a reading (default `literal`). |
| `--set key=value,...` | Flip knobs of the chosen preset (keys in the Configurations table). |
| `--hist N` | History N (default 2). |
| `--quick` | Smaller scenario sets. |
| `--threads N` | Worker threads (default: all cores). |
| `--seeds N`, `--seed-start S` | Random flavours: seeds S..S+N (default 1..501). |
| `--scenario TEXT` | Exhaustive families: only the scenarios whose name contains TEXT. |
| `--order a,b,...` | Replay one block interleaving (the actor of each block) of the first matching scenario, with its event log. |
| `--events`, `--seed-list` | Random: print each seed's event log; list the violating seeds. |
| `--no-traces`, `--max-traces K`, `--only TEXT` | Control the minimised traces (`--only` filters by "[prop] kind"). |

## Results

All numbers are from this integrated model, `--config integrated`, history N = 2, toolchain
1.94.1, run on 2026-09-27, unless a line says "answer N's copy": those are the numbers that answer
reported from its own copy of the model and were not re-run here. "Schedules" are exhaustive block
interleavings, and "seeds" are random runs, seeds 1 to 200,000 per flavour. A P1-P3 violation is a
failure of P1, P1-ref, P2, P3, P3-mixed or P3-faulty. Comparison runs flip one knob of
`integrated` (`--set`) and use 50,000 seeds.

### The full check (`integrated`)

**Exhaustive families** (every block interleaving; `cargo run --release -- exhaustive --config
integrated`):

| Family | Scenarios | Schedules | Action-level interleavings | Schedules with a P1-P3 violation | Side conditions |
|---|---|---|---|---|---|
| concurrent-edits | 36 | 67,080 | 39,793,236 | 0 | none |
| purges | 81 | 12,624 | 830,760 | 0 | none |
| edit-purge | 12 | 2,775 | 117,460 | 0 | none |
| trash-restore | 18 | 13,807 | 1,172,315 | 0 | none |
| snapshots | 20 | 161,280 | 84,028,560 | 0 | none |
| absorb | 18 | 45,360 | 174,982,500 | 0 | none |
| compaction | 3 | 209,520 | 344,194,200 | 0 | none |
| rotation | 5 | 332 | 1,730 | 0 | none |
| restore | 6 | 1,728 | 53,790 | 0 | LOSS 42, SRV-6h 346 |
| healing | 13 | 8,910 | 163,056 | 2, both on the §6 path, reported | LOSS 1,847, SRV-6h 2,220 |
| faulty | 4 | 3,060 | 131,040 | 0 | DISPUTE 168 |
| faulty-kinds | 112 | 150,720 | 21,826,560 | 1,136, all P1, all reported, all with an undetectable fabrication stored | DISPUTE 5,204 |
| revocation | 3 | 402 | 10,420 | 0 | none |
| oversize | 6 | 17,040 | 5,160,960 | 0 | LOSS 240, SRV-6h 282 |
| reissue | 106 | 23,218 | 219,749 | 0 | SRV-6h 1,199 |
| rev-covers | 30 | 351,840 | 243,106,920 | 0 | none |
| rev-named | 3 | 315,000 | 102,148,200 | 0 | none |
| rev-unsent | 8 | 60,480 | 6,625,080 | 0 | none |
| rev-restore | 36 | 104,400 | 4,568,970 | 2,541, all on the §6 path, all reported, P2 0 | SRV-6h 39,660 |
| **Total** | **520** | **1,549,576** | **1,029,135,506** | **3,679** | |

SRV-6h is the side condition "a header a healing request stored bodiless has covers by fewer than
two authors" (the conflict of answers 2 and 4, below). In every exhaustive family P3, P3-mixed,
P3-faulty, RT, FORK, KEY, RECOMP, HLC, P4 and GAP hold, no device stays read-only, and ADR 0021 §8
server properties 1-5 hold.

**Random flavours** (`cargo run --release -- random-all --config integrated --seeds 200000`).
The class columns split the violating seeds by the run label of their P1-ref kind (Properties
checked, "Run labels"); "reported undetectable" is a reported divergence with an undetectable
fabrication stored and no other label.

| Flavour | Seeds | Violating | §6 path | healed header, faulty sole cover | two or more faulty authors | reported undetectable | P2 | Other checks |
|---|---|---|---|---|---|---|---|---|
| random | 200,000 | 0 | | | | | 0 | none |
| random-ops | 200,000 | 138 | 138 | | | | 1 (§6) | FORK 1, RECOMP 2 |
| random-faulty (every device may be faulty) | 200,000 | 157 | 83 | 58 | 16 | | 72 (58 sole cover, 10 two faulty, 4 §6) | FORK 1, HLC 1 |
| random-absorb | 200,000 | 0 | | | | | 0 | none |
| random-heal | 200,000 | 287 | 287 | | | | 5 (§6) | FORK 1, RECOMP 2, LOSS 12,263 |
| random-reissue | 200,000 | 41 | 41 | | | | 5 (§6) | FORK 2 |
| random-reissue-norestore | 200,000 | 0 | | | | | 0 | HLC 1 |
| random-faults | 200,000 | 102 | | | | 102 | 0 | none |
| random-faults-ops | 200,000 | 295 | 137 | 84 | | 74 | 53 (43 sole cover, 10 §6) | FORK 3, RECOMP 2 |
| random-faults-multi | 200,000 | 467 | | | 324 | 143 | 78 (all two faulty) | none |
| random-rev | 200,000 | 0 | | | | | 0 | none |
| random-rev-compromised | 200,000 | 0 | | | | | 0 | none |
| random-rev-restore | 200,000 | 1,190 | 1,190 | | | | 19 (§6) | RECOMP 13 |
| **Total** | **2,600,000** | **2,677** | **1,876** | **142** | **340** | **319** | **233** | |

No violating seed falls outside these four classes, and P3 holds in every seed. The five minimised
FORK and RECOMP traces printed are each a server restore followed by a revocation (the §6 class). The two HLC
findings are answer 1's documented limit (a tombstone does not carry the HLC of a late Restore;
minimal trace in `random-reissue-norestore`, seed 128142) and a faulty-plus-restore run. SRV-6h
appears in every flavour with a restore (for example 30,338 random-heal seeds).

The classes:

- **§6 path** (answers 2 and 5, open): a revocation signed on a restored server whose head for the
  device is below ops other replicas applied. Every divergence there is reported (a flagged item,
  or ops held in the causal buffer), but 44 of the 1,876 seeds also lose a value silently.
- **Undetectable fabrication** (answer 4, open by proof): a faulty device lies about the content of
  an op whose body is compacted. Always reported; P2 and P3-faulty hold.
- **Two or more faulty authors** (answer 4's bound): two faulty devices supply both covers.
- **A healed header's only covers are by a faulty author**: the unresolved part of the conflict
  between answers 2 and 4 (below).

### Answer 1: absorbing a snapshot with a concurrent covered VV

**Rule** (ADR 0018 §3 after "Applying", and §10 "No snapshot"):

> **Absorbing a snapshot.** A replica absorbs a verified snapshot by replacing its state with the
> join of its state and the snapshot's: the state it would reach by applying every op that either
> state covers. The covered VV is the entrywise maximum. [How the join treats records that no
> honest merge produces is answer 4's rule; its join equals this one on every honest state.] A
> snapshot whose covered VV the replica's covers changes nothing. Absorbing is a receipt under
> ADR 0012 §2: the clock receives the highest HLC among the snapshot's values, history entries and
> `purge_hlc`, under the skew guard.
>
> **Merged snapshot.** After a Fetch in which it absorbed a snapshot whose covered VV is concurrent
> with its own, a replica writes and uploads a snapshot of its state once the response's ops are
> applied. The writer rule and the oversize exception apply. Until then, and for good for an
> oversize item, its "newest snapshot" (ADR 0012 §6) is the pair of its previous newest snapshot
> and the absorbed one, and it keeps the ops neither covers.

**Frozen bytes and acceptance.** No ADR 0018 §3-§5 layout, parse rule or §10 limit changes.
Honest converged bytes are the op-by-op state that §3 "Applying" already defines. Acceptance is
unchanged: INV-25 rejected no absorption in any run. The HLC receipt changes the HLC values later
ops carry, not a layout or an acceptance. Whether the merged-snapshot sentence clarifies or partly
supersedes ADR 0012 §6 is the owner's call. The tie-break for one dot carried in two versions,
which answer 1 left open, is settled by answer 4 (the version whose HLC is the verified header's,
then the lower (hlc, value); on one purge dot, the `item_key_id` in the wrap set first).

**Evidence.**
- `absorb` family: 45,360 schedules, 174,982,500 interleavings, 0 P1-P3 violations, 0 GAP,
  RECOMP and HLC. It commits concurrent absorptions of all four kinds (live←live 2,188, live←tomb
  1,758, tomb←live 1,624, tomb←tomb 1,194) and writes 6,764 merged snapshots of 127,724.
- `random-absorb`: 200,000 seeds, 0 violations. Under two-author covers fewer bodies are deleted,
  so the random flavour reaches only 289 concurrent absorptions (answer 1's copy, ADR 0021 server:
  54,725); the exhaustive family is the coverage that counts here.
- The answer's own evidence (answer 1's copy): the DVV join equals the op-union state on
  42,423,312 exhaustive and 6,183,552 random pairs of causal cuts; literal replace fails 20,684
  schedules of its family with 20,924 false gaps; without the merged snapshot RECOMP fails (20,924
  schedules of the family) and the server keeps a third snapshot; without the HLC receipt the
  clock condition fails in 384 schedules. Those ablations are pinned here in
  `tests/families.rs` `answer1_absorption` (the join fails RECOMP, `snapshots` fails HLC without
  the receipt) and `tests/model.rs` `merged_snapshot_keeps_the_item_recomputable`.

### Answer 2: restore healing

**Rule** (ADR 0021, as a partial supersession under ADR 0020 of ADR 0012 §7 "Healing a server
rollback" step 4, "Leaving read-only" and the re-issue sentence of "Upload"; answers ADR 0021 open
question 4 and ADR 0018 open question 12). Changes from the integration are marked.

> 1. **Headers kept.** Clients keep every signed op header they receive or write, with both
>    hashes and the signature, for the life of the vault, as the server does, and every snapshot
>    record they wrote or absorbed. Op bodies are kept only as ADR 0012 §6 already requires.
> 2. **Server behind.** A device finds the server behind when its `state_seq` is lower; or, for
>    another device d, the head h(V, d) is below the device's cursor entry or item-VV entry for d;
>    or, for itself, the head is below its highest acknowledged `device_seq`; or the server lacks an
>    item-key wrap the device received from it or got acknowledged. Each entry is capped at d's
>    known revocation cut-off. It leaves read-only once none of these holds.
> 3. **Healing step 4** is one healing request per vault, atomic under the account lock. It
>    carries every item-key wrap the device holds that the server lacks; then, per device in chain
>    order from h + 1 up to its cursor (its own chain up to its last op; [integration] capped at a
>    known cut-off), every header it holds: [integration] with its body when the device holds the
>    body of a record the server stored before; else without its body when the request's fresh
>    snapshot covers it; else without it when a held snapshot that covers it goes in the request
>    verbatim. An own op never acknowledged [integration] takes the normal upload path unless the
>    server may have stored and served it (answer 3's condition); [integration] the fresh snapshot
>    goes in the request only when a header in it needs a cover, and then covers such own ops
>    without their bodies too. Before the request, the device re-publishes verbatim, chain by
>    chain, the ops whose bodies it holds and which the server stored before; a refusal stops only
>    that chain.
> 4. **Server acceptance.** The server stores a header without a body only inside a healing
>    request whose snapshots cover it (clamped VV computed after the request's headers), else the
>    whole request is refused. The stale-epoch check does not apply to a header without a body,
>    nor to a record re-published verbatim. Outside a healing request the server refuses a
>    snapshot whose covered VV exceeds its heads, [integration] counting a revoked device's entry
>    only up to its `last_accepted_device_seq`. ADR 0021 §8 property 5 gains "and the headers a
>    healing request stored without a body".
> 5. **No second record at a dot.** A client never re-issues an op the server may have stored and
>    served; it re-publishes it as in point 3. [Integration: which ops, see answer 3.]
> 6. **Oversize items.** No fresh snapshot: the request carries the held snapshots that cover
>    pruned ops verbatim, the ops those snapshots cover without their bodies, and every retained
>    op with its body.

**Frozen bytes and acceptance.** No op or snapshot header, no ADR 0018 §3-§5 layout and no
converged byte changes; point 5 prevents a divergence in `item_key_id`. Acceptance changes on the
server only: a new healing-request message with headers without bodies, the stale-epoch exemption
for bodiless headers and verbatim records, and the refusal of snapshots that claim unheld dots
(replacing ADR 0021 §5 "are stored"). Client acceptance is unchanged. New client storage: about
225 B plus 24 B per causal-context entry per op, as on the server.

**Evidence.**
- `restore` (1,728 schedules) and `oversize` (17,040): 0 P1-P3 violations. `healing` (8,910): 2,
  both on the §6 path and reported (minimal: `D0 Write{a=11}; D0 Sync; D2 Fetch; S
  RestoreServer(0); D1 Revoke(D0); D2 Write{b=31}`). No device stays read-only, no false gap, and
  P2 holds in all three. 7,313 healing requests stored in `healing`, none refused.
- `random-heal`: 200,000 seeds, 287 violating, all on the §6 path; P2 fails in 5 of them (answer
  2's copy: 311 §6 seeds with P2 in 41). LOSS (an op only lost devices and a restored-away server
  held) in 12,263 seeds, which no rule can recover.
- Answer 2's copy: the literal reading fails `restore` 785 of 1,728, `healing` 3,927 of 8,910 and
  `oversize` 1,789 of 17,040; each of its parts is needed (`claims=store` healing 23, `wraps=no`
  28, `exempt=no` oversize 6, `republish=no` 12). Re-run here: `--set claims=store` gives 23
  silent-loss schedules in `healing`, and the earlier `candidate` (retained ops, cursor) loses a
  value in `healing` (pinned in `tests/families.rs` `answer2_restore_healing`).

### Answer 3: re-issued ops

**Rule** (ADR 0018 §3, new "Re-issued ops" bullet; ADR 0021 server side):

> A re-issued op (ADR 0012 §7 "Upload") is the same op in a new envelope. It keeps `device_seq`,
> `vault_prev_seq`, `hlc`, the causal context and the op data. Only `vault_key_epoch`, the item key
> picked by the CRYPTO.md §11.6 writer rule (so the envelope's `key_id`), the carried wrap and the
> signature change. The first op under a fresh item key carries its wrap, also when it is a
> re-issued op; a later unsent op under that key drops it. The author holds the re-issued op in
> place of the original: if its tombstone's recorded purge is that op, `item_key_id` becomes the
> re-issued envelope's `key_id`; no other state byte depends on the envelope. The author discards
> every unsent snapshot that covers the op and writes the writer rule's snapshot after this
> change. A client re-issues an op only when the server rejected that op itself as stale, with
> the later old-epoch ops of its chain; a stale answer to a snapshot only discards and rewrites
> that snapshot.
>
> An upload byte-identical to the record the server stores at that (`vault_id`, `device_id`,
> `device_seq`), or with that `snapshot_id`, is answered "already stored" before the
> `vault_prev_seq` and stale-epoch checks, and nothing is stored. A different record at a stored
> dot is refused as a conflict and never replaces the stored one. The client treats "already
> stored" as an acknowledgement.
>
> [Integration, replacing answer 3's unsigned re-publication marker:] A client never re-issues an
> op the server may have stored and served: one it acknowledged, or one whose upload response was
> lost before the server's restore generation changed. It re-publishes such an op as in answer 2
> point 3 (in a healing request, without its body, covered by a fresh snapshot under the current
> key). Any other op answered "stale" is re-issued.

**Frozen bytes and acceptance.** No record layout, parse rule, canonical form or limit changes,
and none to the op header. Settling `item_key_id` for a re-issued purge changes the author's
converged tombstone bytes against the literal reading, so it must land in ADR 0018 before the
version-1 vectors freeze (suggested vector: a purge re-issued under a new key, `item_key_id` = the
re-issued key). "Already stored" changes an answer code only. The integrated re-publication needs
no unsigned marker and never lets a body past the stale-epoch check that the server did not store
before, but it needs a server restore generation that no ADR has (ADR 0012 §7's reconciliation
epoch opened by `rizzy-vault restore`, INV-59, is the nearest existing notion). `op_id` is not
modelled.

**Evidence.**
- `reissue` family: 106 scenarios, 23,218 schedules, 0 P1-P3 violations and 0 RT, FORK and KEY
  (answer 3's copy under its marker rule: KEY 80, restore scenarios, Purge only). It re-issues
  16,476 ops (7,431 Purges); 6,138 schedules end with a tombstone whose recorded purge was
  re-issued; 5,192 re-uploads were answered "already stored".
- `random-reissue-norestore`: 200,000 seeds, 0 violations (one HLC finding, answer 1's limit).
  `random-reissue`: 41 violating, all on the §6 path.
- Answer 3's copy: the literal author diverges on `item_key_id` (6,000 schedules), no dedup loses
  ops silently (564), dedup after the stale check diverges (1,002), covering unsent snapshots kept
  break P3-mixed (947). Re-run here: `--set reissue=keep` gives `item_key_id differs` and
  `--set dedup=none` a silent loss in the quick family (`tests/families.rs` `answer3_reissue`).

### Answer 4: faulty-client snapshots

**Rule** (ADR 0018, a §3 or §5 paragraph; ADR 0021 §3-§4, reopening open question 1):

> A snapshot is a claim signed by its author, never a substitute for the op bodies it covers. A
> replica absorbs one only as the cover of a bodiless header (ADR 0021 §4). It takes nothing that
> a verified op header does not vouch for: it cuts the covered VV to the op headers it has
> verified, ignores values above the cut or whose HLC is not their header's, and reports the cut.
> The absence of a value is never evidence: a key's current values are those that no other held
> value's verified header context covers, and an op body merges even when the VV already covers
> its dot. The replica refuses and reports a snapshot that contradicts an op body it holds or
> received with it. It reports, and never decides, any other disagreement between sources, and
> writes no snapshot of an item while one is unresolved.
>
> R1 also requires retained covers by two different authors. R3 keeps an older snapshot while
> dropping it would leave a bodiless header covered by fewer than two authors. Fetch serves covers
> by two authors for each bodiless header. One faulty device never holds the only copy; f faulty
> devices need f + 1 authors.

**Frozen bytes and acceptance.** No op, snapshot or tombstone layout changes, and honest
converged bytes are unchanged. Acceptance and converged bytes change for dishonest records: not
taking values and refusing body-contradicted snapshots break ADR 0018 §5 "Nothing else rejects a
version-1 record, and no layer normalises one", so this must land in §5 before the version-1
vectors freeze. ADR 0012 §4 step 3 (Accepted) "the op is a no-op" becomes "a covered op still
merges" (the same result on every honest state; restatement or named partial supersession is the
owner's call). ADR 0021 open question 1 is answered the other way, and its §6 storage bound
changes: an item snapshotted by one device only is never compacted. A replica keeps the verified
header of the dots in its state and which dots it merged from bodies (local, not frozen).

**Evidence.**
- `faulty-kinds`: 150,720 schedules, 1,136 P1 schedules, every one reported and with an
  undetectable fabrication stored; P2, P3, P3-mixed and P3-faulty hold (identical to answer 4's
  copy under `evidence-2a`). 76,224 faulty snapshots stored, 2,578 evidence absorptions refused,
  8,953 with a dispute. `faulty`: 0.
- `random-faults` (one faulty device): 102 violating seeds, all reported undetectable, P2 0
  (answer 4's copy: 99). `random-faults-multi`: 467, of which 324 with two or more faulty authors
  and 143 reported undetectable; P2 fails only in the two-faulty class (78).
- Comparisons: with the DVV join instead of the evidence merge (`--set absorb=join`), `faulty-kinds`
  fails P1 in 5,192, P2 in 2,343 and P3-faulty in 51,924 schedules, while `absorb`, `snapshots`
  and `compaction` stay at 0. With ADR 0021's server (`--set server=adr`), `faulty-kinds` fails P1
  in 4,695 and P2 in 1,532, and `random-faults` 669 of 50,000 with P2 in 289.
- Answer 4's copy: two worlds give byte-identical inputs with different op truths, so a lie about
  a compacted op's content is undecidable (re-run here: `tests/faulty.rs`).

### Answer 5: revocation of a device whose ops survive only in snapshots

**Rule** (ADR 0021; answers open question 5 and the last "Settled by the merge spike" bullet):

> 1. A revoked device's ops with `device_seq` ≤ `last_accepted_device_seq` stay for the life of the
>    vault, whether a replica received them as ops or inside another device's snapshot. The server
>    keeps their signed headers and deletes their bodies only under R1. It keeps the revoked
>    device's retained snapshots under R3, as for any author. After the suspension it stores no
>    further op or snapshot from that device.
> 2. The server refuses a snapshot whose covered-VV entry for its own author is above that
>    author's head when it is stored. [Integrated: implied by answer 2's refusal of unheld
>    claims.]
> 3. A client verifies a snapshot signed by a revoked device like any other if its covered-VV
>    entry for that device is ≤ `last_accepted_device_seq`; otherwise it rejects and reports it.
> 4. The stale-epoch check does not apply to an op of a revoked device with `device_seq` ≤
>    `last_accepted_device_seq`, whoever uploads it.
> 5. After a complete Fetch, a client whose cursor for a revoked device is below that device's
>    `last_accepted_device_seq` reports missing data from it (INV-27). This relies on M1's one
>    vault per account; M9 needs the bound per vault.
>
> A revocation completed on a restored server whose head for the device is below ops some replica
> applied counts as a misbehaving server for ADR 0012 §6: detected, not converged.

**Frozen bytes and acceptance.** No bytes change: no ADR 0018 §3-§5 layout, parse rule or limit.
Rules 2 and 4 change what the server accepts on upload; rule 4 changes the Accepted ADR 0012 §7
"Upload" (partial supersession under ADR 0020). Rule 3 changes ADR 0012 §4 step 1 verification for
snapshots, not ADR 0018 §5; rule 5 adds a report to the chain check. The owner fixed ADR 0021 at
three server rules, so rules 2 and 4 need a reopened ADR 0021 or a new small ADR. ADR 0012 §6's
"Only a misbehaving server can make a replica hold an op past the cut-off" is false after a restore
followed by a revocation, and, without rule 2, for a snapshot uploaded before its op.

**Evidence.**
- `rev-covers` (351,840 schedules), `rev-named` (315,000), `rev-unsent` (60,480) and `revocation`
  (402): 0 P1-P3 violations and no side condition. In `rev-covers`, 129,509 schedules end with the
  revoked device's ops only behind snapshots on the server, and 19,314 covers by the revoked
  author are served and accepted.
- `rev-restore` (104,400): 2,541 violating, all on the §6 path and reported, P2 0 (answer 5's copy,
  `candidate-rev`: 9,660, P2 0). 3,343 ADR 0012 §6 recomputations succeed and 2,302 items are
  flagged.
- `random-rev` and `random-rev-compromised`: 200,000 seeds each, 0 violations.
  `random-rev-restore`: 1,190, all on the §6 path, P2 in 19.
- Answer 5's copy: the literal rejection fails `rev-covers` 4,823 schedules with 7,014 false-gap
  schedules and `rev-named` 46,432; open question 5 alone fails `rev-unsent` 2,274 (684 silent).
  Re-run here: `--set revoked-snap=reject,server=adr` gives P1 and false gaps in the quick
  `rev-covers` (`tests/families.rs` `answer5_revocation`).

### Conflicts between the answers, and how they were resolved

1. **The absorption rule: the DVV join (answer 1) or the evidence merge (answer 4).** Resolved: the
   evidence merge. It equals the join on every honest state (`absorb`, `snapshots` and
   `compaction` give identical results with `--set absorb=join`), and only it survives dishonest
   records (the join fails `faulty-kinds` 5,192 P1 / 2,343 P2 schedules). Answer 1's merged-snapshot
   trigger and HLC receipt apply unchanged; "no snapshot while disputed" also stops a merged
   snapshot.
2. **The newest-snapshot basis (answers 1, 4 and 5).** Answer 1 keeps the pair of snapshots until
   the merged one is written; answer 5 needed a base state for its ADR 0012 §6 recomputation. One
   `base` serves both. New in the integration: under the evidence merge the basis is always the
   join of the previous basis and the taken part of the snapshot, and the retained ops the new
   basis covers are folded into it before they are dropped. Without this a faulty cover that
   lacked a value left the item unrecomputable (RECOMP failed in 133 of the quick `faulty`
   schedules; now 0 everywhere outside the §6 path).
3. **A stale answer to an op that may have been stored (answers 2 and 3).** Answer 2 re-publishes
   every op sent without an answer in a healing request; answer 3 re-uploads it with an unsigned
   marker that skips the stale-epoch check, only if the restore generation changed. Resolved by
   taking answer 3's condition with answer 2's mechanism (`stale-sent=gen`): no body a server never
   stored gets past the stale-epoch check (KEY 0 everywhere; answer 3's copy had KEY 80), and without
   a restore nothing is re-published (so no single-author bodiless header appears).

   | Knob | `reissue` family | `random-reissue` (50,000) | `random-reissue-norestore` (50,000) |
   |---|---|---|---|
   | integrated (`gen`) | 0; SRV-6h 1,199 | 7 (§6); FORK 1; SRV-6h 1,899 | 0; SRV-6h 0 |
   | answer 2 alone (`republish`) | 0; SRV-6h 2,464 | 7 (§6); FORK 1; SRV-6h 12,844 | 0; SRV-6h 12,911 |
   | literal (`reissue`) | 26 P1; FORK 160 | 17, 9 of them silent (`item_key_id` differs); FORK 214 | 0 |
4. **Unheld claims: refuse all (answer 2) or only the author's own (answer 5).** Answer 2's refusal
   implies answer 5's rule 2, but as written it also refuses a healer's fresh snapshot that holds
   a revoked device's op past its cut-off (a revocation signed on a restored server). The whole
   healing request is refused, the healer stays read-only for good, and its other ops are lost
   silently. Resolved: a revoked device's entry counts only up to its cut-off (the server can never
   hold more of it; the clamp cuts it). With `--set claims=refuse-strict`: `rev-restore` P2 301
   and 301 devices read-only (integrated: 0 and 0), `random-rev-restore` P2 33 of 50,000
   (integrated: 7). With answer 5's rule only (`claims=store`): `healing` loses a value silently in
   23 schedules (answer 2's finding).
5. **Healing requests against two-author covers (answers 2 and 4). Not fully resolved.** A healing
   request stores a header without its body behind the healer's snapshot alone, which breaks
   answer 4's premise that one device never holds the only copy. If the healer is faulty, its
   own later snapshot can be the only cover served (same author), and receivers lose the value
   silently (minimal: `D0 Write{b=11}; D0 Upload; D0 Write{b=12}; S RestoreServer(0); D0
   FaultySnapshot(OmitValue)`, random-faults-ops seed 6327). Partial resolution (`bodyfirst`): the
   request sends a body whenever the healer holds the body of a record the server stored before,
   and an own op never acknowledged takes the normal upload path. That removes the minimal case
   above; what stays single-author is a header whose body no device holds any more, where the
   healer's snapshot is the only record left anyway. Measured on `random-faults-ops` (50,000):
   integrated 72 violating, P2 12 (10 in this class); without the preference 83, P2 19; with every
   own op body kept for the life of the vault (`--set keepown=yes`, a storage cost answer 2
   declined) 58, P2 4. SRV-6h stays in every restore run (for example `healing` 2,220 schedules;
   without the preference 2,612). Closing it needs a rule the owner has to pick: keep op bodies
   on clients, serve every retained cover of a single-author header, or accept that a faulty
   healer is the single source of what only it held.
6. **Healing chains and revocation (answers 2 and 5).** Answer 5's §6 recomputation removes ops
   past a cut-off; answer 2's request then tried to re-publish them and stayed blocked (a LIVE
   finding in `healing`). Resolved by capping each chain of the request at the known cut-off, as
   answer 2 already capped its comparison.
7. **Two-author covers hide answer 5's literal counterexample.** The literal rejection of a revoked
   author's snapshot fails only under ADR 0021's server, where the fresh device is served the
   revoked author's cover alone; with two-author covers a second cover is served. Not a conflict
   of rules; the test pins it with `server=adr`.
8. **Overlapping fixes merged without conflict:** the retry of an op waiting for a wrap that
   arrives later (answers 2 and 3), the wrap of a dropped or refused record moving to the next
   record under its key (answers 2, 3 and 5), taint bookkeeping for P3-mixed (answers 1 and 4),
   cut-offs from the server and active devices only (answer 2), P2 counting an op held for a
   missing context as reported (answer 5), and the revoker syncing before phase 1 (answer 5).

### Remaining AMBIGUOUS items and open decisions

Every item in [AMBIGUOUS](#ambiguous) where `integrated` takes a non-literal reading needs ADR text
before the version-1 vectors freeze. Grouped by owner decision:

- **ADR 0018 §3/§5 (acceptance and converged bytes):** the absorption rule (items 1-3; answers 1
  and 4), the evidence merge's refusals and "a covered op still merges" (answer 4, touching
  Accepted ADR 0012 §4 step 3), `item_key_id` of a re-issued purge (item 7; answer 3).
- **ADR 0012 §7, Accepted, as partial supersessions under ADR 0020:** the healing request and the
  comparisons (items 4-6; answer 2), the stale answer to a maybe-stored op and the restore
  generation (item 22; answers 2 and 3), the re-issue scope and wrap move (items 23-24; answer 3),
  the revoked author's stale-epoch exemption (answer 5 rule 4).
- **ADR 0021 beyond its three owner rules:** refusal of unheld claims with the revoked cap
  (answers 2 and 5), two-author covers (answer 4, against the recommendation of open question 1),
  the revoked author's snapshot rules (item 17, open question 5), the merged-snapshot trigger (item
  21), the HLC receipt (item 18).
- **Still open, with no rule in any answer:** the ADR 0012 §6 path (a revocation signed on a
  restored server: needs a restore rule), a faulty healer as the only source of a healed header
  (conflict 5), content lies about compacted ops (undecidable), and two or more faulty devices.
- **Model readings kept literal and not tested by any answer:** items 9, 10, 12, 13, 16 and 25.

### Properties that still fail

- **P1, P1-ref:** on the §6 path (`healing` 2, `rev-restore` 2,541 schedules; 1,876 random seeds),
  for undetectable fabrication (`faulty-kinds` 1,136; 319 random seeds, all reported), with two or
  more faulty authors (340 seeds), and with a faulty healer as the sole cover (142 seeds).
- **P2 (silent loss):** 233 of 2,600,000 random seeds and no exhaustive schedule: 101 with a faulty
  healer as the sole cover, 88 with two or more faulty authors, 44 on the §6 path.
- **P3-mixed:** 216 random seeds, all on the §6 path. P3 and P3-faulty never fail.
- **Answer checks:** FORK in 8 random seeds and RECOMP in 19 (each minimised trace printed is a
  restore followed by a revocation); HLC in 2 random seeds (answer 1's documented limit, and one faulty run
  with a restore). RT and KEY never fail.
- **Side conditions:** LOSS in every restore family and flavour (unrecoverable by any rule), SRV-6h
  (conflict 5), DISPUTE (reports by design), and LIVE only on the §6 path (flagged items and ops
  held in the causal buffer) or in faulty runs (a few ops held for a context no honest cover
  supplies: 4 seeds in `random-faults-ops`, 65 in `random-faults-multi`).
