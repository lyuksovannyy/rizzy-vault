# ADR 0020: Record architecture decisions, with partial supersession

- Status: Accepted
- Date: 2026-09-27
- Deciders: project owner
- Milestone: M0
- Supersedes: [ADR 0001](0001-record-architecture-decisions.md) in full, on acceptance.

## Context

Three Proposed ADRs change parts of long Accepted ADRs. [ADR 0018](0018-item-record-encoding.md) and [ADR 0021](0021-server-compaction.md) change parts of [ADR 0012](0012-sync-engine.md). [ADR 0019](0019-native-clients.md) changes parts of [ADR 0013](0013-shared-client-core.md) and [ADR 0016](0016-workspace-layout.md). ADR 0001 offers two routes, and neither fits a narrow change:

- **An `## Amendments` entry** (point 4) is allowed only for changes the ADR itself provides for. ADRs 0012, 0013 and 0016 do not provide for these changes.
- **"Superseded by ADR NNNN"** (point 3) replaces a whole ADR. A narrow change then restates the whole ADR, and a reviewer must diff it to see that nothing else changed. The Decision sections of ADRs 0012, 0013 and 0016 hold 5,146, 1,740 and 2,542 words (`wc -w`, 2026-09-26, V).

ADR 0001's lifecycle is part of its Decision, and ADR 0001 provides for no amendment of it. A new status widens that decision, so it takes a new ADR that supersedes ADR 0001 in full (point 4). This is that ADR. The owner chose this route on 2026-09-26 (owner decision 3).

ADR 0001's Context, Consequences and Alternatives considered still hold. They are not repeated here, and ADR 0001's file stays in place (point 3).

## Decision

Points 1–8 are ADR 0001's Decision word for word, with two changes: point 3's table gains the row "Partially superseded by ADR NNNN (§…)", and point 4's last sentence gains "in full or in the parts it names (point 9)". They keep ADR 0001's numbers, so a citation of "ADR 0001 point N" reads as point N here. Point 9 is new.

1. **We record significant decisions as Architecture Decision Records (ADRs)** in `docs/adr/`. The format follows MADR (Markdown Architectural Decision Records): Nygard's Context / Decision / Consequences, plus "Alternatives considered" and "Open questions for the owner". The template is [ADR 0000](0000-template.md).

2. **File names and numbering.**
   - File name: `docs/adr/NNNN-kebab-title.md`, with a four-digit, zero-padded number.
   - Numbers are sequential and never reused, including for rejected ADRs.
   - A PR takes the next free number. If two open PRs claim the same number, the one merged second renumbers before it merges.
   - 0000 is the template.

3. **Lifecycle.**

   | Status | Meaning | Who sets it |
   |---|---|---|
   | Proposed | Written and open for review. **Not binding. Code must not rely on it.** | Anyone, by opening a PR |
   | Accepted | Binding. Code may implement it and must follow it. | The project owner |
   | Rejected | Considered and declined. The file stays so the reasoning is not repeated. | The project owner |
   | Partially superseded by ADR NNNN (§…) | The parts ADR NNNN names are replaced and no longer bind. Everything else stays binding. Only the status line changes; the old text stays (point 9). | The project owner, in the PR that accepts ADR NNNN |
   | Superseded by ADR NNNN | Replaced. Only the status line changes; the old text stays. | The project owner, in the PR that accepts the replacement |

   - A Proposed ADR can be merged to `main`, so that it can be linked and reviewed alongside the docs. Merging does not make it Accepted.
   - Acceptance is its own change: a PR or commit that sets `Status: Accepted` and updates `Date`. Before that, the owner's answers to "Open questions for the owner" are written into the Decision section. An ADR with unanswered open questions cannot be Accepted.

4. **Accepted ADRs are immutable.** An Accepted ADR's Context, Decision and Consequences are not rewritten. The only edits allowed are:
   - the status line and a link to the superseding ADR;
   - fixes to typos and broken links that do not change meaning;
   - dated entries appended under a final `## Amendments` section, **only** for changes the ADR itself provides for. One example is [ADR 0009](0009-crypto-dependency-policy.md)'s crate table and version pins. Each amendment is its own PR and is approved by the owner.

   Anything that reverses, narrows or widens a decision is a new ADR that supersedes the old one, in full or in the parts it names (point 9).

5. **What needs an Accepted ADR before code is merged:**
   - cryptographic constructions, primitives, parameters and key handling;
   - authentication and session protocols;
   - wire protocol and API versioning rules;
   - persistent formats: ciphertext envelope, op log, export files, local cache, and schema changes that alter what the server stores in either sync mode;
   - security boundaries: server roles, trust boundaries, what each component may see;
   - a new cryptographic dependency (procedure in [ADR 0009](0009-crypto-dependency-policy.md));
   - crate boundaries and dependency direction ([ADR 0016](0016-workspace-layout.md));
   - licensing and contribution terms ([ADR 0017](0017-licensing.md)).

   These do **not** need an ADR: refactors that keep behaviour, bug fixes, UI work within an accepted stack, tests, docs, and non-crypto dependencies. Those follow [CONTRIBUTING.md](../../CONTRIBUTING.md).

6. **Spikes.** ROADMAP M0 allows spikes. Spike code is written to answer a question an ADR needs answered, such as Argon2id timings on a low-end phone. It lives on a branch or outside `crates/`, is never merged into a shipped crate, and its results are cited in the ADR.

7. **Relationship to the other design docs.**
   - [THREAT_MODEL.md](../THREAT_MODEL.md) holds goals, non-goals and invariants.
   - [CRYPTO.md](../CRYPTO.md) holds the detailed specification.
   - ADRs hold the decisions and why they were made.
   - On a *mechanism*, an Accepted ADR wins, and the other docs are fixed in the same PR (the rule THREAT_MODEL.md already states).
   - On a *goal or invariant*, a conflict is a stop-and-ask for the owner.
   - [ROADMAP.md](../ROADMAP.md) remains the source of truth for scope. An ADR does not add scope. If a decision needs scope that is not there, ROADMAP is changed first.

8. **Index.** [docs/adr/README.md](README.md) lists every ADR with its status and milestone. It is updated in the same PR as the ADR.

9. **Partial supersession.** A new ADR may supersede named parts of an Accepted ADR instead of restating it in full.
   - **Naming parts.** The new ADR's Decision lists every part it supersedes, under "What this ADR supersedes". Each entry names the older ADR and one part of it:
     - a section or subsection, by number (`§7`, `§4.2`) or by the exact text of its heading;
     - a numbered point, a rule id or an owner decision (`point 3`, `R7`, `owner decision 2`);
     - a table row, by the exact text of its first cell;
     - a whole bullet, by its bold label or its position, or a whole sentence, by its position or quoted word for word.

     A whole bullet or a whole sentence is the smallest part. A change to a few words names the whole sentence or bullet.
   - **Replacing text.** Each entry writes out the full text that replaces the part. It is complete in itself, never "as ADR NNNN §x, except …". It binds as Decision text of the new ADR.
   - **What stays binding.** Every part the list does not name stays binding, with its original meaning, and counts as Accepted for point 5. Nothing is superseded by implication. A named part stops binding when the new ADR is Accepted, not before.
   - **Status line.** On acceptance, the owner sets the older ADR's status line to `Partially superseded by [ADR NNNN](NNNN-kebab-title.md) (§x, §y)`.
     - The parenthesis lists the sections, points, rules and owner decisions that hold the named parts. One that is only partly named is marked "in part", as in "(§5, §7 in part)". The new ADR's list gives the exact parts.
     - Several partial supersessions accumulate on one line, in order of acceptance, separated by semicolons: `Partially superseded by [ADR NNNN](…) (§4); [ADR MMMM](…) (§7 in part)`.
   - **The old text stays.** The supersession edits nothing in the older ADR except its status line: no marker, no note, no rewrite (point 4).
   - **References.** A reference anywhere (an ADR, a design doc, code, a comment) to a superseded part is read as a reference to its replacing text. References are not edited to follow the change.
   - **Limit.** When, with every partial supersession in force, more than half of the older ADR's Decision would be replaced, the new ADR is a full successor instead (point 3). It restates the older ADR with every change in force. The share is counted with `wc -w` from `## Decision` up to `## Consequences`.

### Owner decisions (2026-09-25), carried forward from ADR 0001

The owner answered ADR 0001's open questions on 2026-09-25:

1. **Acceptance with a second maintainer** → Yes. From the first milestone with two maintainers, ADRs on crypto, auth and persistent formats need the approval of two maintainers, as ADR 0009 already requires for a new crypto crate from M9. Until then the owner accepts alone, and the M8 external audit is the second review.
2. **Order of acceptance for the M0 set** → As recommended:
   1. 0001, 0016 and 0017 first: process, layout and licensing. They block every contribution.
   2. Then 0002–0009, as one batch reviewed against CRYPTO.md. They block all vault code.
   3. Then 0010–0014. They block server and client scaffolding in M1.
   4. 0015 before desktop work starts in M3.

   On 2026-09-25 the owner accepted 0001–0013, 0015 and 0016. 0014 and 0017 remain Proposed, so the gates that need them stay closed: external contributions other than documentation (0017), and server and client scaffolding in M1 (0010–0014) ([README](README.md#gates)).

### Owner decisions (2026-09-26)

3. **How a new ADR changes parts of an Accepted ADR** (ADR 0018 owner decision 11, ADR 0019 open question 1) → partial supersession, through a small successor to ADR 0001. The older ADR's status becomes "Partially superseded by ADR NNNN (§…)". Everything not named stays binding. The owner chose this over restating ADRs 0012, 0013 and 0016 in full.
4. **The limit** → yes: a full successor is needed once more than half of the older Decision, counted in words, would be replaced.
5. **Parts smaller than a section** → yes: point 9 names parts down to a whole bullet or sentence.

### On acceptance

The PR that accepts this ADR makes these edits. None is made now.

1. **Order.** This ADR is Accepted before, or with, the first ADR that relies on point 9. [ADR 0021](0021-server-compaction.md) is to be Accepted before M1 step 3 (owner decision of 2026-09-26), so this ADR is too.
2. **ADR 0001:** status line → "Superseded by [ADR 0020](0020-partial-supersession.md)". Nothing else changes.
3. **[docs/adr/README.md](README.md):** the intro's "rules come from ADR 0001" → ADR 0020; the lifecycle diagram and table gain "Partially superseded by ADR NNNN (§…)"; the "Accepted ADRs are immutable" paragraph ends "… in full or in the parts it names"; the ADR-first rule says the unnamed parts of a Partially superseded ADR count as Accepted; index row 0001 → "Superseded by 0020", row 0020 → "Accepted"; Gates "0001, 0016 and 0017" → "0020, 0016 and 0017".
4. **[CLAUDE.md](../../CLAUDE.md)** (the owner approves the wording): "Before you start" item 3 and "The ADR gate" cite ADR 0020 points 3, 4 and 9 instead of ADR 0001; binding text includes the unnamed parts of a Partially superseded ADR; `Partially superseded` joins the statuses only the owner sets; the "As of …" sentence is brought up to date.
5. **Other files:** [CONTRIBUTING.md](../../CONTRIBUTING.md) line 6 and the [template](0000-template.md) header comment: ADR 0001 → ADR 0020. The template's Status comment adds "Partially superseded by ADR NNNN (§…)". [SECURITY.md](../../SECURITY.md) line 125's status sentence is brought up to date.

## Consequences

ADR 0001's consequences still hold. Partial supersession adds these.

### Positive

- A narrow change to a long Accepted ADR costs the change, not a restatement of the whole ADR and a diff review of it.
- Existing citations of the older ADR keep pointing at a live ADR.
- "Does this part still bind?" keeps a mechanical answer: the status line names the superseding ADRs, and their lists name the exact parts.

### Negative

- A reader of a Partially superseded ADR needs more than one document.
- Superseded text stays in place, unmarked. A reader who jumps to a section and skips the status line reads it as binding. The status line and CLAUDE.md are the defence.
- Past the limit a full successor is still needed, so the restatement cost is deferred, not removed.

### Risks

- **A dependent part is missed:** a change to a named part silently changes what an unnamed part means. Mitigation: the author names that part too, and the reviewer asks "does any unnamed text read differently now?". Two Accepted texts that disagree are a stop-and-ask for the owner.
- **Partial supersession becomes the default** and full successors are never written. Mitigation: the limit in point 9, and the owner can decline a partial supersession and ask for a full successor.

## Alternatives considered

- **Full successors only** (ADR 0001 as accepted). One binding document per topic, and no process change. It lost to owner decision 3. Its cost: about 9,400 words of Decision text in ADRs 0012, 0013 and 0016 restated to change a small share of each.
- **An implicit rule that a later Accepted ADR wins where it conflicts.** Nothing lists what changed, and conflicts surface only in code review.
- **Wider amendments** (point 4). This makes ADR 0001's back-door risk the rule.
- **A marker in the superseded text,** such as a note under each named heading. Easier to spot, but it edits Accepted text, and a row or sentence cannot carry a marker without being rewritten.
- **Whole sections as the smallest part.** Rejected by owner decision 5.

## Open questions for the owner

None open. Questions 1 and 2 were ADR 0001's and are answered as owner decisions 1 and 2. Owner decision 3 is also ADR 0018 owner decision 11 and answers ADR 0019 open question 1. Questions 4 and 5 were answered on 2026-09-26 as owner decisions 4 and 5; the questions below are kept for the reasoning.

4. **Is "more than half of the Decision, counted in words" the right limit?** *Recommendation:* yes. Words measure how much binding text changed. A count of sections does not, because one changed row counts as a whole section.
5. **May a part be smaller than a section?** Point 9 goes down to a whole bullet or sentence. *Recommendation:* yes. With whole sections only, each expected supersession of ADRs 0012, 0013 and 0016 would pass the half limit (about 70–75 % of each Decision, U: estimate from the drafts of 2026-09-26). That amounts to the full successors the owner turned down.

## References

- [ADR 0001](0001-record-architecture-decisions.md): the ADR this one supersedes, with the Context, Consequences and Alternatives that still hold
- [docs/adr/README.md](README.md): index and rules; [ADR 0000](0000-template.md): template
- [ADR 0012](0012-sync-engine.md), [ADR 0013](0013-shared-client-core.md), [ADR 0016](0016-workspace-layout.md): the Accepted ADRs the expected partial supersessions touch
- [ADR 0018](0018-item-record-encoding.md), [ADR 0019](0019-native-clients.md), [ADR 0021](0021-server-compaction.md) (Proposed): the ADRs that rely on point 9
- [ROADMAP.md](../ROADMAP.md) §2 (principle 2), §3 (M0 exit criteria), §5; [THREAT_MODEL.md](../THREAT_MODEL.md), "How to use this document"; [CRYPTO.md](../CRYPTO.md)
- Word counts: `wc -w` from `## Decision` up to `## Consequences` on the Accepted files, 2026-09-26 (V for the counts as run)
- Michael Nygard, "Documenting Architecture Decisions", 2011 (U: not re-read in this session)
- MADR, Markdown Architectural Decision Records, adr.github.io/madr (U: not re-read in this session)
