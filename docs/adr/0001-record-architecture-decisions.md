# ADR 0001: Record architecture decisions

- Status: Proposed
- Date: 2026-09-25
- Deciders: project owner
- Milestone: M0

## Context

Two ROADMAP rules need a written record that sits next to the code:

- ROADMAP principle 2: "Every crypto decision is written down in an ADR before it is coded."
- The M0 exit criteria ask for "crypto design ADRs, architecture decisions".

The project has one maintainer and no code yet. Decisions made now bind every later milestone:

- The key hierarchy has to exist from M1 or M9 needs a rewrite (ROADMAP §6.7).
- The ciphertext envelope has to allow post-quantum algorithms from M1 (ROADMAP §4.3).
- The sync engine has to support both sync modes from M1 (ROADMAP §4.6).

If the reasons for these decisions live only in chat logs and PR comments, they are lost by M8. That is the milestone where an external auditor asks why each one was made.

The failure mode ADRs prevent is a specific one. Code lands first, the design is reverse-engineered from it later, and a security property nobody wrote down gets broken by a refactor. The 2026 ETH Zurich analysis of cloud password managers found 25 or more attacks by a malicious server (Scarlata, Torrisi, Backendal, Paterson, ePrint 2026/058, L). They exploit properties nobody wrote down or clients never checked: item encryption not bound to its context, unauthenticated public keys, key escrow, and downgrades to legacy modes and weaker KDF parameters.

## Decision

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
   | Superseded by ADR NNNN | Replaced. Only the status line changes; the old text stays. | The project owner, in the PR that accepts the replacement |

   - A Proposed ADR can be merged to `main`, so that it can be linked and reviewed alongside the docs. Merging does not make it Accepted.
   - Acceptance is its own change: a PR or commit that sets `Status: Accepted` and updates `Date`. Before that, the owner's answers to "Open questions for the owner" are written into the Decision section. An ADR with unanswered open questions cannot be Accepted.

4. **Accepted ADRs are immutable.** An Accepted ADR's Context, Decision and Consequences are not rewritten. The only edits allowed are:
   - the status line and a link to the superseding ADR;
   - fixes to typos and broken links that do not change meaning;
   - dated entries appended under a final `## Amendments` section, **only** for changes the ADR itself provides for. One example is [ADR 0009](0009-crypto-dependency-policy.md)'s crate table and version pins. Each amendment is its own PR and is approved by the owner.

   Anything that reverses, narrows or widens a decision is a new ADR that supersedes the old one.

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

## Consequences

### Positive

- Every security-relevant decision has written reasoning, alternatives and a status that the M8 auditor can check against the code.
- "Is this allowed?" has a mechanical answer: look for an Accepted ADR.
- Reviews of AI-generated or outside contributions can point at a specific ADR instead of arguing from memory.
- Rejected ADRs stop the same debate from starting again.

### Negative

- Crypto, protocol and format work is slower: you write the ADR, wait for acceptance, and only then code.
- With one maintainer, the owner is the bottleneck for every Accepted ADR.
- The ADRs and CRYPTO.md overlap and can drift apart. The same-PR rule limits this, but only if reviewers enforce it.

### Risks

- ADRs that stay Proposed indefinitely block M1. Mitigation: M1 vault code cannot start until ADRs 0002–0009 and 0016 are Accepted, so the backlog is visible. A Rejected ADR blocks its area until an Accepted replacement exists.
- The amendment exception in point 4 turns into a back door for substantive changes. Mitigation: the reviewer asks "does this change what an implementer must do?" If it does, the change is a new ADR.

## Alternatives considered

- **Decisions in PR descriptions and issues only.** They cannot be found later, have no status, and nothing links a later PR to the decision it depends on.
- **A wiki (GitHub wiki or external).** It is not versioned with the code and not reviewed through PRs. It also drifts from the code and cannot be pinned to a release tag.
- **One large design document only (CRYPTO.md style).** Good for the full specification, bad at showing *which* decision changed *when* and what it replaced. We keep both: CRYPTO.md for the specification, ADRs for the decisions.
- **A heavier RFC process** (separate repo, comment periods, a final comment period). Too heavy for one maintainer. It can be revisited in M9 when a second maintainer exists.
- **Nygard's original format without "Alternatives considered" and "Open questions".** Too little structure for crypto decisions, where the rejected options and the owner's pending calls are most of the value.

## Open questions for the owner

1. **Acceptance with a second maintainer.** Today the owner alone accepts ADRs. ADR 0009 already requires two maintainers to approve a new crypto crate from M9 on. Should the same rule cover ADRs on crypto, auth and persistent formats once a second maintainer exists? *Recommendation:* yes, from the first milestone with two maintainers. Until then the owner accepts alone, and the M8 external audit is the second review.
2. **Order of acceptance for the M0 set.** *Recommendation:*
   1. 0001, 0016 and 0017 first: process, layout and licensing. They block every contribution.
   2. Then 0002–0009, as one batch reviewed against CRYPTO.md. They block all vault code.
   3. Then 0010–0014. They block server and client scaffolding in M1.
   4. 0015 before desktop work starts in M3.

## References

- [docs/adr/README.md](README.md): index and rules
- [ADR 0000](0000-template.md): template
- [ROADMAP.md](../ROADMAP.md) §2 (principle 2), §3 (M0 exit criteria), §5 (decisions to make in M0)
- [THREAT_MODEL.md](../THREAT_MODEL.md), "How to use this document" (ADR-wins-on-mechanism rule)
- [CRYPTO.md](../CRYPTO.md)
- Michael Nygard, "Documenting Architecture Decisions", 2011 (U: not re-read in this session)
- MADR, Markdown Architectural Decision Records, adr.github.io/madr (U: not re-read in this session)
- Scarlata, Torrisi, Backendal, Paterson, "Zero Knowledge (About) Encryption", ePrint 2026/058 (L)
