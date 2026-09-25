# ADR NNNN: Title

<!--
How to use this template (the process is in ADR 0001 and docs/adr/README.md):

1. Copy to docs/adr/NNNN-kebab-title.md, where NNNN is the next free number. Numbers are never reused.
2. Title: a short noun phrase naming the decision, e.g. "Storage: SQLite and PostgreSQL via sqlx".
   Not a question, and not "Use X".
3. Every section below is required. If a section has nothing in it, write "None." Do not delete it.
4. Add a row to the index in docs/adr/README.md in the same PR.
5. Delete these HTML comments before opening the PR.

Writing rules:
- Be concrete. Give parameters, sizes, versions, byte layouts and milestone numbers. "Strong KDF" is not a
  decision. "Argon2id, m=64 MiB, t=3, p=4, client-enforced floor" is.
- Tag each factual claim about a crate, audit, standard or benchmark with its source and a confidence:
  V = primary source read, L = secondary source only, U = unverified. Do not state an unverified claim as fact.
- State the trade-offs, including the ones against the option you recommend.
- Anything that only the owner can decide goes under "Open questions for the owner", with a recommendation.
- Link related ADRs, docs/THREAT_MODEL.md, docs/CRYPTO.md and docs/ROADMAP.md with relative links.
-->

- Status: Proposed
<!-- One of: Proposed | Accepted | Rejected | Superseded by ADR NNNN (written as a relative link to that ADR's file).
     Only the project owner moves an ADR out of Proposed. -->
- Date: YYYY-MM-DD
<!-- The date of the current status. Earlier history is in git. -->
- Deciders: project owner
- Milestone: M1
<!-- The first milestone where this decision constrains code, e.g. "M1" or "M1 (engine) / M4 (modes)". -->

## Context

<!--
The problem, and the forces acting on it: requirements from ROADMAP (quote the row and its MoSCoW priority),
threats from THREAT_MODEL (adversary IDs, invariant IDs), constraints (wasm32, no I/O in core, deny.toml,
toolchain 1.94.1), and facts with sources. No solution yet.
-->

## Decision

<!--
What we will do, written so an implementer can follow it without guessing:
- the exact algorithm, crate, version pin, feature set, parameter, format or boundary;
- what is forbidden;
- which crate or module owns it;
- how it is tested or enforced (CI job, lint, test vector, review checklist item).
Use "must" and "must not" for requirements.
-->

## Consequences

### Positive

<!-- What gets easier or safer. -->

### Negative

<!-- What it costs: performance, complexity, lock-in, work pushed to later milestones. -->

### Risks

<!-- What could make this decision wrong later, and the signal that should trigger a new ADR. -->

## Alternatives considered

<!--
Each serious alternative, with the concrete reason it lost. "Not considered" is not an alternative.
-->

## Open questions for the owner

<!--
Numbered. Each question has a recommendation. When the owner decides, record the answer in the Decision
section before the status moves to Accepted. Write "None." if there are none.
-->

## References

<!--
Relative links to related ADRs and docs, then external sources with confidence tags (V/L/U).
-->
