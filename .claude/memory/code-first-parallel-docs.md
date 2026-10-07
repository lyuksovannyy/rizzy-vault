---
name: code-first-parallel-docs
description: "Owner wants coding to move; ADR/doc bookkeeping runs in parallel via subagents, never as a blocker before code"
metadata:
  node_type: memory
  type: feedback
  originSessionId: e56ac701-2fec-4ec0-b142-a18d4aa378b1
  modified: 2026-09-27T16:59:43.058Z
---

On 2026-09-27, after a long run of ADR bookkeeping (acceptance edits, supersession lines), the owner asked "how long will it take to stop with the documentation and start the work", then "if you still need to do the ADR stuff do it, but start coding work in parallel via subagents". They also accepted ADRs 0017 and 0019 as recommended over my advice to wait, and set Status lines by hand rather than run my command.

**Why:** the owner judges progress by working code; doc process that does not gate code feels like stalling.

**How to apply:** once the ADRs a milestone step needs are Accepted, start the code workflow immediately and run remaining doc/ADR bookkeeping as a parallel background workflow. Keep owner questions to real blockers, give recommendations, accept their call when they overrule, and never make them wait on doc-only work. Still obey the ADR gate and CLAUDE.md (no code without an Accepted ADR). See [[stick-to-milestones]], [[bounded-doc-reviews]], [[m1-state]].
