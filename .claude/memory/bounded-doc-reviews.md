---
name: bounded-doc-reviews
description: "Multi-agent review/fix loops on prose ADRs diverge; use one bounded blockers-only pass, line budgets, and executable spikes for merge semantics"
metadata:
  node_type: memory
  type: feedback
  originSessionId: dd2da8fd-9e83-4462-bdf6-48903c4b8d4c
  modified: 2026-09-26T12:07:09.053Z
---

Do not run open-ended review→fix loops over normative prose (ADRs/specs). On 2026-09-26 a loop-until-dry over ADRs 0014/0018/0019/0020/0021 confirmed ~30 serious findings every round for 3 rounds while the docs ballooned (0020 to 448 lines, 0021 to 440, 0019 to 815); fixers answered each finding with new mechanism, and cross-references between drafts went stale each round. The owner chose "trim + spike".

**Why:** reviewers told to find problems always find some in thousands of lines; fixers that add text create new surface. The owner cannot review what results, and it is the kind of tangent they asked to avoid ([[stick-to-milestones]]).

**How to apply:** author from the last reviewed text and add only owner-decided content; give each doc a line budget; one blockers-only review pass (contradiction with Accepted ADR/owner decision, byte/acceptance divergence, broken refs); fixes must not grow the doc; never let one Proposed ADR describe another draft's internals. Settle convergence/merge edge cases with an executable Rust model (exhaustive permutations) instead of prose review. Code reviews of real diffs (M1 step 1) worked well with find→verify→fix; the divergence is specific to prose.
