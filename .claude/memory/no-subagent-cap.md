---
name: no-subagent-cap
description: Owner lifted the 3-agent parallel cap for rizzy-vault — run as many subagents/workflows as the work needs
metadata:
  node_type: memory
  type: feedback
  originSessionId: bec58c46-3982-462e-9cf3-97acf781f3d0
  modified: 2026-10-10T18:42:54.666Z
---

Run as many subagents and workflow agents in parallel as the work needs; the global "parallel cap 3" rule does not apply here (owner, 2026-10-10: "you can run as much as required sub agents, dont limit your self").

**Why:** owner wants throughput on the HANDOFF gap backlog; cost is not the constraint (ultracode on).
**How to apply:** fan out independent tracks at once (each in its own worktree under rizzy-wt/, see [[harness-quirks]]), add review/verify fan-outs freely. Disk (~7 GB per build worktree) is the real limit: check `df -h` first.
