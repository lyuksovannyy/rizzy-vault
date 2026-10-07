---
name: harness-quirks
description: "How to run parallel agent work in this repo safely (worktrees, workflow resume, toolchain probes)"
metadata:
  node_type: memory
  type: reference
  originSessionId: e56ac701-2fec-4ec0-b142-a18d4aa378b1
  modified: 2026-09-27T14:07:01.171Z
---

- Workflow `isolation: 'worktree'` creates worktrees at `main`, not HEAD. Instead create them yourself: `git worktree add --detach <dir> HEAD` in the scratchpad, plus an APFS clone of the build cache (`cp -cR target <dir>/target`, and `fuzz/target` or `spikes/merge-model/target` when needed). Integrate with `git apply --3way`; to split commits per item, export one patch per worktree and stage each with `git apply --cached`.
- Workflow agents get interrupted when the owner sends a message; resume with `resumeFromRunId` (finished agents replay from cache).
- Never probe with `cargo +<toolchain> ...`: rustup auto-installs the toolchain (happened with nightly on 2026-09-27). Use `rustup toolchain list`. Put this in agent prompts along with "Rust only".
- Prose/ADR review: one blockers-only pass; a blocker that needs a decision goes to the owner, not to a fixer.

See [[bounded-doc-reviews]], [[stick-to-milestones]].

- Disk hygiene (owner asked 2026-09-30, disk was 99% full): after every integration, remove finished worktrees and delete stale agent scratch dirs in the session scratchpad (agents leave multi-GB target copies such as review-copy, fz, tgt); run `cargo clean` on the main checkout (and fuzz/, spikes/merge-model) occasionally, not while a workflow's worktrees still share its blocks. Check `df -h` before launching several build worktrees (each grows to ~7 GB).

**2026-10-06: /private/tmp scratchpad was wiped by the OS mid-workflow** — worktrees wt15-* and all uncommitted work (web redesign, AliasVault importer) lost; only blobs that some `git add` had written survived as unreachable objects (recovered gen work from them). Rules now: put worktrees under /Users/lyuksovannyy/RustroverProjects/rizzy-wt/ (never /private/tmp); have agents snapshot often (`git add -A && git stash create` or commit to a throwaway ref); long gates run via mcp__terminal__run_in_terminal with rizzy-wt/gate.sh (Bash background runs got killed at 2 min).
