---
name: stick-to-milestones
description: "Owner wants work to follow HANDOFF/ROADMAP milestone steps in order, Rust-only tooling, no side tangents"
metadata:
  node_type: memory
  type: feedback
  originSessionId: dd2da8fd-9e83-4462-bdf6-48903c4b8d4c
  modified: 2026-09-26T22:19:38.518Z
---

Follow docs/HANDOFF.md "Next steps" and then ROADMAP.md milestones in order. Do not add side quests (e.g. an extra blind KAT cross-check the handoff didn't ask for). Keep all tooling in Rust — never install Python packages or write Python/other-language helpers; "it's a rust project".

**Why:** Owner interrupted a session (2026-09-26) when I started setting up a Python venv for an independent vector cross-check: "its a rust project", then "if handoff is done stick to milestones completion please".

**How to apply:** Scratch verification = Rust scratch tests/crates only. This binds subagents too: every Workflow/Agent prompt must say "Rust only; no Python or other-language scripts, not even in the scratchpad" — agents wrote Python helpers twice on 2026-09-26 when a prompt omitted it (a KAT constant, a token checker, link checkers). When a handoff exists, execute its steps; once done, delete docs/HANDOFF.md (owner asked explicitly) and continue with the next ROADMAP milestone step. See [[handoff-lifecycle]].
