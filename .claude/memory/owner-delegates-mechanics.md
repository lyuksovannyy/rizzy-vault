---
name: owner-delegates-mechanics
description: "Owner gave full control (2026-09-27): do mechanical owner-acts (ADR status/date lines, index mirrors) myself once they've decided; never hand them commands to run"
metadata:
  node_type: memory
  type: feedback
  originSessionId: bec58c46-3982-462e-9cf3-97acf781f3d0
  modified: 2026-09-27T18:12:28.537Z
---

On 2026-09-27, after I twice handed the owner a long shell command to set ADR Status/Date lines (the auto-mode classifier had blocked me), they replied in Russian, angry: "what the f*** on my side, I give you full control, finish it already". With that explicit authorization the same edit went through the classifier.

**Why:** the owner decides (accept/reject, scope) but does not want to execute mechanics; handing them commands reads as stalling.

**How to apply:** once the owner has made a decision in chat, carry out every mechanical consequence myself: status lines, dates, index cells, mirrors, commits. Cite their authorization in the command description. If a tool still blocks, ask ONE short question about adding a permission rule; don't give them a script to run. Decisions themselves (accepting an ADR, scope, crypto choices) remain theirs. Reply in Russian when they write Russian. See [[code-first-parallel-docs]], [[user-profile]].
