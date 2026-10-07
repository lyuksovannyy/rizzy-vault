---
name: server-hosted-focus
description: Owner frames rizzy-vault as a VPS/container-hosted server with built-in web vault; skip client-machine niceties (rv clipboard) and defer non-essential formats
metadata:
  type: feedback
---

2026-10-01: asked "why do we need rust clipboard? it's a server with built-in web vault" and then "this is a server, meant to be hosted on a vps/container, not run on user hardware, so no". Also: "move kdbx into later, no need for it right now; fix gaps, proceed with next steps". Done in 2057d15 (KDBX → M3, rv no clipboard, THREAT_MODEL mitigation lines updated).

**Why:** the owner prioritises the hosted server + web vault path; anything that only polishes a local client or adds legacy formats is scope creep for M1.

**How to apply:** when a gap only serves `rv`'s local UX or an optional import format, recommend dropping/deferring it rather than adding crates. Remote-access essentials (rv https to a VPS) still count. See [[stick-to-milestones]], [[m1-state]].
