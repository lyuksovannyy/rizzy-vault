---
name: document-everything
description: "Owner requires everything documented (logic, encryption, services, tooling) as the codebase grows; docs are part of every step's definition of done"
metadata:
  node_type: memory
  type: feedback
  originSessionId: dd2da8fd-9e83-4462-bdf6-48903c4b8d4c
  modified: 2026-09-26T21:30:09.445Z
---

Everything must be documented as it is built: logic, encryption, services, tooling — public AND private items, module-level explanations of the logic with spec citations (CRYPTO.md §, ADR, INV-), plus entry points (README.md, docs/README.md index). Enforced since 2026-09-26 by `missing_docs = "warn"` (workspace) and `#![cfg_attr(not(test), warn(clippy::missing_docs_in_private_items))]` in each crate root, under `cargo lint` -D warnings.

**Why:** owner asked "do you do documentation as codebase grows?" and then "ensure that everything is documented, logic, encryption, services, and so on" (2026-09-26).

**How to apply:** every new crate/module/item ships with accurate docs in the same change; normative docs change with behaviour; server work (M1 step 3) ships operator docs (self-hosting, compose, tested backup/restore); clients ship user docs; CHANGELOG from the first tag. Never recreate docs/ARCHITECTURE.md (CLAUDE.md) — the docs index links ADRs instead. Accuracy over volume: a wrong comment on crypto code is worse than none. See [[stick-to-milestones]], [[bounded-doc-reviews]].
