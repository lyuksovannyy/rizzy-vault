# Implementation roadmap for Accepted ADRs 0061, 0063–0070, 0072, 0083–0114 (accepted 2026-10-25)

Each track: implement the ADR, make its "On acceptance" doc edits (status lines are the owner's — list them in HANDOFF, don't flip), pass gate.sh (full gate if web/extension), rebase, integrate, push. Rule: ≤3 concurrent builds.

## Wave A — self-contained errata and doc-only, no code behaviour change (safe first)
- **0083** 0071 plaintext_len erratum: CRYPTO §9.8 + db_backup.rs doc comment. No code change.
- **0088** device-state grammar erratum: record.rs doc; the KAT already exists. Tests: v1→v2 upgrade, version-3 corrupt.
- **0095** owner answers 0023–0028: the parts that supersede with code-matching text — check the code already matches (it does, per the ADR); add the Retry-After test it names; doc edits.
- **0109** sync cursor clarification: the healing guard (FetchRequired while a hold is open) + property test; no format change.

## Wave B — server/client fixes with caps and new codes (M1–M3)
- **0098** security-key per-key size cap + the 6 endpoints documented to match code; new refusal code.
- **0092** rotation size limits: write caps, rotation_limit code, staged rotation + the two new endpoints.
- **0091** revoked-device rotation race: server refusal of the revoked device's creds; INV-111.
- **0094** backup container: streaming writer/reader, 1 TiB cap, in-memory 2 GiB for stdin.
- **0093** attachment lifecycle: attachments/delete-item endpoint, cache format 5, cleanup table, import strips refs, unsupported_item on move.

## Wave C — client/UX features (M2–M3)
- **0099** favicon opt-in (tag 0x0005, on by default).
- **0097** matching: compared-URL rule, regex-lite Regex mode, settings readable regardless of PSL, dotless refused in user groups.
- **0110+0111** vault lock settings on every client + passkey UV + extension idle lock (Chromium MV3 / Firefox MV2). **0096 after 0111.** Accept-order already recorded; implement 0110/0111 together, then 0096's KDBX worker + binding-secrets rules.
- **0105** Secret Key QR (client-only, macOS M3 + web).
- **0108** rv recovery abandon + INV-122 (server ends older recovery sessions).

## Wave D — admin panel (M3, server-rendered)
- **0090** security event log (table, endpoint, alert summary, banner) — needed by 0103/0085.
- **0114** one settings register + the xtask check (needs owner ok to add to CI — report).
- **0085** admin auth + bootstrap token + TOTP.
- **0086** instance settings table + sealed SMTP credential 0x0103.
- **0087** invite-only signup (default invite).
- **0103** disable user.
- **0104** metrics endpoint.
- **0100** notification mail (needs 0086 SMTP + 0090 events).

## Wave E — operator / platform (M3, M8)
- **0106** AGPL source URL (RIZZY_SOURCE_URL, /api/meta, footer).
- **0107** backup-key retention + secrets backup-key CLI.
- **0112** core-dump panic hook + macOS RLIMIT_CORE + AR-31.
- **0113** breach endpoint: doc to match code + any undefined bits.
- **0102** native-client TLS (ADR text + the binding-side pieces that exist; mostly future-client).
- **0101** native-client licensing: the files it defines (ADDITIONAL-PERMISSIONS.txt elements, client-allow.toml, rizzy-core.pin, the check-signoff --repo flag) in THIS repo where they live; the client repos are separate.

## Wave F — post-v1.0 (M5/M6/M9), lower priority, implement last or on request
- **0068** alias tombstone + list/enable + label rotation (masked email, M6).
- **0061** notify WebSocket; **0063–0067, 0069, 0070** sharing/send/mail ingress; **0072** remote backup destinations.
- These are post-v1.0 per ROADMAP; confirm with owner before building, or do the M1–M3 pieces only.

Progress is tracked in HANDOFF §1.
