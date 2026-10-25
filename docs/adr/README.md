# Architecture Decision Records

This directory holds rizzy-vault's Architecture Decision Records (ADRs). Each ADR is one decision: the context, what was decided, what it costs, what else was considered, and what the owner still has to answer. The format and the rules come from [ADR 0020](0020-partial-supersession.md), which carries ADR 0001's rules forward and adds partial supersession. New ADRs start from the [template](0000-template.md).

Related documents:

- [ROADMAP.md](../ROADMAP.md): scope and milestones. It is the source of truth for *what* we build.
- [THREAT_MODEL.md](../THREAT_MODEL.md): goals, non-goals and security invariants.
- [CRYPTO.md](../CRYPTO.md): the detailed cryptographic specification that ADRs 0003–0009 decide on.

## Lifecycle

```text
Proposed ──► Accepted ──► Partially superseded by ADR NNNN (§…)
    │            │
    │            └──────► Superseded by ADR NNNN
    └──────► Rejected
```

| Status | Meaning |
|---|---|
| **Proposed** | Written and open for review. May be merged to `main` for discussion. **Not binding: code must not rely on it.** |
| **Accepted** | Binding. Only the project owner accepts. The owner's answers to "Open questions for the owner" go into the Decision section first. |
| **Rejected** | Declined by the owner. The file stays so that nobody has to reconstruct the reasoning. |
| **Partially superseded by ADR NNNN (§…)** | The parts ADR NNNN names are replaced and no longer bind. Everything else stays binding. Only the status line changes; the old text stays. |
| **Superseded by ADR NNNN** | Replaced by a newer Accepted ADR. Only the status line changes. |

**Who decides:** the project owner accepts or rejects every ADR.

**Accepted ADRs are immutable.** Allowed edits are the status line, typo and link fixes, and dated `## Amendments` entries for changes the ADR itself provides for (for example, the crate table in ADR 0009 or the license allow-list in ADR 0017). Anything else is a new ADR that supersedes the old one, in full or in the parts it names ([ADR 0020](0020-partial-supersession.md) point 9).

## The ADR-first rule

**An Accepted ADR must exist before code for any of the following is merged:**

- cryptography: constructions, primitives, parameters, key handling;
- protocol: authentication, sessions, the wire protocol, API versioning;
- persistent formats: ciphertext envelope, op log, export files, local cache, and schema changes that alter what the server stores;
- security boundaries: server roles, trust boundaries, what each component may see;
- a new cryptographic dependency ([ADR 0009](0009-crypto-dependency-policy.md));
- crate boundaries and dependency direction ([ADR 0016](0016-workspace-layout.md));
- licensing and contribution terms ([ADR 0017](0017-licensing.md)).

The parts of a Partially superseded ADR that no later Accepted ADR names count as Accepted. Proposed is not enough. If the relevant ADR is Proposed, or no ADR exists, stop: write or update the ADR and get it accepted first. Spikes that inform an ADR live on a branch or outside `crates/`, and are never merged into a shipped crate.

Refactors that keep behaviour, bug fixes, tests, docs, UI work within an accepted stack and non-crypto dependencies do not need an ADR. They follow [CONTRIBUTING.md](../../CONTRIBUTING.md).

## Writing a new ADR

1. Copy [0000-template.md](0000-template.md) to `NNNN-kebab-title.md`, using the next free number. Numbers are never reused.
2. Fill every section. Tag claims about crates, audits, standards and benchmarks as V (verified), L (likely) or U (unverified).
3. Add a row to the index below in the same PR.
4. Open the PR with `Status: Proposed`. Acceptance is a separate change by the owner.

## Index

| # | Title | Status | Milestone |
|---|---|---|---|
| 0000 | [Template](0000-template.md) | Template | – |
| 0001 | [Record architecture decisions](0001-record-architecture-decisions.md) | Superseded by [0020](0020-partial-supersession.md) | M0 |
| 0002 | [Own protocol, not Bitwarden-API compatible](0002-own-protocol.md) | Partially superseded by [0022](0022-server-mode-only.md) (point 3 in part) | M1 |
| 0003 | [Authentication: OPAQUE](0003-authentication-opaque.md) | Partially superseded by [0022](0022-server-mode-only.md) (point 10) | M1 |
| 0004 | [Key derivation: Argon2id and the Secret Key](0004-key-derivation-argon2id-secret-key.md) | Accepted | M1 |
| 0005 | [Symmetric encryption: AEAD and key commitment](0005-symmetric-encryption-aead.md) | Accepted | M1 |
| 0006 | [Key hierarchy, per-user keypairs and key wrapping](0006-key-hierarchy.md) | Partially superseded by [0022](0022-server-mode-only.md) (point 1 in part, point 11 in part, Risks in part) | M1 |
| 0007 | [Versioned ciphertext envelope and crypto agility](0007-ciphertext-envelope.md) | Partially superseded by [0054](0054-attachments-envelope-and-api.md) (§3 in part) | M1 |
| 0008 | [Account recovery: Emergency Kit](0008-account-recovery.md) | Partially superseded by [0022](0022-server-mode-only.md) (point 7) | M1 |
| 0009 | [Cryptographic dependency and memory-hygiene policy](0009-crypto-dependency-policy.md) | Partially superseded by [0019](0019-native-clients.md) ("RNG rules" in part); [0052](0052-icon-proxy-role.md) (Amendments, 2026-10-05 entry, "Where it is applied" in part); [0077](0077-webauthn-rs-integration-fixes.md) ("RNG rules" in part, owner decision 1 in part, Amendments 2026-10-22 entry in part) | M1 |
| 0010 | [Server shape: modular monolith with roles](0010-server-shape.md) | Partially superseded by [0022](0022-server-mode-only.md) (§1 in part); [0053](0053-hibp-breach-check-egress.md) (§1 in part) | M1 (`api`, `web`, `worker`) / M3 (`notify`, `icons`) / M6 (`smtp`) |
| 0011 | [Storage: SQLite and PostgreSQL via sqlx](0011-storage.md) | Partially superseded by [0022](0022-server-mode-only.md) (point 9 in part, "Transactions and concurrency" in part, "What is stored, by sync mode", "Backups" in part); [0047](0047-opaque-secrets-operator-commands.md) (owner decision 3 in part) | M1 (SQLite) / M3 (PostgreSQL supported) |
| 0012 | [Sync engine: op log, HLC and version vectors](0012-sync-engine.md) | Partially superseded by [0018](0018-item-record-encoding.md) (§1 in part, §3 in part, §4 in part, §5 in part, §6 in part, §7 in part, §12 in part); [0021](0021-server-compaction.md) (§6 in part, §7 in part); [0022](0022-server-mode-only.md) (Milestone line, §5 in part, §6 in part, §8, §9 in part, §10, §11, §12 in part, owner decisions 3, 5 and 8, Risks in part); [0032](0032-healing-rotation-after-backup.md) (§7 in part); [0050](0050-paged-fetch-tombstone-boundary.md) (§7 in part); [0081](0081-multiple-vaults-personal-and-shared.md) (§1 in part) | M1 (engine, Server mode) |
| 0013 | [Shared Rust client core (wasm + UniFFI)](0013-shared-client-core.md) | Partially superseded by [0022](0022-server-mode-only.md) (§3 in part); [0019](0019-native-clients.md) (Milestone line, Context in part, §1 in part, §2 in part, §3 in part, §5, §6 in part, Negative in part, Risks in part) | M1 (wasm, CLI) / M3 (native desktop bindings) / M7 (UniFFI) |
| 0014 | [UI stack for the web platforms](0014-ui-stack.md) | Partially superseded by [0022](0022-server-mode-only.md) (§6) | M1 (web vault) / M2 (extensions) / M3 (design system) / M5 (share page) |
| 0015 | [Desktop shell: Tauri](0015-desktop-tauri.md) | Superseded by [0019](0019-native-clients.md) | M3 |
| 0016 | [Workspace layout and crate boundaries](0016-workspace-layout.md) | Partially superseded by [0022](0022-server-mode-only.md) (§3 in part); [0019](0019-native-clients.md) (§3 in part, R2 in part, R5, R6, R7 in part, §5 in part, §7, Risks in part, Alternatives considered in part) | M0 (rules, current crates) / M1–M9 (planned crates) |
| 0017 | [Licensing and contribution terms](0017-licensing.md) | Partially superseded by [0073](0073-signed-images-sbom-provenance.md) (§7 in part) | M0 |
| 0018 | [Item-record encoding: canonical binary layout and the M1 item schema](0018-item-record-encoding.md) | Partially superseded by [0076](0076-autocomplete-driven-autofill.md) (§7 in part) | M1 |
| 0019 | [Native desktop and mobile clients in separate repositories](0019-native-clients.md) | Accepted | M3 (desktop) / M7 (mobile) |
| 0020 | [Record architecture decisions, with partial supersession](0020-partial-supersession.md) | Accepted | M0 |
| 0021 | [Server-side compaction with concurrent snapshots](0021-server-compaction.md) | Partially superseded by [0032](0032-healing-rotation-after-backup.md) (§9 "Healing request" in part); [0050](0050-paged-fetch-tombstone-boundary.md) (§4 "Covers" in part); [0081](0081-multiple-vaults-personal-and-shared.md) (§9 in part) | M1 (server; Accepted before step 3) |
| 0022 | [Server mode only: On-device sync parked](0022-server-mode-only.md) | Accepted | M1 (scope) / post-1.0 (parked) |
| 0023 | [Logical database backup file format](0023-logical-backup-format.md) | Partially superseded by [0071](0071-encrypted-db-backup-format.md) (§2 in part) | M1 |
| 0024 | [Disabling core dumps through rustix](0024-core-dump-disabling-rustix.md) | Accepted | M1 (server, `rv`) / M3 (bindings) |
| 0025 | [Key rotation upload: the vault half and the rotation cut-off](0025-rotation-vault-half.md) | Partially superseded by [0081](0081-multiple-vaults-personal-and-shared.md) (§1 in part, §3 in part) | M1 |
| 0026 | [Client device state and encrypted local cache](0026-client-device-state-and-cache.md) | Partially superseded by [0051](0051-equivalence-list-version-persistence.md) (§3 in part); [0056](0056-local-index-recently-used-search.md) (§1 in part, §3 in part); [0057](0057-device-state-v2-keystore.md) (§1 row "Device-state record"; §4 step 5); [0046](0046-recovery-pending-device-stage.md) (§2, §3, §4 in part) | M1 (`rv`) / M2 (extension) / M3 (`rizzy-ffi`) |
| 0027 | [Export payload encoding and plaintext export](0027-export-payload.md) | Partially superseded by [0034](0034-export-reauth-and-plaintext-hold.md) (§5 in part); [0074](0074-passkey-cxf-import-export.md) (§1 in part) | M1 |
| 0028 | [`/api/v1` HTTP conventions](0028-api-v1-http-conventions.md) | Partially superseded by [0031](0031-retiring-old-opaque-setups.md) (item 3 in part); [0032](0032-healing-rotation-after-backup.md) (item 3 in part); [0048](0048-per-account-storage-quota.md) (item 3 in part, item 12 in part); [0049](0049-web-role-route-table.md) (item 10 in part, item 15); [0052](0052-icon-proxy-role.md) (item 1 in part; item 10 in part: the `blob:` token of `img-src`); [0071](0071-encrypted-db-backup-format.md) (item 13); [0075](0075-session-listing-and-ending.md) (item 1 in part); [0081](0081-multiple-vaults-personal-and-shared.md) (item 1 in part) | M1 |
| 0029 | [KeePass KDBX import: legacy primitives in `rizzy-import`](0029-kdbx-import.md) | Accepted | M3 |
| 0030 | [Client-side TLS for `rv`](0030-client-tls-rv.md) | Partially superseded by [0035](0035-ca-file-ca-certificates-only.md) (Decision 5 in part); [0052](0052-icon-proxy-role.md) (Decision 1 in part) | M1 |
| 0031 | [Retiring old OPAQUE setups](0031-retiring-old-opaque-setups.md) | Accepted | M1 |
| 0032 | [Healing a key rotation made after a backup](0032-healing-rotation-after-backup.md) | Accepted | M1 |
| 0033 | [Protocol Buffers encoding for client–server messages](0033-protobuf-api-encoding.md) | Accepted | M1 (JSON only) / M3 (trigger re-checked) |
| 0034 | [Re-authentication before every export and a hold before plaintext export](0034-export-reauth-and-plaintext-hold.md) | Partially superseded by [0074](0074-passkey-cxf-import-export.md) (point 3 in part) | M1 |
| 0035 | [A private CA file holds CA certificates only](0035-ca-file-ca-certificates-only.md) | Accepted | M1 |
| 0036 | [Browser extension: architecture and key custody](0036-browser-extension-architecture-and-key-custody.md) | Partially superseded by [0040](0040-extension-fill-request-from-inline-menu.md) (§4, first bullet, in part); [0043](0043-inline-menu-instance-token.md) (§4, first bullet, in part); [0076](0076-autocomplete-driven-autofill.md) (§4 in part) | M2 |
| 0037 | [URL matching and autofill rules](0037-url-matching-and-autofill-rules.md) | Accepted | M2 |
| 0038 | [Equivalent-domain list: format, signing and governance](0038-equivalent-domain-list.md) | Partially superseded by [0044](0044-equivalence-group-member-rules.md) (§1 in part), [0080](0080-default-site-groups-vaultwarden-seed.md) (§2 in part) | M2 |
| 0039 | [Passkeys in the vault and in the browser extension](0039-passkeys-vault-and-extension.md) | Accepted | M2 |
| 0040 | [The extension's fill request comes from the inline menu, not the content script](0040-extension-fill-request-from-inline-menu.md) | Partially superseded by [0043](0043-inline-menu-instance-token.md) (point 1 in part, point 3 in part); [0076](0076-autocomplete-driven-autofill.md) (point 2; "What this ADR supersedes" in part) | M2 |
| 0041 | [Approving the `p256` crate for ES256 (ECDSA P-256) in passkeys](0041-p256-crate-approval.md) | Accepted | M2 |
| 0042 | [ACCOUNT_SETTINGS plaintext: canonical layout and the M2 matching section](0042-account-settings-matching-layout.md) | Partially superseded by [0081](0081-multiple-vaults-personal-and-shared.md) (§2 in part) | M2 |
| 0043 | [A per-instance token for the inline-menu and passkey-consent iframes](0043-inline-menu-instance-token.md) | Accepted | M2 |
| 0044 | [Equivalence-group member rules: no IP literals, registrable domains only](0044-equivalence-group-member-rules.md) | Accepted | M2 |
| 0045 | [Server-side notification of pending and completed account recovery](0045-recovery-pending-notification.md) | Accepted | M1 |
| 0046 | [A recovery-pending device-state stage for `rv recovery complete`](0046-recovery-pending-device-stage.md) | Accepted | M1 |
| 0047 | [Operator commands for OPAQUE secrets: restore and invalidate](0047-opaque-secrets-operator-commands.md) | Accepted | M1 |
| 0048 | [Per-account storage quota and its wire error code](0048-per-account-storage-quota.md) | Accepted | M1 |
| 0049 | [Web role: a fixed, enumerable route table (compiled-in assets + share links)](0049-web-role-route-table.md) | Accepted | M1 |
| 0050 | [Paged Fetch: tombstone covers that can span a page boundary](0050-paged-fetch-tombstone-boundary.md) | Accepted | M1 |
| 0051 | [Persisting the highest accepted equivalence-list version](0051-equivalence-list-version-persistence.md) | Accepted | M2 |
| 0052 | [Icon-proxy (favicon) role: fetch, cache and re-encode mechanism](0052-icon-proxy-role.md) | Accepted | M3 |
| 0053 | [Watchtower/HIBP breach-check egress route](0053-hibp-breach-check-egress.md) | Accepted | M3 |
| 0054 | [Encrypted attachments: chunk layout, storage shape and upload/download API](0054-attachments-envelope-and-api.md) | Accepted | M3 |
| 0055 | [M3 item types: field keys for SSH key, API credential, software license, Wi-Fi and bank account](0055-m3-item-type-field-keys.md) | Partially superseded by [0078](0078-retire-bank-account-item-type.md) (§1 in part, §2, §3, §4 in part) | M3 |
| 0056 | [M3 local index: recently-used tracking and client-side search](0056-local-index-recently-used-search.md) | Partially superseded by [0081](0081-multiple-vaults-personal-and-shared.md) (§3 in part) | M3 |
| 0057 | [Device-state record version 2: OS-keystore-backed local unlock (`E_ks`)](0057-device-state-v2-keystore.md) | Accepted | M3 |
| 0058 | [WebAuthn/FIDO2 security keys as a server-side second factor](0058-webauthn-2fa-second-factor.md) | Partially superseded by [0077](0077-webauthn-rs-integration-fixes.md) (point 1 in part, points 2, 4 and 8, owner answer 3, "Owner answers at acceptance" closing paragraph in part) | M3 |
| 0059 | [Crypto-crate approval: webauthn-rs for the FIDO2 2FA ceremony](0059-webauthn-rs-crate-approval.md) | Partially superseded by [0077](0077-webauthn-rs-integration-fixes.md) (Decision "Recommendation" in part, checklist item 7 in part, owner answers 1 and 6) | M3 |
| 0060 | [Admin panel: web stack, directory and security boundary](0060-admin-panel-stack-boundary.md) | Accepted | M3 |
| 0061 | [notify role: WebSocket connect authentication and message envelope](0061-notify-websocket-protocol.md) | Proposed | M3 |
| 0062 | [Markdown-in-notes rendering: sanitization and rendering rules](0062-markdown-notes-sanitization.md) | Accepted | M3 |
| 0063 | [Share snapshot plaintext layout and link/fragment grammar](0063-share-snapshot-format.md) | Proposed | M5 |
| 0064 | [Share API, storage and lifecycle](0064-share-api-storage-lifecycle.md) | Proposed | M5 |
| 0065 | [Share recipient page origin and CSP](0065-share-page-origin-csp.md) | Proposed | M5 |
| 0066 | [Recipient email verification by one-time code](0066-share-email-otp-verification.md) | Proposed | M5 |
| 0067 | [Send-style text/file share](0067-send-style-share.md) | Proposed | M5 |
| 0068 | [Alias identity model, storage, and no-enumeration lookup](0068-alias-identity-model.md) | Proposed | M6 |
| 0069 | [SMTP ingress architecture: own listener vs MTA handoff, and the smtp↔api protocol](0069-smtp-ingress-architecture.md) | Proposed | M6 |
| 0070 | [Crypto-crate approval: mail-auth for SPF/DKIM/DMARC verification](0070-mail-auth-crate-approval.md) | Proposed | M6 |
| 0071 | [Encrypted scheduled database backup format (SERVER_DB_BACKUP envelope)](0071-encrypted-db-backup-format.md) | Accepted | M8 |
| 0072 | [Remote backup destinations (WebDAV, S3) and destination-credential storage](0072-remote-backup-destinations.md) | Proposed | M8 |
| 0073 | [Signed release images, SBOM and supply-chain provenance](0073-signed-images-sbom-provenance.md) | Accepted | M8 |
| 0074 | [Passkey import/export via the FIDO Credential Exchange Format (CXF)](0074-passkey-cxf-import-export.md) | Accepted | M8 |
| 0075 | [Session management: listing and ending sessions under `/api/v1/sessions`](0075-session-listing-and-ending.md) | Accepted | M3 |
| 0076 | [Autocomplete-driven autofill: field detection, TOTP-code fill and custom-field autocomplete ids](0076-autocomplete-driven-autofill.md) | Accepted | M3 |
| 0077 | [webauthn-rs integration: deny wrappers, ceremony-state storage, RNG rule and stored credential shape](0077-webauthn-rs-integration-fixes.md) | Partially superseded by [ADR 0082](0082-security-keys-user-presence-only.md) (§2 in part, §7, §9 entries 4, 5, 6, 9 and 13, §10 in part, owner answers at acceptance in part) | M3 |
| 0078 | [Retire the Bank account item type (`0x0009`) and its `bank.` field keys](0078-retire-bank-account-item-type.md) | Accepted | M3 |
| 0079 | [Identity generator: pre-filled new identities, the `identity.sex` and `identity.birthday` keys, bundled name and address data, and the masked-email seam](0079-identity-generator.md) | Accepted | M3 / M6 |
| 0080 | [Default site groups: seeding the signed global equivalence list from Vaultwarden's `global_domains.json`](0080-default-site-groups-vaultwarden-seed.md) | Accepted | M2 |
| 0081 | [Multiple vaults per account: the Personal vault, user-created vaults, and sharing a vault with other users](0081-multiple-vaults-personal-and-shared.md) | Accepted | M3 (Part A) / M9 (Part B) |
| 0082 | [Security keys: user presence only (`danger-user-presence-only-security-keys`)](0082-security-keys-user-presence-only.md) | Accepted | M3 |
| 0083 | [Erratum to ADR 0071: `plaintext_len` is bound by the canonical reader's framing, not by chunk AAD](0083-db-backup-plaintext-len-erratum.md) | Proposed | M8 |
| 0084 | [Bare, unencrypted CXF passkey export (answers ADR 0074 open question 4)](0084-bare-cxf-passkey-export.md) | Proposed | M8 |
| 0085 | [Admin authentication: operator accounts, the bootstrap token, mandatory TOTP and admin sessions](0085-admin-authentication-bootstrap.md) | Proposed | M3 |
| 0086 | [Instance settings persistence: the `auth_instance_settings` table, precedence over configuration, and the sealed SMTP credential (`SERVER_SMTP_CREDENTIAL`, 0x0103)](0086-instance-settings-persistence.md) | Proposed | M3 |
| 0087 | [Invite-only signup: invite tokens, issuance, delivery and redemption (answers ADR 0060 open question 6)](0087-invite-only-signup-tokens.md) | Proposed | M3 |
| 0088 | [Erratum to ADRs 0046 and 0057: one device-state record grammar (record version 1 or 2, stages 1–3)](0088-device-state-record-grammar.md) | Proposed | M1 |
| 0089 | [Extension-origin frames: one content-script message list, the save-dialog instance token, the save-prompt token and the save dialog's visibility gates (reconciles ADRs 0043 and 0076)](0089-extension-frames-and-save-dialog.md) | Proposed | M3 |
| 0090 | [Per-account security event log: `auth_security_events`, event kinds, the `security-events/list` endpoint and the alert summary](0090-per-account-security-event-log.md) | Proposed | M3 |
| 0091 | [Device revocation: the revocation window, the revoked-device rotation race and its accepted residual](0091-revoked-device-rotation-race.md) | Proposed | M3 |
| 0092 | [Rotation size limits: a write-time cap on wrap-set rows, the `rotation_limit` code, and staged rotation so revocation and recovery never fail on size](0092-rotation-size-limits.md) | Proposed | M3 |
| 0095 | [The owner's answers to ADRs 0023–0028, recorded from their acceptance commits, and the ADR 0026, 0027 and 0028 text they contradict](0095-owner-answers-0023-0028-recorded.md) | Proposed | M1 |
| 0096 | [Secrets that cross the client binding (ADR 0013 §3 rule 2, restated in full), and KeePass KDBX import inside the web vault's one core Worker](0096-binding-secrets-and-kdbx-worker.md) | Proposed | M1 / M3 |
| 0097 | [Website matching corrections: the compared URL, the *Regex* mode, and reading ACCOUNT_SETTINGS independently of the reader's PSL](0097-website-matching-corrections.md) | Proposed | M2 |
| 0098 | [Security keys: per-account and per-key limits, the six `webauthn` endpoints and `pending_id` (erratum to ADRs 0077 and 0028)](0098-security-key-limits-and-endpoints.md) | Proposed | M3 |
| 0099 | [Website icons: a per-account opt-in, off by default, and no request while the setting or the `icons` role is off (erratum to ADR 0052)](0099-website-icons-opt-in.md) | Proposed | M3 |
| 0093 | [Attachment lifecycle: cleanup after Purge (`attachments/delete-item`), export and import, and unsupported items on move (answers review D1, D2, D6)](0093-attachment-lifecycle.md) | Proposed | M3 |

## Gates

- **Before external contributions are merged:** 0020, 0016 and 0017 Accepted, and ADR 0017's App Store permission (Decision 3) committed. Documentation PRs are exempt.
- **Before any vault code in M1:** 0002–0009 and 0016 Accepted. 0002–0009 are reviewed as one set against [CRYPTO.md](../CRYPTO.md). A Rejected ADR blocks its area until an Accepted replacement exists.
- **Before server and client scaffolding in M1:** 0010–0014 Accepted.
- **Before desktop work in M3:** 0019 Accepted. For Windows (Linux): spike S2 (S3) recorded as passed, in an ADR 0019 `## Amendments` entry, for the route of ADR 0019 owner decision 8 (9); or, after a failed spike, an Accepted ADR that records the replacement route.
