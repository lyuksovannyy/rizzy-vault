# ADR 0022: Server mode only: On-device sync parked

- Status: Accepted
- Date: 2026-09-27
- Deciders: project owner
- Milestone: M1 (scope) / post-1.0 (parked)
- Supersedes: in part, [ADR 0002](0002-own-protocol.md), [0003](0003-authentication-opaque.md), [0006](0006-key-hierarchy.md), [0008](0008-account-recovery.md), [0010](0010-server-shape.md), [0011](0011-storage.md), [0012](0012-sync-engine.md), [0013](0013-shared-client-core.md), [0014](0014-ui-stack.md) and [0016](0016-workspace-layout.md), on acceptance and only once [ADR 0020](0020-partial-supersession.md) (Record architecture decisions, with partial supersession) is Accepted. §1 lists the parts.

## Context

[ROADMAP](../ROADMAP.md) M4 planned two sync modes. In **Server mode** the server stores the encrypted vault and op log ([ADR 0012](0012-sync-engine.md) §7, built in M1). In **On-device mode** the server is only an encrypted relay and version tracker, with no durable vault copy.

- **Cost.** On-device mode is almost all of M4: a relay-only server with ack sets, a pending-op TTL and stale devices; re-sync from a peer; pairing over the relay (QR or short code, SAS, sealed transfer); mode selection and an admin limit on modes; switching both ways with deletion receipts; data-loss guardrails; batching of relayed ops (ADR 0012 §8–§10; [CRYPTO.md](../CRYPTO.md) §5.7, §11.7, §11.12). It adds audit target 7 and INV-28, INV-29 and INV-31. This is a one-person project (ROADMAP §6, risk 1).
- **Gain.** In Server mode the server already holds only ciphertext ([THREAT_MODEL](../THREAT_MODEL.md) G-1). With the Secret Key, even its database plus `server_setup` gives no offline password attack (CRYPTO.md §5.5). On-device mode would remove the OPAQUE record and the password-derived wraps (INV-28) and some metadata. Users who distrust a hosted server can self-host, which is what the product is (ROADMAP §1).
- **Risk it brings.** Losing every device loses the vault (AR-13). Until this change, ROADMAP §6 risk 8 read: "On-device sync turns support tickets into data loss."
- **What exists.** `rizzy-core` registers the On-device purposes, labels and ids so their values stay reserved, with no construction behind them. `rizzy-sync` is an empty skeleton. No M1 code depends on On-device mode (survey of 2026-09-27).

## Decision

1. **On-device mode is parked** as a post-1.0 idea. Server mode is the only sync mode. Parked means out of v1.0 scope, and only a new ADR brings it back. It covers everything ROADMAP M4 and §4.6 (before this change) and ADR 0012 §8–§10 describe for it: the relay-only server (pending encrypted ops, per-device version vectors, ops purged once acked, batching of relayed ops); the pending-op TTL, stale devices and re-sync from a peer; new-device enrolment by pairing with an existing device over the relay (QR or short code, SAS, `PAIRING_TRANSFER`); mode selection at account creation and the admin restriction of modes; mode switching both ways, with deletion receipts; the On-device data-loss guardrails; and direct LAN sync, which only skips the relay.
2. **Its ids stay reserved and its code stays dormant** in `rizzy-core`, unchanged and not removed: purposes 0x0040 `RELAY_BATCH`, 0x0041 `PAIRING_TRANSFER`, 0x0042 `PAIRING_TRANSFER_SEALED` and 0x0043 `RESYNC_TRANSFER`; labels `relay-key`, `hpke-psk/resync`, `hpke-psk/pairing`, `pairing/key`, `pairing/commit` and `pairing/sas`; the ids `PairingId` and the re-sync `TransferId`; and, under the same rule, the values only On-device mode uses: purpose 0x0005 `PASSWORD_VERIFIER_GRANT`, label `hpke-psk/password-verifier` (CRYPTO.md §11.5) and `sync_mode` value 2 in `account-state` (CRYPTO.md §10.2). Only an ADR that revives On-device mode may use them. Nothing else may reuse them.
3. **M4 keeps its number and is marked removed**, so M5–M10 keep theirs. Nothing is renumbered. Three M4 items move: the conflict UI ("edited on Phone and Laptop at the same time — keep both / pick one") to M3; the transparency page ("exactly what the server stores for this account", Server mode only) to M3; scheduled encrypted backups to user-chosen storage (local folder, WebDAV, S3-compatible) to M8. Every other M4 item is dropped with the mode. Rows under ROADMAP §4.6 that M1 builds stay; the single sync engine loses "for both modes".
4. **Recording.** ROADMAP.md and the project [README](../../README.md) record the scope change now; ROADMAP is the source of truth for scope (ADR 0020 point 7). This ADR records the changes to Accepted ADRs, by partial supersession (ADR 0020 point 9), and lists the design-doc and code edits for its acceptance.
5. **Two in-scope items tied to M4 move** (owner, 2026-09-27): the 30 consecutive green nightly property-test days of ADR 0012 owner decision 5 now gate v1.0 (M8); the device-management ADR that settles the revoked-device rotation race (ADR 0006 "Risks", CRYPTO.md §11.6, AR-18) belongs to M3, with session and device management (ROADMAP §4.3).

### 1. What this ADR supersedes

Under ADR 0020 point 9, this ADR supersedes exactly these parts. "Nothing" means the part is parked with On-device mode and no text replaces it.

| Part, quoted | Replaced by |
|---|---|
| ADR 0002 point 3, "Paths", `GET /api/meta` list, second sub-bullet: "the sync modes the admin allows;" | nothing |
| ADR 0003 point 10: "**On-device mode** stores no OPAQUE record at all." | nothing |
| ADR 0006 point 1, last sentence: "Where each wrapped-key object lives in Server mode and in On-device mode is fixed in one table ([CRYPTO.md §4.2](../CRYPTO.md#42-key-inventory))." | "Where each wrapped-key object lives is fixed in one table ([CRYPTO.md §4.2](../CRYPTO.md#42-key-inventory))." |
| ADR 0006 point 11 "Rotation", first sub-bullet, first sentence: "Account and vault keys rotate on device revocation, recovery, an SK change, a switch to On-device mode, or suspected compromise." | "Account and vault keys rotate on device revocation, recovery, an SK change, or suspected compromise." |
| ADR 0006 "Risks", second bullet, last sentence: "The M4 device-management ADR must settle this." | "The M3 device-management ADR (ROADMAP §4.3) must settle this." (point 5) |
| ADR 0008 point 7: "**On-device mode.** There is no server copy. The encrypted backup file (M4) holds the backup key wrapped twice: …" | nothing |
| ADR 0010 §1 roles table, rows `api` and `worker` | §2 |
| ADR 0011 point 9 "When migrations run", "SQLite", third sub-bullet: "An account deletion or a Server → On-device switch deletes the copy at once. …" | "An account deletion deletes the copy at once. Otherwise the copy would still hold what that deletion removed. The operator then has only their own backups to fall back on." |
| ADR 0011 "Transactions and concurrency", "One lock per account", third sub-bullet, last sentence: "A cross-domain operation (revocation, account deletion, mode switch) is one transaction that takes the lock once." | "A cross-domain operation (revocation, account deletion) is one transaction that takes the lock once." |
| ADR 0011 "What is stored, by sync mode": heading, table and closing sentence | §2 |
| ADR 0011 "Backups", "What a restore cannot do", first sub-bullet: "A DB backup holds nothing of On-device-mode vaults. …" | nothing |
| ADR 0012 Milestone line: "M1 (engine, Server mode) / M4 (On-device mode, pairing, mode switch)" | "M1 (engine, Server mode)" |
| ADR 0012 §5 "Purge", "Only clients purge" sub-bullet, third sentence: "In Server mode as in On-device mode, auto-purge happens only when some client is online after the retention period." | "Auto-purge happens only when some client is online after the retention period." |
| ADR 0012 §6 "Revocation has two phases", "Phase 1" sub-bullet, second sentence: "From that commit on (under the account lock), the server rejects the device's uploads and device authentication and ends its sessions, the relay rejects its batches, and the server returns H, the highest `device_seq` it holds from that device." | "From that commit on (under the account lock), the server rejects the device's uploads and device authentication, ends its sessions, and returns H, the highest `device_seq` it holds from that device." |
| ADR 0012 §6 "Revocation has two phases", fourth sub-bullet: "In On-device mode the relay cannot see `device_seq`. …" | nothing |
| ADR 0012 §8 "On-device mode (M4)" and §10 "Mode switch (M4)", each in full, and owner decision 8: "**Server-mode ciphertext after a switch to On-device mode** → Delete at the switch point …" | nothing |
| ADR 0012 §9, the "**Pairing**" bullet with its sub-bullets, and the "**Stale re-sync**" bullet | nothing; the "**In Server mode,**" bullet stays |
| ADR 0012 §11 "What the server can and cannot see", in full | §2 |
| ADR 0012 §12 "Harness", first sub-bullet: "3–7 simulated devices, plus a simulated server (Server mode) or relay (On-device mode)." | "3–7 simulated devices, plus a simulated server." |
| ADR 0012 §12 "Generated histories", sub-bullets "relay TTL expiry;", "device revocation and pairing a new device;" and "mode switches in both directions, with expired and live web-vault sessions, and a device that is offline at the switch point." | the second becomes "device revocation;"; the other two, nothing |
| ADR 0012 §12 "Properties", item 5 ("**Staleness.** A device offline past the TTL detects it, and never merges silently."), and the "**Named scenario**" bullet ("… three devices, one of them offline past the TTL, a Server → On-device → Server round trip. …") | nothing; items 6 and 7 keep their numbers |
| ADR 0012 owner decision 3: "**Defaults** → Accepted as starting values, to be revisited with M3/M4 data: relay TTL 90 days (admin range 7–365 days); …" | "3. **Defaults** → Accepted as starting values, to be revisited with M3 data: trash retention 30 days; history N = 50 per field; a snapshot after 32 ops." |
| ADR 0012 owner decision 5: "**M4 release gate** → Yes: 30 consecutive days of green nightly property runs before M4 ships." and "Risks", first bullet, last sentence: "The proposal is that M4 does not ship until the nightly job has been green for 30 consecutive days (open question 5)." | "5. **Release gate** → Yes: 30 consecutive days of green nightly property runs before v1.0 (M8) ships." and "v1.0 (M8) does not ship until the nightly job has been green for 30 consecutive days (open question 5)." (point 5) |
| ADR 0013 §3 rule 2 "Named exceptions", eighth sub-bullet: "the pairing QR payload, which carries `pairing_secret`, …" | nothing |
| ADR 0014 §6 "Web vault login and On-device accounts", in full (the login notice for On-device accounts and its Playwright test) | nothing |
| ADR 0016 §3 "Planned crates" table, row `rizzy-domain-relay` | nothing |

Everything these ADRs say that the table does not name stays binding, with its meaning (ADR 0020 point 9). That includes ADR 0012 §9 "In Server mode" and §13, and the text that defines or governs the reserved ids: ADR 0005 point 5, ADR 0006 points 6 and 9, ADR 0007's allow-lists and ADR 0009's composition list. [ADR 0018](0018-item-record-encoding.md) (Accepted) is not superseded: its "M4 ADR" (§3 "Snapshots are claims", owner decision 16) reads as the ADR that revives On-device mode. **Limit** (ADR 0020 point 9): the ADR 0012 parts come to about 1,340 of the 5,146 words of its Decision, 26 %. With ADRs 0018 and 0021 it is at most about 2,270, 44 % (`wc -w` on whole lines, 2026-09-27, V). Each other ADR loses less; ADR 0011, the largest, about 320 of 2,406.

### 2. Replacing text

**ADR 0010 §1, roles table, rows `api` and `worker`:**

| Role | Does | DB access | Inbound | Outbound | From |
|---|---|---|---|---|---|
| `api` | OPAQUE, sessions, devices, vault and op log (Server mode), shares, aliases, admin API, internal ingress endpoints for `smtp` | yes | public API through the reverse proxy; internal listener; admin listener | none | M1 |
| `worker` | Scheduled deletion: expired shares, mail past retention, expired auth state (ADR 0010 §5). Deletes an item's server-side op bodies and snapshots only behind a client-signed snapshot or tombstone (compaction, [ADR 0012](0012-sync-engine.md) §7). **Does not purge trash** (ADR 0010 §1) | yes | none | SMTP relay for notification mail, if configured (M3) | M1 |

**ADR 0011 "What is stored, by sync mode"** becomes "What is stored": [THREAT_MODEL §3.4](../THREAT_MODEL.md#34-what-the-server-holds-by-sync-mode) is the authoritative list. By domain:

| Domain | Stored |
|---|---|
| `auth` | accounts; OPAQUE records with `setup_id`; `E_srv`, `E_rec`, `H_rec`; session-token hashes; 2FA secrets encrypted under a server key kept outside the DB ([CRYPTO.md §5.11](../CRYPTO.md#511-server-side-encryption-not-zero-knowledge)); device certificates and revocations; key bundles; signed `account-state`; key grants; short-lived auth state: sealed login state, challenges, rate-limit counters, pending recoveries ([ADR 0010](0010-server-shape.md) §5) |
| `vault` | vault self-grants, item-key wraps, per-item snapshots, op records not yet compacted, signed op headers kept after compaction, per-device cursors ([ADR 0012](0012-sync-engine.md)) |
| `share` (M5) | share envelopes, link-token and access-token hashes ([CRYPTO.md §11.10](../CRYPTO.md#1110-public-share-link-creation-m5)), expiry, view counts |
| `mail` (M6) | aliases, the alias → account mapping, mail envelopes, retention dates |
| `org` (M9) | defined in M9 |

**ADR 0012 §11 "What the server can and cannot see":**

| Data | Server sees |
|---|---|
| Account, device ids, device certificates, `account-state`, sync mode | yes |
| Vault ids, item ids, item count | yes |
| Per op: `device_seq`, `vault_prev_seq`, HLC, causal context, padded size, upload time | yes, and the signed header is kept for the life of the vault (ADR 0012 §7) |
| Ops per item; which device edited which item | yes |
| Snapshot VVs and padded sizes | yes |
| Field names and values, item type, history, conflicts, tags, URLs | **no** |
| Which device fetched or acked what, and when | yes |

This matches [THREAT_MODEL §3.4](../THREAT_MODEL.md#34-what-the-server-holds-by-sync-mode). In Server mode, the HLC and causal context in the header reveal when an offline edit was made and which devices had seen what. Snapshot VVs would reveal most of that anyway. We accept it as metadata ([NG-5](../THREAT_MODEL.md#14-non-goals)).

### On acceptance

None of these edits is made now. The owner makes them in the change that accepts this ADR.

1. **Order.** ADR 0020 is Accepted first, or in the same change.
2. **Status lines.** Each ADR below gains "Partially superseded by [ADR 0022](0022-server-mode-only.md) (…)", after any earlier entry and separated from it by a semicolon (ADR 0020 point 9): 0002 (point 3 in part); 0003 (point 10); 0006 (point 1 in part, point 11 in part, Risks in part); 0008 (point 7); 0010 (§1 in part); 0011 (point 9 in part, "Transactions and concurrency" in part, "What is stored, by sync mode", "Backups" in part); 0012 (Milestone line, §5 in part, §6 in part, §8, §9 in part, §10, §11, §12 in part, owner decisions 3, 5 and 8, Risks in part); 0013 (§3 in part); 0014 (§6); 0016 (§3 in part). The Status cells in [docs/adr/README.md](README.md) follow; its row 0012 milestone becomes "M1 (engine, Server mode)", and row 0022 becomes Accepted.
3. **CRYPTO.md** (mechanism; ADR 0020 point 7):
   - Parked, heading kept for its anchor, body replaced by one line naming this ADR and the reserved ids: §5.7, §11.7, §11.12. "M4" becomes "reserved (parked, ADR 0022)": §4.2 relay-key row; §4.3 relay-key, password-verifier, re-sync and the four pairing rows; §8.4 rows 0x0005 and 0x0040–0x0043; the §10.1 PSKs of those purposes; §10.2 `sync_mode` 2; §1 rule 2 audit target 7, number kept. To M8: §8.4 `BACKUP_FILE` 0x0071 ("defined by the M8 backup ADR"); "M4 backup" in §9.6 and "Backups (M4)" in §14.
   - On-device text removed: the header status line; the §4.1 diagram branch; §4.2's On-device column and backup and relay mentions; §5.5's On-device row and "password-verifier grants"; §10.2's mode-switch exception and "relay traffic"; pairing in the §11 flow table; the On-device parts of §11.3 steps 4–5, §11.4, §11.5, §11.6 (trigger, steps 1, 7, 9, 10), §11.8 and §11.9; §13's pairing and re-sync row and list; §14's pairing clause and "sync mode" metadata; in §11.6 "Known limitation", "the M4 ADR on device management" becomes the M3 one (point 5); §15 item 1 ("M3, M5 and M6"; reserved constructions get vectors with the ADR that revives them); §15 item 6 marked parked.
4. **THREAT_MODEL.md** (goals and invariants, changed through this ADR as its own rule requires):
   - Marked "parked with On-device mode (ADR 0022)", ids kept: INV-28, INV-31, TB-11, A13 (summary row and section), §7.15, AR-13; Q-3 notes it. INV-29 stays for any "approve this device" flow; its From cell loses M4. Reworded: §1.1 scope (Server mode); G-6 (no "pairing SAS in M4"); NG-5 (Padmé from M1, no batching); NG-8, INV-6 and INV-30 (On-device sentence or clause removed; INV-30 From M3); INV-27 (From M1, no relay); A8 "The rotation race" and AR-18: the M4 device-management ADR becomes the M3 one (point 5).
   - Trimmed: AST-15 (deletion-receipt signing key); §3.1 (Relay row; the `api`, `worker` and server-secrets rows); §3.2 diagram; §3.4 (On-device column; source of the M3 transparency page); A2 (false deletion receipts); §4.2.1 web-vault sentence; A3 ("restrict sync modes"); A8 (two On-device sentences); §5.4–§5.6 and §5.9 (M4 and SAS); §6.3 mail-ack bullet; §7.9 relay purge; AR-3 (batching); AR-8 (M4 pairing); AR-9 (deletion receipts).
5. **Code** (doc comments, milestone tags and one xtask rule; the ids stay):
   - `rizzy-core`: in `envelope/purpose.rs` the registry's `M4` milestone tag becomes a parked tag for 0x0005 and 0x0040–0x0043, and `M8` for `BACKUP_FILE`. The "(M4)" doc tags in `labels.rs`, `ids.rs`, `lib.rs`, `hpke/mod.rs` and `sign/statements.rs` become "reserved, On-device parked (ADR 0022)". On-device sentences go from `keys/derive.rs`, `keys/wrap.rs`, `opaque/mod.rs`, `envelope/parse.rs`, the `test_vectors` docs and `tests/vectors/README.md`. No vector changes: the tier-A vectors use none of the reserved values (grep, 2026-09-27, V).
   - `rizzy-sync` crate doc: Server mode, roadmap M1; no relay, no staleness. `crates/xtask/src/rules.rs`: the planned `rizzy-domain-relay` rule and its entry in `rizzy-server`'s list go, with the ADR 0016 row. [CLAUDE.md](../../CLAUDE.md): no edit; it has no On-device text (grep, V).

## Consequences

### Positive

- Most of M4 leaves v1.0: the relay, pairing, re-sync, the TTL, mode switching and deletion receipts. No pairing or relay code exists to audit in M8, and INV-28 and INV-31 need no tests.
- One storage model to build, test and explain. A new device always logs in and downloads (ADR 0012 §9), so losing every device no longer loses the vault.
- Reserved ids and dormant code keep a revival cheap and free of collisions. M1 code, vectors and milestone numbers do not change.

### Negative

- v1.0 offers no mode without a durable server copy. The server keeps the OPAQUE record, `E_srv`, `E_rec`, snapshots and the op log for every account. A stolen database plus `server_setup` still needs the Secret Key for each guess (CRYPTO.md §5.5).
- Metadata stays with the server: item ids and counts, op headers, which device edited which item (§2; NG-5).
- Dormant code stays in `rizzy-core` with no flow using it: `AccountState` still verifies `sync_mode` 2, and `KeyGrant` still accepts 0x0005. Superseded text stays, unmarked, in ten Accepted ADRs (ADR 0020, "Negative").

### Risks

- **A reserved id is used by accident** in a v1.0 change, against point 2. Signal: a non-test use of a reserved purpose, label or id outside the `rizzy-core` registry.
- **ADR 0012's mode-agnostic claim goes untested,** since §12 no longer simulates a relay. An ADR that revives On-device mode must re-check it, and users asking for a mode with no server copy is the signal for one (ROADMAP scope first, ADR 0020 point 7).

## Alternatives considered

- **Keep M4 as planned.** It lost on cost: a milestone of relay, pairing and switching work for one person. The gain over Server mode with the Secret Key is mostly metadata (CRYPTO.md §5.5), and it brings the data loss of AR-13.
- **Drop On-device mode for good and retire its ids.** It lost to point 2: retiring means changing registry code and M1 tests, and a revival could meet reused ids. Keeping them reserved costs nothing.
- **Renumber M5–M10.** It lost to point 3: every milestone reference in ROADMAP, THREAT_MODEL, CRYPTO, the ADRs and the code would change, and Accepted ADRs change only by supersession.
- **A full successor to ADR 0012.** Not needed: the replaced parts stay under half of its Decision (§1).

## Open questions for the owner

None. The owner decided points 1–5 on 2026-09-27.

## References

- [ROADMAP.md](../ROADMAP.md) §1, §3 (M4), §4.6, §6 (risks 1 and 8), §7; [THREAT_MODEL.md](../THREAT_MODEL.md) G-1, §3.4, A13, INV-28 to INV-31, AR-13; [CRYPTO.md](../CRYPTO.md) §5.5, §5.7, §8.4, §10.2, §11.5, §11.7, §11.12
- [ADR 0020](0020-partial-supersession.md) point 9; the Accepted ADRs in §1. [ADR 0014](0014-ui-stack.md) §6 and [ADR 0018](0018-item-record-encoding.md) owner decision 16 (both Accepted); Proposed ADRs whose On-device carve-outs change with this one: [0019](0019-native-clients.md), [0021](0021-server-compaction.md)
- Word counts: `wc -w` from `## Decision` up to `## Consequences`, and on the named lines, 2026-09-27 (V for the counts as run)
