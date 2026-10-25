# ADR 0099: Website icons: a per-account opt-in, off by default, and no request while the setting or the `icons` role is off (erratum to ADR 0052)

- Status: Proposed
- Date: 2026-10-25
- Deciders: project owner
- Milestone: M3 (`rizzy-client`, `rizzy-wasm`, `packages/core`, `packages/ui`, web vault, extension)
- Supersedes: on acceptance, in part: [ADR 0052](0052-icon-proxy-role.md) (point 5, third sentence). §8 gives the replacement text ([ADR 0020](0020-partial-supersession.md) point 9). It also adds tag `0x0005` to [ADR 0042](0042-account-settings-matching-layout.md)'s registry through an amendment, the route that registry provides for (On acceptance item 2).

## Context

**Trigger.** On 2026-10-25 a ten-reviewer gap review of every ADR was committed ([docs/reviews/2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md); raw findings in [2026-10-25-raw/](../reviews/2026-10-25-raw/)). Afterwards, the same day, the owner told the team to "start" fixing the gaps. This ADR answers theme **S4**: "Favicons (ADR 0052): no user opt-in. The web vault sends every item host on unlock even when the role is off; ROADMAP says "must be optional"." It covers raw finding **G05-24**. Route: erratum and code.

**Requirement.** [ROADMAP §4.4](../ROADMAP.md#44-url-matching--autofill-m2), line 140: "W | Fetching website favicons through our server without privacy controls (leaks which sites you use) — must be optional / proxied / cached anonymously | M3 design". [ADR 0052](0052-icon-proxy-role.md) built the "proxied" and "cached anonymously" parts. The only "optional" control is the operator's: the `icons` role is off by default ([ADR 0010](0010-server-shape.md) owner decision 5, THREAT_MODEL Q-11). No Accepted text gives the user a choice, or says when a client may send a host.

**What ADR 0052 claims.** Point 5, third sentence: "No account, session or request identifier ever reaches `rizzy-icon-proxy` — the endpoint (below) carries none — so the cache cannot correlate requests to a user." That holds inside the `icons` process. It does not hold for the deployment. The endpoint shares the vault's origin and reverse proxy (`deploy/Caddyfile` lines 20–24: `reverse_proxy /api/v1/icons/* {$RIZZY_ICONS_UPSTREAM:rizzy-vault:8080}`, V). The proxy terminates TLS and also carries the account's authenticated `/api/v1` calls, from the same address and at the same moments. A browser usually sends both over one HTTP/2 connection (L, connection reuse; not tested here). [THREAT_MODEL A2](../THREAT_MODEL.md#a2-active-malicious-or-compromised-server) (line 291), an in-scope attacker, can "correlate IPs and timing". It therefore learns which sites the user has items for: data that is otherwise end-to-end encrypted item content (AST-13, line 106, already lists "domains requested from the icons role" as metadata). [INV-77](../THREAT_MODEL.md#8-security-invariants) says the same of the breach check: "IP- and timing-level correlation through the shared proxy is a separately accepted risk, not covered by this invariant". Yet no row in §9 records that risk (V, `correlat` occurs only at lines 291 and 1253).

**What the clients do today** (V, read in this worktree):

- `apps/web/src/views/VaultView.tsx` lines 159–168: one `IconLoader` per unlocked session, created unconditionally: `new IconLoader((host) => client.call("itemIcon", host))`. No setting is read.
- `packages/ui/src/ItemIcon.tsx` lines 13–18: every rendered row with a `websiteHost` calls `icons.request(websiteHost)`. `apps/web/src/views/ItemsPane.tsx` lines 181 and 271–285 render every item of the filtered list, with no windowing. The first view after unlock is "All items". So within moments of unlock, the host of every item in the list is requested. That is the review's "on unlock"; precisely, it happens on the first render of the list.
- `packages/ui/src/itemIcons.ts` lines 16–21 and 39–46: at most once per host per unlocked session, at most `MAX_CONCURRENT = 2` at once, at most `MAX_HOSTS = 2_000` hosts. "Any other failure, including "no icon" and a server without the role, shows the item-type icon and is not retried in this session." A server without the role stops nothing: every later host is still sent.
- `apps/extension/src/popup/views/Items.tsx` lines 41–51: the same loader, unconditional, for each popup view.
- With the role off, the shipped proxy sends `/api/v1/icons/*` to `rizzy-vault` (`deploy/compose.yaml` lines 119–121: "rizzy-vault itself by default, which answers 404"). There an unmatched `/api/` path answers `not_found` (`crates/rizzy-server/src/http/mod.rs` lines 122–126). Every host still crosses the proxy.
- `GET /api/meta` does not say whether the role runs: `MetaResponse` has `server_version`, `api_versions` and `min_client_versions` only (`crates/rizzy-proto/src/meta.rs` lines 221–228). The `api` process cannot know it either: the role is a separate container that the proxy routes to.

**A probe that carries no host already exists.** The `icons` role checks, in order, the source, the rate limit, the body and the parse, and answers `400 invalid_request` to a malformed host (`crates/rizzy-server/src/http/icons.rs` lines 6–17, the module docs; ADR 0052 point 6). The role's own test sends `{"host":""}` and expects `400` with `{"error":"invalid_request"}` (the same file, lines 823–848, `malformed_hosts_are_invalid_requests`). `IconHost::parse("")` is `WireError::Empty` (`crates/rizzy-proto/src/icons.rs` lines 78–80). A server without the role answers the same request `404 not_found` (above). So one request with an empty host tells a client whether the role is reachable, without sending any host and without a server change.

**Where a per-account setting goes.** `ACCOUNT_SETTINGS` is the account's end-to-end-encrypted, synced settings record ([ADR 0042](0042-account-settings-matching-layout.md) §2). Its registry: `0x0001` matching (ADR 0042 §3), `0x0002` vault directory and `0x0003` contact pins ([ADR 0081](0081-multiple-vaults-personal-and-shared.md) §A2, §B2, §0 entry 6), `0x0004` identity-generator defaults (ADR 0042 Amendments, 2026-10-24 entry, which ends "`0x0005`–`0xFFFE` stay unassigned"). The code agrees (`crates/rizzy-client/src/settings.rs` line 90, `vaults/directory.rs` line 46, `identity_gen/defaults.rs` line 31; V). ADR 0042 §2: "a new setting gets a line here by ADR amendment, **no version bump**"; an unrecognised tag is kept and re-emitted verbatim; a violation inside a recognised tag rejects the record.

**Release state.** `git tag` lists no tag (V). No build that fetches icons unconditionally has been released, so ADR 0002 point 5 needs no raise of the minimum client versions.

## Decision

### 1. The setting: "Website icons", per account, synced, `ACCOUNT_SETTINGS` tag `0x0005`

- **Layout.** Tag `0x0005`; value exactly 1 byte: `0x00` = off, `0x01` = on. Any other length or byte is a violation inside a recognised tag, rejected as ADR 0042 §2 says. There is no version field: a richer setting later is a new tag.
- **Reading.** The setting is on only when the account's `ACCOUNT_SETTINGS` record has been loaded and verified in this unlocked session and holds `0x0005` = `0x01`. In every other case it is off: an absent tag, an absent record (`settings_seq = 0`), a record not yet loaded, and a record that is rejected or parked ("update required").
- **Writing.** Turning it on writes `0x01`; turning it off writes `0x00`. It never deletes the tag, so an explicit "off" survives any later change of the default. The change is one more `SettingsEdit` over the existing whole-record settings write (ADR 0042), with its compare-and-swap and its retry.
- **Scope.** One value for the whole account, on every device and client: the web vault, the extension and the native apps (through `rizzy-client`). `rv` shows no icons. Why per account: what leaks is the list of sites, and the first device that fetches gives it all to the operator, who already links all of the account's devices through their authenticated calls. A per-device switch would only let a user believe that one device protects a list the account has already exposed.
- **Default: off** (Open question 1).

### 2. No request while the setting is off

While the setting reads off, a client sends nothing to `/api/v1/icons/fetch`: no host and no probe. The web vault and the extension create no `IconLoader` and show the item-type icon. Turning the setting off during a session clears the loader at once: the queue is dropped, every `blob:` URL is revoked, and answers to requests already in flight are discarded.

### 3. No host while the role is off: the probe

When the setting reads on, the client probes the role once per unlocked session, before any host is sent:

- **Request.** `POST /api/v1/icons/fetch` with the same headers as an icon fetch (no `Authorization` header) and the 11-byte body `{"host":""}`, exactly.
- **Outcome.** A `400` answer with code `invalid_request` means **available**. `429 rate_limited` means wait: the `Retry-After` value, or 4 s without one, at most 3 attempts in all, then **unavailable**. Anything else means **unavailable**: `404 not_found`, another code, a `2xx`, a `5xx` or a transport failure.
- **Lifetime.** The outcome holds until the session locks or the setting is turned off. The next unlock, or turning the setting on again, probes again. The client sends a host only after an "available" outcome in the current session.

### 4. Enforcement in `rizzy-client`

The rule lives in the shared core, so no host application can send a host by mistake:

- `rizzy_client::icons` gains `IconPermit`, a type with a private constructor. The only way to make one is `icon_probe_finish(status, body, setting)`, which returns it when the probe outcome is "available" and the caller passes the setting value read under §1 as on.
- `icon_request` takes `&IconPermit` as well as the host. Without a permit, no request can be built.
- `rizzy-wasm`'s `Session` holds `Option<IconPermit>`. It drops the permit on lock, on a settings write or reload that reads off, and when the session ends. The wasm icon fetch refuses without a permit, with the `CoreError` code `icons_off`. `packages/core`'s `fetchItemIcon` takes the session, and a new `probeItemIcons` runs §3.

### 5. When on and available: as shipped, no batching, no device cache

- Hosts are sent exactly as today (ADR 0052 point 6 and `packages/ui/src/itemIcons.ts`): one host per request, at most once per normalised host per unlocked session, when a row that shows it renders; at most 2 at once and 2,000 hosts per session; a 4 s pause after a rate limit; no retry after any other failure. Icons live in memory and are gone at lock.
- **No batch endpoint.** A request with many hosts would tie them together in the request itself, even for an observer who has only the `icons` process and no connection metadata. Batching saves requests and protects nothing.
- **No persistent icon cache on the device.** It would cut repeat requests, but the operator gets the whole list on the first fetch. Repeat fetches mostly reveal when the user unlocks, which the account's own sync calls already show. A device cache would also be a new persistent format, which needs its own ADR. Not now.

### 6. What the user is told

Settings, section "Website icons": one switch, off by default, with this text (English as given; translations keep the meaning):

> **Show website icons.** To show a site's icon, this app sends the site's host name (for example, `example.com`) to your server, which fetches the icon. The host names are sent without your account name, but the people who run your server could still link them to your account. This setting applies to all your devices.

When the probe says unavailable, the switch stays on and the section adds: "This server does not offer website icons." No probe is sent to word that line while the switch is off.

### 7. Server

No server change. The `icons` role, its cache, its rate limit and `icons/fetch` stay as ADR 0052 gives them, and the role stays off by default (ADR 0010 owner decision 5). An icon is fetched only when the operator runs the role *and* the user turned the setting on.

### 8. What this ADR supersedes

Under [ADR 0020](0020-partial-supersession.md) point 9, the part named below stops binding when this ADR is Accepted. The text given replaces it and binds as Decision text of this ADR. Everything else in ADR 0052 stays binding. One sentence is replaced, far within ADR 0020 point 4's limit.

**[ADR 0052](0052-icon-proxy-role.md)**

1. *Point 5, third sentence* ("No account, session or request identifier ever reaches `rizzy-icon-proxy` — the endpoint (below) carries none — so the cache cannot correlate requests to a user.") is replaced by: "No account, session or request identifier ever reaches `rizzy-icon-proxy` — the endpoint (below) carries none — so neither the role nor its cache can tie a request to a user from what the request carries. The operator of the deployment still can, through the address, connection and timing the reverse proxy sees next to the account's authenticated calls; clients therefore send a host only when the account has turned website icons on and this session's probe found the role ([ADR 0099](0099-website-icons-opt-in.md)), and the remaining exposure is an accepted risk in THREAT_MODEL §9."

ADR 0052 point 6 is not superseded: the endpoint, its body and its codes are unchanged, and the probe uses them as point 6 defines them. ADR 0042 is not superseded: tag `0x0005` is added by the amendment its registry provides for.

### 9. On acceptance (documentation edits, not made in this change)

1. **Status lines and index.** The owner adds "[ADR 0099](0099-website-icons-opt-in.md) (point 5 in part)" to ADR 0052's status line, then updates the two index rows.
2. **[ADR 0042](0042-account-settings-matching-layout.md) Amendments.** A dated entry, approved by the owner as ADR 0020 point 4 requires (the precedent is the 2026-10-24 entry for `0x0004`): "`0x0005` = website icons ([ADR 0099](0099-website-icons-opt-in.md) §1). Layout: exactly one byte, `0x00` off, `0x01` on; any other length or value is a violation inside a recognised tag, rejected as §2 says. `0x0006`–`0xFFFE` stay unassigned."
3. **[CRYPTO.md](../CRYPTO.md) "Account-settings plaintext" paragraph** (line 684): add "and tag `0x0005` (website icons) by [ADR 0099](adr/0099-website-icons-opt-in.md) §1".
4. **[THREAT_MODEL.md](../THREAT_MODEL.md):**
   - §7.11, the "I" row's mitigation cell becomes: "Per-account opt-in, off by default: a client sends a host only when the account's website-icons setting is on and this session's probe found the role ([ADR 0099](adr/0099-website-icons-opt-in.md), INV-NN). Role off by default ([Q-11](#10-open-questions-for-the-owner)). Unauthenticated shared cache. No per-user logs, of domains or of HIBP prefixes; the breach-check endpoint is rate-limited per source ([ADR 0053](adr/0053-hibp-breach-check-egress.md) item 8). Operator-side correlation: AR-MM." The Inv. cell adds INV-NN.
   - AST-13: after "domains requested from the icons role" add "(only for accounts that turned website icons on, [ADR 0099](adr/0099-website-icons-opt-in.md))".
   - **New invariant INV-NN** (the next free id at acceptance; INV-107 unless another ADR takes it first), "From" M3: "A client sends nothing to `/api/v1/icons/fetch` unless the account's website-icons setting (`ACCOUNT_SETTINGS` tag `0x0005`) reads on, and sends a website host only after a probe in the same unlocked session found the `icons` role ([ADR 0099](adr/0099-website-icons-opt-in.md) §2–§4)." Verified by: "`rizzy-client` tests (no `IconPermit` without the setting on and a probe answer of `invalid_request`); web and extension e2e: with the setting off, no request to `/api/v1/icons/` after unlock; with the setting on and the role off, exactly one request, the probe, and no host."
   - **New accepted risk AR-MM** (the next free id; AR-30 unless taken first): "With website icons on, the server operator ([A2](#a2-active-malicious-or-compromised-server), [A3](#a3-malicious-instance-admin)) can link each host requested from the `icons` role, and each breach-check prefix (INV-77), to the account, through the address, connection and timing the reverse proxy sees next to the account's authenticated calls. It learns which sites the user has items for." Why we accept it: "The icons and the breach check need the server to fetch on the user's behalf. Icons are opt-in per account and off by default, with this exposure stated where the user turns them on ([ADR 0099](adr/0099-website-icons-opt-in.md) §6); the breach check runs only when the user asks for it." Revisit: "–". This also gives INV-77's "separately accepted risk" the row it refers to.
   - Q-11: append "The user's own switch, per account and off by default, is [ADR 0099](adr/0099-website-icons-opt-in.md)."
5. **[ROADMAP.md](../ROADMAP.md) line 140** (owner-approved edit): the last cell "M3 design" becomes "M3: [ADR 0052](adr/0052-icon-proxy-role.md), per-account opt-in [ADR 0099](adr/0099-website-icons-opt-in.md)".
6. **Code comments.** `packages/ui/src/itemIcons.ts` and `rizzy_client::icons` module docs: "When" gains the setting and the probe.

### 10. Implementation plan and tests

1. **`rizzy-client`.** `settings.rs`: `TAG_WEBSITE_ICONS = 0x0005`, parse and encode, `SettingsEdit::SetWebsiteIcons(bool)`. `icons.rs`: `IconPermit`, `icon_probe_request`, `icon_probe_finish`, `icon_request(&IconPermit, host)`. Tests: known-answer records with the tag absent, `0x00`, `0x01`; rejection of `0x02` and of lengths 0 and 2; an unknown tag still round-trips; probe outcomes for `400 invalid_request` (available), `400` with another code, `404`, `429` three times, `200` and `500` (unavailable); no permit when the setting reads off whatever the probe said.
2. **`rizzy-wasm`.** `Session::website_icons()` and `set_website_icons(bool)` (over `settings_change`), `Session::icon_probe_request()` and `icon_probe_finish(status, body)`; the icon fetch moves onto the session and refuses with `icons_off` without a permit; the permit is dropped on lock and when a reload reads off. Tests in `crates/rizzy-wasm/src/tests.rs`.
3. **`packages/core`.** `probeItemIcons(session, transport)` and `fetchItemIcon(session, transport, host)`; unit tests for the `icons_off` refusal.
4. **Web vault.** `VaultView.tsx` creates the `IconLoader` only after an "available" probe with the setting on, and clears it when the setting turns off. A new section in `SettingsView.tsx` holds the switch and the text of §6.
5. **Extension.** `popup/views/Items.tsx` and the core host follow the same rule through the extension's core context.
6. **E2E** (`apps/web/e2e/icons.spec.ts`, `apps/extension/e2e/icons.spec.ts`, extending the mocked-role routes they already have): (a) setting off (the default), role mocked on: after unlock and a full list render, no request to `/api/v1/icons/`; (b) setting on, role answering `404`: exactly one request, with body `{"host":""}`; (c) setting on, role on: the probe, then one request per host, each body only `{"host":…}`; (d) the setting turned off mid-session: no request after the switch; (e) the setting turned on in one browser context shows icons in a second context of the same account after its next unlock.

## Consequences

### Positive

- ROADMAP's "must be optional" is met for the user, not only the operator. By default no account sends its list of sites anywhere.
- No host leaves a client whose server has no `icons` role, whatever the proxy does with the path.
- No server change, and the shipped icon endpoint is used exactly as defined.
- The threat model now records the operator-correlation risk that ADR 0052 point 5 and INV-77 left unstated.

### Negative

- With the default off, an operator who enables the role sees it used only by accounts that opt in; most users will see type icons.
- Each unlock with the setting on costs one probe request, and each host still costs one request per session.
- The probe relies on the role answering `invalid_request` to an empty host, before any lookup. That is ADR 0052 point 6's rule and the role's own test. A future change that answers a malformed host with another code turns icons off for everyone, a safe failure that a test in §10 catches.

### Risks

- Clients built before this ADR (development builds only; nothing is released) keep fetching unconditionally. If a release ships before the implementation, ADR 0002 point 5's minimum-version raise is needed for the extension.
- A malicious server can serve a web vault that ignores the setting. That is AR-1 (a backdoored web vault), not a new risk; native clients and the extension keep the rule.

## Alternatives considered

- **A per-device setting.** Lost: the list of sites leaks once from any device, and the operator links an account's devices anyway (§1).
- **An `icons` flag in `GET /api/meta`.** Lost: the `api` process does not know whether the proxy routes to a running role. It would need a new operator variable that can disagree with the real routing. It would also be a wire change to ADR 0002 point 3's meta body.
- **A dedicated `POST /api/v1/icons/status` endpoint.** Clearer than the empty-host probe, but it is a new endpoint (ADR 0028 item 1, ADR 0052 point 6) and a server change for an answer the existing endpoint already gives. It stays the fallback if the empty-host answer ever becomes unreliable.
- **Default on, or on when the operator enables the role.** Open question 1.
- **Batching hosts, or a persistent device icon cache.** Lost (§5).
- **Fetching icons from the sites directly in the browser.** Lost: it exposes the user's address and the list to every site and to third-party image hosts, and needs a looser `img-src`. ADR 0052 chose the proxy for that reason.

## Open questions for the owner

1. **Default.** Off (opt in) or on (opt out), for an account that never touched the setting? *Recommendation:* off. ROADMAP §4.4 says favicon fetching "must be optional". The leak is the list of sites the account has items for, to an in-scope attacker (A2/A3). The cost of off is cosmetic. A variant, "on when the operator enabled the role", still sends the list by default to the operator, whom this setting is meant to protect against.

## References

- [ADR 0052](0052-icon-proxy-role.md) points 5–6; [ADR 0010](0010-server-shape.md) owner decision 5, §2, §4; [ADR 0042](0042-account-settings-matching-layout.md) §2 and Amendments; [ADR 0081](0081-multiple-vaults-personal-and-shared.md) §0 entry 6, §A2, §B2; [ADR 0079](0079-identity-generator.md); [ADR 0053](0053-hibp-breach-check-egress.md); [ADR 0002](0002-own-protocol.md) point 5; [ADR 0020](0020-partial-supersession.md) points 4 and 9.
- [ROADMAP.md](../ROADMAP.md) §4.4 (line 140); [THREAT_MODEL.md](../THREAT_MODEL.md) A2, A3, AST-13, §7.11, §9 (AR-1), INV-51, INV-77, Q-11; [CRYPTO.md](../CRYPTO.md) "Account-settings plaintext".
- Review: [2026-10-25-adr-gap-review.md](../reviews/2026-10-25-adr-gap-review.md) S4; raw [G05](../reviews/2026-10-25-raw/G05.md) G05-24.
- Code (V, read in this worktree): `apps/web/src/views/{VaultView,ItemsPane}.tsx`, `packages/ui/src/{itemIcons.ts,ItemIcon.tsx}`, `apps/extension/src/popup/views/Items.tsx`, `packages/core/src/index.ts` (`fetchItemIcon`), `crates/rizzy-client/src/{icons.rs,settings.rs}`, `crates/rizzy-wasm/src/icons.rs`, `crates/rizzy-proto/src/{icons.rs,meta.rs}`, `crates/rizzy-server/src/http/{icons.rs,mod.rs}`, `deploy/Caddyfile`, `deploy/compose.yaml`.
- HTTP/2 connection reuse by browsers for same-origin requests (L, general browser behaviour; not tested for this deployment).
