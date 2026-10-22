# ADR 0060: Admin panel: web stack, directory and security boundary

- Status: Accepted
- Date: 2026-10-11
- Deciders: project owner
- Milestone: M3

## Context

[ROADMAP §4.9](../ROADMAP.md#49-server-self-hosting--ops-m1-onward), Should, M3: "Admin panel (user
list, disable user, invite-only signup, SMTP settings for notifications)". No ADR covers it yet.
[ADR 0014](0014-ui-stack.md) (Partially superseded by [ADR 0022](0022-server-mode-only.md); the "(§6)"
in that status line names ADR 0014's own §6 — ADR 0022's Decision has only "§1 What this ADR
supersedes" and "§2 Replacing text", no §6 of its own) carves the panel out of its own Context: "It is
a web UI in this repository on the admin listener (ADR 0010 §1), and it renders user-controlled strings
with admin rights, so stored XSS there acts as the admin (THREAT_MODEL §7.19, INV-69). Its stack and
directory are decided before M3 admin work starts, by a revision of this ADR while Proposed or by a new
ADR once Accepted." That Context sentence is not in ADR 0022 §1's supersession list, so it still binds
(ADR 0020 point 9); ADR 0014 is no longer Proposed, so this is that new ADR, superseding nothing in it.

ADR 0010 §1's original roles table was replaced by [ADR 0022](0022-server-mode-only.md) §2 (ADR 0022
§1's list: "ADR 0010 §1 roles table, rows `api` and `worker`"); ADR 0022 §2's current `api` row still
lists "admin listener" in Inbound. ADR 0010 §1's own text that survives, sitting outside that table, is
the bullet "Admin API and metrics bind a separate listener. The reverse proxy does not expose it by
default." This ADR extends both; it supersedes neither. In code today there is one listener
(`Config.listen: SocketAddr`) and `Roles { api, web, worker }` has no admin entry.

[THREAT_MODEL §7.19](../THREAT_MODEL.md#719-admin-panel-and-admin-api-m3) /
[INV-69](../THREAT_MODEL.md#8-security-invariants) (Accepted, line 1228) fix the admin-auth *goals*, not
redecided here: separate admin credentials plus a second factor; a bootstrap token (CRYPTO.md §5.11)
shown once, never logged; strings rendered as text; a strict CSP; CSRF-protected cookies; logged admin
actions. No Accepted ADR, and no sibling M3 ADR (`docs/adr/README.md` names no "admin" ADR), decides
*that* mechanism — where admin credentials live, how the bootstrap token is redeemed, the 2FA ceremony,
session issuance — and ADR 0020 point 5 requires one for "authentication and session protocols" before
merge. This ADR fixes a different mechanism, what renders the UI and where it lives, and leaves that
one open (open question 5).

Crate precedent: `http/web.rs` serves the embedded web vault with its own CSP (`security::WEB_CSP`);
`http/{mod,api,headers,security}.rs` build one `Router` per listener. `admin.rs` is the CLI
admin-subcommands module (`secrets`, `backup`, `restore`), a different module from the panel (§1).
`config.rs`'s `SignupMode { Closed, Open }` notes invite-only signup needs "the M3 admin API"; no
`invite` variant exists. [CRYPTO.md §5.9](../CRYPTO.md#59-account-enumeration) names invite-only the M1
default ("an admin-issued invite token, bound to a login name") but decides none of its mechanism. No
templating crate is in `[workspace.dependencies]`.

## Decision

**Supersedes: none.** This ADR extends ADR 0010 §1, ADR 0022 §2 and fulfills ADR 0014's carve-out; it
changes no Accepted text.

### 1. Where the code lives

Server-rendered pages inside `rizzy-server` (binary `rizzy-vault`) — not a second crate, not a directory
under `apps/`:

- `http/admin_panel/mod.rs` — the router: one page per screen (user list, disable-user confirm,
  signup-mode toggle, SMTP settings) plus POST handlers. Built only into the admin listener's `Router`
  (§2); never merged into `http::router()`.
- `http/admin_panel/auth.rs` — a **named placeholder, not built by this ADR**: login, bootstrap-token
  redemption, the 2FA ceremony and session issuance (INV-69) are an authentication protocol (ADR 0020
  point 5) needing its own Accepted ADR first (open question 5); no screen below lands before it does.
- `http/admin_panel/forms.rs` — CSRF issuance/verification (INV-69) and typed, size-limited form parsing
  for the screens behind that login.
- `templates/admin/*.html` — template sources, Askama's default `templates/` directory at the crate
  root (L, verified at implementation).
- `http/security.rs` gains `ADMIN_CSP`/`add_admin_csp` beside `WEB_CSP`/`API_CSP`: `default-src 'none';
  script-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none';
  base-uri 'none'; object-src 'none'`. No `'wasm-unsafe-eval'`, no `connect-src`.
- `crates/rizzy-server/src/admin.rs` (CLI subcommands) is untouched — a different module path than
  `crate::http::admin_panel`, flagged so the two are not conflated.

### 2. The listener and the boundary

`Config` gains `admin_listen: SocketAddr`, parsed like `listen`, defaulting to a loopback address
(`127.0.0.1:8081`, never `0.0.0.0`): it always binds, so ADR 0010 §1's surviving bullet ("bind a
separate listener... the reverse proxy does not expose it by default") stays exactly true, not
narrowed. `server.rs` binds a second `TcpListener` and runs a second `serve_http` future, concurrently
with the public one, whenever the `api` role is active — the panel needs the `api` role's database and
session machinery, and ADR 0022 §2's current `api` row already lists the admin listener inside that
role, not as a role of its own. The routers share no code path: an `/admin/...` request on `listen` is
a plain `404`, because the admin router is never part of `http::router()`. Compose examples do not
publish `admin_listen`'s port, and the docs tell operators to reach it only over a tunnel or VPN.

### 3. Rendering: Askama, auto-escaping, no raw-HTML sinks

**Askama** (recommended; version, licence and `cargo deny check` confirmed in the implementing PR, U)
renders every page: compile-time-checked `.html` templates, HTML-escaped by default on `{{ }}`. This is
the Rust-template reading of ADR 0014 §2's rule here:

- No template uses Askama's `|safe` filter on a user-controlled string (login name, device name, alias
  label, SMTP host/username). A `cargo xtask` check scans `templates/admin/*.html` and fails on `|safe`
  outside one named exception (none at M3); a unit test renders each with an adversarial string
  (`<script>`, a breakout `"`) and asserts escaped output.
- No template interpolates into a `<script>` block, a `style` attribute or a URL scheme; the panel ships
  no inline script and links only to same-origin, literal, fixed paths — ADR 0014 §2's `SafeLink` rule
  restated for Rust.
- Forms submit natively (no `fetch`, no JSON admin API at M3): a POST re-renders the page.
- Visual design: `packages/ui`'s token format is undecided until ADR 0014 §5's M3 work, so this ADR
  does not import it; the panel gets a small hand-rolled CSS file compiled into the binary.

### 4. M3 scope, and what is left open

ROADMAP §4.9's row names user list, disable user, invite-only signup and SMTP settings; this ADR does
not narrow that scope (ADR 0020 point 7). What it fixes at M3: the user-list, disable-user and SMTP
screens, and a signup screen offering the existing `SignupMode::{Closed, Open}` only. **Invite-only
signup is not a toggle on that enum:** it needs token generation, storage, delivery, redemption, expiry
and revocation, checked against [CRYPTO.md §5.9](../CRYPTO.md#59-account-enumeration)'s enumeration
resistance — §5.9 calls it the M1 default but decides none of that mechanism, and no ADR does. The
invite screen ships once that mechanism has its own Accepted ADR (open question 6). Shared-vault and org
admin screens (ROADMAP §4.11, §4.12) wait for M9/M10's own ADRs. Every screen above also waits on open
question 5: none merges before the admin-login ADR is Accepted.

**Not fixed here:** the storage schema for what these screens toggle (signup mode, recovery wait, SMTP
settings) — no such row exists today, and a toggle needs one that persists without a restart. A schema
change needs an Accepted ADR first (ADR 0020 point 5): a short follow-up under ADR 0011's `auth` domain,
required unconditionally, not left to the implementing PR (open question 3).

**Pending open question 2:** if yes, proposed INV-86 (SMTP credentials have no home today) is that an
SMTP password is sealed at rest by reusing CRYPTO.md §5.11's Algorithm 0x01 server-side envelope, a new
server-only purpose `0x0103` in its 0x0100–0x01FF range — allocated ahead of sibling ADRs 0066/0071/0072
in ADR-number order (Provisional: the allocation was made across the 2026-10-11 batch in ADR-number
order; if ADRs are accepted out of order, the owner renumbers at acceptance.) — the same construction as
`SERVER_TOTP_SECRET`. Never logged (INV-48); the UI never redisplays a saved value, only whether one is
set.

**On acceptance:** [docs/adr/README.md](README.md) gains the 0060 index row; nothing else is
superseded. If open question 2 is yes, CRYPTO.md §5.11 gains the new purpose.

## Consequences

### Positive

- The admin surface stays in the one audited Rust binary (no second JS supply chain, THREAT_MODEL A9);
  auto-escaping is structural (Askama's default), matching ADR 0014 §2's reasoning for React.
- Reuses the crate's router-per-listener pattern; listener separation is enforced by the build, not a
  path check that could regress.

### Negative

- A second, smaller template system alongside React, with no shared design tokens from `packages/ui`
  until a later ADR, and no hot-reloading dev loop.
- Gating every screen on a separate admin-auth ADR (open question 5) means this ADR alone ships nothing
  a user can log into.

### Risks

- A publicly proxied `admin_listen` falls back on INV-69's own mitigations, not this ADR's listener
  split; the deploy docs must say so plainly.
- Real-time interactivity would strain a no-JS template; the signal to revisit is ADR 0010's own
  role-split criteria, before reaching for a second SPA.

## Alternatives considered

- **A second React/Vite SPA under `apps/admin`.** Rejected: pays ADR 0014's JS supply-chain cost twice,
  and widens what an admin-escalation attacker (INV-69) can reach.
- **Serving `apps/web`'s React build from the admin listener.** Rejected: wires in the wasm core and
  `wasm-unsafe-eval` CSP the panel does not need.
- **Hand-written HTML via `format!`/`write!`.** Rejected: no compile-time escaping, the exact failure
  INV-69 exists to close.
- **Tera** or **Maud** replace Askama in §3 if `cargo deny check` finds a problem (open question 1):
  Tera loses on compile-time checking, Maud on reviewability (a macro call, not an HTML diff).

## Open questions for the owner

1. **Template crate: Askama, or Tera/Maud?** *Recommendation:* Askama (§3), pending the implementing
   PR's `cargo deny check`.
2. **Confirm reusing Algorithm 0x01 for SMTP credentials (proposed INV-86, purpose `0x0103`)?**
   *Recommendation:* yes — the same construction CRYPTO.md §5.11 defines; a plaintext password column
   is a regression INV-48 forbids.
3. **Settings-persistence schema: here, or a short ADR 0011 follow-up?** *Recommendation:* the
   follow-up, required unconditionally before the schema is implemented (ADR 0020 point 5) — never the
   implementing PR.
4. **Does the M3 metrics endpoint share `admin_listen`?** *Recommendation:* yes — ADR 0010 §1 and ADR
   0022 §2 already group them.
5. **Admin login, bootstrap-token redemption and the second factor:** no Accepted ADR decides where
   admin credentials live, how the token is redeemed, or the 2FA/session mechanism — INV-69 fixes the
   goal, ADR 0020 point 5 requires the mechanism itself be an Accepted ADR before merge.
   *Recommendation:* add that ADR to this M3 batch now; `admin_panel/auth.rs` stays empty, and no screen
   behind it merges, until it is Accepted.
6. **Invite-only signup's mechanism** (storage, delivery, redemption, expiry, revocation) and its
   enumeration resistance under CRYPTO.md §5.9: undecided by any ADR. *Recommendation:* its own ADR,
   seeded by §5.9's sketch; until then the signup screen offers Closed/Open only (§4).

## References

- [ROADMAP](../ROADMAP.md) §4.9, §4.11, §4.12; [THREAT_MODEL](../THREAT_MODEL.md) §7.19, INV-48, INV-69
  (line 1228), A9; [CRYPTO.md](../CRYPTO.md) §5.9, §5.11
- [ADR 0010](0010-server-shape.md) §1, §2, §4; [ADR 0014](0014-ui-stack.md) Context, §1, §2, §5;
  [ADR 0011](0011-storage.md); [ADR 0020](0020-partial-supersession.md) point 5, 7, 9;
  [ADR 0022](0022-server-mode-only.md) §1, §2
- `crates/rizzy-server/src/{config.rs,server.rs,admin.rs,http/{mod.rs,web.rs,security.rs}}`,
  `docs/adr/README.md` index (no "admin" ADR) (V, 2026-10-11). Askama's defaults: unverified (L)
