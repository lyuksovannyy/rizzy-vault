# rizzy-vault — Product Roadmap & MoSCoW

> Status: **planning**, no code yet. This document is the source of truth for scope.
> Anything not listed here is out of scope until it is added here first.

## 1. What we are building (one paragraph)

A self-hostable, end-to-end encrypted password manager written in Rust that combines:

| Borrowed from | What we take | What we do **not** take |
|---|---|---|
| **Bitwarden / Vaultwarden** | Zero-knowledge E2EE vault, self-hosted single-binary server, sync, orgs/collections model, open source | Their wire protocol and legacy crypto (PBKDF2, password-hash auth). We are *not* a Bitwarden-API-compatible server — that product already exists (Vaultwarden). |
| **1Password** | Visual design language, UX polish, Watchtower-style health, item sharing via link, Secret Key (2SKD) idea, Travel-mode-style ideas later | Their proprietary assets, icons, or trade dress. Inspired-by, never cloned. |
| **AliasVault** | One-click alias identity creation, built-in receive-only mailbox visible in the UI, mail encrypted at ingress with the user's public key | Nothing in particular — but email is optional, not core. |

Target users by phase: **Personal → Enthusiasts/Families → Small & medium businesses.**

## 2. Guiding principles (non-negotiable)

1. **Zero knowledge.** The server never sees plaintext secrets, master passwords, or keys. Ever. Including for shares and email.
2. **No home-made crypto.** Only audited primitives from established crates. Every crypto decision is written down in an ADR before it is coded.
3. **Design the data model for orgs on day one.** UI for orgs comes late; the key hierarchy (per-user keypairs, per-vault keys) must exist from M1 or we rewrite everything at M9.
4. **Versioned everything.** Ciphertext formats, KDF params, API — all carry a version so we can migrate (e.g. to post-quantum) without breaking vaults.
5. **Email is a module, not the core.** The password manager must be fully usable with the mail subsystem disabled.
6. **Ship a usable personal product before starting anything business-shaped.**

## 3. Milestones

| # | Milestone | Goal / exit criteria | Audience |
|---|---|---|---|
| **M0** | Foundations | Threat model, crypto design ADRs, architecture decisions, repo layout, CI, contribution rules. No product code beyond spikes. | Dev |
| **M1** | Core vault (MVP) | Register/login, E2EE vault CRUD, sync, web vault, CLI, import/export, generator, TOTP. Author uses it daily. | Personal (dogfood) |
| **M2** | Browser extension & URL matching | Autofill in Chromium + Firefox, save-on-submit, domain equivalence (youtube.com ≡ youtu.be), match modes. | Personal |
| **M3** | 1Password-grade UX & desktop | Design system, desktop app, quick-access search, Watchtower-style health report, tags/favorites. | Personal |
| **M4** | Sync modes | User picks **Server** sync (encrypted vault stored on server) or **On-device** sync (server is only an encrypted relay + version tracker, no durable vault copy). Switch between modes without data loss. | Personal |
| **M5** | Public sharing | Share an item by link with fragment-held key, expiry, view limits, optional recipient verification. | Personal |
| **M6** | Aliases & email receiving | Generate alias identities, receive-only mailbox in UI, ingress encryption, autofill integration. | Personal / enthusiasts |
| **M7** | Mobile & passkeys | iOS/Android apps with OS autofill, passkey (WebAuthn) storage and use. | Personal |
| **M8** | Hardening → **v1.0** | External security audit, bug bounty, backup/restore drills, docs. Public 1.0 for personal use. | Public |
| **M9** | Families & enthusiasts | Shared vaults, family org, emergency access, multiple mail domains, admin panel. | Enthusiasts |
| **M10** | Business | Org policies, roles, SSO (OIDC/SAML), SCIM, audit logs, admin console, billing hooks. | SMB |

Rough rule: each milestone ends with a tagged release and a written "what we learned" note. A milestone is not done because features are merged; it is done when the exit criteria are met.

---

## 4. MoSCoW by area

Legend: **M** = Must, **S** = Should, **C** = Could, **W** = Won't (not in this horizon). The column *When* is the milestone.
MoSCoW is scored **against v1.0 (end of M8)**. Items for M9/M10 are listed so the architecture accounts for them, but they are *Won't for v1.0* by definition.

### 4.1 Foundations & project hygiene (M0)

| Pri | Item | When |
|---|---|---|
| M | Written threat model (attackers: compromised server, malicious admin, network MITM, malware on client, phishing site, stolen device) | M0 |
| M | Crypto design document + ADRs (see 4.3) reviewed before any vault code | M0 |
| M | Cargo workspace layout: `core` (crypto + models, no I/O), `server`, `cli`, `client-sdk` (wasm + native bindings) | M0 |
| M | CI: fmt, clippy (deny warnings), tests, `cargo audit`, `cargo deny` (licenses/advisories) | M0 |
| M | License policy: AGPL-3.0 server/core; decide client license; dependency license allow-list | M0 |
| S | `SECURITY.md` with disclosure process | M0 |
| S | Fuzzing harness for parsers (import formats, email MIME, URL parser) | M1–M6 |
| C | Reproducible builds for server binary and extension | M8 |
| W | Monorepo tooling beyond Cargo + one JS package manager | — |

### 4.2 Core vault (M1)

| Pri | Item | When |
|---|---|---|
| M | Account registration & login with master password | M1 |
| M | Item types: Login, Secure Note, Card, Identity | M1 |
| M | Custom fields (text, hidden, boolean), multiple URLs per login, notes | M1 |
| M | Folders **or** tags (pick one for M1 — tags recommended; folders are a UI over tags) | M1 |
| M | Password generator (length, charsets, passphrase/wordlist mode) | M1 |
| M | TOTP secret storage + code generation | M1 |
| M | Password history per item | M1 |
| M | Trash with restore (soft delete, auto-purge after N days) | M1 |
| M | Mode-agnostic sync engine (see 4.6): encrypted operation log, per-item version vectors, deterministic merge, no silent data loss. M1 ships Server mode only, but the engine must not assume the server holds the vault | M1 |
| M | Offline read access on clients (encrypted local cache) | M1 |
| M | Import: Bitwarden JSON, 1Password (1PUX), KeePass (KDBX/XML), generic CSV, Chrome/Firefox CSV | M1 |
| M | Export: encrypted JSON (own format) + plaintext JSON/CSV with scary warning | M1 |
| M | CLI client (`rv`) — list, get, add, generate, copy TOTP | M1 |
| M | Web vault (minimal UI acceptable in M1) | M1 |
| S | Attachments (encrypted, size-limited) | M3 |
| S | Item types: SSH key, API credential, Software license, Wi-Fi, Bank account | M3 |
| S | Favorites, recently used, full-text search on decrypted index (client-side only) | M3 |
| S | Item revision history (restore old versions) | M3 |
| C | Markdown in secure notes | M3 |
| C | SSH agent integration (desktop) | post-1.0 |
| C | `.env` / secrets injection for developers (`rv run -- cmd`) | post-1.0 |
| W | Server-side search over item contents (violates zero knowledge) | never |

### 4.3 Cryptography & authentication (M0–M1, audited in M8)

| Pri | Item | When |
|---|---|---|
| M | KDF: **Argon2id** with per-account salt, versioned params, client-side | M1 |
| M | Symmetric: **XChaCha20-Poly1305** (or AES-256-GCM-SIV) via RustCrypto, AAD binds item ID + version | M1 |
| M | Key hierarchy: master key → account key → per-vault keys → item keys; enables rotation & sharing without re-encrypting the world | M1 |
| M | Per-user asymmetric keypair (**X25519** for key wrapping, **Ed25519** for signing) generated at signup — required for sharing, orgs, email | M1 |
| M | Auth that never sends a password-equivalent: **OPAQUE** (`opaque-ke`) or SRP-6a. Recommendation: OPAQUE | M1 |
| M | Secret memory hygiene: `zeroize`, `secrecy`, no secrets in logs/panics | M1 |
| M | Versioned ciphertext envelope format (algorithm id, key id, nonce, ct) | M1 |
| M | Master password change & key rotation | M1 |
| M | 2FA: TOTP, WebAuthn/FIDO2 security keys | M1 (TOTP) / M3 (WebAuthn) |
| M | Recovery story written down and implemented: "Emergency Kit" (printable Secret Key + recovery code). No recovery = data gone, and the UI says so plainly | M1 |
| S | **Secret Key / 2SKD** (1Password-style 128-bit device-held key mixed into KDF) — protects against server breach + weak master password | M1 decision, M3 ship |
| S | Unlock with biometrics / OS keychain on desktop & mobile | M3 / M7 |
| S | Session/device management: list devices, revoke, force logout | M3 |
| C | Hybrid post-quantum key wrapping (X25519 + ML-KEM-768) for sharing & org keys | post-1.0 (format must allow it from M1) |
| C | Login with passkey (PRF extension to derive unlock key) | post-1.0 |
| W | Custom/novel crypto constructions | never |
| W | Server-side password reset that can decrypt vaults | never (org admin recovery in M10 uses explicit key escrow the user consents to) |

### 4.4 URL matching & autofill (M2)

The problem: `youtube.com`, `youtu.be`, `m.youtube.com`, `accounts.google.com` all belong to the same login; `evil-youtube.com` must **never** match. Over-matching is a phishing vulnerability, not a convenience bug.

| Pri | Item | When |
|---|---|---|
| M | URL normalization (scheme, IDNA/punycode, trailing dots, ports, default paths) | M2 |
| M | Registrable-domain matching using the **Public Suffix List** (eTLD+1: `a.b.example.co.uk` → `example.co.uk`) | M2 |
| M | **Equivalent domain groups**: curated global list (e.g. `youtube.com, youtu.be, youtube-nocookie.com`; `google.com, google.co.uk, …`; `apple.com, icloud.com`), shipped with clients, versioned and signed | M2 |
| M | User-defined equivalence groups + ability to disable a global group | M2 |
| M | Per-URI match mode: *Base domain* (default), *Host*, *Starts with*, *Exact*, *Regex* (advanced), *Never* | M2 |
| M | Security rules: never autofill HTTPS-saved credentials on HTTP; never autofill into cross-origin iframes by default; autofill on user gesture only (no silent page-load fill) | M2 |
| M | Visual warning when filling on a domain matched only via equivalence group | M2 |
| M | Browser extension: Chromium (MV3) + Firefox — inline menu, fill, save/update on submit, generator in field | M2 |
| S | Android app-ID ↔ domain mapping (Digital Asset Links) and iOS associated domains | M7 |
| S | Community-contributed equivalence list via PRs with review rules (both domains provably same owner) | M2 |
| S | Safari extension | M3 |
| C | Heuristic multi-step login form support (username page → password page) | M3 |
| C | Auto-suggest adding a domain to an equivalence group when user manually fills | post-1.0 |
| W | Fetching website favicons through our server without privacy controls (leaks which sites you use) — must be optional / proxied / cached anonymously | M3 design |

### 4.5 Design, UI & UX — "1Password feel" (M3)

| Pri | Item | When |
|---|---|---|
| M | Design system: tokens (color, spacing, type), light/dark, component library shared by web vault + extension + desktop | M3 |
| M | Quick-access / command palette (global hotkey on desktop, `Ctrl/Cmd+K` in web) | M3 |
| M | Item detail view with one-click copy, reveal, large-type password display | M3 |
| M | Accessibility: keyboard-only usable, screen reader labels, WCAG AA contrast | M3 |
| M | Desktop app (recommendation: **Tauri** — Rust backend reuses `core`, web UI reuses design system) | M3 |
| S | **Watchtower-style health**: weak, reused, old passwords; missing 2FA where site supports it; breached passwords via HIBP k-anonymity (only 5-char SHA-1 prefix leaves the device) | M3 |
| S | Onboarding flow (import wizard, Emergency Kit download, extension install) | M3 |
| S | Localization framework (i18n from day one of M3, English only at first) | M3 |
| C | Themes / accent color customization | post-1.0 |
| C | Travel mode (hide vaults on device while crossing borders) | M9 |
| W | Pixel-copying 1Password's UI or icons | never |

### 4.6 Sync modes (M4)

Two modes, chosen per account at setup and changeable later:

- **Server mode** (default): the server durably stores the full *encrypted* vault and op log. Any new device just logs in and downloads.
- **On-device mode**: the vault lives only on the user's devices. The server is a **store-and-forward relay**: it keeps the device registry, each device's sync cursor / version vector (metadata only), and encrypted operations **until every registered device has acknowledged them**, then deletes them. No durable vault snapshot on the server.

What on-device mode actually buys you (be honest in the UI): in server mode the server already sees only ciphertext. On-device mode removes the *offline-crackable vault blob* from the server (a breach yields nothing to brute-force against the master password), shrinks metadata, and satisfies "my data never rests on someone else's disk". The price: **lose all devices = lose the vault**, and a new device cannot be set up without an existing one online.

| Pri | Item | When |
|---|---|---|
| M | Single sync engine for both modes (built in M1): client-side encrypted op log, hybrid logical clocks + per-item version vectors, field-level merge, tombstones for deletes, conflicting edits kept as item history instead of dropped | M1 (engine) / M4 (modes) |
| M | Mode selection at account creation, with a plain-language comparison screen | M4 |
| M | **Server mode**: full encrypted vault + op log stored server-side; compaction of op log into snapshots | M1 |
| M | **On-device mode**: server stores only device registry, public keys, per-device version vectors, and pending encrypted ops; ops purged once acked by all active devices | M4 |
| M | Pending-op TTL (configurable, e.g. 90 days); a device offline longer than the TTL is marked stale and must re-sync from a peer device, never from the server | M4 |
| M | New-device enrollment in on-device mode: pair with an existing online device (QR / short code), full snapshot transferred device→device over the relay, E2EE, verified with a short authentication string (SAS) | M4 |
| M | Device revocation: revoked device is removed from the ack set and vault key is rotated | M4 |
| M | Mode switching both ways. Server→device: server deletes vault blobs and op log, and proves it by returning a signed deletion receipt. Device→server: client uploads a full encrypted snapshot. Explicit confirmation, no silent switch | M4 |
| M | Data-loss guardrails for on-device mode: warn when only one device is registered; mandatory encrypted backup prompt (local file) on setup and periodically | M4 |
| M | Transparency page in settings: exactly what the server stores for this account in the current mode (item counts, byte sizes, retention) | M4 |
| M | Server admin can restrict which modes are allowed on the instance | M4 |
| S | Scheduled encrypted backups to user-chosen storage (local folder, WebDAV, S3-compatible) — strongly recommended for on-device mode | M4 |
| S | Size padding and batching of relayed ops to reduce metadata leakage (how often and how much you edit) | M4 |
| S | Clear conflict UI: "edited on Phone and Laptop at the same time — keep both / pick one" | M4 |
| C | Direct LAN sync (mDNS discovery) that skips the relay when devices share a network | post-1.0 |
| C | Fully serverless peer-to-peer sync (e.g. `iroh` / WebRTC) | post-1.0 |
| C | Per-vault mode (e.g. personal vault on-device, shared family vault on server) | M9 |
| W | Web vault as a device in on-device mode — a browser tab is not durable storage. In on-device mode the web vault is disabled (browser extension, desktop, mobile and CLI are real devices) | Won't |
| W | On-device mode for shared/org vaults in v1.0 — multi-user, multi-device relay with membership changes is a separate design problem | M9 decision |

Interactions with other features:
- **Public shares (M5)** are always stored on the server (encrypted, fragment key) — that is their nature. Allowed in both modes; the transparency page lists them.
- **Alias mailbox (M6)**: inbound mail must wait somewhere while devices are offline. In on-device mode mail is kept encrypted on the server until all devices ack, then purged — same relay rule as vault ops.
- **Business (M10)**: org policy can force Server mode (admins need recovery and audit).

### 4.7 Public sharing (M5)

Model: 1Password-style share links. The share is an **encrypted snapshot**, not a live link to the item.

| Pri | Item | When |
|---|---|---|
| M | Create share link for one item; item encrypted with a random key; key lives **only in the URL fragment** (`#…`), never sent to the server | M5 |
| M | Expiry (1h / 1d / 7d / 30d / custom), max views, manual revoke | M5 |
| M | Recipient view page that works without an account | M5 |
| M | Choose which fields are included (e.g. share password but not notes/TOTP) | M5 |
| M | Owner sees list of active shares + view count | M5 |
| S | Restrict to specific email addresses, verified by one-time code | M5 |
| S | Optional extra passphrase on share (out-of-band) | M5 |
| S | "Send"-style arbitrary text/file share (Bitwarden Send equivalent) | M5 |
| C | Recipient can "save to my rizzy-vault" in one click | M9 |
| W | Live shared items between two personal accounts (that is what shared vaults in M9 are for) | M9 |

### 4.8 Aliases & email receiving (M6)

This is the most operationally expensive feature in the whole plan. Read the risks section before starting it.

| Pri | Item | When |
|---|---|---|
| M | Generate alias identity (random name, username, alias address, password) from item creation and from the extension on sign-up forms | M6 |
| M | Inbound SMTP receiver (Rust, e.g. `mail-parser` + own SMTP listener, or front with Postfix/Haraka and hand off) — **receive only** | M6 |
| M | Catch-all per configured domain; alias → owner lookup without revealing which aliases exist (no SMTP user enumeration) | M6 |
| M | **Encrypt at ingress** with the alias owner's public key; server stores ciphertext only; plaintext held in RAM for the minimum time | M6 |
| M | Spam/abuse filtering **before** encryption (rspamd or equivalent), SPF/DKIM/DMARC verification shown in UI | M6 |
| M | Mailbox UI: list, read (sanitized HTML, remote images blocked by default), delete, per-alias view | M6 |
| M | Size limits, attachment limits, retention policy (auto-delete after N days, configurable) | M6 |
| M | Disable/delete alias; mail to disabled alias is rejected at SMTP time | M6 |
| M | Admin docs: MX, SPF, port 25 requirements, reverse proxy, TLS | M6 |
| S | Extract OTP / verification links from mail and offer them in autofill | M6 |
| S | Real-time notification of new mail (WebSocket/SSE → UI, push on mobile in M7) | M6 |
| S | Multiple mail domains per server; user-owned custom domains | M9 |
| C | Forward to real inbox (re-encrypted or plaintext, opt-in) — deliverability nightmare, treat carefully | post-1.0 |
| C | Hosted shared mail domain for non-self-hosters | only if a hosted offering exists |
| W | **Sending** email / replying from alias | Won't for v1.0 (deliverability, abuse, blacklisting) |
| W | Full IMAP/POP server | never — we are not an email provider |

### 4.9 Server, self-hosting & ops (M1 onward)

| Pri | Item | When |
|---|---|---|
| M | Single Rust server binary (recommendation: `axum` + `tokio` + `sqlx`) | M1 |
| M | SQLite (default, personal) and PostgreSQL (orgs/SMB) | M1 (SQLite) / M3 (Postgres) |
| M | Official Docker image + compose file; runs behind any reverse proxy | M1 |
| M | DB migrations, versioned API (`/api/v1`) | M1 |
| M | Rate limiting, lockout/backoff on auth, security headers, CSP on web vault | M1 |
| M | Backup & restore command + documented procedure (tested, not just written) | M1 |
| M | Structured logging with **no secrets** and configurable retention | M1 |
| S | Admin panel (user list, disable user, invite-only signup, SMTP settings for notifications) | M3 |
| S | Push/live sync (WebSocket) so clients update without polling | M3 |
| S | Metrics endpoint (Prometheus) | M3 |
| C | High-availability deployment guide | M10 |
| W | Official managed cloud hosting | not in this roadmap — separate business decision |

### 4.10 Mobile & passkeys (M7)

| Pri | Item | When |
|---|---|---|
| M | Android app with Autofill Framework integration | M7 |
| M | iOS app with AutoFill Credential Provider | M7 |
| M | Shared Rust core via **UniFFI** bindings (no crypto re-implemented in Kotlin/Swift) | M7 |
| M | Biometric unlock, auto-lock timeout, screenshot blocking | M7 |
| M | Passkey storage (store WebAuthn credentials in vault) and use in extension | M7 |
| S | Passkey provider on Android 14+/iOS 17+ | M7 |
| S | Passkey import/export via FIDO Credential Exchange Protocol (CXP/CXF) when stable | M8 |
| C | Wear OS / watchOS TOTP viewer | post-1.0 |

### 4.11 Families & enthusiasts (M9) — *Won't for v1.0*

| Item |
|---|
| Shared vaults with per-member permissions (view / edit / manage) |
| Family organization (up to N users), invites |
| Emergency access (trusted contact can request access after a waiting period) |
| Multiple / custom mail domains for aliases |
| Recipient "save shared item to my vault" |
| Travel mode |

### 4.12 Business / SMB (M10) — *Won't for v1.0*

| Item |
|---|
| Organizations, groups, collections, roles (owner/admin/manager/member) |
| Policies: master password strength, required 2FA, disable personal export, share restrictions |
| SSO via OIDC and SAML, with explicit key-management model (trusted device or key connector) |
| SCIM provisioning (Entra ID, Okta, Google Workspace) |
| Admin account recovery (user-consented key escrow) |
| Event / audit logs, export to SIEM |
| Org-wide Watchtower report (without exposing member secrets) |
| Admin console, seat management, licensing/billing hooks |

---

## 5. Architecture decisions to make in M0 (with current recommendation)

| Decision | Options | Recommendation | Why |
|---|---|---|---|
| Protocol | Bitwarden-API-compatible vs. own | **Own** | Compatibility locks us into Bitwarden's crypto, clients and design; Vaultwarden already does that job. We offer *import*, not wire compatibility. |
| Auth | Bitwarden-style hashed key / SRP / OPAQUE | **OPAQUE** | Server never sees a password-equivalent; audited Rust crate exists. |
| Client core | Per-platform code vs. shared Rust | **Shared Rust `core`** → wasm (web/extension) + UniFFI (mobile) + native (CLI/Tauri) | One crypto implementation to audit. |
| UI stack | Rust UI (Leptos/Dioxus) vs. TypeScript (Svelte/React) | **TypeScript + one framework** for web/extension/desktop | Extension ecosystem, hiring, and component libraries are JS-first. Rust stays where security lives. |
| Desktop | Electron / Tauri | **Tauri** | Smaller, Rust-native, reuses `core` directly. |
| DB | SQLite / Postgres | **Both via sqlx**, SQLite default | Personal self-hosters want zero-config. |
| Sync engine | Whole-vault LWW / per-item LWW / op log + version vectors / full CRDT library (Automerge, Yrs) | **Op log + HLC + per-item version vectors, field-level merge** | Needed for relay-only On-device mode; a full CRDT library is overkill for records of ~20 fields and bloats the payload. |
| Mail ingress | Own SMTP in Rust vs. Postfix/Haraka front | **Decide in M6 spike**; lean own minimal receive-only listener | Fewer moving parts for self-hosters, but must be fuzzed hard. |

## 6. Risks & hard truths

1. **Scope is three products.** Bitwarden, 1Password and AliasVault each have years of work and funded teams. Solo/small-team realistic path: M1–M3 is already a serious year. Protect the core; cut everything else first.
2. **Clients are the real cost, not the server.** The browser extension (autofill across broken real-world forms) and mobile autofill will eat more time than the whole Rust server. Plan for it.
3. **Email is an ops liability.** Self-hosters on residential connections usually cannot receive on port 25; mail domains get abused; spam filtering must happen *before* encryption, so the server briefly sees plaintext mail — the threat model must say so honestly.
4. **URL equivalence is a security surface.** Every entry in the global equivalence list is a potential phishing vector. Entries need proof of common ownership and review by two maintainers.
5. **"1Password design" is not a feature list.** It is consistent, boring polish across every screen. Without a design system in M3 it will look like a template.
6. **Crypto credibility.** Nobody serious (enthusiasts, SMBs) will trust an unaudited password manager. Budget for an external audit before v1.0 or do not call it 1.0.
7. **The org key model must exist from M1.** Retrofitting sharing into a single-user key hierarchy means re-encrypting every vault — the classic rewrite trap.
8. **On-device sync turns support tickets into data loss.** Users *will* lose their only phone. Server mode stays the default; on-device mode ships with backup nagging and a scary-but-honest setup screen. The sync engine is the hardest correctness problem in the project — it needs property-based tests (random edit/offline/reconnect sequences on N simulated devices converging to the same state) before M4 ships.
9. **Naming.** "rizzy-vault" is fine for a personal project; it will be a hard sell to an SMB security buyer. Decide on the public product name before M8.

## 7. Definition of done for v1.0 (end of M8)

- All **Must** items in sections 4.1–4.10 shipped.
- Third-party security audit completed, findings fixed or publicly documented.
- Backup → wipe → restore tested on SQLite and Postgres.
- Sync convergence property tests pass for both modes; mode switch server↔device tested with 3+ devices including one offline past the TTL.
- Import from Bitwarden, 1Password and KeePass verified on real exports.
- Author and at least 10 external users have used it daily for 60+ days without data loss.
