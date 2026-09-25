# rizzy-vault threat model

- Status: Proposed (M0 deliverable, [ROADMAP §4.1](ROADMAP.md#41-foundations--project-hygiene-m0), Must)
- Date: 2026-09-25
- Owner: project owner
- Covers: M1–M8 (v1.0). M9/M10 threats appear where the M1 design has to prepare for them.
- Related: [ROADMAP](ROADMAP.md), [CRYPTO.md](CRYPTO.md), ADRs [0002](adr/0002-own-protocol.md), [0003](adr/0003-authentication-opaque.md), [0004](adr/0004-key-derivation-argon2id-secret-key.md), [0005](adr/0005-symmetric-encryption-aead.md), [0006](adr/0006-key-hierarchy.md), [0007](adr/0007-ciphertext-envelope.md), [0008](adr/0008-account-recovery.md), [0009](adr/0009-crypto-dependency-policy.md), [0010](adr/0010-server-shape.md), [0011](adr/0011-storage.md), [0012](adr/0012-sync-engine.md), [0013](adr/0013-shared-client-core.md), [0015](adr/0015-desktop-tauri.md), [0016](adr/0016-workspace-layout.md)

This document is normative. The invariants in [§8](#8-security-invariants) are requirements. Changing a goal, a non-goal or an invariant needs an ADR, or a PR that updates this file and explains why.

## How to use this document

- A PR that touches auth, crypto, key handling, sync, sharing, autofill, mail ingress, the icons fetcher or release tooling lists the invariants it affects in its description.
- Every invariant gets an automated test in the milestone that introduces it. If it cannot be tested, it gets a named item on a review checklist. An invariant with neither is an open bug.
- IDs (G-, NG-, AST-, A, TB-, INV-, AR-, Q-) are stable, because other documents cite them. A new entry takes the next free number, even when it sits in an earlier table.
- Update this file in each milestone's "what we learned" note ([ROADMAP §3](ROADMAP.md#3-milestones)) and before the M8 audit. The audit scope starts from this file.
- Mechanisms live in [CRYPTO.md](CRYPTO.md) and the ADRs. If this file and an ADR disagree on a mechanism, the ADR wins and this file is fixed in the same PR. If they disagree on a goal or an invariant, stop and ask the owner.

## 0. The short version

- The server stores ciphertext and metadata. It cannot read vault items. It does see who you are, when and from where you connect, and roughly how much you store and edit. It can delete or withhold your data. It can keep a device on an old vault state if that device has never seen a newer one.
- **The web vault is only as trustworthy as the server that serves it.** A malicious or compromised server can ship JavaScript that steals the master password at the next unlock, and a Secret Key the browser remembers at the next page load. The browser extension, desktop app, mobile apps and CLI do not load code from the server. They are the clients for anyone who does not trust their server.
- A stolen database on its own gives no way to guess passwords offline. The database plus the server's OPRF seed does, at one Argon2id evaluation per guess. In the one-container profile both sit on one host. [ADR 0010](adr/0010-server-shape.md) §4 mounts the secrets apart from the data volume, so a data-volume backup holds only the DB, but a stolen disk or a whole-host backup has both. Mixing the Secret Key into the password input makes that infeasible.
- Malware on an unlocked device wins. Malware on a locked device wins at the next unlock. We do not claim otherwise.
- Alias mail is plaintext on the server between SMTP receipt and encryption, because spam filtering has to read it. The server operator can read incoming mail.
- A share link is exactly as secret as every place it gets pasted, until the share expires.
- Autofill matching is a phishing control, and every entry in the domain-equivalence list is a potential phishing vector.

---

## 1. Scope, goals and non-goals

### 1.1 In scope

- All components in [§3](#3-components-and-trust-boundaries) for M1–M8, in both sync modes ([ROADMAP §4.6](ROADMAP.md#46-sync-modes-m4)).
- Deployment profile A (one container) and profile B (the `smtp` role in its own container with no DB access, [ROADMAP §4.9](ROADMAP.md#49-server-self-hosting--ops-m1-onward)). Profile C (HA, M10) inherits profile B's boundaries.
- M9/M10 threats that the M1 key hierarchy must already handle: key distribution to other users, shared vaults, org invites and admin recovery ([ADR 0006](adr/0006-key-hierarchy.md), [ROADMAP §6.7](ROADMAP.md#6-risks--hard-truths)).

### 1.2 Assumptions

| ID | Assumption | If it fails |
|---|---|---|
| ASM-1 | The primitives hold: X25519, Ed25519, ristretto255, XChaCha20-Poly1305, HKDF/HMAC-SHA-2 and Argon2id. | Every guarantee here fails. The only planned response is the post-quantum migration path ([AR-8](#9-accepted-risks-and-out-of-scope), [ADR 0007](adr/0007-ciphertext-envelope.md)). |
| ASM-2 | The client CSPRNG is sound: the OS RNG natively, `crypto.getRandomValues` in browsers. | Keys and nonces become predictable. |
| ASM-3 | The OS, browser and hardware are not compromised while the vault is unlocked. | [NG-1](#14-non-goals). |
| ASM-4 | The first install of a native client comes from an official channel ([§3.1](#31-components)) and is genuine. Later updates are checked against that install's signing identity where the platform allows it. | [A10](#a10-compromised-ci-or-release-credentials). |
| ASM-5 | Account registration runs over TLS that nobody intercepts. OPAQUE registration has no prior shared secret, so a MITM at registration can register the user against itself. | [A4](#a4-network-attacker-mitm). |
| ASM-6 | Operators apply security updates within weeks. | Known bugs stay exploitable. There is no technical mitigation. |
| ASM-7 | The user does not keep the Emergency Kit where a device thief also gets it (for example, as a photo on the same phone), or where someone who administers the instance can reach it. | Kit plus device gives full account access. Kit plus instance admin gives full account access immediately if the admin sets the recovery wait to 0 ([A3](#a3-malicious-instance-admin), [ADR 0008](adr/0008-account-recovery.md)). |

### 1.3 Security goals

| ID | Goal |
|---|---|
| G-1 | **Confidentiality of vault contents.** Items, TOTP seeds, passkeys, attachments, item history, tag/folder names and URLs stay secret from the server (passive and active), the network, other users of the instance, and anyone who holds the DB or backups. There are two exceptions against an *active* server: the web vault ([§4.2.1](#421-the-web-vault-delivery-problem)) and the share recipient page ([A12](#a12-share-link-leakage-m5)). |
| G-2 | **Integrity and authenticity.** The server and the network cannot forge, modify, swap, replay or reorder items, ops, keys or security settings without the client detecting it ([§5](#5-server-controlled-parameter-attacks)). |
| G-3 | **Freshness.** A device never accepts a vault state older than one it has already seen. We do not claim that a brand-new device can detect a stale state. |
| G-4 | **Password secrecy.** The server never receives the master password or a password equivalent. Offline guessing requires the DB *and* the OPRF seed, plus the Secret Key if it is adopted. Exception: when the web vault remembers the Secret Key ("this is my browser"), JavaScript served by an *active* server reads it at the next page load, so those users are protected against that server by the password alone ([§4.2.1](#421-the-web-vault-delivery-problem), [Q-21](#10-open-questions-for-the-owner)). |
| G-5 | **Client-enforced parameters.** The server cannot lower KDF cost or pick a weaker or older envelope or algorithm. |
| G-6 | **Authenticated key distribution.** Whenever a key is wrapped for another device or user, the user can check whose key it is. A user who verifies (pairing SAS in M4, fingerprints in M9) detects substitution. |
| G-7 | **Phishing-resistant autofill.** A credential is never filled into an origin that does not match under [ROADMAP §4.4](ROADMAP.md#44-url-matching--autofill-m2). Cross-domain matches are always visible to the user. |
| G-8 | **Share links.** Only holders of the full link can read a share, and the protocol never gives the server the key. Expiry, view limits and revoke work against an honest server. |
| G-9 | **Mail at rest.** Only the alias owner can read stored alias mail. Plaintext exposure is limited to the ingress window ([§6](#6-email-ingress-m6)). |
| G-10 | **No silent data loss in sync.** Concurrent edits converge, and conflicts are kept as history. |
| G-11 | **Containment.** Compromising the `smtp` or `icons` role does not give access to the database or to other users' stored data. A compromised `smtp` still reads all later mail, and through `resolve` it can enumerate aliases slowly and link aliases that share an owner ([AR-21](#9-accepted-risks-and-out-of-scope)). |
| G-12 | **Recoverability.** Users can list and revoke devices and sessions, rotate the password, Secret Key and account key, and see new device enrollments. |
| G-13 | **Traceable builds.** CI builds every release from a reviewed commit with locked dependencies. From M8, releases are also signed and carry provenance. |

### 1.4 Non-goals

| ID | We do not protect against |
|---|---|
| NG-1 | **Malware, or a person, with code execution on or physical access to a device while the vault is unlocked. This is game over.** We shorten the exposure window (auto-lock, clipboard clearing, zeroize on lock), but we claim no protection. |
| NG-2 | Malware on a locked device that survives until the next unlock. It captures the master password at that unlock. The outcome is the same as NG-1, one unlock later. Keystore (biometric) unlock must not shorten "one unlock later" to "now" ([INV-62](#8-security-invariants)). |
| NG-3 | A compromised OS, browser, firmware, hardware keyboard or OS keystore, including rooted or jailbroken phones. |
| NG-4 | Loss of availability caused by a malicious server or admin. The server can delete, withhold or refuse service. We detect this where we can ([§5.6](#56-rollback-withholding-and-forks)). Backups are the remedy. |
| NG-5 | Hiding metadata from the server: account existence, IP addresses, connection times, device count, approximate item count and sizes, edit frequency. Padding and batching in M4 ([ROADMAP §4.6](ROADMAP.md#46-sync-modes-m4), Should) reduce some of it. Anonymity networks are not supported. |
| NG-6 | Keeping incoming alias mail secret from the server during ingress ([§6](#6-email-ingress-m6)). |
| NG-7 | A weak master password when the attacker has the DB and the OPRF seed and the account has no Secret Key. |
| NG-8 | Recovery after losing both the master password (or the Secret Key) and the recovery code. In On-device mode this also covers losing every device. The data is gone, and the UI says so ([ROADMAP §4.3](ROADMAP.md#43-cryptography--authentication-m0m1-audited-in-m8)). |
| NG-9 | The integrity of server-delivered client code, meaning the web vault and share page, against the server that delivers it ([§4.2.1](#421-the-web-vault-delivery-problem)). |
| NG-10 | Physical side channels (power, EM, acoustic), cold-boot and DMA attacks, and microarchitectural attacks across processes or VMs, beyond our use of constant-time primitives. |
| NG-11 | Coercion. Travel mode is M9, Could. |
| NG-12 | Plaintext that has left our control: filled into a page, pasted, shown on a share recipient's screen, or exported in plaintext. |
| NG-13 | The security of the sites whose credentials the user stores. Storing a site's TOTP seed in the same vault as its password collapses that site's 2FA into one factor. That is the user's choice, and the UI should say so. |
| NG-14 | Network-level DoS against an instance. That belongs to the operator's hosting. |

---

## 2. Assets

| ID | Asset | Where it lives | Must never be readable by | Impact if an attacker gets it |
|---|---|---|---|---|
| AST-1 | Master password | User's head; client memory during unlock | Server, network, anyone | Full account compromise, together with the Secret Key and server access (or on its own, if there is no Secret Key). |
| AST-2 | Secret Key (if adopted, [ADR 0004](adr/0004-key-derivation-argon2id-secret-key.md)) | Emergency Kit printout; every enrolled device's state file, in plaintext until an OS keystore holds it ([CRYPTO.md §4.2](CRYPTO.md#42-key-inventory)); OS and cloud backups of those devices unless excluded ([INV-61](#8-security-invariants)); the web vault's IndexedDB if the user opts in, where JavaScript served by the server can read it at any page load | Server, network | On its own: nothing. With the master password: full account. With the DB and OPRF seed: it removes the protection against offline guessing. Next to `E_local` (device disk or device backup): offline guessing at the Argon2id floor ([A8](#a8-stolen-or-lost-device)). |
| AST-3 | Recovery code ([ADR 0008](adr/0008-account-recovery.md)) | Emergency Kit printout | Server, network | Unwraps the account key: full account, once the ADR 0008 waiting period (72 h default, 0 to 30 days by admin setting) passes without an enrolled device cancelling. |
| AST-4 | Account key: the symmetric root below the password and Secret Key | Wrapped on the server (Server mode) and on devices; plaintext in client memory while unlocked | Server | All current data, plus all future data until it is rotated. |
| AST-5 | Identity (Ed25519) and encryption (X25519) private keys | Wrapped under the account key | Server | Impersonation to the user's own devices and to other users. Decryption of anything wrapped to the user (shared-vault keys in M9, mail in M6). |
| AST-6 | Vault keys and item keys | Wrapped in the hierarchy ([ADR 0006](adr/0006-key-hierarchy.md)) | Server | The items under that vault key or item key. |
| AST-7 | Item plaintext: passwords, notes, cards, identities, custom fields, password history, attachments, tags, URLs | Encrypted everywhere at rest; plaintext in client memory and UI | Server, network | Direct takeover of the user's accounts. URLs alone reveal where the user has accounts. |
| AST-8 | TOTP seeds | Inside items | Server, network | The second factor for those sites. |
| AST-9 | Passkeys (M7) | Inside items | Server, network | Passwordless takeover of those accounts. A synced passkey leaks with the vault, which a device-bound passkey does not. |
| AST-10 | Share keys and share links (M5) | Key only in the URL fragment; ciphertext on the server until expiry | Server, and anyone who was not sent the link | The shared snapshot. |
| AST-11 | Alias mail and the alias-to-account mapping (M6) | Plaintext in `smtp` memory during ingress; ciphertext on the server; mapping on the server | Everyone except the owner (the server during ingress is an accepted exception) | Password-reset mails and OTPs, which lead to takeover of third-party accounts. The mapping ties aliases to a person, which defeats the purpose of an alias. |
| AST-12 | Device keys, session tokens, refresh tokens | Devices; token hashes on the server | Network, other users | API access as the user: download ciphertext, delete data, try to enroll devices (limited by [§5.5](#55-forged-device-registrations)). |
| AST-13 | Metadata: account identifier, IPs, user agents, timestamps, device list, item and op counts and sizes, share view counts, alias addresses, domains requested from the icons role | Server DB, server logs, proxy logs | Outsiders. Kept to a minimum even for the server. | Profiling the user, linking aliases to a person, learning which sites the user uses. |
| AST-14 | OPAQUE server setup: OPRF seed and server static keypair | Server secrets store, outside the DB ([INV-50](#8-security-invariants)) | Everything except the `api` process | If leaked: offline guessing against every account's OPAQUE record ([RFC 9807](#11-references)). If lost: nobody can log in or unwrap the password-wrapped account key; users need the recovery code or an existing device. |
| AST-15 | Other server secrets: deletion-receipt signing key (M4), server data key ([CRYPTO.md §5.11](CRYPTO.md#511-server-side-encryption-not-zero-knowledge)), TLS private key | Server secrets store; reverse proxy | Everything except the owning process | Forged receipts; 2FA bypass after DB theft; TLS impersonation (see [A4](#a4-network-attacker-mitm)). |
| AST-16 | Release credentials: GitHub accounts, CI secrets, container registry, Chrome Web Store / AMO / App Store / Play accounts, desktop updater key, cosign identity (M8), equivalence-list signing key | Maintainers' hardware keys, CI protected environments | Everyone else | A malicious update to every user of that channel, which is NG-1 for all of them. |
| AST-17 | DB and backups | Server, backup storage | Outsiders | Ciphertext, metadata and OPAQUE records ([A1](#a1-passive-server-compromise-db-or-backup-theft)). |
| AST-18 | Logs | Server, proxy, log sinks | Outsiders | Metadata. Secrets too, if [INV-48](#8-security-invariants) is broken. |
| AST-19 | Local encrypted cache and device state (`E_local`, `device_salt`, `E_dev`, SK) | Each device; OS and cloud backups of it unless excluded ([INV-61](#8-security-invariants)); for the browser extension, the browser profile on disk | Other local users, thieves, backup providers | A target for offline guessing ([A8](#a8-stolen-or-lost-device)). |
| AST-20 | Exports | Wherever the user puts them | Everyone else | Encrypted export: offline guessing at the export KDF cost. Plaintext export: everything. |
| AST-21 | Clipboard contents | OS clipboard, clipboard history and cross-device clipboard sync | Other apps, other devices | The copied secret. |
| AST-22 | Local unlock secret for keystore (biometric) unlock (M3/M7, [ADR 0013](adr/0013-shared-client-core.md) §3, [ADR 0015](adr/0015-desktop-tauri.md) §9) | The OS keystore of one device | Any process, including same-user processes, before an OS-enforced user-presence check ([INV-62](#8-security-invariants)) | Opens `E_ks` ([CRYPTO.md §4.2](CRYPTO.md#42-key-inventory)) on that device without the password and without Argon2id: an account-key equivalent there. |

---

## 3. Components and trust boundaries

### 3.1 Components

| Component | What it is | Where its code comes from | Holds keys or plaintext | From |
|---|---|---|---|---|
| Web vault | TypeScript UI plus `rizzy-core` compiled to wasm ([ADR 0013](adr/0013-shared-client-core.md), [0014](adr/0014-ui-stack.md)) | **The instance's `web` role, loaded at every page load** | Yes, in the browser while unlocked | M1 |
| Browser extension | MV3 for Chromium and Firefox; UI plus `rizzy-core` wasm | Chrome Web Store, AMO | Yes | M2 |
| Desktop app | Tauri: Rust backend linked to `rizzy-core`, webview UI ([ADR 0015](adr/0015-desktop-tauri.md)) | Signed releases and the updater feed | Yes: keys in the Rust process, displayed plaintext in the webview | M3 |
| Mobile apps | Native UI plus `rizzy-core` through UniFFI; OS autofill extensions | App Store, Play | Yes | M7 |
| CLI `rv` | Native Rust | Release binaries, or built from source | Yes | M1 |
| `api` role | OPAQUE auth, sessions, vault and op-log storage (Server mode), relay (On-device mode), shares, device registry, admin API ([ADR 0010](adr/0010-server-shape.md)) | Server image | No: ciphertext and metadata only | M1 |
| `web` role | Serves the web vault and the share recipient page as static assets | Server image | No | M1 (share page M5) |
| `notify` role | WebSocket/SSE "something changed" signals; mobile push through APNs/FCM | Server image | No | M3 |
| `worker` role | Purges (shares, relay TTL, mail retention, expired auth state) and op-log compaction bookkeeping. Never trash: lifecycle is encrypted, and clients purge trash with signed `Purge` ops ([ADR 0010](adr/0010-server-shape.md) §1, [ADR 0012](adr/0012-sync-engine.md) §5) | Server image | No | M1 |
| `smtp` role, with rspamd | Receive-only SMTP on port 25; calls rspamd; encrypts to the recipient's public key; hands ciphertext to `api` | Server image; rspamd from its own image | **Plaintext mail, briefly** | M6 |
| `icons` role | Fetches favicons from the internet, re-encodes them, caches them | Server image | No; sees domains | M3 |
| Database | SQLite (default) or PostgreSQL through sqlx ([ADR 0011](adr/0011-storage.md)) | Operator | Ciphertext, OPAQUE records, metadata | M1 / M3 |
| Server secrets | OPAQUE server setup, receipt signing key, server data key | Generated at first start | Server-side secrets ([AST-14](#2-assets), [AST-15](#2-assets)) | M1 |
| Backups | DB dumps and a separate secrets backup | Operator | Same as the DB and secrets | M1 |
| Reverse proxy / TLS terminator | Caddy, Traefik, nginx or similar; the operator's choice | Operator | Sees tokens, ciphertext, IPs | M1 |
| Relay | The `api` and `notify` roles in On-device mode: store-and-forward for encrypted ops, device registry, version vectors. Not a separate binary. | Server image | No | M4 |
| Mail ingress path | MX record, port 25, `smtp` role, rspamd, `api` | DNS and operator | Plaintext during ingress | M6 |
| Share recipient page | Page served by the `web` role; runs in the recipient's browser without an account | **The instance, at every load** | The share plaintext, in the recipient's browser | M5 |
| Distribution channels | Container registry, extension stores, app stores, GitHub releases, desktop updater feed. The signed equivalence list and a PSL snapshot ship inside client builds. | CI | Code for every client | M1+ |
| CI | GitHub Actions ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)), Dependabot | GitHub | No keys today; release credentials once publishing is automated | M0 |
| External services | HIBP range API (M3), DNS (SPF/DKIM/DMARC, blocklists), ACME CA, APNs/FCM | Third parties | No, if the invariants hold | M3+ |

### 3.2 Diagram

```
 ZONE D: USER DEVICES                        ZONE S: SERVER HOST
 trusted only while the OS is clean          trusted for availability, never for confidentiality

 +-------------------------------+           +-------------------------------------------+
 | web vault (browser)           |  HTTPS    | reverse proxy: TLS ends here (TB-3 below) |
 |  TS UI + rizzy-core wasm      |--TB-1---->+-------------------------------------------+
 |  code comes FROM THE SERVER   |<==TB-2====| web role: web vault + share page assets   |
 +-------------------------------+ code from +-------------------------------------------+
 | extension      (store)        | server    | api role: OPAQUE, sessions, vault/op log, |
 | desktop Tauri  (signed rel.)  |--TB-1---->|  relay, shares, devices, admin API        |
 | mobile         (app stores)   |  OPAQUE + +-------------------------------------------+
 | CLI rv         (release bins) |  E2EE     | notify role (WS/SSE, push)                |
 +-------------------------------+           | worker role (purge, TTL, retention)       |
 | local: encrypted cache,       |           +---------------------+---------------------+
 | Secret Key, device key,       |                          TB-4   |   TB-5
 | session token, clipboard      |           +---------------------v---------------------+
 +---------------+---------------+           | DB (SQLite / Postgres)  | server secrets  |
                 | TB-9  fill / page DOM     | + backups               | OPRF seed, keys |
                 v                           +-------------------------+-----------------+
 +-------------------------------+
 | web pages, any origin         |
 | (untrusted, incl. phishing)   |           ZONE M (profile B: own container + network, no DB)
 +-------------------------------+           +-------------------------------------------+
                                    SMTP :25 | smtp role --local HTTP--> rspamd          |
 ZONE N: INTERNET (untrusted)     ---TB-6--->| (alias id, ciphertext) --TB-7--> api      |
  mail senders, websites,                    +-------------------------------------------+
  icon origins, HIBP, DNS, ACME              ZONE I (own container, egress only, no DB)
                                  HTTP fetch +-------------------------------------------+
                                  <--TB-8----| icons role: fetch, re-encode, cache       |
                                             +-------------------------------------------+

 All client traffic, web vault included, passes the reverse proxy before any role.

 SHARE FLOW (M5): owner --link via chat/email (TB-12)--> recipient browser
                  recipient browser <== page code + ciphertext from web/api role (TB-2)

 BUILD AND DISTRIBUTION (TB-13):
  crates.io, npm, base images, third-party Actions --> GitHub Actions CI -->
     container registry | Chrome Web Store, AMO | App Store, Play | GitHub releases, updater feed
```

### 3.3 Trust boundaries

| ID | Boundary | What crosses it | Controls |
|---|---|---|---|
| TB-1 | Device to internet to server | OPAQUE messages, ciphertext, ops, tokens, metadata | TLS (rustls), OPAQUE mutual authentication at login, E2EE payloads, envelope AAD, signed ops |
| TB-2 | **Where client code comes from** | Web vault and share page code, served by the instance | CSP only. There is no cryptographic control against the serving origin ([§4.2.1](#421-the-web-vault-delivery-problem)). |
| TB-3 | Reverse proxy to server process | Everything, including tokens, in plain HTTP on the host or container network | Same host or private network. The proxy is inside the server trust zone. |
| TB-4 | Server process to DB and backups | Ciphertext, OPAQUE records, metadata | sqlx bound parameters; file permissions; DB credentials only for `api` and `worker` |
| TB-5 | Server process to server secrets | OPRF seed, server keys | Stored outside the DB and outside DB backups ([INV-50](#8-security-invariants)) |
| TB-6 | Internet senders to `smtp` | Hostile SMTP and MIME | Safe-Rust parser, fuzzing, limits, isolation ([§6](#6-email-ingress-m6)) |
| TB-7 | `smtp` to `api` | Two calls only ([ADR 0010](adr/0010-server-shape.md) §2): `resolve(alias address)` → accept (alias ID, the account's key bundle with the chain since the `bundle_seq` `smtp` last pinned, [CRYPTO.md §11.13](CRYPTO.md#1113-mail-ingress-m6)) or reject; `deliver(alias ID, ciphertext, padded size)` | No DB credentials in `smtp`; narrow internal API; `resolve` is rate-limited ([INV-44](#8-security-invariants)). A compromised `smtp` can still enumerate aliases slowly and link aliases of one account, because they return the same mail key ([AR-21](#9-accepted-risks-and-out-of-scope)). |
| TB-8 | `icons` to internet | Arbitrary HTTP responses from arbitrary hosts (icon links and redirects point anywhere) | Allow-list of globally routable addresses and ports 80/443, re-encoding, limits ([INV-51](#8-security-invariants)) |
| TB-9 | Extension to web page | Filled values; page DOM events | Isolated worlds, gesture-only fill, extension-origin UI ([INV-36](#8-security-invariants) to [INV-40](#8-security-invariants)) |
| TB-10 | `rizzy-core` to UI code within one client | Item plaintext for display | In the browser this is **not** a security boundary: JS in the same page can read wasm memory. It is an audit boundary. In Tauri and mobile it is a process or IPC boundary, and keys stay on the Rust side. |
| TB-11 | Device to device of the same user (pairing, relay) | Keys, snapshots, ops through the relay | SAS on pairing, device keys certified by the identity key ([INV-16](#8-security-invariants), [INV-29](#8-security-invariants)) |
| TB-12 | Share owner to share recipient | The link, through whatever channel the owner picks | Short expiry, view limits, optional passphrase |
| TB-13 | Source to build to distribution | Dependencies in, artifacts out | cargo-deny, lockfile, CI permissions, signing (M8) |
| TB-14 | Instance admin to users of the instance | Admin actions, instance configuration | Client-enforced crypto ([§5](#5-server-controlled-parameter-attacks)); no escrow before M10 |

### 3.4 What the server holds, by sync mode

This table is the source for the M4 transparency page ([ROADMAP §4.6](ROADMAP.md#46-sync-modes-m4)).

| Data | Server mode | On-device mode | Note |
|---|---|---|---|
| Account identifier (email or username) | Stored | Stored | Needed for login and routing |
| OPAQUE record (envelope, masking key, client public key) | Stored | **Deleted at the switch point** ([CRYPTO.md §5.7](CRYPTO.md#57-on-device-sync-mode), [INV-28](#8-security-invariants), [Q-3](#10-open-questions-for-the-owner)) | Combined with the OPRF seed, it is a password-guessing target |
| Account key wrapped under a password-derived key | Stored | None ([INV-28](#8-security-invariants)) | |
| Account key wrapped under the recovery code | Stored | None | A 128-bit code is not guessable |
| Public keys: identity, encryption, devices (signed) | Stored | Stored | |
| Encrypted vault snapshots | Stored | None | |
| Encrypted op log | Stored, compacted into client-made snapshots; the signed op headers are kept for the life of the vault ([ADR 0012](adr/0012-sync-engine.md) §7) | Only relay batches that some active device has not acked, and never beyond the TTL | |
| Vault self-grants and item-key wraps | Stored | None: they travel inside relay batches and pairing transfers ([CRYPTO.md §4.2](CRYPTO.md#42-key-inventory)) | On the server they would reveal vault and item IDs |
| Per-device version vectors and cursors | Stored | Per-device ack cursors only (highest `batch_seq` per sender) | Reveal edit counts per device |
| Item IDs, op counts, ciphertext sizes, timestamps | Visible | Not visible: ops travel inside relay batches. Per batch: sender device, `batch_seq`, padded size, time ([ADR 0012](adr/0012-sync-engine.md) §11) | Padmé padding reduces sizes ([CRYPTO.md §8.5](CRYPTO.md#85-plaintext-framing-and-padding)) |
| IPs, user agents, connection times | Logs | Logs | Retention is configurable ([ROADMAP §4.9](ROADMAP.md#49-server-self-hosting--ops-m1-onward)) |
| Share ciphertexts, expiry, view counts | Stored | Stored | Shares are server-stored by nature ([ROADMAP §4.6](ROADMAP.md#46-sync-modes-m4)) |
| Alias addresses and alias-to-account mapping | Stored | Stored | Mail routing needs them |
| Alias mail | Plaintext during ingress; ciphertext until deletion or retention expiry | Plaintext during ingress; ciphertext until every device acks | [§6](#6-email-ingress-m6) |
| Server-side 2FA secrets | Encrypted under a server key kept outside the DB | Same | [INV-8](#8-security-invariants) |
| Session tokens | Hashes only | Hashes only | [INV-8](#8-security-invariants) |
| Domains requested from `icons` | Seen by the `icons` role if enabled | Same | [INV-51](#8-security-invariants) |

---

## 4. Adversaries

### 4.0 Summary

| ID | Adversary | Worst realistic outcome | Main mitigation | Residual |
|---|---|---|---|---|
| A1 | Passive server compromise (DB or backup theft) | Offline password guessing, if the OPRF seed was also taken and there is no Secret Key | OPAQUE, OPRF seed outside the DB, Argon2id floor, Secret Key | Weak password with no Secret Key and a leaked seed (a stolen disk or a whole-host backup has both); metadata |
| A2 | Active malicious or compromised server | Backdoored web vault, which means full compromise of web-vault users | Native clients; client-enforced parameters; AAD; signatures; rollback checks | Web vault, share page, metadata, availability, freezing new devices |
| A3 | Malicious instance admin | A2, plus reading alias mail, restoring old backups, setting the recovery wait to 0, and social power | Same as A2; no escrow | Everything except item contents seen through native clients; kit plus admin is an immediate takeover |
| A4 | Network MITM | With valid TLS: metadata. With broken TLS: A2 against web-vault users, token theft, relayed device authentication | TLS, OPAQUE at new-device login, E2EE, request binding ([Q-7](#10-open-questions-for-the-owner)) | Registration over intercepted TLS; TLS-inspecting networks; enrolled devices rely on TLS alone to authenticate the server |
| A5 | Malware on a client | Unlocked: everything. Locked: everything at the next unlock. | None claimed ([NG-1](#14-non-goals), [NG-2](#14-non-goals)); keystore unlock gated by user presence | All of it |
| A6 | Phishing site / autofill abuse | Credentials filled into an attacker's origin; passkey assertions for another RP | PSL, equivalence governance, gesture-only fill, warnings, RP ID checks | Subdomain takeover under base-domain matching; stale lists |
| A7 | Malicious page scripts against the extension | Clickjacked or hidden-field fills; tricking the extension into leaking data or signing for another RP | Extension-origin UI, visibility checks, untrusted-message handling, origin from sender info | Browser-specific gaps |
| A8 | Stolen or lost device, or a backup of its storage | Offline guessing against the local cache; keystore unlock without the password | OS keystore and hardware-bound keys, Argon2id floor, backup exclusion, revocation with rotation | Platforms without a hardware keystore; the rotation race of a compromised revoked device |
| A9 | Supply chain | Malicious code in a client or the server | cargo-deny, lockfile, minimal dependencies, review | A popular dependency turning malicious |
| A10 | Compromised CI or release credentials | Malicious update to every user of a channel, including tag-following server auto-updates | Hardware 2FA, protected release jobs, signing (M8) | Single maintainer as a single point of failure |
| A11 | Malicious email senders | RCE in `smtp` (profile A: whole server), XSS in the mailbox UI, alias probing | Safe-Rust parser, fuzzing, profile B, sandboxed rendering, alias entropy | rspamd is C code parsing hostile input; active aliases are distinguishable |
| A12 | Share-link leakage | Share plaintext read by a third party | Short expiry, view limits, explicit reveal, passphrase | Channel logs until expiry; page code served by the server; burn by a full-link holder |
| A13 | Relay operator (On-device mode) | Metadata, withholding, forks | Signed ops, gap detection, SAS pairing | Metadata; availability |
| A14 | Shoulder surfing, clipboard, screen capture, input-field leaks | A single secret; the master password through a keyboard or spell-check service | Masking, clipboard clearing, screenshot blocking, secret-field attributes | Clipboard history and sync in the OS |
| A15 | Other users and the anonymous internet | Online guessing, enumeration, DoS including login lockout, IDOR, SSRF | Backoff without lockout, dummy records, authz tests, quotas, SSRF allow-list | Registration reveals which identifiers are taken; floods slow new-device and web-vault logins |
| A16 | Malicious import files and shared content | Parser DoS, XSS, `javascript:` URLs | Fuzzing, text rendering, URL scheme allow-list | Parser bugs |
| A17 | Vault member, current or removed (M9) | Edits beyond the member's role; keeping what they saw | Signed ops; client-checked signed roles; vault-key rotation on removal | Cached plaintext after removal |

### A1. Passive server compromise: DB or backup theft

**Capabilities.** Reads a copy of the database or a DB backup: a leaked DB dump, SQL injection that reads tables, a leaked Postgres replica. With a full host compromise, the attacker also reads the server secrets. This is the "breach and dump" attacker.

**Profile A puts both on one host.** [ADR 0010](adr/0010-server-shape.md) §4 keeps the server secrets on their own read-only mount, apart from the data volume that holds SQLite, and the server refuses to start if the secrets file sits inside the data directory. A backup of the data volume alone (the usual Docker and Podman practice) is therefore DB only. A stolen disk, a whole-host backup, or an operator who backs up both mounts together is still DB *plus* seed. With a mandatory Secret Key this changes nothing. If [Q-1](#10-open-questions-for-the-owner) ends with an optional Secret Key, it is the difference between safe and crackable.

**What they obtain.**
- Always: account identifiers, OPAQUE records, wrapped account keys (password wrap and recovery wrap), public keys, encrypted snapshots and op logs, share ciphertexts, alias mail ciphertexts and the alias-to-account mapping, device lists, token hashes, encrypted 2FA secrets, and timestamps.
- **DB only, no OPRF seed:** nothing to guess against. The OPRF key acts as a secret salt. Without it a password guess cannot be tested against the OPAQUE envelope or the password wrap ([RFC 9807](#11-references)). The recovery wrap is under a code of at least 128 bits. Vault data is under 256-bit keys.
- **DB plus OPRF seed (full host compromise, a stolen disk, a whole-host backup, or the seed in the same backup):** offline guessing at one Argon2id evaluation per guess. RFC 9807 states that a corrupted server can always run this attack and that a leaked `oprf_seed` endangers all users. With the proposed floor (m=64 MiB, t=3, p=4; final numbers in [ADR 0004](adr/0004-key-derivation-argon2id-secret-key.md)), one guess cost about **0.24 core-seconds** in the M0 measurement (native, one thread, 2.8 GHz Xeon vCPU, argon2 0.6.0, single run). Dedicated hardware lowers the attacker's cost, so treat these figures as an upper bound:

| Password | Guesses to exhaust | CPU time at 0.24 core-s per guess |
|---|---|---|
| In a top-10^6 list | 10^6 | about 66 core-hours |
| In a top-10^9 list | 10^9 | about 7.5 core-years |
| 4 random diceware words (about 51.7 bits) | 3.7 × 10^15 | about 2.7 × 10^7 core-years |
| Anything, **with a 128-bit Secret Key mixed in** | at least 2^128 | infeasible |

**Mitigations.** OPAQUE instead of a password hash ([ADR 0003](adr/0003-authentication-opaque.md), [INV-1](#8-security-invariants)). OPAQUE server setup stored outside the DB and outside DB backups ([INV-50](#8-security-invariants)). The deploy docs mount the secrets separately from the data volume by default (a container secret, a Podman secret or a systemd credential), and say plainly that a backup of a volume that holds both is a DB-plus-seed backup. An Argon2id floor enforced by the client ([INV-3](#8-security-invariants)). The Secret Key mixed into the OPAQUE password input ([INV-2](#8-security-invariants), [Q-1](#10-open-questions-for-the-owner), [Q-2](#10-open-questions-for-the-owner)). 2FA secrets encrypted and tokens hashed ([INV-8](#8-security-invariants)). AAD binding everywhere, so dumped ciphertext cannot be replayed into another context.

**Residual risk.**
- A weak password without a Secret Key falls to a DB-plus-seed attacker ([NG-7](#14-non-goals)).
- Old backups keep old password wraps. A password change does not invalidate them: an attacker who later learns the *old* password can open the old wrap and get the *unchanged* account key. Only account-key rotation fixes that ([INV-19](#8-security-invariants), [AR-11](#9-accepted-risks-and-out-of-scope)).
- Metadata is exposed ([NG-5](#14-non-goals)).

### A2. Active malicious or compromised server

**Capabilities.** Everything A1 has, plus control over every response: arbitrary replies to any client request, and arbitrary code served to browsers. It can lie about KDF parameters, envelope versions, public keys, device lists and vault state. It can drop, withhold, reorder or replay ops, fork devices, bypass its own rate limits and 2FA checks, keep "deleted" data, sign false deletion receipts, read alias mail at ingress, and correlate IPs and timing. This covers the operator turning malicious and an attacker who has taken over the host.

**What they obtain.**
- From native clients: nothing beyond A1 plus metadata, **if** the invariants in [§5](#5-server-controlled-parameter-attacks) hold.
- From web-vault users: everything, at their next unlock; a remembered Secret Key already at the next page load ([§4.2.1](#421-the-web-vault-delivery-problem)).
- From share recipients: the share plaintext, by serving modified page code that reads the fragment.
- From mail: all incoming mail from the time of compromise ([§6](#6-email-ingress-m6)).
- Availability: all of it ([NG-4](#14-non-goals)).

**Mitigations.** [§5](#5-server-controlled-parameter-attacks) lists them attack by attack. In short: the client decides the parameters; every ciphertext is bound to its context; every public key and device key is signed and pinned; every state transition is checked for freshness. There are no legacy code paths ([ADR 0002](adr/0002-own-protocol.md)) and no escrow ([INV-18](#8-security-invariants)).

**Residual risk.**
- Web vault and share page ([AR-1](#9-accepted-risks-and-out-of-scope)).
- Mail at ingress ([AR-2](#9-accepted-risks-and-out-of-scope)).
- Metadata ([AR-3](#9-accepted-risks-and-out-of-scope)).
- Freezing a new device on stale state, and forks that stay hidden until devices compare state ([AR-5](#9-accepted-risks-and-out-of-scope)).
- Server-enforced controls (2FA, rate limits, view limits, deletion) are only as good as the server ([AR-9](#9-accepted-risks-and-out-of-scope)).

#### 4.2.1 The web-vault delivery problem

In Server mode the web vault is HTML, JS and wasm served by the `web` role of the same instance that stores the ciphertext. The browser runs whatever that origin serves at page load. Anyone who controls what the origin serves can ship a web vault that reads a remembered Secret Key from browser storage at the next page load, with no unlock needed, and sends the master password and every decrypted item to themselves at the next unlock. That includes:
- the operator;
- an attacker with write access to the container or the static files;
- the reverse proxy or TLS terminator;
- anyone who can get a valid certificate for the domain (DNS hijack, mis-issuance);
- a corporate TLS-inspection box.

The protocol cannot detect this, because any detection code would itself be served by the attacker. 1Password's white paper says the same about its own web client (Appendix A, "Beware of the leopard"; secondary source).

**Consequences.**
- For web-vault users, "the server never sees plaintext" holds against a *passive* server only. It does not hold against an *active* one.
- One unlock through a backdoored web vault leaks the password and the Secret Key. That compromises the whole account on every client. Recovery means rotating the password, the Secret Key and the account key.
- **A remembered Secret Key needs no unlock.** If the user ticked "this is my browser" ([CRYPTO.md §7](CRYPTO.md#7-secret-key)), the SK sits in IndexedDB on the vault origin, and any page load of server-served JavaScript can read it. The server already holds the OPRF seed, so it can then guess the master password offline at one Argon2id per guess, without the user ever unlocking again. For these users 2SKD does not hold against an active server ([G-4](#13-security-goals), [Q-21](#10-open-questions-for-the-owner)). The checkbox copy must say "your server can read this".
- Clients that avoid this: the **browser extension** (store-delivered), **desktop app** (signed releases), **mobile apps** (app stores) and **CLI** (release binaries). A malicious server can attack them only through the protocol, which [§5](#5-server-controlled-parameter-attacks) covers. Their own weak point is the distribution channel ([A10](#a10-compromised-ci-or-release-credentials)).
- Turning the web vault off ([Q-6](#10-open-questions-for-the-owner)) is a server-side setting. It protects users from a *compromised* instance that keeps the operator's configuration. It does not protect them from the operator.

**What we do anyway.**
- A strict CSP ([INV-49](#8-security-invariants)). It stops third-party injection, not the origin itself.
- Web-vault assets embedded in the signed server image, not read from a writable directory ([ROADMAP §4.9](ROADMAP.md#49-server-self-hosting--ops-m1-onward): read-only rootfs). This helps against file tampering, not against a malicious operator.
- The hash of each release's web-vault bundle published with the release, and reproducible builds (M8, Could), so anyone can compare what they are served.
- An admin switch to disable the web vault ([Q-6](#10-open-questions-for-the-owner)).
- Plain UI copy: "The web vault is delivered by your server. If you do not trust the server operator, use the extension or the desktop app."

WAICT (Cloudflare with Mozilla and others; prototype in Firefox Nightly) and WEBCAT (Freedom of the Press Foundation; alpha, needs a browser extension) aim to fix this class of problem. Neither can be deployed to general users today (secondary sources). Revisit both post-1.0.

**Residual risk: accepted ([AR-1](#9-accepted-risks-and-out-of-scope)).** People who do not control the server should not unlock their vault in the web vault. On-device mode already disables the web vault ([ROADMAP §4.6](ROADMAP.md#46-sync-modes-m4), Won't).

### A3. Malicious instance admin

**Capabilities.** Everything A2 has, plus the admin's legitimate powers:
- Admin panel (M3): list, disable and delete users; invite-only signup; restrict sync modes.
- Instance-wide KDF defaults. Clients ignore anything below the floor.
- Access to logs, backups and TLS keys.
- Restoring an old backup, which rolls back every account and brings back superseded credentials ([§5.8](#58-server-restore-from-backup)).
- Setting the recovery waiting period anywhere from 0 to 30 days ([ADR 0008](adr/0008-account-recovery.md)). At 0, a pending recovery completes before any device can cancel it.
- Physical access to the host.
- Reading alias mail at ingress.
- M10 only: SSO, a key connector if one is ever built, and admin recovery for users who consented to it.

The admin may be a family member (M9) or an employer (M10). The social context matters: users trust the admin with availability anyway.

**What they obtain.** The same as A2. In M10 they also get the vaults of users who consented to admin recovery. That is the purpose of the feature, and the user must be able to see it ([INV-18](#8-security-invariants)).

**The family case.** An M9 family admin often lives in the same house as the printed Emergency Kits. With the recovery wait set to 0, admin access plus a kit is an immediate account takeover: the enrolled devices are notified but get no time to cancel. The admin needs neither the password nor any server compromise ([ASM-7](#12-assumptions)). A 0 wait belongs on single-account instances only ([Q-15](#10-open-questions-for-the-owner)), and every change to the wait goes into the affected users' security event log ([INV-69](#8-security-invariants)).

**Mitigations.** The same as A2. There is no server-side "reset password and decrypt" function; that is Won't forever ([ROADMAP §4.3](ROADMAP.md#43-cryptography--authentication-m0m1-audited-in-m8)). M10 escrow is opt-in per user, performed by the client, and wraps to an org recovery key that is authenticated like any other user key ([INV-17](#8-security-invariants), [INV-18](#8-security-invariants)). The M4 transparency page shows what the server stores, but it is only accurate on an honest server. The admin panel itself is an attack surface for outsiders; [§7.19](#719-admin-panel-and-admin-api-m3) covers it.

**Residual risk.** Using someone else's instance means trusting them with availability, metadata, alias mail and web-vault integrity. It does not mean trusting them with item contents seen through native clients. The docs for family and SMB deployments should say this in one sentence.

### A4. Network attacker (MITM)

**Capabilities.** Observes and modifies traffic between a client and the server, and between the server and external services (inbound SMTP, icon fetches, HIBP, DNS).

**What they obtain.**
- **With intact TLS:** traffic metadata (sizes, timing, the server name in SNI) and nothing else.
- **With broken TLS** (rogue or mis-issued certificate, a user clicking through a warning, a TLS-inspection proxy, an operator serving plain HTTP):
  - Web-vault users: A2 powers.
  - Native clients: session tokens and ciphertext. With a token the attacker can download ciphertext and make destructive API calls, unless requests are bound to a key ([Q-7](#10-open-questions-for-the-owner)).
  - OPAQUE still protects the password. Where OPAQUE runs (new-device login, the web vault, re-authentication), it also authenticates the server: the envelope's auth tag covers the server's public key registered at registration (RFC 9807), so a MITM without the server's private key cannot complete that login.
  - **Enrolled devices do not run OPAQUE on the everyday path.** They answer a device-key challenge ([CRYPTO.md §5.10](CRYPTO.md#510-sessions-after-authentication)) that binds the server origin *string*, not the TLS channel and not a server key. A MITM whose certificate the client accepts can relay the real server's challenge and walk away with a session. For enrolled native clients, TLS is the only server authentication. Binding the challenge to the TLS channel (a TLS exporter) does not help here, because TLS ends at the operator's reverse proxy and the exporter never reaches the server process ([TB-3](#33-trust-boundaries)). Per-request signatures ([Q-7](#10-open-questions-for-the-owner)) are the practical fix: a relayed session can then only replay what the client itself sends.
- **Inbound mail:** SMTP between sending MTAs and us is opportunistic STARTTLS at best, so mail in transit is exposed to network attackers.

**Mitigations.** TLS through rustls (openssl is banned in [`deny.toml`](../deny.toml)); HSTS; clients refuse `http://` server URLs except `localhost`; OPAQUE mutual authentication where OPAQUE runs; E2EE payloads; tokens never in URLs ([INV-52](#8-security-invariants)); request binding for native clients ([Q-7](#10-open-questions-for-the-owner)). The M6 admin docs cover publishing MTA-STS for the mail domain, so senders that support it enforce TLS.

**Residual risk.** Registration over intercepted TLS ([ASM-5](#12-assumptions)). Web vault over intercepted TLS ([AR-1](#9-accepted-risks-and-out-of-scope)). A relayed device-auth session under intercepted TLS, limited to ciphertext and destructive calls, and further limited by [Q-7](#10-open-questions-for-the-owner) if adopted. Traffic analysis ([NG-5](#14-non-goals)).

### A5. Malware on the client

#### A5a. Vault locked

**Capabilities.** Code running as the user while the vault is locked. It may persist.

**What they obtain.**
- The encrypted local cache.
- The Secret Key, if it is stored on disk rather than in a hardware-backed keystore.
- Session and refresh tokens, which give API access: download ciphertext, delete data.
- The ability to modify user-writable client files (the extension in the browser profile, a user-installed app) and to install a keylogger. Either one captures the password at the next unlock ([NG-2](#14-non-goals)).
- Offline guessing against the local unlock wrap ([A8](#a8-stolen-or-lost-device)). A Secret Key on the same disk adds nothing against this attacker.
- **The keystore-held local unlock secret ([AST-22](#2-assets)), if the store releases it to any same-user process.** Plain DPAPI and an unlocked Secret Service collection do exactly that. The secret opens `E_ks` without the password or Argon2id, so the malware reads the vault *now*, not at the next unlock. [INV-62](#8-security-invariants) therefore offers keystore unlock only where the OS enforces user presence.

**Mitigations.** Keep the Secret Key in the OS keystore where available: Keychain/Secure Enclave, Android Keystore, Windows DPAPI/TPM, Secret Service on Linux (usually no hardware binding). The SK alone gives malware nothing without the password, so any of these stores will do for it. The local unlock secret is different: it is an account-key equivalent on that device, and it goes only into a store that demands user presence, bound to hardware where possible ([INV-62](#8-security-invariants)). Device keys stay wrapped under the account key ([CRYPTO.md §5.10](CRYPTO.md#510-sessions-after-authentication)). Bind tokens to the device key and keep them short-lived ([Q-7](#10-open-questions-for-the-owner)). OS code signing and notarization only stop naive tampering.

**Residual risk.** Malware that persists wins at the next unlock. This is a stated non-goal.

#### A5b. Vault unlocked

**Capabilities and outcome.** Reads process memory, the DOM, the clipboard and the screen. Calls the client's own decrypt functions. Injects into the browser. **This is game over ([NG-1](#14-non-goals)).** Other browser extensions with access to all sites count as malware inside the browser: they can read the web vault's DOM and any filled field on any page.

**What we do.** Auto-lock timeout. Lock on OS lock and sleep. Zeroize keys and decrypted state on lock ([INV-21](#8-security-invariants)). Clear the clipboard. These shorten the window; they do not close it.

### A6. Phishing site and autofill abuse

**Capabilities.** Controls a domain and its content and gets the user to visit it. Goals:
- Get a credential autofilled or typed into the wrong origin.
- Get the master password and Secret Key typed into a fake vault page.
- Get the user to add an equivalence rule.
- Get a malicious entry into the global equivalence list.
- Get a passkey assertion for another site's RP ID (M7; [A7](#a7-malicious-web-page-scripts-against-the-extension) covers the mechanism).

**What they obtain.** The credentials for the matched site. With a fake vault page they get the master password, which is not enough to log in from a new device when a Secret Key is required, unless they also talk the user into typing the Secret Key.

**Mitigations.** The M2 rules ([ROADMAP §4.4](ROADMAP.md#44-url-matching--autofill-m2); [INV-36](#8-security-invariants) to [INV-39](#8-security-invariants)):
- Hosts are normalized to IDNA A-labels, and IDN hosts with mixed scripts are shown in punycode. The idna crate needs version 1.0 or later because of RUSTSEC-2024-0421.
- Registrable domains come from the PSL (eTLD+1).
- Fill happens only on a user gesture, never on page load.
- No HTTPS-saved credential is filled into an HTTP page. Nothing is filled into cross-origin iframes by default.
- A match that exists only through an equivalence group gets a visible warning.
- The fill UI shows the exact host.
- Match mode is set per URI, and *Host* is available for sensitive logins.
- **Every match mode first passes the registrable-domain check.** Modes narrow a match; they never widen it past the registrable domain or an equivalence group ([INV-38](#8-security-invariants)). Without this rule, *Starts with* `https://bank.com` matches `https://bank.com.evil.example/`, and an unanchored *Regex* matches any host.

**Equivalence list governance** ([ROADMAP §6.4](ROADMAP.md#6-risks--hard-truths)):
- Every entry needs proof of common ownership and review by two maintainers.
- The list is signed with a dedicated key, versioned, and shipped inside client releases. A change to the list goes through the release process.
- Clients reject an unsigned list or an older version ([INV-39](#8-security-invariants)). Users can disable any global group.
- Rules for entries, aimed at over-broad groups:
  1. No domain where third parties can host content, unless the PSL already splits it.
  2. For ccTLD variants (`brand.tld`), ownership is proven per variant, not assumed for the whole family.
  3. Entries are re-checked on a schedule, and an entry whose domain lapses is removed. A re-registered lapsed domain is an attacker's domain.
- A malicious contribution usually looks like a harmless addition next to a big brand. The reviewer's job is to prove the ownership link, not to judge whether the addition looks reasonable.

**Residual risk.**
- *Base domain* matching (the default) fills on any subdomain. A subdomain takeover on the real site (for example, a dangling CNAME) receives autofill. Users can choose *Host* mode.
- Old clients carry an old PSL and an old list. A suffix added to the PSL later (a new shared-hosting platform) is treated as one registrable domain by those clients, so different tenants on that platform match each other. The `psl` crate republishes when the list changes; we ship updates in every release, and nothing protects clients that never update ([AR-15](#9-accepted-risks-and-out-of-scope)).
- Users who type their master password into a convincing fake vault page.

### A7. Malicious web page scripts against the extension

**Capabilities.** JavaScript on any page the user visits, including legitimate sites that host third-party scripts. It can do the following:
- Build fake and invisible forms, and fields positioned off-screen or with zero opacity.
- Change the DOM between the user's click and the fill.
- Overlay or clickjack the extension's inline UI. DOM-based clickjacking of PM extensions was shown at DEF CON 33: 10 of 11 extensions were affected (secondary sources).
- Send messages to content scripts, and draw a fake extension UI that asks for the master password.
- Read any value once it is filled. That is inherent: after a fill on the right origin, the page owns the value ([NG-12](#14-non-goals)).

**What they obtain.** Credentials filled into hidden fields or the wrong frame; data leaked through a buggy content-script-to-background channel; the master password typed into a fake UI.

**Mitigations** ([INV-36](#8-security-invariants), [INV-37](#8-security-invariants), [INV-40](#8-security-invariants)):
- Content scripts run in isolated worlds.
- UI that can trigger a fill is rendered in an extension-origin iframe or popup, not in the page DOM.
- Before filling, the extension checks that the target field and the UI are visible and topmost (for example with IntersectionObserver v2 where the browser supports it).
- Only visible fields in the top frame or same-origin frames are filled.
- The content script receives only the values for the fill the user chose.
- The background treats every message as untrusted input and takes the origin from the browser's sender information, never from the message.
- The master password and Secret Key are never requested in page-injected UI; unlock happens only in the toolbar popup or an extension page.
- No `externally_connectable` for web origins. Not even the web vault gets it, because a malicious server controls the web vault's origin.
- MV3 forbids remotely hosted code.

**Passkey provider (M7).** [ROADMAP §4.10](ROADMAP.md#410-mobile--passkeys-m7) makes "passkey storage … and use in extension" a Must. To act as a WebAuthn provider, the extension intercepts `navigator.credentials` in the page's main world, where page script controls everything, including the arguments and any data it passes along. If the extension takes the RP ID or the origin from that data, `evil.example` can ask for an assertion with `rpId: "bank.com"` and relay it to the real bank. That removes the phishing resistance that is the whole point of passkeys. Mitigation ([INV-64](#8-security-invariants)):
- The origin comes from the browser's sender information, never from page-supplied data, and must be HTTPS.
- The requested `rpId` must equal the origin's host or be a registrable-domain suffix of it, checked against the PSL, and is never a public suffix.
- `clientDataJSON` `origin`, `crossOrigin` and `topOrigin` are set from that verified origin.
- Cross-origin iframes are refused by default, as for password fills.
- Mobile providers take the caller from the OS's calling-app verification, the passkey analogue of [INV-41](#8-security-invariants).

**Key custody in the extension (M2).** Under MV3 the service worker is terminated when idle. "Session only" key storage ([ADR 0013](adr/0013-shared-client-core.md) §2) then either re-locks constantly or tempts an implementer to persist keys to `storage.local` or IndexedDB. Content scripts can read `chrome.storage.local` by default. [INV-63](#8-security-invariants) keeps unlocked keys in memory only.

**Residual risk.** New clickjacking and overlay techniques will keep appearing. The M8 audit and the bug bounty include the extension.

### A8. Stolen or lost device

This includes a copy of the device's storage taken from a backup.

**Capabilities.** Physical possession of a powered-off, locked or unlocked device. **Or** a copy of its storage from an OS or cloud backup: iCloud Backup and Android Auto Backup include app data by default, and Time Machine, File History and home-directory backups pick up the CLI's state file. The backup route needs no physical access: a compromised cloud account, the backup provider, or a lost backup disk is enough.

**What they obtain.**
- **Powered off or screen-locked with full-disk encryption:** they first have to break the OS.
- **Access to the file system (no FDE, FDE already unlocked, or a backup copy):**
  - The encrypted local cache.
  - The Secret Key. The device state file holds it in plaintext until an OS keystore does ([CRYPTO.md §4.2](CRYPTO.md#42-key-inventory)); the CLI may keep it in a 0600 file indefinitely ([ADR 0013](adr/0013-shared-client-core.md) §2).
  - Session tokens.
  - The local unlock wrap. Offline unlock ([ROADMAP §4.2](ROADMAP.md#42-core-vault-m1), "offline read access") needs a locally stored wrap of the account key that opens without the server. Anyone holding the device's storage can guess against that wrap at one Argon2id evaluation per guess ([CRYPTO.md §5.5](CRYPTO.md#55-offline-attack-analysis)). The only exception is when the wrap also depends on a key held in a hardware-backed keystore. The A1 cost table applies. The Secret Key sits next to `E_local`, so 2SKD does not help here.
  - **The browser extension** has no OS keystore at all. Its SK, `E_local` and `E_dev` live in the browser profile on disk.
- **With the OS login, or the device passcode:** the keystore-held local unlock secret ([AST-22](#2-assets)) if the keystore releases it on that credential. That skips Argon2id entirely. [INV-62](#8-security-invariants) demands an OS-enforced user-presence check, preferably biometry bound to hardware. A keystore policy that falls back to the device passcode makes the passcode a vault unlock factor, and the setting must say so.
- **Vault unlocked:** everything ([NG-1](#14-non-goals)).

**Mitigations.**
- The local wrap uses the same Argon2id floor ([INV-3](#8-security-invariants)).
- The local wrap is bound to a hardware-backed key where the platform has one (iOS/macOS Secure Enclave, Android StrongBox/TEE, Windows TPM). Guessing then needs the device's secure element, and that element enforces its own rate limits. A backup copy is then useless.
- Device state and the cache are excluded from OS and cloud backups ([INV-61](#8-security-invariants)). The price: a phone or laptop restored from backup comes back without the vault. In Server mode it logs in again. In On-device mode the M4 encrypted backup file is the backup path, not the OS backup.
- Keystore unlock only behind OS-enforced user presence, invalidated when biometric enrolment changes ([INV-62](#8-security-invariants)).
- Auto-lock timeouts.
- Device revocation (M3) and short-lived, device-bound tokens.
- Revocation rotates the account key and the vault keys, and for a lost or stolen device also the identity keys ([INV-30](#8-security-invariants), [CRYPTO.md §11.8](CRYPTO.md#118-device-revocation)).

**Residual risk.**
- Revocation cannot pull back data already cached on the device. Key rotation protects only data written later. For items that matter, the user has to change the site passwords.
- **The rotation race.** A thief who has unlocked the stolen device holds the account key and the identity signing key. Until the remaining devices publish the rotation, the thief can sign device certificates and `account-state` of their own, and race the owner's rotation. Remaining devices accept a rotation only from a non-revoked device and ask the user to confirm the new identity fingerprint on each device ([CRYPTO.md §11.6](CRYPTO.md#116-key-rotation), "Known limitation"). The M4 device-management ADR settles the rest ([AR-18](#9-accepted-risks-and-out-of-scope)).
- The CLI, the browser extension and desktop Linux have no hardware binding ([AR-14](#9-accepted-risks-and-out-of-scope)). The CLI cannot keep its state file out of the user's backups; its docs say so.
- In On-device mode, losing the last device loses the vault ([AR-13](#9-accepted-risks-and-out-of-scope)).

### A9. Supply chain

**Capabilities.** Publishes a malicious version of a dependency or takes over a maintainer account. Vectors:
- A typosquatted crate or npm package.
- Code that runs at build time: `build.rs` scripts, proc macros, npm install scripts.
- A third-party GitHub Action whose tag moves.
- A container base image.
- The Rust toolchain download.

**What they obtain.** Code execution in CI, on developer machines, in the server or inside a client. npm code bundled into the extension or the web vault runs in the same context as decrypted vault data. **The JS dependency tree is therefore as security-critical as the crypto crates.**

**Mitigations.**
- Already in place:
  - A committed `Cargo.lock` and `--locked` builds.
  - `cargo deny check` in CI: RustSec advisories are errors, yanked crates are errors, licenses come from an allow-list, openssl is banned, and only crates.io is an allowed source ([`deny.toml`](../deny.toml)).
  - Weekly Dependabot PRs, which are reviewed and never auto-merged.
  - A pinned toolchain (1.94.1).
- Crypto and core dependencies:
  - A small, reviewed dependency set in `rizzy-core` and `rizzy-sync` ([ADR 0009](adr/0009-crypto-dependency-policy.md), [ADR 0016](adr/0016-workspace-layout.md)), preferring RustCrypto and dalek crates.
  - Any new crypto dependency needs an ADR.
- JS:
  - One package manager, a committed lockfile, install scripts disabled, exact versions, and as few dependencies as possible in the extension.
  - The extension is built in CI, never on a laptop.
- Containers and Actions:
  - Base images pinned by digest and rebuilt on advisories.
  - Third-party Actions pinned by commit SHA. Today they are pinned by tag; see [Q-9](#10-open-questions-for-the-owner).

**Residual risk.** A popular crate or npm package going malicious between two reviews. cargo-vet or a similar audit trail would reduce this ([Q-9](#10-open-questions-for-the-owner)).

### A10. Compromised CI or release credentials

**Capabilities.** Controls a maintainer's GitHub account, CI secrets, the container registry, a store developer account, the desktop updater key or the equivalence-list key.

**What they obtain.** A malicious update delivered to every user of that channel. For the extension and mobile apps, updates install automatically, so most users are hit within days. That is NG-1 for all of them. With the equivalence-list key, they can push a signed malicious equivalence entry.

**Mitigations.**
- Hardware-key 2FA on every account in [AST-16](#2-assets).
- Branch protection with required review. Release builds run only from protected tags in a protected CI environment that PR workflows cannot reach.
- CI already sets `permissions: contents: read` and `persist-credentials: false`.
- PR workflows get no secrets, and `pull_request_target` is never used.
- The equivalence-list key is separate from the release keys ([Q-10](#10-open-questions-for-the-owner)).
- From M8: signed images (cosign), SBOM and provenance ([ROADMAP §4.9](ROADMAP.md#49-server-self-hosting--ops-m1-onward)), plus reproducible builds (Could) so third parties can check releases.

**Server auto-updates.** [ROADMAP §4.9](ROADMAP.md#49-server-self-hosting--ops-m1-onward) promises Podman Quadlet units with `podman auto-update` (Should, M3). That follows an image *tag*, while [§7.17](#717-distribution-channels-m1-onward) tells operators to pin image digests. The two conflict. Before M8 nothing verifies image signatures, so a compromised registry account or release job reaches every auto-updating instance on its next timer run. Each such instance then serves a backdoored web vault to all of its users ([§4.2.1](#421-the-web-vault-delivery-problem)). The same applies to any tag-following updater, such as Watchtower. Owner decision: [Q-17](#10-open-questions-for-the-owner).

**Residual risk.** With one maintainer, one compromised person means a compromised project ([AR-12](#9-accepted-risks-and-out-of-scope)). Stores can also delay or block an urgent security fix. Tag-following server updates before M8, if the owner allows them ([AR-22](#9-accepted-risks-and-out-of-scope)).

### A11. Malicious email senders (M6)

**Capabilities.** Anyone on the internet can reach port 25 and send arbitrary SMTP and MIME:
- malformed or deeply nested multipart messages;
- huge headers and odd encodings;
- compression bombs in attachments;
- HTML and CSS payloads, tracking pixels and phishing links;
- fake "verification codes";
- RCPT probing for aliases;
- floods.

**What they obtain.**
- Remote code execution in the `smtp` role or in rspamd. In profile A that means the whole server. In profile B the attacker reads all later incoming mail and can inject mail with forged authentication results, but cannot reach the DB.
- DoS.
- XSS in the mailbox UI. Rendered on the web-vault origin without a sandbox, that is full vault compromise.
- Read receipts through remote content.
- Confirmation that an alias is active. An active alias accepts RCPT; an unknown or disabled one is rejected. Uniform rejections ([INV-47](#8-security-invariants)) hide *disabled* versus *unknown*, but nothing hides *active* versus *non-existent*. [ROADMAP §4.8](ROADMAP.md#48-aliases--email-receiving-m6) asks both for "no SMTP user enumeration" and for rejecting disabled aliases at SMTP time; the two cannot both hold ([Q-18](#10-open-questions-for-the-owner)).

**Mitigations.** Covered in [§6](#6-email-ingress-m6). In short: mail-parser (safe Rust; the project claims fuzzing and MIRI testing), our own fuzzing ([ROADMAP §4.1](ROADMAP.md#41-foundations--project-hygiene-m0)), size, depth and time limits, profile B isolation ([INV-44](#8-security-invariants)), sandboxed HTML rendering with remote content blocked ([INV-35](#8-security-invariants)), and uniform RCPT responses ([INV-47](#8-security-invariants)). Against probing, the real control is that a generated alias cannot be guessed: at least 64 bits from the CSPRNG in every generated local part, where names and words do not count, plus per-IP RCPT rate limits and tarpitting ([INV-65](#8-security-invariants)). "Random name" aliases in the style `firstname.lastname99` are guessable and do not meet that bar.

**Residual risk.** rspamd is C code parsing hostile input. It runs in its own container with no secrets and no DB access, and that containment is all we get. User-chosen aliases, and active aliases in general, can be confirmed by probing ([AR-20](#9-accepted-risks-and-out-of-scope)).

### A12. Share-link leakage (M5)

**Capabilities.** Gets the full share URL, fragment included, from any of these:
- chat or email logs and their server-side search indexes;
- link-preview bots and mail-security scanners that open links (some run JavaScript);
- the recipient's browser history and synced history;
- screenshots;
- a `Referer` header, if a page on our origin loads a third-party resource.

Separately, a malicious server can serve share-page code that reads the fragment ([§4.2.1](#421-the-web-vault-delivery-problem)).

**What they obtain.** The shared snapshot, until it expires, is revoked, or reaches its view limit. After a recipient has seen the plaintext, nothing can take it back.

**Mitigations** ([INV-32](#8-security-invariants) to [INV-35](#8-security-invariants)):
- The share key is at least 256 bits, generated on the client, and lives only in the fragment.
- The share ID is at least 128 random bits, so shares cannot be enumerated.
- The page fetches the ciphertext and counts a view only after an explicit "Reveal" click, so scanners do not burn views.
- `Referrer-Policy: no-referrer` and no third-party resources.
- Short default expiry. The worker deletes expired shares even if nobody visits.
- Optional passphrase (Should). The access token is derived from the share secret *and* the passphrase, so the server releases the ciphertext only to a request that already knows the passphrase. Guessing is therefore online-only, and 10 failed attempts burn the share ([CRYPTO.md §11.11](CRYPTO.md#1111-public-share-link-opening-m5)). A link holder gets at most 10 guesses. An honest server enforces the burn; a malicious server holds the ciphertext but not the share secret, unless it serves page code that reads the fragment ([AR-1](#9-accepted-risks-and-out-of-scope)).
- **Only callers who hold the fragment can burn a share.** The share ID sits in the URL path, which proxy logs show ([§7.7](#77-web-role-m1)). A request must carry a link token derived from the share secret; with a wrong link token the server answers "not found", rate-limits the caller, and does not count the failure toward the burn ([CRYPTO.md §11.11](CRYPTO.md#1111-public-share-link-opening-m5), [Q-20](#10-open-questions-for-the-owner)). A holder of the full link can still burn the share on purpose ([AR-23](#9-accepted-risks-and-out-of-scope)).
- Email-restricted shares (Should) are checked by the server, so they are an honest-server control only.

**Residual risk.** The link stays usable in every log until the share expires. The page code is served by the server ([AR-1](#9-accepted-risks-and-out-of-scope), [AR-7](#9-accepted-risks-and-out-of-scope)).

### A13. Relay operator in On-device mode (M4)

**Capabilities.** It is an A2 server restricted to relaying, because it holds no snapshot. It can:
- see metadata: device count, IPs, relay batch sizes and times, ack patterns;
- drop, delay, reorder, replay or withhold ops;
- purge ops before every device has acked them;
- show different devices different histories (fork);
- inject device entries;
- MITM pairing traffic;
- keep data it claims to have deleted after a mode switch, and sign a receipt saying it deleted it.

**What they obtain.**
- Metadata.
- Availability: it can stop sync or make a device go stale.
- Nothing readable, if the invariants hold. Forged ops fail signature checks. Replays are idempotent. Reordering does not matter because merge is order-independent. Injected devices are not certified by the identity key. Pairing MITM fails the SAS.

**Mitigations.**
- Signed, AEAD-encrypted ops ([INV-22](#8-security-invariants)) with idempotent, order-independent merge ([INV-23](#8-security-invariants)).
- A gap-free sequence per device, so drops are detected ([INV-27](#8-security-invariants)).
- Device keys certified by the identity key ([INV-16](#8-security-invariants)), and SAS on pairing ([INV-29](#8-security-invariants)).
- A stale device re-syncs from a peer, never from the server ([ROADMAP §4.6](ROADMAP.md#46-sync-modes-m4)).
- Re-keying on a Server-to-On-device switch ([INV-31](#8-security-invariants)), so wraps the server kept stop covering new data.
- Padding and batching (Should).

**Residual risk.**
- Withholding a *suffix* of ops cannot be told apart from "no new edits" until devices compare state through another path.
- **The signed deletion receipt is a signed claim, not a proof.** It is useful as accountability evidence and nothing more. The ROADMAP's word "proves" should become "attests" ([AR-9](#9-accepted-risks-and-out-of-scope)).

### A14. Shoulder surfing, clipboard and screen capture

**Capabilities.** A person looking at the screen, other apps reading the clipboard, OS clipboard history and cross-device clipboard sync, screen recording, screenshots, app-switcher thumbnails, and screen sharing during calls. Input fields leak too:
- A browser's enhanced spell-check service can receive the contents of a revealed password field, once its `type` is switched to `text`.
- The browser's own password manager offers to save the web-vault master password into its synced store.
- Third-party mobile keyboards can learn and upload what is typed.

**What they obtain.** Whatever was shown, copied or typed.

**Mitigations.**
- Secrets are masked by default, revealed per field, and re-masked automatically.
- Large-type display requires an explicit action.
- The clipboard is cleared after a timeout, but only if it still holds our value.
- Copied secrets are marked sensitive or concealed wherever the OS supports it (Windows, macOS and Android have mechanisms; the exact APIs will be confirmed in M3 and M7).
- Screenshots are blocked and the app-switcher preview is hidden on mobile ([ROADMAP §4.10](ROADMAP.md#410-mobile--passkeys-m7)).
- On desktop, the window is excluded from screen capture where the OS allows it (Tauri support is unverified; to be checked in M3).
- The CLI copies to the clipboard by default instead of printing ([INV-56](#8-security-invariants)).
- Secret input fields set `spellcheck="false"` and `autocomplete` values that discourage browser saving, and a reveal does not turn spell-check back on. On mobile, secret fields use secure text entry and the keyboard's no-personalised-learning flag, and a revealed secret is shown read-only rather than in an editable field ([INV-68](#8-security-invariants)). Browsers may ignore `autocomplete` hints (U), so the web-vault copy also tells users not to let the browser save the master password.

**Residual risk.** Clipboard managers that ignore the sensitive flag, and cross-device clipboard sync ([AR-16](#9-accepted-risks-and-out-of-scope)).

### A15. Other users and the anonymous internet

**Capabilities.**
- Online password guessing: each OPAQUE login attempt tests one password.
- Registration spam and storage abuse.
- Account enumeration.
- IDOR attempts against other users' ciphertext, shares and device lists.
- Oversized requests.
- Brute-forcing share IDs.
- Guessing aliases to send spam.
- Using the `icons` role as an open proxy.

**Mitigations.**
- Exponential backoff per (account identifier, source IP), plus a per-account cap on the *rate* of unauthenticated attempts. Never a hard lockout. X-Forwarded-For is trusted only from configured proxies ([INV-7](#8-security-invariants)).
- **Rate limits must not become a lockout weapon.** The login name is printed on the Emergency Kit and is often an email address, so anyone who knows it can keep an account in backoff. In Server mode, password change, key rotation and device revocation all need a fresh OPAQUE re-authentication ([CRYPTO.md §11.5](CRYPTO.md#115-master-password-or-secret-key-change), [§11.6](CRYPTO.md#116-key-rotation), [§11.8](CRYPTO.md#118-device-revocation)). A shared per-account limit would let an attacker stop a victim from revoking a stolen device or rotating after a leak, exactly when it matters. OPAQUE attempts that arrive inside a device-authenticated session therefore use their own bucket, which unauthenticated floods cannot exhaust ([INV-7](#8-security-invariants)).
- Registration is rate-limited as well: RFC 9807 notes that registration is an enumeration oracle.
- Login for unknown accounts uses opaque-ke's dummy record, which is always created since 4.0.0 as a timing fix ([INV-7](#8-security-invariants)).
- Authorization tests for every endpoint and resource type.
- Per-account quotas and body-size limits.
- Share IDs of at least 128 bits; generated aliases with at least 64 random bits ([INV-65](#8-security-invariants)).
- The `icons` role starts from a domain name, but following `<link rel="icon">` targets and redirects leads to arbitrary URLs on arbitrary hosts. The address and port allow-list ([INV-51](#8-security-invariants)) is the control that matters. The role is rate-limited.
- The server does no Argon2 work, so an attacker gets no CPU amplification.

**Residual risk.** Registration reveals whether an identifier is taken. Invite-only signup ([ROADMAP §4.9](ROADMAP.md#49-server-self-hosting--ops-m1-onward), Should) removes that on private instances. A flood against a known login name still slows new-device logins and web-vault logins for that account; enrolled devices keep working.

### A16. Malicious import files and shared content

**Capabilities.** Gets the user to import a crafted file (KDBX/XML, 1PUX zip, CSV, Bitwarden JSON), or in M9 shares an item containing crafted field values.

**What they obtain.**
- Parser DoS: XML entity expansion, zip bombs, huge files.
- Memory-safety bugs. These are unlikely in safe Rust, but not impossible in dependencies.
- XSS if a field value reaches an HTML sink.
- A `javascript:` or `data:` URL behind an "open website" button.
- Spreadsheet formula injection when the user later opens a plaintext CSV export.

**Mitigations.**
- Parsers run in `rizzy-core` with no I/O, do not expand XML entities, parse zips in memory with size caps, and are fuzzed ([ROADMAP §4.1](ROADMAP.md#41-foundations--project-hygiene-m0), Should).
- Field values are always rendered as text ([INV-35](#8-security-invariants)).
- Only `http`/`https` URLs are opened or filled from item fields ([INV-42](#8-security-invariants)).
- The plaintext-export warning mentions formula injection. We do not rewrite values, because changing a password on export is worse.

**Residual risk.** Bugs in the parsers.

### A17. Vault member (M9)

**Capabilities.** A current or removed member of a shared vault ([ROADMAP §4.11](ROADMAP.md#411-families--enthusiasts-m9--wont-for-v10)). Every member holds the vault key and a valid device chain, whatever their role. A view-only member can therefore encrypt and sign well-formed ops for that vault. [CRYPTO.md §10.2](CRYPTO.md#102-ed25519-signatures-and-signed-statements) defines op signatures, which give *attribution*, but no signed membership or role statement, which would give *authorization*.

**What they obtain.**
- Edits a view-only role should forbid, if other members' clients accept every validly signed op from any member. "View / edit / manage" is then enforced only by an honest server.
- After removal: everything they ever decrypted, and whatever they copied.

**Mitigations.**
- Ops are signed by device keys that chain to the member's identity, so every edit is attributable.
- Clients accept an op only if a membership statement, signed by a vault manager and verified by the client, gives its author a role that allows it. The server's role check is a second layer ([INV-67](#8-security-invariants)). The statement format belongs to the M9 ADR.
- Removing a member rotates the vault key ([CRYPTO.md §4.2](CRYPTO.md#42-key-inventory)), so later data is closed to them.

**Residual risk.** A removed member keeps cached plaintext, the same as a revoked device ([A8](#a8-stolen-or-lost-device)).

---

## 5. Server-controlled parameter attacks

Two pieces of prior work set the bar here. Palant (2023) showed that Bitwarden clients accepted server-supplied PBKDF2 iteration counts as low as 5,000, and that the server-side iterations protected only the auth hash, not the encryption key. Scarlata, Torrisi, Backendal and Paterson (ePrint 2026/058, to appear at USENIX Security 2026) describe malicious-server attacks against Bitwarden, LastPass, Dashlane and 1Password in five classes: key escrow and recovery; unbound item-level encryption; unauthenticated public keys in sharing and orgs; backward-compatibility downgrades; and KDF parameter downgrades. Both are secondary-source summaries; see [§11](#11-references).

**Rule: the client decides security parameters.** The server stores and relays them. The client re-validates them against compiled-in policy and against account state authenticated under keys the server does not have.

### 5.1 KDF parameter downgrade

- **Attack.** The server hands out weaker Argon2id parameters at login, registration, password change, local-unlock setup or export. The goal is a weakly stretched record that is cheap to crack after a later dump.
- **Required client-side mitigations.**
  - Every KDF version has a floor compiled into `rizzy-core`. Parameters below it abort the flow before the password is processed ([INV-3](#8-security-invariants)).
  - Parameters for new registrations come from the client's own profile, not from the server.
  - opaque-ke is always called with an explicit KSF. With `ksf: None` it silently falls back to the suite's `Default` KSF; for opaque-ke's own Argon2 KSF that is m=19 MiB, t=2, p=1, and ours is a sentinel that refuses to run ([CRYPTO.md §5.1](CRYPTO.md#51-ciphersuite-and-key-stretching), [INV-4](#8-security-invariants)).
  - The KDF version and parameters are bound into the OPAQUE context and into the AAD of password-derived wraps ([INV-5](#8-security-invariants)).
  - Every path from the password to a key or an authenticator passes through a full Argon2id evaluation at an allowed `kdf_id`. On the server path one run feeds both OPAQUE authentication and `E_srv`. There is no cheaper side path ([INV-6](#8-security-invariants)).
  - Raising parameters is allowed. Lowering them below the floor is impossible without a new client release.
- **Milestone.** M1. **ETH class:** 5.

### 5.2 Envelope and algorithm downgrade

- **Attack.** The server returns ciphertext labelled with an older or weaker envelope version, algorithm ID or key ID, or strips the version to trigger a legacy path.
- **Required client-side mitigations.**
  - The whole envelope header is authenticated as AAD ([INV-9](#8-security-invariants)).
  - Clients decrypt only versions and algorithms on a compiled-in allow-list. There is no fallback path and no legacy path ([INV-10](#8-security-invariants), [ADR 0007](adr/0007-ciphertext-envelope.md)).
  - Clients always write the current version.
  - Deprecating a version means removing it from the allow-list in a client release, after a migration.
  - We start without legacy formats ([ADR 0002](adr/0002-own-protocol.md)). Importers read legacy formats locally and one way only, so they are not a downgrade path.
  - AEAD is key-committing ([INV-11](#8-security-invariants)), which closes the partitioning-oracle class (Len, Grubbs, Ristenpart 2021).
- **Milestone.** M1. **ETH class:** 4.

### 5.3 Unbound items and settings

- **Attack.** The server swaps ciphertext between items or vaults, replays an old item version, drops fields, or replaces settings stored as separate objects (KDF parameters, sync mode, device list). Or it serves an **older, validly encrypted settings object**. Every earlier `ACCOUNT_SETTINGS` envelope still opens under the same account key, so without a freshness check the server can:
  - bring back an equivalence group the user deleted (a phishing fill, [CRYPTO.md §8.4](CRYPTO.md#84-aad-and-purposes));
  - revert a per-URI match mode from *Host* to *Base domain*;
  - drop a contact pin, so that in M9 an attacker key gets pinned as a "first contact".
- **Required client-side mitigations.**
  - Item AAD binds vault ID, item ID, schema version and the op or snapshot identity and version ([INV-13](#8-security-invariants)). It deliberately carries no account ID, because M9 vaults are shared between accounts. A move into another account fails through the different vault ID and vault key.
  - Security-relevant settings live in the signed `account-state` or in `ACCOUNT_SETTINGS`, encrypted under the account key. The client ignores server values that are not in them ([INV-14](#8-security-invariants)).
  - **Settings are fresh, not just authentic.** `account-state` commits to `settings_seq` and to the SHA-256 of the current `ACCOUNT_SETTINGS` envelope, and every settings change publishes a new `account-state`. Clients keep the highest `settings_seq` they have accepted and reject anything lower ([INV-25](#8-security-invariants)). [CRYPTO.md §10.2](CRYPTO.md#102-ed25519-signatures-and-signed-statements) carries both fields in `account-state`.
- **Milestone.** M1. **ETH class:** 2.

### 5.4 Public-key substitution

- **Where it bites.**
  - M4: device pairing and any "approve this device" flow. A relayed public key is the classic MITM point. AliasVault's "Login with Mobile" relays an RSA public key through its server.
  - M5: nowhere for link shares, because they use fragment keys.
  - M6: the mail encryption key. Substituting it gains a fully malicious server nothing, since it reads mail at ingress anyway. An attacker who controls only `api` or the DB would gain the mail, which is why `smtp` pins each account's identity key ([CRYPTO.md §11.13](CRYPTO.md#1113-mail-ingress-m6)).
  - M9: shared-vault and family keys.
  - M10: org keys and the org recovery key.
- **Attack.** The server returns its own public key in place of the recipient's, so the client wraps a vault key or account key to the attacker.
- **Required client-side mitigations.**
  - Each user has an Ed25519 identity key. The X25519 encryption key and every device key are signed by it ([INV-16](#8-security-invariants)).
  - Other users' identity keys are pinned on first use and have fingerprints the user can verify out of band. A changed pinned key blocks key wrapping until the user re-verifies ([INV-17](#8-security-invariants)).
  - Device-to-device transfers need SAS confirmation ([INV-29](#8-security-invariants)).
  - Key transparency (Proton publishes one design) is a post-1.0 candidate ([Q-8](#10-open-questions-for-the-owner)).
- **Residual risk.** A server that substitutes keys on *first* contact beats users who never verify fingerprints (TOFU, [AR-6](#9-accepted-risks-and-out-of-scope)). 1Password's white paper states the same limitation for its own design (secondary source).
- **Milestone.** M1 for key generation and signing; M4 for SAS; M9 for pinning and verification UX. **ETH class:** 3.

### 5.5 Forged device registrations

- **Attack.** The server adds a device entry so other devices encrypt new vault keys to it during revocation or rotation, pairing, or op fan-out. It can also hide a device (the thief's) from the device list.
- **Required client-side mitigations.**
  - Clients accept a device key only when the account identity key certifies it. Only a device holding the unlocked account key can issue that certificate ([INV-16](#8-security-invariants)).
  - The device set is part of the signed `account-state` ([INV-14](#8-security-invariants)), so hiding a device means rolling that state back. That is caught by [INV-25](#8-security-invariants) on any device that has seen the newer state.
  - Other devices notify the user of new enrollments.
  - After a full rotation, clients reject certificates and state signed only by the superseded identity key ([INV-30](#8-security-invariants)).
- **Residual risk.**
  - An attacker who holds the password and Secret Key, or an unlocked device, can enroll a real device. We can only make that visible.
  - A compromised device that is then revoked still holds the old identity key, and can sign certificates or state before the rotation reaches the other devices. It can race its own rotation ([A8](#a8-stolen-or-lost-device), [AR-18](#9-accepted-risks-and-out-of-scope)).
- **Milestone.** M3 (device list, Should), M4 (relay fan-out, Must).

### 5.6 Rollback, withholding and forks

- **Attack.** The server serves an older vault state: before a password change, before a deletion, before a revocation. It restores an old backup for everyone, withholds recent ops, or shows two devices different histories.
- **Required client-side mitigations.**
  - Clients persist the highest version vector they have accepted per item, the last verified `account-state` and the highest `settings_seq`. They reject and report any response that moves backwards ([INV-25](#8-security-invariants)).
  - Ops are signed and carry a gap-free sequence per device, checked from M1 in Server mode ([INV-22](#8-security-invariants), [INV-27](#8-security-invariants)). The server cannot drop a middle op, such as a delete or a password update, while serving later ones.
  - When a server is restored from an old backup, clients that hold newer ops re-upload them ([ADR 0012](adr/0012-sync-engine.md)), together with their latest signed state and revocations. A restore brings back more than old ops; [§5.8](#58-server-restore-from-backup) covers the rest.
  - Server-side compaction discards only ops covered by a snapshot a client produced and signed ([INV-26](#8-security-invariants)).
  - Should: a "vault state fingerprint" shown on each device (a short hash of the signed head) that the user can compare across devices to detect a fork.
- **Residual risk.**
  - A brand-new device has no earlier state to compare against.
  - A fork is invisible until the devices exchange heads through another path.
  - Withholding a suffix looks the same as silence ([AR-5](#9-accepted-risks-and-out-of-scope)).
- **Milestone.** M1 (Server mode), M4 (relay).

### 5.7 Escrow, recovery and org-invite abuse (M9/M10)

- **Attack.** The server invents a recovery requirement ("your org requires recovery enrollment") and supplies an attacker's org key. Or it abuses invite acceptance to take over a vault. The ETH paper reports that Bitwarden's org-invite acceptance allowed exactly this (secondary source).
- **Required client-side mitigations.**
  - There is no escrow before M10 ([INV-18](#8-security-invariants)).
  - Recovery enrollment is always a client action after an explicit user decision. It wraps only to an org recovery key that is authenticated like a user key ([INV-17](#8-security-invariants)), and the user can see that it is on.
  - Invite acceptance never sends key material to a key the user has not authenticated.
  - Emergency access (M9) uses the same rules plus the waiting period.
- **Milestone.** M9/M10. The M1 data model must already carry signed identity keys ([ROADMAP §6.7](ROADMAP.md#6-risks--hard-truths)). **ETH class:** 1 and 3.

### 5.8 Server restore from backup

This one needs no malicious server. Honest operators restore backups after disk failures and botched migrations, and [ROADMAP §4.9](ROADMAP.md#49-server-self-hosting--ops-m1-onward) and M8 require restore drills.

- **What a restore brings back.** The DB returns to an earlier state for every account at once. Lost ops are the easy part: [ADR 0011](adr/0011-storage.md) and [ADR 0012](adr/0012-sync-engine.md) heal them by re-upload. A restore also brings back:
  - **Revoked devices.** The revocation records are gone, so the server again accepts device authentication from a revoked device. A thief who cracked that device's `E_local` offline ([A8](#a8-stolen-or-lost-device)) gets a working session back.
  - **Superseded OPAQUE records and `E_srv`.** If the password was changed because it leaked, and the account key was not rotated, the old password plus the SK logs in again, and the old `E_srv` yields the current account key.
  - **Superseded `H_rec` and `E_rec`.** A kit the user replaced because it was stolen works again once the waiting period passes.
  - **An old signed state for new devices,** which they accept ([AR-5](#9-accepted-risks-and-out-of-scope)).
- Existing devices detect the rollback ([INV-25](#8-security-invariants)). Detection on the client does not stop the server from honouring stale credentials.
- **Required mitigations** ([INV-59](#8-security-invariants)):
  - `rizzy-vault restore` puts every restored account into a **reconciliation epoch**, and prints what that means.
  - A device that reconnects re-uploads its latest signed `account-state`, its bundle chain and every `device-revocation` it holds, alongside the ops and snapshots ADR 0012 already re-uploads.
  - The server verifies them against the account's identity key and adopts the newest valid state. From then on it refuses OPAQUE logins, recovery requests and device authentication whose `password_epoch` or `recovery_epoch` is older than that state, or whose device that state revokes.
  - The honest user's current OPAQUE record and, if the recovery code was rotated, the current `E_rec` were lost in the restore. An enrolled device re-registers OPAQUE the next time the user types the password, as in [CRYPTO.md §5.8](CRYPTO.md#58-loss-or-rotation-of-the-server-opaque-secrets). Recovery stays refused until a device issues a new recovery code and kit.
- **Residual risk.** Until some device presents the newer state, a restore reopens old passwords, old kits and revoked devices. Accounts whose devices never reconnect stay exposed. The restore docs say so and tell the operator to ask users to open a device after a restore ([AR-19](#9-accepted-risks-and-out-of-scope)). A malicious server ignores all of this ([A2](#a2-active-malicious-or-compromised-server)).
- **Milestone.** M1 (restore command, Must). The M1 restore drill and the M8 drills cover a revoked device and a rotated recovery code.

### 5.9 Summary

| Attack | ETH class | Client-side mitigation | Invariants | From |
|---|---|---|---|---|
| KDF parameter downgrade | 5 | Compiled-in floor, explicit KSF, params bound into context and AAD, no path cheaper than one Argon2id | INV-3 to INV-6 | M1 |
| Envelope/algorithm downgrade | 4 | Header in AAD, allow-list, no legacy paths, key commitment | INV-9 to INV-11 | M1 |
| Item/settings swap or stale settings | 2 | AAD binds IDs and version; signed state and encrypted settings; settings committed in the signed state | INV-13, INV-14, INV-25 | M1 |
| Public-key substitution | 3 | Signed keys, pinning, fingerprints, SAS | INV-16, INV-17, INV-29 | M1 / M4 / M9 |
| Forged device registration | 3 | Identity-key certificates, signed device set, notifications, old identity key rejected after rotation | INV-14, INV-16, INV-30 | M3 / M4 |
| Rollback / withholding / fork | – | Monotonic checks, signed ops, sequences, client-made snapshots | INV-22, INV-25 to INV-27 | M1 / M4 |
| Restore reopens old credentials | – | Reconciliation epoch; server refuses credentials older than the newest signed state | INV-59 | M1 |
| Escrow and invite abuse | 1, 3 | No escrow; consented, authenticated, visible enrollment | INV-17, INV-18 | M9 / M10 |
| Member edits beyond role | – | Client-checked signed membership roles | INV-67 | M9 |

---

## 6. Email ingress (M6)

The mail subsystem is optional ([ROADMAP §2](ROADMAP.md#2-guiding-principles-non-negotiable), principle 5). The vault works fully with it disabled ([INV-43](#8-security-invariants)).

### 6.1 What happens, in order

1. A sending MTA connects to port 25. STARTTLS is used only if the sender chooses it.
2. `smtp` checks the recipient alias through `api`'s `resolve` call, which returns the alias ID and the account's key bundle with the chain since the `bundle_seq` `smtp` last pinned, or a rejection ([ADR 0010](adr/0010-server-shape.md) §2). `smtp` accepts the bundle only if it chains from its pin ([CRYPTO.md §11.13](CRYPTO.md#1113-mail-ingress-m6)). Unknown and disabled aliases get the same rejection, down to the same code path ([INV-47](#8-security-invariants)). Active aliases are accepted, so an RCPT probe still tells an active alias from a non-existent one. Alias entropy and RCPT rate limits are the control ([INV-65](#8-security-invariants), [Q-18](#10-open-questions-for-the-owner)).
3. `smtp` receives the message into memory, within size and time limits.
4. `smtp` sends the **plaintext** message to rspamd over local HTTP for spam scoring. It also verifies SPF, DKIM and DMARC (for example with mail-auth).
5. `smtp` builds a record containing the raw message, the headers and the authentication results. It encrypts the record to the alias owner's public key (HPKE, [ADR 0006](adr/0006-key-hierarchy.md) and [CRYPTO.md](CRYPTO.md)), pads the size, and drops the plaintext.
6. `smtp` sends (alias ID, ciphertext, padded size) to `api`. `api` stores it; `notify` wakes the owner's devices with a signal that carries no content.

### 6.2 What the server sees, and for how long

- **Everything in the message**, in `smtp` memory and in rspamd, from step 3 to step 5. That includes sender, recipients, subject, body, attachments, and the password-reset links and OTPs that the alias exists to receive. The window is the time it takes to receive, scan and encrypt one message. We do not promise a number, and a malicious server can keep a copy anyway.
- Connection metadata: sending IP, HELO name, envelope sender, time, size.
- **What rspamd keeps depends on its configuration.** History, Bayes tokens and fuzzy hashes can hold data derived from the message. Which of these the stock configuration enables has not been verified. The M6 spike must check it, and the configuration we ship must disable anything that stores subjects, addresses or content.
- **Blocklist lookups** (RBL/URIBL), which rspamd supports, send sender IPs and the domains or URLs found in mail to third-party DNS blocklist operators. The docs must say this, and the operator decides.
- After step 5 the server keeps alias ID, received time and padded size ([INV-46](#8-security-invariants)). Sender, subject and authentication results stay inside the ciphertext.

### 6.3 What this means, stated plainly

- **The server operator, or anyone who has compromised `smtp`, can read every incoming alias mail.** "Encrypted at ingress" protects stored mail against later DB theft. It does not protect mail against the server. The mailbox UI and docs must say exactly that.
- **A compromised `smtp` can also map aliases to people.** Through `resolve` it can enumerate aliases, slowly because `api` rate-limits the call. The mail key is per account ([CRYPTO.md §4.2](CRYPTO.md#42-key-inventory)), so two aliases that return the same mail key belong to the same person, even if neither ever receives mail. That is the [AST-11](#2-assets) linkage ([AR-21](#9-accepted-risks-and-out-of-scope), [Q-19](#10-open-questions-for-the-owner)).
- Someone with the server can take over any account whose reset mail goes to an alias on that server. This is a reason to keep high-value accounts (bank, primary email) off aliases on instances you do not control.
- Anyone can encrypt to a public key, so the ciphertext does not prove where the mail came from. The SPF, DKIM and DMARC results shown in the UI are only as trustworthy as the `smtp` role that produced them.
- In On-device mode, stored mail stays on the server until every device acks it, the same relay rule as ops ([ROADMAP §4.6](ROADMAP.md#46-sync-modes-m4)).

### 6.4 Mitigations

- **Profile B is required when `smtp` is enabled** ([Q-5](#10-open-questions-for-the-owner)): its own container and network, no DB credentials, output only to `api` ([INV-44](#8-security-invariants)). rspamd runs in its own container with no secrets.
- Plaintext is never written to disk, logs or queues by rizzy-vault ([INV-45](#8-security-invariants)). Queueing happens after encryption.
- Core dumps are disabled at startup ([INV-60](#8-security-invariants)). Release builds use `panic = "abort"`, so a panic mid-ingress raises SIGABRT, and without this a core dump would write the plaintext message to disk. In a container, the kernel's `core_pattern` is host-global, so that dump lands on the *host*.
- Parser hardening: a safe-Rust MIME parser, continuous fuzzing, limits on size, MIME depth, part count, header size and line length, SMTP timeouts, and per-IP and per-alias rate limits.
- Alias probing: generated aliases carry at least 64 random bits in the local part; per-IP RCPT rate limits and tarpitting of repeated rejected recipients ([INV-65](#8-security-invariants)).
- Key substitution by `api` or the DB: `smtp` keeps a pin store on its own volume (identity key and highest `bundle_seq` per account) and seals only to a mail key whose bundle chains from the pin ([CRYPTO.md §11.13](CRYPTO.md#1113-mail-ingress-m6), [ADR 0010](adr/0010-server-shape.md) §4). First contact and a wiped pin store remain TOFU.
- Mail rendering: HTML is sanitized and rendered in a sandboxed iframe with no scripts and no same-origin access. Remote images and CSS fetches are blocked by default ([INV-35](#8-security-invariants)). Attachments are never opened automatically.
- OTP and link extraction (Should) runs on the client after decryption and shows the sender and authentication status next to the extracted value.
- Retention: auto-delete after N days, enforced by `worker`.
- Admin docs cover MX, SPF, MTA-STS, port 25 and rspamd privacy settings.

---

## 7. STRIDE per component

S = spoofing, T = tampering, R = repudiation, I = information disclosure, D = denial of service, E = elevation of privilege. "–" means no component-specific threat beyond what is listed elsewhere.

### 7.1 Web vault (M1)

| | Threat | Mitigation | Inv. |
|---|---|---|---|
| S | Look-alike domain serves a fake login and collects the password and Secret Key. The browser's own password manager offers to save the master password into its synced store. | 2SKD: the password alone does not log in from a new browser. The extension marks the configured server origin. UI copy: the Secret Key is never typed on an enrolled browser, and the browser should not save the master password. `autocomplete` hints that discourage saving. | INV-2, INV-68 |
| T | Server, proxy or anyone with a valid certificate serves modified JS/wasm. XSS through item fields, imports, shared items, icons or server-supplied strings. | [§4.2.1](#421-the-web-vault-delivery-problem). Strict CSP; framework auto-escaping; no raw-HTML sinks; Trusted Types where supported; sandboxed rendering of untrusted content. | INV-35, INV-42, INV-49 |
| R | "I didn't make that change." | Ops are signed by device keys, so the op log attributes every change to a device (not to a person). | INV-22 |
| I | Keys and plaintext sit in the JS heap, readable by XSS and by other extensions with page access. A remembered Secret Key sits in IndexedDB, where server-served JS reads it at any page load; nothing else is persisted ([CRYPTO.md §11.4](CRYPTO.md#114-web-vault)). Enhanced spell-check services receive a revealed password. | Lock clears decrypted state. Auto-lock. SK persistence is opt-in, default off, with copy that says the server can read it ([Q-21](#10-open-questions-for-the-owner)). `spellcheck="false"` on every secret field, kept on reveal. | NG-1, INV-68 |
| D | Browser storage is evicted; the server withholds data. | The web vault is not a durable device ([ROADMAP §4.6](ROADMAP.md#46-sync-modes-m4)); withholding is NG-4. | – |
| E | Any XSS on the vault origin gives full vault access. | The origin serves nothing else. Share content and mail are isolated ([Q-4](#10-open-questions-for-the-owner)). | INV-35 |

### 7.2 Browser extension (M2)

| | Threat | Mitigation | Inv. |
|---|---|---|---|
| S | A page draws a fake extension UI to phish the master password; a site or another extension impersonates ours over messaging. A page asks the passkey provider for an assertion with another site's RP ID (M7). | Unlock only in the popup or an extension page. No `externally_connectable` for web origins. Origin from browser sender info; RP ID checked against it and the PSL. | INV-40, INV-64 |
| T | Page scripts rearrange forms, add invisible fields, or mutate the DOM between click and fill. | Fill on a trusted gesture. Re-check origin, frame and visibility at fill time. Visible fields only. | INV-36, INV-37 |
| R | – | – | – |
| I | Clickjacking of inline UI; hidden-field harvesting; filling into cross-origin iframes; content script leaking data into the page. MV3 worker termination tempts persisting unlocked keys to `storage.local` or IndexedDB, and content scripts can read `storage.local`. | Extension-origin UI; visibility and topmost checks; only the chosen values go to the content script. Unlocked keys in memory only. | INV-37, INV-40, INV-63 |
| D | Hostile pages flood the content script with DOM mutations. | Bounded work per page; matching runs in the background. | – |
| E | A bug in content-script-to-background messaging gives the page access to the vault; a malicious npm dependency or store update. | All messages treated as untrusted; origin taken from browser sender info. Minimal dependencies. MV3 bans remote code. Store accounts protected ([A10](#a10-compromised-ci-or-release-credentials)). | INV-40 |

### 7.3 Desktop app, Tauri (M3)

| | Threat | Mitigation | Inv. |
|---|---|---|---|
| S | Fake update feed; DNS hijack of the updater. | Updates are installed only with a valid signature from the pinned release key ([ADR 0015](adr/0015-desktop-tauri.md)). | INV-55 |
| T | Local malware patches the app or its web assets. | OS code signing and notarization where available; otherwise NG-2. | – |
| R | – | – | – |
| I | XSS in the webview calls IPC commands to pull every item. Keys reach swap or hibernation files: with `unsafe_code = forbid` there is no `mlock` in our crates. A crash dump of the unlocked process holds the account key. The biometric-unlock secret sits in the OS keystore ([AST-22](#2-assets)). | Keys stay in the Rust process. IPC commands return only what the current view needs; none exports keys. Tauri capability allow-list. Export requires re-entering the master password. Core dumps and crash-report upload disabled. Keystore unlock only behind OS-enforced user presence; none on Linux. | INV-21, INV-60, INV-62, AR-10 |
| D | – | – | – |
| E | Webview compromise escalates to the Rust side through IPC, custom URI schemes or deep links. | Treat IPC and deep-link input as untrusted; small command surface; CSP in the webview. | – |

### 7.4 Mobile apps (M7)

| | Threat | Mitigation | Inv. |
|---|---|---|---|
| S | A malicious app claims a web domain to receive autofill; accessibility-service autofill can be phished. A malicious app asks the passkey provider for another RP's assertion. | Web credentials are filled into apps only with verified Digital Asset Links or associated domains, or after an explicit warning. No accessibility fallback by default. The passkey provider takes the caller from the OS's calling-app verification. | INV-41, INV-64 |
| T | Rooted or jailbroken device. | NG-3. | – |
| R | – | – | – |
| I | Screenshots and app-switcher previews; push payloads visible to Apple and Google. The iOS AutoFill extension's memory cap (about 120 MB, secondary source) leaves little headroom for a 64 MiB Argon2id run there, so AutoFill unlocks through `E_ks` with a keychain-held unlock secret ([CRYPTO.md §6.4](CRYPTO.md#64-feasibility)). iCloud Backup and Android Auto Backup copy app data by default. Third-party keyboards learn typed text. | Screenshot blocking ([ROADMAP §4.10](ROADMAP.md#410-mobile--passkeys-m7)). Pushes carry no content. Keychain item gated by biometry, hardware-bound and invalidated on enrolment change ([Q-13](#10-open-questions-for-the-owner)). Device state excluded from backup, keychain items `ThisDeviceOnly`. Secure text entry and no-personalised-learning flags. | INV-54, INV-61, INV-62, INV-68 |
| D | The memory cap kills AutoFill mid-unlock. | Measure in M7 ([Q-13](#10-open-questions-for-the-owner)). | – |
| E | The app/extension shared container exposes keys to a compromised extension process. | Share only wrapped keys and the keychain reference, within one app group. | – |

### 7.5 CLI `rv` (M1)

| | Threat | Mitigation | Inv. |
|---|---|---|---|
| S | Wrong or impersonated server. | TLS through rustls. OPAQUE authenticates the server's registered static key at new-device login and re-authentication. Everyday device authentication adds nothing beyond TLS ([A4](#a4-network-attacker-mitm)); per-request signatures limit a relayed session ([Q-7](#10-open-questions-for-the-owner)). | INV-1 |
| T | – | – | – |
| R | – | – | – |
| I | Secrets in argv (`ps`, shell history), environment variables, terminal scrollback, piped logs. A session-token file readable by other users. Core dumps of the unlocked process. The state file (SK, `E_local`) in the user's home-directory backups. | Secrets come in only through a TTY prompt or stdin. Output goes to the clipboard by default. Token in the OS keyring or a 0600 file. Core dumps disabled at startup. No keystore unlock: the OS keyring does not enforce user presence. The docs tell users to keep the state file out of backups. | INV-56, INV-60, INV-61, INV-62 |
| D | – | – | – |
| E | – (runs as the user) | – | – |

### 7.6 `api` role (M1)

| | Threat | Mitigation | Inv. |
|---|---|---|---|
| S | Online password guessing; replay of stolen tokens; forged X-Forwarded-For to dodge rate limits. | Rate limits and backoff. Server-enforced 2FA (stops remote attackers, not the server). Short-lived, hashed tokens, optionally bound to the device key ([Q-7](#10-open-questions-for-the-owner)). XFF trusted only from configured proxies. | INV-7, INV-8 |
| T | Stored ciphertext, ops, keys or settings modified server-side. | Detected by clients ([§5](#5-server-controlled-parameter-attacks)). | INV-9 to INV-14, INV-22, INV-25 |
| R | Disputes over account events (logins, device enrollments, 2FA changes, share creation). | A security event log per account, without secrets, visible to the user. M10 adds org audit logs. | INV-48 |
| I | IDOR on another user's ciphertext, devices or shares; errors that leak internals; account enumeration. | Authorization check and test for every endpoint and resource type. Uniform errors. Dummy OPAQUE record. | INV-7 |
| D | Registration spam, op floods, oversized payloads, share spam, storage exhaustion. Login floods against a known login name (it is printed on the Emergency Kit) that lock the owner out of re-authentication, and so out of revocation and rotation. A panic in any role writes a core dump with in-memory secrets. | Quotas, body-size limits, invite-only signup option. The server runs no KDF, so there is no amplification. Backoff per (account, source), no hard lockout; device-authenticated re-auth has its own bucket. Core dumps disabled. | INV-7, INV-60 |
| E | Account-to-admin escalation; SQL injection. | Admin API on separate routes with separate credentials ([§7.19](#719-admin-panel-and-admin-api-m3)); sqlx bound parameters only. | INV-53, INV-69 |

### 7.7 `web` role (M1)

| | Threat | Mitigation | Inv. |
|---|---|---|---|
| S | – | – | – |
| T | Modified static files on disk; cache poisoning at a proxy or CDN. | Assets embedded in the binary and image; read-only rootfs; release bundle hashes published. | – |
| R | – | – | – |
| I | Share IDs and paths in logs; `Referer` leakage. | `Referrer-Policy: no-referrer`; no secrets in paths. | INV-33 |
| D | – | – | – |
| E | Path traversal in static serving; framing the vault (clickjacking). | Assets served from memory, with no filesystem path built from the request. `frame-ancestors 'none'`, HSTS, `nosniff`. | INV-49 |

### 7.8 `notify` role (M3)

| | Threat | Mitigation | Inv. |
|---|---|---|---|
| S | Unauthenticated subscriptions learn when an account syncs. | Subscriptions are authenticated; the token is never in the URL. | INV-52 |
| T | Fake "changed" signals. | Signals carry no data; clients sync and verify. | – |
| R | – | – | – |
| I | Device online presence; push metadata at APNs/FCM. | Signals and pushes carry no content. | INV-54 |
| D | Connection exhaustion. | Per-account connection caps. | – |
| E | – | – | – |

### 7.9 `worker` role (M1)

| | Threat | Mitigation | Inv. |
|---|---|---|---|
| S | – | – | – |
| T | A compaction bug corrupts history. | Compaction discards only ops covered by a snapshot a client produced and signed. | INV-26 |
| R | – | – | – |
| I | "Deleted" data survives in DB free pages, WAL files or backups. | SQLite secure-delete settings to be evaluated ([ADR 0011](adr/0011-storage.md)). Deletion from backups follows backup retention; the docs say so. | AR-11 |
| D | Purging too early (unacked relay ops) or too late (expired shares). Trash is not the worker's: clients purge it with signed `Purge` ops, because the server cannot see lifecycle ([ADR 0010](adr/0010-server-shape.md) §1). | Relay purge only after every active device has acked or the TTL has passed. Share expiry enforced even without visits. Purge rules have tests. | INV-34 |
| E | – | – | – |

### 7.10 `smtp` role and rspamd (M6)

| | Threat | Mitigation | Inv. |
|---|---|---|---|
| S | Forged sender addresses; alias enumeration through RCPT replies. | SPF/DKIM/DMARC results shown in the UI. Unknown and disabled aliases get identical replies; active aliases remain distinguishable, so generated aliases carry at least 64 random bits, and RCPT is rate-limited per IP and tarpitted. | INV-47, INV-65 |
| T | Malformed MIME aimed at the parser; a compromised `smtp` forging "DKIM pass". | Safe-Rust parser with fuzzing. Authentication results are only as trustworthy as `smtp`; the docs say so. | – |
| R | – | – | – |
| I | Plaintext during ingress; logs; rspamd retention; blocklist lookups; a core dump after a panic mid-ingress. A compromised `smtp` uses `resolve` to enumerate aliases slowly and to link aliases that return the same mail key. | [§6](#6-email-ingress-m6). Core dumps disabled. `resolve` rate-limited; the linkage is accepted for v1.0 ([Q-19](#10-open-questions-for-the-owner)). | INV-44, INV-45, INV-46, INV-60, AR-21 |
| D | Floods, huge or deeply nested messages, compression bombs, slow SMTP clients. | Size, depth and time limits; per-IP and per-alias limits; storage quotas; retention. | – |
| E | RCE in `smtp` or rspamd. Profile A: the whole server. Profile B: later mail plaintext and mail injection, but no DB. | Profile B required ([Q-5](#10-open-questions-for-the-owner)); no DB credentials. | INV-44 |

### 7.11 `icons` role (M3)

| | Threat | Mitigation | Inv. |
|---|---|---|---|
| S | DNS rebinding sends a public name to an internal address. | Check the resolved IP on every redirect and connect to exactly the IP that was checked, with no second resolution. | INV-51 |
| T | Cache poisoning serves malicious images to every user. | Re-encode to a raster format with size caps; never serve SVG. | INV-51 |
| R | – | – | – |
| I | Reveals which sites users have accounts on (requests, IPs, timing); exposes the server's IP to target sites. | Off by default ([Q-11](#10-open-questions-for-the-owner)). Unauthenticated shared cache. No per-user logs. | INV-51 |
| D | Slow or huge responses; decompression bombs. | Timeouts, byte caps, pixel caps. | – |
| E | SSRF into internal services (DB, admin and metrics listener, rspamd controller, cloud metadata at 169.254.169.254, overlay networks in 100.64.0.0/10, local listeners via 0.0.0.0) and into private addresses hidden in IPv4-mapped or NAT64 form; image decoder bugs. | Allow-list: globally routable unicast only, embedded IPv4 checked, ports 80 and 443 only. Own container, no DB credentials. Safe-Rust decoders. | INV-51 |

### 7.12 Database and backups (M1)

| | Threat | Mitigation | Inv. |
|---|---|---|---|
| S | – | – | – |
| T | Direct modification; restoring an old backup rolls back every account, and also brings back revoked devices, superseded OPAQUE records and `E_srv`, and superseded recovery wraps. | Clients detect the rollback ([§5.6](#56-rollback-withholding-and-forks)) and re-upload newer ops, signed state and revocations. The server then refuses credentials older than the newest signed state ([§5.8](#58-server-restore-from-backup)). | INV-25, INV-59 |
| R | – | – | – |
| I | [A1](#a1-passive-server-compromise-db-or-backup-theft). Off-site backup copies are often less protected than the server. A whole-host backup holds the DB *and* the server secrets; a backup of the data volume alone does not ([ADR 0010](adr/0010-server-shape.md) §4). | OPRF seed excluded from DB backups and mounted separately from the data volume by default. Backups hold only ciphertext and metadata. Operators should encrypt backups at rest. | INV-50 |
| D | Corruption or loss. | Backup and restore tested, not just written ([ROADMAP §4.9](ROADMAP.md#49-server-self-hosting--ops-m1-onward)). | – |
| E | SQL injection. | sqlx bound parameters only. | INV-53 |

### 7.13 Server secrets (M1)

| | Threat | Mitigation | Inv. |
|---|---|---|---|
| S | – | – | – |
| T | A replaced OPAQUE setup makes every login fail (DoS). It does not capture passwords. | Integrity check at startup; alert. | – |
| R | – | – | – |
| I | A leaked OPRF seed enables offline guessing against every account. | Stored outside the DB with restrictive permissions; never logged; excluded from DB backups. | INV-48, INV-50 |
| D | A lost OPRF seed means nobody can log in or unwrap the password wrap; users fall back to the recovery code or an existing device. | Backed up separately; the restore drill covers it. | INV-50 |
| E | – | – | – |

### 7.14 Reverse proxy / TLS terminator (M1)

| | Threat | Mitigation | Inv. |
|---|---|---|---|
| S | Forged X-Forwarded-For. | List of trusted proxies. | – |
| T | The terminator modifies responses: A2 powers against web-vault users. | [§4.2.1](#421-the-web-vault-delivery-problem). | – |
| R | – | – | – |
| I | Sees tokens, ciphertext, IPs and paths; access logs. | Tokens never in URLs; no secrets in paths; log-retention guidance. | INV-52 |
| D | – | – | – |
| E | Exposes internal endpoints (admin, metrics). | Admin and metrics on a separate listener, not proxied by default. | – |

### 7.15 Relay, On-device mode (M4)

| | Threat | Mitigation | Inv. |
|---|---|---|---|
| S | Injected devices; impersonation during pairing. | Identity-key certificates; SAS. | INV-16, INV-29 |
| T | Forged, dropped, reordered or replayed ops. | Signed ops; idempotent, order-independent merge; per-device sequences. | INV-22, INV-23, INV-27 |
| R | "We deleted your data" backed by a signed receipt. | The receipt is a signed claim, not proof. | AR-9 |
| I | Device count, IPs, relay batch sizes and times, ack patterns. | Padding and batching (Should). | NG-5 |
| D | Withholding; purging before ack; stranding stale devices. | Gap detection; TTL; re-sync from a peer. | INV-27 |
| E | – | – | – |

### 7.16 Share recipient page (M5)

| | Threat | Mitigation | Inv. |
|---|---|---|---|
| S | A look-alike page on an attacker's domain asks the recipient for credentials. | Our page never asks for credentials; the docs say so. | – |
| T | The server serves modified page code that reads the fragment. | None beyond [§4.2.1](#421-the-web-vault-delivery-problem). | AR-1 |
| R | View counts are reported by the server. | Honest-server control. | AR-9 |
| I | Fragment in history and synced history; previews; scanners; `Referer`; third-party resources. | Explicit reveal; no third-party resources; no-referrer; short expiry. | INV-32, INV-33 |
| D | Link scanners burn the view limit. A caller with only the share path (proxy logs, [§7.7](#77-web-role-m1)) sends bad tokens to burn the share. | A view counts only on explicit reveal. Only failures that carry a valid link token count toward the burn; a path-only caller gets "not found" and a rate limit ([CRYPTO.md §11.11](CRYPTO.md#1111-public-share-link-opening-m5), [Q-20](#10-open-questions-for-the-owner)). | INV-33, AR-23 |
| E | Share content runs script on the vault origin. | Text rendering; separate origin ([Q-4](#10-open-questions-for-the-owner)). | INV-35 |

### 7.17 Distribution channels (M1 onward)

| | Threat | Mitigation | Inv. |
|---|---|---|---|
| S | Look-alike extensions or apps in stores; unofficial container images. | Official channel list in the README and SECURITY.md; signed images (M8). | – |
| T | A compromised store or registry account pushes a malicious update; image tags moved. Tag-following server auto-update (`podman auto-update`, ROADMAP §4.9, Should, M3) installs it on every such instance before M8 adds signatures. | Hardware-key 2FA; deploy docs pin image digests; cosign verification (M8); reproducible builds (M8, Could). Digest pinning and `podman auto-update` conflict; owner decision [Q-17](#10-open-questions-for-the-owner). | AR-12, AR-22 |
| R | Nobody can tell which commit an artifact came from. | Provenance and SBOM (M8). | – |
| I | – | – | – |
| D | A store takedown or slow review blocks a security fix. | Document side-loading where a platform allows it. | – |
| E | An update widens permissions or adds code paths silently. | Release checklist: diff of permissions and manifest. | – |

### 7.18 CI (M0)

| | Threat | Mitigation | Inv. |
|---|---|---|---|
| S | Maintainer account takeover; forged commits. | Hardware-key 2FA; branch protection with required review; signed release tags. | – |
| T | A malicious PR edits workflows or build scripts; a third-party action changes under its tag. | `permissions: contents: read` and `persist-credentials: false` (in place). Fork PRs get no secrets. No `pull_request_target`. Pin actions by SHA ([Q-9](#10-open-questions-for-the-owner)). Release builds do not restore caches written by PR jobs. | – |
| R | – | GitHub audit log. | – |
| I | Secrets reachable from dependency build scripts. | No secrets in test jobs; release secrets only in a protected environment. | – |
| D | – | – | – |
| E | Dependency `build.rs` and proc macros run arbitrary code during build and test. | cargo-deny, lockfile, review of new dependencies, read-only token. | INV-57 |

### 7.19 Admin panel and admin API (M3)

The admin panel ([ROADMAP §4.9](ROADMAP.md#49-server-self-hosting--ops-m1-onward), Should, M3) lists and disables users, controls signup and sets instance policy, including the recovery waiting period. It binds a separate listener that the reverse proxy does not expose by default ([ADR 0010](adr/0010-server-shape.md) §1). A malicious admin is [A3](#a3-malicious-instance-admin); this table is about outsiders reaching admin powers.

| | Threat | Mitigation | Inv. |
|---|---|---|---|
| S | Theft of the first-run bootstrap token from logs, container output or a world-readable file; password-only admin login. | Bootstrap token stored in the secrets file (mode 0600), shown once, never logged. Admin credentials are separate from user accounts and need a second factor. | INV-48, INV-69 |
| T | CSRF against admin actions from a page the admin visits. Stored XSS through user-controlled strings (login names, device names, alias labels) rendered in the admin UI, which then acts with admin rights. | SameSite cookies plus a CSRF token on every state-changing request. Every user-controlled string rendered as text. The admin UI has its own strict CSP. | INV-69 |
| R | "Who disabled this user, or shortened the recovery wait?" | Every admin action goes into the affected users' security event log, without secrets. | INV-69 |
| I | The panel shows metadata: login names, device lists, storage use, last-seen times. | Show only what administration needs. No item metadata beyond counts and sizes ([§3.4](#34-what-the-server-holds-by-sync-mode)). | – |
| D | An attacker with admin access disables every user. | Same as the malicious admin: availability depends on the admin ([NG-4](#14-non-goals)). | – |
| E | Setting the recovery wait to 0. With physical access to a printed kit, for example an M9 family admin in the same house, that is an immediate takeover ([A3](#a3-malicious-instance-admin)). | A 0 wait only on single-account instances ([Q-15](#10-open-questions-for-the-owner)). Every change to the wait is logged to and visible for each user. | INV-69 |

---

## 8. Security invariants

Each line is a testable statement that every later milestone must keep. "From" is the milestone that introduces the invariant. From then on it is a regression test.

### 8.1 Authentication and passwords

| ID | Invariant | From | Verified by |
|---|---|---|---|
| INV-1 | The server never receives a value from which the master password can be verified offline without the OPRF seed. Registration, login and password change send only OPAQUE protocol messages (RFC 9807). | M1 | API schema review; an integration test captures every request body during register, login and password change and checks it contains only OPAQUE messages. |
| INV-2 | If the Secret Key is adopted: checking a master-password guess against server data needs the Secret Key as well as the OPRF seed, and the Secret Key is never sent to the server. | M1 (see [Q-1](#10-open-questions-for-the-owner)) | Test vector: the OPAQUE password input depends on the Secret Key. Canary test (INV-15). |
| INV-3 | Clients refuse to register, log in, change the password, set up or perform local unlock, or create an encrypted export with Argon2id parameters below the compiled-in floor for that KDF version. Server-supplied parameters below the floor abort the flow before the password is processed. | M1 | Mock server returning sub-floor parameters for each flow. |
| INV-4 | Every opaque-ke call site passes an explicit Argon2id KSF with the account's parameters. The crate's default KSF is never used, and our KSF's `Default` fails closed. | M1 | Unit test: a call with `ksf: None` returns `KsfError`. Review rule. |
| INV-5 | The KDF version and parameters are bound into the OPAQUE context and into the AAD of every password-derived wrap. Tampering with stored parameters makes login or unwrap fail. It never succeeds with different parameters. | M1 | Tamper test on the stored parameters. |
| INV-6 | No path from the master password to a key or an authenticator is cheaper than one Argon2id evaluation at an allowed `kdf_id`. Each flow runs a fixed number of evaluations ([CRYPTO.md §5.4](CRYPTO.md#54-where-the-unlock-key-comes-from), [§11](CRYPTO.md#11-flows)): unlock on an enrolled device and web-vault login, one; signup on a durable client and first login on a new device, two (OPAQUE KSF, then the local wrap); signup in the web vault, one; re-enrolment of a device that knows only the new password after a rotation ([CRYPTO.md §11.3](CRYPTO.md#113-unlock-on-an-enrolled-device) step 5), two (the OPAQUE KSF and the new local wrap); password change in Server mode, three (re-authentication with the old password, then registration and the local wrap with the new one); password change in On-device mode, two on the changing device and two on each other device ([CRYPTO.md §11.5](CRYPTO.md#115-master-password-or-secret-key-change)). A keystore unlock through `E_ks` runs none, because it does not start from the master password ([INV-62](#8-security-invariants)). | M1 | Instrumented test counting KSF calls per flow against that table. |
| INV-7 | A login attempt does not reveal whether the account exists (dummy record, same error and timing). Unauthenticated login and registration attempts get exponential backoff per (account identifier, source IP) and a per-account cap on their rate, never a hard lockout. OPAQUE re-authentication from a device-authenticated session uses a separate bucket that unauthenticated attempts cannot exhaust. | M1 | Integration tests comparing existing and unknown accounts; rate-limit tests; a flood of unauthenticated attempts against one account does not block re-authentication, rotation or revocation from an enrolled device. |
| INV-8 | Server-side 2FA secrets are stored encrypted under a server key kept outside the DB. Session and refresh tokens are stored only as hashes. | M1 | DB-dump inspection test. |
| INV-66 | If an email-based login reset exists ([Q-16](#10-open-questions-for-the-owner)), it never replaces the OPAQUE record, `E_srv` or `E_rec`, grants no access to ciphertext, devices, shares or recovery, and is announced to and cancellable by every enrolled device. | M1 (only if the feature exists) | Integration test of the reset flow against each forbidden action. |

### 8.2 Envelope and encryption

| ID | Invariant | From | Verified by |
|---|---|---|---|
| INV-9 | Every ciphertext produced by `rizzy-core` is a versioned envelope ([ADR 0007](adr/0007-ciphertext-envelope.md)), and the whole header (version, algorithm ID, key ID) is authenticated as AAD. | M1 | Bit-flip test on each header field. |
| INV-10 | Clients decrypt only envelope versions and algorithm IDs on a compiled-in allow-list. An unknown or removed ID is an error. There is no fallback, legacy or unauthenticated decryption path. | M1 | A test for every ID that is not allowed. |
| INV-11 | All symmetric encryption is key-committing: a ciphertext opens under at most one key ([ADR 0005](adr/0005-symmetric-encryption-aead.md)). | M1 | Test with a ciphertext crafted to collide under two keys for the underlying AEAD; the commitment check rejects it. |
| INV-12 | AEAD nonces are drawn from the CSPRNG inside `rizzy-core`. No public API accepts a caller-supplied nonce. | M1 | API review; unit test. |
| INV-13 | Item AAD binds vault ID, item ID, item schema version, and the op or snapshot identity and version (op: op ID, device ID, `device_seq`, HLC and the op-header hash; snapshot: snapshot ID and the snapshot-header hash, which covers the version vector and the author device ID). A ciphertext moved to another item, vault or version fails to decrypt. A move into another account fails through the different vault ID and vault key; item AAD deliberately has no account ID, because M9 vaults are shared ([CRYPTO.md §8.4](CRYPTO.md#84-aad-and-purposes)). | M1 | Swap tests, including a swap into another account's vault. |
| INV-14 | Security-relevant settings (KDF version and parameters, envelope version, sync mode, device set, recovery status, pinned contact keys, equivalence groups and overrides, match modes, autofill rules) live in the signed `account-state` or in `ACCOUNT_SETTINGS`, encrypted under the account key. Clients ignore server values for these that are not in them. Freshness is [INV-25](#8-security-invariants). | M1 | Tamper test for each setting. |

### 8.3 Keys and identities

| ID | Invariant | From | Verified by |
|---|---|---|---|
| INV-15 | The master password, Secret Key, recovery code, account key, vault keys, item keys and private keys never leave a client unencrypted. | M1 | **Canary test**: create an account with known secrets, exercise every flow, then search every HTTP body, DB row, log line and backup file for them (raw, hex, base64). |
| INV-16 | Each account has an Ed25519 identity key and an X25519 encryption key, both generated on the client at signup. The encryption public key and every device key are signed by the identity key. Clients reject a public key without a valid signature chain. | M1 (device keys sign ops from M1, [INV-22](#8-security-invariants)) | Unit tests with unsigned and mis-signed keys. |
| INV-17 | A client wraps a key to another user's key (member, org, org recovery) only if that key is fingerprint-verified or pinned on first use. A change to a pinned key blocks wrapping until the user re-verifies. | M9 | Test with a substituted key. |
| INV-18 | No server-side path can decrypt vault data. There is no key escrow before M10. In M10, admin recovery requires the client to wrap to an authenticated org recovery key after explicit user consent, and the user can see that it is on. | M1 / M10 | API review: no endpoint accepts or returns an unwrapped key. M10 consent tests. |
| INV-19 | A password change re-registers OPAQUE and re-wraps the account key. An "also rotate keys" option exists. It runs a standard rotation: a new account key and new vault keys, with item keys re-wrapped and replaced on their next write ([CRYPTO.md §11.5](CRYPTO.md#115-master-password-or-secret-key-change), [§11.6](CRYPTO.md#116-key-rotation)). | M1 | Test: after rotation, the old password plus an old wrap from a pre-change backup no longer yields current keys. |
| INV-20 | The recovery code carries at least 128 bits of entropy and is generated on the client. | M1 | Generator unit test. |
| INV-21 | Secret-bearing types zeroize on drop, and their `Debug` and `Display` output is redacted. Panics and errors never contain secret values. | M1 | Unit tests on formatting output; review rule ([ADR 0009](adr/0009-crypto-dependency-policy.md)). |

### 8.4 Sync and state

| ID | Invariant | From | Verified by |
|---|---|---|---|
| INV-22 | Every op is AEAD-encrypted under its item key, which is wrapped under the vault key ([CRYPTO.md §8.4](CRYPTO.md#84-aad-and-purposes)), and signed by the originating device key. Clients reject ops with a bad signature or from a revoked device. | M1 | Unit tests. |
| INV-23 | Applying an op twice has the same effect as applying it once, and any order of a given set of ops yields the same state. | M1 | Property tests with N simulated devices ([ROADMAP §6.8](ROADMAP.md#6-risks--hard-truths)). |
| INV-24 | Conflicting edits are kept as item history. No op is dropped silently. | M1 | Property tests. |
| INV-25 | Clients persist the highest version vector they have accepted per item, the last verified `account-state` (`state_seq`) and the highest `settings_seq`. `account-state` commits to `settings_seq` and to the SHA-256 of the current `ACCOUNT_SETTINGS` envelope, and every settings change publishes a new `account-state` with `state_seq + 1`. A server response that moves any of these backwards, or an `ACCOUNT_SETTINGS` envelope whose `settings_seq` or hash differs from the verified state, is rejected and reported, never applied. | M1 | Mock-server rollback tests: an older item version; an older `account-state`; an older, validly encrypted `ACCOUNT_SETTINGS` (for example one that restores a deleted equivalence group). |
| INV-26 | Server-side compaction discards only ops covered by a snapshot a client produced and signed. | M1 | Test. |
| INV-27 | Each device's op stream carries a gap-free sequence (`device_seq`, and `vault_prev_seq` per vault, [ADR 0012](adr/0012-sync-engine.md)). A gap is reported as missing data, never skipped, and nothing from that device past the gap is applied. | M1 (Server mode) / M4 (relay) | Server mode: the server omits op *n* from a device and serves *n+1*; the client reports missing data and applies nothing past the gap. M4: the same through the relay. |
| INV-28 | In On-device mode the server stores no vault snapshot, no op older than the TTL, and nothing that lets anyone check a master-password guess offline: no OPAQUE record and no password-derived wrap. | M4 ([Q-3](#10-open-questions-for-the-owner)) | DB inspection after a mode switch. |
| INV-29 | Pairing and any "approve this device" flow transfer key material only after both devices confirm the same SAS. | M4 | Test with a relay that swaps keys. |
| INV-30 | Revoking a device publishes a signed `device-revocation` and a new `account-state`, and rotates the account key and every owned vault key. Revoking a lost or stolen device runs a full rotation that also replaces the identity keys ([CRYPTO.md §11.6](CRYPTO.md#116-key-rotation), [§11.8](CRYPTO.md#118-device-revocation)). Data written after the revocation cannot be read with the revoked device's keys. Once a client has accepted the rotation's `account-state`, it rejects any device certificate, `device-revocation`, bundle or `account-state` signed only by a superseded identity key; the full rotation re-issues every certificate and revocation under the new key ([CRYPTO.md §11.6](CRYPTO.md#116-key-rotation) step 7). In On-device mode the device also leaves the relay ack set. A device that re-enrols itself under a new `device_id` revokes its old one without a rotation, because those keys never left it ([CRYPTO.md §11.3](CRYPTO.md#113-unlock-on-an-enrolled-device) step 5). | M3 (Server-mode revocation from the device list) / M4 (relay) | Tests: after a standard rotation, the revoked device's account key opens no new wrap; after a full rotation, a certificate and an `account-state` signed with the old identity key are rejected; after a full rotation, a device enrolled afterwards verifies every retained op of the revoked device and of an expired web session. |
| INV-31 | Switching from Server mode to On-device mode rotates the account key and the vault keys, and item keys are replaced on their next write (the lazy rule in [CRYPTO.md §11.6](CRYPTO.md#116-key-rotation)), so any copy of old wraps the server kept does not cover data written after the switch. | M4 | Test: old server-side wraps cannot open ops written after the switch. |
| INV-67 | In a shared vault, clients accept an op only if its author holds, in a membership statement signed by a vault manager and verified by the client, a role that allows that op. A view-only member's edits are rejected even when the server accepts them. The statement format belongs to the M9 ADR. | M9 | Test: an op signed by a view-only member's device is rejected by the other members' clients. |

### 8.5 Sharing

| ID | Invariant | From | Verified by |
|---|---|---|---|
| INV-32 | The share secret (32 bytes, the source of the share key and tokens) is generated on the client and exists only in the URL fragment and, encrypted, in the owner's vault ([CRYPTO.md §11.10](CRYPTO.md#1110-public-share-link-creation-m5)). It never appears in a request, log line, analytics event or `Referer`. The share ID is at least 128 random bits. | M5 | Browser end-to-end test capturing all network traffic from the owner and recipient pages. |
| INV-33 | The recipient page fetches the ciphertext and counts a view only after an explicit user action. It loads no third-party resources and sends `Referrer-Policy: no-referrer`. | M5 | End-to-end test. |
| INV-34 | At expiry, revoke or maximum views, the server deletes the share ciphertext, whether or not anyone visits. | M5 | Worker test. |
| INV-35 | Untrusted rich content (share payloads, mail HTML) is rendered as text or in a sandboxed iframe without `allow-scripts` and `allow-same-origin`. It can never read the web vault's storage or keys. Remote mail content is blocked by default. | M5 / M6 | End-to-end test with XSS payloads. |

### 8.6 Autofill and URLs

| ID | Invariant | From | Verified by |
|---|---|---|---|
| INV-36 | Nothing is filled without a trusted user gesture. | M2 | Extension end-to-end tests. |
| INV-37 | No HTTPS-saved credential is filled into an HTTP page. Nothing is filled into cross-origin iframes by default. Nothing is filled into hidden or invisible fields. | M2 | End-to-end tests with adversarial pages. |
| INV-38 | Matching runs on normalized A-label hosts against the PSL. A host with a different registrable domain matches only through a signed global group or a user group, and the fill UI marks such matches. This registrable-domain check runs before every match mode, *Starts with* and *Regex* included; a mode can only narrow the match. Regexes are matched against the full normalised URL. | M2 | Table-driven tests, including `evil-youtube.com`, IDN homographs, PSL private suffixes, *Starts with* `https://bank.com` against `https://bank.com.evil.example/`, and an unanchored regex against a foreign host. |
| INV-39 | Clients accept a global equivalence list only with a valid signature from the list key and a version no lower than the last one accepted. | M2 | Tests with an unsigned list, a list signed with the wrong key, and an older list. |
| INV-40 | The extension never asks for the master password or Secret Key in page-injected UI. UI that triggers a fill runs in an extension-origin context. There is no `externally_connectable` for web origins. The background treats every content-script message as untrusted. | M2 | Manifest check in CI; review checklist. |
| INV-41 | Mobile clients fill web credentials into a native app only if the app is verified for that domain, or after the user confirms a warning. | M7 | Test with an unverified app. |
| INV-42 | Clients open or fill only `http` and `https` URLs taken from item fields. `javascript:`, `data:`, `file:` and similar schemes are never opened. | M1 | Unit test. |
| INV-64 | A passkey provider (extension or mobile) creates a credential or signs an assertion only when: the caller's origin comes from the browser's sender information, or from the OS's calling-app verification on mobile, never from page-supplied data; the origin is HTTPS; the requested `rpId` equals the origin's host or is a registrable-domain suffix of it, checked against the PSL, and is never a public suffix (private PSL entries included); and `clientDataJSON` `origin`, `crossOrigin` and `topOrigin` are set from that verified origin. Cross-origin iframes are refused by default. | M7 | Table-driven tests: `evil.example` requesting `rpId` `bank.com`; `rpId` `co.uk` and `github.io`; an `http` origin; a cross-origin iframe; an origin forged in the page's message. |

### 8.7 Mail

| ID | Invariant | From | Verified by |
|---|---|---|---|
| INV-43 | The vault builds and runs fully with the mail subsystem disabled. | M6 | CI build and test job with mail off. |
| INV-44 | The `smtp` role holds no database credentials and has no network path to the DB. It reaches `api` only through two internal calls ([ADR 0010](adr/0010-server-shape.md) §2): `resolve(alias address)`, rate-limited, which returns the alias ID and the account's key bundle with the chain since the `bundle_seq` `smtp` last pinned ([CRYPTO.md §11.13](CRYPTO.md#1113-mail-ingress-m6)), or a rejection; and `deliver(alias ID, ciphertext, padded size)`. | M6 | Deployment test for profile B; config review; a test that `smtp`'s credential opens no other endpoint. |
| INV-45 | rizzy-vault never writes plaintext mail to disk, logs or queues. Plaintext exists only in `smtp` memory and in the request to the local spam filter. | M6 | Log and file-system canary test with a marker message. |
| INV-46 | The only mail metadata the server can see is alias ID, received time and padded size. Sender, subject and authentication results are inside the ciphertext. | M6 | DB inspection test. |
| INV-47 | SMTP replies for unknown and disabled aliases are identical and go through the same code path. (Active aliases are accepted and so remain distinguishable; see INV-65.) | M6 | Test comparing replies. |
| INV-65 | Generated alias local parts contain at least 64 bits from the CSPRNG; human-readable parts (names, words, digits chosen to look human) do not count toward it. `smtp` rate-limits RCPT attempts per source IP and tarpits repeated rejected recipients. The UI says that user-chosen aliases can be confirmed by probing. | M6 | Generator unit test for the entropy floor; RCPT rate-limit and tarpit tests. |

### 8.8 Server and operations

| ID | Invariant | From | Verified by |
|---|---|---|---|
| INV-48 | Logs never contain secrets, OPAQUE messages, bearer tokens, share keys or mail content. | M1 | Canary test (INV-15) extended to logs at the most verbose level. |
| INV-49 | The web vault is served with a CSP that forbids inline script, `eval` (except `wasm-unsafe-eval`) and third-party origins, plus `frame-ancestors 'none'`, HSTS and `nosniff`. | M1 | Header test. |
| INV-50 | The OPAQUE server setup (OPRF seed, server keypair) is stored outside the DB and outside DB backups. The backup docs cover backing it up separately. | M1 | Test that a DB dump contains no setup material; a restore drill that includes it. |
| INV-51 | The icons fetcher connects only to globally routable unicast addresses on ports 80 and 443. It refuses every range in the IANA IPv4 and IPv6 special-purpose address registries that is not marked globally reachable (including 0.0.0.0/8, loopback, RFC 1918, 100.64.0.0/10, link-local, unique-local and reserved space), and all multicast and broadcast. Addresses that embed IPv4 (IPv4-mapped `::ffff:0:0/96`, NAT64 `64:ff9b::/96`) are judged by the embedded IPv4 address. The check runs after DNS resolution and on every redirect, and the connection goes to exactly the IP that was checked, with no second resolution. It never serves SVG or other active content, and it does not log requested domains per user. | M3 | SSRF test suite with one case per refused range, the mapped and NAT64 forms of a private address, a non-standard port, DNS rebinding and redirects. |
| INV-52 | Bearer tokens never appear in URLs, including WebSocket connect URLs. | M1 | Test and review rule. |
| INV-53 | All SQL uses bound parameters through sqlx. No query is built from strings. | M1 | Lint or review rule. |
| INV-54 | Push notifications and `notify` signals carry no vault or mail content, only a wake-up signal. | M3 | Payload test. |
| INV-55 | Native clients install updates only after verifying a signature from the pinned release identity. | M3 | Updater test with a bad signature. |
| INV-59 | After `rizzy-vault restore`, every restored account is in a reconciliation epoch. Reconnecting devices re-upload their latest signed `account-state`, bundle chain and `device-revocation` statements. Once the server has verified a newer state against the account's identity key, it refuses OPAQUE logins, recovery requests and device authentication whose `password_epoch` or `recovery_epoch` is older than that state, or whose device that state revokes ([§5.8](#58-server-restore-from-backup)). The comparison uses the `password_epoch` the server stores with each OPAQUE record and the `recovery_epoch` it stores with `H_rec` ([CRYPTO.md §11](CRYPTO.md#11-flows), "Replacing credentials"). Out-of-band state adoption and certificate-carrying device authentication are accepted only during the reconciliation epoch ([ADR 0012](adr/0012-sync-engine.md) §7). | M1 | Restore drill: back up; change the password, rotate the recovery code, revoke a device; restore; reconnect a remaining device; the old password, the old recovery code and the revoked device are all refused. Outside reconciliation, a client holding only the identity key gets no challenge and cannot replace the state. |
| INV-60 | Every native binary (all server roles, `rv`, the desktop app) disables core dumps at startup. On Linux: `PR_SET_DUMPABLE = 0` and `RLIMIT_CORE = 0`, through safe wrappers such as rustix 1.1.5's `set_dumpable_behavior` and `setrlimit` (source checked; adding the crate goes through [ADR 0009](adr/0009-crypto-dependency-policy.md)), so `unsafe_code = forbid` is no obstacle. On macOS and Windows: opt out of local dumps and crash-report upload where the platform allows it (mechanism to confirm in M3, U). No crash-reporting SDK is linked. | M1 | Each binary asserts its own dumpable flag and core limit after start. The INV-45 canary is extended with a forced panic in `smtp` mid-ingress: no plaintext appears in any file, core files included. |
| INV-69 | The admin panel and admin API authenticate admins separately from user accounts and require a second factor. The first-run bootstrap token lives in the secrets file (mode 0600), is shown once and is never logged. The admin UI renders every user-controlled string as text, has its own strict CSP, and rejects cross-site requests (SameSite cookies plus a CSRF token). Every admin action, including a change to the recovery waiting period, goes into the affected users' security event log. | M3 | XSS payloads in login and device names rendered in the admin UI; CSRF test; log inspection for the bootstrap token; event-log test for a wait change. |

### 8.9 Clients and supply chain

| ID | Invariant | From | Verified by |
|---|---|---|---|
| INV-56 | `rv` never takes secret values from argv or environment variables, and prints a secret to a terminal only when asked to explicitly. | M1 | CLI tests. |
| INV-57 | `cargo deny check` passes on every PR (RustSec advisories, licenses, bans including openssl, crates.io only). `Cargo.lock` is committed and CI builds use `--locked`. | M0 | CI (in place). |
| INV-58 | `rizzy-core` and `rizzy-sync` do no network, filesystem or clock I/O. Randomness and time are injected by the caller, and `cargo check-wasm` passes ([ADR 0016](adr/0016-workspace-layout.md)). | M0 | CI (`cargo check-wasm`, in place); dependency review. |
| INV-61 | Device state (SK, `E_local`, `device_salt`, `E_dev`) and the encrypted cache are kept out of OS and cloud backups. iOS: the backup-exclusion resource attribute, and keychain items with a `ThisDeviceOnly` accessibility class. Android: backup disabled, or these files excluded through data-extraction rules. Desktop: a local, non-roaming app-data path, marked excluded from OS backup where the OS supports it. CLI: the docs say where the state file lives and that it must stay out of backups. | M1 (CLI docs) / M3 (desktop) / M7 (mobile) | Per-platform test that the attribute or rule is set; CLI docs review. |
| INV-62 | Keystore (biometric) unlock releases the local unlock secret ([AST-22](#2-assets)) only after an OS-enforced user-presence check, bound to hardware where available: a Secure Enclave or StrongBox/TEE key with a biometry access-control flag, or a Windows Hello key-credential operation, not plain DPAPI. The secret is invalidated when biometric enrolment changes. A policy that accepts the device passcode as a fallback is labelled as such in the setting. Where the OS cannot enforce presence (Linux Secret Service, plain DPAPI, the CLI's keyring or file), keystore unlock is not offered. Exact APIs are confirmed in M3 and M7 (U). | M3 / M7 | Per-platform test that the key's access-control flags are set; review checklist; a test that the Linux and CLI builds expose no keystore unlock. |
| INV-63 | In the browser extension, unlocked key material (account, vault, item and device private keys, `pw_in`, unlock keys) exists only in memory: the service worker, an offscreen document, or `storage.session` left at its default trusted-contexts access level (Chromium; Firefox behaviour to confirm in M2, U). It is never written to `storage.local`, `storage.sync` or IndexedDB, and no storage that content scripts can read holds secrets. Only wrapped device state is persisted. | M2 | Test that inspects every extension storage area after unlock and after a worker restart; review checklist. |
| INV-68 | Secret input fields (master password, Secret Key, recovery code, export password, share passphrase, revealed secret fields) set `spellcheck="false"` and `autocomplete` values that discourage browser saving. Revealing a field (switching `type` to `text`) keeps spell-check off. Mobile secret fields use secure text entry and the no-personalised-learning keyboard flag, and a revealed secret is shown read-only. | M1 (web vault) / M2 / M3 / M7 | DOM tests on each secret field before and after reveal; mobile UI tests. |

### 8.10 Changes this document requires elsewhere

The invariants above were stricter than some mechanisms as first written. This table tracks the edits they forced. Until an edit lands, the invariant is the requirement and the mechanism text is the bug.

| Document | Required change | Invariant | Status |
|---|---|---|---|
| [CRYPTO.md §10.2](CRYPTO.md#102-ed25519-signatures-and-signed-statements) | `account-state` gains `u64 settings_seq` and `settings_hash` (SHA-256 of the current `ACCOUNT_SETTINGS` envelope). Every settings change publishes a new state. [§11.3](CRYPTO.md#113-unlock-on-an-enrolled-device) checks the fetched settings against it. | INV-25 | Done |
| [CRYPTO.md §11.6](CRYPTO.md#116-key-rotation), [ADR 0006](adr/0006-key-hierarchy.md) | After a full rotation, statements signed only by the superseded identity key are rejected. | INV-30 | Done: CRYPTO.md §10.2 ("Which identity key verifies what") and §11.3 step 3 |
| [ADR 0011](adr/0011-storage.md) ("What a restore cannot do"), [ADR 0012](adr/0012-sync-engine.md) ("Healing a server rollback") | Add the reconciliation epoch and the re-upload of signed state and revocations. | INV-59 | Done |
| [ADR 0010](adr/0010-server-shape.md) §2 and §4 | Replace the SSRF deny-list with the INV-51 allow-list. Mount server secrets separately from the data volume by default. | INV-51, INV-50 | Done |
| [CRYPTO.md §12.2](CRYPTO.md#122-memory-hygiene) | Next to `panic = "abort"`: core dumps disabled at startup. | INV-60 | Done |
| [ADR 0013](adr/0013-shared-client-core.md) §2 table, [ADR 0015](adr/0015-desktop-tauri.md) §9 | Extension key storage per INV-63. The CLI's "OS keyring, or a 0600 file" may hold device state, never a keystore-unlock secret. Biometric unlock per INV-62. | INV-62, INV-63 | Done |
| [ADR 0008](adr/0008-account-recovery.md) decision 8 | Remove the email login reset, or bound it by INV-66 ([Q-16](#10-open-questions-for-the-owner)). | INV-66 | Done: removed |
| [CRYPTO.md §11.11](CRYPTO.md#1111-public-share-link-opening-m5) | Burn rule ([Q-20](#10-open-questions-for-the-owner)). | – | Done: link token split from access token |
| [ROADMAP §4.8](ROADMAP.md#48-aliases--email-receiving-m6), [§4.9](ROADMAP.md#49-server-self-hosting--ops-m1-onward) | Alias enumeration wording ([Q-18](#10-open-questions-for-the-owner)); Quadlet auto-update ([Q-17](#10-open-questions-for-the-owner)). | INV-65 | Open: ROADMAP edits are the owner's |

---

## 9. Accepted risks and out of scope

| ID | Accepted risk | Why we accept it | Revisit |
|---|---|---|---|
| AR-1 | A malicious or compromised server can backdoor the web vault and the share recipient page ([§4.2.1](#421-the-web-vault-delivery-problem)). | No deployable fix exists today. Native clients avoid the problem. | When WAICT or WEBCAT can be deployed; post-1.0 |
| AR-2 | The server sees alias mail in plaintext at ingress ([§6](#6-email-ingress-m6)). | Spam filtering has to run before encryption. | – |
| AR-3 | The server sees metadata: account existence, IPs, timing, counts, sizes ([NG-5](#14-non-goals)). | Hiding it needs anonymity infrastructure that is out of scope. | M4 padding |
| AR-4 | A weak password with no Secret Key falls to a DB-plus-OPRF-seed attacker. | The Secret Key is the fix ([Q-1](#10-open-questions-for-the-owner)). | M1 decision |
| AR-5 | A new device can be frozen on a stale state. Forks and withheld suffixes stay hidden until devices compare heads. | Fork consistency is the best a single untrusted server allows. | Post-1.0 (LAN or P2P sync) |
| AR-6 | Trust on first use for other users' keys (M9) when nobody verifies fingerprints. | Key transparency is too big for v1.0. | [Q-8](#10-open-questions-for-the-owner) |
| AR-7 | Once a share is opened, the plaintext cannot be recalled; the link stays live in chat logs until it expires. | This is how link sharing works. | – |
| AR-8 | Harvest-now-decrypt-later against X25519 wraps (M6 mail, M9 sharing, M4 pairing) and against OPAQUE's group. 256-bit symmetric encryption is not materially affected. | ML-KEM and X-Wing crates are unaudited, and X-Wing and HPKE-PQ are still drafts (fact sheet). The envelope reserves algorithm IDs. | [Q-12](#10-open-questions-for-the-owner) |
| AR-9 | Server-enforced controls (2FA, rate limits, view limits, expiry, email-restricted shares, device suspension, deletion, deletion receipts) hold only against an honest server. | Nothing but cryptography constrains a malicious server, and these controls are not cryptographic. | – |
| AR-10 | Keys can reach swap and hibernation files. Our crates forbid `unsafe`, so they cannot `mlock`. | zeroize shortens the window. OS full-disk encryption protects swap against a thief with a powered-off machine and nothing else: not against later same-user or root access, and not against anything that copies the files while the OS runs. Crash dumps are not accepted here; they are disabled ([INV-60](#8-security-invariants)). In a container the kernel's `core_pattern` is host-global; with a pipe handler and `fs.suid_dumpable = 2` the host may still collect a root-readable dump (U, confirm in M1), so the operator docs say to disable core collection for the container. | Could use a vetted mlock crate ([ADR 0009](adr/0009-crypto-dependency-policy.md)) |
| AR-11 | Old backups keep old wraps and deleted data. A password change does not invalidate old wraps. | Account-key rotation exists ([INV-19](#8-security-invariants)); backup retention is the operator's decision. | – |
| AR-12 | One maintainer holds all release credentials. | That is the project's size today. | Before M8 |
| AR-13 | On-device mode: losing every device loses the vault. | That is the point of the mode; the UI warns about it ([ROADMAP §4.6](ROADMAP.md#46-sync-modes-m4)). | – |
| AR-14 | Stolen devices without a hardware keystore allow offline guessing at the Argon2id floor: the CLI (and its state file in the user's own backups), the browser extension (SK, `E_local` and `E_dev` in the browser profile), and desktop Linux. The web vault keeps no `E_local` ([CRYPTO.md §11.4](CRYPTO.md#114-web-vault)), so a stolen browser yields at most a remembered SK. | There is no platform mechanism to use. | – |
| AR-15 | Old clients carry old PSL snapshots and equivalence lists. | Clients that never update cannot be fixed. | – |
| AR-16 | OS clipboard history and cross-device clipboard sync can ignore the sensitive flag. | Outside our control. | – |
| AR-17 | iOS AutoFill unlocks through `E_ks`, with an unlock secret held in the keychain behind biometry, instead of running the full KDF ([CRYPTO.md §6.4](CRYPTO.md#64-feasibility)). | The memory cap leaves no alternative; the keychain and biometry are the boundary ([INV-62](#8-security-invariants)). | M7 ([Q-13](#10-open-questions-for-the-owner)) |
| AR-18 | A compromised device that is later revoked holds the old identity key and can race its own rotation, signing certificates or state before the remaining devices see the rotation. | Remaining devices accept a rotation only from a non-revoked device and ask the user to confirm the new fingerprint. Nothing stops a device that already holds the identity key from signing first. | M4 device-management ADR |
| AR-19 | A restore from backup reopens superseded passwords, recovery codes and revoked devices until a device presents the newer signed state ([§5.8](#58-server-restore-from-backup), [INV-59](#8-security-invariants)). Accounts whose devices never reconnect stay exposed. | The server has no other source for the newer state. The restore command and docs warn the operator. | – |
| AR-20 | RCPT probing tells an active alias from a non-existent one. User-chosen aliases can be confirmed by guessing. | Accepting mail for active aliases requires it. Generated aliases are unguessable ([INV-65](#8-security-invariants)). | [Q-18](#10-open-questions-for-the-owner) |
| AR-21 | A compromised `smtp` can enumerate aliases slowly through `resolve`, and link aliases of one account because they share the mail key. | It already reads all later mail ([AR-2](#9-accepted-risks-and-out-of-scope)), which links aliases that receive mail anyway. | [Q-19](#10-open-questions-for-the-owner) |
| AR-22 | Only if the owner allows tag-following server auto-update before M8 ([Q-17](#10-open-questions-for-the-owner)): each such instance installs whatever the registry serves under the tag. | Opt-in, with the trade-off stated where it is enabled. | M8 (signature verification) |
| AR-23 | Anyone holding a share's full link can burn it with 10 bad access tokens, and a recipient who mistypes a share passphrase 10 times burns it too. A holder of only the share path cannot: failures count only with a valid link token ([CRYPTO.md §11.11](CRYPTO.md#1111-public-share-link-opening-m5)). | The burn bounds passphrase guessing to 10 online attempts. A full-link holder can already read a share without a passphrase. | – |

**Explicitly out of scope:** everything in [§1.4](#14-non-goals); the security of the user's email provider and phone number, because no *data* recovery goes through them; and the security of third-party services we call (HIBP, DNS blocklists, APNs/FCM) beyond limiting what we send them. [ADR 0008](adr/0008-account-recovery.md) decision 8 allows no email-based reset of anything ([Q-16](#10-open-questions-for-the-owner)). If a login reset is ever added, [INV-66](#8-security-invariants) bounds what it may do, and whoever controls the user's mailbox or the instance's outbound mail is an attacker against it.

---

## 10. Open questions for the owner

| ID | Question | Recommendation |
|---|---|---|
| Q-1 | **Ship the Secret Key in M1?** [ROADMAP §4.3](ROADMAP.md#43-cryptography--authentication-m0m1-audited-in-m8) contradicts itself. The M1 Emergency Kit is "printable Secret Key + recovery code" (Must, M1), but the Secret Key itself is "Should, M1 decision, M3 ship". | **Ship it in M1.** It is what makes a DB-plus-seed breach harmless ([A1](#a1-passive-server-compromise-db-or-backup-theft)). Mixed into the OPAQUE input, adding it later means every account has to re-register and every Emergency Kit has to be reprinted. Fix the ROADMAP row either way. |
| Q-2 | Mix the Secret Key into the OPAQUE password input, or only into the vault-key derivation? | **Into the OPAQUE input** (and so into `export_key`). If it goes only into the vault key, a DB-plus-seed attacker can still guess the password against the OPAQUE record, which defeats 2SKD for authentication. Mechanism in [ADR 0003](adr/0003-authentication-opaque.md) and [ADR 0004](adr/0004-key-derivation-argon2id-secret-key.md). |
| Q-3 | **How do devices authenticate in On-device mode?** [ROADMAP §4.6](ROADMAP.md#46-sync-modes-m4) says a breach "yields nothing to brute-force against the master password". That is false if the server keeps the OPAQUE record or a password wrap. | **Adopted** in [CRYPTO.md §5.7](CRYPTO.md#57-on-device-sync-mode), [ADR 0003](adr/0003-authentication-opaque.md) decision 10 and [ADR 0012](adr/0012-sync-engine.md) §10 (all Proposed): delete the OPAQUE record and the password wraps at the switch point, authenticate devices to the relay with their device keys, and re-register OPAQUE from an unlocked device when switching back ([INV-28](#8-security-invariants)). If the owner rejects this, the ROADMAP wording has to change. |
| Q-4 | Serve the share recipient page and rendered mail from a **separate origin** (for example `share.<domain>`), so an XSS there cannot reach web-vault storage? | Require a second hostname when M5 ships. [INV-35](#8-security-invariants) is the minimum; a separate origin is defence in depth. It costs self-hosters one DNS name and one certificate. |
| Q-5 | Allow the `smtp` role in profile A (same process or container as `api` and the DB)? | **No.** The `smtp` role refuses to start with DB credentials present. Profile B becomes a hard requirement for mail, not a recommendation. |
| Q-6 | Web vault on by default in Server mode, and with an admin switch to turn it off? | On by default (M1 needs it), with an admin switch and a one-line trust notice in the UI. Recommend the extension or desktop app during onboarding. |
| Q-7 | Bind API sessions to the device key with a signature per request, so stolen bearer tokens are useless, including behind TLS-inspecting proxies? | **Yes, for native clients from M1**, with the `device-request` statement that [CRYPTO.md §5.10](CRYPTO.md#510-sessions-after-authentication) specifies (the OPAQUE `session_key` is not used). It is cheap now and painful later. It is also the only practical answer to a MITM relaying the device-auth challenge ([A4](#a4-network-attacker-mitm)): binding to the TLS channel does not work, because TLS ends at the operator's reverse proxy. The web vault keeps short-lived bearer tokens. Decide before M1 auth work starts. If declined, a stolen bearer token or a relayed device-auth session gives ciphertext access and destructive calls until the session ends. |
| Q-8 | Key authenticity for M9 sharing: TOFU plus verifiable fingerprints, or key transparency? | TOFU plus fingerprints (safety-number style) for M9. Evaluate key transparency after 1.0. |
| Q-9 | CI hardening beyond what is in place: pin third-party Actions by commit SHA (today `actions/checkout@v4`, `Swatinem/rust-cache@v2` and `EmbarkStudios/cargo-deny-action@v2` are pinned by tag), and adopt cargo-vet or similar for new dependencies? | Pin by SHA now and let Dependabot bump them. Decide on cargo-vet before M1 adds crypto crates. |
| Q-10 | Governance for the equivalence list with one maintainer ("review by two maintainers", [ROADMAP §6.4](ROADMAP.md#6-risks--hard-truths)), and who holds the list-signing key? | Use a dedicated offline list key, separate from release keys. Until there is a second maintainer, ship only groups with public proof of common ownership, and keep the global list small. |
| Q-11 | `icons` role default? | **Off by default.** When on: anonymous, shared cache, no per-user logs ([INV-51](#8-security-invariants)). |
| Q-12 | When to add post-quantum hybrid wrapping (X25519 + ML-KEM-768)? | Keep algorithm IDs reserved in M1 ([ADR 0007](adr/0007-ciphertext-envelope.md)). Re-check the audit status of ml-kem and x-wing and the standard status of X-Wing and HPKE-PQ before M9 sharing ships. |
| Q-13 | iOS AutoFill unlock: run Argon2id inside the extension (memory cap about 120 MB) or use a keychain-cached key gated by biometry? | Keychain-cached key gated by biometry, measured in M7 ([AR-17](#9-accepted-risks-and-out-of-scope)). |
| Q-14 | Server-side WebAuthn 2FA (M3): webauthn-rs pulls in openssl, which [`deny.toml`](../deny.toml) bans, and webauthn_rp pulls in `rsa` with an unpatched advisory (RUSTSEC-2023-0071). | Tracked in [ADR 0009](adr/0009-crypto-dependency-policy.md). The threat model only requires that any exception is scoped to the server binary and never reaches `rizzy-core` or the clients. |
| Q-15 | What does recovery with the Emergency Kit require besides the recovery code? | **Answered in [ADR 0008](adr/0008-account-recovery.md)** (Proposed, so it still needs the owner's acceptance): a server-enforced waiting period, 72 h by default and admin-configurable from 0 to 30 days, cancellable by any enrolled device, with notification to every device and the account email. The UI tells users to store the kit like a passport. **Remaining sub-question:** allow a 0 wait only on instances with exactly one account? *Recommendation:* yes. Otherwise an M9 family admin with physical access to a kit gets an immediate takeover ([A3](#a3-malicious-instance-admin), [§7.19](#719-admin-panel-and-admin-api-m3)). |
| Q-16 | Keep an email-based login reset ("an email can reset a *login*, never the data", from an earlier draft of [ADR 0008](adr/0008-account-recovery.md))? | **Remove it.** ADR 0008 decision 8 (Proposed) now does: email is a notification channel only. In this design a login without the account key opens nothing for an honest user; the recovery code covers a forgotten password. For whoever controls the user's mailbox, or the instance's outbound mail (the operator), it would be an authenticated session: download ciphertext, delete data, start or cancel a recovery, force enrolled devices to log out. If the owner keeps it, [INV-66](#8-security-invariants) applies, and what is left of the feature is almost nothing. |
| Q-17 | [ROADMAP §4.9](ROADMAP.md#49-server-self-hosting--ops-m1-onward) promises Quadlet units with `podman auto-update` (Should, M3). Auto-update follows an image tag, while the deploy docs pin digests ([§7.17](#717-distribution-channels-m1-onward)). Before M8 nothing verifies image signatures, so one compromised release reaches every auto-updating instance and its web-vault users ([A10](#a10-compromised-ci-or-release-credentials)). | Ship the Quadlet units in M3 with auto-update **off**. Document turning it on once images are signed and a shipped `policy.json` template verifies them with sigstore (M8). Before M8, auto-update is opt-in only, with the trade-off stated where it is enabled ([AR-22](#9-accepted-risks-and-out-of-scope)). Change the ROADMAP row to match. |
| Q-18 | [ROADMAP §4.8](ROADMAP.md#48-aliases--email-receiving-m6) requires alias lookup "without revealing which aliases exist" and also rejecting disabled aliases at SMTP time. Active aliases accept mail, so RCPT probing always separates active from non-existent. Options: (a) reject unknown and disabled identically, accept active, and rely on alias entropy; (b) accept every RCPT for a configured domain and drop unknown or disabled mail after DATA, which hides existence but stores and scans spam for addresses that do not exist and contradicts "rejected at SMTP time". | **(a)**, with at least 64 random bits in every generated local part ([INV-65](#8-security-invariants)), per-IP RCPT limits and tarpitting. That makes addresses long (13 base32 characters of randomness). The owner may prefer readable "random name" addresses; the price is that they can be confirmed by guessing. Reword the ROADMAP row to "does not reveal which aliases exist beyond confirming a guessed address; generated addresses cannot be guessed". |
| Q-19 | `resolve` returns the account's mail key bundle, so a compromised `smtp` links aliases that belong to one person ([§6.3](#63-what-this-means-stated-plainly)). Per-alias mail keys, or accept the linkage? | **Accept it for v1.0** ([AR-21](#9-accepted-risks-and-out-of-scope)). A compromised `smtp` already reads all later mail, which links every alias that receives mail. Per-alias keys mean one signed key per alias, more key-rotation work and a larger bundle. Revisit with M9 multiple mail domains. |
| Q-20 | The share burn after 10 failed tokens ([CRYPTO.md §11.11](CRYPTO.md#1111-public-share-link-opening-m5)) lets anyone who has only the share path destroy a share ([A12](#a12-share-link-leakage-m5)). | Add a **link token** derived from the share secret alone, and count failures toward the burn only on requests whose link token is valid. A path-only holder then cannot burn a share, and a link holder still gets only 10 passphrase guesses. Shares without a passphrase need no burn: their 256-bit token is not guessable, so per-source rate limits suffice. **Adopted** in [CRYPTO.md §11.11](CRYPTO.md#1111-public-share-link-opening-m5) (Proposed), which keeps the burn for every share; for a share without a passphrase it never triggers for an honest client. Residual: [AR-23](#9-accepted-risks-and-out-of-scope). |
| Q-21 | Let the web vault remember the Secret Key ("this is my browser", [CRYPTO.md §7](CRYPTO.md#7-secret-key), §16 question 5)? Server-served JavaScript reads it at the next page load, without any unlock, and the server already holds the OPRF seed. For those users [G-4](#13-security-goals) does not hold against an active server. | Keep it **opt-in, default off**, with checkbox copy that says the server can read it. Drop it instead if the owner wants G-4 without an exception; the cost is typing the SK on every browser session. |

---

## 11. References

Confidence follows the M0 fact sheet: **V** means the primary source (or its source text) was read. **L** means the claim comes from secondary coverage or search snippets and was not read in the original.

| Reference | Used for | Conf. |
|---|---|---|
| RFC 9807, *The OPAQUE Augmented PAKE Protocol* (IRTF CFRG, 2025) and the draft source text `cfrg/draft-irtf-cfrg-opaque` | Offline attack by a corrupted server, `oprf_seed` leak, registration as an enumeration oracle, Context guidance, key-robust MAC | V (text), L (date) |
| opaque-ke 4.0.x README, CHANGELOG and source (`ksf` defaults, dummy record) | KSF fallback, zero-salt KSF, dummy-record timing fix | V |
| RFC 9106, *Argon2* | Argon2id parameter choices | L |
| RFC 9180, *HPKE* | Mail ingress encryption | L |
| NIST SP 800-38D §8.3 | AES-GCM random-nonce limit | L |
| draft-irtf-cfrg-xchacha-03 | XChaCha20 nonce bounds | L |
| Len, Grubbs, Ristenpart, "Partitioning Oracle Attacks", USENIX Security 2021, ePrint 2020/1491 | Key commitment | L |
| Dodis, Grubbs, Ristenpart, Woodage, "Fast Message Franking" (Invisible Salamanders), CRYPTO 2018 | Key commitment | L |
| Albertini et al., "How to Abuse and Fix Authenticated Encryption Without Key Commitment", USENIX Security 2022, ePrint 2020/1456 | Key commitment | L |
| Chan, Rogaway, CTX, ePrint 2022/1260 | Key commitment options | L |
| Scarlata, Torrisi, Backendal, Paterson, "Zero Knowledge (About) Encryption", ePrint 2026/058, to appear at USENIX Security 2026 | Malicious-server attack classes ([§5](#5-server-controlled-parameter-attacks)) | L |
| W. Palant, "Bitwarden design flaw: server side iterations", 2023-01-23 | KDF downgrade ([§5.1](#51-kdf-parameter-downgrade)) | L |
| Backendal, Haller, Paterson, "MEGA: Malleable Encryption Goes Awry", IEEE S&P 2023 | Provider-side key recovery | L |
| 1Password security design white paper, Appendix A ("Beware of the leopard") | Web-client delivery risk; public-key substitution limitation | L |
| WAICT ([waict.dev](https://waict.dev/)); WEBCAT ([freedomofpress/webcat](https://github.com/freedomofpress/webcat), ePrint 2025/797) | Web-code integrity ([§4.2.1](#421-the-web-vault-delivery-problem)) | L |
| Marek Tóth, DOM-based extension clickjacking, DEF CON 33 (2025) | Extension clickjacking ([A7](#a7-malicious-web-page-scripts-against-the-extension)) | L |
| OWASP Password Storage Cheat Sheet | Argon2id minimums, for comparison | V |
| W3C WebAuthn Level 3 (REC) | M3 2FA, post-1.0 PRF unlock | V/L |
| RUSTSEC-2024-0421 (idna), RUSTSEC-2023-0071 (rsa) | Dependency constraints | V |
| M0 Argon2id measurement (argon2 0.6.0, Rust 1.94.1, 2.8 GHz Xeon vCPU, single runs) | Cost table in [A1](#a1-passive-server-compromise-db-or-backup-theft) | V |
| rustix 1.1.5 source (`process::set_dumpable_behavior`, `process::setrlimit` with `Resource::Core`; safe public API; licence Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT) | Core-dump suppression without `unsafe` in our crates ([INV-60](#8-security-invariants)) | V (crate source read locally) |
| IANA IPv4 and IPv6 Special-Purpose Address Registries (RFC 6890) | SSRF allow-list ([INV-51](#8-security-invariants)) | U (not re-read for this document) |
| Platform documentation: MV3 service-worker lifecycle and `chrome.storage` access levels; iCloud Backup and Android Auto Backup defaults; iOS keychain accessibility classes and biometry access control; Android Keystore user-authentication keys; Windows Hello key credentials; Linux `core(5)` and `prctl(2)` | [A8](#a8-stolen-or-lost-device), INV-60 to INV-63 | U (general knowledge, not re-read; each is confirmed in the milestone that implements it) |
