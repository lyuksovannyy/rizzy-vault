# ADR 0010: Server shape: modular monolith with roles

- Status: Proposed
- Date: 2026-09-25
- Deciders: project owner
- Milestone: M1 (`api`, `web`, `worker`) / M3 (`notify`, `icons`) / M6 (`smtp`)

## Context

The server stores ciphertext and metadata, runs OPAQUE, relays ops and serves the static web clients. Through M8 the typical deployment is one person or one family on one small machine. SMB deployments arrive in M10.

Most of the server handles authenticated clients and ciphertext. Two parts face a different kind of hostile input:
- **`smtp` (M6)** accepts mail from anyone on port 25. It holds plaintext mail in memory until it encrypts it ([THREAT_MODEL §6](../THREAT_MODEL.md#6-email-ingress-m6), AR-2).
- **`icons` (M3)** fetches URLs that users choose, indirectly. That is the classic SSRF setup ([THREAT_MODEL §7.11](../THREAT_MODEL.md#711-icons-role-m3)).

A code-execution bug in either one must not reach the database or the server secrets ([THREAT_MODEL](../THREAT_MODEL.md#13-security-goals) G-11, [INV-44, INV-51](../THREAT_MODEL.md#8-security-invariants)). `api`, `web`, `notify` and `worker` handle authenticated clients and ciphertext, and share one trust level.

[ROADMAP §4.9](../ROADMAP.md#49-server-self-hosting--ops-m1-onward) sets the frame:
- one Rust binary on axum, tokio and sqlx;
- one OCI image for Docker and Podman;
- rootless Podman tested in CI from M1;
- `smtp` isolated in its own container, with no DB access.

Crate facts (fact sheet, V): axum 0.8.9, tokio 1.53.1, sqlx 0.9.0.

This ADR is the only record of the server's shape. It is written so the owner can accept or reject it as a whole.

## Decision

### 1. One binary, selectable roles

The `rizzy-server` crate builds one binary, `rizzy-vault`. A process runs the roles given by `--roles` (or `RIZZY_ROLES`):

| Role | Does | DB access | Inbound | Outbound | From |
|---|---|---|---|---|---|
| `api` | OPAQUE, sessions, devices, vault and op log (Server mode), relay (On-device mode), shares, aliases, admin API, internal ingress endpoints for `smtp` | yes | public API through the reverse proxy; internal listener; admin listener | none | M1 |
| `web` | Serves the web vault and the share page from assets embedded in the binary (§4) | no | public, through the proxy | none | M1 |
| `worker` | Scheduled deletion: expired shares, relay batches past their TTL, mail past retention, expired auth state (§5). Deletes an item's server-side op bodies and snapshots only behind a client-signed snapshot or tombstone (compaction, [ADR 0012](0012-sync-engine.md) §7). **Does not purge trash** (below) | yes | none | SMTP relay for notification mail, if configured (M3) | M1 |
| `notify` | WebSocket/SSE wake-up signals to connected clients. No mobile push (open question 6) | yes (sessions) | public, through the proxy | none | M3 |
| `icons` | Fetches favicons, re-encodes them, caches them | **no** | public, through the proxy | the internet only | M3 |
| `smtp` | Receive-only SMTP, rspamd, pinning each account's identity key, sealing to the recipient's key, handing ciphertext to `api` | **no** | port 25 on the host (2525 in the container, §4) | rspamd, the `api` internal listener, DNS | M6 |

- **Default roles:** with no `--roles`, a process runs `api,web,worker`, plus `notify` from M3.
- **Admin API and metrics** bind a separate listener. The reverse proxy does not expose it by default ([THREAT_MODEL §7.14](../THREAT_MODEL.md#714-reverse-proxy--tls-terminator-m1)).
- **Why `worker` cannot purge trash.** Lifecycle (`Active` / `Trashed`) is an encrypted field inside op bodies, and a purge is a client-signed `Purge` op that any device issues ([ADR 0012](0012-sync-engine.md) §1, §5). The server cannot see which items are trashed or since when. Letting it purge would need a clear-text lifecycle column, which is a new metadata leak, and an unsigned server-side delete path. That is the unbound-item-state pattern ([THREAT_MODEL §5.3](../THREAT_MODEL.md#53-unbound-items-and-settings), ETH class 2). Trash is purged by whichever client is online after the retention period. [THREAT_MODEL §3.1 and §7.9](../THREAT_MODEL.md#79-worker-role-m1) say the same.

### 2. Isolation rules, enforced in code

- **`smtp` and `icons` run alone.** A process started with either role refuses to start if:
  - the role is combined with any other role, or
  - it can see any database setting (a URL or a SQLite path), or
  - it can see any server-secret file (the secrets file, [CRYPTO.md §5.11](../CRYPTO.md#511-server-side-encryption-not-zero-knowledge)).

  This turns [THREAT_MODEL Q-5](../THREAT_MODEL.md#10-open-questions-for-the-owner) and INV-44 into a startup check instead of a line in the docs. Tests cover each refusal.
- **`smtp` reaches `api` through exactly two internal endpoints.** They sit on the internal listener only and are authenticated with a per-deployment bearer secret, mounted as a file.
  1. `resolve(alias address, last pinned bundle_seq)` returns `accept(alias_id, the account's current key bundle and the bundle chain since that bundle_seq)` or `reject`. Unknown and disabled aliases get the same answer ([INV-47](../THREAT_MODEL.md#8-security-invariants)). `smtp` seals only to a mail key whose bundle chains from its pin ([CRYPTO.md §11.13](../CRYPTO.md#1113-mail-ingress-m6)).
  2. `deliver(alias_id, ciphertext, padded size)` returns `ok`.

  That secret opens nothing else. `api` rate-limits `resolve`, so a compromised `smtp` cannot enumerate aliases quickly. It can still enumerate them slowly; we accept that.
- **`icons` holds no credentials at all.**
  - It serves an anonymous shared cache with no per-user logs, and it is off by default ([THREAT_MODEL Q-11](../THREAT_MODEL.md#10-open-questions-for-the-owner)).
  - Its SSRF guard runs in the process and is an **allow-list** ([INV-51](../THREAT_MODEL.md#8-security-invariants)). It connects only to globally routable unicast addresses on ports 80 and 443, and it judges IPv4-mapped and NAT64 addresses by the embedded IPv4 address. The check runs after DNS resolution and on every redirect, and the connection goes to exactly the IP that was checked.
  - Container networks are a second layer, not the control. A default Docker or Podman network still routes to the host's LAN and to cloud metadata addresses.
- **With SQLite, one process writes the file.** Every DB role runs in that one process. At startup the server takes an exclusive writer lock on a lock file next to the database, and refuses to start if another process holds it. The file is never placed on a network filesystem ([ADR 0011](0011-storage.md)). The subcommands follow the same lock:
  - **`rizzy-vault backup` takes no writer lock.** It opens a read-only connection and reads inside one read transaction, which WAL allows next to the running server. It writes to stdout or to a path the operator names. So it works through `docker compose exec` or `podman exec` while the server runs. If the M1 test shows that a read-only reader in a second process cannot work next to the server, the fallback is a backup that the running server performs, triggered through the admin listener.
  - **`restore`, `migrate` and `secrets rotate` take the writer lock.** They run only while the server is stopped.
- **One active `worker` per database.** With PostgreSQL, a `worker` holds a session-level advisory lock on a **dedicated connection outside the sqlx pool**. A session-level lock belongs to one connection, so a lock taken on a pooled connection would be released silently whenever the pool recycles or drops that connection, while the worker kept running jobs. The worker checks that the connection and the lock are still alive before each job batch, and stops running jobs as soon as that connection drops. Extra `worker` replicas are hot standbys.

### 3. How roles communicate

- **Inside one process:** through Rust APIs and the in-process event bus, `rizzy-bus` ([ADR 0016](0016-workspace-layout.md)).
- **Between processes** (profile C):
  - `notify` learns about changes through PostgreSQL `LISTEN/NOTIFY`. Messages carry only IDs, as in "account X changed".
  - `api` replicas share short-lived auth state through the database (§5).
  - There is no Redis, NATS or other broker to run.
- **`smtp` → `api`:** HTTP on the internal network, as in §2.
- **`icons` and `web`** talk to no other role.

### 4. One image, three deployment profiles

One OCI image carries the one binary with every role.
- **Build:** multi-arch (amd64, arm64); a static musl binary; a distroless base; non-root UID; read-only root filesystem.
- **Writable paths:** the data volume (SQLite, and [ADR 0011](0011-storage.md)'s short-lived pre-migration copy); for `icons`, a cache volume; for `smtp` (M6), a small pin-store volume that holds, per account, the pinned identity key and the highest accepted `bundle_seq` ([CRYPTO.md §11.13](../CRYPTO.md#1113-mail-ingress-m6)). The pin store holds no secrets and no DB data, so the §2 startup checks still pass. Nothing else.
- **Server secrets are a separate, read-only mount** ([INV-50](../THREAT_MODEL.md#8-security-invariants), TB-5): a Docker or Podman secret, or a second volume at `/run/rizzy-secrets`, never under the data directory.
  - Why: self-hosters back up whole volumes (tar, restic, volume snapshots). With the secrets on the data volume, every such backup would hold the DB *and* the OPRF seed, which INV-50 exists to prevent. ADR 0011's pre-migration copy also sits in the data directory.
  - The server refuses to start if the secrets file resolves to a path inside the data directory. It never writes the secrets file. State that changes at run time, such as a used bootstrap token ([INV-69](../THREAT_MODEL.md#8-security-invariants)), is recorded in the DB.
  - `rizzy-vault secrets init` creates the secrets once, run as a one-off with the secrets mount writable. `rizzy-vault secrets rotate` ([CRYPTO.md §5.8](../CRYPTO.md#58-loss-or-rotation-of-the-server-opaque-secrets)) runs the same way. The compose files ship both as one-off services.
  - The compose files and backup docs show two volumes with different backup targets. ADR 0011's `backup-secrets` covers the secrets.
- **Web assets are embedded in the binary** ([THREAT_MODEL §7.7](../THREAT_MODEL.md#77-web-role-m1)), behind a cargo feature, `embed-web`, that is off by default.
  - The image build runs `pnpm build` for `apps/web`, then builds `rizzy-server` with `embed-web`. Release images always have it.
  - Without the feature, `web` serves a fixed page saying that this build has no web vault. Every Rust CI job (`cargo lint`, tests on three OSes, `cargo doc`) builds without it and needs no JavaScript toolchain.
  - Consequence: reproducible server images (M8) also need a reproducible `apps/web` build. The image-build CI job is listed in [ADR 0016](0016-workspace-layout.md) §5.
- **Ports.** Every listener inside the container uses an unprivileged port. `smtp` listens on 2525, and the host maps 25 → 2525, so the non-root UID never binds a privileged port.
  - Rootless Podman cannot publish host ports below 1024 unless the host lowers `net.ipv4.ip_unprivileged_port_start` (general knowledge; the M1 rootless CI job confirms it). This bites in M1 for 80 and 443, not only in M6 for 25.
  - The default compose file therefore publishes the TLS proxy on high host ports (8080 and 8443), and the rootless Podman CI job uses them. The docs cover the sysctl and a host firewall redirect for 80, 443 and 25.
- **Runtimes:** Docker and rootless Podman. `compose.yaml` works with both `docker compose` and `podman compose`, and rootless Podman runs in CI from M1 ([ROADMAP §4.9](../ROADMAP.md#49-server-self-hosting--ops-m1-onward)). Quadlet units come in M3.
- **Supply chain:** cosign signatures, SBOM and provenance come in M8.

| Profile | Containers | DB | For | From |
|---|---|---|---|---|
| **A: solo** | 1 × `rizzy-vault` (`api,web,worker`; `notify` from M3), plus the TLS reverse proxy | SQLite on the data volume; secrets on their own mount | one person or one family | M1 |
| **B: solo + mail** | A, plus `rizzy-vault --roles smtp`, plus rspamd | SQLite | A with aliases | M6 |
| **C: team** | `api,web,notify` in 1–N containers, sharing auth state through PostgreSQL (§5); `worker` with the leader lock; `smtp` and rspamd as in B; the TLS reverse proxy | PostgreSQL | families who want PostgreSQL, SMB | M3 (PostgreSQL); M10 (HA guide) |

`icons`, when enabled, is one more container in any profile.

**Networks** in the B and C compose files:
- `edge`: reverse proxy ↔ `api`, `web`, `notify`, `icons`
- `ingress`: `smtp` ↔ the `api` internal listener
- `mail`: `smtp` ↔ rspamd
- `db`: DB roles ↔ PostgreSQL

`smtp` joins only `ingress` and `mail`, plus its published port. `icons` joins only `edge`, plus outbound internet.

**TLS** ends at the operator's reverse proxy, which is a second container in every profile. The M1 compose file ships a Caddy example. The binary has no ACME client in M1 (open question 3).

### 5. Short-lived auth state lives in the database

From M1, on both engines, every piece of short-lived auth state lives in `auth_` tables, never in process memory:
- OPAQUE `ServerLogin` state, keyed by `login_id`, with a 60 s TTL ([CRYPTO.md §5.10](../CRYPTO.md#510-sessions-after-authentication)). It carries key-confirmation material: a live DB reader who saw it in the clear could complete a login that is in flight. It is therefore stored sealed under a server key from the secrets mount, like the 2FA secrets ([INV-8](../THREAT_MODEL.md#8-security-invariants)): as `SERVER_LOGIN_STATE`, and the 2FA secrets as `SERVER_TOTP_SECRET` ([CRYPTO.md §5.11](../CRYPTO.md#511-server-side-encryption-not-zero-knowledge));
- device-auth challenges, with a 60 s TTL (CRYPTO.md §5.10);
- rate-limit and backoff counters per (account, source), and per-IP signup limits ([ROADMAP §4.9](../ROADMAP.md#49-server-self-hosting--ops-m1-onward), [CRYPTO.md §5.9](../CRYPTO.md#59-account-enumeration));
- pending recoveries and their waiting periods ([CRYPTO.md §11.9](../CRYPTO.md#119-recovery-with-the-emergency-kit)).

Each read-and-update of these rows is one transaction under [ADR 0011](0011-storage.md)'s per-account lock. `worker` deletes expired rows.

Why: in profile C, a KE3 message or a challenge response can land on any `api` replica. Per-replica counters would also multiply an attacker's guess budget by the number of replicas. On SQLite this costs a few row writes per login, which does not matter at personal scale, and the same code serves both engines. The state also survives a restart.

## Consequences

### Positive

- A personal user runs one `rizzy-vault` container plus a TLS proxy, with one data volume and one secrets mount.
- The two components that take hostile input run without DB credentials, without server secrets and without a network path to the DB. That is where the threat model puts the boundary.
- A volume-level backup of the data volume no longer contains the OPRF seed.
- There is one artifact to build, scan, sign and version, and every role in a deployment runs the same version.
- No distributed transactions. Account deletion, key rotation and mode switches are single DB transactions.
- Any `api` replica can finish any login, and rate limits hold across replicas.
- Splitting a role out later is a deployment change, not a rewrite, because crate boundaries already separate the roles ([ADR 0016](0016-workspace-layout.md)).

### Negative

- The `smtp` and `icons` containers carry the storage code, although it cannot run there. Isolation comes from configuration, startup checks and network placement, not from the code being absent. A code-execution bug in `smtp` gets a binary that knows how to talk to PostgreSQL, but no credentials and no route to it.
- A vulnerable dependency in any role, for example the MIME parser, means a new image for every user, including users who never enabled mail.
- Binary size and build time grow with every role.
- With SQLite, profiles A and B are limited to one writing process. Scaling out means moving to PostgreSQL.
- Two mounts instead of one. Operators must back up the secrets mount separately, and losing that backup has the consequences in [CRYPTO.md §5.8](../CRYPTO.md#58-loss-or-rotation-of-the-server-opaque-secrets).
- Every login attempt and challenge writes rows, where process memory would do for a single process. This does not matter at personal scale; measure it for M10.
- The server image depends on a JavaScript build, so a reproducible server image needs a reproducible `apps/web` build.
- If open question 6 goes as recommended, mobile apps get no push in v1.0 and rely on background refresh.

### Risks

- Operators will try to run `smtp` inside the main container to save effort. The startup refusal stops this, and the docs explain why.
- Mounting the SQLite volume into two server containers would break the one-writer rule. The lock file stops the second process.
- An operator who backs up the whole host captures DB and secrets together again. So does one who moves the secrets directory into the data volume by hand. The startup check catches the second case, not the first; the backup docs say so.
- If mail becomes the main source of CVEs, "one binary" turns into a liability. The split criteria below say when to act.

## Alternatives considered

**Microservices: separate binaries and images, one database per service.** Rejected.

- *What it would give us:*
  - smaller dependency trees per service, e.g. an `smtp` image with no DB code in it at all;
  - independent releases and independent scaling;
  - fault isolation;
  - clear ownership once there are several teams.
- *Why not now:*
  - A personal self-hoster would run five to seven containers plus a message broker, to store a few megabytes of ciphertext.
  - Account deletion, key rotation, mode switches and relay purges each touch several domains. With a DB per service they become sagas with partial-failure states. That is where "no silent data loss" breaks.
  - Every service boundary is one more authenticated network API to design, test and audit.
  - Versioning N services against each other costs work and gives users nothing at this size.
  - The security split we actually need, `smtp` and `icons`, we already get with roles.

*Criteria for splitting further.* Any one of these justifies moving a role into its own binary, and then its own image, through a new ADR:
1. The role needs a dependency we do not want in the main binary, for security or licence reasons. Examples: a C library for mail filtering, or a licence outside `deny.toml`'s allow-list.
2. Production measurements show one role hurting the others (for example, `icons` image decoding raises `api` p99 latency), and running it as a separate container of the same image does not fix it.
3. The role needs a release cadence that one shared release blocks, such as weekly security fixes to `smtp`.
4. The role is written in another language or runtime.
5. A separate maintainer owns a domain end to end.

The first candidate is `smtp`. Its crate already has no path to storage ([ADR 0016](0016-workspace-layout.md)), so a separate `rizzy-smtp` binary in the same image is a cheap first step.

**A plain monolith without roles**, everything always on in one process. Rejected: it puts the MIME parser and the URL fetcher next to the DB credentials and the OPRF seed, which G-11 forbids.

**Auth state in process memory**, with profile C limited to one `api` replica, or to sticky sessions, until a later ADR. Rejected. Sticky sessions do not survive a replica restart, per-replica rate limits multiply the guess budget, and two code paths for the same state would drift. The database is already there.

**Server secrets on the data volume**, next to SQLite. Rejected. It is simpler to set up, but every volume-level backup then carries the seed with the DB (INV-50).

**Each instance calls APNs and FCM directly.** Not possible for the official apps. APNs and FCM accept pushes only with the credentials of the Apple developer account or Firebase project that owns the app, and the project cannot give those to every self-hoster. See open question 6.

**Postfix or Haraka in front, instead of our own `smtp` role.** Not decided here; [ROADMAP §5](../ROADMAP.md#5-architecture-decisions-to-make-in-m0-with-current-recommendation) leaves it to an M6 spike. The role model works either way: behind a front MTA, `smtp` becomes the handoff receiver, under the same isolation rules.

**Kubernetes first** (Helm, operators). Not a target before M10 ([ROADMAP §4.9](../ROADMAP.md#49-server-self-hosting--ops-m1-onward), Could). Profile C runs on Kubernetes with no change to the binary.

## Open questions for the owner

1. **Accept or reject this ADR.** It is the only record of the server's shape. *Recommendation:* accept.
2. **`smtp` refuses to start when DB configuration is visible** ([THREAT_MODEL Q-5](../THREAT_MODEL.md#10-open-questions-for-the-owner)). This makes profile B mandatory for mail. *Recommendation:* yes.
3. **Built-in TLS with ACME,** so that profile A needs no reverse proxy. *Recommendation:* not in M1; ship the Caddy example. Revisit in M3 if setup reports show the proxy is the main hurdle. A built-in ACME client means new TLS-adjacent code and a new dependency, and it would still face the rootless port limit in §4.
4. **Authentication for `smtp` → `api`:** a bearer secret on an isolated network, or mutual TLS. *Recommendation:* the bearer secret for M6. Use mTLS only if profile C deployments span several hosts.
5. **`icons` off by default** ([THREAT_MODEL Q-11](../THREAT_MODEL.md#10-open-questions-for-the-owner)). *Recommendation:* yes.
6. **Mobile push (M7).** Each self-hosted instance cannot push to the official apps itself (see Alternatives). Options:
   - (a) A project-run push relay that forwards content-free wake-ups, with one credential per instance. Bitwarden runs such a relay for self-hosted servers, and Vaultwarden can use it (general knowledge, not re-verified). It is a hosted service that [ROADMAP §4.9](../ROADMAP.md#49-server-self-hosting--ops-m1-onward) does not plan. It would see every device's push token, which instance the token belongs to, and when each wake-up is sent. Apple and Google see the token and the timing in any design that uses their push.
   - (b) No push. The apps sync on OS background refresh and in the foreground.
   - (c) UnifiedPush on Android, through a distributor that the user or admin runs.

   *Recommendation:* (b) for v1.0, and (c) as an Android opt-in if users ask. The Should row "push on mobile in M7" in [ROADMAP §4.8](../ROADMAP.md#48-aliases--email-receiving-m6) then changes to background refresh, which is a ROADMAP edit for the owner. Payloads carry no content under any option ([INV-54](../THREAT_MODEL.md#8-security-invariants)).

## References

- [ROADMAP](../ROADMAP.md) §4.8, §4.9, §5 (rows "Server shape" and "Mail ingress"), §6.3
- [THREAT_MODEL](../THREAT_MODEL.md) §3, §5.3, §6, §7.6–§7.14, G-11, INV-8, INV-44, INV-47, INV-50, INV-51, INV-54, INV-69, Q-5, Q-11
- [CRYPTO.md](../CRYPTO.md) §5.8 (server secrets), §5.9, §5.10 (login state and challenges), §11.9 (pending recoveries), §11.13 (mail sealing)
- [ADR 0011](0011-storage.md) (transactions, backups), [ADR 0012](0012-sync-engine.md) (§1, §5 trash and purge; §7 compaction), [ADR 0016](0016-workspace-layout.md)
- Fact sheet 2026-09-25: axum 0.8.9, tokio 1.53.1, sqlx 0.9.0 (V)
- Rootless Podman's port limit and the APNs/FCM credential model: general knowledge, not re-verified for this ADR
