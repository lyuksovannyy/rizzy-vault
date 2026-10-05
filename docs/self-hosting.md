# Self-hosting rizzy-vault

This guide is for the operator of a rizzy-vault server: install, configuration, the secrets file, TLS, upgrades, and backup and restore. It describes **this build** (M1, in progress). Where the build is missing something the design requires, the guide says so in a **Gap** note. Do not work around a gap: wait for the release that closes it.

The design behind this guide: [ADR 0010](adr/0010-server-shape.md) (server shape, deployment profiles), [ADR 0011](adr/0011-storage.md) (storage, migrations, backups), [CRYPTO.md §5.8 and §5.11](CRYPTO.md#58-loss-or-rotation-of-the-server-opaque-secrets) (server secrets), and [THREAT_MODEL.md §5.8](THREAT_MODEL.md#58-server-restore-from-backup) (restore from backup).

Contents:
1. [What you run](#1-what-you-run)
2. [Install](#2-install)
3. [First run](#3-first-run)
4. [Configuration reference](#4-configuration-reference)
5. [The secrets file](#5-the-secrets-file)
6. [TLS, the reverse proxy and ports](#6-tls-the-reverse-proxy-and-ports)
7. [Upgrades and migrations](#7-upgrades-and-migrations)
8. [Backup](#8-backup)
9. [Restore](#9-restore)
10. [The restore drill](#10-the-restore-drill)
11. [Logs](#11-logs)
12. [Checklist](#12-checklist)

## 1. What you run

One image holds one binary, `rizzy-vault`, with every role ([ADR 0010](adr/0010-server-shape.md) §1). The M1 roles are `api` (login, devices, vault sync), `web` (the web vault page) and `worker` (expired-state purges, compaction). **Profile A (solo)**, the M1 profile, runs all three in one container on SQLite, behind a TLS reverse proxy:

```text
 clients ──HTTPS──▶ proxy (Caddy) ──HTTP──▶ rizzy-vault (api,web,worker)
                    host ports 8080/8443     │            │
                                             ▼            ▼
                              volume rizzy-vault-data   volume rizzy-vault-secrets (read-only)
                              (SQLite database)         (OPAQUE seed, server keys)
```

The files are in [`deploy/`](../deploy/):

| File | What it is |
|---|---|
| [`Containerfile`](../deploy/Containerfile) | The image: a static musl binary on distroless, non-root (UID 65532), read-only root filesystem |
| [`compose.yaml`](../deploy/compose.yaml) | Profile A for `docker compose` and `podman compose`, the one-off admin commands, and a commented PostgreSQL variant |
| [`Caddyfile`](../deploy/Caddyfile) | The TLS proxy: certificate from ACME, everything forwarded to `rizzy-vault` |
| [`rizzy-vault.env.example`](../deploy/rizzy-vault.env.example) | The settings `compose.yaml` reads; copy it to `deploy/.env` |

The server keeps two kinds of data, on two volumes, with **different backup targets** ([ADR 0010](adr/0010-server-shape.md) §4, [INV-50](THREAT_MODEL.md#8-security-invariants)):

- `rizzy-vault-data`: the SQLite database. Ciphertext and the metadata [THREAT_MODEL §3.4](THREAT_MODEL.md#34-what-the-server-holds-by-sync-mode) lists; no plaintext, no server secret.
- `rizzy-vault-secrets`: the server secrets file. With it, a stolen database backup allows offline password guessing against every account. Without it, nobody can log in with a password.

Never put both into one backup, one archive or one volume.

**Not in this build** (M1 is in progress):
- A verified image build with the web vault. [`deploy/Containerfile`](../deploy/Containerfile) now builds the web vault (`apps/web`, M1 step 5) and embeds it with the `embed-web` feature ([ADR 0010](adr/0010-server-shape.md) §4): a `wasm` stage (wasm-bindgen-cli at the locked version, `cargo xtask build-wasm`), a `web` stage (Node.js 24, pnpm, `pnpm install --frozen-lockfile`, `pnpm run build`), then the server. That image build has not been run end to end yet; until it has, check that `/` of a new image serves the web vault, not the fixed "no web vault in this build" page. To build a binary with it from source instead: `pnpm install --frozen-lockfile`, `pnpm run build:wasm` (needs `wasm-bindgen-cli` at the locked version), `pnpm run build`, then `cargo build --locked --release -p rizzy-server --bin rizzy-vault --features embed-web`. The API is complete for the M1 clients.
- PostgreSQL as a supported setup (M3). This build runs every M1 role on it, the `worker` included (one active worker per database, the others wait as standbys), but its PostgreSQL tests are not run in CI yet, and the PostgreSQL side of the instance lock, of `restore`, `migrate` and `secrets rotate` ([§9](#9-restore)) has not been run against a real PostgreSQL server at all. Do not rely on it before M3.
- The admin panel and API (M3), `notify`, `icons` (M3), `smtp` (M6), Quadlet units (M3), signed images (M8).

**Core dumps are off.** A crash must never write the server's memory (keys, the OPAQUE secrets, session state) to disk ([INV-60](THREAT_MODEL.md#8-security-invariants), [ADR 0024](adr/0024-core-dump-disabling-rustix.md)). Before it reads its configuration, `rizzy-vault` sets its core-file limit (`RLIMIT_CORE`) to 0 and, on Linux, marks itself non-dumpable (`PR_SET_DUMPABLE` 0); it reads both back and refuses to start (exit 1, `cannot disable core dumps: ...` on stderr) if either did not take. There is no setting to turn this off. As defence in depth, [`compose.yaml`](../deploy/compose.yaml) also sets `ulimits: core: 0` on every container; under systemd, set `LimitCORE=0` in the unit. On the host, the kernel's `core_pattern` is global to all containers: if it pipes to a crash collector (`systemd-coredump`, `apport`, `abrt`) and `fs.suid_dumpable` is 2, check that the collector stores nothing for this container ([AR-10](THREAT_MODEL.md#9-accepted-risks-and-out-of-scope); whether such a collector can still capture a non-dumpable process is unverified).

## 2. Install

Requirements: a Linux host (amd64 or arm64) with Docker and the compose plugin, or Podman 4+ with `podman compose`; a DNS name pointing at the host. The database must live on a local filesystem, **never on NFS or SMB** ([ADR 0011](adr/0011-storage.md), SQLite settings): named volumes on a local disk are fine.

```sh
git clone https://github.com/lyuksovannyy/rizzy-vault
cd rizzy-vault/deploy
cp rizzy-vault.env.example .env
$EDITOR .env                      # RIZZY_DOMAIN and RIZZY_ORIGIN, see §4 and §6
docker compose build              # or: podman compose build
```

There is no published image yet: CI builds the image for `linux/amd64` and `linux/arm64` on every pull request but pushes nothing, and its publish jobs stay off unless the project owner enables them (they would push unsigned development builds to `ghcr.io`; signed images are M8). `docker compose build` builds `localhost/rizzy-vault:dev` from the repository ([`deploy/Containerfile`](../deploy/Containerfile)). Building needs network access to the base images' registry (`docker.io`), to crates.io (`index.crates.io`, `static.crates.io`), to the npm registry (`registry.npmjs.org`, for pnpm and the web vault's locked JavaScript dependencies), and to `static.rust-lang.org`: the repository's `rust-toolchain.toml` pins a toolchain with `rustfmt`, `clippy` and the `wasm32-unknown-unknown` target, and rustup downloads whatever of it the base image lacks. Behind an egress allow-list or a registry mirror, allow all four. For both architectures at once: `docker buildx build --platform linux/amd64,linux/arm64 -f deploy/Containerfile -t <name> ..` (from `deploy/`), or `podman build --platform linux/amd64,linux/arm64 --manifest <name> -f deploy/Containerfile ..`.

Every command in this guide runs from `deploy/`. With Podman, replace `docker` by `podman`.

## 3. First run

**Create the secrets, once:**

```sh
docker compose --profile admin run --rm secrets-init
```

This writes `/run/rizzy-secrets/secrets.json` in the `rizzy-vault-secrets` volume, mode 0600: the OPAQUE server setup, `enum_key`, the first data key and the first-run bootstrap token ([CRYPTO.md §5.11](CRYPTO.md#511-server-side-encryption-not-zero-knowledge)). It never overwrites an existing file. **Back it up now** ([§5](#5-the-secrets-file)).

**Start:**

```sh
docker compose up -d
docker compose logs rizzy-vault
```

A healthy start logs `database_created` (first start only) and `listening`. A start that fails logs why and exits; see [§4](#4-configuration-reference) for configuration errors (exit code 2). The server refuses to start if the secrets file is inside the data directory, if it does not fit the database (a different setup, a missing data key), or, with SQLite, if another process holds the database's writer lock (with PostgreSQL: while `restore`, `migrate`, `secrets rotate` or `secrets retire-setups` holds the instance lock, [§9](#9-restore)), or if the secrets file holds an OPAQUE setup the database marks retired ([§5](#5-the-secrets-file)).

**Create the first accounts.** Signup is `closed` by default, and the admin panel that issues invites comes in M3. Until then:

1. set `RIZZY_SIGNUP=open` in `.env` and `docker compose up -d` (the container restarts with the new value);
2. create the accounts from the clients;
3. set `RIZZY_SIGNUP=closed` and `docker compose up -d` again.

While signup is open, anyone who reaches the server can create an account (rate-limited per source and per name, [CRYPTO.md §5.9](CRYPTO.md#59-account-enumeration)). Keep that window short, or restrict the proxy to your own addresses for it (Caddy's `remote_ip` matcher).

**The bootstrap token** ([INV-69](THREAT_MODEL.md#8-security-invariants)) is in the secrets file. This build never prints or logs it; its only reader is the M3 admin API, which shows it once. Nothing to do with it now.

## 4. Configuration reference

Settings are `RIZZY_*` names. Each comes from the environment, or from a configuration file named by `--config <path>` or `RIZZY_CONFIG`; the environment wins over the file, and `--roles` wins over both. The file holds `NAME=value` lines; blank lines and lines starting with `#` are skipped; there is no quoting or interpolation; an unknown or repeated name is refused, so a misspelt setting never passes silently. **No setting is ever taken from the command line except `--roles` and `--config`**, so the database URL cannot leak through the process list.

| Setting | Default | Meaning |
|---|---|---|
| `RIZZY_ORIGIN` | – (required by `api` and `worker`) | The canonical origin clients use, for example `https://vault.example.com` or `https://vault.example.com:8443`. It is bound into OPAQUE and every device signature: **changing it later locks every account out**. It must be an `https://` origin: the server refuses to start with an `http://` one, unless the host is `localhost` or a loopback address (`127.0.0.1`, `[::1]`), which is for local testing only. |
| `RIZZY_ROLES` | `api,web,worker` | Comma-separated roles. `notify`, `icons` and `smtp` are refused in this build. |
| `RIZZY_LISTEN` | `127.0.0.1:8080` (the image sets `0.0.0.0:8080`) | The HTTP listener of `api` and `web`. Plain HTTP: always behind the TLS proxy. |
| `RIZZY_DATA_DIR` | `/data` | The data volume: `rizzy-vault.sqlite3`, its WAL, its lock file, and the pre-migration copy. |
| `RIZZY_DATABASE_URL` | – (SQLite in the data directory) | A `postgres://` URL. Not supported before M3 (see `compose.yaml`). It may carry the password; it is never logged or printed. It is the one setting that can hold a secret: a configuration file that holds it must be readable by the server's user only (the server does not check the file's mode). |
| `RIZZY_SECRETS_FILE` | `/run/rizzy-secrets/secrets.json` | The secrets file. Must resolve outside the data directory, or the server refuses to start. |
| `RIZZY_SIGNUP` | `closed` | `closed` or `open` ([§3](#3-first-run)). |
| `RIZZY_TRUSTED_PROXIES` | empty | Comma-separated IP addresses of the reverse proxies whose `X-Forwarded-For` is believed: single IPv4 or IPv6 addresses, as the listener sees them, with no CIDR prefix, port, brackets or host name (a proxy pool lists every address); a value that does not parse refuses the start. `compose.yaml` sets the proxy's fixed address. Rate limits count per client address (per /64 for IPv6), so without it every client shares the proxy's budget. List only infrastructure you control, never an address a client can connect from: a listed address can name any source. A listed proxy must set `X-Forwarded-For` on every request, or the API answers `400` ([§6](#6-tls-the-reverse-proxy-and-ports)). |
| `RIZZY_LOG_LEVEL` | `info` | `error`, `warn`, `info` or `debug`. |
| `RIZZY_WORKER_INTERVAL_SECS` | `60` | Seconds between two worker runs, 1 to 86400. |
| `RIZZY_MAX_UPLOAD_BYTES` | `33554432` (32 MiB) | Body limit of vault uploads, restore healing and the account commit that carries a key rotation, 32 MiB to 256 MiB. The proxy must allow at least this much (Caddy has no limit by default). |
| `RIZZY_RECOVERY_WAIT_HOURS` | `72` | The recovery waiting period in whole hours, 0 to 720 (30 days); anything else refuses the start. See "The recovery waiting period" below. |

**The recovery waiting period** ([ADR 0008](adr/0008-account-recovery.md) decision 5, [CRYPTO.md §11.9](CRYPTO.md#119-recovery-with-the-emergency-kit)). A user who lost every device recovers the account with the recovery code from the Emergency Kit. A valid code does not release the account at once: it opens a pending recovery, and the server releases the account only `RIZZY_RECOVERY_WAIT_HOURS` later. During the wait, any enrolled device of the account can cancel the recovery. That is what protects a user whose printed kit was stolen: the thief has to wait, and the user's own device can say no.
- **Default 72 h.** Keep it unless you have a reason. Longer (up to 30 days) gives users more time to notice; shorter gives a thief less to wait out.
- **0 means no wait:** kit plus server access is an immediate takeover, and the account's devices get no time to cancel. Use 0 only on an instance with a single account, where you are the only user and the kit is yours ([THREAT_MODEL Q-15](THREAT_MODEL.md#10-open-questions-for-the-owner)). The server does not check how many accounts exist; it logs `recovery_wait_zero` at every start as a reminder.
- **A change applies to recoveries started after the restart.** A recovery that is already pending keeps the release time it was opened with.
- The wait is enforced by the server. It protects against a kit thief, not against whoever runs the server.
- In this build a change of the setting is not recorded in the users' security event log (that log is part of the M3 admin work, [INV-69](THREAT_MODEL.md#8-security-invariants)); tell your users when you change it.
- With `compose.yaml`, set it in `.env`; the server container reads it from there.

`compose.yaml` also reads these, for the containers around the server: `RIZZY_DOMAIN` (the proxy's host name), `RIZZY_HTTP_PORT` and `RIZZY_HTTPS_PORT` (the proxy's host ports, default 8080 and 8443), `RIZZY_IMAGE`, `RIZZY_PROXY_IMAGE`, `RIZZY_EDGE_SUBNET`, `RIZZY_PROXY_IP`, and `RIZZY_SECRETS_BACKUP_DIR` (the host directory `backup-secrets` writes to, default `./backup-secrets`, [§5](#5-the-secrets-file)).

**Commands** of the binary (`docker compose --profile admin run --rm <service>` runs the matching one-off service):

| Command | One-off service | Needs |
|---|---|---|
| `rizzy-vault [serve] [--roles <list>]` | `rizzy-vault` | – |
| `rizzy-vault secrets init` | `secrets-init` | the secrets volume writable |
| `rizzy-vault secrets rotate [--data-key]` | `secrets-rotate` | the server stopped (it takes the SQLite writer lock, or the PostgreSQL instance lock); the secrets volume writable; with `--data-key`, the data volume too ([§5](#5-the-secrets-file)) |
| `rizzy-vault secrets retire-setups [--grace-days <n>]` | `secrets-retire-setups` | the server stopped (it takes the SQLite writer lock, or the PostgreSQL instance lock); the secrets and data volumes writable ([§5](#5-the-secrets-file)) |
| `rizzy-vault backup-secrets --out <file> --passphrase-file <file\|->` | `backup-secrets` | the secrets volume (read-only is enough) |
| `rizzy-vault migrate` | `migrate` | the server stopped (it takes the SQLite writer lock, or the PostgreSQL instance lock) |
| `rizzy-vault backup --out <file\|->` | none: `docker compose exec` into the running server ([§8](#8-backup)) | nothing: it runs next to the server |
| `rizzy-vault restore --in <file\|->` | `restore` (reads standard input) | the server stopped (it takes the SQLite writer lock, or the PostgreSQL instance lock), an empty database, the instance's secrets file ([§9](#9-restore)) |

The one-off services of `compose.yaml` are written for SQLite: they mount the data volume and have no network. On PostgreSQL, `migrate`, `restore`, `secrets-rotate` and `secrets-retire-setups` also need `RIZZY_DATABASE_URL` and the database's network, like the server.

Exit codes: 0 success, 1 a runtime failure, 2 a usage or configuration error. Messages name the setting or file that failed, never a value.

## 5. The secrets file

What it holds: every OPAQUE server setup (the OPRF seed and server keypair) by `setup_id`, `enum_key` (fake login answers for unknown names), every server data key by `data_key_id` (they seal 2FA secrets and in-flight login state), and the bootstrap token ([CRYPTO.md §5.11](CRYPTO.md#511-server-side-encryption-not-zero-knowledge)).

**Handling.**
- It lives on its own volume, `rizzy-vault-secrets`, mounted **read-only** into the server. Only `secrets init`, `secrets rotate` and `secrets retire-setups` mount it writable, as one-offs. The server never writes it.
- Mode 0600, owned by UID 65532. Nothing else on the host needs to read it.
- Instead of the named volume you may bind-mount a host directory, a Docker or Podman secret, or a systemd credential at `/run/rizzy-secrets` ([ADR 0010](adr/0010-server-shape.md) §4). Never inside the data directory: the server refuses that.
- A whole-host backup (a VM snapshot, a backup of `/var/lib/docker`) captures the database and the secrets together, which is exactly what INV-50 forbids. Exclude one of the two volumes from such a backup, or encrypt that backup as carefully as the secrets themselves.

**Back it up** with `backup-secrets`, which encrypts the file under a passphrase of your choice ([ADR 0011](adr/0011-storage.md) owner decision 3). The passphrase comes from a file or standard input, never from the command line:

`backup-secrets` writes into its own staging directory, `RIZZY_SECRETS_BACKUP_DIR` (default `./backup-secrets`, that is `deploy/backup-secrets`). It is **not** the directory the database archives go to ([§8](#8-backup) uses `./backup-db`): the two must never share a directory, an archive or a backup job. Better, point `RIZZY_SECRETS_BACKUP_DIR` in `.env` at a directory outside the repository checkout. Both default directories are in `.gitignore` and `.dockerignore`.

```sh
mkdir -p backup-secrets
sudo chown 65532:65532 backup-secrets && sudo chmod 0700 backup-secrets     # Docker (rootful)
# podman unshare chown 65532:65532 backup-secrets && chmod 0700 backup-secrets   # rootless Podman
docker compose --profile admin run --rm -T backup-secrets < ~/rizzy-backup-passphrase
sudo mv backup-secrets/rizzy-secrets-backup.json /somewhere/safe/rizzy-secrets-$(date +%F).json
```

The file is written with mode 0600 and never overwrites, so move it away before the next run; do not leave it in the staging directory, and never point a host backup tool at that directory together with `backup-db`. Keep it, and the passphrase, **apart from the database backups** (another medium, another location, another account), and make a new one after every `secrets rotate`.

> **Gap: no command reads the encrypted backup yet.** No Accepted ADR names a command that restores the secrets from a `backup-secrets` file, so this build has none (the decryption code exists and is tested, see [§10](#10-the-restore-drill)). Until that command ships, a `backup-secrets` file alone does not let you restore. Also keep a copy of `secrets.json` itself, encrypted with a tool you trust (for example `age` or `gpg`) and stored apart from the database backups. Write it straight to its safe place, never into the repository checkout or next to the database archives:
>
> ```sh
> docker run --rm -v rizzy-vault-secrets:/s:ro --user 65532:65532 docker.io/library/alpine:3 \
>   cat /s/secrets.json | age -p > /somewhere/safe/rizzy-secrets-$(date +%F).json.age
> ```
>
> In this build that encrypted copy is the **only** way to restore the secrets.

**Rotation** ([CRYPTO.md §5.8](CRYPTO.md#58-loss-or-rotation-of-the-server-opaque-secrets), §5.11): `secrets rotate` adds a new OPAQUE setup, which new registrations use; an existing account moves to it the next time a client logs in, or unlocks an enrolled device, with the typed password (a transparent re-registration with the same password, [ADR 0031](adr/0031-retiring-old-opaque-setups.md)). `secrets rotate --data-key` adds a new data key and marks it current. Stop the server first (every replica, on PostgreSQL; the command refuses otherwise):

```sh
docker compose stop rizzy-vault
docker compose --profile admin run --rm secrets-rotate
docker compose start rizzy-vault
```

**After `secrets rotate --data-key`:**
1. The old data keys stay in the file and keep opening what they sealed, so the server starts as before.
2. The running server's worker re-seals every 2FA secret under the new key, account by account. Its `worker_run` log line counts them in `totp_rows_resealed`; an instance without 2FA has nothing to re-seal. `totp_reseal_failures` above 0 (and a `worker_totp_reseal_skipped` line) means a row could not be opened with the key it names: that account's 2FA is broken already, and its old key is kept.
3. The old key is **removed from the file by the next `secrets rotate --data-key`**, once no row names it; the command prints which keys it dropped. The server never writes the secrets file, so nothing drops a key while it runs, and this build has no command that drops a key without adding a new one.
4. Make a new secrets backup after every rotation, and **keep the previous one as long as you keep database backups taken before the 2FA secrets were re-sealed**: such a backup still names the old key, and `restore` refuses it when the secrets file no longer holds that key ([§9](#9-restore) step 4).

**Retiring old OPAQUE setups** ([CRYPTO.md §5.8](CRYPTO.md#58-loss-or-rotation-of-the-server-opaque-secrets) step 4, [ADR 0031](adr/0031-retiring-old-opaque-setups.md)): `secrets retire-setups --grace-days N` (default 90, 0 to 3650) retires every OPAQUE setup that is not the current one and whose successor the server recorded at least N days ago (the successor is recorded at the first server start after `secrets rotate`). Stop the server first, as for `secrets rotate`:

```sh
docker compose stop rizzy-vault
docker compose --profile admin run --rm secrets-retire-setups          # default: 90 days
# docker compose --profile admin run --rm secrets-retire-setups secrets retire-setups --grace-days 0
docker compose start rizzy-vault
```

- It prints, per retired setup, its `setup_id`, when its successor was recorded and how many accounts are still on it (ids and counts only). Those accounts lose password login at the next start: they log in through an enrolled device, which moves them to the current setup with the typed password, or with their recovery code. A web-only account without a device needs its recovery code, and its login only says "wrong password".
- `--grace-days 0` retires at once, for a setup you know leaked; it asks for no confirmation.
- It marks the setups retired in the database (and drops pending logins), then rewrites the secrets file without them. The server refuses to start with a secrets file that holds a retired setup ("run `secrets retire-setups` again"): after a crash between the two steps, or with an old secrets backup, run the command again (any `--grace-days`) and it finishes.
- The server never retires a setup by itself. Its worker logs `opaque_setup_retirable` (the `setup_id` and the count) at most once a day for a setup whose successor is more than 90 days old.
- Make a new secrets backup afterwards: an old one still holds the retired setups, and a leaked old backup is a leaked setup.

**If the secrets are lost** and no backup exists, nobody can log in with a password: the OPAQUE records cannot be used without their setup. The design's way out is that users with an enrolled device re-register OPAQUE from that device the next time they type their password, and others use their recovery code ([CRYPTO.md §5.8](CRYPTO.md#58-loss-or-rotation-of-the-server-opaque-secrets)). Starting the old database with a new secrets file is refused (the setup does not match), which is what you want.

> **Gap: this build has no re-registration or recovery endpoint.** The HTTP API of this build has no OPAQUE re-registration, recovery, password-change, device-revocation or key-rotation request. So **losing the secrets without a restorable copy locks every account out for good** in this build: there is no path back for any user. Since `backup-secrets` files cannot be read back yet (the gap above), the `age`/`gpg` copy of `secrets.json` is your only working restore path. Make it now, and check that you can decrypt it.

## 6. TLS, the reverse proxy and ports

TLS ends at the reverse proxy, a second container ([ADR 0010](adr/0010-server-shape.md) §4). The binary has no TLS and no ACME client in M1. `compose.yaml` ships Caddy, which obtains and renews a certificate for `RIZZY_DOMAIN` automatically and forwards everything to `rizzy-vault:8080`.

**Ports.** Rootless Podman cannot publish host ports below 1024 by default, so `compose.yaml` publishes the proxy on **8080 (HTTP) and 8443 (HTTPS)**. You then have two choices:
- **Serve on 443** (recommended): let the host forward 80 → 8080 and 443 → 8443 (a firewall redirect, for example with nftables), or allow unprivileged ports (`sysctl net.ipv4.ip_unprivileged_port_start=80`) and set `RIZZY_HTTP_PORT=80`, `RIZZY_HTTPS_PORT=443`. With rootful Docker, setting the two variables is enough. `RIZZY_ORIGIN` is then `https://<domain>`.
- **Serve on 8443**: `RIZZY_ORIGIN=https://<domain>:8443`. Caddy's automatic certificate needs ports 80 or 443 reachable from the internet for the ACME challenge, so on high ports you need a DNS-challenge Caddy build or your own certificate (`tls /path/cert.pem /path/key.pem` in the `Caddyfile`).

Whichever you choose, `RIZZY_ORIGIN` must be exactly the origin users type, and it must not change afterwards.

**What `rv` needs from the certificate** ([ADR 0030](adr/0030-client-tls-rv.md)). The command-line client speaks **TLS 1.3 only** (Caddy offers it by default; a proxy configured for TLS 1.2 alone is refused) and checks the certificate against Mozilla's root CAs built into `rv`, not the operating system's store. A certificate from a public CA, such as Caddy's automatic one, needs nothing more. With your own certificate (the `tls /path/cert.pem /path/key.pem` line above) issued by a **private CA**, users give `rv` that CA's certificate with `--ca-file <path>` or `RIZZY_CLI_CA_FILE` ([rv.md](rv.md#tls-and-a-private-ca)); it then replaces the public roots for them. The certificate must name the host (or IP address) of `RIZZY_ORIGIN`.

**A self-signed server certificate does not work with `rv`**, not even in the CA file: `rv` has no certificate pinning, so it refuses a CA file holding any certificate that is not a CA certificate (`CA:FALSE`, or no basic constraints), and the verifier it uses refuses a CA certificate (`cA=true`) as the server's own certificate. Make a small CA instead and issue the server certificate from it: one CA certificate with `CA:TRUE`, kept with its key away from the server, and a server certificate with `CA:FALSE`, `extendedKeyUsage=serverAuth` and a `subjectAltName` for your domain. Give `rv` the CA certificate, and Caddy the server certificate and its key. The OpenSSL commands in [`crates/rizzy-cli/tests/fixtures/tls/README.md`](../crates/rizzy-cli/tests/fixtures/tls/README.md) show the shape (use your own names and a sensible validity, and never those test files).

**Another proxy** (nginx, Traefik, HAProxy) works if it ([ADR 0028](adr/0028-api-v1-http-conventions.md) items 5, 9 and 11):
- terminates TLS and forwards plain HTTP/1.1 to port 8080 on a network the clients cannot reach directly. The listener is plaintext only because that hop is trusted (loopback, or a private network you control); never publish it directly;
- serves rizzy-vault at the **root of the origin** and forwards the path and query **byte for byte**. Native clients sign the exact request-target they send, so a proxy that strips or adds a path prefix, or that rewrites, normalises or re-encodes the target (merging `//`, resolving `.` and `..`, changing the case of a percent-encoding) makes every signed request fail with `401`. The proxy may rewrite `Host`: it is not signed, the origin is;
- **sets `X-Forwarded-For` on every request**: it replaces (does not append to) a client-sent value, or appends the client address as the last entry. The server reads the header from the right, skipping trusted proxies, and only its last 16 field lines and 1024 bytes. Each entry is a bare IPv4 or IPv6 address: no port, no brackets, no `unknown`;
- has its own address in `RIZZY_TRUSTED_PROXIES`, and no other;
- accepts request bodies up to `RIZZY_MAX_UPLOAD_BYTES`;
- does not compress responses, and does not log request bodies or the `Authorization` header.

**A listed proxy that sends no usable `X-Forwarded-For` breaks the API.** When the connection comes from an address in `RIZZY_TRUSTED_PROXIES` and the header is missing, malformed, or names only trusted proxies, every `/api/v1` request is answered `400 invalid_request`. The server never falls back to the proxy's own address, because every user behind it would then share one rate-limit budget. If all clients get `400` after you set `RIZZY_TRUSTED_PROXIES`, check that the proxy sets the header (the shipped `Caddyfile` does). `GET /api/meta` and the web page are served regardless, so a health check from the proxy host still works.

**Rate limits.** A client that is rate-limited gets `429` with a `Retry-After` header in whole seconds; clients wait that long before they try again. Do not strip the header at the proxy.

**Memory.** Request bodies are bounded per `api` process: at most 8 requests with the upload limit are read at once, plus 1 MiB for each other connection (1024 connections at most), about 1.25 GiB of bodies at the default `RIZZY_MAX_UPLOAD_BYTES` and 3 GiB at the 256 MiB maximum, and more while they are parsed. Several `api` processes have no shared cap: size each for it, and limit connections at the proxy.

The server sets HSTS, CSP and the other security headers itself ([INV-49](THREAT_MODEL.md#8-security-invariants)), sends no CORS header and does not compress. It logs no IP address; if your proxy keeps access logs, they do, and you decide their retention.

**Health check:** `GET https://<domain>/api/meta` answers 200. The image has no shell or HTTP client, so there is no in-container `HEALTHCHECK`.

## 7. Upgrades and migrations

Migrations are forward-only and embedded in the binary ([ADR 0011](adr/0011-storage.md) points 8–9). There are no down-migrations: **a downgrade is a restore of the backup taken before the upgrade.**

On SQLite the server migrates at startup. Only when a migration is pending, it first writes a consistent copy of the database next to it, `rizzy-vault.sqlite3.pre-migration` (mode 0600). It holds everything the database held before the upgrade, deleted data included ([AR-11](THREAT_MODEL.md#9-accepted-risks-and-out-of-scope)), for as long as it exists.

**When the copy goes away.** The worker deletes it once **one server process** has run for 24 h after passing its startup checks. That time is kept in memory only, so **every restart starts the 24 h again**: a server restarted more often than once a day, which includes a daily native backup ([§8](#8-backup) stops and starts it), never deletes the copy. Once you have checked the upgrade (the server starts, users can log in and sync), delete the copy yourself:

```sh
docker run --rm -v rizzy-vault-data:/data --user 65532:65532 docker.io/library/alpine:3 \
  rm -f /data/rizzy-vault.sqlite3.pre-migration
```

The §8 backup also leaves it out of the database archives.

> **Gap: no account deletion in this build.** ADR 0011 point 9 also has an account deletion delete the copy at once. This build has no account-deletion request, so nothing but the worker and you deletes it.

To upgrade, keep the server stopped from the backup until the new image starts, so that the backup is the last state the old release wrote:

```sh
git pull && docker compose build                 # or pull the new image, once published
docker compose stop rizzy-vault
mkdir -p backup-db                               # the §8 backup, without its final `start`
docker run --rm -v rizzy-vault-data:/data:ro -v "$PWD/backup-db:/backup" docker.io/library/alpine:3 \
  tar -C /data --exclude=./rizzy-vault.sqlite3.pre-migration \
      -czf "/backup/rizzy-data-$(date +%Y%m%dT%H%M%S).tar.gz" .
docker compose up -d                             # starts the new image; never `start` in between
docker compose logs rizzy-vault                  # database_migrated_after_copy, then listening
```

To run the migration as its own step (for example to see it succeed before serving), run `docker compose --profile admin run --rm migrate` while the server is stopped. On PostgreSQL (M3) this step is required: a server that finds a pending migration there refuses to start and names the command. There, `migrate` takes the instance lock ([§9](#9-restore)): stop every server process of the database first, all replicas and roles, or it refuses.

If the upgraded server does not start, keep the old image, restore the pre-upgrade backup ([§9](#9-restore)), and report the problem.

## 8. Backup

**What to back up:**

| What | How | Where to keep it |
|---|---|---|
| The database (`rizzy-vault-data`) | `rizzy-vault backup` below; also the native copy, for losing the disk | With your data backups, encrypted at rest |
| The secrets (`rizzy-vault-secrets`) | `backup-secrets`, plus the encrypted copy of [§5](#5-the-secrets-file) | **Apart** from the database backups |
| `deploy/.env`, `deploy/Caddyfile` | Any | Anywhere (no secret in profile A) |

### The logical backup: `rizzy-vault backup`

`rizzy-vault backup` writes the whole database, every table as rows, to one file in the engine-neutral format of [ADR 0023](adr/0023-logical-backup-format.md). It reads one consistent snapshot on a read-only connection and takes no lock, so it runs **next to the running server**, which keeps serving. Pipe it straight into an encryption tool, so the unencrypted file never touches the disk (Docker; the same with `podman`):

```sh
set -o pipefail                                  # bash/zsh: a failed backup fails the pipeline
mkdir -p backup-db
docker compose exec -T rizzy-vault /usr/local/bin/rizzy-vault backup --out - \
  | age -r age1yourpublickey... > "backup-db/rizzy-db-$(date +%Y%m%dT%H%M%S).rvbackup.age"
```

`--out -` writes the file to standard output (refused when that is a terminal); `--out <file>` writes a new file with mode 0600 instead and never overwrites one. The command prints the file's size and its **SHA-256** on stderr: record it with the archive. The file name is yours to choose.

What the file is, and is not:
- **Integrity, not authentication.** The file ends with a SHA-256 of everything before it; `restore` checks it before reading anything, so a truncated or corrupted file is refused. It does not stop a deliberate edit: anyone who can write the file can recompute it. Protect the archives like the database itself.
- **Not encrypted.** It holds what the database holds: every user's ciphertext, login names, device metadata, OPAQUE records and timestamps ([THREAT_MODEL §3.4](THREAT_MODEL.md#34-what-the-server-holds-by-sync-mode)). It never holds the server secrets ([INV-50](THREAT_MODEL.md#8-security-invariants)), but a database backup **plus** the secrets allows offline password guessing, so encrypt it (`age` above, or your backup tool's encryption) and store it apart from the secrets backup.
- **Tied to its release.** It restores only with a release of the same database schema version. After an upgrade, take a new backup; to restore an older one, use the release that wrote it, then upgrade ([§7](#7-upgrades-and-migrations)).
- **At most 2 GiB** in this release, which reads the whole file into memory. `backup` refuses to write a larger one, so every backup it writes can be restored. Sessions and in-flight login state are not in it: after a restore every user signs in again.

It works the same on PostgreSQL (one `REPEATABLE READ` snapshot), and the same pair moves an instance from SQLite to PostgreSQL: `backup` on the SQLite instance, `restore` into the empty PostgreSQL database ([§9](#9-restore)).

### The native copy, for losing the disk

A copy of the SQLite files, taken with the server stopped ([ADR 0011](adr/0011-storage.md)'s native method). Restoring it puts the files back as they were and **opens no reconciliation epoch** ([§9](#9-restore)), so use it only to recover from losing the database, never to undo a change; `rizzy-vault restore` of a logical backup is the restore that protects users.

**Why stopped.** The running server holds the database's single writer, so no second process can take a `VACUUM INTO` copy; the image has no `sqlite3` tool; and copying the files of a live WAL database can produce an inconsistent copy. Stopping takes a few seconds: in-flight requests finish (at most 30 s) and the worker stops. The WAL file (`rizzy-vault.sqlite3-wal`) can still hold recent, acknowledged writes after the stop, so a backup is always the whole directory, never the main file alone.

**Native backup** (Docker; the same with `podman`):

```sh
mkdir -p backup-db
docker compose stop rizzy-vault
docker run --rm -v rizzy-vault-data:/data:ro -v "$PWD/backup-db:/backup" docker.io/library/alpine:3 \
  tar -C /data --exclude=./rizzy-vault.sqlite3.pre-migration \
      -czf "/backup/rizzy-data-$(date +%Y%m%dT%H%M%S).tar.gz" .
docker compose start rizzy-vault
```

The archives go to `deploy/backup-db`, a directory of their own: never the `backup-secrets` staging directory of [§5](#5-the-secrets-file), and never a directory a secrets copy is written to. Better, use a directory outside the repository checkout (replace `$PWD/backup-db`). Point your backup tool at this directory only.

This archives the data volume: the database, its WAL and shared-memory files (the WAL holds acknowledged writes; never separate it from the database file) and the lock file (harmless). It leaves out the pre-migration copy ([§7](#7-upgrades-and-migrations)), which is not needed to restore and would keep pre-upgrade data in every archive. Encrypt the archive before it leaves the host (for example `age -p`, or your backup tool's encryption): it holds every user's ciphertext, login names, device metadata and timestamps ([THREAT_MODEL §3.4](THREAT_MODEL.md#34-what-the-server-holds-by-sync-mode)), and a database backup plus the secrets allows offline password guessing.

**Retention.** Old backups keep old data: deleted items, and key wraps that a password change does not invalidate ([AR-11](THREAT_MODEL.md#9-accepted-risks-and-out-of-scope)). Keep only as many as you need. Deleted ciphertext also survives in the WAL, `rizzy-vault.sqlite3-wal`, until a checkpoint: `secure_delete` overwrites deleted data in the database file, not in the WAL ([ADR 0011](adr/0011-storage.md), SQLite settings). So every native archive can hold recently deleted data, and so can the live volume, until the next checkpoint (AR-11).

**Schedule** both with the host's cron or a systemd timer: the logical backup as often as you like (the server keeps running), the native copy less often (the server is down for the few seconds the archive takes). Check the backups with the drill ([§10](#10-the-restore-drill)).

## 9. Restore

**Read this first: what a restore does to users** ([THREAT_MODEL §5.8](THREAT_MODEL.md#58-server-restore-from-backup)). A restore rolls **every** account back to the backup. Lost vault changes are the easy part: devices that still hold them re-upload them. The hard part is that a restore also brings back, until the users' devices correct it:
- **revoked devices**, which can authenticate again;
- **old passwords**: a password changed after the backup works again (with the Secret Key);
- **old recovery codes**: an Emergency Kit replaced after the backup works again.

**The reconciliation-epoch notice.** The design's defence is the reconciliation epoch ([INV-59](THREAT_MODEL.md#8-security-invariants)): `rizzy-vault restore` puts every restored account into a reconciliation epoch and draws a new restore generation ([ADR 0021](adr/0021-server-compaction.md) §2). Devices that reconnect then re-upload their newest signed account state, their bundle chain and every device revocation they hold; the server adopts the newest valid state and from then on refuses the old password, the old recovery code and the revoked devices. Until some device of an account reconnects, that account stays exposed, and accounts whose devices never reconnect stay rolled back ([AR-19](THREAT_MODEL.md#9-accepted-risks-and-out-of-scope)). An enrolled device re-registers the password the next time the user types it; recovery stays refused until the user repairs it from an enrolled device (`rv recovery repair`).

**Key rotations made after the backup** ([ADR 0032](adr/0032-healing-rotation-after-backup.md)): every standalone rotation, device revocation, Secret Key change and full rotation is healed by the first enrolled device that saw it and reconnects (`rv sync`, or any command that goes online). It re-publishes the bundle chain, the newer account state with every certificate and revocation, the identity keys wrapped under the current account key, the settings, and each vault's self-grant with its wrap set, then the vault records; the server checks each repair against the signed state it now holds, inside or outside the reconciliation epoch. Two things wait for the users:
- **Logins.** Until a device of the account re-registers the login record (at its next unlock with the master password, which `rv` does in the same run), a new login with the correct password is refused with `credentials_stale`, and `rv login` says so. A device that missed the rotation logs in with the password to catch up once that is done.
- **Recovery.** The recovery code stays refused until the user runs `rv recovery repair --name <login>` on an enrolled device: a new code and Emergency Kit, or with `--retype` the current code when it did not change since the backup.

An account used only from the web vault has no device that can heal it, and stays as the backup left it ([AR-19](THREAT_MODEL.md#9-accepted-risks-and-out-of-scope)). A native restore opens no reconciliation epoch: the newer state is never taken back, and users repeat their changes.

### `rizzy-vault restore`

`rizzy-vault restore` loads a `rizzy-vault backup` file into an **empty** database, with the server stopped. In order ([ADR 0023](adr/0023-logical-backup-format.md) §5), it:
1. shuts every server process out, with the SQLite writer lock or the PostgreSQL instance lock (below; it refuses while a server runs), and checks that the database is empty: no row, and either new or at exactly this release's schema;
2. reads the file (at most 2 GiB) and checks its magic, format version and SHA-256 before anything else, then parses it strictly;
3. requires the backup's schema version to be this release's;
4. checks the secrets file against the backup, as the server's startup check does: the OPAQUE setups the backup records must be the secrets file's, and every data key a 2FA row names must be in it. A fresh secrets file is refused; restore the instance's own secrets first;
5. loads every row in one transaction, draws a **new restore generation** and puts **every account into a reconciliation epoch**;
6. prints the number of rows and of accounts in reconciliation, and the notice above.

Any failure leaves the database without a single application row (it may be left migrated to this release's schema), so you can fix the cause and run it again.

Procedure (Docker; the same with `podman`). Keep the current database aside first if it holds anything you may need (a native archive, [§8](#8-backup)):

```sh
docker compose stop rizzy-vault
docker run --rm -v rizzy-vault-data:/data docker.io/library/alpine:3 \
  sh -c 'find /data -mindepth 1 -delete && chown 65532:65532 /data && chmod 0700 /data'
age -d backup-db/rizzy-db-YYYYMMDDTHHMMSS.rvbackup.age \
  | docker compose --profile admin run --rm -T restore
docker compose start rizzy-vault
docker compose logs rizzy-vault        # expect: listening
```

If the secrets volume was lost too, restore it **before** running `restore` (below). `restore` exits with 0 on success, 1 when it refused or failed (a running server, a non-empty database, a damaged file, another schema version, secrets that do not belong to the backup), and 2 on a usage error.

### The PostgreSQL instance lock

SQLite has one writing process, and a lock file next to the database proves it. PostgreSQL has no such file, and several server processes may share one database. So that `restore`, `migrate` and `secrets rotate` can still prove that no server is using the database ([ADR 0023](adr/0023-logical-backup-format.md) §5 step 1):

- **Every server process** that opens the database (`api`, `worker`, any replica) holds a PostgreSQL session-level advisory lock in **shared** mode, on a dedicated connection outside its pool, from startup until it has closed its pools. A `web`-only process opens no database and holds nothing.
- **`restore`, `migrate` and `secrets rotate`** take the same lock in **exclusive** mode, without waiting. If any server process still holds it, they refuse (exit 1, "the database's instance lock is held") and change nothing: stop every replica and run the command again. While one of them runs, a server refuses to start; it starts normally once the command has finished.
- **The key** is the single `bigint` advisory key `8247886433088438273` (`0x7276610300000001`). In `pg_locks` it shows as `locktype = 'advisory'`, `classid = 1920360707`, `objid = 1`, `objsubid = 1`, with `mode` `ShareLock` for a server and `ExclusiveLock` for an admin command. To see who holds it:

  ```sql
  SELECT pid, mode, granted FROM pg_locks
  WHERE locktype = 'advisory' AND classid = 1920360707 AND objid = 1 AND objsubid = 1;
  ```

  Do not take advisory locks with this key from anything else that uses the database. (The worker's leader lock and the per-account locks use the two-integer key space, `classid` `1920360706` and `1920360705` with `objsubid = 2`.)
- **If a server loses the lock** (its dedicated connection dropped: a database restart, a failover, a network cut, `pg_terminate_backend`), it notices at its next check, at most 15 s later plus a 10 s timeout, logs `instance_lock_lost` and **exits with code 1** without the usual shutdown grace. A restart policy (`restart: unless-stopped` in `compose.yaml`) brings it back, and it takes the lock again. In that short window an admin command would be granted the lock although the server still runs, so stop the servers yourself before `restore`, `migrate` or `secrets rotate`; do not rely on the lock alone.
- A connection pooler in transaction mode (PgBouncer) does not keep a session, and a session-level lock needs one: point `RIZZY_DATABASE_URL` at PostgreSQL itself, or at a pooler in session mode.
- `backup` takes no lock and runs next to the servers.

> **Not run against PostgreSQL yet.** The PostgreSQL tests of this lock exist but need a PostgreSQL server (`RIZZY_TEST_POSTGRES_URL`) and are not part of CI before M3; in this build they have not been run. Treat PostgreSQL restores as untested until then.

### The native restore, for losing the disk

A native restore puts the files back as they were: **no reconciliation epoch is opened and the restore generation does not change** (the automated drill pins this, [§10](#10-the-restore-drill)). So after a native restore:
- the old passwords, old recovery codes and revoked devices of the backup are accepted **and reconnecting devices do not close them**: the server accepts the newer state they hold only during a reconciliation epoch;
- clients cannot see that a restore happened through the restore generation, so ADR 0021's rules for changes that were in flight at backup time do not apply; such changes can be lost or reported as a conflict.

Use a native restore **only to recover from losing the database when no logical backup is recent enough**, never to undo an unwanted change, and do the "after a restore" steps below.

**Native restore** (the server stopped; Docker, the same with `podman`):

```sh
docker compose stop rizzy-vault
docker run --rm -v rizzy-vault-data:/data -v "$PWD/backup-db:/backup:ro" docker.io/library/alpine:3 \
  sh -c 'find /data -mindepth 1 -delete \
         && tar -C /data -xzf /backup/rizzy-data-YYYYMMDDTHHMMSS.tar.gz \
         && chown -R 65532:65532 /data && chmod 0700 /data'
docker compose start rizzy-vault
docker compose logs rizzy-vault        # expect: listening
```

**If the secrets volume was lost too**, restore it **before** `rizzy-vault restore` or before starting the server, from your encrypted copy of `secrets.json` ([§5](#5-the-secrets-file)):

```sh
age -d /somewhere/safe/rizzy-secrets-YYYY-MM-DD.json.age | docker run --rm -i -v rizzy-vault-secrets:/s docker.io/library/alpine:3 \
  sh -c 'umask 077 && cat > /s/secrets.json && chown -R 65532:65532 /s && chmod 0700 /s'
```

The server refuses to start against a database whose OPAQUE setup does not match the secrets file ([CRYPTO.md §5.8](CRYPTO.md#58-loss-or-rotation-of-the-server-opaque-secrets)): the database and the secrets must belong to the same instance. Never run `secrets init` to "fix" that: new secrets cannot open the restored accounts.

**After a restore:**
1. Tell every user that the server was restored to a backup of `<date>`, and ask them to open each of their devices soon, so the devices detect the rollback ([INV-25](THREAT_MODEL.md#8-security-invariants)) and re-upload what the server lost.
2. Security changes made after the backup (a password change, a device revocation, a recovery-code replacement) are undone by the restore. The design heals them when a device of the account reconnects during the reconciliation epoch that `rizzy-vault restore` opens (a native restore opens none, see above), and otherwise has users repeat them. **In this build** `rv` heals them as [§9](#9-restore) says, key rotations included ([ADR 0032](adr/0032-healing-rotation-after-backup.md)); tell users who had recovery on to run `rv recovery repair` once their devices are online again.
3. Accounts whose devices never reconnect stay as the backup left them.

## 10. The restore drill

A backup you have never restored is a hope, not a backup ([ROADMAP §4.9](ROADMAP.md#49-server-self-hosting--ops-m1-onward): "tested, not just written").

**Automated (runs with `cargo test`).** [`crates/rizzy-server/tests/drill.rs`](../crates/rizzy-server/tests/drill.rs) runs the backup → wipe → restore drill in a fast form, against real SQLite files, through the functions the binary runs: `secrets init`, a populated instance, a start with the startup checks, `rizzy-vault backup` to a file next to the running server, `backup-secrets`, the native copy, a wipe, the secrets restored byte for byte from the encrypted backup, `rizzy-vault restore` of the backup file into an empty database, and a restart. It checks that the data reads back exactly, that the restore draws a new restore generation and opens a reconciliation epoch for every account (INV-59), that the backup file holds none of the secrets file's secrets (INV-50: every OPAQUE server setup, `enum_key`, every data key and the bootstrap token, searched for both as bytes and as their base64url text), and that a restore next to the running server, into a non-empty database, with a fresh secrets file, or of a damaged file is refused, as is a wrong passphrase. It also checks the warning of [§9](#9-restore): a native copy restored in place starts, but keeps the old restore generation and opens no epoch. `crates/rizzy-server/tests/cli.rs` runs the two commands as processes: through a pipe and a file, the digest on stderr, and the refusals.

> **Gap: the full drill of ADR 0011 is automated on SQLite only.** ADR 0011 requires simulated clients that change a password, enrol and revoke devices and rotate keys after the backup, then reconnect to the restored server and heal it, on SQLite and PostgreSQL. `rv`'s end-to-end tests run it on SQLite against the built binary: a restore after an enrolment and after vault edits (`crates/rizzy-cli/tests/e2e.rs`), and after a standard rotation, a revocation with a full rotation, a password change and a Secret Key change with a full rotation, with the login record re-registered, a device that missed the rotation catching up and the recovery repair ([ADR 0032](adr/0032-healing-rotation-after-backup.md); `crates/rizzy-cli/tests/healing.rs`). The same drill against PostgreSQL is not run yet.

**Manual, on your own backups (monthly, and after every upgrade).** Restore the newest backups into **scratch volumes**, start a server on them **with no network**, and check that it passes its startup checks. The scratch server never talks to clients: it would honour the backup's old credentials.

```sh
docker volume create rizzy-drill-data && docker volume create rizzy-drill-secrets
docker run --rm -v rizzy-drill-data:/data docker.io/library/alpine:3 \
  sh -c 'chown 65532:65532 /data && chmod 0700 /data'
age -d /somewhere/safe/rizzy-secrets-YYYY-MM-DD.json.age | docker run --rm -i -v rizzy-drill-secrets:/s docker.io/library/alpine:3 \
  sh -c 'umask 077 && cat > /s/secrets.json && chown -R 65532:65532 /s && chmod 0700 /s'
age -d backup-db/rizzy-db-YYYYMMDDTHHMMSS.rvbackup.age \
  | docker run --rm -i --network none --read-only --tmpfs /tmp --user 65532:65532 \
      -v rizzy-drill-data:/data -v rizzy-drill-secrets:/run/rizzy-secrets:ro \
      localhost/rizzy-vault:dev restore --in -
# expect "restored N rows; M accounts are in a reconciliation epoch ..."
docker run --rm --network none --read-only --tmpfs /tmp \
  -e RIZZY_ORIGIN=https://vault.example.com \
  -v rizzy-drill-data:/data -v rizzy-drill-secrets:/run/rizzy-secrets:ro \
  localhost/rizzy-vault:dev serve
# expect the line with "event":"listening"; then Ctrl-C
docker volume rm rizzy-drill-data rizzy-drill-secrets
```

`restore` succeeding means the file is intact (its SHA-256 matches), was written by this release's schema, and belongs to these secrets; `listening` means the server's startup checks accept the result. Drill the native archives the same way, unpacking one into the scratch data volume (as in [§9](#9-restore)) instead of running `restore`. Also try your passphrase on the newest `backup-secrets` file once the command that reads it exists ([§5](#5-the-secrets-file)).

## 11. Logs

The server writes one JSON object per line to stderr: `ts_ms`, `level`, `event`, and fields that are integers or fixed strings. By construction it never logs secrets, tokens, request bodies, headers, login names, file paths or IP addresses ([INV-48](THREAT_MODEL.md#8-security-invariants)). Retention is the container runtime's: `compose.yaml` keeps at most 5 files of 10 MB (`json-file` driver); change `logging` there. Rootless Podman may ignore some of these options; check `podman inspect` and set `log_size_max` in `containers.conf` if needed.

## 12. Checklist

- [ ] `RIZZY_ORIGIN` is the exact `https://` origin users type, and will not change.
- [ ] The secrets volume is mounted read-only into the server and is not inside the data volume.
- [ ] A `backup-secrets` file **and** an encrypted copy of `secrets.json` exist, stored apart from the database backups; the passphrase is stored safely.
- [ ] Database backups (`rizzy-vault backup`) run on a schedule, are encrypted, and are pruned; their SHA-256 is recorded.
- [ ] No backup holds both volumes (whole-host snapshots included).
- [ ] The database is on a local disk, not NFS or SMB.
- [ ] `RIZZY_SIGNUP` is `closed` outside the first-accounts window.
- [ ] `RIZZY_TRUSTED_PROXIES` lists exactly the proxy, and the proxy sets `X-Forwarded-For` on every request and forwards the path and query unchanged.
- [ ] The manual drill of [§10](#10-the-restore-drill) passed this month.
- [ ] Base images are pinned by digest if you build your own image.
- [ ] The host's crash collector (if `core_pattern` pipes to one) stores no dumps of the rizzy-vault container ([§1](#1-what-you-run)).
