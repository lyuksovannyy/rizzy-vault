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
- The web vault (M1 step 5): the `web` role serves a fixed "no web vault in this build" page. The API is complete for the M1 clients.
- `rizzy-vault backup` and `rizzy-vault restore` (see [§8](#8-backup) and [§9](#9-restore)).
- PostgreSQL as a supported setup (M3). This build runs every M1 role on it, the `worker` included (one active worker per database, the others wait as standbys), but its PostgreSQL tests are not run in CI yet.
- The admin panel and API (M3), `notify`, `icons` (M3), `smtp` (M6), Quadlet units (M3), signed images (M8).

## 2. Install

Requirements: a Linux host (amd64 or arm64) with Docker and the compose plugin, or Podman 4+ with `podman compose`; a DNS name pointing at the host. The database must live on a local filesystem, **never on NFS or SMB** ([ADR 0011](adr/0011-storage.md), SQLite settings): named volumes on a local disk are fine.

```sh
git clone https://github.com/lyuksovannyy/rizzy-vault
cd rizzy-vault/deploy
cp rizzy-vault.env.example .env
$EDITOR .env                      # RIZZY_DOMAIN and RIZZY_ORIGIN, see §4 and §6
docker compose build              # or: podman compose build
```

There is no published image yet: CI builds the image for `linux/amd64` and `linux/arm64` on every pull request but pushes nothing, and its publish jobs stay off unless the project owner enables them (they would push unsigned development builds to `ghcr.io`; signed images are M8). `docker compose build` builds `localhost/rizzy-vault:dev` from the repository ([`deploy/Containerfile`](../deploy/Containerfile)). Building needs network access to the base images' registry (`docker.io`), to crates.io (`index.crates.io`, `static.crates.io`), and to `static.rust-lang.org`: the repository's `rust-toolchain.toml` pins a toolchain with `rustfmt`, `clippy` and the `wasm32-unknown-unknown` target, and rustup downloads whatever of it the base image lacks. Behind an egress allow-list or a crates.io mirror, allow all three. For both architectures at once: `docker buildx build --platform linux/amd64,linux/arm64 -f deploy/Containerfile -t <name> ..` (from `deploy/`), or `podman build --platform linux/amd64,linux/arm64 --manifest <name> -f deploy/Containerfile ..`.

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

A healthy start logs `database_created` (first start only) and `listening`. A start that fails logs why and exits; see [§4](#4-configuration-reference) for configuration errors (exit code 2). The server refuses to start if the secrets file is inside the data directory, if it does not fit the database (a different setup, a missing data key), or, with SQLite, if another process holds the database's writer lock.

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
| `RIZZY_ORIGIN` | – (required by `api` and `worker`) | The canonical origin clients use, for example `https://vault.example.com` or `https://vault.example.com:8443`. It is bound into OPAQUE and every device signature: **changing it later locks every account out**. |
| `RIZZY_ROLES` | `api,web,worker` | Comma-separated roles. `notify`, `icons` and `smtp` are refused in this build. |
| `RIZZY_LISTEN` | `127.0.0.1:8080` (the image sets `0.0.0.0:8080`) | The HTTP listener of `api` and `web`. Plain HTTP: always behind the TLS proxy. |
| `RIZZY_DATA_DIR` | `/data` | The data volume: `rizzy-vault.sqlite3`, its WAL, its lock file, and the pre-migration copy. |
| `RIZZY_DATABASE_URL` | – (SQLite in the data directory) | A `postgres://` URL. Not supported before M3 (see `compose.yaml`). It may carry the password; it is never logged or printed. |
| `RIZZY_SECRETS_FILE` | `/run/rizzy-secrets/secrets.json` | The secrets file. Must resolve outside the data directory, or the server refuses to start. |
| `RIZZY_SIGNUP` | `closed` | `closed` or `open` ([§3](#3-first-run)). |
| `RIZZY_TRUSTED_PROXIES` | empty | Comma-separated IP addresses of the reverse proxies whose `X-Forwarded-For` is believed. `compose.yaml` sets the proxy's fixed address. Rate limits count per client address, so without it every client shares the proxy's budget. Never list an address a client can connect from. |
| `RIZZY_LOG_LEVEL` | `info` | `error`, `warn`, `info` or `debug`. |
| `RIZZY_WORKER_INTERVAL_SECS` | `60` | Seconds between two worker runs, 1 to 86400. |
| `RIZZY_MAX_UPLOAD_BYTES` | `33554432` (32 MiB) | Body limit of vault uploads, 32 MiB to 256 MiB. The proxy must allow at least this much (Caddy has no limit by default). |

`compose.yaml` also reads these, for the containers around the server: `RIZZY_DOMAIN` (the proxy's host name), `RIZZY_HTTP_PORT` and `RIZZY_HTTPS_PORT` (the proxy's host ports, default 8080 and 8443), `RIZZY_IMAGE`, `RIZZY_PROXY_IMAGE`, `RIZZY_EDGE_SUBNET`, `RIZZY_PROXY_IP`, and `RIZZY_SECRETS_BACKUP_DIR` (the host directory `backup-secrets` writes to, default `./backup-secrets`, [§5](#5-the-secrets-file)).

**Commands** of the binary (`docker compose --profile admin run --rm <service>` runs the matching one-off service):

| Command | One-off service | Needs |
|---|---|---|
| `rizzy-vault [serve] [--roles <list>]` | `rizzy-vault` | – |
| `rizzy-vault secrets init` | `secrets-init` | the secrets volume writable |
| `rizzy-vault secrets rotate [--data-key]` | `secrets-rotate` | the server stopped (it takes the writer lock); the secrets volume writable |
| `rizzy-vault backup-secrets --out <file> --passphrase-file <file\|->` | `backup-secrets` | the secrets volume (read-only is enough) |
| `rizzy-vault migrate` | `migrate` | the server stopped (SQLite) |

Exit codes: 0 success, 1 a runtime failure, 2 a usage or configuration error. Messages name the setting or file that failed, never a value.

## 5. The secrets file

What it holds: every OPAQUE server setup (the OPRF seed and server keypair) by `setup_id`, `enum_key` (fake login answers for unknown names), every server data key by `data_key_id` (they seal 2FA secrets and in-flight login state), and the bootstrap token ([CRYPTO.md §5.11](CRYPTO.md#511-server-side-encryption-not-zero-knowledge)).

**Handling.**
- It lives on its own volume, `rizzy-vault-secrets`, mounted **read-only** into the server. Only `secrets init` and `secrets rotate` mount it writable, as one-offs. The server never writes it.
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

**Rotation** ([CRYPTO.md §5.8](CRYPTO.md#58-loss-or-rotation-of-the-server-opaque-secrets), §5.11): `secrets rotate` adds a new OPAQUE setup, which new registrations use; existing accounts keep theirs until their next password change. `secrets rotate --data-key` adds a new data key and marks it current; the old ones stay in the file and keep opening what they sealed. Stop the server first:

```sh
docker compose stop rizzy-vault
docker compose --profile admin run --rm secrets-rotate
docker compose start rizzy-vault
```

**If the secrets are lost** and no backup exists, nobody can log in with a password: the OPAQUE records cannot be used without their setup. The design's way out is that users with an enrolled device re-register OPAQUE from that device the next time they type their password, and others use their recovery code ([CRYPTO.md §5.8](CRYPTO.md#58-loss-or-rotation-of-the-server-opaque-secrets)). Starting the old database with a new secrets file is refused (the setup does not match), which is what you want.

> **Gap: this build has no re-registration or recovery endpoint.** The HTTP API of this build has no OPAQUE re-registration, recovery, password-change, device-revocation or key-rotation request. So **losing the secrets without a restorable copy locks every account out for good** in this build: there is no path back for any user. Since `backup-secrets` files cannot be read back yet (the gap above), the `age`/`gpg` copy of `secrets.json` is your only working restore path. Make it now, and check that you can decrypt it.

## 6. TLS, the reverse proxy and ports

TLS ends at the reverse proxy, a second container ([ADR 0010](adr/0010-server-shape.md) §4). The binary has no TLS and no ACME client in M1. `compose.yaml` ships Caddy, which obtains and renews a certificate for `RIZZY_DOMAIN` automatically and forwards everything to `rizzy-vault:8080`.

**Ports.** Rootless Podman cannot publish host ports below 1024 by default, so `compose.yaml` publishes the proxy on **8080 (HTTP) and 8443 (HTTPS)**. You then have two choices:
- **Serve on 443** (recommended): let the host forward 80 → 8080 and 443 → 8443 (a firewall redirect, for example with nftables), or allow unprivileged ports (`sysctl net.ipv4.ip_unprivileged_port_start=80`) and set `RIZZY_HTTP_PORT=80`, `RIZZY_HTTPS_PORT=443`. With rootful Docker, setting the two variables is enough. `RIZZY_ORIGIN` is then `https://<domain>`.
- **Serve on 8443**: `RIZZY_ORIGIN=https://<domain>:8443`. Caddy's automatic certificate needs ports 80 or 443 reachable from the internet for the ACME challenge, so on high ports you need a DNS-challenge Caddy build or your own certificate (`tls /path/cert.pem /path/key.pem` in the `Caddyfile`).

Whichever you choose, `RIZZY_ORIGIN` must be exactly the origin users type, and it must not change afterwards.

**Another proxy** (nginx, Traefik, HAProxy) works if it:
- terminates TLS and forwards plain HTTP/1.1 to port 8080 on a network the clients cannot reach directly;
- **replaces** (does not append to) a client-sent `X-Forwarded-For`, or appends the client address as the last entry; the server reads the header from the right, skipping trusted proxies;
- has its own address in `RIZZY_TRUSTED_PROXIES`, and no other;
- accepts request bodies up to `RIZZY_MAX_UPLOAD_BYTES`;
- does not compress responses, and does not log request bodies or the `Authorization` header.

The server sets HSTS, CSP and the other security headers itself ([INV-49](THREAT_MODEL.md#8-security-invariants)). It logs no IP address; if your proxy keeps access logs, they do, and you decide their retention.

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

To run the migration as its own step (for example to see it succeed before serving), run `docker compose --profile admin run --rm migrate` while the server is stopped. On PostgreSQL (M3) this step is required: a server that finds a pending migration there refuses to start and names the command.

If the upgraded server does not start, keep the old image, restore the pre-upgrade backup ([§9](#9-restore)), and report the problem.

## 8. Backup

**What to back up:**

| What | How | Where to keep it |
|---|---|---|
| The database (`rizzy-vault-data`) | The native copy below | With your data backups, encrypted at rest |
| The secrets (`rizzy-vault-secrets`) | `backup-secrets`, plus the encrypted copy of [§5](#5-the-secrets-file) | **Apart** from the database backups |
| `deploy/.env`, `deploy/Caddyfile` | Any | Anywhere (no secret in profile A) |

> **Gap: no `rizzy-vault backup` command yet.** ADR 0011 specifies a logical, engine-neutral backup, `rizzy-vault backup` and `rizzy-vault restore`, in "a versioned and documented file format". No Accepted ADR defines that file format yet, so this build does not have the commands (the storage layer has the dump and restore logic, and the automated drill in [§10](#10-the-restore-drill) exercises it). Until they ship, the backup is ADR 0011's **native method**: a copy of the SQLite files, taken with the server stopped.

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

**Schedule** it with the host's cron or a systemd timer; the server is down for the few seconds the archive takes. Check the archives with the drill ([§10](#10-the-restore-drill)).

## 9. Restore

**Read this first: what a restore does to users** ([THREAT_MODEL §5.8](THREAT_MODEL.md#58-server-restore-from-backup)). A restore rolls **every** account back to the backup. Lost vault changes are the easy part: devices that still hold them re-upload them. The hard part is that a restore also brings back, until the users' devices correct it:
- **revoked devices**, which can authenticate again;
- **old passwords**: a password changed after the backup works again (with the Secret Key);
- **old recovery codes**: an Emergency Kit replaced after the backup works again.

**The reconciliation-epoch notice.** The design's defence is the reconciliation epoch ([INV-59](THREAT_MODEL.md#8-security-invariants)): `rizzy-vault restore` puts every restored account into a reconciliation epoch and draws a new restore generation ([ADR 0021](adr/0021-server-compaction.md) §2). Devices that reconnect then re-upload their newest signed account state, their bundle chain and every device revocation they hold; the server adopts the newest valid state and from then on refuses the old password, the old recovery code and the revoked devices. Until some device of an account reconnects, that account stays exposed, and accounts whose devices never reconnect stay rolled back ([AR-19](THREAT_MODEL.md#9-accepted-risks-and-out-of-scope)). An enrolled device re-registers the password the next time the user types it; recovery stays refused until a device issues a new recovery code.

> **Gap: this build cannot open reconciliation epochs from a restore.** Only `rizzy-vault restore` opens them, and it does not exist yet ([§8](#8-backup)). The native restore below puts the files back as they were: **no reconciliation epoch is opened and the restore generation does not change** (the automated drill pins this, [§10](#10-the-restore-drill)). So after a native restore:
> - the old passwords, old recovery codes and revoked devices of the backup are accepted **and reconnecting devices do not close them**: the server accepts the newer state they hold only during a reconciliation epoch;
> - clients cannot see that a restore happened through the restore generation, so ADR 0021's rules for changes that were in flight at backup time do not apply; such changes can be lost or reported as a conflict.
>
> Use a native restore **only to recover from losing the database**, never to undo an unwanted change, and do the "after a restore" steps below.

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

If the secrets volume was lost too, restore it **before** starting the server, from your encrypted copy of `secrets.json` ([§5](#5-the-secrets-file)):

```sh
age -d /somewhere/safe/rizzy-secrets-YYYY-MM-DD.json.age | docker run --rm -i -v rizzy-vault-secrets:/s docker.io/library/alpine:3 \
  sh -c 'umask 077 && cat > /s/secrets.json && chown -R 65532:65532 /s && chmod 0700 /s'
```

The server refuses to start against a database whose OPAQUE setup does not match the secrets file ([CRYPTO.md §5.8](CRYPTO.md#58-loss-or-rotation-of-the-server-opaque-secrets)): the database and the secrets must belong to the same instance. Never run `secrets init` to "fix" that: new secrets cannot open the restored accounts.

**After a restore:**
1. Tell every user that the server was restored to a backup of `<date>`, and ask them to open each of their devices soon, so the devices detect the rollback ([INV-25](THREAT_MODEL.md#8-security-invariants)) and re-upload what the server lost.
2. Security changes made after the backup (a password change, a device revocation, a recovery-code replacement) are undone by the restore, and a native restore does not heal them (see the gap above). The design's answer is to repeat them. **In this build that is not possible**: its HTTP API has no password-change, device-revocation, recovery-code or key-rotation request, so no such change can have been made through this build, and users cannot repeat one until those requests ship. When they do, ask users to repeat every such change made after the backup.
3. Accounts whose devices never reconnect stay as the backup left them.

## 10. The restore drill

A backup you have never restored is a hope, not a backup ([ROADMAP §4.9](ROADMAP.md#49-server-self-hosting--ops-m1-onward): "tested, not just written").

**Automated (runs with `cargo test`).** [`crates/rizzy-server/tests/drill.rs`](../crates/rizzy-server/tests/drill.rs) runs the backup → wipe → restore drill in a fast form, against real SQLite files, through the functions the binary runs: `secrets init`, a populated instance, a start with the startup checks, a logical dump next to the running server, `backup-secrets`, the native copy, a wipe, the secrets restored byte for byte from the encrypted backup, the dump restored into an empty database, and a restart. It checks that the data reads back exactly, that the restore draws a new restore generation and opens a reconciliation epoch for every account (INV-59), that the database backup holds none of the secrets file's secrets (INV-50: every OPAQUE server setup, `enum_key`, every data key and the bootstrap token, searched for both as bytes and as their base64url text), and that a restore into a non-empty database, a fresh secrets file next to the restored database and a wrong passphrase are refused. It also checks the gap of [§9](#9-restore): a native copy restored in place starts, but keeps the old restore generation and opens no epoch.

> **Gap: the full drill of ADR 0011 is not automated yet.** ADR 0011 requires simulated clients that change a password, enrol and revoke devices and rotate keys after the backup, then reconnect to the restored server and heal it, on SQLite and PostgreSQL. That needs the client core (M1 step 4) and the password-change, revocation and rotation endpoints, which are not in this build.

**Manual, on your own backups (monthly, and after every upgrade).** Restore the newest backups into **scratch volumes**, start a server on them **with no network**, and check that it passes its startup checks. The scratch server never talks to clients: it would honour the backup's old credentials.

```sh
docker volume create rizzy-drill-data && docker volume create rizzy-drill-secrets
docker run --rm -v rizzy-drill-data:/data -v "$PWD/backup-db:/backup:ro" docker.io/library/alpine:3 \
  sh -c 'tar -C /data -xzf /backup/rizzy-data-YYYYMMDDTHHMMSS.tar.gz && chown -R 65532:65532 /data && chmod 0700 /data'
age -d /somewhere/safe/rizzy-secrets-YYYY-MM-DD.json.age | docker run --rm -i -v rizzy-drill-secrets:/s docker.io/library/alpine:3 \
  sh -c 'umask 077 && cat > /s/secrets.json && chown -R 65532:65532 /s && chmod 0700 /s'
docker run --rm --network none --read-only --tmpfs /tmp \
  -e RIZZY_ORIGIN=https://vault.example.com \
  -v rizzy-drill-data:/data -v rizzy-drill-secrets:/run/rizzy-secrets:ro \
  localhost/rizzy-vault:dev serve
# expect the line with "event":"listening"; then Ctrl-C
docker volume rm rizzy-drill-data rizzy-drill-secrets
```

`listening` means the archive unpacked into a database this release can open and migrate, and that the secrets fit it. Also try your passphrase on the newest `backup-secrets` file once the command that reads it exists ([§5](#5-the-secrets-file)).

## 11. Logs

The server writes one JSON object per line to stderr: `ts_ms`, `level`, `event`, and fields that are integers or fixed strings. By construction it never logs secrets, tokens, request bodies, headers, login names, file paths or IP addresses ([INV-48](THREAT_MODEL.md#8-security-invariants)). Retention is the container runtime's: `compose.yaml` keeps at most 5 files of 10 MB (`json-file` driver); change `logging` there. Rootless Podman may ignore some of these options; check `podman inspect` and set `log_size_max` in `containers.conf` if needed.

## 12. Checklist

- [ ] `RIZZY_ORIGIN` is the exact origin users type, and will not change.
- [ ] The secrets volume is mounted read-only into the server and is not inside the data volume.
- [ ] A `backup-secrets` file **and** an encrypted copy of `secrets.json` exist, stored apart from the database backups; the passphrase is stored safely.
- [ ] Database backups run on a schedule, are encrypted, and are pruned.
- [ ] No backup holds both volumes (whole-host snapshots included).
- [ ] The database is on a local disk, not NFS or SMB.
- [ ] `RIZZY_SIGNUP` is `closed` outside the first-accounts window.
- [ ] `RIZZY_TRUSTED_PROXIES` lists exactly the proxy.
- [ ] The manual drill of [§10](#10-the-restore-drill) passed this month.
- [ ] Base images are pinned by digest if you build your own image.
