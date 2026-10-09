# `rv`: the command-line client

`rv` is the rizzy-vault command-line client (crate [`rizzy-cli`](../crates/rizzy-cli/src/lib.rs), M1). It talks to a rizzy-vault server ([self-hosting.md](self-hosting.md)) and keeps an encrypted copy of the vault on this computer, so reading works offline. `rv --help` prints the full command list.

Status: M1, not audited. Read [SECURITY.md](../SECURITY.md) before trusting it with real secrets.

## Secrets never go on the command line

`rv` takes no secret as an argument or from the environment. It asks on the terminal with echo off. When standard input is not a terminal, it reads the secrets from it, one per line, in the order it asks. A field value that is a secret is given with `--secret <key>`, which asks for it the same way.

`rv` prints a secret only when the command exists to show one: the Emergency Kit at `signup`, `secret-key` and `recovery complete`, the two-factor secret at `2fa enable`, `item show --reveal`, `generate`, `totp`. It has no clipboard output (owner decision, 2026-10-01), so those values stay in the terminal's scrollback: clear it.

## Where the data lives, and keeping it out of backups

| Platform | Directory |
|---|---|
| any, if set | `$RIZZY_CLI_DATA_DIR` |
| Linux and other Unix | `$XDG_DATA_HOME/rizzy-vault`, or `~/.local/share/rizzy-vault` |
| macOS | `~/Library/Application Support/rizzy-vault` |
| Windows | `%LOCALAPPDATA%\rizzy-vault` |

Each account has one SQLite file, `<account id>.sqlite3`, and a lock file next to it. On Unix `rv` creates the directory with mode 0700 and the files with mode 0600. A directory that already exists and is open to the group or to others is set to 0700 at every run; if `rv` cannot do that (the directory is not yours), it stops.

**Exclude this directory from backups and file-sync tools** (Time Machine, iCloud Drive, Dropbox, rsync jobs, home-directory snapshots). The file holds this device's Secret Key in the clear and the vault keys wrapped under the master password ([ADR 0026](adr/0026-client-device-state-and-cache.md) §2). A copy of it lets whoever holds the copy guess the master password offline (threat model INV-61). `rv` does not set the exclusion for you.

Do not restore the file from a copy either. If `rv` finds that the server has seen newer requests or edits from this device than the file knows, it raises the alarm "device state outdated", goes read-only, and asks you to enrol again: `rv device forget`, then `rv login`.

Only one `rv` runs on an account at a time; a second one waits up to two seconds for the first to finish, then fails with "in use".

## First use

```sh
rv signup --server https://vault.example.org --name alice
```

`signup` asks for a master password, then shows the **Emergency Kit** (the Secret Key and, unless `--no-recovery-code` is given, the recovery code) and asks you to type part of it back before anything is sent. Write the kit down on paper. Without the Secret Key no new device can log in; without the recovery code a forgotten master password cannot be replaced.

The server address must be `https://`. Plain `http://` is accepted only for `localhost` and loopback addresses ([ADR 0028](adr/0028-api-v1-http-conventions.md)).

On another computer:

```sh
rv login --server https://vault.example.org --name alice
```

It asks for the master password and the Secret Key from the kit.

### TLS and a private CA

`rv` speaks TLS 1.3 only, through rustls with the `ring` provider ([ADR 0030](adr/0030-client-tls-rv.md)). A server, or the reverse proxy in front of it, that offers only TLS 1.2 is refused. `rv` follows no redirect and uses no HTTP proxy (`HTTPS_PROXY` is not read).

By default `rv` trusts Mozilla's root CAs, built into `rv` (the operating system's trust store is not used). A server with a certificate from a public CA, such as the Let's Encrypt certificate the shipped Caddy obtains, works as is.

If the server's certificate comes from your own CA, give `rv` that CA's certificate:

```sh
rv --ca-file /path/to/ca.pem login --server https://vault.example.org --name alice
# or, for every command:
export RIZZY_CLI_CA_FILE=/path/to/ca.pem
```

`--ca-file` (it may stand anywhere on the command line) wins over `RIZZY_CLI_CA_FILE`. Neither is stored, so set one for every run: every command that opens an account on an `https://` server reads the file, even one that then works offline. The file's certificates **replace** the public roots: with it, `rv` trusts only your CA. It must be PEM, at most 64 KiB, with one to 16 `CERTIFICATE` blocks (other blocks are ignored), each one a CA certificate (`CA:TRUE` in its basic constraints) that rustls accepts as a trust anchor. A file that breaks a rule stops `rv` before it contacts the server.

The CA file is not a certificate pin. A self-signed server certificate placed in it does not work: one with `CA:FALSE` (like the server certificate itself) is refused when the file is read, and one with `CA:TRUE` is refused at the handshake. The server needs a certificate issued by a separate CA certificate (see [self-hosting.md §6](self-hosting.md#6-tls-the-reverse-proxy-and-ports)). There is no certificate pinning and no revocation checking in this version.

A refused handshake names the server and the reason (unknown CA, expired, wrong name, no TLS 1.3, …); nothing was sent, so the command can simply be repeated once the cause is fixed.

## Daily use

```sh
rv unlock                      # checks the password, syncs, says where the device stands
rv sync
rv item list                   # --trash lists the trash
rv item show 3fa2              # ids may be shortened to a unique prefix; --reveal shows secrets
rv item create --type login --field item.name=Example --field login.username=alice \
               --secret login.password --uri https://example.org --tag work
rv item edit 3fa2 --secret login.password --clear item.notes --untag work
rv item edit 3fa2 --uri https://login.example.org --custom "Account=1234" --custom-secret PIN
rv item edit 3fa2 --set-uri 9b1c=https://example.org/new --remove-custom 52e0
rv item edit 3fa2 --move-uri 9b1c=first --move-custom 52e0=after:7d41
rv item trash 3fa2             # restore, purge
rv generate --length 24        # or --words 6
rv totp 3fa2
```

Every command asks for the master password: nothing unlocked outlives the process. A command that changes something writes it to the local file first and then uploads it. If the server is not reachable the change stays queued and the next `rv sync` sends it.

URIs and custom fields are list elements: `item show` prints each with its element id in the key (`uri/<id>/value`, `field/<id>/label`), and `--set-uri`, `--remove-uri`, `--set-custom`, `--set-custom-secret` and `--remove-custom` take that id or a unique prefix of it. `--uri`, `--custom <label>=<text>`, `--custom-secret <label>` (a hidden field: the value is asked for) and `--custom-bool <label>=true|false` add one, after the last. Removing one clears every attribute of it, so it disappears on every device. A hidden field's value is never taken from the command line: `--set-custom` refuses it, `--set-custom-secret` asks.

`--move-uri <id>=<place>` and `--move-custom <id>=<place>` reorder them; a place is `first`, `last`, `before:<id>` or `after:<id>`, and `item show` prints each list's ids in order (`order of uri: …`). Moves run in the order given, after the same command's removals and additions. A move writes only the moved element's position; when two devices placed elements at the same spot and nothing fits between them any more, the whole list's positions are rewritten evenly, which is invisible apart from the new `order` values. Tags and password history have no order of their own and cannot be moved.

`item show` lists `login.password`'s history (up to 50 older values) in its own section, newest first, each concealed as `********` unless `--reveal` is given, same as every other secret. A password imported from another manager (`pwhist/<id>/value` · `/ms`) gets a second, separate section: the ADR defines no order across the two, so they are never interleaved.

Item types: `login`, `note`, `card`, `identity`, `ssh-key`, `api-credential`, `software-license`, `wifi`, `bank-account`, `passkey`. Field keys are those of the item schema ([ADR 0018](adr/0018-item-record-encoding.md)), for example `item.name`, `item.notes`, `login.username`, `login.password`, `login.totp`, `card.number`.

## Export and import

```sh
rv export --out vault.rizzy --name alice                 # encrypted, under a password for this file
rv export --out vault.json  --name alice --format json   # plaintext
rv export --out vault.csv   --name alice --format csv    # plaintext, loses what CSV cannot hold
rv import --in vault.rizzy                               # the format is recognised from the file
rv import --in export.csv --format chrome-csv            # name the format when it is not
```

- **Every export asks for your master password again** and checks it with the server (an OPAQUE login with this device's Secret Key, as for a password change), so an export needs the server. A wrong password ends the export and writes nothing. `--name` is your login name.
- **The encrypted export** then asks for a new password for that file, twice. It is needed to import the file; it is not your master password, and nobody can recover it if it is lost. It must not be empty.
- **A plaintext export** shows a warning, waits 10 seconds, then asks you to type `EXPORT PLAINTEXT` at the terminal. No flag or environment variable skips the warning, the wait or the phrase. What you type during the wait is read by the phrase prompt afterwards. Delete the file when you are done with it.
- An export never overwrites a file. Choose a new name.
- Trashed items are in every export. An export larger than 16 MiB is refused in M1 ([ADR 0027](adr/0027-export-payload.md)).
- An export holds what this computer has. Run `rv sync` first.
- **Import recognises the format** of the file: our encrypted export (it then asks for that file's password), our plaintext JSON export, Bitwarden JSON, 1Password 1PUX, KeePass XML, Chrome, Firefox or generic CSV, and AliasVault's CSV export or its `.avux` (unencrypted) export archive. Our own CSV export cannot be imported (it leaves data out): import the JSON or the encrypted export. AliasVault's encrypted `.avex` export cannot be imported either; export unencrypted (CSV or `.avux`) instead. When the format is not recognised, name it with `--format`: `bitwarden-json` (unencrypted), `1pux`, `keepass-xml`, `csv`, `chrome-csv`, `firefox-csv`, `rizzy-json` (our plaintext JSON), `rizzy-encrypted` (our encrypted export), `aliasvault-csv`, `aliasvault-avux`. `--format` also overrides what was recognised. `rv` reports what it could not import.

## Devices and key rotation

```sh
rv device list
rv device revoke 9c41 --name alice     # a lost or stolen device: revokes it and rotates every key
rv device revoke 9c41 --name alice --standard   # a device you wiped yourself
rv rotate --name alice                 # --full also replaces the identity keys
rv device forget                       # removes this computer's copy of the account
```

`device forget` first uploads the edits the server has not acknowledged, if it can verify them, and tells you what was lost if it cannot. It asks you to type a confirmation. It does not revoke the device: do that from another device with `rv device revoke`.

If a rotation or a signup is interrupted after it was sent, the next `rv` run finds out whether the server took it and finishes it or sends it again before doing anything else. `rv` keeps what it saved for the rotation or signup as long as the outcome is unknown: no answer, a proxy's error page (`502`, `504`), a server failure or a rate limit. It drops it only when the server answers with a refusal and, for a rotation, a second look at the account shows the rotation was not applied.

`rv login` and `rv recovery complete` save nothing before the server answers ([ADR 0026](adr/0026-client-device-state-and-cache.md) defines no pending stage for them; an open point). If their answer is lost, `rv` says that the outcome is unknown: run the command again, and if the first attempt did reach the server, revoke the extra device it left with `rv device revoke`. After a recovery with an unknown outcome keep both Emergency Kits until you know which one logs in.

## Master password, Secret Key and two-factor login

```sh
rv password   --name alice              # a new master password; --rotate also rotates the keys
rv secret-key --name alice              # a new Secret Key and Emergency Kit; rotates the keys
rv secret-key --name alice --full-rotation   # the same, and new identity keys: the kit was stolen
rv 2fa enable  --name alice             # server-side two-factor login with an authenticator app
rv 2fa disable --name alice
```

Each of them first logs in again with the current master password (and a two-factor code when two-factor login is on). `password` asks for the new master password twice; it does not rotate the keys unless `--rotate` is given, which you want if the old password leaked (with a recovery code, it then asks for that code and keeps it). `secret-key` keeps the master password, shows a **new Emergency Kit** and asks you to type part of it back before anything is sent; by default it also rotates the keys and issues a new recovery code, which the kit shows. `--skip-rotation` is the opt-out: then the kit has no recovery code, and the earlier one stays valid, so keep the old kit for its recovery code (only its Secret Key stops working). `--full-rotation` is for a kit you believe was stolen: the rotation also replaces the account's identity keys, so each of your other devices shows a new safety number the next time it goes online and asks you to type `CONFIRM` after comparing it with one you trust. The old kit stops working only once the server has taken the change: if the server refuses it, `rv` says the change was not made and the new kit is void, and the old kit stays the valid one. If copying the kit takes more than four minutes, `rv` logs in once more before sending the change (the server takes it only within five minutes of a login). Your other devices ask for the new master password, and the new Secret Key if it changed, the next time they go online.

If such a change is interrupted after it was sent, it is kept like an interrupted rotation: the next `rv` run opens with the **current** master password, asks for the new one, and finishes the change or sends it again. If the server does not take it then, `rv` says so, and the previous master password and Emergency Kit stay the valid ones.

**When the server retires its old login setup** ([ADR 0031](adr/0031-retiring-old-opaque-setups.md)). After the operator runs `rizzy-vault secrets rotate`, the server asks clients to move each account to its new login setup. `rv` does it by itself the next time it goes online, with the master password you typed to open the device (no prompt, no change to your password, Secret Key or kit). If the operator later retires the old setup (`secrets retire-setups`) before an account moved, its password login stops working, but its enrolled devices still open: `rv` moves the account then, and password logins work again. An interrupted signup that was waiting when the setup was retired is registered again: `rv` asks for its master password, the login name and the invite, and sends it once more; its Emergency Kit stays valid. If the server refuses it a second time, the signup stays saved and the next run tries again. An interrupted master password or Secret Key change, or key rotation, cannot be sent once the account's own setup was retired: it needs a password login, which the retired setup no longer allows. `rv` then says so and keeps the change saved, nothing is changed, and your current master password, Secret Key and Emergency Kit stay the valid ones; tell the operator (a recovery with the Emergency Kit also restores the password login).

`2fa enable` shows the secret once, as an `otpauth://` URI and in Base32, for your authenticator app, then asks for the app's current code. From then on every login asks for a code. `2fa disable` needs a current code too, a newer one than the code its own login used. Codes are typed at the terminal or piped in, never given on the command line. Losing the authenticator needs the server administrator.

## Forgotten master password

```sh
rv recovery start    --server https://vault.example.org --name alice
rv recovery complete --server https://vault.example.org --name alice
rv recovery cancel                      # on a device that is still enrolled
```

`recovery start` needs the recovery code from the Emergency Kit. The server then makes you wait (72 hours), and a device that is still enrolled can cancel a recovery you did not start with `rv recovery cancel`. `recovery complete` asks for the recovery code again, sets a new master password, shows a **new Emergency Kit** (the old Secret Key and recovery code stop working), rotates the keys unless `--skip-rotation` is given, and enrols this computer. Every other device then asks for the new master password and Secret Key the next time it goes online. An operator who runs the server for one person can set the wait to 0 hours (`RIZZY_RECOVERY_WAIT_HOURS`, see [self-hosting.md](self-hosting.md)).

## After the server was restored from a backup

If the server's operator restored it from an older backup, the edits made after that backup are gone from the server but not from your devices. The next `rv sync` on a device that holds them notices that the server is behind, says so ("The server has lost changes this device holds"), sends them back in one request, and goes on. Until that has happened the device does not write: an edit is refused as read-only, and reading works as before. Run `rv sync` on each device that was in use after the backup. If the server refuses the request, or a device cannot send back everything the server lost, `rv` says so and the device stays read-only.

The restore can also take the account back: a device added after the backup, for example. `rv` then sees an older account state than the one it holds, raises the rollback alarm, and sends the newer state back ("Sending the newer one back"); a device the restored server does not know at all first shows the server its certificate. If the server takes them, the alarm is lifted ("The server holds this device's account state again") and the device goes on as above. A server put back from a plain file copy rather than with `rizzy-vault restore` does not take them: the alarm stays, and every run tries again.

A key rotation, a device removal, a password change or a Secret Key change made after the backup is healed the same way ([ADR 0032](adr/0032-healing-rotation-after-backup.md)): the first device that saw it and runs `rv sync` sends back the newer account state with its keys and the vault's key, then the lost edits, and, with the master password you typed, registers your login with the server again. Until that last step has run, `rv login` on a new device is refused with "restored from a backup" even with the right password; run `rv sync` on a device that is already set up, then try again. A device that missed the change (it did not run between the change and the restore) catches up by logging in with your master password at its next `rv sync`, once the login works again; until then it says to open a device that saw the change.

After such a restore your recovery code does not start a recovery until you repair it on an enrolled device:

```sh
rv recovery repair --name alice            # a new recovery code and Emergency Kit
rv recovery repair --name alice --retype   # or: type the current recovery code again
```

`--retype` works only when the code did not change since the backup; if the server does not take it, run the command without `--retype` and keep the new kit it shows (the old recovery code then stops working).

## Alarms

`rv` stops writing and says so when it cannot trust what it sees: the server rolled the account back, served another identity key, or knows more about this device than the local file does. The alarm stays until it is dealt with; a rollback alarm is lifted once the server shows this device's account state again (above). For an identity change, `rv` shows a safety number to compare on another device before you accept it. For "device state outdated" the only way on is to enrol again. While a rollback, fork or unconfirmed-identity alarm is raised, `rv device forget` refuses to remove the local file, with or without the master password: the file is the evidence.

## Not in this build

Certificate pinning, revocation checking, the operating system's trust store, TLS 1.2 and HTTP proxies ([ADR 0030](adr/0030-client-tls-rv.md)); and no-echo input on platforms without `stty` (there, pipe the secrets in).
