# `rv`: the command-line client

`rv` is the rizzy-vault command-line client (crate [`rizzy-cli`](../crates/rizzy-cli/src/lib.rs), M1). It talks to a rizzy-vault server ([self-hosting.md](self-hosting.md)) and keeps an encrypted copy of the vault on this computer, so reading works offline. `rv --help` prints the full command list.

Status: M1, not audited. Read [SECURITY.md](../SECURITY.md) before trusting it with real secrets.

## Secrets never go on the command line

`rv` takes no secret as an argument or from the environment. It asks on the terminal with echo off. When standard input is not a terminal, it reads the secrets from it, one per line, in the order it asks. A field value that is a secret is given with `--secret <key>`, which asks for it the same way.

`rv` prints a secret only when the command exists to show one: the Emergency Kit at `signup` and `recovery complete`, `item show --reveal`, `generate`, `totp`. It does not copy to the clipboard in this build, so those values stay in the terminal's scrollback: clear it.

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

Only one `rv` runs on an account at a time; a second one fails with "in use".

## First use

```sh
rv signup --server https://vault.example.org --name alice
```

`signup` asks for a master password, then shows the **Emergency Kit** (the Secret Key and, unless `--no-recovery-code` is given, the recovery code) and asks you to type part of it back before anything is sent. Write the kit down on paper. Without the Secret Key no new device can log in; without the recovery code a forgotten master password cannot be replaced.

The server address must be `https://`. Plain `http://` is accepted only for `localhost` and loopback addresses ([ADR 0028](adr/0028-api-v1-http-conventions.md)).

**This build cannot dial `https://` yet.** The TLS client crates need the owner's approval under [ADR 0009](adr/0009-crypto-dependency-policy.md), which has not been given. Until it is, `rv` refuses an `https://` address and works only against a server on `localhost` or a loopback address (the same machine, or a tunnel you trust that ends there).

On another computer:

```sh
rv login --server https://vault.example.org --name alice
```

It asks for the master password and the Secret Key from the kit.

## Daily use

```sh
rv unlock                      # checks the password, syncs, says where the device stands
rv sync
rv item list                   # --trash lists the trash
rv item show 3fa2              # ids may be shortened to a unique prefix; --reveal shows secrets
rv item create --type login --field item.name=Example --field login.username=alice \
               --secret login.password --uri https://example.org --tag work
rv item edit 3fa2 --secret login.password --clear item.notes --untag work
rv item trash 3fa2             # restore, purge
rv generate --length 24        # or --words 6
rv totp 3fa2
```

Every command asks for the master password: nothing unlocked outlives the process. A command that changes something writes it to the local file first and then uploads it. If the server is not reachable the change stays queued and the next `rv sync` sends it.

Item types: `login`, `note`, `card`, `identity`, `ssh-key`, `api-credential`, `software-license`, `wifi`, `bank-account`, `passkey`. Field keys are those of the item schema ([ADR 0018](adr/0018-item-record-encoding.md)), for example `item.name`, `item.notes`, `login.username`, `login.password`, `login.totp`, `card.number`.

## Export and import

```sh
rv export --out vault.rizzy                  # encrypted; asks for an export password
rv export --out vault.json --format json     # plaintext
rv export --out vault.csv  --format csv      # plaintext, loses what CSV cannot hold
rv import --in export.json --format bitwarden-json
```

- An export never overwrites a file. Choose a new name.
- A plaintext export needs you to type `EXPORT PLAINTEXT`. There is no flag that skips this. Delete the file when you are done with it.
- Trashed items are in every export. An export larger than 16 MiB is refused in M1 ([ADR 0027](adr/0027-export-payload.md)).
- An export holds what this computer has. Run `rv sync` first.
- Import formats: `bitwarden-json` (unencrypted), `1pux`, `keepass-xml`, `csv`, `chrome-csv`, `firefox-csv`, `rizzy-json` (our plaintext JSON), `rizzy-encrypted` (our encrypted export). `rv` reports what it could not import.

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

## Forgotten master password

```sh
rv recovery start    --server https://vault.example.org --name alice
rv recovery complete --server https://vault.example.org --name alice
rv recovery cancel                      # on a device that is still enrolled
```

`recovery start` needs the recovery code from the Emergency Kit. The server then makes you wait (72 hours), and a device that is still enrolled can cancel a recovery you did not start with `rv recovery cancel`. `recovery complete` asks for the recovery code again, sets a new master password, shows a **new Emergency Kit** (the old Secret Key and recovery code stop working), rotates the keys unless `--skip-rotation` is given, and enrols this computer. Every other device must then log in again with the new master password and Secret Key.

## Alarms

`rv` stops writing and says so when it cannot trust what it sees: the server rolled the account back, served another identity key, or knows more about this device than the local file does. The alarm stays until it is dealt with. For an identity change, `rv` shows a safety number to compare on another device before you accept it. For "device state outdated" the only way on is to enrol again. While a rollback, fork or unconfirmed-identity alarm is raised, `rv device forget` refuses to remove the local file, with or without the master password: the file is the evidence.

## Not in this build

Clipboard output, a private CA, changing the master password or the Secret Key outside recovery, editing the URIs and custom fields of an existing item, and no-echo input on platforms without `stty` (there, pipe the secrets in).
