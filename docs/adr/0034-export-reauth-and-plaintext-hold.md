# ADR 0034: Re-authentication before every export and a hold before plaintext export

- Status: Accepted
- Date: 2026-10-05
- Deciders: project owner
- Milestone: M1
- Supersedes: [ADR 0027](0027-export-payload.md) §5 in part (its first bullet), on acceptance.

## Context

[ROADMAP §4.2](../ROADMAP.md#42-core-vault-m1), Must for M1: "Export: encrypted JSON (own format) + plaintext JSON/CSV with scary warning". [ADR 0027](0027-export-payload.md) §5 (Accepted) gates plaintext export behind its warning and the typed `EXPORT PLAINTEXT`; it gates the encrypted export behind nothing. [ADR 0013](0013-shared-client-core.md) §3 already allows plaintext out of the core only for "an explicit plaintext export, after re-authentication", and THREAT_MODEL §7.3 says "Plaintext export only after re-authentication", but no Accepted text fixes the re-authentication or covers the encrypted export.

The threat is someone at an unlocked, unattended session (web tab, `rv` with a cached unlock): without a gate, one click or command writes the whole vault to a file, readable by anyone (plaintext, [AST-20](../THREAT_MODEL.md#2-assets)) or guessable offline under a password the attacker chose (encrypted). On 2026-10-05 the owner decided the gates below; commit cd1c1ae built them before this ADR (V, code read for this ADR). Export and import files are hostile input on the way back in (THREAT_MODEL A16).

## Decision

1. **Re-authentication before every export**, encrypted or plaintext: an OPAQUE login of the session's account with the master password and the Secret Key, over the device session ([CRYPTO.md §11](../CRYPTO.md#11-flows) "Re-authenticate"). `rizzy-client::export::gate::ExportGate` accepts it only if the account the login verified is the session's; another account is `WrongPasswordOrSecretKey`, as a wrong password. `rv` asks for the master password and takes the Secret Key from the device record (`rv export --name <login>`); the web vault asks for both.
2. **One re-authentication allows one export within 5 minutes** (`REAUTH_WINDOW_MS`, the §11 freshness window). Authorising an export spends it; a refusal spends nothing. The host's clock decides; a clock that went back counts as not fresh. The web vault's gate lives in the unlocked session and goes with a lock; `rv` makes a new gate for each `rv export`.
3. **Permission tokens.** `VaultSync::export_encrypted`, `export_plaintext_json` and `export_plaintext_csv` take `EncryptedExportAuth` or `PlaintextExportAuth`, which have no public constructor: only `ExportGate::authorize_encrypted` / `authorize_plaintext` create them (`ReauthRequired` otherwise). The plaintext calls keep ADR 0027 §5's `PlaintextExportAck`.
4. **Encrypted export password.** A new password for the file, asked twice (the two must match), with [CRYPTO.md §2](../CRYPTO.md#2-conventions) "New passwords" checks (`check_export_password`: not empty, no unassigned code point), run before the token is taken and again by the export. The host says it is not the master password and cannot be recovered.
5. **Plaintext export: warning, then a 10-second hold** (`PLAINTEXT_EXPORT_HOLD_MS` = 10,000). The host shows ADR 0027 §5's warning verbatim (with the CSV addition) and records it (`plaintext_warning_shown`); `authorize_plaintext` refuses with `PlaintextExportHold` until 10 s after the warning was last shown. No flag, setting or environment variable skips or shortens the hold.
   - **Web vault:** a visible countdown with the confirm control disabled; each time the dialog shows the warning, the hold restarts in the core and in the countdown.
   - **`rv`:** blocks for the whole hold on a monotonic clock, then asks for the phrase (a terminal is required). `rv` cannot discard what is typed during the hold: it stays in the terminal's input buffer and the phrase prompt reads it (`tcflush` needs `unsafe` or an unadmitted crate). The phrase must still match exactly.
   - The typed `EXPORT PLAINTEXT` of ADR 0027 §5 stays.
6. **Import recognises the format from the bytes** (`rizzy-client::export::detect::detect_format`): size cap first (the largest importer input), then signatures (zip → 1PUX, KDBX → the KeePass XML reader, which refuses it), then the existing bounded, fuzzed readers (our strict encrypted-export JSON reader, `rizzy-import`'s `json` and `csv` readers) on the JSON root or CSV header. Answers: our encrypted export (the host asks for that file's password), a `rizzy-import` format, our plaintext CSV export (refused: it has no reader, ADR 0027 §6), or unknown (the user names the format; `rv import --format` also overrides). The answer only picks the reader, which checks the whole file again; it is a kind, never a byte of the file (INV-48). Fuzz target `client_detect_format`.

**What this ADR supersedes:** ADR 0027 §5, its first bullet ("`rizzy-client` exposes plaintext export only through …"), replaced by the text in "On acceptance", which binds as Decision text of this ADR. The rest of ADR 0027 §5 stays binding.

## Consequences

### Positive
- An unattended unlocked session cannot write an export without the master password; one re-authentication cannot be reused for a second file.
- The hold makes the warning harder to click past; import needs no format choice in the common case.

### Negative
- `rv export` needs the server (re-authentication) and `--name`; an offline device cannot export.
- One more Argon2id (the OPAQUE KSF) per export; plaintext export takes at least 10 s.

### Risks
- The gate is client-side: a modified client skips it (ADR 0013 §4 "Honest limit"). It defends an honest client left unlocked, not a hostile one.
- Type-ahead in `rv` can pre-fill the phrase; if that matters, a terminal-flush mechanism needs its own ADR.

## Alternatives considered
- **Gate plaintext only** (ADR 0027 as Accepted): the encrypted export under an attacker-chosen password is the same leak, offline-guessable at the attacker's leisure.
- **Unlock the cache instead of OPAQUE re-authentication:** works offline, but checks nothing the server can rate-limit and is not the re-authentication ADR 0013 §3 names.
- **A server-checked fresh session** (the §11 5-minute flag): export never reaches the server; the client gate carries the same window.

## Open questions for the owner

None. The owner decided the content on 2026-10-05.

## On acceptance

1. **ADR 0027 §5, first bullet.** Current text:
   > `rizzy-client` exposes plaintext export only through a call that takes an explicit acknowledgement value. Before creating it, every host shows the warning below and requires the user to type `EXPORT PLAINTEXT` exactly; no flag, setting or environment variable skips this, and `rv` reads the phrase from the terminal, so a plaintext export never runs unattended. The plaintext goes to the host as one zeroizing byte buffer.

   Replacement:
   > `rizzy-client` exposes every export, encrypted or plaintext, only through calls that take a permission token its export gate alone creates, after a fresh OPAQUE re-authentication of the session's account (another account counts as a wrong password); one re-authentication allows one export within 5 minutes ([ADR 0034](0034-export-reauth-and-plaintext-hold.md)). The plaintext calls also take an explicit acknowledgement value. Before creating it, every host shows the warning below, holds the user for 10 seconds (the gate refuses a plaintext token until 10 seconds after the warning was last shown), and requires the user to type `EXPORT PLAINTEXT` exactly; no flag, setting or environment variable skips the re-authentication, the warning, the hold or the phrase, and `rv` reads the phrase from the terminal, so no export runs unattended. The plaintext goes to the host as one zeroizing byte buffer.
2. **Status lines:** ADR 0027 → "Partially superseded by [ADR 0034](0034-export-reauth-and-plaintext-hold.md) (§5 in part)"; this ADR → Accepted; both index rows follow.
3. **THREAT_MODEL.md §2, AST-20** "Impact" cell: "Encrypted export: offline guessing at the export KDF cost. Plaintext export: everything." → "Encrypted export: offline guessing at the export KDF cost. Plaintext export: everything. Every export first needs a fresh re-authentication with the master password ([ADR 0034](adr/0034-export-reauth-and-plaintext-hold.md))."
4. **THREAT_MODEL.md §7.3**, row I, Mitigation: "Plaintext export only after re-authentication." → "Every export only after a fresh re-authentication, one export per re-authentication within 5 minutes; a plaintext export also after the warning, a 10-second hold and the typed phrase ([ADR 0034](adr/0034-export-reauth-and-plaintext-hold.md))."

## References
- [ADR 0013](0013-shared-client-core.md) §3–§4, [ADR 0020](0020-partial-supersession.md) point 9, [ADR 0027](0027-export-payload.md) §5–§6; [CRYPTO.md](../CRYPTO.md) §2, §11, §11.14; [THREAT_MODEL.md](../THREAT_MODEL.md) AST-20, A16, INV-48; [rv.md](../rv.md#export-and-import).
- Code (V, cd1c1ae): `crates/rizzy-client/src/export/{gate,detect}.rs`, `crates/rizzy-cli/src/{commands,device,ui}.rs`, `crates/rizzy-wasm/src/session.rs`, `apps/web/src/{export-flow,hold}.ts`, `apps/web/src/views/TransferPane.tsx`, `fuzz/fuzz_targets/client_detect_format.rs`.
