# ADR 0084: Bare, unencrypted CXF passkey export (answers ADR 0074 open question 4)

- Status: Accepted
- Date: 2026-10-24
- Deciders: project owner
- Milestone: M8 (`rizzy-client` `export::cxf`, `rizzy-wasm`, `rv`, web vault)
- Supersedes: [ADR 0074](0074-passkey-cxf-import-export.md) (owner answer 4 at acceptance; §5 item 2's replacement sentence); [ADR 0034](0034-export-reauth-and-plaintext-hold.md) (point 3 in part, point 5 in part); [ADR 0027](0027-export-payload.md) (§5 in part: one sentence of its first bullet as ADR 0034 replaced it), on acceptance. §6 below names the exact parts and their replacements.

## Context

**The owner's words, verbatim (2026-10-24):** "Approve bare unencrypted export. Gated behind the exact same scary warning, 10-second hold, and typed phrase EXPORT PLAINTEXT as plaintext CSV/JSON. This allows users to export passkeys directly into other password managers without being locked into rizzy-vault round-trips."

**The question this answers.** [ADR 0074](0074-passkey-cxf-import-export.md) (Accepted 2026-10-11, implemented) open question 4: "Should M8 also ship a bare, unencrypted CXF export (ADR 0027 §4's plaintext-CSV shape, gated the same way), so a user can hand a file straight to another vendor's importer, not only round-trip through rizzy-vault? … *Recommendation:* yes, as a `payload`-free plaintext form in the same change, behind the identical warning/hold/phrase … **a yes here is also a ROADMAP §4.10 edit for the owner to make**". Its owner answer 4 at acceptance (2026-10-22) left it open: "Until the owner makes that edit, the bare form is out of scope. This stays open." The owner's words above approve it, and approve the ROADMAP edit with it (On acceptance, item 1).

**ROADMAP.** [§4.10](../ROADMAP.md#410-mobile--passkeys-m7), Should, M8: "Passkey import/export via FIDO Credential Exchange Protocol (CXP/CXF) when stable". [§4.2](../ROADMAP.md#42-core-vault-m1), Must, M1: "Export: encrypted JSON (own format) + plaintext JSON/CSV with scary warning".

**What exists** (V, code read at `f20ad1d`):

- **The CXF document writer.** `VaultSync::cxf_document(rng, now_ms) -> (SecretBytes, CxfExport)` (`crates/rizzy-client/src/export/cxf.rs` line 427) builds the CXF 1.0 document in one zeroizing buffer: one account (random id), one CXF item per **active** Login item of the vault that has at least one passkey, in item-id order, one passkey credential per `passkey/<id>/…` element (ADR 0074 §2 "Building the item"); an element that cannot make a credential is left out and counted (`CxfExport::skipped`); trashed items are not exported. It refuses (`ExportTooLarge`) a document its own reader would refuse: more than `MAX_ENTRIES` items or credentials per item, more than `MAX_JSON_LEN` bytes or `MAX_NODES` values.
- **The encrypted CXF export.** `VaultSync::export_cxf(rng, PlaintextExportAuth, PlaintextExportAck, export_password, now_ms)` (line 399) runs `cxf_document`, wraps it as `u16(payload_version = 2) ‖ bytes(cxf_json)` (`encode_cxf_payload`, which adds the 16 MiB envelope cap) and seals it in a `"format":"rizzy-vault-cxf-export"` file. Its warning is `CXF_EXPORT_WARNING` (line 102), ADR 0074 §2's text. The module docs say: "**No bare, unencrypted CXF export exists**: ADR 0074's open question 4 needs a ROADMAP §4.10 edit first (owner answer 4 at acceptance)."
- **The bare CXF import.** `detect_format` answers `Import(Format::CxfJson)` for a JSON root with an `accounts` array and an integer `version.major` (`rizzy_import::cxf::looks_like_cxf`; `crates/rizzy-client/src/export/detect.rs` line 175), and `rizzy_import::cxf` reads it with no password (ADR 0074 §3 "Bare file (the interop case)"; fuzz target `import_cxf`). The test `a_bare_cxf_file_imports_through_the_same_reader` (`crates/rizzy-client/src/tests/export.rs` line 2023) imports the CXF 1.0 specification's own example credential. `rv import --format cxf-json` and the web import both reach it.
- **The plaintext gate** ([ADR 0034](0034-export-reauth-and-plaintext-hold.md), `crates/rizzy-client/src/export/gate.rs`): `ExportGate::authorize_plaintext` issues a `PlaintextExportAuth` only after a fresh OPAQUE re-authentication (one export per re-authentication, within 5 minutes) and 10 s (`PLAINTEXT_EXPORT_HOLD_MS`) after the warning was last shown; `PlaintextExportAck::from_typed_phrase` accepts only `PLAINTEXT_EXPORT_PHRASE` = `"EXPORT PLAINTEXT"` (`plaintext.rs` line 125). `export_plaintext_json`, `export_plaintext_csv` and `export_cxf` take both tokens.
- **The hosts.** `rv export --format cxf` shows `CXF_EXPORT_WARNING`, then `plaintext_gate` (the hold on a monotonic clock, then the phrase from the terminal), then `write_new_file` (`crates/rizzy-cli/src/commands.rs` lines 1291–1312). The web vault's Transfer pane has a "Passkey export (CXF)" section whose dialog "Export passkeys (CXF)" shows the warning, counts down and asks for the phrase, and saves `rizzy-vault-passkeys-<YYYY-MM-DD>.json` (`apps/web/src/views/TransferPane.tsx` lines 338–460); the plaintext JSON/CSV export saves `rizzy-vault-plaintext-<YYYY-MM-DD>.json|csv` and zeroes its buffer after the save (lines 210–216). Both dialogs are in the axe audit and the keyboard walk (`apps/web/e2e/a11y.spec.ts`, `keyboard-nav.spec.ts`).

**The warnings that exist.** [ADR 0027](0027-export-payload.md) §5, frozen English source: "This file will hold every password, one-time-code secret, card number and note of this vault, unencrypted. Anyone and any program that can read the file can read them all, including backup and cloud-sync tools and other users of this computer. rizzy-vault cannot protect, track or erase the file once it is written. Delete it as soon as you have used it. To keep a copy of your vault, use the encrypted export instead." Its first sentence is false for a file that holds only passkeys, and it says nothing about what makes a leaked passkey worse than a leaked password: the holder can sign in as the user with no password at all, and changing the account's password does not stop them. ADR 0074 §2 already refused to reuse this text for the CXF export, for a similar reason, and gave `export_cxf` its own constant.

**A related fact, not changed here** (V, code read: `json_item` in `plaintext.rs` writes every displayed register except `@lifecycle`): the plaintext JSON export already holds every passkey's private key, as a `{"bytes":…}` value under `passkey/<id>/private_key`, in our own format that no other manager reads. ADR 0027 §5's warning does not mention passkeys (open question 2).

**Threats.** [THREAT_MODEL.md](../THREAT_MODEL.md) AST-9 (passkeys: "Passwordless takeover of those accounts … Since M8, CXF export can take every synced passkey's private key out of the vault in one file") and AST-20 (exports: "Plaintext export: everything … Since M8, a CXF export also carries every passkey's private key, in a form any compliant password manager can read"); A16 (a malicious import file: the bare reader exists and is fuzzed); INV-56 (`rv` refuses a terminal as stdout). The gate is client-side (ADR 0034 Risks: "a modified client skips it"); this ADR does not change that.

**Interop (U).** Whether other password managers import a bare CXF 1.0 JSON *file*, as opposed to receiving CXF over CXP or a platform credential-exchange API, was not checked for this ADR. The format is the one ADR 0074's Context read from the CXF 1.0 Proposed Standard (V there); vendor import support for a file is unverified.

## Decision

### 1. What is exported, and in which form

A **bare CXF export** is the CXF document of ADR 0074 §2, written as is: UTF-8 JSON, the exact bytes `cxf_document` produces, with no `rizzy-vault-cxf-export` wrapper, no `EXPORT_FILE` envelope, no `payload_version` prefix and no key derivation. Nothing in it is encrypted, signed or authenticated.

- **Items:** exactly the encrypted CXF export's — one CXF item per active Login item with at least one passkey, of the one vault the export names ([ADR 0081](0081-multiple-vaults-personal-and-shared.md) §A8: Personal unless another is named), one passkey credential per element; elements that cannot make a credential are left out and counted; trashed items are not exported. `exporterDisplayName` = `"rizzy-vault"` and `exporterRpId` = `""` (ADR 0074 owner answer 5).
- **Caps:** the reader's (`MAX_ENTRIES`, `MAX_JSON_LEN`, `MAX_NODES`), which `cxf_document` already enforces, so every file it writes reads back through `Format::CxfJson`. The 16 MiB `MAX_PLAINTEXT_LEN` of the envelope does not apply: there is no envelope.
- **One writer.** The bare export and the encrypted CXF export must call the same `cxf_document`. For the same vault state, RNG stream and clock, the bare file is byte for byte the `cxf_json` inside the encrypted file's payload (tested, §5).

### 2. The function and its gate

`rizzy-client::export::cxf` gains:

```rust
pub struct CxfPlaintextExport {
    /// The CXF document, unencrypted: one zeroizing buffer of its final size.
    pub document: SecretBytes,
    pub passkeys: usize,
    pub items: usize,
    pub skipped: usize,
}

impl VaultSync {
    pub fn export_cxf_plaintext<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        auth: PlaintextExportAuth,
        ack: PlaintextExportAck,
        now_ms: u64,
    ) -> Result<CxfPlaintextExport, ClientError>;
}
```

- It takes `PlaintextExportAuth` and `PlaintextExportAck` — the tokens of `export_plaintext_json` and `export_plaintext_csv` — and consumes both whatever the outcome, as `export_cxf` does. There is no other entry point to a bare CXF document: `cxf_document` stays `pub(crate)`.
- So the gate is the plaintext export's, unchanged: a fresh re-authentication (ADR 0034 points 1–2), then the warning of §3 shown and recorded (`plaintext_warning_shown`), the 10-second hold (`PLAINTEXT_EXPORT_HOLD_MS`, restarted each time the warning is shown again), and the typed phrase `EXPORT PLAINTEXT`, exactly. No flag, setting or environment variable skips or shortens any of them, and no export runs unattended.
- **Errors:** `ClientError::ExportOversizeItems` and `ClientError::ExportTooLarge` as `cxf_document` returns them; `ClientError::Internal`. There is no export password and so no password check.
- The document never appears in a log, an error or a `Debug` output (INV-48); it goes to the host as one zeroizing buffer (CRYPTO.md §12.2), like the plaintext export.

### 3. The warning

A new frozen constant, `rizzy_client::export::cxf::CXF_PLAINTEXT_EXPORT_WARNING`. It is neither ADR 0027 §5's text, whose first sentence is false here, nor ADR 0074 §2's `CXF_EXPORT_WARNING`, which describes an encrypted file. It keeps ADR 0027 §5's sentences wherever they are true for this file, word for word, and adds what is worse about passkeys. Frozen English source; a translation keeps every sentence:

> This file will hold the private key of every passkey in this vault, unencrypted, as a standard CXF document that any compliant password manager can read. Anyone and any program that can read the file can read them all, including backup and cloud-sync tools and other users of this computer, and can use them to sign in as you, without your password, on every site they belong to. Changing your passwords does not undo that: each passkey would have to be removed from its site and replaced. rizzy-vault cannot protect, track or erase the file once it is written. Delete it as soon as you have imported it into the other password manager. It carries only passkeys, not the rest of this vault. To keep a copy of your passkeys, use the encrypted passkey export instead.

Every host shows it, verbatim and in full, before it asks for the phrase, and the hold runs from the moment it was last shown. No host shortens it or shows it only in part.

### 4. Hosts

- **`rizzy-wasm`:** `Session::export_cxf_plaintext(vault_id, typed_phrase, now_ms)` (`js_name = exportCxfPlaintext`) returns `{ file: Uint8Array, passkeys: number }`. Its checks run in `export_cxf`'s order: `reauth_fresh` (else `reauth_required`), then `PlaintextExportAck::from_typed_phrase` (else `plaintext_export_not_acknowledged`), then `authorize_plaintext` (else `plaintext_export_hold`), then the export. A refusal spends nothing (ADR 0034 point 2). A free function `cxf_plaintext_export_warning()` (`js_name = cxfPlaintextExportWarning`) returns §3's constant. The bindings are regenerated (`RUSTC_BOOTSTRAP=1 cargo xtask expand-bindings --write`); any rise in `unsafe` is generator glue and is explained in the commit ([ADR 0019](0019-native-clients.md) §4.1).
- **`rv`:** `rv export --out <file> --name <login> --format cxf-json [--vault <vault>]`. `cxf-json` is the name `rv import --format` already uses for the same bytes, so a file round-trips under one name. The steps are those of `--format cxf` without the file password: the output-path check, the re-authentication, then §3's warning, `plaintext_gate` (the hold, then the phrase from a terminal), then `write_new_file` under ADR 0027 §5 "Output file" (`create_new`, mode 0600 at creation on Unix, a partial file removed on failure, "file exists" for anything at the path, a symlink included; stdout refused when it is a terminal, INV-56). The closing note: "Exported N passkeys of M as a CXF file, unencrypted. Import it into the other password manager, then delete it." and, if any, the existing skipped-passkeys note. The usage text becomes "--format takes encrypted, json, csv, cxf or cxf-json".
- **Web vault:** the Transfer pane's "Passkey export (CXF)" section gains a second, secondary control, "Export passkeys unencrypted…", next to "Export passkeys…". It opens a modal dialog, "Export passkeys unencrypted (CXF)", built like the plaintext-export dialog: §3's warning from the core, `plaintextWarningShown` called each time the dialog shows it (the countdown restarts, in the core and on screen), a visible 10-second countdown with the confirm control ("Export passkeys unencrypted") disabled, the phrase field, and no file-password fields. On success the file is saved as `rizzy-vault-passkeys-plaintext-<YYYY-MM-DD>.json`, type `application/json`, through the platform download (ADR 0027 §5 "Hosts that save through the platform"); the buffer is zeroed after the save, as the plaintext export does; the status line reads "Wrote {count} passkeys, unencrypted. Delete the file as soon as you have imported it." The new UI strings go into `packages/i18n`; the warning comes from the core.
- **Not in scope:** CXP and every live transfer; CXF's non-passkey credential types (ADR 0074 §1); any change to the plaintext JSON/CSV exports or their warning (open question 2).

### 5. Tests

- **`rizzy-client`** (`src/tests/export.rs`):
  - *Round trip:* a vault with an ES256 and an EdDSA passkey on one Login, a second Login with one passkey, a trashed Login with a passkey, a Login without passkeys, and one element missing a field. `export_cxf_plaintext`, then `detect_format` on the bytes is `Import(Format::CxfJson)`, then `import(Format::CxfJson, …)` and `import_items` into a second vault. Every active passkey arrives with the same `rp_id`, `user_handle`, `credential_id`, `private_key` and `alg`; the trashed one and the broken element do not (`skipped` = 1); the imported ES256 key signs an assertion that verifies under its derived COSE key, as `a_bare_cxf_file_imports_through_the_same_reader` does.
  - *One writer:* with the same seeded RNG and clock, `export_cxf_plaintext`'s document equals the `cxf_json` read back out of `export_cxf`'s payload.
  - *Warning:* `CXF_PLAINTEXT_EXPORT_WARNING` equals §3's text exactly, and differs from `PLAINTEXT_EXPORT_WARNING` and `CXF_EXPORT_WARNING`.
  - *Caps:* a vault past `MAX_ENTRIES` passkey items is `ExportTooLarge` before anything is written.
- **Gate** (`rizzy-wasm` session tests, through `exportCxfPlaintext`): without a re-authentication → `reauth_required`; the warning not yet shown, or shown less than 10 s ago → `plaintext_export_hold`; showing it again restarts the hold; a wrong or lower-case phrase → `plaintext_export_not_acknowledged`; each refusal spends nothing; a success spends the re-authentication, so a second export needs a new one.
- **`rv`** (`crates/rizzy-cli/tests/e2e.rs`): `--format cxf-json` parses (`args.rs` `cxf_commands_parse`); the export prints `CXF_PLAINTEXT_EXPORT_WARNING` before the phrase prompt (found the way the plaintext test finds `PLAINTEXT_EXPORT_WARNING`), refuses a wrong phrase, writes a mode-0600 file, and refuses an existing path; `rv import --in <that file>` into a second account detects `cxf-json`, asks for no password and brings the passkeys in.
- **Web e2e** (`apps/web/e2e/cxf.spec.ts`): a new test imports the CXF fixture, opens "Export passkeys unencrypted (CXF)", checks that the warning is shown in full, that the confirm control stays disabled during the countdown and without the exact phrase, that the download is named `^rizzy-vault-passkeys-plaintext-\d{4}-\d{2}-\d{2}\.json$` and parses as JSON with `version.major` = 1, and that importing it into a second account detects "CXF JSON", asks for no password and shows the passkey.
- **Accessibility:** the new dialog joins the axe audit (`apps/web/e2e/a11y.spec.ts`: visible, focus trapped, Cancel closes) and the keyboard-only walk (`keyboard-nav.spec.ts`: the phrase field is focused on open, as in the plaintext dialog; Escape closes it; the focus returns to "Export passkeys unencrypted…"). Both must pass with no rule suppressed.
- **Fuzzing:** no new target. The new code writes and parses nothing new; the bare file's reader is the existing `import_cxf` target, and its detection the existing `client_detect_format` target.

### 6. What this ADR supersedes

Each entry names one part of an Accepted ADR and writes out its replacement in full ([ADR 0020](0020-partial-supersession.md) point 9). Everything else in ADRs 0027, 0034 and 0074 stays binding: ADR 0074 §1–§4, its open question 4 itself (answered here, not replaced), and its Consequences; ADR 0027 §5's warning bullets, which stay exactly right for plaintext JSON and CSV.

1. **[ADR 0074](0074-passkey-cxf-import-export.md), "Owner answers at acceptance (2026-10-22)", point 4**, word for word: "A bare, unencrypted CXF export: the recommendation is yes, in the same change, behind the same warning, hold and phrase. But it needs a ROADMAP §4.10 edit, and §4.10 still names only "Passkey import/export via FIDO Credential Exchange Protocol (CXP/CXF) when stable". Until the owner makes that edit, the bare form is out of scope. This stays open."

   Replacement:

   > 4. A bare, unencrypted CXF export: yes (owner, 2026-10-24), with the ROADMAP §4.10 edit that names it. [ADR 0084](0084-bare-cxf-passkey-export.md) decides it: `VaultSync::export_cxf_plaintext` writes the CXF document of §2 unencrypted, behind the plaintext export's gate (re-authentication, its own warning, the 10-second hold and the typed `EXPORT PLAINTEXT`), and the existing bare-file reader of §3 reads it back.

2. **[ADR 0034](0034-export-reauth-and-plaintext-hold.md) point 3, first sentence**, in the text [ADR 0074](0074-passkey-cxf-import-export.md) §5 item 2 put in its place: "`VaultSync::export_encrypted`, `export_plaintext_json`, `export_plaintext_csv` and `export_cxf` take `EncryptedExportAuth` or `PlaintextExportAuth`, which have no public constructor: only `ExportGate::authorize_encrypted` / `authorize_plaintext` create them (`ReauthRequired` otherwise); `export_cxf` takes `PlaintextExportAuth` ([ADR 0074](0074-passkey-cxf-import-export.md) §2)."

   Replacement:

   > `VaultSync::export_encrypted`, `export_plaintext_json`, `export_plaintext_csv`, `export_cxf` and `export_cxf_plaintext` take `EncryptedExportAuth` or `PlaintextExportAuth`, which have no public constructor: only `ExportGate::authorize_encrypted` / `authorize_plaintext` create them (`ReauthRequired` otherwise); `export_cxf` ([ADR 0074](0074-passkey-cxf-import-export.md) §2) and `export_cxf_plaintext` ([ADR 0084](0084-bare-cxf-passkey-export.md) §2) take `PlaintextExportAuth`.

   The point's second sentence, "The plaintext calls keep ADR 0027 §5's `PlaintextExportAck`.", stays; `export_cxf_plaintext` is one of those calls.

3. **[ADR 0034](0034-export-reauth-and-plaintext-hold.md) point 5, second sentence**, word for word: "The host shows ADR 0027 §5's warning verbatim (with the CSV addition) and records it (`plaintext_warning_shown`); `authorize_plaintext` refuses with `PlaintextExportHold` until 10 s after the warning was last shown."

   Replacement:

   > The host shows the warning of the export it is about to make, verbatim, and records it (`plaintext_warning_shown`): ADR 0027 §5's (with the CSV addition) for plaintext JSON and CSV, `CXF_EXPORT_WARNING` ([ADR 0074](0074-passkey-cxf-import-export.md) §2) for the encrypted CXF export, and `CXF_PLAINTEXT_EXPORT_WARNING` ([ADR 0084](0084-bare-cxf-passkey-export.md) §3) for the bare CXF export; `authorize_plaintext` refuses with `PlaintextExportHold` until 10 s after the warning was last shown.

4. **[ADR 0027](0027-export-payload.md) §5, first bullet, third sentence**, in the text [ADR 0034](0034-export-reauth-and-plaintext-hold.md) put in its place ("What this ADR supersedes"; its "On acceptance" item 1), word for word: "Before creating it, every host shows the warning below, holds the user for 10 seconds (the gate refuses a plaintext token until 10 seconds after the warning was last shown), and requires the user to type `EXPORT PLAINTEXT` exactly; no flag, setting or environment variable skips the re-authentication, the warning, the hold or the phrase, and `rv` reads the phrase from the terminal, so no export runs unattended."

   Replacement:

   > Before creating it, every host shows the warning below (for the encrypted CXF export, [ADR 0074](0074-passkey-cxf-import-export.md) §2's own warning instead, and for the bare CXF export, [ADR 0084](0084-bare-cxf-passkey-export.md) §3's), holds the user for 10 seconds (the gate refuses a plaintext token until 10 seconds after the warning was last shown), and requires the user to type `EXPORT PLAINTEXT` exactly; no flag, setting or environment variable skips the re-authentication, the warning, the hold or the phrase, and `rv` reads the phrase from the terminal, so no export runs unattended.

Entries 3 and 4 also cover the encrypted CXF export, whose own warning ADR 0074 §2 already fixed without naming these two sentences. They change nothing for it; they make the texts agree.

## Consequences

### Positive

- Interop on the way out: a user can hand their passkeys to another password manager that reads a CXF file, without a rizzy-vault round trip. That closes ADR 0074's "export side is a CXF-shaped self-backup, not interop-out".
- No new format, envelope, purpose, key derivation, parser or dependency. The document writer, the reader and the gate already exist and are tested; the new code is one function, one constant, two bindings and two host flows.
- The warning says what is specific to passkeys: a leak signs in without a password, and a password change does not fix it.

### Negative

- Every exported passkey's private key lands on disk in the clear, which the encrypted CXF export was designed to avoid (ADR 0074 Alternatives, "Bare, unencrypted CXF export only"). The gate slows a user down; it does not protect the file.
- One more frozen warning text, which translations must keep sentence for sentence.
- Two CXF export controls in the web vault, side by side; the dialogs' titles, buttons and warnings must keep them apart.

### Risks

- **Other vendors may not import a bare CXF file** (Context, U), or may expect a different shape. Signal: a mainstream manager's documented CXF import refusing our file. Mitigation: the document follows CXF 1.0 as ADR 0074 read it; a change of shape needs a new ADR, not a quiet tweak.
- **The file outlives its purpose** in downloads folders, backups and cloud sync. Mitigation: the warning says so, and says to delete the file after the import; nothing else can be done for a plaintext file.
- **A modified client skips the gate** (ADR 0034 Risks). Unchanged: the gate defends an honest client left unlocked, not a hostile one.
- **CXF changes shape** (ADR 0074 Risks): our own reader refuses an unknown `version.major`; another vendor's reader is outside our control.

## Alternatives considered

- **Reuse ADR 0027 §5's warning verbatim, with a passkey "adds" sentence** (the CSV mechanism). Rejected: its first sentence, "This file will hold every password, one-time-code secret, card number and note of this vault", is false for a passkey-only file, and the frozen base text cannot be edited. §3 keeps every sentence of it that is true here, word for word (open question 1).
- **Reuse `CXF_EXPORT_WARNING`.** Rejected: it begins "Once decrypted with its export password", which is false for a file that is not encrypted.
- **A dedicated phrase** (for example `EXPORT PASSKEYS`). Rejected by the owner's words ("typed phrase EXPORT PLAINTEXT") and by ADR 0074 owner answer 3.
- **Ship the bare export only, and drop the encrypted CXF export.** Rejected: the encrypted form stays the safe way to keep a copy, and §3's last sentence points to it.
- **Name the `rv` format `cxf-plaintext`.** It would say "plaintext" outright, but the same bytes would then go by two names (`rv import --format cxf-json` already exists). The warning, the hold and the phrase are what warn the user, not the flag name.

## Open questions for the owner

1. **Is §3's own warning text what "the exact same scary warning" means?** The owner's words can be read as "the same gate" (warning, hold, phrase) or as "ADR 0027 §5's exact text". That text's first sentence is false for this file (it lists passwords, one-time-code secrets, card numbers and notes, and the file holds none of them) and it does not say that a leaked passkey signs in without a password. *Recommendation:* the gate is identical and the text is §3's own constant, which keeps ADR 0027 §5's other sentences word for word. If the owner wants ADR 0027 §5's text verbatim instead, §3 and §6 entries 3 and 4 shrink accordingly, and no other part of this ADR changes.
2. **Should ADR 0027 §5's warning also name passkeys?** The plaintext JSON export already carries every passkey's private key (Context), and its warning does not say so. *Recommendation:* yes, in a separate Proposed ADR that supersedes that warning bullet. It is outside the owner's words of 2026-10-24, and this ADR does not change it.

## On acceptance

The accepting change makes these edits; none is made now ([ADR 0020](0020-partial-supersession.md) point 9).

1. **[ROADMAP §4.10](../ROADMAP.md#410-mobile--passkeys-m7)** (the owner's approval of 2026-10-24). The row

   `| S | Passkey import/export via FIDO Credential Exchange Protocol (CXP/CXF) when stable | M8 |`

   becomes

   `| S | Passkey import/export via FIDO Credential Exchange Protocol (CXP/CXF) when stable; export also as a bare, unencrypted CXF file, behind the plaintext-export warning, 10-second hold and typed EXPORT PLAINTEXT, so passkeys can move straight into another password manager (owner decision of 2026-10-24, [ADR 0084](adr/0084-bare-cxf-passkey-export.md)) | M8 |`

2. **Status lines and [index](README.md) rows.** [ADR 0074](0074-passkey-cxf-import-export.md), now "Accepted": "Partially superseded by [ADR 0084](0084-bare-cxf-passkey-export.md) (§5 in part, owner answer 4)". [ADR 0034](0034-export-reauth-and-plaintext-hold.md): append "; [ADR 0084](0084-bare-cxf-passkey-export.md) (point 3 in part, point 5 in part)". [ADR 0027](0027-export-payload.md): append "; [ADR 0084](0084-bare-cxf-passkey-export.md) (§5 in part)". This ADR's row and status line move to Accepted.
3. **[CRYPTO.md §11.14](../CRYPTO.md#1114-encrypted-export-m1).** After the "CXF passkey export" bullet, add: "**Bare CXF export (M8, [ADR 0084](adr/0084-bare-cxf-passkey-export.md)).** The same CXF document, unencrypted: no wrapper, no envelope and no key derivation. It is gated like a plaintext export and reads back as a bare CXF file ([ADR 0074](adr/0074-passkey-cxf-import-export.md) §3)." The "Plaintext export" bullet becomes: "**Plaintext export** (JSON or CSV, and the bare CXF export) exists, behind the "scary warning" from ROADMAP §4.2."
4. **[THREAT_MODEL.md](../THREAT_MODEL.md) [AST-9](../THREAT_MODEL.md#2-assets)** ("Impact" cell), after its last sentence: "A bare CXF export writes them to a file unencrypted ([ADR 0084](adr/0084-bare-cxf-passkey-export.md))." **[AST-20](../THREAT_MODEL.md#2-assets)** ("Impact" cell), after its last sentence: "A bare CXF export holds every passkey's private key unencrypted, behind the plaintext export's gate ([ADR 0084](adr/0084-bare-cxf-passkey-export.md))."

## References

- [ADR 0074](0074-passkey-cxf-import-export.md) §1–§5, open question 4, owner answers 3–5; [ADR 0034](0034-export-reauth-and-plaintext-hold.md) points 1–5; [ADR 0027](0027-export-payload.md) §3–§6; [ADR 0039](0039-passkeys-vault-and-extension.md) §1 (the passkey fields); [ADR 0081](0081-multiple-vaults-personal-and-shared.md) §A8; [ADR 0019](0019-native-clients.md) §4.1 (generated glue); [ADR 0020](0020-partial-supersession.md) point 9.
- [ROADMAP §4.2](../ROADMAP.md#42-core-vault-m1), [§4.10](../ROADMAP.md#410-mobile--passkeys-m7); [CRYPTO.md §11.14](../CRYPTO.md#1114-encrypted-export-m1), §12.2; [THREAT_MODEL.md](../THREAT_MODEL.md) AST-9, AST-20, A16, INV-48, INV-56.
- Code (V, read at `f20ad1d`): `crates/rizzy-client/src/export/cxf.rs` (`CXF_EXPORT_WARNING`, `export_cxf`, `cxf_document`, `encode_cxf_payload`), `plaintext.rs` (`PLAINTEXT_EXPORT_PHRASE`, `PLAINTEXT_EXPORT_WARNING`, `json_item`), `gate.rs`, `detect.rs`; `crates/rizzy-import/src/cxf.rs` (`looks_like_cxf`); `crates/rizzy-wasm/src/session.rs` (`export_cxf`, `plaintext_warning_shown`, `cxf_export_warning`); `crates/rizzy-cli/src/commands.rs` (`export`, `plaintext_gate`), `args.rs`; `apps/web/src/views/TransferPane.tsx`, `apps/web/e2e/cxf.spec.ts`, `a11y.spec.ts`, `keyboard-nav.spec.ts`; the test `a_bare_cxf_file_imports_through_the_same_reader`.
- FIDO Alliance, Credential Exchange Format 1.0 (Proposed Standard, errata 2026-03-09): read for ADR 0074 (V there); not re-read for this ADR. Vendor support for importing a bare CXF file: U.
