// SPDX-License-Identifier: AGPL-3.0-only

// The English catalogue: the source locale, and the only one for now (ROADMAP §4.5, "English
// only at first"). Its keys are the type `MessageKey` (`translate.ts`), so a key used anywhere
// but missing here, or missing from another locale's catalogue, is a compile error.
//
// Rules for an entry (README.md):
// - The key is `<area>.<name>`. `errors.<code>` words one stable error code of the core or of
//   the web vault (ADR 0013 §3 rule 4: errors are codes; the host words them). An `errors.*`
//   entry takes no placeholder: no error message ever includes a value the user typed (INV-48).
// - A placeholder is `{name}` (a letter, then letters, digits or `_`), filled by `t`.
//   Braces mean nothing else. The text is plain text: React escapes it; it is never HTML
//   (ADR 0014 §2).
// - Plurals are not supported yet; no message needs one.

/** The English text of every message. `as const` keeps each text's literal type, which is how
 *  `t` knows a message's placeholders. */
export const en = {
  // ---- Error codes (moved from apps/web/src/messages.ts; identical English) ----
  "errors.wrong_password_or_secret_key": "Wrong login name, master password or Secret Key.",
  "errors.server_unauthorized": "Wrong login name, master password or Secret Key.",
  "errors.server_second_factor_required": "This account needs a two-factor code.",
  "errors.totp_cancelled": "Login cancelled.",
  "errors.server_rate_limited": "Too many attempts. Wait a little and try again.",
  "errors.server_api_version_gone": "This server no longer speaks the API this web vault uses. Reload the page.",
  "errors.server_client_too_old": "This web vault is older than the server allows. Reload the page.",
  "errors.server_state_conflict": "That name is taken, or the server refused the request. Try another.",
  "errors.server_invalid_request": "The server refused the request.",
  "errors.server_payload_too_large": "That is larger than the server accepts.",
  "errors.server_internal": "The server failed. Try again later.",
  "errors.server_not_found": "The server does not offer this.",
  "errors.server_unknown": "The server answered with an error this web vault does not know.",
  "errors.server_fresh_session_required": "Log in again to do this.",
  "errors.server_setup_retired":
    "The server changed its login setup while you signed up. Sign up again, or try again later.",
  "errors.setup_retired": "The server refused the registration again after it was restarted. Try again later.",
  "errors.server_credentials_stale":
    "The server was restored from a backup and does not take this login yet. Open rizzy-vault on a device that is already set up for this account (it repairs the server with your master password), then log in again.",
  "errors.server_quota_exceeded":
    "This account has reached its storage limit on this server, so the server did not save the latest change. Ask the server's operator for more space.",
  "errors.attachment_too_large": "That file is larger than 25 MiB, the most an attachment can hold.",
  "errors.attachment_incomplete":
    "The attachment did not download completely or failed its check, so it was not saved. Try again; if it keeps failing, the server may not hold all of it.",
  "errors.transport_failed": "Cannot reach the server. Check the connection and try again.",
  "errors.response_too_large": "The server's answer was too large.",
  "errors.locked": "The vault is locked.",
  "errors.session_ended": "This session has ended. Log in again.",
  "errors.read_only": "This vault is read-only right now.",
  "errors.invalid_input": "That input is not valid.",
  "errors.invalid_edit": "That change is not valid for this item.",
  "errors.unknown_item": "That item no longer exists.",
  "errors.emergency_kit_not_confirmed": "That is not the last group of your Secret Key. Check the kit.",
  "errors.export_decryption_failed": "Wrong password for this export file, or the file is damaged.",
  "errors.invalid_export_file": "That is not a rizzy-vault export file.",
  "errors.export_update_required": "That export was made by a newer rizzy-vault.",
  "errors.plaintext_export_not_acknowledged": "Type the phrase exactly as shown.",
  "errors.reauth_required":
    "Confirm your Secret Key and master password first. The confirmation allows one export within five minutes.",
  "errors.plaintext_export_hold": "Read the warning. The export can continue when the countdown ends.",
  "errors.passwords_differ": "The two passwords differ.",
  "errors.unrecognised_format": "The file's format was not recognised. Choose it from the list.",
  "errors.rizzy_csv_not_importable":
    "This is a rizzy-vault CSV export, which cannot be imported (CSV leaves data out). Import the JSON or the encrypted export instead.",
  "errors.import_failed": "That file could not be imported in that format.",
  "errors.unknown_format": "Unknown format.",
  "errors.rollback": "The server sent an older vault state than this session has seen. Do not trust this server; report it.",
  "errors.fork": "The server showed this session a different history than before. Do not trust this server; report it.",
  "errors.account_key_rotated": "The account's keys changed on another device. Log in again.",
  "errors.vault_key_rotated": "The vault's keys changed on another device. Log in again.",
  "errors.identity_change_unconfirmed": "The account's identity changed and is not confirmed. Use a trusted device.",
  "errors.device_state_outdated": "This session is out of date. Log in again.",
  "errors.wrong_state": "That step is not possible now.",
  "errors.already_shown": "The Emergency Kit can be shown only once.",
  "errors.core_crashed": "The vault core stopped. Reload the page and log in again.",
  "errors.settings_update_required":
    "This account's settings were saved by a newer rizzy-vault. Update to read or change them; autofill matching is off until then.",
  "errors.equivalence_domain_rejected":
    "Use each site's own domain, like example.com: not a public suffix such as co.uk or github.io, and not a subdomain such as www.example.com.",
  "errors.settings_limit_reached": "The account settings are full: at most 64 groups of your own and 1,024 turned-off groups.",
  "errors.autocomplete_invalid": "An autocomplete id is 1–64 lowercase letters, digits, “-”, “_” or “.”, with no spaces.",
  "errors.autocomplete_reserved": "That autocomplete id is reserved for the manager.",
  "errors.autocomplete_duplicate": "Another custom field of this item already uses that autocomplete id.",
  "errors.autocomplete_kind": "Only text and hidden custom fields can have an autocomplete id.",
  "errors.label_required": "Every custom field needs a display name.",

  // ---- Shared ----
  // An error code without an `errors.*` entry: shown with the code itself, so that a report
  // names it. The code is the core's or the server's stable identifier, never user input.
  "common.unknownError": "Something went wrong ({code}).",
  "action.continue": "Continue",
  "action.cancel": "Cancel",

  // ---- Login and unlock (apps/web/src/views/LoginView.tsx) ----
  "login.title": "Log in to rizzy-vault",
  "login.unlockTitle": "Unlock rizzy-vault",
  "login.loginName": "Login name",
  "login.secretKey": "Secret Key",
  "login.secretKeyHint": "From your Emergency Kit. It starts with RV1-.",
  "login.masterPassword": "Master password",
  "login.noSavingHint":
    "Do not let the browser save your master password or Secret Key. This web vault keeps nothing after a reload or a lock: you log in again each time.",
  "login.submit": "Log in",
  "login.unlock": "Unlock",
  "login.busy": "Logging in…",
  "login.createAccount": "Create an account",

  // ---- Second factor at login (apps/web/src/views/TotpDialog.tsx) ----
  // ---- Attachments (ADR 0054) ----
  "attachments.heading": "Attachments",
  "attachments.empty": "No attachments.",
  "attachments.add": "Attach a file",
  "attachments.limit": "Up to 25 MiB per file. Files are encrypted before they leave this browser.",
  "attachments.adding": "Encrypting and uploading {name}…",
  "attachments.added": "Attached {name}.",
  "attachments.download": "Download {name}",
  "attachments.downloaded": "Downloaded {name}.",
  "attachments.delete": "Delete {name}",
  "attachments.deleteTitle": "Delete this attachment?",
  "attachments.deleteDescription": "{name} will be removed from this item and from the server. This cannot be undone.",
  "attachments.deleteConfirm": "Delete attachment",
  "attachments.deleted": "Deleted {name}.",
  "totp.title": "Two-factor code",
  "totp.prompt": "Enter the current code from your authenticator app.",
  "totp.code": "Code",

  // ---- Passkey export and import, CXF (apps/web/src/views/TransferPane.tsx; ADR 0074) ----
  "transfer.cxfTitle": "Passkey export (CXF)",
  "transfer.cxfIntro":
    "Every passkey of your active logins, as a standard FIDO Credential Exchange Format (CXF) document inside a file encrypted under a password for that file. Only passkeys, nothing else.",
  "transfer.cxfCount": "Passkeys to export: {count}.",
  "transfer.cxfOpen": "Export passkeys…",
  "transfer.cxfDialogTitle": "Export passkeys (CXF)",
  "transfer.cxfPassword": "Password for this export file",
  "transfer.cxfPasswordRepeat": "Repeat the password for this export file",
  "transfer.cxfPasswordHint": "Needed to import the file. It is not your master password, and nobody can recover it if it is lost.",
  "transfer.cxfConfirm": "Export passkeys",
  "transfer.cxfWritten": "Wrote {count} passkeys, encrypted. Keep the file's password: it is needed to import the file.",
  "transfer.countdown": "Read the warning. You can continue in {seconds} s.",
  "transfer.countdownDone": "You can continue now.",
  "transfer.typePhrase": "Type {phrase} to continue",
  "transfer.formatCxfJson": "CXF passkey file (FIDO Credential Exchange Format)",
  "transfer.formatRizzyCxf": "rizzy-vault passkey export (CXF, encrypted)",
  "transfer.credentialsSkipped": "CXF credentials not imported (only passkeys are): {count}.",
} as const satisfies Readonly<Record<string, string>>;
