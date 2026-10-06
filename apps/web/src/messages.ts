// User-facing text for the stable error codes (ADR 0013 §3 rule 4: errors are codes; the host
// words them). A code without an entry is shown as a generic failure with the code itself, so
// that a report names it. No message ever includes a value the user typed (INV-48).
//
// Generator refusals (`generator_*`) use the core's own wording, copied into
// `generator-constants.ts` rather than imported at runtime (that module's docs: the UI thread
// imports only types from `@rizzy-vault/core`, ADR 0013 §4), so every `ErrorText` in the app,
// not just the generator views, shows the same sentence for the same code.
import { generatorErrorMessage } from "./generator-constants.ts";
import { CORE_CRASHED, TOTP_CANCELLED } from "./protocol.ts";

/** The text for each code this web vault words. */
const MESSAGES: Readonly<Record<string, string>> = {
  wrong_password_or_secret_key: "Wrong login name, master password or Secret Key.",
  server_unauthorized: "Wrong login name, master password or Secret Key.",
  server_second_factor_required: "This account needs a two-factor code.",
  [TOTP_CANCELLED]: "Login cancelled.",
  server_rate_limited: "Too many attempts. Wait a little and try again.",
  server_api_version_gone: "This server no longer speaks the API this web vault uses. Reload the page.",
  server_client_too_old: "This web vault is older than the server allows. Reload the page.",
  server_state_conflict: "That name is taken, or the server refused the request. Try another.",
  server_invalid_request: "The server refused the request.",
  server_payload_too_large: "That is larger than the server accepts.",
  server_internal: "The server failed. Try again later.",
  server_not_found: "The server does not offer this.",
  server_unknown: "The server answered with an error this web vault does not know.",
  server_fresh_session_required: "Log in again to do this.",
  server_setup_retired:
    "The server changed its login setup while you signed up. Sign up again, or try again later.",
  setup_retired: "The server refused the registration again after it was restarted. Try again later.",
  server_credentials_stale:
    "The server was restored from a backup and does not take this login yet. Open rizzy-vault on a device that is already set up for this account (it repairs the server with your master password), then log in again.",
  transport_failed: "Cannot reach the server. Check the connection and try again.",
  response_too_large: "The server's answer was too large.",
  locked: "The vault is locked.",
  read_only: "This vault is read-only right now.",
  invalid_input: "That input is not valid.",
  invalid_edit: "That change is not valid for this item.",
  unknown_item: "That item no longer exists.",
  emergency_kit_not_confirmed: "That is not the last group of your Secret Key. Check the kit.",
  export_decryption_failed: "Wrong password for this export file, or the file is damaged.",
  invalid_export_file: "That is not a rizzy-vault export file.",
  export_update_required: "That export was made by a newer rizzy-vault.",
  plaintext_export_not_acknowledged: "Type the phrase exactly as shown.",
  reauth_required:
    "Confirm your Secret Key and master password first. The confirmation allows one export within five minutes.",
  plaintext_export_hold: "Read the warning. The export can continue when the countdown ends.",
  passwords_differ: "The two passwords differ.",
  unrecognised_format: "The file's format was not recognised. Choose it from the list.",
  rizzy_csv_not_importable:
    "This is a rizzy-vault CSV export, which cannot be imported (CSV leaves data out). Import the JSON or the encrypted export instead.",
  import_failed: "That file could not be imported in that format.",
  unknown_format: "Unknown format.",
  rollback: "The server sent an older vault state than this session has seen. Do not trust this server; report it.",
  fork: "The server showed this session a different history than before. Do not trust this server; report it.",
  account_key_rotated: "The account's keys changed on another device. Log in again.",
  vault_key_rotated: "The vault's keys changed on another device. Log in again.",
  identity_change_unconfirmed: "The account's identity changed and is not confirmed. Use a trusted device.",
  device_state_outdated: "This session is out of date. Log in again.",
  wrong_state: "That step is not possible now.",
  already_shown: "The Emergency Kit can be shown only once.",
  [CORE_CRASHED]: "The vault core stopped. Reload the page and log in again.",
};

/** The text for `code`. */
export function messageFor(code: string): string {
  if (code in MESSAGES) {
    return MESSAGES[code] ?? `Something went wrong (${code}).`;
  }
  if (code.startsWith("generator_")) {
    return generatorErrorMessage(code);
  }
  return `Something went wrong (${code}).`;
}
