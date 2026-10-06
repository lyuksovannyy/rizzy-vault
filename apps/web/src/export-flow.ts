// The export and import steps of the "Export and import" pane, apart from React, so that the
// gates are tested without a DOM (owner decision 2026-10-05):
// - every export, encrypted or plaintext, comes after a re-authentication with the Secret Key
//   and master password (`confirmIdentity`), which the core accepts for one export within five
//   minutes;
// - the encrypted export is under a new password for that file, typed twice;
// - an import file's format is recognised from its bytes; our encrypted export then asks for
//   the file's password.
// The core enforces each gate itself (`reauth_required`, `plaintext_export_hold`); these
// checks only stop a request the core would refuse and word it.
import type { DetectedImportFormat, EncryptedExport, ImportFormat } from "@rizzy-vault/core";

import { CallError, type CoreClient, secretBytes } from "./core-client.ts";

/** The part of {@link CoreClient} these steps use, so tests can pass a fake. */
export type Caller = Pick<CoreClient, "call">;

/** The re-authentication every export needs: an OPAQUE login with what the user typed. */
export async function confirmIdentity(
  client: Caller,
  secretKey: string,
  password: string,
): Promise<void> {
  await client.call("reauthenticate", secretBytes(secretKey), secretBytes(password));
}

/**
 * The encrypted export under a new password for the file, typed twice. Refuses before the core
 * is asked when the two differ (`passwords_differ`) or no re-authentication is fresh
 * (`reauth_required`).
 */
export async function encryptedExport(
  client: Caller,
  password: string,
  repeat: string,
): Promise<EncryptedExport> {
  if (password !== repeat) {
    throw new CallError("passwords_differ");
  }
  if (!(await client.call("reauthFresh"))) {
    throw new CallError("reauth_required");
  }
  return client.call("exportEncrypted", secretBytes(password));
}

/** What the import form does with a recognised (or chosen) format. */
export type ImportPlan =
  | { readonly kind: "encrypted" }
  | { readonly kind: "file"; readonly format: ImportFormat }
  | { readonly kind: "refused"; readonly code: string };

/** The plan for a format: our encrypted export, an importer, or a refusal with its code. */
export function importPlan(format: DetectedImportFormat): ImportPlan {
  switch (format) {
    case "rizzy-encrypted":
      return { kind: "encrypted" };
    case "rizzy-csv":
      return { kind: "refused", code: "rizzy_csv_not_importable" };
    case "unknown":
      return { kind: "refused", code: "unrecognised_format" };
    default:
      return { kind: "file", format };
  }
}

/** How the import form names each format. */
export const FORMAT_LABELS: Readonly<Record<Exclude<DetectedImportFormat, "unknown">, string>> = {
  "rizzy-encrypted": "rizzy-vault encrypted export",
  "rizzy-json": "rizzy-vault plaintext JSON export",
  "rizzy-csv": "rizzy-vault plaintext CSV export (cannot be imported)",
  "bitwarden-json": "Bitwarden JSON (unencrypted)",
  "1pux": "1Password (.1pux)",
  "keepass-xml": "KeePass XML",
  "chrome-csv": "Chrome CSV",
  "firefox-csv": "Firefox CSV",
  csv: "Generic CSV",
  "aliasvault-csv": "AliasVault CSV",
  "aliasvault-avux": "AliasVault (.avux)",
};
