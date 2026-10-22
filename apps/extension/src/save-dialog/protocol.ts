// SPDX-License-Identifier: AGPL-3.0-only

// The `postMessage` protocol between the content script and the extension-origin save dialog
// (ADR 0076 §5.2). Like the inline menu's (`inline-menu/protocol.ts`), the content script →
// iframe direction is forgeable by the page (any frame can post into the iframe), so the show
// message carries only what is needed to *ask* the long-lived context: the ADR 0043 instance
// token (which the background vouches for, a forged one is refused) and the save-prompt token.
// The rows the dialog shows come from the long-lived context directly
// (`messaging/contract.ts`'s `SaveDialogRequestMessage`), never from this message.
import { MAX_FIELD_VALUE_LEN, isInstanceToken } from "../messaging/contract.ts";

export const SAVE_DIALOG_SHOW = "rizzy-save-dialog-show";
export const SAVE_DIALOG_DONE = "rizzy-save-dialog-done";

export interface SaveDialogShowMessage {
  readonly type: typeof SAVE_DIALOG_SHOW;
  /** The embedding page's origin: the target of the "done" reply, never an identity claim. */
  readonly pageOrigin: string;
  /** ADR 0043 point 3: this iframe instance's token. */
  readonly instanceToken: string;
  /** The pending save prompt's one-time token. */
  readonly token: string;
}

export interface SaveDialogDoneMessage {
  readonly type: typeof SAVE_DIALOG_DONE;
}

export function isSaveDialogShowMessage(value: unknown): value is SaveDialogShowMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    v["type"] === SAVE_DIALOG_SHOW &&
    typeof v["pageOrigin"] === "string" &&
    v["pageOrigin"].length <= MAX_FIELD_VALUE_LEN &&
    isInstanceToken(v["instanceToken"]) &&
    typeof v["token"] === "string" &&
    v["token"].length <= 256
  );
}

export function isSaveDialogDoneMessage(value: unknown): value is SaveDialogDoneMessage {
  return typeof value === "object" && value !== null && (value as Record<string, unknown>)["type"] === SAVE_DIALOG_DONE;
}

/** The dialog's title for a save or an update (ADR 0076 §5.3). */
export function dialogTitle(suggestion: "save" | "update", itemTitle: string | undefined): string {
  return suggestion === "save" ? "Save this login to rizzy-vault?" : `Update “${itemTitle ?? "this login"}” in rizzy-vault?`;
}

/** One row's label (ADR 0076 §5.3): "Add custom field <Display Name>" or "Update <Display
 * Name>", with "(hidden)" for a masked field. */
export function rowText(kind: "add" | "update", label: string, concealed: boolean): string {
  const base = kind === "add" ? "Add custom field" : `Update ${label}`;
  return concealed ? `${base} (hidden)` : base;
}
