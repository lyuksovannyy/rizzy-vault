// SPDX-License-Identifier: AGPL-3.0-only

// The popup's fixed sentences for the passkey re-verification (ADR 0110 §7 points 3 and 6): one
// per reply code, none echoing any input.
import type { UvReplyCode } from "../messaging/contract.ts";

/** The sentence the verification view shows for `code`. */
export function uvReplySentence(code: UvReplyCode): string {
  switch (code) {
    case "uv_ok":
      return "Verified. The passkey request continues on the page.";
    case "uv_wrong_password":
      return "Wrong master password. Try again.";
    case "uv_attempts_exhausted":
      return "Too many wrong master passwords. The passkey request was cancelled.";
    case "uv_ceremony_gone":
      return "This passkey request is no longer waiting. Start it again on the page.";
    case "uv_cancelled":
      return "The passkey request was cancelled.";
    case "uv_locked":
      return "The vault locked. Unlock it, then start the passkey request again on the page.";
  }
}

/** The kind of a waiting ceremony, as the view names it. */
export function uvKindLabel(kind: "create" | "get"): string {
  return kind === "create" ? "Save passkey" : "Sign in";
}
