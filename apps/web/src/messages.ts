// SPDX-License-Identifier: AGPL-3.0-only

// User-facing text for the stable error codes (ADR 0013 §3 rule 4: errors are codes; the host
// words them). The words are the `errors.<code>` entries of the English catalogue in
// `@rizzy-vault/i18n` (`packages/i18n/src/en.ts`); this module only picks the entry. A code
// without an entry is shown as a generic failure with the code itself, so that a report names
// it. No message ever includes a value the user typed (INV-48).
//
// Generator refusals (`generator_*`) use the core's own wording, copied into
// `generator-constants.ts` rather than imported at runtime (that module's docs: the UI thread
// imports only types from `@rizzy-vault/core`, ADR 0013 §4), so every `ErrorText` in the app,
// not just the generator views, shows the same sentence for the same code. Identity generator
// refusals (`identity_*`, ADR 0079) do the same through `identity-constants.ts`.
import { isMessageKey, t } from "@rizzy-vault/i18n";

import { generatorErrorMessage } from "./generator-constants.ts";
import { identityErrorMessage } from "./identity-constants.ts";

/** The text for `code`. */
export function messageFor(code: string): string {
  const key = `errors.${code}` as const;
  if (isMessageKey(key)) {
    return t(key);
  }
  if (code.startsWith("generator_")) {
    return generatorErrorMessage(code);
  }
  if (code.startsWith("identity_")) {
    return identityErrorMessage(code);
  }
  return t("common.unknownError", { code });
}
