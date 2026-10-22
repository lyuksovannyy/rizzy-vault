// SPDX-License-Identifier: AGPL-3.0-only

// The inline menu's per-row disclosure (ADR 0076 §4.1 step 4), split out of `main.ts` so it is
// unit tested in Node (`test/inline-menu-offer.test.ts`).
import type { OfferCandidate } from "../messaging/contract.ts";

/** The disclosure of one row (ADR 0076 §4.1 step 4): "Also fills: one-time code · <Display
 * Name> · <Display Name> (hidden)". Display Names are rendered as text, never a value. */
export function disclosureText(offered: OfferCandidate | undefined): string {
  if (offered === undefined) {
    return "";
  }
  const parts = [
    ...(offered.fillsTotp ? ["one-time code"] : []),
    ...offered.customFill.map((c) => (c.concealed ? `${c.label} (hidden)` : c.label)),
  ];
  return parts.length === 0 ? "" : `Also fills: ${parts.join(" · ")}`;
}
