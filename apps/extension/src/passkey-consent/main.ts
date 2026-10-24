// SPDX-License-Identifier: AGPL-3.0-only

// The passkey consent iframe's own script (ADR 0039 §2; ADR 0014 §2-style framework-free,
// same reasoning as `inline-menu/main.ts`: a handful of buttons with no state worth a
// framework). Runs at the extension's own origin, inside an iframe `passkey-relay.ts` injects
// into an untrusted page: see `protocol.ts` for exactly what that origin boundary does and does
// not guarantee, and `inline-menu/main.ts`'s own module docs for the general pattern this
// mirrors (the same ADR 0040 "the privileged document asks the long-lived context directly"
// rule, applied here to approving/declining a ceremony instead of choosing a fill).
import "@rizzy-vault/ui/tokens.css";
import "../surface.css";

import { isPasskeyConsentShowMessage, PASSKEY_CONSENT_DONE, type PasskeyConsentShowMessage } from "./protocol.ts";
import type { PasskeyCeremonyMessage, PasskeyCeremonyResponse } from "../messaging/contract.ts";

const prompt = document.getElementById("prompt");
if (prompt === null) {
  throw new Error("passkey-consent: #prompt is missing from index.html");
}

let replyOrigin: string | undefined;

window.addEventListener("message", (event) => {
  // `event.source`/`event.origin` are browser-set from the real sending window/document
  // (`inline-menu/main.ts`'s identical check, same residual: the sender here is `window.parent`,
  // which the embedding page's own script shares with the content script — checking it anyway
  // rejects any other window's attempt at no cost).
  if (event.source !== window.parent) {
    return;
  }
  if (!isPasskeyConsentShowMessage(event.data)) {
    return;
  }
  replyOrigin = event.data.pageOrigin;
  render(event.data);
});

function render(offer: PasskeyConsentShowMessage): void {
  if (prompt === null) {
    return;
  }
  prompt.replaceChildren();
  const heading = document.createElement("p");
  heading.textContent =
    offer.kind === "create"
      ? `Save a passkey for ${offer.rpId} as ${offer.userName ?? ""}?`
      : `Sign in to ${offer.rpId} with a saved passkey`;
  prompt.appendChild(heading);

  if (offer.kind === "create") {
    // ADR 0081 §A8: a new login's vault, the Personal vault preselected every time.
    const picker = vaultPicker(offer);
    prompt.appendChild(
      button(offer.rpName ?? offer.rpId, () => void respond(offer, approvedMessage(offer, undefined, picker?.value))),
    );
  } else {
    for (const candidate of offer.candidates ?? []) {
      prompt.appendChild(
        button(`${candidate.itemTitle} (${candidate.userName})`, () =>
          void respond(offer, approvedMessage(offer, candidate.passkeyRef)),
        ),
      );
    }
  }
  prompt.appendChild(
    button("Not now", () =>
      void respond(offer, { type: "passkey_ceremony_declined", instanceToken: offer.instanceToken, ceremonyToken: offer.ceremonyToken }),
    ),
  );
}

/** The vault picker of a `create` that saves a new login, appended to the prompt, or
 * `undefined` when the offer has none (one vault, or a passkey added to an existing login). */
function vaultPicker(offer: PasskeyConsentShowMessage): HTMLSelectElement | undefined {
  if (prompt === null || offer.vaults === undefined || offer.vaults.length < 2) {
    return undefined;
  }
  const label = document.createElement("label");
  label.htmlFor = "consent-vault";
  label.textContent = "Vault";
  const select = document.createElement("select");
  select.id = "consent-vault";
  select.name = "vault";
  for (const vault of offer.vaults) {
    const option = document.createElement("option");
    option.value = vault.id;
    option.textContent = vault.label;
    option.selected = vault.id === offer.defaultVaultId;
    select.appendChild(option);
  }
  prompt.append(label, select);
  return select;
}

/** Both tokens travel together, each its own check at the background: `instanceToken` (ADR 0043,
 * "is this the consent iframe the content script built") and `ceremonyToken` (ADR 0039 §2, "is
 * this the ceremony the background offered"), never one in place of the other (ADR 0043 point 6). */
function approvedMessage(offer: PasskeyConsentShowMessage, chosenPasskeyRef?: string, vaultId?: string): PasskeyCeremonyMessage {
  return {
    type: "passkey_ceremony_approved",
    instanceToken: offer.instanceToken,
    ceremonyToken: offer.ceremonyToken,
    ...(chosenPasskeyRef !== undefined ? { chosenPasskeyRef } : {}),
    ...(vaultId !== undefined && vaultId !== "" ? { vaultId } : {}),
  };
}

function button(label: string, onClick: (event: MouseEvent) => void): HTMLButtonElement {
  const el = document.createElement("button");
  el.type = "button";
  el.textContent = label;
  el.addEventListener("click", (event) => {
    // Defence in depth, not the primary guarantee (INV-36), exactly as `inline-menu/main.ts`'s
    // identical check documents: the primary guarantee is that this document's DOM is
    // unreachable from the page's own JS at all.
    if (!event.isTrusted) {
      return;
    }
    onClick(event);
  });
  return el;
}

/** Sends the one privileged message this document ever sends (ADR 0039 §2, mirroring ADR 0040),
 * and always settles once the round trip is over — the caller holds the
 * {@link PASSKEY_CONSENT_DONE} teardown message until this settles, exactly for the reason
 * `inline-menu/main.ts`'s `requestFill` already documents (removing the iframe mid-flight would
 * tear down this document's own JS execution context before the extension message channel had a
 * chance to complete the round trip). The response itself (`PasskeyCeremonyResponse`) is never
 * inspected beyond that: a failure here still means "fall back" to the content script/page, via
 * the separate `apply_passkey_result` push this response's own doc explains — never a secret,
 * either way (ADR 0040 "never back to the iframe"). */
async function respond(offer: PasskeyConsentShowMessage, message: PasskeyCeremonyMessage): Promise<void> {
  const origin = replyOrigin;
  const ext = typeof chrome !== "undefined" ? chrome : browser;
  try {
    if (ext !== undefined) {
      await (ext.runtime.sendMessage(message) as Promise<PasskeyCeremonyResponse | undefined>);
    }
  } catch {
    // The background/offscreen document was unreachable: nothing more to do — the page's own
    // pending ceremony falls back on its own timeout either way.
  } finally {
    if (origin !== undefined) {
      window.parent.postMessage({ type: PASSKEY_CONSENT_DONE }, origin);
    }
  }
}

