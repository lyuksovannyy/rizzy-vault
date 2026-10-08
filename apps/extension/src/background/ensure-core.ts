// A tiny, Chromium-only piece of transport plumbing, not part of the content-script/popup
// contract in `messaging/contract.ts`: a message the popup/options transport sends once before
// its first real request, purely to make `background/service-worker.ts` create the offscreen
// document if nothing has done so yet (fixes "popup opens before any content script has run on
// Chromium" — `ensureOffscreenDocument` was previously only ever called from the content-script
// message path, so a fresh profile's popup/options messages had no live receiver). Kept out of
// `messaging/contract.ts`'s `PopupRequest`/`PopupResponse` union on purpose: those types are the
// documented, one-call-per-action vocabulary the long-lived context answers (ADR 0036 §4); this
// message never reaches the long-lived context at all, and the long-lived context's own
// `onMessage` listener (`core-host/listener.ts`) simply ignores it like any other message it
// does not recognise.
export const ENSURE_CORE_MESSAGE = { type: "ensure_core" } as const;

export function isEnsureCoreMessage(value: unknown): boolean {
  return typeof value === "object" && value !== null && (value as { type?: unknown }).type === "ensure_core";
}
