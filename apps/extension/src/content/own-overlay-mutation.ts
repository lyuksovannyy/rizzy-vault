// Split out of `content-script.ts` so it can be unit tested without a DOM environment
// (`content-script.ts`'s own top-level `if (window.top === window) { installContentScript(); }`
// runs at import time, which this workspace's `vitest` `environment: "node"` has no `window`
// for at all — importing that file directly would crash before any test body ran). This module
// has no top-level side effects and duck-types `hasAttribute` rather than checking
// `instanceof HTMLElement`, so a plain test double works under plain Node too, with no new
// `jsdom`/`happy-dom` dependency. Nodes are typed `unknown` (not a structural `Node`/`Element`
// stand-in interface): TypeScript's "weak type" check rejects a real `Node` against an
// interface whose only property is optional, since the two share no required property at all —
// casting inside {@link isOwn} instead avoids that without widening the public API.
function isOwn(node: unknown): boolean {
  const el = node as { hasAttribute?: (name: string) => boolean };
  return typeof el.hasAttribute === "function" && (el.hasAttribute("data-rizzy-inline-menu") || el.hasAttribute("data-rizzy-save-prompt"));
}

/** Whether every node a batch of `MutationRecord`s added or removed is one of the content
 * script's own overlay elements (the inline-menu iframe, the save-prompt banner) — see
 * `content-script.ts`'s `MutationObserver` callback for why this matters: without this filter,
 * showing or hiding either overlay is itself a `childList` mutation under
 * `document.documentElement`, so it would re-trigger field detection, which could show or hide
 * an overlay again — an unbounded loop, found empirically running this change's E2E coverage
 * against a real Chromium build. A mutation that touches anything else at all (even alongside
 * one of ours) counts as a real page change and must still trigger a re-detection. */
export function isOwnOverlayMutation(records: readonly { addedNodes: Iterable<unknown>; removedNodes: Iterable<unknown> }[]): boolean {
  for (const record of records) {
    for (const node of record.addedNodes) {
      if (!isOwn(node)) {
        return false;
      }
    }
    for (const node of record.removedNodes) {
      if (!isOwn(node)) {
        return false;
      }
    }
  }
  return true;
}
