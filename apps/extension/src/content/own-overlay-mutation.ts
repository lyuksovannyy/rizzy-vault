// SPDX-License-Identifier: AGPL-3.0-only

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
/** Exported so `content-script.ts`'s own max-z-index-sibling occlusion check (A7 bypass-2 fix)
 * can reuse the exact same "is this one of OUR overlay elements" test — the one other place in
 * this codebase that needs to tell our own overlay apart from anything else on the page, for the
 * same underlying reason: a decoy sharing the frame's own insertion point is exactly what both
 * checks must not mistake for the frame's own, legitimate sibling. */
export function isOwnOverlayElement(node: unknown): boolean {
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
      if (!isOwnOverlayElement(node)) {
        return false;
      }
    }
    for (const node of record.removedNodes) {
      if (!isOwnOverlayElement(node)) {
        return false;
      }
    }
  }
  return true;
}

/** Whether `node` is one of our own overlay elements or sits inside one (walking
 * `parentNode`, duck-typed like {@link isOwnOverlayElement}). */
function isInOwnOverlay(node: unknown): boolean {
  let current: unknown = node;
  while (typeof current === "object" && current !== null) {
    if (isOwnOverlayElement(current)) {
      return true;
    }
    current = (current as { parentNode?: unknown }).parentNode;
  }
  return false;
}

/**
 * What one `MutationObserver` batch means for field detection, now that the content script
 * also observes attributes (multi-step login pages reveal a password field in place by toggling
 * `hidden`/`style`/`class`; ROADMAP §4.4 M3):
 * - `"structure"`: some record added or removed a node that is not ours — a full re-detection
 *   and re-report, exactly as before attributes were observed ({@link isOwnOverlayMutation});
 * - `"attributes"`: only attribute changes, at least one on a page element — re-detect, and
 *   re-report only if the login step changed;
 * - `"none"`: everything touched was our own overlay (the inline menu restyles its own iframe
 *   on every animation frame, which must never count as the page changing).
 */
export function pageMutations(
  records: readonly { type: string; target: unknown; addedNodes: Iterable<unknown>; removedNodes: Iterable<unknown> }[],
): "none" | "attributes" | "structure" {
  let attributes = false;
  for (const record of records) {
    if (record.type === "attributes") {
      attributes ||= !isInOwnOverlay(record.target);
      continue;
    }
    if (!isOwnOverlayMutation([record])) {
      return "structure";
    }
  }
  return attributes ? "attributes" : "none";
}
