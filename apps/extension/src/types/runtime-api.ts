// Picks whichever WebExtension global this browser provides (ADR 0036 §2: Chromium `chrome.*`,
// Firefox `browser.*`, both promise-based for everything this extension calls). One indirection
// point so the rest of the source never branches on browser.
export function webext(): WebExtNamespace {
  const ext = typeof chrome !== "undefined" ? chrome : browser;
  if (ext === undefined) {
    throw new Error("no WebExtension runtime (chrome/browser) in this context");
  }
  return ext;
}

/** Whether `chrome.offscreen` exists (Chromium; ADR 0036 §2). Firefox has no offscreen API. */
export function hasOffscreen(): boolean {
  const ext = webext();
  return ext.offscreen !== undefined;
}
