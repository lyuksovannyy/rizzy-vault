// Hands a file to the user as a download: the Emergency Kit, exports. The bytes become a
// `blob:` URL that lives only for the click, and nothing is uploaded or stored. This and
// `SafeLink.tsx` are the only places that set an `href` (`eslint.config.js`).

/** Saves `bytes` as a file named `name`. */
export function saveFile(name: string, bytes: Uint8Array, type: string): void {
  const blob = new Blob([bytes as Uint8Array<ArrayBuffer>], { type });
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.rel = "noopener";
    document.body.append(a);
    a.click();
    a.remove();
  } finally {
    // Revoked after the click has been dispatched; the download keeps its own reference.
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }
}

/** Today's date as `YYYY-MM-DD`, for file names. */
export function dateStamp(now: Date = new Date()): string {
  return now.toISOString().slice(0, 10);
}
