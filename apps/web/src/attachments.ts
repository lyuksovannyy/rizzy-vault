// SPDX-License-Identifier: AGPL-3.0-only

// Pure helpers of the attachments section (`views/AttachmentsSection.tsx`, ADR 0054).
//
// `MAX_ATTACHMENT_BYTES` copies `@rizzy-vault/core`'s value rather than importing it: the UI
// thread imports only types from that package (ADR 0013 §4; `eslint.config.js`).
// `test/attachments.test.ts` checks that the copy has not drifted.

/** The largest attachment, in bytes: 25 MiB (ADR 0054 §2). The core checks it again. */
export const MAX_ATTACHMENT_BYTES = 26_214_400;

/** The media type a file is declared with when the browser names none (ADR 0054 §4: declared,
 * never sniffed). */
export const DEFAULT_MIME = "application/octet-stream";

/** A byte count for display: bytes, KiB or MiB, one decimal. */
export function formatSize(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KiB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

/** The refusal for a chosen file before it is read: `attachment_too_large` over the cap. */
export function precheck(size: number): string | undefined {
  return size > MAX_ATTACHMENT_BYTES ? "attachment_too_large" : undefined;
}

/** The media type to declare for a file the browser typed as `type` (empty when unknown). */
export function declaredMime(type: string): string {
  return type === "" ? DEFAULT_MIME : type;
}
