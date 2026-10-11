// SPDX-License-Identifier: AGPL-3.0-only

// The hostile-value corpus the adversarial-import harness places into imported item fields
// (threat model A16; INV-35, INV-42, INV-49). Every payload carries `window.__rzxHit = true` as
// its side effect: a window-level tripwire (`e2e/attack/snapshot.ts`) that is a stronger oracle
// than "no `console.error`", because a payload that is inert (rendered as text, refused as a
// link, dropped by a sanitizer) never sets it, while a `<script>` that actually ran would. The
// element-sink oracle (`checkMarkers` in `oracles.ts`) is the discriminating check on top of
// it: CSP (INV-49) blocks the script from *running*, but an HTML sink would still have turned
// the text into a live element, which is the INV-35 violation this harness hunts; the tripwire
// alone would read green in both cases.
//
// Markers are not embedded in the payload text itself (fighting every format's own escaping
// rules to keep a marker intact is not worth it); instead every generated item's title records
// the `(format, field, payloadId)` triple that produced it (`hostile-imports.ts`), which is the
// harness's minimisation for free: a failing assertion names the triple directly.

/** One field a hostile value is placed into. `uri` means a value the app treats as a URL
 * (INV-42); the others are rendered as plain item content (INV-35). */
export type FieldTarget =
  | "title"
  | "username"
  | "notes"
  | "uri"
  | "customName"
  | "customValue"
  | "totp"
  | "tag"
  | "passkeyRpId";

/** A hostile value and what it is testing for. */
export interface Payload {
  readonly id: string;
  readonly value: string;
  readonly kind: "sink" | "uri-scheme" | "injection" | "oversized";
}

/** Sink payloads (INV-35): if any of these becomes a live DOM element or runs, the field
 * reached an HTML sink. Safe for any text field; several double as CSV/XML/JSON breakout
 * attempts (quotes, angle brackets, comment delimiters). */
export const SINK_PAYLOADS: readonly Payload[] = [
  { id: "script-tag", value: "<script>window.__rzxHit=true</script>", kind: "sink" },
  { id: "img-onerror", value: '<img src=x onerror="window.__rzxHit=true">', kind: "sink" },
  { id: "svg-onload", value: '<svg onload="window.__rzxHit=true">', kind: "sink" },
  {
    id: "iframe-srcdoc",
    value: '<iframe srcdoc="&lt;script&gt;window.__rzxHit=true&lt;/script&gt;"></iframe>',
    kind: "sink",
  },
  {
    id: "style-url-js",
    value: '<div style="background:url(javascript:window.__rzxHit=true)">x</div>',
    kind: "sink",
  },
  {
    id: "attr-breakout",
    value: '" onmouseover="window.__rzxHit=true" data-x="',
    kind: "sink",
  },
  {
    id: "html-comment-breakout",
    value: "--><script>window.__rzxHit=true</script><!--",
    kind: "sink",
  },
  {
    id: "polyglot",
    value: "'\"--></style></script><svg onload=window.__rzxHit=true>",
    kind: "sink",
  },
  { id: "markdown-js-link", value: "[click me](javascript:window.__rzxHit=true)", kind: "sink" },
  { id: "template-dollar", value: "${7*7}", kind: "injection" },
  { id: "template-mustache", value: "{{7*7}}", kind: "injection" },
  { id: "crlf-injection", value: "normal\r\nSet-Cookie: injected=1", kind: "injection" },
  { id: "null-byte", value: "before\u0000after", kind: "injection" },
  { id: "rtl-override", value: "safe‮exe.cmd", kind: "injection" },
  { id: "csv-formula", value: "=1+1", kind: "injection" },
  { id: "csv-formula-cmd", value: "@SUM(1+1)*cmd|' /C calc'!A0", kind: "injection" },
];

/** URI-scheme payloads (INV-42): a value placed into a URI/URL field. The oracle reads the
 * resolved `a.protocol` / `a.href`, never the raw stored text (the WHATWG URL parser strips
 * control characters and normalises case, so the browser's own resolution is the only
 * trustworthy read: `safeHttpUrl` in `apps/web/src/safe-url.ts` already relies on it). */
export const URI_PAYLOADS: readonly Payload[] = [
  { id: "uri-javascript", value: "javascript:window.__rzxHit=true", kind: "uri-scheme" },
  { id: "uri-javascript-mixed-case", value: "JaVaScRiPt:window.__rzxHit=true", kind: "uri-scheme" },
  { id: "uri-javascript-tab", value: "java\tscript:window.__rzxHit=true", kind: "uri-scheme" },
  { id: "uri-javascript-newline", value: "java\nscript:window.__rzxHit=true", kind: "uri-scheme" },
  { id: "uri-javascript-leading-ws", value: "   javascript:window.__rzxHit=true", kind: "uri-scheme" },
  { id: "uri-javascript-nul-prefix", value: "\u0000javascript:window.__rzxHit=true", kind: "uri-scheme" },
  {
    id: "uri-data-html",
    value: "data:text/html,<script>window.__rzxHit=true</script>",
    kind: "uri-scheme",
  },
  {
    id: "uri-data-base64",
    value: "data:text/html;base64,PHNjcmlwdD53aW5kb3cuX19yenhIaXQ9dHJ1ZTwvc2NyaXB0Pg==",
    kind: "uri-scheme",
  },
  { id: "uri-vbscript", value: "vbscript:msgbox(1)", kind: "uri-scheme" },
  { id: "uri-file", value: "file:///etc/passwd", kind: "uri-scheme" },
  { id: "uri-blob", value: "blob:https://example.com/00000000-0000-0000-0000-000000000000", kind: "uri-scheme" },
  { id: "uri-credentials", value: "https://attacker:secret@example.com/", kind: "uri-scheme" },
  { id: "uri-about", value: "about:blank", kind: "uri-scheme" },
  { id: "uri-chrome", value: "chrome://settings", kind: "uri-scheme" },
];

/** Short, control-character-free payloads safe for a tag/folder name (`tag_key`,
 * `crates/rizzy-core/src/item/tag.rs`: 1-64 UTF-8 bytes, no Cc code point). */
export const TAG_SAFE_PAYLOADS: readonly Payload[] = SINK_PAYLOADS.filter(
  (p) => p.id !== "crlf-injection" && p.id !== "null-byte" && new TextEncoder().encode(p.value).length <= 64,
);

/** Oversized values (A16 "parser DoS", and the per-field caps `rizzy-import` enforces):
 * `MAX_TEXT_LEN` is 65,535 bytes per Text value (`crates/rizzy-import/src/limits.rs`). The
 * oracle is not content, but that the import finishes (no hang, no crash) and reports cleanly
 * (`import-report` with a sane, non-negative count, or a clean error code) rather than
 * poisoning later items or corrupting the page. */
export const OVERSIZED_PAYLOADS: readonly Payload[] = [
  { id: "oversized-text-70k", value: "A".repeat(70_000), kind: "oversized" },
  { id: "oversized-text-unicode-40k", value: "🔥".repeat(40_000), kind: "oversized" },
];

/** Every sink and URI payload, for the nightly full sweep. */
export const ALL_FIELD_PAYLOADS: readonly Payload[] = [...SINK_PAYLOADS, ...URI_PAYLOADS];
