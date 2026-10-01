// The one URL check of the web vault (ADR 0014 §2 "One openUrl / SafeLink helper"; INV-42):
// only `http:` and `https:` URLs taken from item fields are ever opened. `javascript:`,
// `data:`, `file:`, `blob:` and every other scheme are shown as text and never become a link.
// `SafeLink.tsx` is the only component that renders such a link; ESLint bans dynamic `href`
// values, `window.open` and `location` assignments elsewhere (`eslint.config.js`).

/**
 * The URL to open for an item field's text, or `undefined` when it must not be opened. The
 * text is parsed by the WHATWG URL parser, so a scheme hidden behind leading spaces, control
 * characters or mixed case is judged by what the browser would actually open.
 */
export function safeHttpUrl(text: string): string | undefined {
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return undefined;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return undefined;
  }
  // No credentials in a URL we open: they would be sent to the site in the clear.
  if (url.username !== "" || url.password !== "") {
    return undefined;
  }
  return url.href;
}
