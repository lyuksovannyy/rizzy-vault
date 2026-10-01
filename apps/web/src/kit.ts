// The Emergency Kit as the web vault shows and saves it (CRYPTO.md §7 "Emergency Kit"): the
// server URL, the login name, the Secret Key, the recovery code if one was issued, and a blank
// line for the master password, with the two warnings CRYPTO.md §7 requires in plain words.
//
// The saved file is printable HTML, generated here in the browser (CRYPTO.md §7: "on the client
// only, as printable HTML/PDF"). It holds no script and no style, and carries a CSP that loads
// nothing (`default-src 'none'`), so opening it from disk runs nothing. Every value is
// HTML-escaped: the login name is user input, and the other values come from the server or
// the core; none may become markup.

/** The kit as the page shows it. Strings cannot be wiped; they live until the page moves on. */
export interface ShownKit {
  readonly serverOrigin: string;
  readonly loginName: string;
  readonly secretKey: string;
  readonly recoveryCode: string | undefined;
}

/**
 * CRYPTO.md §7: the takeover warning. Unconditional: with a recovery code, the sheet and server
 * access are enough (CRYPTO.md §8, after the recovery waiting period); without one, the sheet
 * still holds the Secret Key and the line where a master password may be written.
 */
export const KIT_TAKEOVER_WARNING =
  "Anyone with this sheet and access to your server can take over your account.";

/** CRYPTO.md §7: the data-loss warning. */
export const KIT_LOSS_WARNING =
  "If you lose both this sheet and your master password, and no device is still logged in, your data is gone. Nobody, the server operator included, can recover it.";

/** Escapes text for HTML element content and double-quoted attribute values. */
export function escapeHtml(text: string): string {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/** The rows of the kit, in order. */
function rows(kit: ShownKit): [string, string][] {
  const out: [string, string][] = [
    ["Server", kit.serverOrigin],
    ["Login name", kit.loginName],
    ["Secret Key", kit.secretKey],
  ];
  if (kit.recoveryCode !== undefined) {
    out.push(["Recovery code", kit.recoveryCode]);
  }
  return out;
}

/** The printable HTML of the downloadable Emergency Kit (module docs). */
export function kitHtml(kit: ShownKit): string {
  const items = rows(kit)
    .map(([label, value]) => `<dt>${escapeHtml(label)}</dt>\n<dd><code>${escapeHtml(value)}</code></dd>`)
    .join("\n");
  return [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    `<meta http-equiv="Content-Security-Policy" content="default-src 'none'">`,
    '<meta name="referrer" content="no-referrer">',
    "<title>rizzy-vault Emergency Kit</title>",
    "</head>",
    "<body>",
    "<h1>rizzy-vault Emergency Kit</h1>",
    `<p><strong>${escapeHtml(KIT_TAKEOVER_WARNING)}</strong></p>`,
    `<p><strong>${escapeHtml(KIT_LOSS_WARNING)}</strong></p>`,
    "<p>Print this page and keep the paper somewhere safe and offline, then delete this file.</p>",
    "<dl>",
    items,
    "<dt>Master password</dt>",
    "<dd>______________________________ (write it by hand, or not at all)</dd>",
    "</dl>",
    "</body>",
    "</html>",
    "",
  ].join("\n");
}
