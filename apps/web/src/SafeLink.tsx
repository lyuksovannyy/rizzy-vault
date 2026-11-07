// SPDX-License-Identifier: AGPL-3.0-only

// The only component that renders a link from item data (INV-42; `safe-url.ts`), and the
// footer's link to the server's source (ADR 0106 §4), which follows the same rules. A URL that is
// not `http:` or `https:` renders as plain text. Links open in a new tab with no opener and no
// referrer, so the site gets no handle on the vault page.
import { t } from "@rizzy-vault/i18n";
import { IconOpen } from "@rizzy-vault/ui";

import { safeHttpUrl } from "./safe-url.ts";

/** A link to `url` if it is safe to open, else the text. */
export function SafeLink(props: { readonly url: string }) {
  const href = safeHttpUrl(props.url);
  if (href === undefined) {
    return <span className="unsafe-url">{props.url}</span>;
  }
  return (
    <a href={href} target="_blank" rel="noopener noreferrer">
      {props.url}
    </a>
  );
}

/**
 * The footer's "Source" link (ADR 0106 §4; ADR 0017 §7, AGPL §13): where users get the source
 * of the server and web vault they use, from `/api/meta`'s `source_url` as the core read it
 * (`checkServer`). Nothing at all, not even a placeholder, while there is no URL. The core
 * already accepts only `https://` URLs; this checks again (defence in depth): `https:` only,
 * then the same WHATWG check as {@link SafeLink}. The full URL is the tooltip; the link opens
 * in a new tab with no opener and no referrer.
 */
export function SourceLink(props: { readonly url: string | undefined }) {
  const { url } = props;
  if (url === undefined || !url.startsWith("https://")) {
    return null;
  }
  const href = safeHttpUrl(url);
  if (href === undefined || !href.startsWith("https:")) {
    return null;
  }
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" title={url}>
      {t("footer.source")}
    </a>
  );
}

/** An icon-only open button beside a {@link SafeLink}, to the same safe `url` and no other
 * (item 3's detail-pane "open" button). Renders nothing for a URL `SafeLink` would not link
 * either, so there is never a button with no safe destination. */
export function SafeOpenButton(props: { readonly url: string; readonly label: string }) {
  const href = safeHttpUrl(props.url);
  if (href === undefined) {
    return null;
  }
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className="icon-button" aria-label={props.label}>
      <IconOpen />
    </a>
  );
}
