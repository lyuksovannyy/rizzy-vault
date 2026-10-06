// The only component that renders a link from item data (INV-42; `safe-url.ts`). A URL that is
// not `http:` or `https:` renders as plain text. Links open in a new tab with no opener and no
// referrer, so the site gets no handle on the vault page.
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
