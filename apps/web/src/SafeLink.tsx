// The only component that renders a link from item data (INV-42; `safe-url.ts`). A URL that is
// not `http:` or `https:` renders as plain text. Links open in a new tab with no opener and no
// referrer, so the site gets no handle on the vault page.
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
