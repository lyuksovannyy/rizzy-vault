// SPDX-License-Identifier: AGPL-3.0-only

// ADR 0106 §4 (implementation step 7): the footer's "Source" link to the server's source URL.
// It is a new-tab link with no opener and no referrer, the full URL as its tooltip; nothing is
// rendered without a URL, or for one that is not `https:` even if one reached it.
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { SourceLink } from "../src/SafeLink.tsx";

function render(url: string | undefined): string {
  return renderToStaticMarkup(createElement(SourceLink, { url }));
}

describe("SourceLink", () => {
  it("links to an https source URL in a new tab, with no opener or referrer", () => {
    const html = render("https://example.com/src?ref=v1#top");
    expect(html).toBe(
      '<a href="https://example.com/src?ref=v1#top" target="_blank" rel="noopener noreferrer" ' +
        'title="https://example.com/src?ref=v1#top">Source</a>',
    );
  });

  it("renders nothing without a URL", () => {
    expect(render(undefined)).toBe("");
  });

  it("renders nothing for a URL that is not https, even if one reached it", () => {
    for (const bad of [
      "http://example.com/src",
      "HTTPS://example.com/src",
      "javascript:alert(1)",
      " https://example.com/src",
      "https://user:pw@example.com/src",
      "data:text/html,x",
      "",
    ]) {
      expect(render(bad), JSON.stringify(bad)).toBe("");
    }
  });
});
