// SPDX-License-Identifier: AGPL-3.0-only

// Settings → Website matching shows a stored group that fails a PSL- or IDNA-dependent rule as
// "Ignored for matching", with its reason, and offers Delete (ADR 0097 §4.2).
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { InertGroupRow, inertReasonText } from "../src/views/MatchingPane.tsx";

describe("inert user groups (ADR 0097 §4.2)", () => {
  it("names the reason, with ADR 0097's text for a domain that is not registrable", () => {
    expect(inertReasonText({ kind: "not_registrable", domain: "github.io" })).toBe(
      "github.io is not a registrable domain for this version of rizzy-vault",
    );
    expect(inertReasonText({ kind: "third_party_flag", domain: undefined })).not.toContain("{domain}");
  });

  it("renders as Ignored for matching, with a labelled Delete", () => {
    const html = renderToStaticMarkup(
      createElement(InertGroupRow, {
        group: {
          id: "b0".repeat(16),
          domains: ["example.com", "github.io"],
          reasons: [{ kind: "not_registrable", domain: "github.io" }],
        },
        busy: false,
        onDelete: () => undefined,
      }),
    );
    expect(html).toContain("Ignored for matching");
    expect(html).toContain("github.io is not a registrable domain for this version of rizzy-vault");
    expect(html).toMatch(/<button[^>]*aria-label="Delete the group [^"]+"[^>]*>Delete<\/button>/);
  });
});
