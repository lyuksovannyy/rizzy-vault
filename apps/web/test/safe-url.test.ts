// INV-42: only `http:` and `https:` URLs from item fields are ever opened (unit test, as the
// invariant's check column requires).
import { describe, expect, it } from "vitest";

import { safeHttpUrl } from "../src/safe-url.ts";

describe("safeHttpUrl", () => {
  it("allows http and https", () => {
    expect(safeHttpUrl("https://example.com/login")).toBe("https://example.com/login");
    expect(safeHttpUrl("http://example.com")).toBe("http://example.com/");
    expect(safeHttpUrl("HTTPS://EXAMPLE.com")).toBe("https://example.com/");
    expect(safeHttpUrl("  https://example.com  ")).toBe("https://example.com/");
  });

  it("refuses every other scheme, however it is spelled", () => {
    for (const bad of [
      "javascript:alert(1)",
      "JaVaScRiPt:alert(1)",
      " javascript:alert(1)",
      "\tjavascript:alert(1)",
      "java\nscript:alert(1)",
      "\u0000javascript:alert(1)",
      "data:text/html,<script>alert(1)</script>",
      "file:///etc/passwd",
      "blob:https://example.com/uuid",
      "vbscript:msgbox(1)",
      "ftp://example.com",
      "chrome://settings",
      "about:blank",
      "example.com",
      "//example.com",
      "",
      "not a url",
    ]) {
      expect(safeHttpUrl(bad), JSON.stringify(bad)).toBeUndefined();
    }
  });

  it("refuses credentials in the URL", () => {
    expect(safeHttpUrl("https://user:pass@example.com")).toBeUndefined();
    expect(safeHttpUrl("https://user@example.com")).toBeUndefined();
  });
});
