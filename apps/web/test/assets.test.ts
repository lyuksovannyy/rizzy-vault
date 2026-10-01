// The web vault's built files and the server's embedded table name the same paths
// (`apps/web/assets.ts`, `crates/rizzy-server/src/http/web.rs`), so a file the build emits is
// always one the server serves.
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { EMBEDDED_FILES } from "../assets.ts";

describe("embedded files", () => {
  it("match the server's table", () => {
    const web = readFileSync(
      new URL("../../../crates/rizzy-server/src/http/web.rs", import.meta.url),
      "utf8",
    );
    const served = [...web.matchAll(/asset!\("([^"]+)"/g)].map((m) => m[1]).sort();
    const built = EMBEDDED_FILES.filter((f) => f !== "index.html").sort();
    expect(served).toEqual(built);
    expect(EMBEDDED_FILES).toContain("index.html");
  });
});
