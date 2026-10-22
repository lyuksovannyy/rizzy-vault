// SPDX-License-Identifier: AGPL-3.0-only

// The attachments section's pure helpers (`src/attachments.ts`, ADR 0054), and the check that
// its copy of the 25 MiB cap matches `@rizzy-vault/core`'s (the one runtime import of the core
// that `test/**` may make, as `generator-constants.test.ts` does).
import { MAX_ATTACHMENT_BYTES as CORE_MAX_ATTACHMENT_BYTES } from "@rizzy-vault/core";
import { describe, expect, it } from "vitest";

import { DEFAULT_MIME, MAX_ATTACHMENT_BYTES, declaredMime, formatSize, precheck } from "../src/attachments.ts";
import { group } from "../src/fields.ts";

describe("attachments", () => {
  it("copies the core's cap: 25 MiB", () => {
    expect(MAX_ATTACHMENT_BYTES).toBe(CORE_MAX_ATTACHMENT_BYTES);
    expect(MAX_ATTACHMENT_BYTES).toBe(25 * 1024 * 1024);
  });

  it("refuses a file over the cap before it is read, and nothing else", () => {
    expect(precheck(0)).toBeUndefined();
    expect(precheck(MAX_ATTACHMENT_BYTES)).toBeUndefined();
    expect(precheck(MAX_ATTACHMENT_BYTES + 1)).toBe("attachment_too_large");
  });

  it("formats sizes and declares a default media type", () => {
    expect(formatSize(0)).toBe("0 B");
    expect(formatSize(1023)).toBe("1023 B");
    expect(formatSize(1536)).toBe("1.5 KiB");
    expect(formatSize(MAX_ATTACHMENT_BYTES)).toBe("25.0 MiB");
    expect(declaredMime("")).toBe(DEFAULT_MIME);
    expect(declaredMime("image/png")).toBe("image/png");
  });

  it("keeps attachment fields out of the item's other fields", () => {
    const element = "ab".repeat(16);
    const grouped = group([
      { key: `attachment/${element}/name`, list: "attachment", element, attribute: "name", value: "a.pdf" } as never,
      { key: "item.name", value: "x" } as never,
    ]);
    expect(grouped.other).toEqual([]);
    expect(grouped.fixed.map((f) => f.key)).toEqual(["item.name"]);
  });
});
