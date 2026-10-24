// SPDX-License-Identifier: AGPL-3.0-only

// The transparency group's pure parts (`transparency.ts`): the counts table, and the static
// list kept to what this server holds today (THREAT_MODEL §3.4 rows for unbuilt roles left out).
import { describe, expect, it } from "vitest";

import { RETENTION, STORED, countRows, formatBytes, usageText } from "../src/transparency.ts";

describe("countRows", () => {
  it("lists items, trashed items and devices, in that order", () => {
    expect(countRows({ items: 3, trashed: 1, devices: 0 })).toEqual([
      { label: "Items", value: 3 },
      { label: "Items in the Trash", value: 1 },
      { label: "Enrolled devices, active or revoked", value: 0 },
    ]);
  });
});

describe("usage (ADR 0048 §5)", () => {
  it("formats bytes in binary units", () => {
    expect(formatBytes(0)).toBe("0 bytes");
    expect(formatBytes(1023)).toBe("1023 bytes");
    expect(formatBytes(1024)).toBe("1.0 KiB");
    expect(formatBytes(1536 * 1024)).toBe("1.5 MiB");
    expect(formatBytes(5 * 1024 ** 3)).toBe("5.0 GiB");
    expect(formatBytes(-5)).toBe("0 bytes");
    expect(formatBytes(Number.NaN)).toBe("0 bytes");
  });

  it("states the used bytes, the quota and a percentage that is not capped", () => {
    expect(usageText({ bytesUsed: 1536 * 1024, quotaBytes: 5 * 1024 ** 3 })).toBe("1.5 MiB of 5.0 GiB (0%)");
    expect(usageText({ bytesUsed: 128 * 1024 ** 2, quotaBytes: 256 * 1024 ** 2 })).toBe(
      "128.0 MiB of 256.0 MiB (50%)",
    );
    // The headroom of one upload can take an account past its quota (ADR 0048 §3).
    expect(usageText({ bytesUsed: 300 * 1024 ** 2, quotaBytes: 256 * 1024 ** 2 })).toBe(
      "300.0 MiB of 256.0 MiB (117%)",
    );
  });
});

describe("STORED", () => {
  it("has one row per kind of data, each with a description", () => {
    const names = STORED.map((r) => r.data);
    expect(new Set(names).size).toBe(names.length);
    for (const row of STORED) {
      expect(row.how.length).toBeGreaterThan(0);
    }
  });

  it("covers the account, key, vault and session rows of THREAT_MODEL §3.4", () => {
    const text = STORED.map((r) => `${r.data} ${r.how}`).join("\n");
    for (const needle of [
      "login name",
      "OPAQUE",
      "account key",
      "recovery code",
      "Public keys",
      "change log",
      "key wraps",
      "Sync positions",
      "padded ciphertext sizes",
      "two-factor",
      "Session tokens",
    ]) {
      expect(text).toContain(needle);
    }
  });

  it("lists nothing the server does not hold yet (shares, aliases, mail, icons)", () => {
    const text = STORED.map((r) => `${r.data} ${r.how}`).join("\n").toLowerCase();
    for (const absent of ["share", "alias", "mail", "icon"]) {
      expect(text).not.toContain(absent);
    }
  });
});

describe("RETENTION", () => {
  it("states the 30-day Trash period and what lives for the life of the vault", () => {
    const text = RETENTION.join("\n");
    expect(text).toContain("30 days");
    expect(text).toContain("tombstone");
    expect(text).toContain("life of the vault");
    expect(text).toContain("backups");
  });
});
