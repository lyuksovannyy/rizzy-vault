// SPDX-License-Identifier: AGPL-3.0-only

// The ADR 0043 instance-token minting helper (`content/instance-token.ts`): `crypto.randomUUID()`
// when it exists, else the same canonical v4 layout built from `getRandomValues` (a plain
// `http://` page, where `randomUUID`, a [SecureContext] member, is absent). Either way the
// result must pass `messaging/contract.ts`'s `isInstanceToken`, the background's shape check.
import { describe, expect, it } from "vitest";

import { mintInstanceToken } from "../src/content/instance-token.ts";
import { isInstanceToken } from "../src/messaging/contract.ts";

describe("mintInstanceToken", () => {
  it("uses crypto.randomUUID() when it exists", () => {
    const fixed = "3b241101-e2bb-4255-8caf-4136c566a962";
    expect(mintInstanceToken({ getRandomValues: crypto.getRandomValues.bind(crypto), randomUUID: () => fixed })).toBe(fixed);
    expect(isInstanceToken(mintInstanceToken())).toBe(true);
  });

  it("without randomUUID, builds a canonical v4 UUID from getRandomValues, version and variant bits forced", () => {
    for (const fill of [0x00, 0xff, 0x5a]) {
      const token = mintInstanceToken({ getRandomValues: <T extends ArrayBufferView | null>(a: T): T => {
        if (a instanceof Uint8Array) {
          a.fill(fill);
        }
        return a;
      } });
      expect(isInstanceToken(token)).toBe(true);
      expect(token[14]).toBe("4");
      expect("89ab").toContain(token[19]);
    }
  });

  it("without randomUUID, uses the real CSPRNG: distinct tokens", () => {
    const random = { getRandomValues: crypto.getRandomValues.bind(crypto) };
    const tokens = new Set(Array.from({ length: 64 }, () => mintInstanceToken(random)));
    expect(tokens.size).toBe(64);
    for (const token of tokens) {
      expect(isInstanceToken(token)).toBe(true);
    }
  });
});
