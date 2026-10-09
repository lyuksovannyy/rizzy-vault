// `messaging/bytes.ts`: the shared base64 encode/decode for every passkey message's byte fields.
import { describe, expect, it } from "vitest";

import { base64ToBytes, boundedBase64ToBytes, bytesToBase64 } from "../src/messaging/bytes.ts";

describe("bytesToBase64 / base64ToBytes", () => {
  it("round-trips arbitrary bytes, including 0x00 and 0xff", () => {
    const bytes = new Uint8Array([0, 1, 2, 254, 255, 128, 16, 32]);
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
  });

  it("round-trips an empty buffer", () => {
    expect(base64ToBytes(bytesToBase64(new Uint8Array(0)))).toEqual(new Uint8Array(0));
  });

  it("round-trips a 32-byte buffer (this project's own credential-id/private-key size)", () => {
    const bytes = new Uint8Array(32).map((_, i) => i * 7);
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
  });
});

describe("boundedBase64ToBytes", () => {
  it("decodes a buffer within the bound", () => {
    const bytes = new Uint8Array([1, 2, 3]);
    expect(boundedBase64ToBytes(bytesToBase64(bytes), 32)).toEqual(bytes);
  });

  it("throws for an encoded string too long to possibly fit the bound", () => {
    const over = bytesToBase64(new Uint8Array(64));
    expect(() => boundedBase64ToBytes(over, 32)).toThrow(RangeError);
  });

  it("throws for a decoded length over the bound even when the encoded length check alone would pass", () => {
    const exact = bytesToBase64(new Uint8Array(33));
    expect(() => boundedBase64ToBytes(exact, 32)).toThrow(RangeError);
  });
});
