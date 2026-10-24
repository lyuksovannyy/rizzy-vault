// SPDX-License-Identifier: AGPL-3.0-only

// Security keys on the UI thread (ADR 0058): base64url, the server's options JSON turned into the
// browser's dictionaries, the security-key messages between the UI and the Worker, and the
// client's round trip of a prompt.
import { describe, expect, it } from "vitest";

import { CoreClient, type WorkerPort } from "../src/core-client.ts";
import { type FromWorker, type ToWorker, isFromWorker, isToWorker } from "../src/protocol.ts";
import { creationOptions, fromBase64Url, requestOptions, toBase64Url } from "../src/webauthn.ts";

describe("base64url", () => {
  it("round-trips without padding and refuses other alphabets", () => {
    for (const bytes of [[], [0], [0xfb, 0xff], [1, 2, 3, 4, 5]]) {
      const text = toBase64Url(new Uint8Array(bytes));
      expect(text).not.toMatch(/[+/=]/);
      expect([...fromBase64Url(text)]).toEqual(bytes);
    }
    expect(toBase64Url(new Uint8Array([0xfb, 0xff]))).toBe("-_8");
    expect(() => fromBase64Url("a+b/")).toThrow();
  });
});

describe("options", () => {
  const creation = JSON.stringify({
    publicKey: {
      rp: { id: "vault.example.com", name: "vault.example.com" },
      user: { id: "AQID", name: "alice", displayName: "alice" },
      challenge: "BAUG",
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      timeout: 60000,
      attestation: "none",
      excludeCredentials: [{ type: "public-key", id: "Bwc" }],
      attestationFormats: null,
      hints: ["security-key"],
    },
  });

  it("decodes the binary members and drops nulls", () => {
    const o = creationOptions(creation);
    expect([...new Uint8Array(o.challenge as ArrayBuffer)]).toEqual([4, 5, 6]);
    expect([...new Uint8Array(o.user.id as ArrayBuffer)]).toEqual([1, 2, 3]);
    expect([...new Uint8Array(o.excludeCredentials?.[0]?.id as ArrayBuffer)]).toEqual([7, 7]);
    expect("attestationFormats" in o).toBe(false);
    expect(o.rp.id).toBe("vault.example.com");
    expect(o.timeout).toBe(60000);
  });

  it("reads request options with allowCredentials", () => {
    const o = requestOptions(
      JSON.stringify({
        publicKey: {
          challenge: "AA",
          rpId: "vault.example.com",
          allowCredentials: [{ type: "public-key", id: "AQ" }],
          userVerification: "discouraged",
        },
      }),
    );
    expect(o.rpId).toBe("vault.example.com");
    expect(o.allowCredentials).toHaveLength(1);
  });

  it("refuses malformed options", () => {
    expect(() => creationOptions("{}")).toThrow();
    expect(() => requestOptions(JSON.stringify({ publicKey: { challenge: 5 } }))).toThrow();
  });
});

describe("security-key messages", () => {
  it("checks their shapes", () => {
    const answer = { kind: "credential", credential: "{}" };
    expect(isToWorker({ kind: "security-key", id: 1, answer })).toBe(true);
    expect(isToWorker({ kind: "security-key", id: 1, answer: null })).toBe(true);
    expect(isToWorker({ kind: "security-key", id: 1, answer: { kind: "retry" } })).toBe(true);
    expect(isToWorker({ kind: "security-key", id: 1, answer: { kind: "totp", code: "1" } })).toBe(
      true,
    );
    expect(isToWorker({ kind: "security-key", id: 1, answer: { kind: "credential" } })).toBe(false);
    expect(isToWorker({ kind: "security-key", id: 1, answer: { kind: "other" } })).toBe(false);
    expect(
      isFromWorker({ kind: "ask-security-key", id: 1, options: "{}", totpAllowed: false }),
    ).toBe(true);
    expect(isFromWorker({ kind: "ask-security-key", id: 1, options: 5, totpAllowed: false })).toBe(
      false,
    );
  });

  it("round-trips a prompt through the client", async () => {
    const sent: ToWorker[] = [];
    let listener: ((event: MessageEvent<unknown>) => void) | undefined;
    const port: WorkerPort = {
      postMessage: (message) => sent.push(message),
      addEventListener: (_type, l) => {
        listener = l;
      },
    };
    const client = new CoreClient(port);
    client.setSecurityKeyPrompt((request) =>
      Promise.resolve({ kind: "credential", credential: request.options }),
    );
    const ask: FromWorker = { kind: "ask-security-key", id: 9, options: "{}", totpAllowed: true };
    listener?.({ data: ask } as MessageEvent<unknown>);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(sent).toEqual([
      { kind: "security-key", id: 9, answer: { kind: "credential", credential: "{}" } },
    ]);
  });
});
