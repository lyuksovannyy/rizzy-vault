// SPDX-License-Identifier: AGPL-3.0-only

// packages/core without a server: loading, errors, the transport's request shape, the
// generator, the frozen texts, and the flows' refusals of bad input.
import { beforeAll, describe, expect, it } from "vitest";

import {
  CoreError,
  type CoreRequest,
  type Transport,
  breachCheckUnavailable,
  checkPasswordBreach,
  checkServer,
  fetchTransport,
  iconHost,
  generatePassphraseWithOptions,
  generatePasswordWithOptions,
  login,
  newElementId,
  plaintextExportPhrase,
  plaintextExportWarning,
  revocationPendingNotice,
  version,
} from "../src/index.js";
import { loadCore } from "./load.js";

beforeAll(() => {
  loadCore();
});

/** A transport that answers every request with `status` and `body`, and records them. */
function fixed(status: number, body: string): { transport: Transport; seen: CoreRequest[] } {
  const seen: CoreRequest[] = [];
  const transport: Transport = async (request) => {
    seen.push(request);
    return { status, body: new TextEncoder().encode(body) };
  };
  return { transport, seen };
}

describe("the module", () => {
  it("reports its version", () => {
    expect(version()).toBe("0.0.0");
  });

  // The generator's full option surface (every class rule, exclude, symbol set, entropy,
  // limits, error codes) is covered by generator.test.ts; this is only a smoke test that the
  // module wires generatePasswordWithOptions/generatePassphraseWithOptions through to Rust.
  it("generates passwords and passphrases in Rust", () => {
    const password = generatePasswordWithOptions({ length: 24, excludeAmbiguous: true });
    expect(password.value).toHaveLength(24);
    expect(password.entropyBits).toBeGreaterThan(100);
    expect(generatePassphraseWithOptions({ words: 6 }).value.split(".")).toHaveLength(6);
    expect(() => generatePasswordWithOptions({ length: 0 })).toThrow(CoreError);
  });

  it("can include or exclude character classes", () => {
    const digitsOnly = generatePasswordWithOptions({
      length: 32,
      lowercase: "excluded",
      uppercase: "excluded",
      digits: "required",
      symbols: "excluded",
    });
    expect(digitsOnly.value).toMatch(/^[0-9]+$/);
    expect(() =>
      generatePasswordWithOptions({
        length: 8,
        lowercase: "excluded",
        uppercase: "excluded",
        digits: "excluded",
        symbols: "excluded",
      }),
    ).toThrow(CoreError);
  });

  it("mints distinct element ids for new list rows", () => {
    const a = newElementId();
    const b = newElementId();
    expect(a).toMatch(/^[0-9a-f]{32}$/);
    expect(a).not.toBe(b);
  });

  it("carries the frozen plaintext-export texts", () => {
    expect(plaintextExportPhrase()).toBe("EXPORT PLAINTEXT");
    expect(plaintextExportWarning()).toContain("unencrypted");
  });

  // Passkey creation is a session call since ADR 0110 (its `UV` flag needs the session's state):
  // the ceremony and INV-64 are `rizzy-client::passkey`'s and `rizzy-wasm::passkey`'s tests, the
  // round trip through a real session is e2e.test.ts's, and the wrappers are passkey-uv.test.ts's.
});

describe("errors", () => {
  it("are CoreError instances with the core's stable code", async () => {
    const { transport, seen } = fixed(500, "");
    const error = await login(transport, {
      origin: "not an origin",
      loginName: "alice",
      secretKey: "RV1-nope",
      password: "pw",
    }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(CoreError);
    expect((error as CoreError).code).toBe("invalid_input");
    // Nothing was sent for input that does not parse.
    expect(seen).toHaveLength(0);
  });

  it("leave secrets passed as bytes zeroed, even when the call fails", async () => {
    const { transport } = fixed(500, "");
    const secretKey = new TextEncoder().encode("RV1-nope");
    const password = new TextEncoder().encode("pw");
    const error = await login(transport, {
      origin: "https://vault.example.com",
      loginName: "alice",
      secretKey,
      password,
    }).catch((e: unknown) => e);
    expect((error as CoreError).code).toBe("invalid_input");
    expect(secretKey.every((b) => b === 0)).toBe(true);
    expect(password.every((b) => b === 0)).toBe(true);
  });

  it("read a server's error answer by its code, never its status", async () => {
    const { transport } = fixed(429, '{"error":"rate_limited"}');
    const error = await checkServer(transport).catch((e: unknown) => e);
    expect((error as CoreError).code).toBe("server_rate_limited");
    const garbage = fixed(502, "<html>bad gateway</html>");
    const bad = await checkServer(garbage.transport).catch((e: unknown) => e);
    expect((bad as CoreError).code).toBe("invalid_server_response");
  });

  it("name a write refused during another device's removal, with the banner's text (ADR 0091 §2)", async () => {
    const { transport } = fixed(409, '{"error":"revocation_pending"}');
    const error = await checkServer(transport).catch((e: unknown) => e);
    expect((error as CoreError).code).toBe("server_revocation_pending");
    expect(revocationPendingNotice()).toBe(
      "Another of your devices is removing a device. Changes are paused for up to 10 minutes.",
    );
  });

  it("return the server's version and its source URL only when valid (ADR 0106 §3)", async () => {
    const head = '"server_version":"0.1.0","api_versions":["v1"],"min_client_versions":[]';
    const without = await checkServer(fixed(200, `{${head}}`).transport);
    expect(without).toEqual({ serverVersion: "0.1.0" });
    expect("sourceUrl" in without).toBe(false);
    const withUrl = await checkServer(
      fixed(200, `{${head},"source_url":"https://example.com/src?x=1#y"}`).transport,
    );
    expect(withUrl).toEqual({ serverVersion: "0.1.0", sourceUrl: "https://example.com/src?x=1#y" });
    for (const bad of ['"http://example.com/src"', '"javascript:alert(1)"', "5", "null", "[]"]) {
      const info = await checkServer(fixed(200, `{${head},"source_url":${bad}}`).transport);
      expect(info).toEqual({ serverVersion: "0.1.0" });
    }
  });
});

describe("the transport", () => {
  it("sends what the core built and nothing else", async () => {
    const calls: { url: string; init: RequestInit | undefined }[] = [];
    const fakeFetch = (async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), init });
      return new Response(
        '{"server_version":"0.1.0","api_versions":["v1"],"min_client_versions":[]}',
        { status: 200 },
      );
    }) as typeof fetch;
    await checkServer(fetchTransport("http://127.0.0.1:1", fakeFetch));
    expect(calls).toHaveLength(1);
    const call = calls[0];
    expect(call?.url).toBe("http://127.0.0.1:1/api/meta");
    expect(call?.init?.method).toBe("GET");
    expect(call?.init?.redirect).toBe("error");
    expect(call?.init?.credentials).toBe("omit");
    expect(call?.init?.cache).toBe("no-store");
    expect(call?.init?.headers).toEqual({ "Rizzy-Client": "web/0.0.0" });
  });

  it("turns a network failure into transport_failed", async () => {
    const failing = (async () => {
      throw new TypeError("network");
    }) as typeof fetch;
    const error = await checkServer(fetchTransport("http://x", failing)).catch((e: unknown) => e);
    expect((error as CoreError).code).toBe("transport_failed");
  });

  it("turns a body that breaks off mid-read into transport_failed", async () => {
    const broken = (async () => {
      let sent = false;
      const body = new ReadableStream<Uint8Array>({
        pull(controller) {
          if (sent) {
            controller.error(new TypeError("connection reset"));
          } else {
            sent = true;
            controller.enqueue(new Uint8Array([123]));
          }
        },
      });
      return new Response(body, { status: 200 });
    }) as typeof fetch;
    const error = await checkServer(fetchTransport("http://x", broken)).catch((e: unknown) => e);
    expect((error as CoreError).code).toBe("transport_failed");
  });

  it("refuses a body larger than the API allows before reading it", async () => {
    const huge = (async () =>
      new Response("x", {
        status: 200,
        headers: { "Content-Length": String(512 * 1024 * 1024) },
      })) as typeof fetch;
    const error = await checkServer(fetchTransport("http://x", huge)).catch((e: unknown) => e);
    expect((error as CoreError).code).toBe("response_too_large");
  });
});


describe("the breach check (ADR 0053)", () => {
  // SHA-1("password") = 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8 (HIBP's documented example).
  const hit = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

  it("sends the 5-character prefix only, without a session, and zeroes the password", async () => {
    const { transport, seen } = fixed(200, JSON.stringify({ range: `0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n${hit}:42` }));
    const password = new TextEncoder().encode("password");
    const result = await checkPasswordBreach(transport, password);
    expect(result).toEqual({ found: true, count: 42 });
    expect(password.every((b) => b === 0)).toBe(true);
    expect(seen).toHaveLength(1);
    const request = seen[0]!;
    expect(request.method).toBe("POST");
    expect(request.path).toBe("/api/v1/icons/breach-range");
    expect(request.headers["Authorization"]).toBeUndefined();
    expect(new TextDecoder().decode(request.body)).toBe('{"prefix":"5BAA6"}');
  });

  it("reads not found, padding and the server's refusals", async () => {
    expect(await checkPasswordBreach(fixed(200, JSON.stringify({ range: "" })).transport, "password")).toEqual({
      found: false,
      count: 0,
    });
    expect(
      await checkPasswordBreach(fixed(200, JSON.stringify({ range: `${hit}:0` })).transport, "password"),
    ).toEqual({ found: false, count: 0 });
    for (const [status, body, code] of [
      [404, '{"error":"not_found"}', "server_not_found"],
      [429, '{"error":"rate_limited"}', "server_rate_limited"],
      [500, '{"error":"internal"}', "server_internal"],
      [200, '{"range":"<html>"}', "invalid_server_response"],
    ] as const) {
      const error = await checkPasswordBreach(fixed(status, body).transport, "password").catch((e: unknown) => e);
      expect((error as CoreError).code).toBe(code);
      expect(breachCheckUnavailable(code)).toBe(code !== "server_rate_limited");
    }
    const empty = await checkPasswordBreach(fixed(200, "{}").transport, "").catch((e: unknown) => e);
    expect((empty as CoreError).code).toBe("invalid_input");
  });
});

describe("item icons (ADR 0052)", () => {
  // The fetch and the probe need a session's permit (ADR 0099 §4): e2e.test.ts covers them.
  it("normalises hosts without sending anything", () => {
    expect(iconHost("WWW.Example.COM")).toBe("www.example.com");
    expect(iconHost("Secret-Bank.Example.")).toBe("secret-bank.example");
    expect(iconHost("b\u00fccher.de")).toBe("xn--bcher-kva.de");
    expect(iconHost("[::1]")).toBeUndefined();
    expect(iconHost("")).toBeUndefined();
  });
});
