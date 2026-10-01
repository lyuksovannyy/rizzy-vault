// packages/core without a server: loading, errors, the transport's request shape, the
// generator, the frozen texts, and the flows' refusals of bad input.
import { beforeAll, describe, expect, it } from "vitest";

import {
  CoreError,
  type CoreRequest,
  type Transport,
  checkServer,
  fetchTransport,
  generatePassphrase,
  generatePassword,
  login,
  plaintextExportPhrase,
  plaintextExportWarning,
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

  it("generates passwords and passphrases in Rust", () => {
    const password = generatePassword(24, true, true);
    expect(password.value).toHaveLength(24);
    expect(password.entropyBits).toBeGreaterThan(100);
    expect(generatePassphrase(6).value.split(".")).toHaveLength(6);
    expect(() => generatePassword(0)).toThrow(CoreError);
  });

  it("carries the frozen plaintext-export texts", () => {
    expect(plaintextExportPhrase()).toBe("EXPORT PLAINTEXT");
    expect(plaintextExportWarning()).toContain("unencrypted");
  });
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

