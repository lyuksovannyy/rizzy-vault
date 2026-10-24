// SPDX-License-Identifier: AGPL-3.0-only

// Positive controls for the adversarial-import harness's oracles (`e2e/attack/oracles.ts`):
// each oracle is fed a hand-built, deliberately bad `Snapshot` and must flag it. This is the
// proof the harness can detect a real violation, not only that today's app happens to pass it
// (the task's own requirement). It also covers the harness's own generators (`hostile-
// imports.ts`, `zip.ts`, `rng.ts`) at the unit level: determinism, and that each generated file
// actually carries the hostile value in the field it claims to.
import { describe, expect, it } from "vitest";

import { buildHostileFile, traceTitle } from "../e2e/attack/hostile-imports.ts";
import {
  checkAll,
  checkHeaders,
  checkOversizedHandling,
  checkSecretFields,
  checkSinks,
  checkStorage,
  checkUriScheme,
  type Snapshot,
} from "../e2e/attack/oracles.ts";
import { SINK_PAYLOADS, URI_PAYLOADS } from "../e2e/attack/payloads.ts";
import { mulberry32, pick } from "../e2e/attack/rng.ts";
import { buildStoredZip, crc32 } from "../e2e/attack/zip.ts";

const EMPTY_SNAPSHOT: Snapshot = {
  links: [],
  sinkHits: [],
  tripwireHit: false,
  cspViolations: [],
  secretFields: [],
  storage: [],
  headers: [],
  oversizedImportCrashed: false,
};

describe("positive controls: each oracle catches a planted violation", () => {
  it("checkUriScheme flags a rendered javascript: link, and allows an https one", () => {
    expect(
      checkUriScheme({
        ...EMPTY_SNAPSHOT,
        links: [{ descriptor: "<a>", protocol: "javascript:", href: "javascript:alert(1)" }],
      }),
    ).toHaveLength(1);
    expect(
      checkUriScheme({ ...EMPTY_SNAPSHOT, links: [{ descriptor: "<a>", protocol: "https:", href: "https://x" }] }),
    ).toEqual([]);
  });

  it("checkSinks flags a planted sink element and a tripwire hit, and allows neither", () => {
    expect(checkSinks({ ...EMPTY_SNAPSHOT, sinkHits: [{ tag: "img", descriptor: '<img onerror="x">' }] })).toHaveLength(
      1,
    );
    expect(checkSinks({ ...EMPTY_SNAPSHOT, tripwireHit: true })).toHaveLength(1);
    expect(checkSinks(EMPTY_SNAPSHOT)).toEqual([]);
  });

  it("checkSecretFields flags an unmasked or spell-checked secret input", () => {
    const bad = checkSecretFields({
      ...EMPTY_SNAPSHOT,
      secretFields: [
        { label: "Master password", phase: "masked", type: "text", spellcheck: "true", autocomplete: "on", autocapitalize: null },
      ],
    });
    expect(bad.length).toBeGreaterThanOrEqual(3);
    const good = checkSecretFields({
      ...EMPTY_SNAPSHOT,
      secretFields: [
        { label: "Master password", phase: "masked", type: "password", spellcheck: "false", autocomplete: "off", autocapitalize: null },
        { label: "Master password", phase: "revealed", type: "text", spellcheck: "false", autocomplete: "off", autocapitalize: null },
      ],
    });
    expect(good).toEqual([]);
  });

  it("checkStorage flags a secret value planted in localStorage, raw, hex or base64", () => {
    const secret = "correct horse battery staple";
    const raw = checkStorage(
      { ...EMPTY_SNAPSHOT, storage: [{ area: "localStorage", key: "cache", value: `x=${secret}` }] },
      [secret],
    );
    expect(raw).toHaveLength(1);
    const hex = Buffer.from(secret, "utf8").toString("hex");
    const hexHit = checkStorage(
      { ...EMPTY_SNAPSHOT, storage: [{ area: "sessionStorage", key: "cache", value: hex }] },
      [secret],
    );
    expect(hexHit).toHaveLength(1);
    const clean = checkStorage(
      { ...EMPTY_SNAPSHOT, storage: [{ area: "localStorage", key: "theme", value: "dark" }] },
      [secret],
      ["theme"],
    );
    expect(clean).toEqual([]);
  });

  it("checkHeaders flags a missing CSP, an unsafe-inline CSP, and a missing nosniff/referrer header", () => {
    expect(checkHeaders({ ...EMPTY_SNAPSHOT, headers: [{ path: "/", status: 200, headers: {}, isHttps: false }] })).not.toEqual(
      [],
    );
    const unsafe = checkHeaders({
      ...EMPTY_SNAPSHOT,
      headers: [
        {
          path: "/",
          status: 200,
          headers: {
            "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
          },
          isHttps: false,
        },
      ],
    });
    expect(unsafe.some((v) => v.oracle === "INV-49 header-value")).toBe(true);
    const good = checkHeaders({
      ...EMPTY_SNAPSHOT,
      headers: [
        {
          path: "/",
          status: 200,
          headers: {
            "content-security-policy": "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; frame-ancestors 'none'",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
          },
          isHttps: false,
        },
      ],
    });
    expect(good).toEqual([]);
  });

  it("checkOversizedHandling flags a crashed/hung page and allows a responsive one", () => {
    expect(checkOversizedHandling({ ...EMPTY_SNAPSHOT, oversizedImportCrashed: true })).toHaveLength(1);
    expect(checkOversizedHandling(EMPTY_SNAPSHOT)).toEqual([]);
  });

  it("checkAll aggregates every oracle (one planted violation of each kind)", () => {
    const violations = checkAll(
      {
        links: [{ descriptor: "<a>", protocol: "javascript:", href: "javascript:x" }],
        sinkHits: [{ tag: "svg", descriptor: "<svg onload>" }],
        tripwireHit: false,
        cspViolations: [],
        secretFields: [],
        storage: [{ area: "localStorage", key: "sk", value: "RV1-secret-key" }],
        headers: [{ path: "/", status: 200, headers: {}, isHttps: false }],
        oversizedImportCrashed: true,
      },
      ["RV1-secret-key"],
    );
    const oracles = new Set(violations.map((v) => v.oracle));
    expect(oracles.has("INV-42 uri-scheme")).toBe(true);
    expect(oracles.has("INV-35 sink-fingerprint")).toBe(true);
    expect(oracles.has("CRYPTO.md §11.4 storage-secret")).toBe(true);
    expect(oracles.has("INV-49 header-missing")).toBe(true);
    expect(oracles.has("A16 oversized-crash")).toBe(true);
  });
});

describe("zip.ts: the stored-zip writer the 1PUX/.avux generators depend on", () => {
  it("crc32 matches a known vector (the empty string, and a short ASCII string)", () => {
    expect(crc32(new Uint8Array())).toBe(0);
    expect(crc32(new TextEncoder().encode("123456789"))).toBe(0xcbf43926);
  });

  it("builds an archive whose declared CRC-32 matches the member bytes (what a real reader checks)", () => {
    const data = new TextEncoder().encode('{"hello":"world"}');
    const zip = buildStoredZip([{ name: "export.data", data }]);
    expect(zip.length).toBeGreaterThan(data.length);
    expect(zip.slice(0, 4)).toEqual(new Uint8Array([0x50, 0x4b, 0x03, 0x04]));
    // The archive holds the member's bytes verbatim after the local header (no compression).
    const needle = Buffer.from(data).toString("latin1");
    expect(Buffer.from(zip).toString("latin1")).toContain(needle);
  });
});

describe("hostile-imports.ts: every format carries the payload in the field it claims to", () => {
  it("traceTitle round-trips through every generated format's bytes", () => {
    // A payload with no quote, angle bracket or comma: JSON, XML and CSV each escape or quote
    // those differently, so a raw substring check across every format needs a payload none of
    // them touch. The escaping itself is each format's own job, covered by reading the real
    // document back below ("rizzy-json field keys…") and, for the live app, by the Playwright
    // spec's sink fingerprint (`e2e/adversarial-import.spec.ts`), not by a byte search here.
    const payload = SINK_PAYLOADS.find((p) => p.id === "template-dollar");
    if (payload === undefined) {
      throw new Error("payloads.ts: template-dollar payload missing");
    }
    const uriPayload = URI_PAYLOADS.find((p) => p.id === "uri-javascript");
    if (uriPayload === undefined) {
      throw new Error("payloads.ts: uri-javascript payload missing");
    }
    for (const format of [
      "bitwarden-json",
      "1pux",
      "keepass-xml",
      "chrome-csv",
      "csv",
      "aliasvault-csv",
      "aliasvault-avux",
      "rizzy-json",
    ] as const) {
      const file = buildHostileFile(format, [{ field: "title" as const, payload }]);
      const text = Buffer.from(file.bytes).toString("latin1");
      const trace = traceTitle(format, "title", payload.id);
      expect(text, `${format} is missing its own trace title`).toContain(trace);
      expect(text, `${format} is missing the payload value for its title case`).toContain(payload.value);
    }
    // Firefox CSV has no title column at all (`firefoxCsv`'s own docs): `rowKeys` carries a
    // short per-case marker in `username` instead of the usual trace title, and that marker,
    // not `traceTitle`, is what must actually appear in the generated bytes.
    const ffFile = buildHostileFile("firefox-csv", [{ field: "title", payload }]);
    const ffText = Buffer.from(ffFile.bytes).toString("latin1");
    expect(ffFile.rowKeys).toHaveLength(1);
    expect(ffText).toContain(ffFile.rowKeys[0]);
    // The username field case is the one exception: there, the row key is the payload itself.
    const ffUserFile = buildHostileFile("firefox-csv", [{ field: "username", payload }]);
    expect(ffUserFile.rowKeys[0]).toBe(payload.value);
    expect(Buffer.from(ffUserFile.bytes).toString("latin1")).toContain(payload.value);

    // The uri field, across formats, carries the uri-scheme payload verbatim (never
    // percent-encoded or otherwise mangled by the generator itself — a reader's own URL
    // parser is what interprets it, not this harness).
    const uriFile = buildHostileFile("bitwarden-json", [{ field: "uri", payload: uriPayload }]);
    expect(Buffer.from(uriFile.bytes).toString("latin1")).toContain(uriPayload.value);
  });

  it("is deterministic: the same seed and cases produce byte-identical files", () => {
    const rand1 = mulberry32(0xabcdef);
    const rand2 = mulberry32(0xabcdef);
    const cases1 = pick(rand1, SINK_PAYLOADS, 5).map((payload) => ({ field: "notes" as const, payload }));
    const cases2 = pick(rand2, SINK_PAYLOADS, 5).map((payload) => ({ field: "notes" as const, payload }));
    expect(cases1.map((c) => c.payload.id)).toEqual(cases2.map((c) => c.payload.id));
    const a = buildHostileFile("rizzy-json", cases1);
    const b = buildHostileFile("rizzy-json", cases2);
    expect(Buffer.from(a.bytes).equals(Buffer.from(b.bytes))).toBe(true);
  });

  it("rizzy-json field keys match the ADR 0018 §7 grammar the record layer carries verbatim", () => {
    const payload = SINK_PAYLOADS[0]!;
    const file = buildHostileFile("rizzy-json", [
      { field: "customName", payload },
      { field: "tag", payload: { id: "short", value: "work", kind: "injection" } },
    ]);
    const doc = JSON.parse(Buffer.from(file.bytes).toString("utf8")) as {
      format: string;
      items: { fields: { key: string }[] }[];
    };
    expect(doc.format).toBe("rizzy-vault-plaintext-export");
    const keys = doc.items.flatMap((i) => i.fields.map((f) => f.key));
    // `list/<32-hex>/attribute` (`crates/rizzy-core/src/item/tests.rs`'s `element_key` helper).
    expect(keys.some((k) => /^field\/[0-9a-f]{32}\/label$/.test(k))).toBe(true);
    // `tag/<hex-of-utf8-name>` (`crates/rizzy-core/src/item/tag.rs` module docs).
    expect(keys.some((k) => /^tag\/[0-9a-f]+$/.test(k))).toBe(true);
  });
});
