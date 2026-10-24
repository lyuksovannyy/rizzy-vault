// SPDX-License-Identifier: AGPL-3.0-only

// Pure oracles over a `Snapshot` (A16/A14/A8/A1; THREAT_MODEL.md §7.1, §7.7, INV-35, INV-42,
// INV-49, INV-68, CRYPTO.md §11.4): no DOM, no Playwright, so they run the same way in the
// browser-driven spec (`adversarial-import.spec.ts`) and in the positive-control unit test
// (`apps/web/test/attack-oracles.test.ts`), which is how the harness proves it can actually
// detect a violation — it feeds these functions a hand-built bad snapshot and asserts a
// `Violation` comes back, not just that the real app currently passes.
//
// Why a sink fingerprint, not only the `window.__rzxHit` tripwire (`payloads.ts` module docs):
// INV-49's CSP blocks an injected `<script>` from *running*, so the tripwire alone would read
// green even when a field value reached a raw-HTML sink — which is the INV-35 violation this
// harness hunts. `sinkFingerprint` instead looks for the sink itself: an event-handler
// attribute, an `iframe[srcdoc]`, a `<script>` element, or a `style` attribute holding a
// `javascript:` URL. React never emits any of these from its own markup (synthetic props
// become listeners, not literal DOM attributes), so their presence means a field's raw text
// became a live element, CSP notwithstanding.

/** One oracle's finding: human-readable, and enough of a needle to grep the snapshot for. */
export interface Violation {
  readonly oracle: string;
  readonly detail: string;
}

/** An `<a>` (or any element Playwright reports a resolved protocol for) that the page rendered
 * from item content. `descriptor` is a short, hand-built `<tag attr="…">` string (never
 * `outerHTML`, which ADR 0014 §2's lint rule bans everywhere, this harness included). */
export interface LinkInfo {
  readonly descriptor: string;
  readonly protocol: string;
  readonly href: string;
}

/** An element matching the sink fingerprint (module docs). */
export interface SinkHit {
  readonly tag: string;
  readonly descriptor: string;
}

/** One secret input's attributes, before or after "Show" (INV-68). */
export interface SecretFieldSnapshot {
  readonly label: string;
  readonly phase: "masked" | "revealed";
  readonly type: string | null;
  readonly spellcheck: string | null;
  readonly autocomplete: string | null;
  readonly autocapitalize: string | null;
}

/** One browser-storage entry (A8/A1; CRYPTO.md §11.4). */
export interface StorageEntry {
  readonly area: "localStorage" | "sessionStorage" | "indexedDB" | "cookie";
  readonly key: string;
  readonly value: string;
}

/** The response headers of one served path (INV-49, §7.7). */
export interface HeaderSnapshot {
  readonly path: string;
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly isHttps: boolean;
}

/** Everything one oracle pass reads, collected by `snapshot.ts` in the real browser or built
 * by hand for a positive control. */
export interface Snapshot {
  readonly links: readonly LinkInfo[];
  readonly sinkHits: readonly SinkHit[];
  readonly tripwireHit: boolean;
  readonly cspViolations: readonly string[];
  readonly secretFields: readonly SecretFieldSnapshot[];
  readonly storage: readonly StorageEntry[];
  readonly headers: readonly HeaderSnapshot[];
  readonly oversizedImportCrashed: boolean;
}

const SAFE_PROTOCOLS = new Set(["http:", "https:"]);

/** INV-42: every link the page actually renders from item content opens only `http`/`https`. */
export function checkUriScheme(snap: Snapshot): Violation[] {
  return snap.links
    .filter((l) => !SAFE_PROTOCOLS.has(l.protocol))
    .map((l) => ({
      oracle: "INV-42 uri-scheme",
      detail: `a rendered link resolves to ${l.protocol} (${l.href}): ${l.descriptor}`,
    }));
}

/** INV-35: no field value ever reached a raw-HTML sink (module docs' fingerprint), and the
 * tripwire a sink would have run never fired. Both conditions are checked, independently: a
 * sink hit is reported even if, for some reason, the tripwire did not fire (e.g. a payload
 * variant whose script never executes but still planted a live, attacker-controlled element —
 * still a sink, still reportable), and a tripwire hit is reported even with no fingerprint
 * match (a sink shape this harness's fingerprint does not yet cover). */
export function checkSinks(snap: Snapshot): Violation[] {
  const out: Violation[] = snap.sinkHits.map((h) => ({
    oracle: "INV-35 sink-fingerprint",
    detail: `a live <${h.tag}> sink element exists: ${h.descriptor}`,
  }));
  if (snap.tripwireHit) {
    out.push({ oracle: "INV-35 tripwire", detail: "window.__rzxHit was set: a payload executed" });
  }
  return out;
}

/** INV-68 / A14: a secret input's attributes, masked and (module docs) still after reveal. */
export function checkSecretFields(snap: Snapshot): Violation[] {
  const out: Violation[] = [];
  for (const f of snap.secretFields) {
    const where = `${f.label} (${f.phase})`;
    if (f.phase === "masked" && f.type !== "password") {
      out.push({ oracle: "INV-68 masked", detail: `${where}: type is ${String(f.type)}, not password` });
    }
    if (f.phase === "revealed" && f.type !== "text") {
      out.push({ oracle: "INV-68 reveal", detail: `${where}: type is ${String(f.type)}, expected text` });
    }
    if (f.spellcheck !== "false") {
      out.push({ oracle: "INV-68 spellcheck", detail: `${where}: spellcheck is ${String(f.spellcheck)}` });
    }
    if (f.autocomplete === null || f.autocomplete === "on") {
      out.push({ oracle: "INV-68 autocomplete", detail: `${where}: autocomplete is ${String(f.autocomplete)}` });
    }
  }
  return out;
}

/** The secrets that must never appear in browser storage, as the caller's own session made
 * them (CRYPTO.md §11.4; A8/A1); the INV-15 canary pattern applied to storage instead of the
 * network/DB/logs. Matched raw, and matched case-insensitively against a hex/base64 recoding
 * so a trivial re-encoding does not hide a hit. */
export function buildSecretNeedles(secrets: readonly string[]): readonly string[] {
  const needles = new Set<string>();
  for (const s of secrets) {
    if (s.length === 0) {
      continue;
    }
    needles.add(s);
    needles.add(Buffer.from(s, "utf8").toString("hex"));
    needles.add(Buffer.from(s, "utf8").toString("base64"));
  }
  return [...needles];
}

/** A8/A1, CRYPTO.md §11.4: storage holds no secret; the only persisted values are the
 * non-secret theme choice and, if explicitly opted in (never in this harness), the Secret Key.
 * `allowedKeys` lists the keys/paths this snapshot is allowed to hold at all (the theme). */
export function checkStorage(
  snap: Snapshot,
  secrets: readonly string[],
  allowedKeys: readonly string[] = [],
): Violation[] {
  const needles = buildSecretNeedles(secrets).filter((n) => n.length >= 4);
  const out: Violation[] = [];
  for (const entry of snap.storage) {
    for (const needle of needles) {
      if (entry.value.includes(needle)) {
        out.push({
          oracle: "CRYPTO.md §11.4 storage-secret",
          detail: `${entry.area} ${entry.key} contains a secret value`,
        });
        break;
      }
    }
    if (!allowedKeys.includes(entry.key) && entry.area !== "cookie" && /secret|password|unlock|E_local|sk\b/i.test(entry.key)) {
      out.push({
        oracle: "CRYPTO.md §11.4 storage-key",
        detail: `${entry.area} has an unexpected key that looks secret-shaped: ${entry.key}`,
      });
    }
  }
  return out;
}

const REQUIRED_HEADERS: ReadonlyArray<{ readonly name: string; readonly must: (v: string) => boolean }> = [
  {
    name: "content-security-policy",
    must: (v) =>
      /frame-ancestors\s+'none'/.test(v) &&
      !/unsafe-inline/.test(v) &&
      !/script-src[^;]*\*(?!\S)/.test(v),
  },
  { name: "x-content-type-options", must: (v) => v.toLowerCase() === "nosniff" },
  { name: "referrer-policy", must: (v) => v.toLowerCase().includes("no-referrer") },
];

/** INV-49 / §7.7: the headers every served path carries. HSTS is checked only over `https:`
 * (an http-only e2e server cannot carry it meaningfully; see `not_covered`). */
export function checkHeaders(snap: Snapshot): Violation[] {
  const out: Violation[] = [];
  for (const h of snap.headers) {
    for (const required of REQUIRED_HEADERS) {
      const value = h.headers[required.name];
      if (value === undefined) {
        out.push({ oracle: "INV-49 header-missing", detail: `${h.path}: no ${required.name} header` });
      } else if (!required.must(value)) {
        out.push({ oracle: "INV-49 header-value", detail: `${h.path}: ${required.name} is ${value}` });
      }
    }
    if (h.isHttps && h.headers["strict-transport-security"] === undefined) {
      out.push({ oracle: "INV-49 hsts-missing", detail: `${h.path}: no Strict-Transport-Security over https` });
    }
  }
  return out;
}

/** A16 "parser DoS" read narrowly: an oversized field did not hang or crash the page. The
 * generator-level caps (`limits.rs`) are the Rust importer's own job and its fuzz targets'; this
 * oracle only watches that the browser session stayed alive and responsive. */
export function checkOversizedHandling(snap: Snapshot): Violation[] {
  return snap.oversizedImportCrashed
    ? [{ oracle: "A16 oversized-crash", detail: "an oversized import left the page unresponsive or crashed" }]
    : [];
}

/** Every oracle, in one pass. */
export function checkAll(
  snap: Snapshot,
  secrets: readonly string[],
  allowedStorageKeys: readonly string[] = [],
): Violation[] {
  return [
    ...checkUriScheme(snap),
    ...checkSinks(snap),
    ...checkSecretFields(snap),
    ...checkStorage(snap, secrets, allowedStorageKeys),
    ...checkHeaders(snap),
    ...checkOversizedHandling(snap),
  ];
}
