// SPDX-License-Identifier: AGPL-3.0-only

// Collects a `Snapshot` (`oracles.ts`) from the real browser page: the only place this harness
// touches the DOM, network or storage. Every function here *reads*; the oracles *judge* — kept
// apart so the judging logic is a pure, positive-controllable function (`oracles.ts` module
// docs).
import { type Page, expect } from "@playwright/test";

import { secretField } from "../helpers.ts";
import type { HeaderSnapshot, LinkInfo, SecretFieldSnapshot, SinkHit, StorageEntry } from "./oracles.ts";

/** Installs the tripwire and the CSP-violation collector before the page's first script runs
 * (`page.addInitScript`, called once, before `page.goto`): a payload that actually executed
 * sets `window.__rzxHit`, and every `securitypolicyviolation` event is recorded. Survives this
 * SPA's client-side navigations because it is an init script, not a one-off `evaluate`. */
export async function installTripwire(page: Page): Promise<void> {
  await page.addInitScript(() => {
    (window as unknown as { __rzxHit: boolean }).__rzxHit = false;
    const csp: string[] = [];
    (window as unknown as { __rzxCsp: string[] }).__rzxCsp = csp;
    document.addEventListener("securitypolicyviolation", (e) => {
      csp.push(`${e.violatedDirective}: ${e.blockedURI}`);
    });
  });
}

/** The `<script>` elements already on the page (`src`, or inline text) before any hostile
 * content is rendered: the app's own bundle loader, which `collectSinks` must not flag. */
export async function captureScriptBaseline(page: Page): Promise<string[]> {
  return page.evaluate(() =>
    Array.from(document.querySelectorAll("script")).map((s) => s.getAttribute("src") ?? s.textContent ?? ""),
  );
}

const SINK_ATTR_SELECTOR =
  '[onerror], [onload], [onmouseover], [onclick], [onfocus], [onanimationstart], iframe[srcdoc], [style*="javascript:"]';

/** The sink fingerprint (`oracles.ts` module docs): new `<script>` elements since `baseline`,
 * plus any element carrying an event-handler attribute, an `iframe[srcdoc]`, or an inline
 * `style` with a `javascript:` URL — none of which the app's own React markup ever emits. Each
 * hit is described from its tag name and attributes, never `el.outerHTML` (ADR 0014 §2's lint
 * rule bans that property everywhere, this harness included; the attribute values are already
 * attacker content, so re-serialising the whole element buys nothing a few attributes do not). */
export async function collectSinks(page: Page, baseline: readonly string[]): Promise<SinkHit[]> {
  return page.evaluate(
    ({ baseline, selector }) => {
      const describe = (el: Element): string => {
        const attrs = Array.from(el.attributes)
          .map((a) => `${a.name}="${a.value.slice(0, 60)}"`)
          .join(" ");
        return `<${el.tagName.toLowerCase()}${attrs.length > 0 ? ` ${attrs}` : ""}>`;
      };
      const hits: { tag: string; descriptor: string }[] = [];
      for (const el of Array.from(document.querySelectorAll("script"))) {
        const id = el.getAttribute("src") ?? el.textContent ?? "";
        if (!baseline.includes(id)) {
          hits.push({ tag: "script", descriptor: describe(el) });
        }
      }
      for (const el of Array.from(document.querySelectorAll(selector))) {
        hits.push({ tag: el.tagName.toLowerCase(), descriptor: describe(el) });
      }
      return hits;
    },
    { baseline: [...baseline], selector: SINK_ATTR_SELECTOR },
  );
}

/** Whether a payload actually ran (`installTripwire`). */
export async function readTripwire(page: Page): Promise<boolean> {
  return page.evaluate(() => (window as unknown as { __rzxHit: boolean }).__rzxHit);
}

/** The CSP violations recorded since `installTripwire` (informative: a violation here means
 * CSP itself blocked something, which is a second line of defence, not the primary oracle). */
export async function readCspViolations(page: Page): Promise<string[]> {
  return page.evaluate(() => (window as unknown as { __rzxCsp: string[] }).__rzxCsp ?? []);
}

/** Every `<a href>` the page currently renders, with the resolved (not raw-attribute) protocol
 * and href (`safe-url.ts`'s own approach: the WHATWG URL parser, as the browser sees it). */
export async function collectLinks(page: Page): Promise<LinkInfo[]> {
  return page.evaluate(() =>
    Array.from(document.querySelectorAll("a[href]")).map((a) => {
      const anchor = a as HTMLAnchorElement;
      return {
        descriptor: `<a href="${anchor.getAttribute("href")?.slice(0, 120) ?? ""}">`,
        protocol: anchor.protocol,
        href: anchor.href,
      };
    }),
  );
}

/** One secret field's attributes, masked and (if it has a reveal toggle) after "Show" — then
 * re-hidden, so the caller finds the UI as it found it. */
export async function collectSecretField(page: Page, label: string): Promise<SecretFieldSnapshot[]> {
  const field = secretField(page, label);
  const input = field.locator("input[data-secret-field]");
  const read = async (phase: "masked" | "revealed"): Promise<SecretFieldSnapshot> => ({
    label,
    phase,
    type: await input.getAttribute("type"),
    spellcheck: await input.getAttribute("spellcheck"),
    autocomplete: await input.getAttribute("autocomplete"),
    autocapitalize: await input.getAttribute("autocapitalize"),
  });
  const out = [await read("masked")];
  const show = field.getByRole("button", { name: "Show" });
  if ((await show.count()) > 0) {
    await show.click();
    out.push(await read("revealed"));
    await field.getByRole("button", { name: "Hide" }).click();
  }
  return out;
}

/** Browser storage after a flow (A8/A1; CRYPTO.md §11.4): localStorage, sessionStorage, every
 * IndexedDB database's every record (Chromium's `indexedDB.databases()`: not available in
 * every engine, see `not_covered`), and cookies. */
export async function collectStorage(page: Page): Promise<StorageEntry[]> {
  const [local, session, idb] = await Promise.all([
    page.evaluate(() => Object.entries(localStorage).map(([k, v]) => [k, String(v)] as const)),
    page.evaluate(() => Object.entries(sessionStorage).map(([k, v]) => [k, String(v)] as const)),
    page.evaluate(async () => {
      const out: [string, string][] = [];
      const idbWindow = window as unknown as { indexedDB?: IDBFactory };
      if (idbWindow.indexedDB === undefined || typeof idbWindow.indexedDB.databases !== "function") {
        return out;
      }
      const infos = await idbWindow.indexedDB.databases();
      for (const info of infos) {
        if (info.name === undefined) {
          continue;
        }
        const name = info.name;
        const db = await new Promise<IDBDatabase>((resolve, reject) => {
          const req = idbWindow.indexedDB!.open(name);
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => reject(req.error);
        });
        for (const storeName of Array.from(db.objectStoreNames)) {
          const records = await new Promise<unknown>((resolve, reject) => {
            const tx = db.transaction(storeName, "readonly");
            const getAll = tx.objectStore(storeName).getAll();
            getAll.onsuccess = () => resolve(getAll.result);
            getAll.onerror = () => reject(getAll.error);
          });
          out.push([`${name}/${storeName}`, JSON.stringify(records)]);
        }
        db.close();
      }
      return out;
    }),
  ]);
  const cookies = await page.context().cookies();
  return [
    ...local.map(([key, value]) => ({ area: "localStorage" as const, key, value })),
    ...session.map(([key, value]) => ({ area: "sessionStorage" as const, key, value })),
    ...idb.map(([key, value]) => ({ area: "indexedDB" as const, key, value })),
    ...cookies.map((c) => ({ area: "cookie" as const, key: c.name, value: c.value })),
  ];
}

/** Response headers of each path in `paths` (INV-49, §7.7), fetched through the page's own
 * request context (same origin, same TLS state). */
export async function collectHeaders(page: Page, origin: string, paths: readonly string[]): Promise<HeaderSnapshot[]> {
  const out: HeaderSnapshot[] = [];
  for (const path of paths) {
    const res = await page.request.get(`${origin}${path}`);
    out.push({ path, status: res.status(), headers: res.headers(), isHttps: origin.startsWith("https:") });
  }
  return out;
}

/** Whether the page is still alive and responsive, for the oversized-import oracle: a hang or
 * a crashed renderer never resolves this `evaluate`, so the caller races it against a timeout. */
export async function pageIsResponsive(page: Page, timeoutMs = 5_000): Promise<boolean> {
  try {
    await expect
      .poll(() => page.evaluate(() => 1 + 1), { timeout: timeoutMs })
      .toBe(2);
    return true;
  } catch {
    return false;
  }
}
