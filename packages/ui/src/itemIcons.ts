// SPDX-License-Identifier: AGPL-3.0-only

// Item icons, for the web vault and the extension popup (ADR 0052 point 6). Pure logic: no wasm,
// no network and no DOM beyond the injected URL factory; the caller's fetcher is the one call
// into its core (the web vault's Worker, the extension's core-holding context).
//
// - **What leaves the browser.** For an item that has a website, the core sends the
//   website's hostname, and nothing else (no account, session or item, no Authorization header),
//   to this server's `icons` role, which fetches the site's icon, re-encodes it as a PNG of at
//   most 128×128 pixels and caches it anonymously. No third-party image is ever loaded by the
//   browser: the page shows the server's PNG only.
// - **How it is shown.** The bytes the core checked become a same-origin `blob:` URL
//   (`URL.createObjectURL`) for an `<img alt="">` (`ItemIcon.tsx`): never markup, never a
//   `data:` URL. The web vault's CSP allows `img-src 'self' blob:` for exactly this (ADR 0052
//   owner answer 7); the extension pages' CSP does not restrict images. The icon is decorative: the item's title is the row's text, so the image has an empty `alt`.
// - **When.** An icon is fetched once per hostname per unlocked session, when a row that needs
//   it is shown; at most `MAX_CONCURRENT` fetches run at once. A rate limit (the role allows
//   30 a minute, 10 at once, per address) pauses the queue for `RATE_LIMIT_WAIT_MS` and retries
//   the same host. Any other failure, including "no icon" and a server without the role, shows
//   the item-type icon and is not retried in this session. `clear()` (on lock) revokes every
//   URL and stops the queue.

/** The core call that fetches one icon: PNG bytes, or `null` for none. */
export type IconFetcher = (websiteHost: string) => Promise<Uint8Array | null>;

/** Makes and revokes the URLs the page shows. */
export interface IconUrls {
  create(png: Uint8Array): string;
  revoke(url: string): void;
}

/** Timer functions, injectable for tests. */
export interface IconTimers {
  set(f: () => void, ms: number): unknown;
  clear(handle: unknown): void;
}

/** The most icon fetches in flight at once. */
export const MAX_CONCURRENT = 2;

/** How long the queue pauses after a rate limit: about the time the role takes to refill two
 * requests (one per 2 s). */
export const RATE_LIMIT_WAIT_MS = 4_000;

/** The most hostnames a session tracks; past it, no new icon is fetched (memory bound). */
export const MAX_HOSTS = 2_000;

/** The browser's `blob:` URLs. */
export const blobUrls: IconUrls = {
  create: (png) => URL.createObjectURL(new Blob([png as Uint8Array<ArrayBuffer>], { type: "image/png" })),
  revoke: (url) => URL.revokeObjectURL(url),
};

const browserTimers: IconTimers = {
  set: (f, ms) => setTimeout(f, ms),
  clear: (h) => clearTimeout(h as ReturnType<typeof setTimeout>),
};

/** The cache key of a website host: trimmed, lowercase, no trailing dot. The core normalises
 * further (IDNA), so two keys can name one site; that only costs one more request. */
export function iconKey(websiteHost: string): string {
  return websiteHost.trim().toLowerCase().replace(/\.+$/u, "");
}

type IconState =
  | { readonly kind: "queued" }
  | { readonly kind: "loading" }
  | { readonly kind: "icon"; readonly url: string }
  | { readonly kind: "none" };

/** The session's icons (module docs). */
export class IconLoader {
  readonly #fetch: IconFetcher;
  readonly #urls: IconUrls;
  readonly #timers: IconTimers;
  readonly #states = new Map<string, IconState>();
  readonly #queue: string[] = [];
  readonly #listeners = new Set<() => void>();
  #running = 0;
  #pause: unknown = undefined;
  #stopped = false;

  constructor(fetch: IconFetcher, urls: IconUrls = blobUrls, timers: IconTimers = browserTimers) {
    this.#fetch = fetch;
    this.#urls = urls;
    this.#timers = timers;
  }

  /** The URL of `websiteHost`'s icon, or `null` while there is none (yet). */
  peek(websiteHost: string): string | null {
    const state = this.#states.get(iconKey(websiteHost));
    return state?.kind === "icon" ? state.url : null;
  }

  /** Starts fetching `websiteHost`'s icon, once per session. */
  request(websiteHost: string): void {
    const key = iconKey(websiteHost);
    if (this.#stopped || key === "" || this.#states.has(key) || this.#states.size >= MAX_HOSTS) {
      return;
    }
    this.#states.set(key, { kind: "queued" });
    this.#queue.push(key);
    this.#pump();
  }

  /** Calls `listener` after every change; returns the unsubscribe function. */
  subscribe(listener: () => void): () => void {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }

  /** Revokes every URL and stops the queue (on lock). */
  clear(): void {
    this.#stopped = true;
    if (this.#pause !== undefined) {
      this.#timers.clear(this.#pause);
      this.#pause = undefined;
    }
    for (const state of this.#states.values()) {
      if (state.kind === "icon") {
        this.#urls.revoke(state.url);
      }
    }
    this.#states.clear();
    this.#queue.length = 0;
    this.#notify();
  }

  #notify(): void {
    for (const listener of this.#listeners) {
      listener();
    }
  }

  #pump(): void {
    while (!this.#stopped && this.#pause === undefined && this.#running < MAX_CONCURRENT) {
      const key = this.#queue.shift();
      if (key === undefined) {
        return;
      }
      this.#running += 1;
      this.#states.set(key, { kind: "loading" });
      void this.#load(key);
    }
  }

  async #load(key: string): Promise<void> {
    let next: IconState | "retry";
    try {
      const png = await this.#fetch(key);
      next = png === null || this.#stopped ? { kind: "none" } : { kind: "icon", url: this.#urls.create(png) };
    } catch (e) {
      next = codeOf(e) === "server_rate_limited" ? "retry" : { kind: "none" };
    }
    this.#running -= 1;
    if (this.#stopped) {
      return;
    }
    if (next === "retry") {
      this.#states.set(key, { kind: "queued" });
      this.#queue.unshift(key);
      if (this.#pause === undefined) {
        this.#pause = this.#timers.set(() => {
          this.#pause = undefined;
          this.#pump();
        }, RATE_LIMIT_WAIT_MS);
      }
      return;
    }
    this.#states.set(key, next);
    if (next.kind === "icon") {
      this.#notify();
    }
    this.#pump();
  }
}

/** The error code of a rejected Worker call. */
function codeOf(e: unknown): string | undefined {
  if (typeof e === "object" && e !== null && "code" in e && typeof e.code === "string") {
    return e.code;
  }
  return undefined;
}
