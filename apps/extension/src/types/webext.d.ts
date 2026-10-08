// Minimal ambient WebExtension types for exactly the APIs this extension calls (ADR 0036 §2,
// §4). Deliberately not `@types/chrome`: that package types the whole Chrome extension surface,
// most of it unused here, and pulling it in is a dependency-review question for the owner
// (CLAUDE.md "Dependencies") this ADR's implementation PR does not need to raise. If a later
// change needs more of the surface, prefer widening this file over adding the dependency.
//
// `chrome` (Chromium, MV3) and `browser` (Firefox, the WebExtensions polyfilled global) share
// the same promise-based shape for everything used here; Firefox's `chrome.*` callback form is
// never used. A thin runtime shim picks whichever global exists (`src/types/runtime-api.ts`).

/** The subset of `chrome.runtime` / `browser.runtime` this extension calls. */
interface WebExtRuntime {
  readonly id: string;
  getURL(path: string): string;
  sendMessage(message: unknown): Promise<unknown>;
  readonly onMessage: WebExtEvent<
    (message: unknown, sender: WebExtMessageSender, sendResponse: (response?: unknown) => void) => boolean | void
  >;
  readonly onInstalled: WebExtEvent<() => void>;
  readonly onStartup: WebExtEvent<() => void>;
  connect(connectInfo?: { name?: string }): WebExtPort;
  readonly onConnect: WebExtEvent<(port: WebExtPort) => void>;
}

interface WebExtPort {
  readonly name: string;
  postMessage(message: unknown): void;
  disconnect(): void;
  readonly onMessage: WebExtEvent<(message: unknown) => void>;
  readonly onDisconnect: WebExtEvent<() => void>;
}

/** What a message sender reports (ADR 0036 §4: origin is read from here, never the body). */
interface WebExtMessageSender {
  readonly id?: string;
  readonly origin?: string;
  readonly tab?: { readonly id?: number; readonly url?: string };
  readonly frameId?: number;
}

interface WebExtEvent<Listener> {
  addListener(listener: Listener): void;
  removeListener(listener: Listener): void;
}

/** `chrome.offscreen` (Chromium only; ADR 0036 §2, reason `WORKERS`). */
interface WebExtOffscreen {
  hasDocument(): Promise<boolean>;
  createDocument(options: { url: string; reasons: string[]; justification: string }): Promise<void>;
  closeDocument(): Promise<void>;
}

/** `chrome.storage.session` (ADR 0013 §3 rule 2; ADR 0036 §2 fallback) and `.local`. */
interface WebExtStorageArea {
  get(keys?: string | string[] | null): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | string[]): Promise<void>;
  clear(): Promise<void>;
}

interface WebExtStorage {
  readonly session: WebExtStorageArea;
  readonly local: WebExtStorageArea;
}

/** `chrome.idle` / `browser.idle` (ADR 0036 §3 auto-lock). */
interface WebExtIdle {
  setDetectionInterval(seconds: number): void;
  queryState(detectionIntervalInSeconds: number): Promise<"active" | "idle" | "locked">;
  readonly onStateChanged: WebExtEvent<(state: "active" | "idle" | "locked") => void>;
}

interface WebExtTabs {
  query(queryInfo: { active?: boolean; currentWindow?: boolean }): Promise<Array<{ id?: number; url?: string }>>;
  create(createProperties: { url: string }): Promise<unknown>;
}

interface WebExtNamespace {
  readonly runtime: WebExtRuntime;
  // `storage` and `idle` are typed optional, not assumed present: measured empirically (not
  // documented in Chrome's own API reference at the time of writing) against a real Chromium
  // build, `chrome.offscreen` document's own `chrome` object exposes neither namespace at all —
  // both are `undefined` there, unlike every other extension page (popup, options, the
  // service worker). `core-host/listener.ts`'s own doc comment covers the fix this forces: the
  // one `onMessage` listener this extension depends on for everything must register before any
  // code that assumes either exists can throw and abort registration.
  readonly storage?: WebExtStorage;
  readonly idle?: WebExtIdle;
  readonly tabs: WebExtTabs;
  readonly offscreen?: WebExtOffscreen;
}

// `chrome` exists in Chromium; `browser` in Firefox. Both are optional at the type level so
// `src/types/runtime-api.ts` can feature-detect without either global being declared `any`.
// eslint-disable-next-line no-var
declare var chrome: WebExtNamespace | undefined;
// eslint-disable-next-line no-var
declare var browser: WebExtNamespace | undefined;
