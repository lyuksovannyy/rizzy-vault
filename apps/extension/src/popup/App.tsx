// The popup's top-level view (ADR 0036 §4 "Popup... unlock, search, item list and detail with
// copy, generator, lock, open web vault" — ROADMAP §4.4 wording).
import { useEffect, useState } from "react";

import type { ExtensionClient } from "../core/client.ts";
import { EnrolView } from "./views/Enrol.tsx";
import { GeneratorView } from "./views/Generator.tsx";
import { ItemsView } from "./views/Items.tsx";
import { LockedView } from "./views/Locked.tsx";

export interface AppProps {
  readonly client: ExtensionClient;
  /** Opens `url` in a new tab (`chrome.tabs.create`/`browser.tabs.create`) — injected so this
   * component stays testable without a real `WebExtNamespace`. */
  readonly openTab: (url: string) => void;
}

type View = "loading" | "enrol" | "locked" | "items" | "generator";

export function App({ client, openTab }: AppProps) {
  const [view, setView] = useState<View>("loading");
  const [error, setError] = useState<string | undefined>(undefined);
  const [serverOrigin, setServerOrigin] = useState<string | undefined>(undefined);
  const [syncing, setSyncing] = useState(false);
  const [syncMessage, setSyncMessage] = useState<string | undefined>(undefined);
  // Bumped after every sync that actually completes (auto, on unlock, or the manual button) so
  // `ItemsView`'s own `useEffect` — which otherwise fetches the list exactly once, on mount —
  // refetches too. Found empirically running this change's E2E coverage: without this, a device
  // that stays on the Items view the whole time (never switching to Generator and back, which
  // would remount it) keeps showing "No items." forever after a sync that pulled or pushed real
  // items, even while the popup's own "Synced." message says the sync succeeded.
  const [itemsRevision, setItemsRevision] = useState(0);

  const refreshStatus = () => {
    void client
      .status()
      .then((status) => {
        setServerOrigin(status.serverOrigin);
        setView(!status.enrolled ? "enrol" : status.locked ? "locked" : "items");
      })
      .catch((e: unknown) => {
        setError(e instanceof Error ? e.message : "status_failed");
        setView("enrol");
      });
  };

  useEffect(refreshStatus, [client]);

  const unlocked = view === "items" || view === "generator";

  const runSync = () => {
    setSyncing(true);
    setSyncMessage(undefined);
    void client
      .sync()
      .then(() => {
        setSyncMessage("Synced.");
        setItemsRevision((r) => r + 1);
      })
      .catch((e: unknown) => setSyncMessage(e instanceof Error ? e.message : "sync_failed"))
      .finally(() => setSyncing(false));
  };

  // Mirrors the web vault's `VaultView` ("one sync on mount," `apps/web/src/views/VaultView.tsx`):
  // enrolment (CRYPTO.md §11.2) carries device certificates and account state, never an initial
  // pull of existing items — a freshly enrolled device's cache starts empty, and would offer no
  // autofill candidates at all until something calls `sync()`. Fires once on the transition into
  // "unlocked" (both "items" and "generator" count as unlocked, so switching between them does
  // not re-trigger this), not on every render. Declared above the `"loading"` early return,
  // along with every other hook in this component: hooks must run in the same order on every
  // render (React error #310 otherwise — hit empirically while writing this change, when this
  // effect lived below the early return and so ran on some renders but not others).
  useEffect(() => {
    if (unlocked) {
      runSync();
    }
  }, [unlocked]);

  if (view === "loading") {
    return <p>Loading…</p>;
  }

  return (
    <main>
      <h1>rizzy-vault</h1>
      {error !== undefined ? <p role="alert">{error}</p> : undefined}
      {view === "enrol" ? <EnrolView client={client} onEnrolled={refreshStatus} /> : undefined}
      {view === "locked" ? <LockedView client={client} onUnlocked={refreshStatus} /> : undefined}
      {view === "items" ? <ItemsView client={client} revision={itemsRevision} /> : undefined}
      {view === "generator" ? <GeneratorView client={client} /> : undefined}
      {unlocked ? (
        <nav>
          <button type="button" onClick={() => setView("items")} disabled={view === "items"}>
            Items
          </button>
          <button type="button" onClick={() => setView("generator")} disabled={view === "generator"}>
            Generator
          </button>
          <button type="button" disabled={syncing} onClick={runSync}>
            {syncing ? "Syncing…" : "Sync"}
          </button>
          {serverOrigin !== undefined ? (
            <button type="button" onClick={() => openTab(serverOrigin)}>
              Open web vault
            </button>
          ) : undefined}
          <button
            type="button"
            onClick={() => {
              void client.lock().then(refreshStatus);
            }}
          >
            Lock
          </button>
        </nav>
      ) : undefined}
      {syncMessage !== undefined ? <p role="status">{syncMessage}</p> : undefined}
    </main>
  );
}
