// The popup's top-level view (ADR 0036 §4 "Popup... unlock, search, item list and detail with
// copy, generator, lock, open web vault" — ROADMAP §4.4 wording; this change ships Locked and
// the generator, which need no device binding, and reports the rest in `not_done`).
import { useEffect, useState } from "react";

import type { ExtensionClient } from "../core/client.ts";
import { GeneratorView } from "./views/Generator.tsx";
import { LockedView } from "./views/Locked.tsx";

export interface AppProps {
  readonly client: ExtensionClient;
}

type View = "loading" | "locked" | "generator";

export function App({ client }: AppProps) {
  const [view, setView] = useState<View>("loading");
  const [error, setError] = useState<string | undefined>(undefined);

  useEffect(() => {
    void client
      .status()
      .then((status) => setView(status.locked ? "locked" : "generator"))
      .catch((e: unknown) => {
        setError(e instanceof Error ? e.message : "status_failed");
        setView("locked");
      });
  }, [client]);

  if (view === "loading") {
    return <p>Loading…</p>;
  }

  return (
    <main>
      <h1>rizzy-vault</h1>
      {error !== undefined ? <p role="alert">{error}</p> : undefined}
      {view === "locked" ? (
        <LockedView client={client} onUnlocked={() => setView("generator")} />
      ) : (
        <GeneratorView client={client} />
      )}
      <nav>
        <button type="button" onClick={() => setView("generator")}>
          Generator
        </button>
        <button
          type="button"
          onClick={() => {
            void client.lock().then(() => setView("locked"));
          }}
        >
          Lock
        </button>
        {/* "Open web vault" needs the account's server_origin, which nothing in this change can
            read yet (no enrolment binding, core/bindings.ts): not_done. */}
      </nav>
    </main>
  );
}
