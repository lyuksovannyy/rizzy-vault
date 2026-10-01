// The web vault's entry point (ADR 0014; ROADMAP §4.2). It starts the one core Worker that
// holds the wasm instance and the keys (ADR 0013 §4) and renders the UI, which talks to the
// Worker only through `CoreClient`.
import "@rizzy-vault/ui/tokens.css";
import "./app.css";

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App.tsx";
import { CoreClient } from "./core-client.ts";
import { CORE_CRASHED } from "./protocol.ts";
import { workerScriptUrl } from "./trusted-types.ts";
import coreWorkerUrl from "./core-worker.ts?worker&url";

const worker = new Worker(workerScriptUrl(coreWorkerUrl), { type: "module", name: "rizzy-core" });
const client = new CoreClient(worker);
// A Worker that fails to load or throws at the top level answers nothing: fail every call.
worker.addEventListener("error", () => client.fail(CORE_CRASHED));

const root = document.getElementById("root");
if (root !== null) {
  createRoot(root).render(
    <StrictMode>
      <App client={client} />
    </StrictMode>,
  );
}
