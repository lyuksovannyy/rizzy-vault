// The popup's entry point (ADR 0036 §4, §6): a short-lived React app that never loads wasm
// directly, reaching the core only through `core/client.ts`'s messaging-backed client.
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { createRuntimeTransport, ExtensionClient } from "../core/client.ts";
import { webext } from "../types/runtime-api.ts";
import { App } from "./App.tsx";

const client = new ExtensionClient(createRuntimeTransport(webext()));
const root = document.getElementById("root");
if (root !== null) {
  createRoot(root).render(
    <StrictMode>
      <App client={client} />
    </StrictMode>,
  );
}
