// The Chromium offscreen document's entry point (ADR 0036 §2): one of the two long-lived
// contexts that may hold `@rizzy-vault/core`'s wasm instance. Created by the service worker
// (`background/service-worker.ts`) with `chrome.offscreen.createDocument`, reason `WORKERS`
// (ADR 0036 "Owner answers at acceptance", recorded in `apps/extension/README.md`); loaded by
// `offscreen.html`. The message-handling logic itself is shared with the Firefox background
// page (`background-page.ts`) through `listener.ts`/`core-context.ts`: this file is only the
// browser-specific bootstrap.
import { installCoreContextListener } from "./listener.ts";
import { webext } from "../types/runtime-api.ts";

// `acceptContentScripts: false`: the service worker (`background/service-worker.ts`) is the
// one Chromium context that validates and forwards a raw content-script message here.
installCoreContextListener(webext(), { acceptContentScripts: false });
