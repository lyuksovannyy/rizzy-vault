// SPDX-License-Identifier: AGPL-3.0-only

// The Firefox background page's entry point (ADR 0036 §2; ADR 0111 §2.2, §2.4): Firefox is
// Manifest V2 with a **persistent** background page (`background-page.html`, which loads this
// module), because an MV3 Firefox background is an event page that unloads when idle and would
// take the unlocked vault with it. A persistent page stays loaded until the extension is unloaded
// or the browser closes; if it reloads (an extension-process crash), it starts locked (ADR 0111
// §1.2). Firefox has no `chrome.offscreen`, so this page is both the long-lived core-holding
// context and the only background context: there is no message-routing service worker on this
// build. It reads the lock settings from `storage` and receives `browser.idle` itself (§3.2).
import { installCoreContextListener } from "./listener.ts";
import { webext } from "../types/runtime-api.ts";

// `acceptContentScripts: true`: Firefox has no separate service worker, so this is the only
// context a real content-script message ever reaches — it must validate and handle it directly
// (fixes the content script's `fields_detected`/`credentials_submitted` messages previously
// resolving to `undefined` forever on this browser build).
installCoreContextListener(webext(), { acceptContentScripts: true, lockSource: "own_storage" });
