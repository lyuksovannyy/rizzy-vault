// The Firefox background page's entry point (ADR 0036 §2): "the background page on Firefox
// (MV3 `background.scripts`, which Firefox keeps non-ephemeral unlike Chromium's event page)."
// Firefox has no `chrome.offscreen`; its manifest (`manifest.firefox.json`) loads this script
// directly as the background, so it is both the long-lived core-holding context and the
// MV3-required background entry — there is no separate message-routing-only service worker on
// this browser build (there is nothing for one to protect that this page does not already
// hold correctly: it never exposes key material across a message boundary either).
import { installCoreContextListener } from "./listener.ts";
import { webext } from "../types/runtime-api.ts";

// `acceptContentScripts: true`: Firefox has no separate service worker, so this is the only
// context a real content-script message ever reaches — it must validate and handle it directly
// (fixes the content script's `fields_detected`/`fill_chosen`/`credentials_submitted` messages
// previously resolving to `undefined` forever on this browser build).
installCoreContextListener(webext(), { acceptContentScripts: true });
