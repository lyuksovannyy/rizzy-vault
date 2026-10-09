// Vite build of the extension's ES-module surfaces (ADR 0014 §3): the popup, the options page,
// the inline-menu iframe, the service worker (Chromium) or background page (Firefox), and the
// offscreen document (Chromium). These may freely share chunks (every one of them is loaded as
// `type: "module"`, which both browsers support for these contexts) — including the
// inline-menu iframe, since it loads from this extension's own origin and its own subsequent
// module fetches are ordinary same-extension loads, not resource requests from the untrusted
// page that embeds it (only `index.html` itself needs a `web_accessible_resources` entry in the
// manifests; see `README.md`). The content script is a separate build
// (`vite.content.config.ts`): it must be one self-contained file, since `content_scripts`
// cannot load a dynamically-chunked module graph the way these can.
//
// `mode` selects the target ("chromium" | "firefox", passed as `--mode`) so the single
// background entry point matches ADR 0036 §2: Chromium gets the message-routing-only service
// worker plus the offscreen document; Firefox gets just its own long-lived background page.
import { copyFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

import type { Plugin } from "vite";
import { defineConfig } from "vitest/config";

const root = fileURLToPath(new URL(".", import.meta.url));

function copyManifest(mode: string): Plugin {
  return {
    name: "rizzy-copy-manifest",
    apply: "build",
    closeBundle() {
      const outDir = fileURLToPath(new URL(`./dist/${mode}`, import.meta.url));
      mkdirSync(outDir, { recursive: true });
      copyFileSync(`${root}manifest.${mode}.json`, `${outDir}/manifest.json`);
    },
  };
}

export default defineConfig(({ mode }) => {
  const target = mode === "firefox" ? "firefox" : "chromium";
  const entry = (path: string) => fileURLToPath(new URL(path, import.meta.url));

  const input: Record<string, string> = {
    "src/popup/index": entry("./src/popup/index.html"),
    "src/options/index": entry("./src/options/index.html"),
    "src/inline-menu/index": entry("./src/inline-menu/index.html"),
    "src/passkey-consent/index": entry("./src/passkey-consent/index.html"),
  };
  if (target === "chromium") {
    input["src/background/service-worker"] = entry("./src/background/service-worker.ts");
    input["src/core-host/offscreen"] = entry("./src/core-host/offscreen.html");
  } else {
    input["src/core-host/background-page"] = entry("./src/core-host/background-page.ts");
  }

  return {
    root,
    build: {
      outDir: entry(`./dist/${target}`),
      emptyOutDir: true,
      target: "es2022",
      sourcemap: false,
      modulePreload: { polyfill: false },
      rollupOptions: {
        input,
        output: {
          entryFileNames: "[name].js",
          chunkFileNames: "src/chunks/[name]-[hash].js",
          assetFileNames: "src/assets/[name][extname]",
        },
      },
    },
    plugins: [copyManifest(target)],
    test: {
      // "node", not "jsdom": every test here (messaging, sender, auto-lock, cache mapping) is
      // pure logic with an injectable clock/fake IndexedDB-free API, needing no DOM. Adding
      // `jsdom` as a dependency only to flip this would be an unjustified new dependency
      // (CLAUDE.md "Dependencies") for tests that do not need it; `content-script.ts`, which
      // does touch the DOM, has no unit test in this change (`not_done`) for the same reason.
      environment: "node",
      include: ["test/**/*.test.ts"],
    },
  };
});
