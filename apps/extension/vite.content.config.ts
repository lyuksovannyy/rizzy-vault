// The content scripts' own build (ADR 0036 §4, §6; ADR 0014 §2; ADR 0039 §2): each one self-
// contained, no chunk splitting, because `content_scripts`/a `<script src>` load exactly the
// file named — neither resolves a module graph the way an extension page's
// `<script type="module">` does. `inlineDynamicImports` plus a single Rollup input is what
// forces that: Rollup refuses `inlineDynamicImports` with more than one input, and refuses an
// IIFE output with genuine code-splitting across inputs at all ("UMD and IIFE output formats are
// not supported for code-splitting builds") — so this config builds exactly ONE of the three
// standalone entries per invocation, selected by the `RIZZY_CONTENT_ENTRY` env var
// `package.json`'s `build:chromium`/`build:firefox` scripts set before each of the three
// `vite build --config` calls (this project's installed Vite version has no "array of configs"
// support to do this in one call — `UserConfigExport` admits no array — unlike some other Vite
// major versions). Running each as a separate `vite build --config` (not more entries in
// `vite.config.ts`) is what keeps Rollup from sharing a chunk between any of these and the
// popup/background bundle, which would otherwise produce a file that `import`s a sibling chunk
// no manifest/web-accessible-resource entry lists.
//
// `src/content/passkey-page-shim.ts` is bundled here too, even though it is not a
// `content_scripts` entry at all (it is injected as a web-accessible `<script src>` by
// `passkey-relay.ts`, module docs there): it has the exact same "one self-contained file, no
// module graph to resolve" requirement, since the page that loads it offers no module resolution
// for an extension's internal imports either.
import { fileURLToPath } from "node:url";

import { defineConfig } from "vite";

const ENTRIES: Readonly<Record<string, { readonly input: string; readonly output: string }>> = {
  "content-script": { input: "./src/content/content-script.ts", output: "src/content/content-script.js" },
  "passkey-relay": { input: "./src/content/passkey-relay.ts", output: "src/content/passkey-relay.js" },
  "passkey-page-shim": { input: "./src/content/passkey-page-shim.ts", output: "src/content/passkey-page-shim.js" },
};

export default defineConfig(({ mode }) => {
  const target = mode === "firefox" ? "firefox" : "chromium";
  const entryName = process.env["RIZZY_CONTENT_ENTRY"] ?? "content-script";
  const entry = ENTRIES[entryName];
  if (entry === undefined) {
    throw new Error(`vite.content.config.ts: unknown RIZZY_CONTENT_ENTRY "${entryName}"`);
  }
  return {
    build: {
      outDir: fileURLToPath(new URL(`./dist/${target}`, import.meta.url)),
      emptyOutDir: false, // vite.config.ts's build already emptied and populated this directory.
      target: "es2022",
      sourcemap: false,
      rollupOptions: {
        input: fileURLToPath(new URL(entry.input, import.meta.url)),
        output: {
          format: "iife",
          inlineDynamicImports: true,
          entryFileNames: entry.output,
        },
      },
    },
  };
});
