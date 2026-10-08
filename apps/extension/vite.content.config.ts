// The content script's own build (ADR 0036 §4, §6; ADR 0014 §2): one self-contained file, no
// chunk splitting, because `content_scripts` loads exactly the files its manifest entry lists
// — it does not resolve a module graph the way an extension page's `<script type="module">`
// does. `inlineDynamicImports` plus a single Rollup input is what forces that; running this as
// a second, separate `vite build` (not a second entry in `vite.config.ts`) is what keeps Rollup
// from sharing a chunk between this file and the popup/background bundle, which would otherwise
// produce a `content/content-script.js` that `import`s a sibling chunk no manifest lists.
import { fileURLToPath } from "node:url";

import { defineConfig } from "vite";

export default defineConfig(({ mode }) => {
  const target = mode === "firefox" ? "firefox" : "chromium";
  return {
    build: {
      outDir: fileURLToPath(new URL(`./dist/${target}`, import.meta.url)),
      emptyOutDir: false, // vite.config.ts's build already emptied and populated this directory.
      target: "es2022",
      sourcemap: false,
      rollupOptions: {
        input: fileURLToPath(new URL("./src/content/content-script.ts", import.meta.url)),
        output: {
          format: "iife",
          inlineDynamicImports: true,
          entryFileNames: "src/content/content-script.js",
        },
      },
    },
  };
});
