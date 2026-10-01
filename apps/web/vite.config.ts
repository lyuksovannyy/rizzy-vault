// Vite build of the web vault (ADR 0014 §3). The output (`dist/`) is what `rizzy-server`
// embeds with its `embed-web` feature (ADR 0010 §4), so it is shaped for that:
// - fixed file names (`assets.ts`), checked after every build;
// - no inline script or style, nothing from another origin (the INV-49 CSP, `WEB_CSP` in
//   `crates/rizzy-server/src/http/security.rs`): assets are never inlined as `data:` URLs,
//   there is no module-preload polyfill, and the CSS is one file;
// - the wasm core runs in one dedicated module Worker (ADR 0013 §4), built as its own entry.
import { readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

import type { Plugin } from "vite";
import { defineConfig } from "vitest/config";

import { EMBEDDED_FILES } from "./assets.ts";

const outDir = fileURLToPath(new URL("./dist", import.meta.url));

/** Every file under `dir`, as paths relative to `outDir` with `/` separators. */
function listFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      out.push(...listFiles(path));
    } else {
      out.push(relative(outDir, path).split(sep).join("/"));
    }
  }
  return out;
}

/** Fails the build unless `dist/` holds exactly {@link EMBEDDED_FILES}. */
function exactOutput(): Plugin {
  return {
    name: "rizzy-exact-output",
    apply: "build",
    closeBundle() {
      const found = listFiles(outDir).sort();
      const expected = [...EMBEDDED_FILES].sort();
      if (found.join("\n") !== expected.join("\n")) {
        throw new Error(
          `dist/ must hold exactly the embedded files (apps/web/assets.ts).\n` +
            `expected: ${expected.join(", ")}\nfound:    ${found.join(", ")}`,
        );
      }
    },
  };
}

/** Fixed output names for one bundle (`[name]` is the entry or asset base name). */
const fixedNames = {
  entryFileNames: "assets/[name].js",
  chunkFileNames: "assets/[name].js",
  assetFileNames: "assets/[name][extname]",
};

export default defineConfig({
  base: "/",
  oxc: {
    jsx: { runtime: "automatic", importSource: "react" },
  },
  build: {
    outDir,
    emptyOutDir: true,
    target: "es2022",
    sourcemap: false,
    // Never inline an asset as a `data:` URL: the CSP allows `'self'` only.
    assetsInlineLimit: 0,
    cssCodeSplit: false,
    modulePreload: { polyfill: false },
    rolldownOptions: {
      input: { app: fileURLToPath(new URL("./index.html", import.meta.url)) },
      output: fixedNames,
    },
  },
  worker: {
    format: "es",
    rolldownOptions: {
      output: { ...fixedNames, entryFileNames: "assets/core-worker.js" },
    },
  },
  plugins: [exactOutput()],
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
  },
});
