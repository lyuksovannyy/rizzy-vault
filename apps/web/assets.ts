// The files of the built web vault, by path under `dist/` (ADR 0010 §4, THREAT_MODEL §7.7).
//
// The names are fixed, with no content hash, because `rizzy-server` embeds exactly these files
// with `include_bytes!` under its `embed-web` feature and serves each from memory at `/<path>`:
// no path is ever built from a request. `vite.config.ts` fails the build when the output holds
// any other file or lacks one of these, and `test/assets.test.ts` checks that the server's
// table (`crates/rizzy-server/src/http/web.rs`) names the same paths.
export const EMBEDDED_FILES = [
  "index.html",
  "assets/app.js",
  "assets/style.css",
  "assets/core-worker.js",
  "assets/rizzy_core_bg.wasm",
] as const;
