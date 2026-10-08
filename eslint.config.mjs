// ESLint for the web-platform UI code (ADR 0014 §2: "ESLint enforces these in CI from M1").
// Run from the repository root: `pnpm run lint`. `apps/web/test/lint-rules.test.ts` checks that
// each rule below fires on a sample of what it bans.
//
// What each block enforces:
// - no raw-HTML sinks (`react/no-danger`'s target and the DOM sinks of §2, by
//   `no-restricted-syntax` / `no-restricted-properties`, so no React plugin is needed);
// - no `eval`, `new Function` or string timers;
// - one `SafeLink` / `openUrl` helper (INV-42): dynamic `href` values, `window.open`,
//   `location.assign` / `replace` and assignments to `location` only in the allowed files;
// - no runtime CSS-in-JS (an import ban) and no `style` prop: styles are static CSS files;
// - `type="password"` only inside the one secret-field component (INV-68);
// - the generated wasm-bindgen output only through packages/core (ADR 0013 §4), and on the UI
//   thread of the web vault only type imports of packages/core: the wasm instance lives in the
//   core Worker alone.
import tseslint from "typescript-eslint";

/** Raw-HTML sinks (ADR 0014 §2, a minimum). */
const HTML_SINK_PROPERTIES = [
  "innerHTML",
  "outerHTML",
  "insertAdjacentHTML",
  "createContextualFragment",
  "setHTMLUnsafe",
  "parseHTMLUnsafe",
  "parseFromString",
  "srcdoc",
].map((property) => ({ property, message: "Raw-HTML sink: banned by ADR 0014 §2." }));

/** Navigation away from the vault with a computed URL (INV-42). */
const NAVIGATION_PROPERTIES = [
  { object: "window", property: "open", message: "Open item URLs only through SafeLink (INV-42)." },
  { object: "location", property: "assign", message: "Open item URLs only through SafeLink (INV-42)." },
  { object: "location", property: "replace", message: "Open item URLs only through SafeLink (INV-42)." },
  { object: "document", property: "write", message: "Raw-HTML sink: banned by ADR 0014 §2." },
  { object: "document", property: "writeln", message: "Raw-HTML sink: banned by ADR 0014 §2." },
];

/** Syntax bans that hold everywhere. */
const SYNTAX = [
  {
    selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
    message: "Raw-HTML sink (react/no-danger): banned by ADR 0014 §2.",
  },
  {
    selector: "JSXAttribute[name.name='srcDoc']",
    message: "srcdoc only in the sandboxed-frame helper (ADR 0014 §2, INV-35).",
  },
  {
    selector: "JSXAttribute[name.name='style']",
    message: "Styles are static CSS files (ADR 0014 §2; the CSP refuses inline styles).",
  },
  {
    selector: "AssignmentExpression[left.type='Identifier'][left.name='location']",
    message: "Open item URLs only through SafeLink (INV-42).",
  },
  {
    selector: "AssignmentExpression > MemberExpression.left[property.name='location']",
    message: "Open item URLs only through SafeLink (INV-42).",
  },
  {
    selector: "AssignmentExpression > MemberExpression.left[object.name='location'][property.name='href']",
    message: "Open item URLs only through SafeLink (INV-42).",
  },
];

/** Bans that hold everywhere except the helper that implements them. */
const DYNAMIC_HREF = {
  selector: "JSXAttribute[name.name='href'] > JSXExpressionContainer",
  message: "Dynamic href only in SafeLink.tsx (INV-42).",
};
const HREF_ASSIGNMENT = {
  selector: "AssignmentExpression > MemberExpression.left[property.name='href']",
  message: "href is set only in SafeLink.tsx and download.ts (INV-42).",
};
const PASSWORD_INPUT = {
  selector: "JSXAttribute[name.name='type'][value.value='password']",
  message: "Secret inputs only through SecretField of packages/ui (INV-68).",
};

/** Imports banned everywhere: deep imports of the core, runtime CSS-in-JS. */
const IMPORT_PATTERNS = [
  {
    group: ["@rizzy-vault/core/*", "**/generated/*"],
    message: "Reach the wasm core only through @rizzy-vault/core (ADR 0013 §4).",
  },
  {
    group: [
      "styled-components",
      "@emotion/*",
      "@stitches/*",
      "goober",
      "styled-jsx",
      "jss",
      "react-jss",
      "@compiled/*",
    ],
    message: "No runtime CSS-in-JS (ADR 0014 §2).",
  },
];

export default tseslint.config(
  {
    ignores: [
      "**/node_modules/**",
      "**/dist/**",
      "**/generated/**",
      "target/**",
      "crates/**",
      "fuzz/**",
      "spikes/**",
      "**/test-results/**",
      "**/playwright-report/**",
    ],
  },
  {
    files: ["**/*.{ts,tsx,mjs,js}"],
    extends: [tseslint.configs.recommended],
    languageOptions: {
      parserOptions: { ecmaFeatures: { jsx: true } },
      // The globals `no-implied-eval` watches (string timers); TypeScript checks the rest.
      globals: {
        window: "readonly",
        self: "readonly",
        globalThis: "readonly",
        setTimeout: "readonly",
        setInterval: "readonly",
        execScript: "readonly",
      },
    },
    rules: {
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-script-url": "error",
      "no-restricted-properties": ["error", ...HTML_SINK_PROPERTIES, ...NAVIGATION_PROPERTIES],
      "no-restricted-syntax": ["error", ...SYNTAX, DYNAMIC_HREF, HREF_ASSIGNMENT, PASSWORD_INPUT],
      "@typescript-eslint/no-restricted-imports": ["error", { patterns: IMPORT_PATTERNS }],
    },
  },
  {
    // packages/core is the one module that imports the generated bindings.
    files: ["packages/core/**"],
    rules: { "@typescript-eslint/no-restricted-imports": "off" },
  },
  {
    // The one link helper (INV-42).
    files: ["apps/web/src/SafeLink.tsx"],
    rules: {
      "no-restricted-syntax": ["error", ...SYNTAX, HREF_ASSIGNMENT, PASSWORD_INPUT],
    },
  },
  {
    // The download helper sets a blob: URL on a detached anchor.
    files: ["apps/web/src/download.ts"],
    rules: {
      "no-restricted-syntax": ["error", ...SYNTAX, DYNAMIC_HREF, PASSWORD_INPUT],
    },
  },
  {
    // The one secret-field component (INV-68).
    files: ["packages/ui/src/SecretField.tsx"],
    rules: {
      "no-restricted-syntax": ["error", ...SYNTAX, DYNAMIC_HREF, HREF_ASSIGNMENT],
    },
  },
  {
    // The web vault's UI thread: types only from packages/core (ADR 0013 §4).
    files: ["apps/web/src/**"],
    ignores: ["apps/web/src/core-worker.ts"],
    rules: {
      "@typescript-eslint/no-restricted-imports": [
        "error",
        {
          patterns: IMPORT_PATTERNS,
          paths: [
            {
              name: "@rizzy-vault/core",
              allowTypeImports: true,
              message: "The UI thread loads no wasm: only type imports of @rizzy-vault/core (ADR 0013 §4).",
            },
          ],
        },
      ],
    },
  },
  {
    // The extension's UI, content script and background/service-worker surfaces: types only
    // from @rizzy-vault/core (ADR 0036 §4, "no primitive crypto call is ever exposed across a
    // message boundary"; the content script additionally never imports it at all, ADR 0014
    // §2). `core-host/` is the one long-lived context allowed a value import (ADR 0036 §2).
    files: ["apps/extension/src/**"],
    ignores: ["apps/extension/src/core-host/**"],
    rules: {
      "@typescript-eslint/no-restricted-imports": [
        "error",
        {
          patterns: IMPORT_PATTERNS,
          paths: [
            {
              name: "@rizzy-vault/core",
              allowTypeImports: true,
              message: "Only the long-lived context (core-host/) loads the wasm core (ADR 0036 §4).",
            },
          ],
        },
      ],
    },
  },
  {
    // Tests and build configuration run in Node, not in the vault page.
    files: ["**/test/**", "**/e2e/**", "**/*.config.{ts,mjs}"],
    rules: {
      "no-restricted-syntax": ["error", ...SYNTAX.filter((s) => !s.selector.includes("style"))],
      // The URL tests hold `javascript:` samples as strings.
      "no-script-url": "off",
    },
  },
);
