// The ESLint rules of ADR 0014 §2 (`eslint.config.mjs` at the repository root) fire on what
// they ban, and leave the allowed files alone. Each sample is linted as if it were a file of
// the web vault's UI thread.
import { fileURLToPath } from "node:url";

import { ESLint } from "eslint";
import { describe, expect, it } from "vitest";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const eslint = new ESLint({ cwd: root });

/** The rule ids reported for `code` as the file `path` (relative to the repository root). */
async function rulesFor(code: string, path = "apps/web/src/sample.tsx"): Promise<string[]> {
  const [result] = await eslint.lintText(code, { filePath: `${root}${path}` });
  return (result?.messages ?? []).map((m) => m.ruleId ?? "fatal");
}

describe("ADR 0014 §2 lint rules", () => {
  it("ban raw-HTML sinks", async () => {
    for (const code of [
      "export const A = () => <div dangerouslySetInnerHTML={{ __html: x }} />;",
      "el.innerHTML = s;",
      "el.outerHTML = s;",
      "el.insertAdjacentHTML('beforeend', s);",
      "document.write(s);",
      "range.createContextualFragment(s);",
      "el.setHTMLUnsafe(s);",
      "new DOMParser().parseFromString(s, 'text/html');",
      "frame.srcdoc = s;",
      "export const F = () => <iframe srcDoc={s} />;",
    ]) {
      const rules = await rulesFor(`declare const el: any, s: string, x: any, range: any, frame: any;\n${code}`);
      expect(rules, code).toEqual(
        expect.arrayContaining([expect.stringMatching(/no-restricted-(syntax|properties)/)]),
      );
    }
  });

  it("ban eval and its relatives", async () => {
    expect(await rulesFor("eval('1');")).toContain("no-eval");
    expect(await rulesFor("new Function('return 1');")).toContain("no-new-func");
    expect(await rulesFor("setTimeout('alert(1)', 1);")).toContain("no-implied-eval");
  });

  it("allow links only through SafeLink", async () => {
    const link = "declare const u: string;\nexport const L = () => <a href={u}>x</a>;";
    expect(await rulesFor(link)).toContain("no-restricted-syntax");
    expect(await rulesFor(link, "apps/web/src/SafeLink.tsx")).not.toContain("no-restricted-syntax");
    expect(await rulesFor("export const L = () => <a href=\"/\">x</a>;")).toEqual([]);
    expect(await rulesFor("declare const u: string;\nwindow.open(u);")).toContain("no-restricted-properties");
    expect(await rulesFor("declare const u: string;\nlocation.assign(u);")).toContain("no-restricted-properties");
    expect(await rulesFor("declare const u: string;\nlocation.href = u;")).toContain("no-restricted-syntax");
    expect(await rulesFor("declare const u: string;\nwindow.location = u as never;")).toContain("no-restricted-syntax");
    const anchor = "declare const a: HTMLAnchorElement, u: string;\na.href = u;";
    expect(await rulesFor(anchor)).toContain("no-restricted-syntax");
    expect(await rulesFor(anchor, "apps/web/src/download.ts")).not.toContain("no-restricted-syntax");
  });

  it("ban runtime CSS-in-JS and inline styles", async () => {
    expect(await rulesFor("import styled from 'styled-components';")).toContain(
      "@typescript-eslint/no-restricted-imports",
    );
    expect(await rulesFor("import { css } from '@emotion/react';")).toContain(
      "@typescript-eslint/no-restricted-imports",
    );
    expect(await rulesFor("export const S = () => <div style={{ color: 'red' }} />;")).toContain(
      "no-restricted-syntax",
    );
  });

  it("keep password inputs inside SecretField", async () => {
    const input = "export const P = () => <input type=\"password\" />;";
    expect(await rulesFor(input)).toContain("no-restricted-syntax");
    expect(await rulesFor(input, "packages/ui/src/SecretField.tsx")).not.toContain("no-restricted-syntax");
  });

  it("keep the wasm core in the Worker", async () => {
    const value = "import { init } from '@rizzy-vault/core';\nvoid init;";
    expect(await rulesFor(value)).toContain("@typescript-eslint/no-restricted-imports");
    expect(await rulesFor(value, "apps/web/src/core-worker.ts")).not.toContain(
      "@typescript-eslint/no-restricted-imports",
    );
    expect(await rulesFor("import type { ItemSummary } from '@rizzy-vault/core';\nexport type I = ItemSummary;")).toEqual([]);
    expect(await rulesFor("import x from '@rizzy-vault/core/generated/rizzy_core.js';\nvoid x;", "apps/web/src/core-worker.ts")).toContain(
      "@typescript-eslint/no-restricted-imports",
    );
  });
});
