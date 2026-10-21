// SPDX-License-Identifier: AGPL-3.0-only

// A deliberately small, test-only reader for the login-step HTML fixtures
// (`test/fixtures/login-steps/*.html`): turns one fixture into exactly the `InputFacts` and form
// hints `content-script.ts`'s `collectLoginFacts` gathers from a real document, so
// `login-step.ts`'s heuristic can be unit tested in Node (this package's Vitest runs in the
// `node` environment and adds no DOM library: CLAUDE.md "Dependencies"). It understands only the
// subset of HTML the fixtures use, all of it written for this purpose and well-formed:
//
// - `<form>` nesting, `<input>`, `<label for>` and wrapping `<label>`, `<button>` (scripts are
//   dropped: a fixture is read as first loaded);
// - visibility the way the content script's gate decides it, statically: `type="hidden"`, the
//   `hidden` attribute, inline `display:none`, `visibility:hidden`, `opacity:0`, a zero
//   `width`/`height`, or a negative `left`/`top` (off-screen) on the input or any ancestor;
//   `data-fixture-covered` stands in for "another element is painted on top" (the topmost
//   check), which needs real layout and is covered for real by the Playwright suite;
// - `<iframe>` contents are never read (the attribute `srcdoc` is just an attribute here, and
//   a `src` document is never fetched): the content script runs in the top frame only and never
//   sees a cross-origin frame's fields, which is the point of the iframe fixtures.
//
// The same fixture files are served to real Chromium by `e2e/multistep.spec.ts`, so the
// static reading here is checked against the browser's own.
import { NO_FORM, type InputFacts } from "../../src/content/login-step.ts";

const VOID = new Set(["input", "br", "img", "meta", "link", "hr", "source"]);

interface Open {
  readonly tag: string;
  readonly hidden: boolean;
  readonly form: number;
  readonly isLabel: boolean;
  readonly isButton: boolean;
  readonly submitButton: boolean;
}

function parseAttrs(raw: string): Map<string, string> {
  const attrs = new Map<string, string>();
  const re = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g;
  for (const m of raw.matchAll(re)) {
    const name = (m[1] ?? "").toLowerCase();
    attrs.set(name, m[2] ?? m[3] ?? m[4] ?? "");
  }
  return attrs;
}

function styleHides(style: string): boolean {
  const s = style.replace(/\s+/g, "").toLowerCase();
  return (
    s.includes("display:none") ||
    s.includes("visibility:hidden") ||
    /(^|;)opacity:0(\.0*)?(;|$)/.test(s) ||
    /(^|;)(width|height):0(px)?(;|$)/.test(s) ||
    /(^|;)(left|top):-\d{3,}px/.test(s)
  );
}

function hides(attrs: Map<string, string>): boolean {
  return attrs.has("hidden") || attrs.has("data-fixture-covered") || styleHides(attrs.get("style") ?? "");
}

export interface FixtureFacts {
  readonly inputs: readonly InputFacts[];
  /** The fixture's own `id` attribute of each input, parallel to `inputs` (for assertions). */
  readonly ids: readonly string[];
  readonly formHint: (form: number) => string;
}

export function factsFromHtml(html: string): FixtureFacts {
  // Strip comments, scripts and iframe bodies first: none is ever part of the top frame's own
  // inputs as the page is first loaded (a script's later DOM changes are the e2e suite's job).
  const source = html
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "")
    .replace(/<iframe\b[^>]*>[\s\S]*?<\/iframe>/gi, "");
  const stack: Open[] = [];
  const pending: { attrs: Map<string, string>; form: number; hidden: boolean; wrapLabel: number | undefined }[] = [];
  const labelTextFor = new Map<string, string>();
  const wrapLabelText: string[] = [];
  const formHints: string[] = [];
  const noFormHints: string[] = [];
  let formCount = 0;
  // Labels and buttons currently open, innermost last; their text accumulates until they close.
  const labelBuffers: { text: string; forId: string | undefined; wrapIndex: number }[] = [];
  const buttonBuffers: { text: string; form: number }[] = [];

  const re = /<\/?([a-zA-Z][a-zA-Z0-9-]*)([^>]*)>|([^<]+)/g;
  for (const m of source.matchAll(re)) {
    const text = m[3];
    if (text !== undefined) {
      for (const l of labelBuffers) {
        l.text += text;
      }
      for (const b of buttonBuffers) {
        b.text += text;
      }
      continue;
    }
    const whole = m[0];
    const tag = (m[1] ?? "").toLowerCase();
    const attrs = parseAttrs(m[2] ?? "");
    const parent = stack[stack.length - 1];
    const inheritedHidden = parent?.hidden ?? false;
    const inheritedForm = parent?.form ?? NO_FORM;
    if (whole.startsWith("</")) {
      // Pop to the matching open tag.
      for (let i = stack.length - 1; i >= 0; i -= 1) {
        if (stack[i]?.tag === tag) {
          const closed = stack.splice(i);
          for (const c of closed) {
            if (c.isLabel) {
              const buf = labelBuffers.pop();
              if (buf !== undefined) {
                if (buf.forId !== undefined) {
                  labelTextFor.set(buf.forId, (labelTextFor.get(buf.forId) ?? "") + " " + buf.text);
                }
                wrapLabelText[buf.wrapIndex] = buf.text;
              }
            }
            if (c.isButton) {
              const buf = buttonBuffers.pop();
              if (buf !== undefined && c.submitButton) {
                if (buf.form === NO_FORM) {
                  noFormHints.push(buf.text);
                } else {
                  formHints[buf.form] = `${formHints[buf.form] ?? ""} ${buf.text}`;
                }
              }
            }
          }
          break;
        }
      }
      continue;
    }
    const hidden = inheritedHidden || hides(attrs);
    if (tag === "form") {
      const index = formCount;
      formCount += 1;
      formHints[index] = ["id", "name", "action", "aria-label"].map((a) => attrs.get(a) ?? "").join(" ");
      stack.push({ tag, hidden, form: index, isLabel: false, isButton: false, submitButton: false });
      continue;
    }
    if (tag === "input") {
      const type = (attrs.get("type") ?? "text").toLowerCase();
      if (type === "submit") {
        const value = attrs.get("value") ?? "";
        if (inheritedForm === NO_FORM) {
          noFormHints.push(value);
        } else {
          formHints[inheritedForm] = `${formHints[inheritedForm] ?? ""} ${value}`;
        }
      }
      const enclosingLabel = [...stack].reverse().find((o) => o.isLabel);
      pending.push({
        attrs,
        form: inheritedForm,
        hidden: hidden || type === "hidden",
        wrapLabel: enclosingLabel === undefined ? undefined : labelBuffers[labelBuffers.length - 1]?.wrapIndex,
      });
      continue;
    }
    if (VOID.has(tag)) {
      continue;
    }
    const isLabel = tag === "label";
    const isButton = tag === "button";
    const buttonType = (attrs.get("type") ?? "submit").toLowerCase();
    if (isLabel) {
      labelBuffers.push({ text: "", forId: attrs.get("for"), wrapIndex: wrapLabelText.length });
      wrapLabelText.push("");
    }
    if (isButton) {
      buttonBuffers.push({ text: "", form: inheritedForm });
    }
    stack.push({
      tag,
      hidden,
      form: inheritedForm,
      isLabel,
      isButton,
      submitButton: isButton && buttonType === "submit",
    });
  }

  const inputs: InputFacts[] = [];
  const ids: string[] = [];
  for (const p of pending) {
    const a = p.attrs;
    const id = a.get("id") ?? "";
    const typeRaw = (a.get("type") ?? "text").toLowerCase();
    const known = ["text", "email", "tel", "password", "search", "hidden", "checkbox", "radio", "submit", "button", "number", "url"];
    const type = known.includes(typeRaw) ? typeRaw : "text";
    const labelText = `${id === "" ? "" : (labelTextFor.get(id) ?? "")} ${p.wrapLabel === undefined ? "" : (wrapLabelText[p.wrapLabel] ?? "")}`;
    const hints = [a.get("name") ?? "", id, a.get("placeholder") ?? "", a.get("aria-label") ?? "", labelText]
      .join(" ")
      .toLowerCase();
    inputs.push({
      type,
      autocomplete: (a.get("autocomplete") ?? "").toLowerCase(),
      hints,
      visible: !p.hidden,
      editable: !a.has("readonly") && !a.has("disabled"),
      form: p.form,
    });
    ids.push(id);
  }
  const formHint = (form: number): string =>
    (form === NO_FORM ? noFormHints.join(" ") : (formHints[form] ?? "")).toLowerCase();
  return { inputs, ids, formHint };
}
