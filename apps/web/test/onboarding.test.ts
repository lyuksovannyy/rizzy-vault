// SPDX-License-Identifier: AGPL-3.0-only

// The getting-started guide (`src/onboarding.ts`, `src/views/OnboardingView.tsx`): its steps
// and their skip/continue/back moves, the formats its import step names, the values its
// extension step fills in, and the markup screen readers and the keyboard rely on (rendered to
// static HTML, as no DOM runs here).
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { FORMAT_LABELS } from "../src/export-flow.ts";
import {
  ONBOARDING_START,
  ONBOARDING_STEPS,
  advance,
  currentStep,
  extensionSetupValues,
  importSources,
  isFinished,
  stepPosition,
  stepStatus,
} from "../src/onboarding.ts";
import type { CoreClient } from "../src/core-client.ts";
import { ExtensionStep, KitStep, OnboardingView } from "../src/views/OnboardingView.tsx";
import type { VaultContext } from "../src/views/VaultView.tsx";

describe("onboarding steps", () => {
  it("are the kit, the import and the extension, in that order", () => {
    expect(ONBOARDING_STEPS.map((s) => s.id)).toEqual(["kit", "import", "extension"]);
    expect(currentStep(ONBOARDING_START)?.id).toBe("kit");
    expect(stepPosition(1)).toBe("Step 2 of 3");
  });

  it("can each be skipped, to the end", () => {
    let s = ONBOARDING_START;
    for (const step of ONBOARDING_STEPS) {
      expect(currentStep(s)?.id).toBe(step.id);
      s = advance(s, { kind: "skip" });
    }
    expect(isFinished(s)).toBe(true);
    expect(currentStep(s)).toBeUndefined();
    expect(s.outcomes).toEqual({ kit: "skipped", import: "skipped", extension: "skipped" });
    // Nothing moves once finished.
    expect(advance(s, { kind: "back" })).toBe(s);
    expect(advance(s, { kind: "skip" })).toBe(s);
  });

  it("continue past the kit only once its confirmation is ticked", () => {
    expect(advance(ONBOARDING_START, { kind: "continue" })).toBe(ONBOARDING_START);
    expect(advance(ONBOARDING_START, { kind: "continue", kitSaved: false })).toBe(ONBOARDING_START);
    const s = advance(ONBOARDING_START, { kind: "continue", kitSaved: true });
    expect(currentStep(s)?.id).toBe("import");
    expect(s.outcomes).toEqual({ kit: "done" });
    // The other steps need no confirmation.
    expect(currentStep(advance(s, { kind: "continue" }))?.id).toBe("extension");
  });

  it("go back without forgetting how a step ended, and not before the first", () => {
    expect(advance(ONBOARDING_START, { kind: "back" })).toBe(ONBOARDING_START);
    const s = advance(advance(ONBOARDING_START, { kind: "skip" }), { kind: "continue" });
    const back = advance(s, { kind: "back" });
    expect(currentStep(back)?.id).toBe("import");
    expect(back.outcomes).toEqual({ kit: "skipped", import: "done" });
  });

  it("say how each ended in the step list", () => {
    const s = advance(ONBOARDING_START, { kind: "skip" });
    expect([0, 1, 2].map((i) => stepStatus(s, i))).toEqual(["skipped", "current", "not started"]);
    const done = advance(advance(s, { kind: "continue" }), { kind: "continue" });
    expect([0, 1, 2].map((i) => stepStatus(done, i))).toEqual(["skipped", "done", "done"]);
  });
});

describe("the import step's formats", () => {
  it("are the existing import's, other password managers only", () => {
    const sources = importSources();
    expect(sources).toContain(FORMAT_LABELS["bitwarden-json"]);
    expect(sources).toContain(FORMAT_LABELS["1pux"]);
    expect(sources).toContain(FORMAT_LABELS["keepass-xml"]);
    expect(sources).toContain(FORMAT_LABELS["chrome-csv"]);
    // Another manager's CXF passkey file (ADR 0074 §3) is one; our own CXF export is not.
    expect(sources).toContain(FORMAT_LABELS["cxf-json"]);
    expect(sources.some((s) => s.startsWith("rizzy-vault"))).toBe(false);
    expect(sources).toHaveLength(Object.keys(FORMAT_LABELS).length - 4);
  });
});

describe("the extension step", () => {
  it("fills in the server and login name, and only names the secrets", () => {
    const values = extensionSetupValues("https://vault.example.com", "alice");
    expect(values.map((v) => v.field)).toEqual([
      "Server URL",
      "Account (login name)",
      "Secret Key",
      "Master password",
    ]);
    expect(values[0]?.value).toBe("https://vault.example.com");
    expect(values[1]?.value).toBe("alice");
    expect(values.filter((v) => v.secret).map((v) => v.field)).toEqual(["Secret Key", "Master password"]);
  });

  it("renders static instructions with no link to follow", () => {
    const html = renderToStaticMarkup(
      createElement(ExtensionStep, { serverOrigin: "https://vault.example.com", loginName: "alice" }),
    );
    expect(html).toContain("chrome://extensions");
    expect(html).toContain("about:debugging#/runtime/this-firefox");
    expect(html).toContain("https://vault.example.com");
    expect(html).toContain("alice");
    expect(html).not.toContain("<a ");
    expect(html).not.toContain("<img");
  });
});

/** A context the first step never calls into. */
function fakeContext(): VaultContext {
  const client = {
    call: () => Promise.reject(new Error("not called")),
  } as unknown as CoreClient;
  return {
    client,
    clipboard: undefined as unknown as VaultContext["clipboard"],
    session: { locked: false, accountId: "a", deviceId: "d", readOnly: false, unsentChanges: 0 },
    afterWrite: () => Promise.resolve(),
    revision: 0,
    generator: undefined as unknown as VaultContext["generator"],
  };
}

describe("the guide's markup", () => {
  const html = renderToStaticMarkup(
    createElement(OnboardingView, { ctx: fakeContext(), loginName: "alice", onClose: () => undefined }),
  );

  it("is a labelled region with the current step marked", () => {
    expect(html).toMatch(/role="region" aria-labelledby="onboarding-title"/);
    expect(html).toContain('id="onboarding-title"');
    expect(html).toMatch(/<li aria-current="step">Keep your Emergency Kit safe/);
    expect(html.match(/aria-current=/g)).toHaveLength(1);
    expect(html).toContain("Step 1 of 3: Keep your Emergency Kit safe");
  });

  it("moves the focus to a heading that can take it", () => {
    expect(html).toMatch(/<h2 id="onboarding-step-title" tabindex="-1">/);
  });

  it("offers skip and close on the first step, and holds Continue until the kit is confirmed", () => {
    expect(html).toContain(">Skip this step</button>");
    expect(html).toContain(">Close the guide</button>");
    expect(html).toMatch(/<button type="button" disabled="">Continue<\/button>/);
    expect(html).not.toContain(">Back</button>");
  });

  it("never shows the kit's secrets again", () => {
    expect(html).not.toContain("kit-secret-key");
    expect(html).not.toContain("kit-recovery-code");
    expect(html).not.toContain("emergency-kit");
    expect(html).not.toMatch(/RV1-|RVR1-/);
  });

  it("labels the kit confirmation and its hint", () => {
    const kit = renderToStaticMarkup(createElement(KitStep, { saved: false, onSaved: () => undefined }));
    expect(kit).toMatch(/<label class="check"><input type="checkbox" aria-describedby="onboarding-kit-hint"\/>I saved my Emergency Kit/);
    expect(kit).toContain('id="onboarding-kit-hint"');
  });
});
