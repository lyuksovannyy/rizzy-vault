// SPDX-License-Identifier: AGPL-3.0-only

// The getting-started guide (`onboarding.ts` module docs): three steps, each of which can be
// skipped, then a summary. It opens right after signup and from Settings; nothing about it is
// stored.
//
// Keyboard and screen readers (ROADMAP §4.5 accessibility Must): every control is a native
// button, checkbox or form field in reading order; the guide is a labelled region; the step
// list marks the current step with `aria-current="step"` and says how each other step ended;
// and each new step moves the focus to its heading, so a screen reader announces the step
// that just opened instead of staying on a button that is gone.
import { useEffect, useRef, useState } from "react";

import { KIT_LOSS_WARNING, KIT_TAKEOVER_WARNING } from "../kit.ts";
import {
  ONBOARDING_START,
  ONBOARDING_STEPS,
  advance,
  currentStep,
  extensionSetupValues,
  importSources,
  stepPosition,
  stepStatus,
} from "../onboarding.ts";
import { ImportForm } from "./TransferPane.tsx";
import type { VaultContext } from "./VaultView.tsx";

/** The Emergency Kit step: a confirmation only; the kit is never shown again (ADR 0008). */
export function KitStep(props: { readonly saved: boolean; readonly onSaved: (saved: boolean) => void }) {
  return (
    <>
      <p>
        Your Emergency Kit was shown once, when you created the account. It cannot be shown again,
        here or by the server operator.
      </p>
      <p>
        It holds your Secret Key. This web vault asks for the Secret Key at every login, and every
        new browser or device needs it too.
      </p>
      <ul>
        <li>Keep the downloaded or printed kit somewhere safe and offline, away from this computer.</li>
        <li>Do not keep it only inside this vault: you need it to open the vault.</li>
      </ul>
      <p className="warning">
        <strong>{KIT_TAKEOVER_WARNING}</strong> {KIT_LOSS_WARNING}
      </p>
      <label className="check">
        <input
          type="checkbox"
          checked={props.saved}
          onChange={(e) => props.onSaved(e.currentTarget.checked)}
          aria-describedby="onboarding-kit-hint"
        />
        I saved my Emergency Kit and keep it somewhere safe
      </label>
      <p className="hint" id="onboarding-kit-hint">
        Tick this to continue, or skip the step. If you did not keep a copy, this account cannot be
        opened again once this session ends.
      </p>
    </>
  );
}

/** The import step: the existing import form, with the formats it reads. */
function ImportStep(props: { readonly ctx: VaultContext }) {
  return (
    <>
      <p>
        Bring your passwords from the password manager you used before. Export them there first,
        then choose the file here: its format is recognised. The file is read in this browser; only
        the encrypted items reach the server.
      </p>
      <p id="onboarding-import-sources">Files this import reads:</p>
      <ul aria-labelledby="onboarding-import-sources">
        {importSources().map((s) => (
          <li key={s}>{s}</li>
        ))}
      </ul>
      <ImportForm ctx={props.ctx} headingLevel={3} />
    </>
  );
}

/** The extension step: static instructions; nothing is fetched. `serverOrigin` is this web
 * vault's own origin. */
export function ExtensionStep(props: { readonly serverOrigin: string; readonly loginName: string }) {
  return (
    <>
      <p>
        The browser extension fills your logins on websites and offers to save new ones. Install it
        in each browser you use.
      </p>
      <p>
        It is not in the browser stores yet. Ask whoever runs your server for a build, or build it
        from the rizzy-vault source (<code>apps/extension</code>), then load it:
      </p>
      <h3>Chrome, Edge, Brave and other Chromium browsers</h3>
      <ol>
        <li>
          Open <code>chrome://extensions</code> and turn on Developer mode.
        </li>
        <li>
          Choose Load unpacked and pick the <code>chromium</code> folder of the build.
        </li>
      </ol>
      <h3>Firefox</h3>
      <ol>
        <li>
          Open <code>about:debugging#/runtime/this-firefox</code>.
        </li>
        <li>
          Choose Load Temporary Add-on and pick <code>manifest.json</code> in the{" "}
          <code>firefox</code> folder of the build. Firefox removes it again when it restarts, and
          this build is less tested than the Chromium one.
        </li>
      </ol>
      <h3>Then set it up</h3>
      <p>
        Open the extension from the browser toolbar. Its "Set up this device" form asks for:
      </p>
      <dl className="kit onboarding-fields">
        {extensionSetupValues(props.serverOrigin, props.loginName).map((v) => (
          <div key={v.field} className="onboarding-field">
            <dt>{v.field}</dt>
            <dd className={v.secret ? undefined : "mono"}>{v.value}</dd>
          </div>
        ))}
      </dl>
    </>
  );
}

/** The guide (module docs). `onClose` leaves it, at any step. */
export function OnboardingView(props: {
  readonly ctx: VaultContext;
  readonly loginName: string;
  readonly onClose: () => void;
}) {
  const [state, setState] = useState(ONBOARDING_START);
  const [kitSaved, setKitSaved] = useState(false);
  const heading = useRef<HTMLHeadingElement>(null);
  const step = currentStep(state);

  // A new step (or the summary) takes the focus to its heading (module docs).
  useEffect(() => {
    heading.current?.focus();
  }, [state.index]);

  const last = state.index === ONBOARDING_STEPS.length - 1;

  return (
    <div className="panel narrow onboarding" role="region" aria-labelledby="onboarding-title">
      <h1 id="onboarding-title">Get started</h1>
      <p className="muted">
        Three short steps. Skip any of them; Settings can open this guide again.
      </p>
      <ol className="onboarding-steps" aria-label="Steps">
        {ONBOARDING_STEPS.map((s, i) => (
          <li key={s.id} aria-current={i === state.index ? "step" : undefined}>
            {s.title} <span className="muted">({stepStatus(state, i)})</span>
          </li>
        ))}
      </ol>
      {step === undefined ? (
        <section aria-labelledby="onboarding-step-title">
          <h2 id="onboarding-step-title" ref={heading} tabIndex={-1}>
            You are set up
          </h2>
          <ul aria-label="How each step ended">
            {ONBOARDING_STEPS.map((s, i) => (
              <li key={s.id}>
                {s.title}: {stepStatus(state, i)}
              </li>
            ))}
          </ul>
          <div className="actions">
            <button type="button" onClick={props.onClose}>
              Go to your vault
            </button>
          </div>
        </section>
      ) : (
        <section aria-labelledby="onboarding-step-title">
          <h2 id="onboarding-step-title" ref={heading} tabIndex={-1}>
            {stepPosition(state.index)}: {step.title}
          </h2>
          {step.id === "kit" && <KitStep saved={kitSaved} onSaved={setKitSaved} />}
          {step.id === "import" && <ImportStep ctx={props.ctx} />}
          {step.id === "extension" && <ExtensionStep serverOrigin={window.location.origin} loginName={props.loginName} />}
          <div className="actions">
            <button
              type="button"
              disabled={step.id === "kit" && !kitSaved}
              onClick={() => setState((s) => advance(s, { kind: "continue", kitSaved }))}
            >
              {last ? "Finish" : "Continue"}
            </button>
            <button type="button" className="secondary" onClick={() => setState((s) => advance(s, { kind: "skip" }))}>
              Skip this step
            </button>
            {state.index > 0 && (
              <button type="button" className="secondary" onClick={() => setState((s) => advance(s, { kind: "back" }))}>
                Back
              </button>
            )}
            <button type="button" className="secondary" onClick={props.onClose}>
              Close the guide
            </button>
          </div>
        </section>
      )}
    </div>
  );
}
