// SPDX-License-Identifier: AGPL-3.0-only

// The getting-started guide after signup (ROADMAP §4.5, Should, M3: "Onboarding flow (import
// wizard, Emergency Kit download, extension install)"), apart from React so that its steps are
// tested without a DOM. `views/OnboardingView.tsx` renders it.
//
// It only composes what already exists (ADR 0014: the web vault's UI); it adds no endpoint, no
// wire field and no stored value:
// - **Emergency Kit.** The kit is shown once, at signup (ADR 0008 point 1, CRYPTO.md §7; the
//   core answers `already_shown` to a second request). The guide never shows it again; it only
//   asks the user to confirm that the copy they made is kept safe.
// - **Import.** The existing import of the "Export and import" pane (`TransferPane.tsx`
//   `ImportForm`), with its format recognition and its formats (`FORMAT_LABELS`).
// - **Browser extension.** Static instructions. Nothing is fetched: the guide makes no request
//   of its own.
//
// Nothing about the guide is remembered. The web vault keeps no value in browser storage but
// the opted-in Secret Key and the theme choice (CRYPTO.md §11.4), so "the guide was done" is not
// stored, locally or on the server: the guide opens right after signup, in memory, and Settings
// can open it again at any time.
import type { DetectedImportFormat } from "@rizzy-vault/core";

import { FORMAT_LABELS } from "./export-flow.ts";

/** The guide's steps, in order. */
export type OnboardingStepId = "kit" | "import" | "extension";

/** One step of the guide. */
export interface OnboardingStep {
  readonly id: OnboardingStepId;
  /** The step's short name, in the step list and in its heading. */
  readonly title: string;
}

/** The steps (module docs). */
export const ONBOARDING_STEPS: readonly OnboardingStep[] = [
  { id: "kit", title: "Keep your Emergency Kit safe" },
  { id: "import", title: "Import from another password manager" },
  { id: "extension", title: "Install the browser extension" },
];

/** How a step ended: confirmed or carried out ("done"), or passed over ("skipped"). */
export type StepOutcome = "done" | "skipped";

/** Where the guide is: the current step's index (`ONBOARDING_STEPS.length` once finished) and
 * how each step that was left ended. */
export interface OnboardingState {
  readonly index: number;
  readonly outcomes: Readonly<Partial<Record<OnboardingStepId, StepOutcome>>>;
}

/** The guide's first state. */
export const ONBOARDING_START: OnboardingState = { index: 0, outcomes: {} };

/** What the user did on the current step. */
export type OnboardingAction =
  /** "Continue": the step is done. On the kit step only with `kitSaved` (the box ticked). */
  | { readonly kind: "continue"; readonly kitSaved?: boolean }
  /** "Skip this step". */
  | { readonly kind: "skip" }
  /** "Back" to the previous step; the outcome recorded for it stays until it is left again. */
  | { readonly kind: "back" };

/** Whether the guide has gone past its last step. */
export function isFinished(state: OnboardingState): boolean {
  return state.index >= ONBOARDING_STEPS.length;
}

/** The current step, or `undefined` once finished. */
export function currentStep(state: OnboardingState): OnboardingStep | undefined {
  return ONBOARDING_STEPS[state.index];
}

/**
 * The next state. "Continue" on the kit step needs the confirmation ticked; without it the
 * state is returned unchanged (the button is disabled then, so this only guards). "Back" on the
 * first step, and any action once finished, change nothing.
 */
export function advance(state: OnboardingState, action: OnboardingAction): OnboardingState {
  const step = currentStep(state);
  if (step === undefined) {
    return state;
  }
  switch (action.kind) {
    case "back":
      return state.index === 0 ? state : { ...state, index: state.index - 1 };
    case "skip":
      return { index: state.index + 1, outcomes: { ...state.outcomes, [step.id]: "skipped" } };
    case "continue":
      if (step.id === "kit" && action.kitSaved !== true) {
        return state;
      }
      return { index: state.index + 1, outcomes: { ...state.outcomes, [step.id]: "done" } };
  }
}

/** "Step 2 of 3", for the step heading. */
export function stepPosition(index: number): string {
  return `Step ${index + 1} of ${ONBOARDING_STEPS.length}`;
}

/** The status a step shows in the step list (read by screen readers too). */
export function stepStatus(state: OnboardingState, index: number): string {
  if (index === state.index) {
    return "current";
  }
  const step = ONBOARDING_STEPS[index];
  const outcome = step === undefined ? undefined : state.outcomes[step.id];
  return outcome === "done" ? "done" : outcome === "skipped" ? "skipped" : "not started";
}

/** The other password managers' formats the import reads, by name: the existing import's own
 * list (`FORMAT_LABELS`) without rizzy-vault's own exports, the CSV one of which it refuses. */
export function importSources(): readonly string[] {
  return (Object.entries(FORMAT_LABELS) as [Exclude<DetectedImportFormat, "unknown">, string][])
    .filter(([id]) => !id.startsWith("rizzy-"))
    .map(([, label]) => label);
}

/** What the extension's "Set up this device" form asks for, with the values that are not
 * secret filled in: this web vault's own origin (the server: it serves the vault, ADR 0010 §4)
 * and the login name. The Secret Key and the master password are named, never shown. */
export function extensionSetupValues(
  serverOrigin: string,
  loginName: string,
): readonly { readonly field: string; readonly value: string; readonly secret: boolean }[] {
  return [
    { field: "Server URL", value: serverOrigin, secret: false },
    { field: "Account (login name)", value: loginName, secret: false },
    { field: "Secret Key", value: "the Secret Key from your Emergency Kit", secret: true },
    { field: "Master password", value: "your master password", secret: true },
  ];
}
