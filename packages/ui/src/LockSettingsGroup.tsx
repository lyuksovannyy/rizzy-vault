// SPDX-License-Identifier: AGPL-3.0-only

// The "Locking" settings group of ADR 0110 §1–§2 and its turn-off warning dialog, one component
// for the web vault's Settings view and the extension's options page (Implementation plan,
// step 4). The words are the host's (`packages/i18n`'s `lock.*` keys), passed in as
// `LockSettingsText`; the values and the storage are the host's too (`rizzy.lock_settings`,
// parsed and encoded by Rust through packages/core). This file only draws the controls and
// enforces the UI rules:
//
// - Four controls: the master switch, the idle select (fixed values, no free entry), the restart
//   switch (on and disabled everywhere today, with its line, §4.1) and the sleep switch with its
//   helper text.
// - **Master off** (§1 point 2): the three sub-options stay rendered, in the tab order and showing
//   their kept values, but are `aria-disabled="true"`, ignore activation, and are described by
//   "Turn on automatic locking to change these.". They are dimmed by colour (muted text that still
//   meets AA), not hidden.
// - **Master on → off** goes through the dialog; **off → on** applies at once (§1 points 3–4).
// - **The dialog** (§2): a modal `role="alertdialog"` labelled by its title and described by its
//   body. Confirm stays focusable but `aria-disabled` and ignores click, Enter and Space for
//   `confirmDelayMs` of the monotonic clock (`performance.now()`) from the moment the dialog opens,
//   its label counting "(5)" … "(1)". One visually hidden polite live region announces the wait
//   at the start and the end, not every second. Focus starts on Cancel, which works at once;
//   Escape is Cancel; Tab stays inside; on close focus returns to the master switch. Reopening
//   restarts the countdown, because the dialog mounts afresh. Anything but Confirm after the
//   delay (Cancel, Escape, the backdrop, the page closing, a lock unmounting the view) leaves
//   locking on: only Confirm calls `onChange` with `autoLock: false`.
//
// The switches are `<button role="switch">` rather than checkboxes, so that "activation ignored"
// is one check in the click handler (Space and Enter both click a button) and a controlled
// checkbox never flips under a `preventDefault`.
import { type KeyboardEvent, type Ref, useEffect, useId, useRef, useState } from "react";

import { trapTab } from "./focusTrap.ts";
import { COUNTDOWN_POLL_MS, countdown } from "./lockCountdown.ts";
import { setModalOpen } from "./modalRegistry.ts";

export { COUNTDOWN_POLL_MS, countdown } from "./lockCountdown.ts";

/** The settings the group shows and changes (`lockOnRestart` is always on, §4.1). */
export interface LockSettingsValue {
  readonly autoLock: boolean;
  readonly idleMinutes: number;
  readonly lockOnSleep: boolean;
}

/** The group's words, from the host's catalogue (`lock.settings.*`, `lock.disable.*`). */
export interface LockSettingsText {
  readonly title: string;
  readonly autoLock: string;
  /** The idle select's label; its options are the minutes ("5"). */
  readonly idle: string;
  readonly restart: string;
  /** §4.1's line: why the restart switch is on and disabled. */
  readonly restartHint: string;
  readonly sleep: string;
  readonly sleepHint: string;
  readonly offHint: string;
  readonly disableTitle: string;
  readonly disableBody: string;
  readonly disableConfirm: string;
  readonly disableConfirmCountdown: (seconds: number) => string;
  readonly disableCancel: string;
  readonly disableWait: string;
  readonly disableReady: string;
}

/** The props of {@link LockSettingsGroup}. */
export interface LockSettingsGroupProps {
  /** The current settings; `undefined` while they load (every control is then inert). */
  readonly value: LockSettingsValue | undefined;
  /** The idle values, in minutes, in display order (ADR 0110 §1). */
  readonly idleMinutes: readonly number[];
  /** `LOCK_DISABLE_CONFIRM_DELAY_MS` (§2 point 3). */
  readonly confirmDelayMs: number;
  readonly text: LockSettingsText;
  /** Applies and stores a change; called at once for every change but turning locking off,
   * which is called only from the dialog's Confirm after the delay. */
  readonly onChange: (next: LockSettingsValue) => void;
  /** The monotonic clock, in milliseconds; `performance.now()` by default. */
  readonly clock?: () => number;
}

const monotonic = (): number => performance.now();

/** Space-separated ids, the empty ones left out; `undefined` when none is left. */
function ids(...list: (string | false | undefined)[]): string | undefined {
  const kept = list.filter((x): x is string => typeof x === "string" && x.length > 0);
  return kept.length === 0 ? undefined : kept.join(" ");
}

/** One switch row: a visible label and a `role="switch"` button named by it. */
function Switch(props: {
  readonly labelId: string;
  readonly label: string;
  readonly checked: boolean;
  readonly disabled: boolean;
  readonly describedBy?: string | undefined;
  readonly onActivate: () => void;
  readonly buttonRef?: Ref<HTMLButtonElement>;
}) {
  return (
    <div className="switch-row">
      <span id={props.labelId} className="switch-label">
        {props.label}
      </span>
      <button
        ref={props.buttonRef}
        type="button"
        role="switch"
        className="switch"
        aria-checked={props.checked}
        aria-labelledby={props.labelId}
        aria-disabled={props.disabled ? "true" : undefined}
        aria-describedby={props.describedBy}
        onClick={() => {
          if (!props.disabled) {
            props.onActivate();
          }
        }}
      >
        <span className="switch-knob" aria-hidden="true" />
      </button>
    </div>
  );
}

/** The "Locking" settings group (module docs). */
export function LockSettingsGroup(props: LockSettingsGroupProps) {
  const id = useId();
  const titleId = `${id}-title`;
  const offHintId = `${id}-off`;
  const restartHintId = `${id}-restart-hint`;
  const sleepHintId = `${id}-sleep-hint`;
  const idleId = `${id}-idle`;
  const [dialogOpen, setDialogOpen] = useState(false);
  const toggleRef = useRef<HTMLButtonElement>(null);
  const wasOpen = useRef(false);
  const { value, text } = props;
  const loading = value === undefined;
  const off = value?.autoLock === false;
  const subDisabled = loading || off;
  const offDescribed = off ? offHintId : undefined;

  // On close, focus returns to the master switch (§2 point 5).
  useEffect(() => {
    if (wasOpen.current && !dialogOpen) {
      toggleRef.current?.focus();
    }
    wasOpen.current = dialogOpen;
  }, [dialogOpen]);

  const change = (next: Partial<LockSettingsValue>) => {
    if (value !== undefined) {
      props.onChange({ ...value, ...next });
    }
  };

  return (
    <div className="panel narrow lock-settings" role="region" aria-labelledby={titleId}>
      <h2 id={titleId}>{text.title}</h2>
      <Switch
        labelId={`${id}-auto`}
        label={text.autoLock}
        checked={value?.autoLock ?? true}
        disabled={loading}
        buttonRef={toggleRef}
        onActivate={() => {
          if (value?.autoLock === true) {
            setDialogOpen(true);
          } else {
            change({ autoLock: true });
          }
        }}
      />
      <div className="lock-sub" data-dimmed={subDisabled ? "true" : undefined}>
        {off && (
          <p id={offHintId} className="hint">
            {text.offHint}
          </p>
        )}
        <div className="switch-row">
          <label htmlFor={idleId} className="switch-label">
            {text.idle}
          </label>
          <select
            id={idleId}
            value={value?.idleMinutes ?? props.idleMinutes[2]}
            aria-disabled={subDisabled ? "true" : undefined}
            aria-describedby={offDescribed}
            onMouseDown={(e) => {
              if (subDisabled) {
                e.preventDefault(); // Does not open the list.
              }
            }}
            onKeyDown={(e) => {
              if (subDisabled && e.key !== "Tab") {
                e.preventDefault(); // Arrows, Space, Enter and letters change nothing.
              }
            }}
            onChange={(e) => {
              const minutes = Number(e.currentTarget.value);
              if (!subDisabled && props.idleMinutes.includes(minutes)) {
                change({ idleMinutes: minutes });
              }
            }}
          >
            {props.idleMinutes.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        </div>
        <Switch
          labelId={`${id}-restart`}
          label={text.restart}
          checked
          disabled
          describedBy={ids(restartHintId, offDescribed)}
          onActivate={() => undefined}
        />
        <p id={restartHintId} className="hint">
          {text.restartHint}
        </p>
        <Switch
          labelId={`${id}-sleep`}
          label={text.sleep}
          checked={value?.lockOnSleep ?? true}
          disabled={subDisabled}
          describedBy={ids(sleepHintId, offDescribed)}
          onActivate={() => change({ lockOnSleep: !(value?.lockOnSleep ?? true) })}
        />
        <p id={sleepHintId} className="hint">
          {text.sleepHint}
        </p>
      </div>
      {dialogOpen && (
        <LockDisableDialog
          text={text}
          delayMs={props.confirmDelayMs}
          clock={props.clock ?? monotonic}
          onCancel={() => setDialogOpen(false)}
          onConfirm={() => {
            setDialogOpen(false);
            change({ autoLock: false });
          }}
        />
      )}
    </div>
  );
}

/** The turn-off warning dialog (module docs; ADR 0110 §2). Mount it to open it. The countdown
 * polls the monotonic clock every `COUNTDOWN_POLL_MS` and re-renders when the shown second
 * changes; whether Confirm works is decided by the clock at the click itself. */
export function LockDisableDialog(props: {
  readonly text: LockSettingsText;
  readonly delayMs: number;
  readonly clock: () => number;
  readonly onCancel: () => void;
  readonly onConfirm: () => void;
}) {
  const id = useId();
  const titleId = `${id}-title`;
  const bodyId = `${id}-body`;
  const { text, delayMs, clock } = props;
  const [openedAt] = useState(() => clock());
  const [state, setState] = useState(() => countdown(0, delayMs));
  const [announcement, setAnnouncement] = useState("");
  const containerRef = useRef<HTMLDivElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    setModalOpen(true);
    cancelRef.current?.focus();
    // Set after the empty region is in the page, so the change is announced.
    setAnnouncement(text.disableWait);
    return () => setModalOpen(false);
  }, [text.disableWait]);

  useEffect(() => {
    if (state.ready) {
      setAnnouncement(text.disableReady);
      return undefined;
    }
    const timer = setInterval(() => {
      const next = countdown(clock() - openedAt, delayMs);
      setState((current) => (current.ready === next.ready && current.seconds === next.seconds ? current : next));
    }, COUNTDOWN_POLL_MS);
    return () => clearInterval(timer);
  }, [state.ready, delayMs, clock, openedAt, text.disableReady]);

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Escape") {
      e.preventDefault();
      props.onCancel();
      return;
    }
    trapTab(e, containerRef.current);
  };

  return (
    <div className="overlay">
      <button type="button" className="dialog-backdrop" aria-label={text.disableCancel} onClick={props.onCancel} />
      <div
        ref={containerRef}
        className="panel dialog confirm-dialog lock-disable-dialog"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={bodyId}
        onKeyDown={onKeyDown}
      >
        <h2 id={titleId}>{text.disableTitle}</h2>
        <p id={bodyId}>{text.disableBody}</p>
        <p className="sr-only" aria-live="polite">
          {announcement}
        </p>
        <div className="actions">
          <button ref={cancelRef} type="button" className="secondary" onClick={props.onCancel}>
            {text.disableCancel}
          </button>
          <button
            type="button"
            className="danger"
            aria-disabled={state.ready ? undefined : "true"}
            onClick={() => {
              // The monotonic clock decides, not the last rendered state (§2 point 3).
              if (countdown(clock() - openedAt, delayMs).ready) {
                props.onConfirm();
              }
            }}
          >
            {state.ready ? text.disableConfirm : text.disableConfirmCountdown(state.seconds)}
          </button>
        </div>
      </div>
    </div>
  );
}
