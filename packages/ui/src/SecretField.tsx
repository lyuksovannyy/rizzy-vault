// The one secret-field component (ADR 0014 §2 "Secret input fields"; THREAT_MODEL INV-68, A14).
//
// Every secret input of the web surfaces — the master password, the Secret Key, the recovery
// code, the export password, and a revealed secret field — is rendered by this component and
// no other. It:
// - sets `spellcheck="false"`, so that no enhanced spell-check service receives the secret;
// - sets `autocomplete="off"`, `autocorrect="off"` and `autocapitalize="off"`, hints that
//   discourage the browser from saving or learning it (browsers may ignore them, so the login
//   copy also tells users not to let the browser save the master password);
// - keeps all of them when "Show" switches `type` from `password` to `text`;
// - renders a revealed read-only value the same way (`readOnly`), so a reveal never lands in a
//   field that has spell-check on.
//
// The input is uncontrolled by default: the secret is read from the element on submit (through
// `inputRef`) and the caller clears the element afterwards, so it never sits in React state.
import { type KeyboardEvent, type Ref, useId, useState } from "react";

/** The attributes every secret input carries, before and after a reveal (INV-68). */
export const SECRET_INPUT_ATTRIBUTES = {
  spellCheck: false,
  autoComplete: "off",
  autoCorrect: "off",
  autoCapitalize: "off",
} as const;

/** The props of {@link SecretField}. */
export interface SecretFieldProps {
  /** The visible label. */
  readonly label: string;
  /** The form name of the input (no secret in it). */
  readonly name: string;
  /** The element, for the caller to read and clear the value on submit. */
  readonly inputRef?: Ref<HTMLInputElement>;
  /** A read-only revealed value (item view); absent for an input. */
  readonly value?: string;
  /** Whether the field must be filled before the form submits. */
  readonly required?: boolean;
  /** Starts revealed (a value the user just asked to see). */
  readonly initiallyRevealed?: boolean;
  /** Focus the field when it mounts. */
  readonly autoFocus?: boolean;
  /** A hint under the field. */
  readonly hint?: string;
  /** Called with the typed text when the field is used as a controlled input. */
  readonly onInput?: (text: string) => void;
  /** Called after each reveal toggle, with the new state. */
  readonly onRevealChange?: (revealed: boolean) => void;
}

/** A labelled secret input, masked until the user asks to see it (module docs). */
export function SecretField(props: SecretFieldProps) {
  const id = useId();
  const [revealed, setRevealed] = useState(props.initiallyRevealed === true);
  // Caps Lock hint: read only `getModifierState("CapsLock")` off the keyboard event, never the
  // key itself, so this never sees or logs a character of the secret being typed (CLAUDE.md
  // "Never log secrets"; nothing here is logged either way, but the same rule shapes what this
  // reads). Wired only on an editable (`!readOnly`) input: a revealed value (`value` is set) is
  // nothing but a `readOnly` display the user cannot type into, so a keypress landing there
  // would be a stray one, not a caps-lock-relevant one.
  const [capsLock, setCapsLock] = useState(false);
  const readOnly = props.value !== undefined;
  const toggle = () => {
    const next = !revealed;
    setRevealed(next);
    props.onRevealChange?.(next);
  };
  const checkCapsLock = (e: KeyboardEvent<HTMLInputElement>) => {
    setCapsLock(e.getModifierState("CapsLock"));
  };
  // Leaving the field (Tab, a click elsewhere) with Caps Lock still on but no further key
  // pressed in it must not leave a stale hint showing: there is no modifier event to read once
  // focus is gone, so this clears it outright rather than guessing.
  const clearCapsLockHint = () => setCapsLock(false);
  return (
    <div className="secret-field">
      <label htmlFor={id}>{props.label}</label>
      <div className="secret-field-row">
        <input
          id={id}
          name={props.name}
          ref={props.inputRef}
          type={revealed ? "text" : "password"}
          {...SECRET_INPUT_ATTRIBUTES}
          data-secret-field=""
          readOnly={readOnly}
          required={props.required === true}
          autoFocus={props.autoFocus === true}
          {...(readOnly
            ? {}
            : { onKeyDown: checkCapsLock, onKeyUp: checkCapsLock, onBlur: clearCapsLockHint })}
          {...(readOnly ? { value: props.value } : {})}
          {...(props.onInput !== undefined
            ? { onInput: (e: { currentTarget: HTMLInputElement }) => props.onInput?.(e.currentTarget.value) }
            : {})}
        />
        <button
          type="button"
          className="secondary"
          aria-pressed={revealed}
          aria-controls={id}
          onClick={toggle}
        >
          {revealed ? "Hide" : "Show"}
        </button>
      </div>
      {!revealed && capsLock && (
        <p className="hint caps-lock-hint" role="status">
          Caps Lock is on.
        </p>
      )}
      {props.hint !== undefined && <p className="hint">{props.hint}</p>}
    </div>
  );
}
