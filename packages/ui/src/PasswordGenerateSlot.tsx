// The generate button and settings popover next to a password-type field (the login password,
// or a hidden custom field): "Generate" fills the field with the current options at once; the
// gear opens a popover with the same character/word options the generator page offers, and
// generates (and fills) again when the options change there.
//
// This component is presentation only: it holds no option values of its own (every value is a
// prop, every change calls back to the caller) and it never touches the core. The caller (the
// web vault's `ItemEditor`) owns the options — kept in its session's generator memory, shared
// with the generator page — and the actual `generate*WithOptions` call, so this package stays
// free of `@rizzy-vault/core` (ADR 0014 §5: the design system has no business logic).
//
// A character class rule is `rizzy-core`'s own `ClassRule`, shown as Off / Allowed / Required;
// this module declares the same three string values rather than importing the type, so the
// caller's `@rizzy-vault/core` objects pass through structurally without this package naming
// that dependency.
import { useId, useState } from "react";

/** A character class rule ("excluded" | "included" | "required"), `rizzy-core`'s own `ClassRule`. */
export type GeneratorClassRule = "excluded" | "included" | "required";

/** The character-mode options of a password generate request (`@rizzy-vault/core`'s `PasswordOptions`). */
export interface GeneratorPasswordOptions {
  readonly length: number;
  readonly lowercase: GeneratorClassRule;
  readonly uppercase: GeneratorClassRule;
  readonly digits: GeneratorClassRule;
  readonly symbols: GeneratorClassRule;
  readonly excludeAmbiguous: boolean;
  readonly exclude: string;
  readonly symbolSet: string | null;
}

/** The word-mode options of a passphrase generate request (`@rizzy-vault/core`'s `PassphraseOptions`). */
export interface GeneratorPassphraseOptions {
  readonly words: number;
  readonly separator: string;
  readonly capitalize: boolean;
  readonly includeNumber: boolean;
}

/** The generator's bounds, so the popover's controls match `rizzy-core`'s limits. */
export interface GeneratorLimits {
  readonly minLength: number;
  readonly maxLength: number;
  readonly minWords: number;
  readonly maxWords: number;
  readonly symbols: string;
  readonly ambiguous: string;
  readonly maxSetTextLength: number;
}

/** The props of {@link PasswordGenerateSlot}. */
export interface PasswordGenerateSlotProps {
  /** Which field this slot fills, for its control labels (not sent anywhere). */
  readonly fieldName: string;
  readonly mode: "password" | "passphrase";
  readonly onModeChange: (mode: "password" | "passphrase") => void;
  readonly passwordOptions: GeneratorPasswordOptions;
  readonly onPasswordOptionsChange: (options: GeneratorPasswordOptions) => void;
  readonly passphraseOptions: GeneratorPassphraseOptions;
  readonly onPassphraseOptionsChange: (options: GeneratorPassphraseOptions) => void;
  readonly limits: GeneratorLimits;
  /** Generates a value with the current options and fills the field. Shows its own busy/error.
   * Resolves `true` on success, `false` on a refusal — never rejects. The popover awaits this
   * to decide whether to close (module docs: a refusal must keep the popover open). */
  readonly onGenerate: () => Promise<boolean>;
  readonly busy?: boolean;
  /** The core's refusal message for the current options, if they are not valid right now. */
  readonly errorMessage?: string;
}

/** One character class row: a label and an Off / Allowed / Required select. */
function ClassRow(props: {
  readonly id: string;
  readonly label: string;
  readonly value: GeneratorClassRule;
  readonly onChange: (rule: GeneratorClassRule) => void;
}) {
  return (
    <div className="class-rule-row">
      <label htmlFor={props.id}>{props.label}</label>
      <select
        id={props.id}
        value={props.value}
        onChange={(e) => props.onChange(e.currentTarget.value as GeneratorClassRule)}
      >
        <option value="excluded">Off</option>
        <option value="included">Allowed</option>
        <option value="required">Required</option>
      </select>
    </div>
  );
}

/** The generate button and settings popover beside a password field (module docs). */
export function PasswordGenerateSlot(props: PasswordGenerateSlotProps) {
  const [open, setOpen] = useState(false);
  const uid = useId();
  const { passwordOptions: p, passphraseOptions: ph, limits } = props;

  const setPasswordOption = <K extends keyof GeneratorPasswordOptions>(
    key: K,
    value: GeneratorPasswordOptions[K],
  ) => props.onPasswordOptionsChange({ ...p, [key]: value });
  const setPassphraseOption = <K extends keyof GeneratorPassphraseOptions>(
    key: K,
    value: GeneratorPassphraseOptions[K],
  ) => props.onPassphraseOptionsChange({ ...ph, [key]: value });

  return (
    <span className="password-generate-slot" data-field={props.fieldName}>
      <button
        type="button"
        className="secondary small"
        onClick={() => void props.onGenerate()}
        disabled={props.busy === true}
      >
        Generate
      </button>
      <button
        type="button"
        className="secondary small icon-button"
        aria-label="Generator settings"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        ⚙
      </button>
      {/* Shown next to the bare "Generate" button only while the popover is closed — once it
          is open, the same message moves inside the popover (below), right above the controls
          that caused it, instead of sitting outside the panel the user needs to look at. */}
      {props.errorMessage !== undefined && !open && (
        <span className="error generator-slot-error" role="alert">
          {props.errorMessage}
        </span>
      )}
      {open && (
        <div className="popover generator-popover" role="group" aria-label="Generator settings">
          {props.errorMessage !== undefined && (
            <span className="error generator-slot-error" role="alert">
              {props.errorMessage}
            </span>
          )}
          <fieldset>
            <legend>Kind</legend>
            <label className="check">
              <input
                type="radio"
                name={`${uid}-mode`}
                checked={props.mode === "password"}
                onChange={() => props.onModeChange("password")}
              />
              Password
            </label>
            <label className="check">
              <input
                type="radio"
                name={`${uid}-mode`}
                checked={props.mode === "passphrase"}
                onChange={() => props.onModeChange("passphrase")}
              />
              Passphrase
            </label>
          </fieldset>
          {props.mode === "password" ? (
            <>
              <label htmlFor={`${uid}-length`}>Length: {p.length}</label>
              <input
                id={`${uid}-length`}
                type="range"
                min={limits.minLength}
                max={limits.maxLength}
                value={p.length}
                onChange={(e) => setPasswordOption("length", Number(e.currentTarget.value))}
              />
              <ClassRow
                id={`${uid}-lowercase`}
                label="Lowercase"
                value={p.lowercase}
                onChange={(v) => setPasswordOption("lowercase", v)}
              />
              <ClassRow
                id={`${uid}-uppercase`}
                label="Uppercase"
                value={p.uppercase}
                onChange={(v) => setPasswordOption("uppercase", v)}
              />
              <ClassRow
                id={`${uid}-digits`}
                label="Digits"
                value={p.digits}
                onChange={(v) => setPasswordOption("digits", v)}
              />
              <ClassRow
                id={`${uid}-symbols`}
                label="Symbols"
                value={p.symbols}
                onChange={(v) => setPasswordOption("symbols", v)}
              />
              <label className="check">
                <input
                  type="checkbox"
                  checked={p.excludeAmbiguous}
                  onChange={(e) => setPasswordOption("excludeAmbiguous", e.currentTarget.checked)}
                />
                Avoid look-alike characters
              </label>
              <label htmlFor={`${uid}-exclude`}>Exclude characters</label>
              <input
                id={`${uid}-exclude`}
                type="text"
                autoComplete="off"
                maxLength={limits.maxSetTextLength}
                value={p.exclude}
                onChange={(e) => setPasswordOption("exclude", e.currentTarget.value)}
              />
              <label htmlFor={`${uid}-symbol-set`}>Custom symbol set</label>
              <input
                id={`${uid}-symbol-set`}
                type="text"
                autoComplete="off"
                placeholder={`Default: ${limits.symbols}`}
                maxLength={limits.maxSetTextLength}
                value={p.symbolSet ?? ""}
                onChange={(e) =>
                  setPasswordOption("symbolSet", e.currentTarget.value === "" ? null : e.currentTarget.value)
                }
              />
            </>
          ) : (
            <>
              <label htmlFor={`${uid}-words`}>Words: {ph.words}</label>
              <input
                id={`${uid}-words`}
                type="range"
                min={limits.minWords}
                max={limits.maxWords}
                value={ph.words}
                onChange={(e) => setPassphraseOption("words", Number(e.currentTarget.value))}
              />
              <label htmlFor={`${uid}-separator`}>Separator</label>
              <input
                id={`${uid}-separator`}
                type="text"
                autoComplete="off"
                maxLength={1}
                value={ph.separator}
                onChange={(e) => setPassphraseOption("separator", e.currentTarget.value)}
              />
              <label className="check">
                <input
                  type="checkbox"
                  checked={ph.capitalize}
                  onChange={(e) => setPassphraseOption("capitalize", e.currentTarget.checked)}
                />
                Capitalise each word
              </label>
              <label className="check">
                <input
                  type="checkbox"
                  checked={ph.includeNumber}
                  onChange={(e) => setPassphraseOption("includeNumber", e.currentTarget.checked)}
                />
                Include a number
              </label>
            </>
          )}
          <div className="actions">
            <button
              type="button"
              onClick={() => {
                // Only close on success: a refusal (e.g. every character class off, or every
                // character excluded) must leave the popover open, with the offending option
                // still in view next to the error, rather than close before the user can see
                // or fix it (module docs).
                void props.onGenerate().then((ok) => {
                  if (ok) {
                    setOpen(false);
                  }
                });
              }}
              disabled={props.busy === true}
            >
              Generate
            </button>
            <button type="button" className="secondary" onClick={() => setOpen(false)}>
              Close
            </button>
          </div>
        </div>
      )}
    </span>
  );
}
