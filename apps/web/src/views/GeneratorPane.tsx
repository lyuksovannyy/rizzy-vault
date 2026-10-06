// The password and passphrase generator (ROADMAP §4.2). The core generates (rizzy-core
// `generator`, OS randomness in the Worker) and computes the entropy of a set of options
// without generating anything (`passwordEntropy`/`passphraseEntropy`); this view only collects
// the options, shows the value in the secret-field component, and offers a copy button. No
// generation or entropy arithmetic happens here.
//
// Each character class (lowercase, uppercase, digits, symbols) is one of the core's own
// `ClassRule`s — excluded, included or required, shown as Off/Allowed/Required — so
// "include/exclude characters" is the generator's existing options, not a new rule invented
// here. `exclude` and `symbolSet` are plain text the core parses and checks (`generator_*`
// codes on a bad one); this view never interprets them itself.
//
// Options are kept in `ctx.generator` (generator-memory.ts), shared with the editor's generate
// popover and cleared only when the vault locks. The entropy meter re-checks the current
// options after every change (debounced) so a value the user has not generated yet still shows
// its bit count and, for an impossible combination, the core's own refusal message
// (`generatorErrorMessage`) instead of a UI-invented one.
import type { ClassRule, Generated, GeneratorCheck, PassphraseOptions, PasswordOptions } from "@rizzy-vault/core";
import { SecretField } from "@rizzy-vault/ui";
import { useEffect, useRef, useState } from "react";

import { codeOf } from "../core-client.ts";
import { GENERATOR_LIMITS } from "../generator-constants.ts";
import { checkEntropy, generateValue } from "../generator-flow.ts";
import { messageFor } from "../messages.ts";
import type { VaultContext } from "./VaultView.tsx";
import { useAction } from "./common.tsx";

/** How long after the last edit the live entropy/refusal check runs. */
const CHECK_DEBOUNCE_MS = 150;

/** One character class row: a label and an Off / Allowed / Required select. */
function ClassRow(props: {
  readonly label: string;
  readonly value: ClassRule;
  readonly onChange: (rule: ClassRule) => void;
}) {
  const id = `gen-class-${props.label}`;
  return (
    <div className="class-rule-row">
      <label htmlFor={id}>{props.label}</label>
      <select
        id={id}
        value={props.value}
        onChange={(e) => props.onChange(e.currentTarget.value as ClassRule)}
      >
        <option value="excluded">Off</option>
        <option value="included">Allowed</option>
        <option value="required">Required</option>
      </select>
    </div>
  );
}

/** The entropy meter: the core's bit count, or its refusal message for an impossible combination. */
function EntropyMeter(props: { readonly check: GeneratorCheck | undefined }) {
  const { check } = props;
  if (check === undefined) {
    return null;
  }
  if (!check.ok) {
    return (
      <p className="error" role="alert" data-code={check.code}>
        {check.message}
      </p>
    );
  }
  return <p className="muted">About {Math.floor(check.entropyBits)} bits of entropy.</p>;
}

/** The generator (module docs). */
export function GeneratorPane(props: { readonly ctx: VaultContext }) {
  const { ctx } = props;
  const { generator } = ctx;
  const { mode, setMode, passwordOptions, setPasswordOptions, passphraseOptions, setPassphraseOptions } =
    generator;
  const [result, setResult] = useState<Generated | undefined>();
  const [check, setCheck] = useState<GeneratorCheck | undefined>();
  const [copied, setCopied] = useState(false);
  const { busy, error, run } = useAction();
  const checkToken = useRef(0);

  // The live entropy/refusal check: re-runs after every option change, debounced, and ignores
  // a stale answer that resolves after a newer one started (`checkToken`).
  useEffect(() => {
    const token = (checkToken.current += 1);
    const timer = setTimeout(() => {
      void (async () => {
        try {
          const entropyBits = await checkEntropy(ctx.client, mode, passwordOptions, passphraseOptions);
          if (checkToken.current === token) {
            setCheck({ ok: true, entropyBits });
          }
        } catch (e) {
          if (checkToken.current === token) {
            const code = codeOf(e);
            setCheck({ ok: false, code, message: messageFor(code) });
          }
        }
      })();
    }, CHECK_DEBOUNCE_MS);
    return () => {
      clearTimeout(timer);
    };
  }, [mode, passwordOptions, passphraseOptions, ctx.client]);

  const generate = () =>
    void run(async () => {
      setCopied(false);
      const value = await generateValue(ctx.client, mode, passwordOptions, passphraseOptions);
      setResult(value);
      generator.pushHistory(value);
    });

  const setPasswordOption = <K extends keyof PasswordOptions>(key: K, value: PasswordOptions[K]) =>
    setPasswordOptions({ ...passwordOptions, [key]: value });
  const setPassphraseOption = <K extends keyof PassphraseOptions>(
    key: K,
    value: PassphraseOptions[K],
  ) => setPassphraseOptions({ ...passphraseOptions, [key]: value });

  return (
    <div className="panel narrow generator-pane">
      <h2>Generator</h2>
      <fieldset>
        <legend>Kind</legend>
        <label className="check">
          <input type="radio" name="gen-mode" checked={mode === "password"} onChange={() => setMode("password")} />
          Password
        </label>
        <label className="check">
          <input
            type="radio"
            name="gen-mode"
            checked={mode === "passphrase"}
            onChange={() => setMode("passphrase")}
          />
          Passphrase
        </label>
      </fieldset>
      {mode === "password" ? (
        <>
          <label htmlFor="gen-length">Length</label>
          <div className="length-controls">
            <input
              id="gen-length"
              type="range"
              min={GENERATOR_LIMITS.minLength}
              max={GENERATOR_LIMITS.maxLength}
              value={passwordOptions.length}
              onChange={(e) => setPasswordOption("length", Number(e.currentTarget.value))}
            />
            <input
              type="number"
              aria-label="Length (number)"
              min={GENERATOR_LIMITS.minLength}
              max={GENERATOR_LIMITS.maxLength}
              value={passwordOptions.length}
              onChange={(e) => setPasswordOption("length", Number(e.currentTarget.value))}
            />
          </div>
          <fieldset>
            <legend>Characters</legend>
            <ClassRow
              label="Lowercase (a–z)"
              value={passwordOptions.lowercase}
              onChange={(v) => setPasswordOption("lowercase", v)}
            />
            <ClassRow
              label="Uppercase (A–Z)"
              value={passwordOptions.uppercase}
              onChange={(v) => setPasswordOption("uppercase", v)}
            />
            <ClassRow
              label="Digits (0–9)"
              value={passwordOptions.digits}
              onChange={(v) => setPasswordOption("digits", v)}
            />
            <ClassRow
              label="Symbols"
              value={passwordOptions.symbols}
              onChange={(v) => setPasswordOption("symbols", v)}
            />
          </fieldset>
          <label className="check">
            <input
              type="checkbox"
              checked={passwordOptions.excludeAmbiguous}
              onChange={(e) => setPasswordOption("excludeAmbiguous", e.currentTarget.checked)}
            />
            Avoid look-alike characters ({GENERATOR_LIMITS.ambiguous})
          </label>
          <label htmlFor="gen-exclude">Exclude characters</label>
          <input
            id="gen-exclude"
            type="text"
            autoComplete="off"
            placeholder="Characters never used, e.g. {}[]"
            maxLength={GENERATOR_LIMITS.maxSetTextLength}
            value={passwordOptions.exclude}
            onChange={(e) => setPasswordOption("exclude", e.currentTarget.value)}
          />
          <label htmlFor="gen-symbol-set">Custom symbol set</label>
          <input
            id="gen-symbol-set"
            type="text"
            autoComplete="off"
            placeholder={`Default: ${GENERATOR_LIMITS.symbols}`}
            maxLength={GENERATOR_LIMITS.maxSetTextLength}
            value={passwordOptions.symbolSet ?? ""}
            onChange={(e) =>
              setPasswordOption("symbolSet", e.currentTarget.value === "" ? null : e.currentTarget.value)
            }
          />
        </>
      ) : (
        <>
          <label htmlFor="gen-words">Words: {passphraseOptions.words}</label>
          <input
            id="gen-words"
            type="range"
            min={GENERATOR_LIMITS.minWords}
            max={GENERATOR_LIMITS.maxWords}
            value={passphraseOptions.words}
            onChange={(e) => setPassphraseOption("words", Number(e.currentTarget.value))}
          />
          <label htmlFor="gen-separator">Separator</label>
          <input
            id="gen-separator"
            type="text"
            autoComplete="off"
            maxLength={1}
            value={passphraseOptions.separator}
            onChange={(e) => setPassphraseOption("separator", e.currentTarget.value)}
          />
          <label className="check">
            <input
              type="checkbox"
              checked={passphraseOptions.capitalize}
              onChange={(e) => setPassphraseOption("capitalize", e.currentTarget.checked)}
            />
            Capitalise each word
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={passphraseOptions.includeNumber}
              onChange={(e) => setPassphraseOption("includeNumber", e.currentTarget.checked)}
            />
            Include a number
          </label>
        </>
      )}
      <EntropyMeter check={check} />
      <div className="actions">
        <button type="button" onClick={generate} disabled={busy}>
          {result === undefined ? "Generate" : "Regenerate"}
        </button>
      </div>
      {error !== undefined && (
        <p className="error" role="alert" data-code={error}>
          {messageFor(error)}
        </p>
      )}
      {result !== undefined && (
        <div className="generated">
          <SecretField label="Generated" name="generated" value={result.value} initiallyRevealed />
          <p className="muted">About {Math.floor(result.entropyBits)} bits of entropy.</p>
          <button
            type="button"
            className="secondary"
            onClick={() =>
              void run(async () => {
                await ctx.clipboard.copy(result.value);
                setCopied(true);
              })
            }
          >
            {copied ? "Copied (cleared in 30 s)" : "Copy"}
          </button>
        </div>
      )}
      {(() => {
        // `result` is this render's own state, lost and recreated every time the pane mounts
        // (switching tabs unmounts it); `generator.history` survives that, so after a mount
        // with no `result` yet its newest entry is not "already shown above" and belongs in
        // this list too — hence slicing by whether a result is currently displayed, not by a
        // fixed offset.
        const earlier = generator.history.slice(result === undefined ? 0 : 1);
        return (
          earlier.length > 0 && (
            <details className="generator-history">
              <summary>Earlier values this session ({earlier.length})</summary>
              <ul>
                {earlier.map((g, i) => (
                  <li key={`history-${i}`} className="mono">
                    <SecretField label={`Earlier value ${i + 1}`} name={`history-${i}`} value={g.value} />
                  </li>
                ))}
              </ul>
            </details>
          )
        );
      })()}
    </div>
  );
}
