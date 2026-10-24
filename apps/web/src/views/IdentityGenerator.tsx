// SPDX-License-Identifier: AGPL-3.0-only

// The identity generator on "New identity" (ADR 0079 §10): the form opens already filled from
// the core's draw, and a generator bar above the fields redraws it.
//
// - **Defaults.** The synced defaults (Settings → Identity generator, ACCOUNT_SETTINGS tag
//   0x0004) or the first-time ones, with this session's last-used age range over them
//   (`identity-memory.ts`). The country is the synced one, else the browser language's region
//   if it is bundled, else US. The sex radio starts at the default if one is set, else at the
//   draw's sex.
// - **Pickers.** Sex, country, age and email style each redraw their field and its dependents
//   through the Worker's `identityRegenerate` (`identity.sex`, `identity.country`,
//   `identity.birthday`, `identity.email`); Regenerate all is a fresh draw. Which redrawn values
//   are written is `identity-form.ts`'s `mergeDraft`: never a field the user typed in, except
//   through that field's own Regenerate button. An invalid custom or exact age shows its error
//   and redraws nothing.
// - **Worker handles.** The core's draft stays in the Worker under a handle (`identity-drafts.ts`);
//   calls run one after another here (`enqueue`) so a redraw always names the latest handle, and
//   the handle is released when the editor closes.
// - **Email.** Until masked email exists (M6) the domain is the user's own, from the synced
//   defaults; with none the email stays empty and its field says how to set one (§8). The field
//   is a plain input.
import type { IdentityCountry, IdentityEmailStyle, IdentitySex } from "@rizzy-vault/core";
import { IconGenerator } from "@rizzy-vault/ui";
import { type ReactNode, useEffect, useId, useRef, useState } from "react";

import { codeOf } from "../core-client.ts";
import { SEX_OPTIONS } from "../fields.ts";
import {
  AGE_PRESETS,
  CATCH_ALL_NOTE,
  COLLISION_NOTICE,
  DEFAULT_IDENTITY_DEFAULTS,
  GENERATED_KEYS,
  IDENTITY_MAX_AGE,
  IDENTITY_MIN_AGE,
  NO_DOMAIN_HINT,
  generatedName,
} from "../identity-constants.ts";
import {
  AGE_CUSTOM,
  AGE_EXACT,
  type AgeChoice,
  type AgeInput,
  type AgeRange,
  type GeneratorChoice,
  type IdentityForm,
  ITEM_NAME,
  type RedrawScope,
  ageChoiceFor,
  ageRangeOf,
  announcement,
  defaultCountry,
  drawnSex,
  formFromDraft,
  mergeDraft,
  optionsOf,
  selectAge,
  startBlank,
  startingDefaults,
  typed,
} from "../identity-form.ts";
import type { IdentityDraftMessage } from "../protocol.ts";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText } from "./common.tsx";

/** Whether two ranges are the same. */
function sameRange(a: AgeRange, b: AgeRange): boolean {
  return a.min === b.min && a.max === b.max;
}

/**
 * The age picker (ADR 0079 §3, §10): the presets, then "Custom range" (Min and Max) and "Exact
 * age" (one age). An invalid number shows its error, tied to its input with
 * `aria-describedby`; the caller redraws only on a valid change (`ageRangeOf`). Also used by
 * Settings → Identity generator for the default range.
 */
export function AgePicker(props: {
  readonly idPrefix: string;
  readonly label: string;
  readonly choice: AgeChoice;
  /** The last valid range: where a custom mode starts. */
  readonly range: AgeRange;
  readonly onChange: (choice: AgeChoice) => void;
  readonly disabled?: boolean;
}) {
  const { choice } = props;
  const result = ageRangeOf(choice);
  const problems: Partial<Record<AgeInput, string>> = result.ok ? {} : result.problems;
  const number = (which: AgeInput, label: string, value: string) => {
    const id = `${props.idPrefix}-${which}`;
    const problem = problems[which];
    return (
      <div className="field-edit">
        <label htmlFor={id}>{label}</label>
        <input
          id={id}
          type="number"
          inputMode="numeric"
          min={IDENTITY_MIN_AGE}
          max={IDENTITY_MAX_AGE}
          step={1}
          value={value}
          disabled={props.disabled === true}
          {...(problem !== undefined ? { "aria-invalid": true, "aria-describedby": `${id}-error` } : {})}
          onChange={(e) => props.onChange({ ...choice, [which]: e.currentTarget.value })}
        />
        {problem !== undefined && (
          <p className="error small" id={`${id}-error`}>
            {problem}
          </p>
        )}
      </div>
    );
  };
  return (
    <>
      <label htmlFor={`${props.idPrefix}-select`}>{props.label}</label>
      <select
        id={`${props.idPrefix}-select`}
        value={choice.select}
        disabled={props.disabled === true}
        onChange={(e) => props.onChange(selectAge(choice, e.currentTarget.value, props.range))}
      >
        {AGE_PRESETS.map((p) => (
          <option key={p.id} value={p.id}>
            {p.label}
          </option>
        ))}
        <option value={AGE_CUSTOM}>Custom range</option>
        <option value={AGE_EXACT}>Exact age</option>
      </select>
      {choice.select === AGE_CUSTOM && (
        <div className="age-inputs">
          {number("min", "Min", choice.min)}
          {number("max", "Max", choice.max)}
        </div>
      )}
      {choice.select === AGE_EXACT && <div className="age-inputs">{number("exact", "Age (years)", choice.exact)}</div>}
    </>
  );
}

/** What the editor uses of the generator (module docs). */
export interface IdentityGenerator {
  /** The generator runs (a new identity) and its first draw is in. */
  readonly ready: boolean;
  /** Whether the generator holds `key`'s value (a generated key or the item name). */
  owns(key: string): boolean;
  /** `key`'s value in the form. */
  value(key: string): string;
  /** The user typed `value` into `key`. */
  type(key: string, value: string): void;
  /** The generator bar, shown above the fields. */
  readonly bar: ReactNode;
  /** The Regenerate button and hint after `key`'s input, and the id its input names in
   * `aria-describedby`, if any. */
  extras(key: string, inputId: string): { readonly after: ReactNode; readonly describedBy?: string };
  /** The identity was saved: its age range becomes this session's last-used one. */
  saved(): void;
}

/** The identity generator of a "New identity" form; inactive (owning nothing) unless `enabled`. */
export function useIdentityGenerator(ctx: VaultContext, enabled: boolean): IdentityGenerator {
  const ids = useId();
  const firstRange = { min: DEFAULT_IDENTITY_DEFAULTS.ageMin, max: DEFAULT_IDENTITY_DEFAULTS.ageMax };
  const [countries, setCountries] = useState<readonly IdentityCountry[]>([]);
  const [form, setFormState] = useState<IdentityForm | undefined>();
  const [sex, setSex] = useState<IdentitySex>("female");
  const [country, setCountry] = useState("US");
  const [age, setAge] = useState<AgeChoice>(() => ageChoiceFor(firstRange));
  const [range, setRange] = useState<AgeRange>(firstRange);
  const [emailStyle, setEmailStyle] = useState<IdentityEmailStyle>("name");
  const [emailDomain, setEmailDomain] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>();
  const [message, setMessage] = useState("");
  const formRef = useRef<IdentityForm | undefined>(undefined);
  const handleRef = useRef<number | undefined>(undefined);
  const aliveRef = useRef(false);
  const queue = useRef<Promise<void>>(Promise.resolve());

  const setForm = (next: IdentityForm) => {
    formRef.current = next;
    setFormState(next);
  };

  /** Frees a handle in the Worker, best effort (a lock frees it anyway). */
  const release = (handle: number) => {
    void ctx.client.call("identityRelease", handle).catch(() => undefined);
  };

  // The first draw, and the release of the last handle when the editor closes.
  useEffect(() => {
    if (!enabled) {
      return undefined;
    }
    aliveRef.current = true;
    let live = true;
    void (async () => {
      try {
        const [synced, list] = await Promise.all([
          ctx.client.call("identityDefaults").catch(() => null),
          ctx.client.call("identityCountries"),
        ]);
        const start = startingDefaults(synced, ctx.identity.lastAge);
        const languages = navigator.languages.length > 0 ? navigator.languages : [navigator.language];
        const code = defaultCountry(start.country, languages, list.map((c) => c.code));
        const startRange = { min: start.ageMin, max: start.ageMax };
        const draft = await ctx.client.call(
          "identityGenerate",
          optionsOf({ sex: start.sex, country: code, age: startRange, emailStyle: start.emailStyle, emailDomain: start.emailDomain }),
        );
        if (!live) {
          release(draft.handle);
          return;
        }
        handleRef.current = draft.handle;
        setCountries(list);
        setCountry(code);
        setRange(startRange);
        setAge(ageChoiceFor(startRange));
        setEmailStyle(start.emailStyle);
        setEmailDomain(start.emailDomain);
        setSex(start.sex !== "random" ? start.sex : (drawnSex(draft.fields["identity.sex"]) ?? "female"));
        setForm(formFromDraft(draft.fields, draft.itemName));
      } catch (e) {
        if (live) {
          setError(codeOf(e));
        }
      }
    })();
    return () => {
      live = false;
      aliveRef.current = false;
      const handle = handleRef.current;
      handleRef.current = undefined;
      if (handle !== undefined) {
        release(handle);
      }
    };
    // The client is the dependency; the session memory is read once, when the form opens.
  }, [ctx.client, enabled]);

  /** Runs `op` after every earlier one, so each redraw names the latest handle. */
  const enqueue = (op: () => Promise<void>) => {
    queue.current = queue.current.then(async () => {
      setBusy(true);
      setError(undefined);
      try {
        await op();
      } catch (e) {
        setError(codeOf(e));
      } finally {
        setBusy(false);
      }
    });
  };

  /** Keeps a new draft's handle; `false` (and released) once the editor has closed. */
  const keep = (draft: IdentityDraftMessage): boolean => {
    if (!aliveRef.current) {
      release(draft.handle);
      return false;
    }
    handleRef.current = draft.handle;
    return true;
  };

  /** Writes a draft into the form and announces it. */
  const apply = (draft: IdentityDraftMessage, scope: RedrawScope) => {
    const current = formRef.current;
    if (current === undefined) {
      return;
    }
    const merged = mergeDraft(current, draft.fields, scope);
    setForm(merged.form);
    setMessage(announcement(scope, merged.written));
  };

  const choiceWith = (over: Partial<GeneratorChoice>): GeneratorChoice => ({
    sex,
    country,
    age: range,
    emailStyle,
    emailDomain,
    ...over,
  });

  /** Redraws `fieldKey` and its dependents under the pickers, with `over` changed. */
  const redraw = (fieldKey: string, scope: RedrawScope, over: Partial<GeneratorChoice> = {}) => {
    const options = optionsOf(choiceWith(over));
    enqueue(async () => {
      const handle = handleRef.current;
      if (handle === undefined) {
        return;
      }
      const draft = await ctx.client.call("identityRegenerate", handle, fieldKey, options);
      if (keep(draft)) {
        apply(draft, scope);
      }
    });
  };

  const regenerateAll = () => {
    const options = optionsOf(choiceWith({}));
    enqueue(async () => {
      const draft = await ctx.client.call("identityGenerate", options);
      const old = handleRef.current;
      if (!keep(draft)) {
        return;
      }
      if (old !== undefined) {
        release(old);
      }
      apply(draft, { kind: "all" });
    });
  };

  const clearGenerated = () => {
    enqueue(async () => {
      const current = formRef.current;
      if (current !== undefined) {
        setForm(startBlank(current));
        setMessage("Generated values cleared");
      }
      await Promise.resolve();
    });
  };

  const changeAge = (next: AgeChoice) => {
    setAge(next);
    const result = ageRangeOf(next);
    if (result.ok && !sameRange(result.range, range)) {
      setRange(result.range);
      redraw("identity.birthday", { kind: "picker" }, { age: result.range });
    }
  };

  const ready = enabled && form !== undefined;
  const owns = (key: string) => ready && (key === ITEM_NAME || GENERATED_KEYS.includes(key));

  const bar: ReactNode = !enabled ? null : (
    <fieldset className="identity-generator" aria-busy={busy}>
      <legend>Generated details</legend>
      <p className="hint">{COLLISION_NOTICE}</p>
      <ErrorText code={error} />
      {ready && (
        <>
          <fieldset>
            <legend>Sex</legend>
            {SEX_OPTIONS.map((o) => (
              <label key={o.value} className="check">
                <input
                  type="radio"
                  name={`${ids}-sex`}
                  checked={sex === o.value}
                  onChange={() => {
                    const next = o.value === "male" ? "male" : "female";
                    setSex(next);
                    redraw("identity.sex", { kind: "picker" }, { sex: next });
                  }}
                />
                {o.label}
              </label>
            ))}
          </fieldset>
          <label htmlFor={`${ids}-country`}>Country</label>
          <select
            id={`${ids}-country`}
            value={country}
            onChange={(e) => {
              const next = e.currentTarget.value;
              setCountry(next);
              redraw("identity.country", { kind: "picker" }, { country: next });
            }}
          >
            {countries.map((c) => (
              <option key={c.code} value={c.code}>
                {c.name}
              </option>
            ))}
          </select>
          <AgePicker idPrefix={`${ids}-age`} label="Age" choice={age} range={range} onChange={changeAge} />
          <fieldset>
            <legend>Email style</legend>
            {(
              [
                { value: "name", label: "Name + birthday" },
                { value: "nickname", label: "Nickname" },
              ] as const
            ).map((o) => (
              <label key={o.value} className="check">
                <input
                  type="radio"
                  name={`${ids}-email-style`}
                  checked={emailStyle === o.value}
                  onChange={() => {
                    setEmailStyle(o.value);
                    redraw("identity.email", { kind: "picker" }, { emailStyle: o.value });
                  }}
                />
                {o.label}
              </label>
            ))}
            <p className="hint">{CATCH_ALL_NOTE}</p>
          </fieldset>
          <div className="actions">
            <button type="button" className="secondary" onClick={regenerateAll}>
              Regenerate all
            </button>
            <button type="button" className="secondary" onClick={clearGenerated}>
              Start blank
            </button>
          </div>
        </>
      )}
      <p className="sr-only" role="status">
        {message}
      </p>
    </fieldset>
  );

  return {
    ready,
    owns,
    value: (key) => formRef.current?.values[key] ?? form?.values[key] ?? "",
    type: (key, value) => {
      const current = formRef.current;
      if (current !== undefined) {
        setForm(typed(current, key, value));
      }
    },
    bar,
    extras: (key, inputId) => {
      if (!ready || !GENERATED_KEYS.includes(key)) {
        return { after: null };
      }
      if (key === "identity.email" && emailDomain === null) {
        const hint = `${inputId}-hint`;
        return {
          after: (
            <p className="hint" id={hint}>
              {NO_DOMAIN_HINT} (Settings, Identity generator).
            </p>
          ),
          describedBy: hint,
        };
      }
      return {
        after: (
          <button
            type="button"
            className="secondary small icon-button"
            aria-label={`Regenerate ${generatedName(key)}`}
            title={`Regenerate ${generatedName(key)}`}
            onClick={() => redraw(key, { kind: "field", key })}
          >
            <IconGenerator />
          </button>
        ),
      };
    },
    saved: () => {
      if (ready) {
        ctx.identity.setLastAge(range);
      }
    },
  };
}
