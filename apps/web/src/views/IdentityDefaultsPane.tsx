// SPDX-License-Identifier: AGPL-3.0-only

// Settings → Identity generator (ADR 0079 §8, Open question 7): the defaults a new identity
// opens with — sex, country, age range, email style — and the email domain for generated
// identities, which is the only way to get a generated email address until masked email (M6).
//
// They are the account's ACCOUNT_SETTINGS tag 0x0004, end-to-end encrypted and synced like the
// matching settings (`MatchingPane.tsx`): one `changeMatchSettings({ kind: "identityDefaults" })`
// commit, which the core retries once on top of another device's newer state, and which the
// server takes only within five minutes of a login ("Log in again to do this."). That is why
// the "New identity" form never writes them itself: its last-used age range stays in this
// session's memory (`identity-memory.ts`), which a save here clears so the saved range applies.
//
// The age mode is not stored, only the range; this picker derives it on open (§10).
import type { IdentityCountry, IdentityDefaults, IdentityEmailStyle, IdentitySexChoice } from "@rizzy-vault/core";
import { type FormEvent, useCallback, useEffect, useId, useState } from "react";

import { codeOf } from "../core-client.ts";
import { CATCH_ALL_NOTE, DEFAULT_IDENTITY_DEFAULTS } from "../identity-constants.ts";
import { type AgeChoice, type AgeRange, ageChoiceFor, ageRangeOf } from "../identity-form.ts";
import { messageFor } from "../messages.ts";
import { AgePicker } from "./IdentityGenerator.tsx";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText, useAction } from "./common.tsx";

/** The settings form's values. */
interface Draft {
  readonly sex: IdentitySexChoice;
  readonly country: string;
  readonly age: AgeChoice;
  readonly range: AgeRange;
  readonly emailStyle: IdentityEmailStyle;
  readonly domain: string;
}

/** The form as it opens on `d`. */
function draftOf(d: IdentityDefaults): Draft {
  const range = { min: d.ageMin, max: d.ageMax };
  return {
    sex: d.sex,
    country: d.country ?? "",
    age: ageChoiceFor(range),
    range,
    emailStyle: d.emailStyle,
    domain: d.emailDomain ?? "",
  };
}

/** The Identity generator settings (module docs). */
export function IdentityDefaultsPane(props: { readonly ctx: VaultContext }) {
  const { ctx } = props;
  const ids = useId();
  const titleId = `${ids}-title`;
  const domainId = `${ids}-domain`;
  const [countries, setCountries] = useState<readonly IdentityCountry[]>([]);
  const [draft, setDraft] = useState<Draft | undefined>();
  const [loadError, setLoadError] = useState<string | undefined>();
  const [domainError, setDomainError] = useState<string | undefined>();
  const [done, setDone] = useState<string | undefined>();
  const { busy, error, run } = useAction();

  const load = useCallback(async () => {
    try {
      const [defaults, list] = await Promise.all([
        ctx.client.call("identityDefaults"),
        ctx.client.call("identityCountries"),
      ]);
      setCountries(list);
      setDraft(draftOf(defaults ?? DEFAULT_IDENTITY_DEFAULTS));
      setLoadError(undefined);
    } catch (e) {
      setDraft(undefined);
      setLoadError(codeOf(e));
    }
  }, [ctx.client]);

  useEffect(() => {
    void load();
  }, [load, ctx.revision]);

  const save = (e: FormEvent) => {
    e.preventDefault();
    if (draft === undefined) {
      return;
    }
    const age = ageRangeOf(draft.age);
    if (!age.ok) {
      return;
    }
    setDone(undefined);
    setDomainError(undefined);
    void run(async () => {
      let emailDomain: string | null = null;
      if (draft.domain.trim() !== "") {
        try {
          emailDomain = await ctx.client.call("normalizeEmailDomain", draft.domain.trim());
        } catch (err) {
          setDomainError(codeOf(err));
          return;
        }
      }
      const defaults: IdentityDefaults = {
        sex: draft.sex,
        country: draft.country === "" ? null : draft.country,
        ageMin: age.range.min,
        ageMax: age.range.max,
        emailStyle: draft.emailStyle,
        emailDomain,
      };
      await ctx.client.call("changeMatchSettings", { kind: "identityDefaults", defaults });
      ctx.identity.setLastAge(undefined);
      setDone("The identity generator defaults are saved.");
      await load();
    });
  };

  const set = (over: Partial<Draft>) => setDraft((d) => (d === undefined ? d : { ...d, ...over }));

  return (
    <div className="panel narrow" role="region" aria-labelledby={titleId}>
      <h2 id={titleId}>Identity generator</h2>
      <p className="muted">
        What a new identity is filled with. These settings are end-to-end encrypted with your account
        and apply on every device.
      </p>
      {loadError !== undefined && <ErrorText code={loadError} />}
      {done !== undefined && (
        <p className="notice" role="status">
          {done}
        </p>
      )}
      <ErrorText code={error} />
      {draft !== undefined && (
        <form onSubmit={save} noValidate>
          <label htmlFor={`${ids}-sex`}>Default sex</label>
          <select
            id={`${ids}-sex`}
            value={draft.sex}
            disabled={busy}
            onChange={(e) => {
              const v = e.currentTarget.value;
              set({ sex: v === "male" || v === "female" ? v : "random" });
            }}
          >
            <option value="random">Random</option>
            <option value="male">Male</option>
            <option value="female">Female</option>
          </select>
          <label htmlFor={`${ids}-country`}>Default country</label>
          <select
            id={`${ids}-country`}
            value={draft.country}
            disabled={busy}
            onChange={(e) => set({ country: e.currentTarget.value })}
          >
            <option value="">From this browser's language</option>
            {countries.map((c) => (
              <option key={c.code} value={c.code}>
                {c.name}
              </option>
            ))}
          </select>
          <AgePicker
            idPrefix={`${ids}-age`}
            label="Default age"
            choice={draft.age}
            range={draft.range}
            disabled={busy}
            onChange={(next) => {
              const result = ageRangeOf(next);
              set(result.ok ? { age: next, range: result.range } : { age: next });
            }}
          />
          <fieldset>
            <legend>Default email style</legend>
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
                  checked={draft.emailStyle === o.value}
                  disabled={busy}
                  onChange={() => set({ emailStyle: o.value })}
                />
                {o.label}
              </label>
            ))}
          </fieldset>
          <label htmlFor={domainId}>Email domain for generated identities</label>
          <input
            id={domainId}
            type="text"
            autoComplete="off"
            spellCheck={false}
            value={draft.domain}
            disabled={busy}
            aria-describedby={domainError !== undefined ? `${domainId}-error ${domainId}-hint` : `${domainId}-hint`}
            {...(domainError !== undefined ? { "aria-invalid": true } : {})}
            onChange={(e) => set({ domain: e.currentTarget.value })}
          />
          {domainError !== undefined && (
            <p className="error small" id={`${domainId}-error`}>
              {messageFor(domainError)}
            </p>
          )}
          <p className="hint" id={`${domainId}-hint`}>
            Your own catch-all domain or a forwarding service's domain, such as example.com. Leave it
            empty and new identities get no email address. {CATCH_ALL_NOTE}
          </p>
          <div className="actions">
            <button type="submit" disabled={busy || !ageRangeOf(draft.age).ok}>
              Save identity defaults
            </button>
          </div>
        </form>
      )}
    </div>
  );
}
