// SPDX-License-Identifier: AGPL-3.0-only

// The second-factor prompt: the Worker asks for it mid-login, when the server wants a code
// (`ask-totp` in `protocol.ts`). The code is single-use, so it is a plain numeric input. Its
// text is the `totp.*` and `action.*` entries of `@rizzy-vault/i18n`.
import { t } from "@rizzy-vault/i18n";
import { type FormEvent, useState } from "react";

/** Asks for the authenticator code; answers `null` on cancel. */
export function TotpDialog(props: { readonly onAnswer: (code: string | null) => void }) {
  const [code, setCode] = useState("");
  const submit = (e: FormEvent) => {
    e.preventDefault();
    props.onAnswer(code.trim());
  };
  return (
    <div className="overlay">
      <form className="panel dialog" role="dialog" aria-modal="true" aria-labelledby="totp-title" onSubmit={submit}>
        <h2 id="totp-title">{t("totp.title")}</h2>
        <p>{t("totp.prompt")}</p>
        <label htmlFor="totp-code">{t("totp.code")}</label>
        <input
          id="totp-code"
          name="totp"
          inputMode="numeric"
          autoComplete="one-time-code"
          spellCheck={false}
          autoFocus
          required
          value={code}
          onChange={(e) => setCode(e.currentTarget.value)}
        />
        <div className="actions">
          <button type="submit">{t("action.continue")}</button>
          <button type="button" className="secondary" onClick={() => props.onAnswer(null)}>
            {t("action.cancel")}
          </button>
        </div>
      </form>
    </div>
  );
}
