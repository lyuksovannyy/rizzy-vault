// SPDX-License-Identifier: AGPL-3.0-only

// The security-key prompt of a login (ADR 0058 point 3; CRYPTO.md §11.17): the Worker asks for
// it after the password and Secret Key verified (`ask-security-key` in `protocol.ts`). The
// browser's `navigator.credentials.get` runs here, on the UI thread and the web vault's own
// origin, when the user presses the button (Safari needs that user gesture). Its text is the
// `securityKey.*` and `action.*` entries of `@rizzy-vault/i18n`.
import type { SecurityKeyAnswer } from "@rizzy-vault/core";
import { t } from "@rizzy-vault/i18n";
import { trapTab } from "@rizzy-vault/ui";
import { type FormEvent, useRef, useState } from "react";

import { getAssertion, webauthnAvailable } from "../webauthn.ts";

/** Asks for the security key; answers `null` on cancel. A TOTP code is offered when the
 * account has one too (`totpAllowed`). */
export function SecurityKeyDialog(props: {
  readonly options: string;
  readonly totpAllowed: boolean;
  /** The previous prompt of this login failed (the dialog is shown again for a new challenge). */
  readonly retried: boolean;
  readonly onAnswer: (answer: SecurityKeyAnswer | null) => void;
}) {
  const { options, totpAllowed, retried, onAnswer } = props;
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(retried);
  const [code, setCode] = useState<string | undefined>();
  const dialogRef = useRef<HTMLDivElement>(null);
  const available = webauthnAvailable();

  const useKey = () => {
    setBusy(true);
    setFailed(false);
    getAssertion(options).then(
      (credential) => onAnswer({ kind: "credential", credential }),
      () => {
        // Cancelled, timed out or no matching key. The challenge may have expired too: ask
        // the server for a fresh one, then the user tries again.
        setBusy(false);
        setFailed(true);
        onAnswer({ kind: "retry" });
      },
    );
  };

  const submitCode = (e: FormEvent) => {
    e.preventDefault();
    if (code !== undefined) {
      onAnswer({ kind: "totp", code: code.trim() });
    }
  };

  return (
    <div className="overlay">
      <div
        ref={dialogRef}
        className="panel dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="security-key-title"
        aria-describedby="security-key-prompt"
        onKeyDown={(e) => trapTab(e, dialogRef.current)}
      >
        <h2 id="security-key-title">{t("securityKey.title")}</h2>
        {code === undefined ? (
          <>
            <p id="security-key-prompt">
              {available ? t("securityKey.prompt") : t("securityKey.unavailable")}
            </p>
            {failed && (
              <p className="error" role="alert">
                {t("securityKey.failed")}
              </p>
            )}
            <div className="actions">
              {available && (
                <button type="button" autoFocus disabled={busy} onClick={useKey}>
                  {t("securityKey.use")}
                </button>
              )}
              {totpAllowed && (
                <button type="button" className="secondary" onClick={() => setCode("")}>
                  {t("securityKey.useCode")}
                </button>
              )}
              <button type="button" className="secondary" onClick={() => onAnswer(null)}>
                {t("action.cancel")}
              </button>
            </div>
          </>
        ) : (
          <form onSubmit={submitCode}>
            <p id="security-key-prompt">{t("totp.prompt")}</p>
            <label htmlFor="security-key-code">{t("totp.code")}</label>
            <input
              id="security-key-code"
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
              <button type="button" className="secondary" onClick={() => onAnswer(null)}>
                {t("action.cancel")}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
