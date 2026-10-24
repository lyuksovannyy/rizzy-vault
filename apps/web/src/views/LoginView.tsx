// SPDX-License-Identifier: AGPL-3.0-only

// Login (CRYPTO.md §11.4: every web-vault session is an OPAQUE login with the login name, the
// Secret Key and the master password; the second factor is asked for when the server wants
// it). Also the "unlock" screen after a lock: the login name stays in memory, nothing else.
// Its text is the `login.*` entries of `@rizzy-vault/i18n`.
import { t } from "@rizzy-vault/i18n";
import { SecretField } from "@rizzy-vault/ui";
import { type FormEvent, useRef, useState } from "react";

import { type CoreClient, secretBytes } from "../core-client.ts";
import type { SessionInfo } from "../protocol.ts";
import { ErrorText, takeSecret, useAction } from "./common.tsx";

/** The login form. */
export function LoginView(props: {
  readonly client: CoreClient;
  readonly initialLoginName: string;
  readonly notice?: string;
  readonly onLoggedIn: (loginName: string, session: SessionInfo) => void;
  readonly onSignup: () => void;
}) {
  const [loginName, setLoginName] = useState(props.initialLoginName);
  const secretKey = useRef<HTMLInputElement>(null);
  const password = useRef<HTMLInputElement>(null);
  const { busy, error, run } = useAction();
  const unlock = props.initialLoginName !== "";

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const sk = secretBytes(takeSecret(secretKey.current));
    const pw = secretBytes(takeSecret(password.current));
    const name = loginName.trim();
    void run(async () => {
      const session = await props.client.call("login", name, sk, pw);
      props.onLoggedIn(name, session);
    });
  };

  return (
    <form className="panel narrow" onSubmit={submit} aria-labelledby="login-title">
      <h1 id="login-title">{unlock ? t("login.unlockTitle") : t("login.title")}</h1>
      {props.notice !== undefined && <p className="notice">{props.notice}</p>}
      <label htmlFor="login-name">{t("login.loginName")}</label>
      <input
        id="login-name"
        name="username"
        autoComplete="off"
        spellCheck={false}
        autoCapitalize="off"
        required
        autoFocus={!unlock}
        value={loginName}
        onChange={(e) => setLoginName(e.currentTarget.value)}
      />
      <SecretField
        label={t("login.secretKey")}
        name="secret-key"
        inputRef={secretKey}
        required
        hint={t("login.secretKeyHint")}
      />
      <SecretField
        label={t("login.masterPassword")}
        name="master-password"
        inputRef={password}
        required
        autoFocus={unlock}
      />
      <p className="hint">{t("login.noSavingHint")}</p>
      <ErrorText code={error} />
      <div className="actions">
        <button type="submit" disabled={busy}>
          {busy ? t("login.busy") : unlock ? t("login.unlock") : t("login.submit")}
        </button>
        <button type="button" className="link" onClick={props.onSignup} disabled={busy}>
          {t("login.createAccount")}
        </button>
      </div>
    </form>
  );
}
