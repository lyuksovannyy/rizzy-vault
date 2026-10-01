// Login (CRYPTO.md §11.4: every web-vault session is an OPAQUE login with the login name, the
// Secret Key and the master password; the second factor is asked for when the server wants
// it). Also the "unlock" screen after a lock: the login name stays in memory, nothing else.
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
      <h1 id="login-title">{unlock ? "Unlock rizzy-vault" : "Log in to rizzy-vault"}</h1>
      {props.notice !== undefined && <p className="notice">{props.notice}</p>}
      <label htmlFor="login-name">Login name</label>
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
        label="Secret Key"
        name="secret-key"
        inputRef={secretKey}
        required
        hint="From your Emergency Kit. It starts with RV1-."
      />
      <SecretField
        label="Master password"
        name="master-password"
        inputRef={password}
        required
        autoFocus={unlock}
      />
      <p className="hint">
        Do not let the browser save your master password or Secret Key. This web vault keeps
        nothing after a reload or a lock: you log in again each time.
      </p>
      <ErrorText code={error} />
      <div className="actions">
        <button type="submit" disabled={busy}>
          {busy ? "Logging in…" : unlock ? "Unlock" : "Log in"}
        </button>
        <button type="button" className="link" onClick={props.onSignup} disabled={busy}>
          Create an account
        </button>
      </div>
    </form>
  );
}
