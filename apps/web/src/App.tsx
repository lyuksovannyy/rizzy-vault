// The web vault's top level: start the core, then log in or sign up, then the vault.
//
// The web vault persists nothing (CRYPTO.md §11.4): every session is an OPAQUE login, and a
// lock or a reload ends it. "Unlock" is therefore a new login, with the login name kept in
// memory only.
import { ToastProvider } from "@rizzy-vault/ui";
import { useCallback, useEffect, useState } from "react";

import { type CoreClient, codeOf } from "./core-client.ts";
import { messageFor } from "./messages.ts";
import type { SessionInfo } from "./protocol.ts";
import { ThemeProvider } from "./theme.ts";
import { LoginView } from "./views/LoginView.tsx";
import { SignupView } from "./views/SignupView.tsx";
import { TotpDialog } from "./views/TotpDialog.tsx";
import { VaultView } from "./views/VaultView.tsx";

/** Where the app is. */
type Phase =
  | { readonly kind: "starting" }
  | { readonly kind: "unavailable"; readonly code: string }
  | { readonly kind: "login"; readonly notice?: string }
  | { readonly kind: "signup" }
  | { readonly kind: "vault"; readonly session: SessionInfo };

/** The web vault (module docs). */
export function App(props: { readonly client: CoreClient }) {
  const { client } = props;
  const [phase, setPhase] = useState<Phase>({ kind: "starting" });
  const [loginName, setLoginName] = useState("");
  const [totpAsk, setTotpAsk] = useState<((code: string | null) => void) | undefined>();

  useEffect(() => {
    client.setTotpPrompt(
      () =>
        new Promise<string | null>((resolve) => {
          setTotpAsk(() => (code: string | null) => {
            setTotpAsk(undefined);
            resolve(code);
          });
        }),
    );
    client.call("start").then(
      () => setPhase({ kind: "login" }),
      (e: unknown) => setPhase({ kind: "unavailable", code: codeOf(e) }),
    );
  }, [client]);

  const onUnlocked = useCallback((name: string, session: SessionInfo) => {
    setLoginName(name);
    setPhase({ kind: "vault", session });
  }, []);

  const onLocked = useCallback((notice?: string) => {
    setPhase(notice === undefined ? { kind: "login" } : { kind: "login", notice });
  }, []);

  let body;
  switch (phase.kind) {
    case "starting":
      body = <p className="status">Starting the vault…</p>;
      break;
    case "unavailable":
      body = (
        <div className="panel" role="alert">
          <h1>The vault cannot start</h1>
          <p>{messageFor(phase.code)}</p>
        </div>
      );
      break;
    case "login":
      body = (
        <LoginView
          client={client}
          initialLoginName={loginName}
          {...(phase.notice === undefined ? {} : { notice: phase.notice })}
          onLoggedIn={onUnlocked}
          onSignup={() => setPhase({ kind: "signup" })}
        />
      );
      break;
    case "signup":
      body = (
        <SignupView
          client={client}
          onDone={onUnlocked}
          onCancel={() => setPhase({ kind: "login" })}
        />
      );
      break;
    case "vault":
      body = (
        <VaultView
          client={client}
          loginName={loginName}
          initialSession={phase.session}
          onLocked={onLocked}
        />
      );
      break;
  }

  return (
    <ThemeProvider>
      <ToastProvider>
        <main>{body}</main>
        {totpAsk !== undefined && <TotpDialog onAnswer={totpAsk} />}
      </ToastProvider>
    </ThemeProvider>
  );
}
