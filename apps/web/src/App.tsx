// SPDX-License-Identifier: AGPL-3.0-only

// The web vault's top level: start the core, then log in or sign up, then the vault.
//
// The web vault persists nothing (CRYPTO.md §11.4): every session is an OPAQUE login, and a
// lock or a reload ends it. "Unlock" is therefore a new login, with the login name kept in
// memory only.
import { ToastProvider } from "@rizzy-vault/ui";
import type { SecurityKeyAnswer } from "@rizzy-vault/core";
import { useCallback, useEffect, useRef, useState } from "react";

import { type CoreClient, codeOf } from "./core-client.ts";
import { messageFor } from "./messages.ts";
import type { SessionInfo } from "./protocol.ts";
import { ThemeProvider } from "./theme.ts";
import { LoginView } from "./views/LoginView.tsx";
import { SignupView } from "./views/SignupView.tsx";
import { SecurityKeyDialog } from "./views/SecurityKeyDialog.tsx";
import { TotpDialog } from "./views/TotpDialog.tsx";
import { VaultView } from "./views/VaultView.tsx";

/** Where the app is. */
type Phase =
  | { readonly kind: "starting" }
  | { readonly kind: "unavailable"; readonly code: string }
  | { readonly kind: "login"; readonly notice?: string }
  | { readonly kind: "signup" }
  /** `guide`: open the getting-started guide first (after signup only; `onboarding.ts`). */
  | { readonly kind: "vault"; readonly session: SessionInfo; readonly guide: boolean };

/** The web vault (module docs). */
export function App(props: { readonly client: CoreClient }) {
  const { client } = props;
  const [phase, setPhase] = useState<Phase>({ kind: "starting" });
  const [loginName, setLoginName] = useState("");
  const [totpAsk, setTotpAsk] = useState<((code: string | null) => void) | undefined>();
  const [keyAsk, setKeyAsk] = useState<
    | {
        readonly options: string;
        readonly totpAllowed: boolean;
        readonly retried: boolean;
        readonly answer: (answer: SecurityKeyAnswer | null) => void;
      }
    | undefined
  >();
  const lastKeyRetry = useRef(false);

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
    client.setSecurityKeyPrompt(
      (request) =>
        new Promise<SecurityKeyAnswer | null>((resolve) => {
          const retried = lastKeyRetry.current;
          lastKeyRetry.current = false;
          setKeyAsk({
            ...request,
            retried,
            answer: (answer) => {
              lastKeyRetry.current = answer?.kind === "retry";
              setKeyAsk(undefined);
              resolve(answer);
            },
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
    setPhase({ kind: "vault", session, guide: false });
  }, []);

  const onSignedUp = useCallback((name: string, session: SessionInfo) => {
    setLoginName(name);
    setPhase({ kind: "vault", session, guide: true });
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
          onDone={onSignedUp}
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
          startWithGuide={phase.guide}
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
        {keyAsk !== undefined && (
          <SecurityKeyDialog
            options={keyAsk.options}
            totpAllowed={keyAsk.totpAllowed}
            retried={keyAsk.retried}
            onAnswer={keyAsk.answer}
          />
        )}
      </ToastProvider>
    </ThemeProvider>
  );
}
