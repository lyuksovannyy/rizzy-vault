// Signup in the order of "Secrets before commit" (CRYPTO.md §11): the registration runs, the
// Emergency Kit is shown once (with a download), the user re-types the last group of the
// Secret Key, and only then is the account committed and the first session opened.
import { SecretField } from "@rizzy-vault/ui";
import { type FormEvent, useRef, useState } from "react";

import { type CoreClient, codeOf, secretBytes } from "../core-client.ts";
import { dateStamp, saveFile } from "../download.ts";
import { KIT_LOSS_WARNING, KIT_TAKEOVER_WARNING, type ShownKit, kitHtml } from "../kit.ts";
import type { SessionInfo } from "../protocol.ts";
import { ErrorText, takeSecret, useAction } from "./common.tsx";

/** The signup screens. */
export function SignupView(props: {
  readonly client: CoreClient;
  readonly onDone: (loginName: string, session: SessionInfo) => void;
  readonly onCancel: () => void;
}) {
  const { client } = props;
  const [step, setStep] = useState<"form" | "kit" | "commit-failed">("form");
  const [loginName, setLoginName] = useState("");
  const [invite, setInvite] = useState("");
  const [recovery, setRecovery] = useState(true);
  const [kit, setKit] = useState<ShownKit | undefined>();
  const [lastGroup, setLastGroup] = useState("");
  const password = useRef<HTMLInputElement>(null);
  const repeat = useRef<HTMLInputElement>(null);
  const { busy, error, setError, run } = useAction();

  const start = (e: FormEvent) => {
    e.preventDefault();
    const pw = takeSecret(password.current);
    const again = takeSecret(repeat.current);
    if (pw !== again) {
      setError("passwords_differ");
      return;
    }
    const name = loginName.trim();
    void run(async () => {
      await client.call(
        "signupStart",
        name,
        secretBytes(pw),
        invite.trim() === "" ? undefined : invite.trim(),
        recovery,
      );
      const k = await client.call("signupKit");
      const decoder = new TextDecoder();
      setKit({
        serverOrigin: k.serverOrigin,
        loginName: k.loginName,
        secretKey: decoder.decode(k.secretKey),
        recoveryCode: k.recoveryCode === undefined ? undefined : decoder.decode(k.recoveryCode),
      });
      k.secretKey.fill(0);
      k.recoveryCode?.fill(0);
      setStep("kit");
    });
  };

  /**
   * Sends the commit, then opens the first session. A wrong last group is refused before
   * anything is sent, so the kit step stays; any other failure leaves the commit's outcome
   * unknown, and "Try again" sends the same bytes (ADR 0028 "Register finish").
   */
  const finish = async (send: () => Promise<void>) => {
    let failed: string | undefined;
    const ok = await run(async () => {
      try {
        await send();
      } catch (e) {
        failed = codeOf(e);
        throw e;
      }
    });
    if (!ok) {
      if (failed !== "emergency_kit_not_confirmed") {
        setStep("commit-failed");
      }
      return;
    }
    await run(async () => {
      const session = await client.call("signupLogin");
      setKit(undefined);
      props.onDone(kit?.loginName ?? loginName.trim(), session);
    });
  };

  const confirm = (e: FormEvent) => {
    e.preventDefault();
    void finish(() => client.call("signupConfirm", lastGroup.trim()));
  };

  const cancel = () => {
    void client.call("signupCancel");
    setKit(undefined);
    props.onCancel();
  };

  if (step === "form") {
    return (
      <form className="panel narrow" onSubmit={start} aria-labelledby="signup-title">
        <h1 id="signup-title">Create an account</h1>
        <label htmlFor="signup-name">Login name</label>
        <input
          id="signup-name"
          name="username"
          autoComplete="off"
          spellCheck={false}
          autoCapitalize="off"
          required
          autoFocus
          value={loginName}
          onChange={(e) => setLoginName(e.currentTarget.value)}
        />
        <SecretField label="Master password" name="new-master-password" inputRef={password} required />
        <SecretField label="Repeat the master password" name="repeat-master-password" inputRef={repeat} required />
        <label htmlFor="signup-invite">Invite (if this server asks for one)</label>
        <input
          id="signup-invite"
          name="invite"
          autoComplete="off"
          spellCheck={false}
          value={invite}
          onChange={(e) => setInvite(e.currentTarget.value)}
        />
        <label className="check">
          <input type="checkbox" checked={recovery} onChange={(e) => setRecovery(e.currentTarget.checked)} />
          Issue a recovery code (recommended)
        </label>
        {error === "passwords_differ" ? (
          <p className="error" role="alert">The two passwords differ.</p>
        ) : (
          <ErrorText code={error} />
        )}
        <div className="actions">
          <button type="submit" disabled={busy}>
            {busy ? "Creating…" : "Continue"}
          </button>
          <button type="button" className="secondary" onClick={cancel} disabled={busy}>
            Back to login
          </button>
        </div>
      </form>
    );
  }

  return (
    <div className="panel" aria-labelledby="kit-title">
      <h1 id="kit-title">Your Emergency Kit</h1>
      <p className="warning">
        This is shown once. Save or print it now. Without the Secret Key you cannot log in on a
        new browser or device, and nobody, the server operator included, can recover it.
      </p>
      <p className="warning" data-testid="kit-warnings">
        <strong>{KIT_TAKEOVER_WARNING}</strong> {KIT_LOSS_WARNING}
      </p>
      {kit !== undefined && (
        <dl className="kit" data-testid="emergency-kit">
          <dt>Server</dt>
          <dd>{kit.serverOrigin}</dd>
          <dt>Login name</dt>
          <dd>{kit.loginName}</dd>
          <dt>Secret Key</dt>
          <dd className="mono" data-testid="kit-secret-key">{kit.secretKey}</dd>
          {kit.recoveryCode !== undefined && (
            <>
              <dt>Recovery code</dt>
              <dd className="mono" data-testid="kit-recovery-code">{kit.recoveryCode}</dd>
            </>
          )}
        </dl>
      )}
      <div className="actions">
        <button
          type="button"
          className="secondary"
          onClick={() =>
            kit !== undefined &&
            saveFile(
              `rizzy-vault-emergency-kit-${dateStamp()}.html`,
              new TextEncoder().encode(kitHtml(kit)),
              "text/html;charset=utf-8",
            )
          }
        >
          Download the kit
        </button>
        <button type="button" className="secondary" onClick={() => window.print()}>
          Print
        </button>
      </div>
      {step === "kit" ? (
        <form onSubmit={confirm}>
          <label htmlFor="kit-confirm">
            To confirm you saved it, type the last group of your Secret Key
          </label>
          <input
            id="kit-confirm"
            name="kit-confirm"
            autoComplete="off"
            spellCheck={false}
            autoCapitalize="characters"
            required
            value={lastGroup}
            onChange={(e) => setLastGroup(e.currentTarget.value)}
          />
          <ErrorText code={error} />
          <div className="actions">
            <button type="submit" disabled={busy}>
              {busy ? "Creating the account…" : "Create the account"}
            </button>
            <button type="button" className="secondary" onClick={cancel} disabled={busy}>
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <div>
          <ErrorText code={error} />
          <p>The account may or may not have been created. Sending the same request again is safe.</p>
          <div className="actions">
            <button type="button" disabled={busy} onClick={() => void finish(() => client.call("signupRetryCommit"))}>
              Try again
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
