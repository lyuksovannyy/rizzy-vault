// Server two-factor authentication (TOTP at login, CRYPTO.md §11.15): enrol with an
// authenticator app, confirm with its current code, or remove it with a current code. The
// enrolment secret is shown once, in the secret-field component. There is no QR code in M1:
// the web vault would need an encoder library, and the `otpauth://` URI and the Base32
// secret can be typed or pasted into the authenticator.
import type { TwoFactorSetup } from "@rizzy-vault/core";
import { SecretField } from "@rizzy-vault/ui";
import { type FormEvent, useState } from "react";

import type { VaultContext } from "./VaultView.tsx";
import { ErrorText, useAction } from "./common.tsx";

/** The two-factor settings (module docs). */
export function TwoFactorPane(props: { readonly ctx: VaultContext }) {
  const { ctx } = props;
  const [setup, setSetup] = useState<TwoFactorSetup | undefined>();
  const [code, setCode] = useState("");
  const [disableCode, setDisableCode] = useState("");
  const [done, setDone] = useState<string | undefined>();
  const { busy, error, run } = useAction();

  const confirm = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      await ctx.client.call("confirmTwoFactor", code.trim());
      setSetup(undefined);
      setCode("");
      setDone("Two-factor authentication is on. Logins now ask for a code.");
    });
  };

  const disable = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      await ctx.client.call("disableTwoFactor", disableCode.trim());
      setDisableCode("");
      setDone("Two-factor authentication is off.");
    });
  };

  return (
    <div className="panel narrow">
      <h2>Two-factor authentication</h2>
      {done !== undefined && <p className="notice">{done}</p>}
      {setup === undefined ? (
        <div className="actions">
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              void run(async () => {
                setDone(undefined);
                setSetup(await ctx.client.call("enableTwoFactor"));
              })
            }
          >
            Set up an authenticator app
          </button>
        </div>
      ) : (
        <form onSubmit={confirm}>
          <p>Add this account to your authenticator app, then enter the code it shows.</p>
          <SecretField label="Setup key (Base32)" name="totp-secret" value={setup.secret} />
          <SecretField label="Setup URI" name="totp-uri" value={setup.otpauthUri} />
          <label htmlFor="totp-confirm">Code from the app</label>
          <input
            id="totp-confirm"
            inputMode="numeric"
            autoComplete="one-time-code"
            spellCheck={false}
            required
            value={code}
            onChange={(e) => setCode(e.currentTarget.value)}
          />
          <div className="actions">
            <button type="submit" disabled={busy}>
              Turn on
            </button>
          </div>
        </form>
      )}
      <form onSubmit={disable}>
        <h3>Turn two-factor off</h3>
        <label htmlFor="totp-disable">Current code</label>
        <input
          id="totp-disable"
          inputMode="numeric"
          autoComplete="one-time-code"
          spellCheck={false}
          required
          value={disableCode}
          onChange={(e) => setDisableCode(e.currentTarget.value)}
        />
        <div className="actions">
          <button type="submit" className="secondary" disabled={busy}>
            Turn off
          </button>
        </div>
      </form>
      <ErrorText code={error} />
    </div>
  );
}
