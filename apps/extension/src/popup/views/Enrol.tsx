// The enrolment form (CRYPTO.md §11.2; ADR 0036 §3): server URL, account (login name), Secret
// Key and master password, same four values the web vault's own login screen collects for a new
// device. `SecretField` renders the Secret Key and the master password (INV-68: both are
// secrets); the server origin and login name are not.
import { useRef, useState } from "react";

import { SecretField } from "@rizzy-vault/ui";

import type { ExtensionClient } from "../../core/client.ts";

export interface EnrolViewProps {
  readonly client: ExtensionClient;
  readonly onEnrolled: () => void;
}

export function EnrolView({ client, onEnrolled }: EnrolViewProps) {
  const serverOriginRef = useRef<HTMLInputElement>(null);
  const loginNameRef = useRef<HTMLInputElement>(null);
  const secretKeyRef = useRef<HTMLInputElement>(null);
  const masterPasswordRef = useRef<HTMLInputElement>(null);
  const totpRef = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | undefined>(undefined);
  const [pending, setPending] = useState(false);

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        const serverOrigin = serverOriginRef.current?.value.trim() ?? "";
        const loginName = loginNameRef.current?.value.trim() ?? "";
        const secretKey = secretKeyRef.current?.value ?? "";
        const masterPassword = masterPasswordRef.current?.value ?? "";
        const totp = totpRef.current?.value.trim();
        setPending(true);
        setError(undefined);
        void client
          .enrol({ serverOrigin, loginName, secretKey, masterPassword, ...(totp !== undefined && totp !== "" ? { totp } : {}) })
          .then(onEnrolled)
          .catch((err: unknown) => {
            setError(err instanceof Error ? err.message : "enrol_failed");
          })
          .finally(() => {
            setPending(false);
            // Secrets are read from the elements above and never held in React state (same
            // pattern as the web vault's login form); clear them here regardless of outcome.
            if (secretKeyRef.current !== null) {
              secretKeyRef.current.value = "";
            }
            if (masterPasswordRef.current !== null) {
              masterPasswordRef.current.value = "";
            }
          });
      }}
    >
      <h2>Set up this device</h2>
      <label>
        Server URL
        <input ref={serverOriginRef} type="url" name="serverOrigin" required autoFocus placeholder="https://vault.example.com" />
      </label>
      <label>
        Account (login name)
        <input ref={loginNameRef} type="text" name="loginName" required />
      </label>
      <SecretField label="Secret Key" name="secretKey" inputRef={secretKeyRef} required />
      <SecretField label="Master password" name="masterPassword" inputRef={masterPasswordRef} required />
      <label>
        Two-factor code (only if this account has 2FA enabled)
        <input ref={totpRef} type="text" name="totp" inputMode="numeric" autoComplete="off" />
      </label>
      <button type="submit" disabled={pending}>
        {pending ? "Setting up…" : "Set up"}
      </button>
      {error !== undefined ? (
        <p role="alert">
          {error === "totp_required"
            ? "This account needs a two-factor code — enter it above and try again."
            : error === "already_enrolled"
              ? "This browser is already set up for an account. Reset the extension to enrol a different one."
              : error}
        </p>
      ) : undefined}
    </form>
  );
}
