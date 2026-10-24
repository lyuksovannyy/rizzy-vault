// SPDX-License-Identifier: AGPL-3.0-only

// Security keys as a server-side second factor (ADR 0058; CRYPTO.md §11.17), in Settings →
// Two-factor authentication: the account's keys with their labels, adding one under a label, and
// removing one. Adding runs `navigator.credentials.create` here, on the UI thread and this
// origin; the core only builds and reads the requests. Adding and removing need a recent login
// (`server_fresh_session_required` otherwise, which the error text words). A key is a second
// factor only: it never unlocks the vault, and recovery does not need it.
import type { SecurityKeyInfo } from "@rizzy-vault/core";
import { ConfirmDialog } from "@rizzy-vault/ui";
import { type FormEvent, useCallback, useEffect, useId, useState } from "react";

import { createCredential, webauthnAvailable } from "../webauthn.ts";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText, useAction } from "./common.tsx";

/** The longest label the server takes, in UTF-8 bytes (rizzy-proto `MAX_WEBAUTHN_LABEL_LEN`). */
const MAX_LABEL_BYTES = 64;

/** The security-key part of the two-factor settings (module docs). */
export function SecurityKeysSection(props: { readonly ctx: VaultContext }) {
  const { ctx } = props;
  const [keys, setKeys] = useState<SecurityKeyInfo[] | undefined>();
  const [label, setLabel] = useState("");
  const [done, setDone] = useState<string | undefined>();
  const [removing, setRemoving] = useState<SecurityKeyInfo | undefined>();
  const [browserError, setBrowserError] = useState(false);
  const { busy, error, run } = useAction();
  const titleId = useId();
  const available = webauthnAvailable();

  const reload = useCallback(async () => {
    setKeys(await ctx.client.call("listSecurityKeys"));
  }, [ctx.client]);

  useEffect(() => {
    void run(reload);
  }, [run, reload]);

  const add = (e: FormEvent) => {
    e.preventDefault();
    setDone(undefined);
    setBrowserError(false);
    void run(async () => {
      const name = label.trim();
      const enrolment = await ctx.client.call("startSecurityKeyEnrolment");
      let credential: string;
      try {
        credential = await createCredential(enrolment.options);
      } catch {
        setBrowserError(true);
        return;
      }
      await ctx.client.call("confirmSecurityKey", enrolment.enrolmentId, name, credential);
      setLabel("");
      setDone(`Security key "${name}" added. Logins now ask for a security key.`);
      await reload();
    });
  };

  const remove = () => {
    const key = removing;
    setRemoving(undefined);
    if (key === undefined) {
      return;
    }
    setDone(undefined);
    void run(async () => {
      await ctx.client.call("removeSecurityKey", key.credentialId);
      setDone(`Security key "${key.label}" removed.`);
      await reload();
    });
  };

  const tooLong = new TextEncoder().encode(label.trim()).length > MAX_LABEL_BYTES;

  return (
    <section aria-labelledby="security-keys-title">
      <h3 id="security-keys-title">Security keys</h3>
      <p>
        A hardware security key (FIDO2/WebAuthn) as your second factor. Logins in this web vault
        then ask you to touch it after your password. The rv command line and the browser
        extension cannot use a security key: keep an authenticator app as well if you use them.
      </p>
      {done !== undefined && <p className="notice">{done}</p>}
      {keys !== undefined && keys.length === 0 && <p>No security key yet.</p>}
      {keys !== undefined && keys.length > 0 && (
        <ul className="security-keys" aria-label="Your security keys">
          {keys.map((key) => (
            <li key={key.credentialId}>
              <span>{key.label}</span>{" "}
              <span className="muted">added {new Date(key.createdMs).toLocaleDateString()}</span>{" "}
              <button
                type="button"
                className="secondary"
                disabled={busy}
                aria-label={`Remove security key ${key.label}`}
                onClick={() => setRemoving(key)}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
      {available ? (
        <form onSubmit={add}>
          <label htmlFor="security-key-label">Name for the new key</label>
          <p id="security-key-pin-hint" className="muted">
            Logging in needs only a touch of the key. While you add it, some keys ask for their PIN
            or fingerprint once; that is the key&apos;s own check, not rizzy-vault&apos;s.
          </p>
          <input
            id="security-key-label"
            aria-describedby="security-key-pin-hint"
            autoComplete="off"
            spellCheck={false}
            required
            maxLength={MAX_LABEL_BYTES}
            aria-invalid={tooLong}
            value={label}
            onChange={(e) => setLabel(e.currentTarget.value)}
          />
          <div className="actions">
            <button type="submit" disabled={busy || tooLong || label.trim() === ""}>
              Add security key
            </button>
          </div>
        </form>
      ) : (
        <p>This browser cannot use security keys here.</p>
      )}
      {browserError && (
        <p className="error" role="alert">
          The security key did not answer, or the browser refused it. Try again.
        </p>
      )}
      <ErrorText code={error} />
      <ConfirmDialog
        open={removing !== undefined}
        titleId={titleId}
        title="Remove this security key?"
        description="Logins will no longer accept it. If it was your only second factor, logins will ask only for your password and Secret Key."
        confirmLabel="Remove"
        danger
        onConfirm={remove}
        onCancel={() => setRemoving(undefined)}
      />
    </section>
  );
}
