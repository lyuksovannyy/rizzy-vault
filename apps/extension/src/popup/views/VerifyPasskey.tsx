// SPDX-License-Identifier: AGPL-3.0-only

// The passkey re-verification view (ADR 0110 §7 points 3–6): shown before anything else when the
// popup's active tab has a passkey ceremony waiting for a master-password verification. It shows
// what the background vouches for (the verified origin, the `rpId`, the credential's user name,
// the kind) and asks for the master password; it chooses nothing (the passkey or the vault was
// chosen at the consent click). The toolbar popup is the only place this password is entered
// (INV-123). As in `Locked.tsx`, the password is read from the element on submit and the element
// cleared, never held in React state; replies are fixed sentences that echo no input.
import { useRef, useState } from "react";

import { SecretField } from "@rizzy-vault/ui";

import type { ExtensionClient } from "../../core/client.ts";
import type { PasskeyVerificationView, UvReplyCode } from "../../messaging/contract.ts";
import { uvKindLabel, uvReplySentence } from "../passkey-verify.ts";

export interface VerifyPasskeyViewProps {
  readonly client: ExtensionClient;
  readonly ceremony: PasskeyVerificationView;
  /** Called with every reply that ends this view: all but `uv_wrong_password`. */
  readonly onFinished: (code: UvReplyCode) => void;
}

export function VerifyPasskeyView({ client, ceremony, onFinished }: VerifyPasskeyViewProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [reply, setReply] = useState<UvReplyCode | undefined>(undefined);
  const [pending, setPending] = useState(false);

  const settle = (code: UvReplyCode) => {
    setReply(code);
    if (code !== "uv_wrong_password") {
      onFinished(code);
    }
  };

  return (
    <form
      aria-labelledby="verify-heading"
      onSubmit={(e) => {
        e.preventDefault();
        const value = inputRef.current?.value ?? "";
        setPending(true);
        setReply(undefined);
        void client
          .passkeyVerifySubmit(ceremony.ceremonyToken, value)
          .catch((): UvReplyCode => "uv_ceremony_gone")
          .then(settle)
          .finally(() => {
            setPending(false);
            if (inputRef.current !== null) {
              inputRef.current.value = "";
            }
          });
      }}
    >
      <h2 id="verify-heading">Verify to continue</h2>
      <dl>
        <dt>Request</dt>
        <dd>{uvKindLabel(ceremony.kind)}</dd>
        <dt>Website</dt>
        <dd>{ceremony.origin}</dd>
        <dt>Relying party</dt>
        <dd>{ceremony.rpId}</dd>
        <dt>Account</dt>
        <dd>{ceremony.userName}</dd>
      </dl>
      <SecretField label="Master password" name="masterPassword" inputRef={inputRef} required autoFocus />
      <button type="submit" disabled={pending}>
        Verify
      </button>
      <button
        type="button"
        disabled={pending}
        onClick={() => {
          setPending(true);
          void client
            .passkeyVerifyCancel(ceremony.ceremonyToken)
            .catch((): UvReplyCode => "uv_cancelled")
            .then(settle)
            .finally(() => setPending(false));
        }}
      >
        Cancel
      </button>
      {reply !== undefined ? <p role="alert">{uvReplySentence(reply)}</p> : undefined}
    </form>
  );
}
