// The unlock form (ADR 0036 §3, §4). `SecretField` is the one component INV-68 allows to render
// a secret input; the typed master password is read from the element on submit and the element
// cleared, never held in React state (same pattern as the web vault's login form).
import { useRef, useState } from "react";

import { SecretField } from "@rizzy-vault/ui";

import type { ExtensionClient } from "../../core/client.ts";

export interface LockedViewProps {
  readonly client: ExtensionClient;
  readonly onUnlocked: () => void;
}

export function LockedView({ client, onUnlocked }: LockedViewProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | undefined>(undefined);
  const [pending, setPending] = useState(false);

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        const value = inputRef.current?.value ?? "";
        setPending(true);
        setError(undefined);
        void client
          .unlock(value)
          .then(onUnlocked)
          .catch((err: unknown) => {
            setError(err instanceof Error ? err.message : "unlock_failed");
          })
          .finally(() => {
            setPending(false);
            if (inputRef.current !== null) {
              inputRef.current.value = "";
            }
          });
      }}
    >
      <SecretField label="Master password" name="masterPassword" inputRef={inputRef} required autoFocus />
      <button type="submit" disabled={pending}>
        Unlock
      </button>
      {error !== undefined ? (
        <p role="alert">
          {error === "bindings_not_implemented"
            ? "Device enrolment/unlock is not wired in yet (M2 work in progress)."
            : error}
        </p>
      ) : undefined}
    </form>
  );
}
