// Small shared pieces of the views: the error line and the "busy" hook.
import { useCallback, useState } from "react";

import { codeOf } from "../core-client.ts";
import { messageFor } from "../messages.ts";

/** An error line for a code, or nothing. */
export function ErrorText(props: { readonly code: string | undefined }) {
  if (props.code === undefined) {
    return null;
  }
  return (
    <p className="error" role="alert" data-code={props.code}>
      {messageFor(props.code)}
    </p>
  );
}

/**
 * Runs one async action at a time: `busy` while it runs, `error` with the code it failed with.
 * Returns whether it succeeded.
 */
export function useAction(): {
  busy: boolean;
  error: string | undefined;
  setError: (code: string | undefined) => void;
  run: (f: () => Promise<void>) => Promise<boolean>;
} {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>();
  const run = useCallback(async (f: () => Promise<void>) => {
    setBusy(true);
    setError(undefined);
    try {
      await f();
      return true;
    } catch (e) {
      setError(codeOf(e));
      return false;
    } finally {
      setBusy(false);
    }
  }, []);
  return { busy, error, setError, run };
}

/** Reads a secret input's text and empties the element, so the text sits in no React state. */
export function takeSecret(input: HTMLInputElement | null): string {
  if (input === null) {
    return "";
  }
  const text = input.value;
  input.value = "";
  return text;
}
