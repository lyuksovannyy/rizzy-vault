// Small shared pieces of the views: the error line and the "busy" hook.
import { useCallback, useRef, useState } from "react";

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
 *
 * The guard against a second, overlapping run is a ref, checked and set synchronously inside
 * the call — not the `busy` state, which only takes effect once React re-renders the disabled
 * button. Two clicks fired in the same tick (a fast double click, or Playwright's unthrottled
 * clicks) would otherwise both pass a `disabled={busy}` check that has not re-rendered yet,
 * running the action twice at once; the second call here is dropped instead.
 */
export function useAction(): {
  busy: boolean;
  error: string | undefined;
  setError: (code: string | undefined) => void;
  run: (f: () => Promise<void>) => Promise<boolean>;
} {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>();
  const running = useRef(false);
  const run = useCallback(async (f: () => Promise<void>) => {
    if (running.current) {
      return false;
    }
    running.current = true;
    setBusy(true);
    setError(undefined);
    try {
      await f();
      return true;
    } catch (e) {
      setError(codeOf(e));
      return false;
    } finally {
      running.current = false;
      setBusy(false);
    }
  }, []);
  return { busy, error, setError, run };
}

/** Reads a secret input's text and empties the element, so the text sits in no React state.
 * Only call this once the save it is for has already succeeded (see `peekSecret`): clearing the
 * element before that point would drop the value from a retried save. */
export function takeSecret(input: HTMLInputElement | null): string {
  if (input === null) {
    return "";
  }
  const text = input.value;
  input.value = "";
  return text;
}

/** Reads a secret input's text without clearing the element. Used to build a save's changeset
 * synchronously, before the async save has even been attempted: the element must still hold the
 * value if that attempt fails, so a retry resends the same secret instead of silently omitting
 * it. The caller clears the element itself (`takeSecret`, or `input.value = ""`) only after the
 * save has resolved successfully. */
export function peekSecret(input: HTMLInputElement | null): string {
  return input?.value ?? "";
}
