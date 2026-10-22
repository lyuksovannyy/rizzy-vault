// SPDX-License-Identifier: AGPL-3.0-only

// The Watchtower breach check in the UI (ADR 0053; `breach.ts` module docs): the "Check for
// breaches" control of an item's password and of a generated value, and the vault-wide
// "Password health" report.
//
// Nothing here holds an item's password: `breachCheckItem` runs inside the Worker, which reads
// the password in the core and sends only a 5-character hash prefix. A generated value is
// already on this thread (it is shown), so it crosses back as bytes the Worker zeroes. Results
// are announced in a polite live region; nothing is checked until the user asks.
import type { ItemSummary } from "@rizzy-vault/core";
import { useEffect, useRef, useState } from "react";

import {
  type BreachResult,
  FOUND_CAVEAT,
  PRIVACY_NOTE,
  type ReportState,
  failureText,
  resultText,
  runReport,
} from "../breach.ts";
import { codeOf } from "../core-client.ts";
import type { VaultContext } from "./VaultView.tsx";

/** The result line of one check: a live region, empty until a check finishes. */
function ResultLine(props: {
  readonly result: BreachResult | undefined;
  readonly failure: string | undefined;
  readonly testId: string;
}) {
  const { result, failure } = props;
  let text = "";
  let className = "muted";
  if (failure !== undefined) {
    text = failureText(failure);
  } else if (result !== undefined) {
    text = resultText(result);
    className = result.found ? "breach-found" : "breach-clear";
  }
  return (
    <p className={className} role="status" aria-live="polite" data-testid={props.testId}>
      {text}
      {result?.found === true && failure === undefined && <span className="hint"> {FOUND_CAVEAT}</span>}
    </p>
  );
}

/** The "Check for breaches" control: `check` runs the Worker call (module docs). */
export function BreachCheckButton(props: {
  readonly check: () => Promise<BreachResult | null>;
  readonly label?: string;
  readonly testId: string;
}) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<BreachResult | undefined>();
  const [failure, setFailure] = useState<string | undefined>();
  const live = useRef(true);
  useEffect(
    () => () => {
      live.current = false;
    },
    [],
  );
  const run = async () => {
    if (busy) {
      return;
    }
    setBusy(true);
    setFailure(undefined);
    setResult(undefined);
    try {
      const r = await props.check();
      if (live.current) {
        setResult(r ?? undefined);
      }
    } catch (e) {
      if (live.current) {
        setFailure(codeOf(e));
      }
    } finally {
      if (live.current) {
        setBusy(false);
      }
    }
  };
  return (
    <div className="breach-check">
      <button type="button" className="secondary small" disabled={busy} onClick={() => void run()}>
        {busy ? "Checking…" : (props.label ?? "Check for breaches")}
      </button>
      <ResultLine result={result} failure={failure} testId={props.testId} />
    </div>
  );
}

/** The vault-wide report (module docs). */
export function PasswordHealthPane(props: {
  readonly ctx: VaultContext;
  readonly onOpenItem: (id: string) => void;
}) {
  const { ctx, onOpenItem } = props;
  const [state, setState] = useState<ReportState | undefined>();
  const [loadError, setLoadError] = useState<string | undefined>();
  const cancel = useRef(false);
  const live = useRef(true);
  useEffect(() => {
    live.current = true;
    return () => {
      live.current = false;
      cancel.current = true;
    };
  }, []);

  const running = state?.status === "running";

  const start = async () => {
    cancel.current = false;
    setLoadError(undefined);
    let items: ItemSummary[];
    try {
      items = await ctx.client.call("items", false);
    } catch (e) {
      setLoadError(codeOf(e));
      return;
    }
    const logins = items
      .filter((i) => i.itemType === "login")
      .map((i) => ({ id: i.id, title: i.title === "" ? "(untitled)" : i.title }));
    await runReport(
      logins,
      (id) => ctx.client.call("breachCheckItem", id),
      (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
      () => cancel.current || !live.current,
      (s) => {
        if (live.current) {
          setState(s);
        }
      },
    );
  };

  const failed = typeof state?.status === "object" ? state.status.failed : undefined;
  return (
    <div className="panel narrow password-health">
      <h1>Password health</h1>
      <p>Check the passwords of your Login items against known data breaches.</p>
      <p className="hint">{PRIVACY_NOTE}</p>
      <div className="actions">
        {running ? (
          <button
            type="button"
            className="secondary"
            onClick={() => {
              cancel.current = true;
            }}
          >
            Stop
          </button>
        ) : (
          <button type="button" onClick={() => void start()}>
            {state === undefined ? "Check all passwords" : "Check again"}
          </button>
        )}
      </div>
      {loadError !== undefined && (
        <p className="error" role="alert">
          {failureText(loadError)}
        </p>
      )}
      <div role="status" aria-live="polite" data-testid="health-status">
        {state !== undefined && (
          <p>
            {state.status === "running" && `Checked ${state.checked} of ${state.total} items…`}
            {state.status === "done" &&
              (state.withPassword === 0
                ? "No Login item has a password to check."
                : `Checked ${state.withPassword} password${state.withPassword === 1 ? "" : "s"}: ${
                    state.hits.length === 0
                      ? "none found in known data breaches."
                      : `${state.hits.length} found in known data breaches.`
                  }`)}
            {state.status === "cancelled" && `Stopped after ${state.checked} of ${state.total} items.`}
            {failed !== undefined && failureText(failed)}
          </p>
        )}
      </div>
      {state !== undefined && state.status === "running" && (
        <progress max={Math.max(state.total, 1)} value={state.checked} aria-label="Checking passwords" />
      )}
      {state !== undefined && state.hits.length > 0 && (
        <section aria-labelledby="health-found-heading">
          <h2 id="health-found-heading">Found in data breaches</h2>
          <p className="hint">{FOUND_CAVEAT}</p>
          <ul className="health-list">
            {state.hits.map((h) => (
              <li key={h.id}>
                <button type="button" className="link" onClick={() => onOpenItem(h.id)}>
                  {h.title}
                </button>{" "}
                <span className="muted">
                  seen {h.count === 1 ? "once" : `${h.count.toLocaleString("en")} times`}
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
