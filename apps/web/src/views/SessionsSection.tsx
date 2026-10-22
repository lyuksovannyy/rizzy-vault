// SPDX-License-Identifier: AGPL-3.0-only

// The account's sessions (ADR 0075 §9), under the Devices pane: what the server reports as open,
// with "End" on another session's password login or recovery row and "End all other sessions".
//
// - **Device sessions are not ended here** (§5): a native device re-authenticates on its next
//   request. Its row says to suspend or revoke the device from another of your devices, which
//   the web vault cannot do (CRYPTO.md §11's flow table).
// - **Freshness** (R3, R4): ending needs a login of at most five minutes. When the server says
//   the session is too old (`server_fresh_session_required`), the pane asks for the Secret Key
//   and master password, logs in again, switches to the new session, ends the old one, and
//   then does what was asked.
// - **The list is the server's word** (AR-9): the pane says so, and says that ending a session
//   does not stop anyone who knows the master password and Secret Key (§8).
import type { SessionListView, SessionRowView } from "@rizzy-vault/core";
import { ConfirmDialog, SecretField } from "@rizzy-vault/ui";
import { type FormEvent, useCallback, useEffect, useId, useRef, useState } from "react";

import { codeOf, secretBytes } from "../core-client.ts";
import { DEVICE_LABEL_HEX_LEN } from "../notices.ts";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText, takeSecret, useAction } from "./common.tsx";

/** What the user asked to end: one row, or every other session. */
type Pending = { readonly kind: "one"; readonly row: SessionRowView } | { readonly kind: "others" };

/** The short label of a device id, as the device list shows it. */
function deviceLabel(id: string | undefined): string {
  return id === undefined ? "unknown device" : `${id.slice(0, DEVICE_LABEL_HEX_LEN)}…`;
}

/** The words of a row's kind (ADR 0075 §9). */
export function sessionLabel(row: SessionRowView): string {
  switch (row.kind) {
    case "password-login":
      return "Web or password login";
    case "password-recheck":
      return `Password re-check on device ${deviceLabel(row.deviceId)}`;
    case "device":
      return `Device ${deviceLabel(row.deviceId)}`;
    case "recovery":
      return "Account recovery in progress";
    default:
      return "Session of an unknown kind";
  }
}

/** What a row offers instead of "End", if anything (ADR 0075 §5, §9). */
export function sessionHint(row: SessionRowView): string | undefined {
  if (row.current) {
    return "This browser. Locking the vault ends it.";
  }
  if (row.kind === "device") {
    return "Use another of your devices to suspend or revoke it.";
  }
  if (row.kind === "recovery") {
    return "If you did not start a recovery, cancel it from one of your enrolled devices.";
  }
  return undefined;
}

/** The Sessions section (module docs). */
export function SessionsSection(props: { readonly ctx: VaultContext }) {
  const { ctx } = props;
  const [list, setList] = useState<SessionListView | undefined>();
  const [loadError, setLoadError] = useState<string | undefined>();
  const [pending, setPending] = useState<Pending | undefined>();
  const [confirming, setConfirming] = useState(false);
  const [reauth, setReauth] = useState(false);
  const [done, setDone] = useState<string | undefined>();
  const [reload, setReload] = useState(0);
  const { busy, error, setError, run } = useAction();
  const secretKey = useRef<HTMLInputElement>(null);
  const password = useRef<HTMLInputElement>(null);
  const titleId = useId();

  useEffect(() => {
    let live = true;
    ctx.client.call("sessions").then(
      (l) => {
        if (live) {
          setList(l);
          setLoadError(undefined);
        }
      },
      (e: unknown) => live && setLoadError(codeOf(e)),
    );
    return () => {
      live = false;
    };
  }, [ctx.client, ctx.revision, reload]);

  /** Sends what `p` asks for; on a stale session, asks for the credentials first. */
  const end = useCallback(
    (p: Pending) =>
      run(async () => {
        setDone(undefined);
        try {
          if (p.kind === "one") {
            await ctx.client.call("endSession", p.row.id);
          } else {
            await ctx.client.call("endOtherSessions");
          }
        } catch (e) {
          if (codeOf(e) === "server_fresh_session_required") {
            setPending(p);
            setReauth(true);
            return;
          }
          throw e;
        }
        const notices = await ctx.client.call("sessionNotices");
        setDone(p.kind === "one" ? notices.oneEnded : notices.othersEnded);
        setPending(undefined);
        setReload((n) => n + 1);
      }),
    [ctx.client, run],
  );

  const ask = (p: Pending) => {
    setPending(p);
    setConfirming(true);
  };

  const confirmed = () => {
    setConfirming(false);
    if (pending !== undefined) {
      void end(pending);
    }
  };

  const submitReauth = (e: FormEvent) => {
    e.preventDefault();
    const sk = secretBytes(takeSecret(secretKey.current));
    const pw = secretBytes(takeSecret(password.current));
    const p = pending;
    void run(async () => {
      await ctx.client.call("refreshSession", sk, pw);
      setReauth(false);
    }).then((ok) => {
      if (ok && p !== undefined) {
        void end(p);
      }
    });
  };

  const others = list?.sessions.filter((s) => s.endable).length ?? 0;

  return (
    <section aria-labelledby="sessions-title">
      <h2 id="sessions-title">Sessions</h2>
      <p className="muted">
        The sessions the server reports as open for this account. This is the server&apos;s word: a
        server that misbehaves could leave some out. Ending a session does not stop anyone who knows
        your master password and Secret Key from logging in again; change your password if you think
        someone does.
      </p>
      <ErrorText code={loadError} />
      {list !== undefined && (
        <table aria-label="Sessions">
          <thead>
            <tr>
              <th scope="col">Session</th>
              <th scope="col">Opened</th>
              <th scope="col">Expires</th>
              <th scope="col">Action</th>
            </tr>
          </thead>
          <tbody>
            {list.sessions.map((s) => (
              <tr key={s.id} aria-current={s.current ? "true" : undefined}>
                <td>
                  {sessionLabel(s)}
                  {s.current && <strong> (this session)</strong>}
                </td>
                <td>{new Date(s.createdAtMs).toLocaleString()}</td>
                <td>{new Date(s.expiresAtMs).toLocaleString()}</td>
                <td>
                  {s.endable ? (
                    <button
                      type="button"
                      className="secondary"
                      disabled={busy}
                      aria-label={`End ${sessionLabel(s)} opened ${new Date(s.createdAtMs).toLocaleString()}`}
                      onClick={() => ask({ kind: "one", row: s })}
                    >
                      End
                    </button>
                  ) : (
                    <span className="muted">{sessionHint(s)}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {list?.truncated === true && (
        <p className="muted">The server listed only the newest sessions; there are more.</p>
      )}
      <div className="actions">
        <button
          type="button"
          className="secondary"
          disabled={busy || list === undefined || others === 0}
          onClick={() => ask({ kind: "others" })}
        >
          End all other sessions
        </button>
      </div>
      {reauth && (
        <form onSubmit={submitReauth} aria-labelledby="sessions-reauth-title">
          <h3 id="sessions-reauth-title">Log in again to end sessions</h3>
          <p>
            Ending a session needs a login of at most five minutes. Enter your Secret Key and master
            password: this browser switches to the new login and ends its old session.
          </p>
          <SecretField label="Secret Key" name="sessions-secret-key" inputRef={secretKey} required />
          <SecretField
            label="Master password"
            name="sessions-master-password"
            inputRef={password}
            required
          />
          <div className="actions">
            <button type="submit" disabled={busy}>
              {busy ? "Checking…" : "Log in and continue"}
            </button>
            <button
              type="button"
              className="secondary"
              disabled={busy}
              onClick={() => {
                setReauth(false);
                setPending(undefined);
                setError(undefined);
              }}
            >
              Cancel
            </button>
          </div>
        </form>
      )}
      <ErrorText code={error} />
      {done !== undefined && (
        <p className="status" role="status">
          {done}
        </p>
      )}
      <ConfirmDialog
        open={confirming}
        titleId={titleId}
        title={
          pending?.kind === "one" ? `End "${sessionLabel(pending.row)}"?` : "End all other sessions?"
        }
        description={
          pending?.kind === "one"
            ? "That session is logged out at its next request."
            : "Every other web or password login, and any account recovery session, is logged out at its next request. Your devices stay logged in."
        }
        confirmLabel="End"
        danger
        onConfirm={confirmed}
        onCancel={() => {
          setConfirming(false);
          setPending(undefined);
        }}
      />
    </section>
  );
}
