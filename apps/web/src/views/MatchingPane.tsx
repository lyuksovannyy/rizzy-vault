// SPDX-License-Identifier: AGPL-3.0-only

// Website matching (ADR 0037 §6–§7, ADR 0042; ROADMAP §4.4 "User-defined equivalence groups +
// ability to disable a global group"): the account-level match default, the account's own
// equivalence groups, and the global groups it turned off. All three live in the signed account
// state's `ACCOUNT_SETTINGS`; each change is one `account/commit` the core builds and checks
// (`changeMatchSettings`), so the server can neither read them nor bring back an older version.
//
// "Check a website" asks the core what autofill would offer on an address under these settings
// (the same decision the extension makes), so a change can be seen before it is relied on.
//
// The server takes a settings change only within five minutes of logging in (CRYPTO.md §11
// "Replacing credentials"); after that the change fails with "Log in again to do this."
import type { EquivalenceGroupInfo, MatchModeValue, MatchSettings, SettingsChange } from "@rizzy-vault/core";
import { type FormEvent, useCallback, useEffect, useId, useState } from "react";

import { codeOf } from "../core-client.ts";
import {
  ACCOUNT_DEFAULT_OPTIONS,
  type CheckedItem,
  checkedItems,
  groupLabel,
  parseGroupDomains,
} from "../match-settings.ts";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText, useAction } from "./common.tsx";

/** One global group with its on/off switch. */
function GlobalGroupRow(props: {
  readonly group: EquivalenceGroupInfo;
  readonly busy: boolean;
  readonly onChange: (change: SettingsChange) => void;
}) {
  const { group } = props;
  const label = groupLabel(group.domains);
  return (
    <li>
      <span className={group.disabled ? "muted" : undefined}>{label}</span>{" "}
      <button
        type="button"
        className="secondary"
        disabled={props.busy}
        aria-label={`${group.disabled ? "Turn on" : "Turn off"} the group ${label}`}
        onClick={() =>
          props.onChange({ kind: group.disabled ? "enableGlobalGroup" : "disableGlobalGroup", id: group.id })
        }
      >
        {group.disabled ? "Turn on" : "Turn off"}
      </button>
    </li>
  );
}

/** "Check a website" (module docs). */
function CheckWebsite(props: { readonly ctx: VaultContext; readonly settings: MatchSettings }) {
  const { ctx } = props;
  const inputId = useId();
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<{ readonly host: string; readonly items: readonly CheckedItem[] } | undefined>();
  const { busy, error, run } = useAction();

  const check = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      setResult(undefined);
      const decision = await ctx.client.call("matchCandidates", url.trim());
      const items = await ctx.client.call("items", false);
      setResult({ host: decision.pageHost, items: checkedItems(decision, items) });
    });
  };

  // A settings change can change the answer: clear a stale one.
  useEffect(() => {
    setResult(undefined);
  }, [props.settings]);

  return (
    <form onSubmit={check} aria-label="Check a website">
      <h3>Check a website</h3>
      <label htmlFor={inputId}>Website address</label>
      <input
        id={inputId}
        type="url"
        value={url}
        placeholder="https://example.com/login"
        onChange={(e) => setUrl(e.currentTarget.value)}
        required
      />
      <div className="actions">
        <button type="submit" className="secondary" disabled={busy}>
          Check
        </button>
      </div>
      <ErrorText code={error} />
      {result !== undefined && (
        <div role="status" aria-label={`Matching items on ${result.host}`}>
          {result.items.length === 0 ? (
            <p className="muted">No item would be offered on {result.host}.</p>
          ) : (
            <ul className="matching-list">
              {result.items.map((item) => (
                <li key={item.id}>
                  {item.title}
                  {item.viaGroup && <span className="muted"> (through an equivalence group, saved for {item.savedHost})</span>}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </form>
  );
}

/** The Website matching settings (module docs). */
export function MatchingPane(props: { readonly ctx: VaultContext }) {
  const { ctx } = props;
  const titleId = useId();
  const defaultId = useId();
  const domainsId = useId();
  const [settings, setSettings] = useState<MatchSettings | undefined>();
  const [loadError, setLoadError] = useState<string | undefined>();
  const [domains, setDomains] = useState("");
  const [done, setDone] = useState<string | undefined>();
  const { busy, error, run } = useAction();

  const load = useCallback(async () => {
    try {
      setSettings(await ctx.client.call("matchSettings"));
      setLoadError(undefined);
    } catch (e) {
      setSettings(undefined);
      setLoadError(codeOf(e));
    }
  }, [ctx.client]);

  useEffect(() => {
    void load();
  }, [load, ctx.revision]);

  const change = (next: SettingsChange, message: string, after?: () => void) => {
    setDone(undefined);
    void run(async () => {
      await ctx.client.call("changeMatchSettings", next);
      after?.();
      setDone(message);
      await load();
    });
  };

  const addGroup = (e: FormEvent) => {
    e.preventDefault();
    change({ kind: "addUserGroup", domains: parseGroupDomains(domains) }, "The group is saved.", () => setDomains(""));
  };

  return (
    <div className="panel narrow" role="region" aria-labelledby={titleId}>
      <h2 id={titleId}>Website matching</h2>
      <p className="muted">
        Which saved logins autofill offers on a website. These settings are end-to-end encrypted
        with your account and apply on every device.
      </p>
      {loadError !== undefined && <ErrorText code={loadError} />}
      {done !== undefined && (
        <p className="notice" role="status">
          {done}
        </p>
      )}
      <ErrorText code={error} />
      {settings !== undefined && (
        <>
          <label htmlFor={defaultId}>Default match for websites</label>
          <select
            id={defaultId}
            value={settings.matchDefault}
            disabled={busy}
            onChange={(e) => {
              const mode = Number.parseInt(e.currentTarget.value, 10);
              change({ kind: "matchDefault", mode: mode as MatchModeValue }, "The default is saved.");
            }}
          >
            {ACCOUNT_DEFAULT_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
          <p className="hint">
            Used by every saved website whose own match is "Account default". "Base domain" also
            matches the site's other addresses and any group below.
          </p>

          <h3>Your equivalence groups</h3>
          <p className="hint">
            Sites that share one login, like example.com and example.net. Autofill offers a login
            saved for one of them on the others, with a warning first.
          </p>
          {settings.userGroups.length === 0 ? (
            <p className="muted">No groups of your own.</p>
          ) : (
            <ul className="matching-list" aria-label="Your equivalence groups">
              {settings.userGroups.map((g) => (
                <li key={g.id}>
                  <span>{groupLabel(g.domains)}</span>{" "}
                  <button
                    type="button"
                    className="secondary"
                    disabled={busy}
                    aria-label={`Remove the group ${groupLabel(g.domains)}`}
                    onClick={() => change({ kind: "removeUserGroup", id: g.id }, "The group is removed.")}
                  >
                    Remove
                  </button>
                </li>
              ))}
            </ul>
          )}
          <form onSubmit={addGroup} aria-label="Add an equivalence group">
            <label htmlFor={domainsId}>Domains of a new group</label>
            <textarea
              id={domainsId}
              value={domains}
              rows={2}
              placeholder="example.com, example.net"
              onChange={(e) => setDomains(e.currentTarget.value)}
              required
            />
            <p className="hint">Two or more, separated by commas or new lines. Each must be a site's own domain.</p>
            <div className="actions">
              <button type="submit" disabled={busy}>
                Add group
              </button>
            </div>
          </form>

          <h3>Global equivalence groups</h3>
          {settings.globalGroups.length === 0 ? (
            <p className="muted">
              This build ships no signed global list yet, so there is no global group to turn off.
            </p>
          ) : (
            <ul className="matching-list" aria-label="Global equivalence groups">
              {settings.globalGroups.map((g) => (
                <GlobalGroupRow
                  key={g.id}
                  group={g}
                  busy={busy}
                  onChange={(next) =>
                    change(next, next.kind === "disableGlobalGroup" ? "The group is turned off." : "The group is turned on.")
                  }
                />
              ))}
            </ul>
          )}
          {settings.otherDisabled.length > 0 && (
            <>
              <p className="hint">Turned off, but not in this build's list:</p>
              <ul className="matching-list">
                {settings.otherDisabled.map((id) => (
                  <li key={id}>
                    <code>{id}</code>{" "}
                    <button
                      type="button"
                      className="secondary"
                      disabled={busy}
                      onClick={() => change({ kind: "enableGlobalGroup", id }, "The group is turned on.")}
                    >
                      Turn on
                    </button>
                  </li>
                ))}
              </ul>
            </>
          )}

          <CheckWebsite ctx={ctx} settings={settings} />
        </>
      )}
    </div>
  );
}
