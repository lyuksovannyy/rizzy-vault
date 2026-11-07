// SPDX-License-Identifier: AGPL-3.0-only

// Settings, "Website icons" (ADR 0099 §1, §6): one switch for the whole account, on by default,
// written as ACCOUNT_SETTINGS tag 0x0005 through the existing settings edit
// (`changeMatchSettings({ kind: "websiteIcons", on })`). The disclosure is the text under the
// switch, always shown, on or off; there is no one-time notice, banner or onboarding step. While
// the switch is on and the session's probe found no `icons` role, the section adds "This server
// does not offer website icons."; while it is off, no probe is sent to word that line.
import type { IconsStatus } from "@rizzy-vault/core";
import { useCallback, useEffect, useId, useState } from "react";

import { codeOf } from "../core-client.ts";
import type { VaultContext } from "./VaultView.tsx";
import { ErrorText, useAction } from "./common.tsx";

/** The disclosure under the switch (ADR 0099 §6, English as given), after its bold lead. */
export const WEBSITE_ICONS_DISCLOSURE =
  "To show a site's icon, this app sends the site's host name (for example, example.com) to your " +
  "server, which fetches the icon. The host names are sent without your account name, but the " +
  "people who run your server could still link them to your account. This setting applies to all " +
  "your devices.";

/** The line added while on and the probe found no role (ADR 0099 §6). */
export const WEBSITE_ICONS_UNAVAILABLE = "This server does not offer website icons.";

/** The "Website icons" section of Settings (module docs). */
export function WebsiteIconsPane({ ctx }: { readonly ctx: VaultContext }) {
  const ids = useId();
  const titleId = `${ids}-title`;
  const descId = `${ids}-desc`;
  const [on, setOn] = useState<boolean | undefined>();
  const [status, setStatus] = useState<IconsStatus | undefined>();
  const [loadError, setLoadError] = useState<string | undefined>();
  const { busy, error, run } = useAction();

  const load = useCallback(async () => {
    try {
      const value = await ctx.client.call("websiteIcons");
      setOn(value);
      setLoadError(undefined);
      // Only while on: the probe is what the vault already ran this session, so this sends at
      // most the one probe; while off it sends nothing at all.
      setStatus(value ? await ctx.client.call("iconsProbe") : "off");
    } catch (e) {
      setLoadError(codeOf(e));
    }
  }, [ctx.client]);

  useEffect(() => {
    void load();
  }, [load, ctx.revision]);

  const toggle = (next: boolean) => {
    void run(async () => {
      await ctx.client.call("changeMatchSettings", { kind: "websiteIcons", on: next });
      await load();
      ctx.iconsChanged();
    });
  };

  return (
    <div className="panel narrow" role="region" aria-labelledby={titleId}>
      <h2 id={titleId}>Website icons</h2>
      {loadError !== undefined && <ErrorText code={loadError} />}
      <ErrorText code={error} />
      <label className="check">
        <input
          type="checkbox"
          checked={on ?? false}
          disabled={on === undefined || busy || ctx.session.readOnly}
          aria-describedby={descId}
          onChange={(e) => toggle(e.currentTarget.checked)}
        />
        <strong>Show website icons.</strong>
      </label>
      <p id={descId} className="muted">
        {WEBSITE_ICONS_DISCLOSURE}
      </p>
      {on === true && status === "unavailable" && <p className="muted">{WEBSITE_ICONS_UNAVAILABLE}</p>}
    </div>
  );
}
