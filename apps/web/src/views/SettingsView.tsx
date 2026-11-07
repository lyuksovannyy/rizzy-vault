// SPDX-License-Identifier: AGPL-3.0-only

// Settings (redesign slice 2, item 5): Two-factor, Devices and Appearance, grouped under one
// sidebar entry instead of three. Each group is still its own panel; this view only lays them
// out together and adds the Appearance group (theme.ts module docs: memory-only for now). The
// "What the server stores" group (ROADMAP §4.5) is `TransparencyPane.tsx`. The "Getting started"
// group re-opens the guide shown after signup (`onboarding.ts`), which is remembered nowhere.
// "Website matching" (`MatchingPane.tsx`) is the account match default and equivalence groups
// (ADR 0042). "Identity generator" (`IdentityDefaultsPane.tsx`) is the synced defaults of a new
// identity and its email domain (ADR 0079 Open question 7). "Third-party notices" carries the
// attributions THIRD_PARTY_NOTICES.md requires (the EFF wordlist; the default site groups,
// ADR 0080; the identity generator's data, ADR 0079). "Website icons" (`WebsiteIconsPane.tsx`) is
// the account's switch for item icons and its disclosure (ADR 0099 §6). "Locking" is this
// device's lock settings (ADR 0110 §1–§2; packages/ui `LockSettingsGroup.tsx`, `autolock.ts`).
import { t } from "@rizzy-vault/i18n";
import { LockSettingsGroup, type LockSettingsText, ThirdPartyNotices } from "@rizzy-vault/ui";
import { useState } from "react";

import { IDLE_MINUTES, LOCK_DISABLE_CONFIRM_DELAY_MS } from "../autolock.ts";
import { codeOf } from "../core-client.ts";
import { isTheme, useThemeContext } from "../theme.ts";
import { ErrorText } from "./common.tsx";
import type { VaultContext } from "./VaultView.tsx";
import { DevicesPane } from "./DevicesPane.tsx";
import { IdentityDefaultsPane } from "./IdentityDefaultsPane.tsx";
import { MatchingPane } from "./MatchingPane.tsx";
import { TransparencyPane } from "./TransparencyPane.tsx";
import { TwoFactorPane } from "./TwoFactorPane.tsx";
import { WebsiteIconsPane } from "./WebsiteIconsPane.tsx";

/** The Appearance group: the theme choice (module docs). */
function AppearanceGroup() {
  const { theme, setTheme } = useThemeContext();
  return (
    <div className="panel narrow">
      <h2>Appearance</h2>
      <label htmlFor="theme-select">Theme</label>
      <select
        id="theme-select"
        value={theme}
        onChange={(e) => {
          const next = e.currentTarget.value;
          if (isTheme(next)) {
            setTheme(next);
          }
        }}
      >
        <option value="system">Match system</option>
        <option value="light">Light</option>
        <option value="dark">Dark</option>
      </select>
      <p className="hint">
        Kept for this session only: a reload or a lock returns to "Match system" (CRYPTO.md
        §11.4).
      </p>
    </div>
  );
}

/** The Locking group's words (ADR 0110 §1–§2, §4.1: the browser's restart line). */
const LOCK_TEXT: LockSettingsText = {
  title: t("lock.settings.title"),
  autoLock: t("lock.settings.autoLock"),
  idleBefore: t("lock.settings.idleBefore"),
  idleAfter: t("lock.settings.idleAfter"),
  restart: t("lock.settings.restartBrowser"),
  restartHint: t("lock.settings.restartBrowserHint"),
  sleep: t("lock.settings.sleep"),
  sleepHint: t("lock.settings.sleepHint"),
  offHint: t("lock.settings.offHint"),
  disableTitle: t("lock.disable.title"),
  disableBody: t("lock.disable.body"),
  disableConfirm: t("lock.disable.confirm"),
  disableConfirmCountdown: (seconds) => t("lock.disable.confirmCountdown", { seconds: String(seconds) }),
  disableCancel: t("lock.disable.cancel"),
  disableWait: t("lock.disable.wait"),
  disableReady: t("lock.disable.ready"),
};

/** The Locking group: this device's lock settings (module docs). */
function LockingGroup(props: { readonly ctx: VaultContext }) {
  const [error, setError] = useState<string | undefined>();
  return (
    <>
      <LockSettingsGroup
        value={props.ctx.lockSettings}
        idleMinutes={IDLE_MINUTES}
        confirmDelayMs={LOCK_DISABLE_CONFIRM_DELAY_MS}
        text={LOCK_TEXT}
        onChange={(next) => {
          props.ctx.changeLockSettings(next).then(
            () => setError(undefined),
            (e: unknown) => setError(codeOf(e)),
          );
        }}
      />
      <ErrorText code={error} />
    </>
  );
}

/** The "Getting started" group: re-opens the guide (module docs). */
function GettingStartedGroup(props: { readonly onOpenGuide: () => void }) {
  return (
    <div className="panel narrow" role="region" aria-labelledby="settings-guide-title">
      <h2 id="settings-guide-title">Getting started</h2>
      <p className="muted">
        The guide shown after signup: keeping your Emergency Kit safe, importing from another
        password manager, and installing the browser extension.
      </p>
      <div className="actions">
        <button type="button" className="secondary" onClick={props.onOpenGuide}>
          Open the getting-started guide
        </button>
      </div>
    </div>
  );
}

/** Settings (module docs). */
export function SettingsView(props: { readonly ctx: VaultContext; readonly onOpenGuide: () => void }) {
  return (
    <div className="settings-view">
      <h1>Settings</h1>
      <TwoFactorPane ctx={props.ctx} />
      <DevicesPane ctx={props.ctx} />
      <MatchingPane ctx={props.ctx} />
      <IdentityDefaultsPane ctx={props.ctx} />
      <WebsiteIconsPane ctx={props.ctx} />
      <LockingGroup ctx={props.ctx} />
      <AppearanceGroup />
      <TransparencyPane ctx={props.ctx} />
      <GettingStartedGroup onOpenGuide={props.onOpenGuide} />
      <ThirdPartyNotices className="panel narrow third-party-notices" />
    </div>
  );
}
