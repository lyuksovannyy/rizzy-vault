// SPDX-License-Identifier: AGPL-3.0-only

// The options page: this device's lock settings (ADR 0110 §1–§3, the Locking group shared with
// the web vault through packages/ui's `LockSettingsGroup` and its turn-off dialog), and the
// third-party notices (THIRD_PARTY_NOTICES.md; ADR 0080 owner answer 5).
//
// The record `rizzy.lock_settings` lives in `storage.local` (ADR 0110 §3 table: not secret, not
// synced, never sent to the server). This page reads it and asks the long-lived context to parse
// it, and to encode a change, with Rust's `lock_settings` (the core is loaded there only, ADR 0036
// §2); it then writes the record itself, as the one writer the settings UI is (§3 point 6). The
// long-lived context applies a write at once: on Chromium the service worker pushes it on
// `storage.onChanged`, on Firefox the background page re-reads it. Writing removes the legacy
// key `rizzy.auto_lock_minutes` too, which the long-lived context otherwise migrates once.
import "@rizzy-vault/ui/tokens.css";
import "../surface.css";

import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";

import { t } from "@rizzy-vault/i18n";
import { LockSettingsGroup, type LockSettingsText, type LockSettingsValue, ThirdPartyNotices } from "@rizzy-vault/ui";

import { ExtensionClient, createRuntimeTransport } from "../core/client.ts";
import {
  LEGACY_AUTO_LOCK_KEY,
  LOCK_SETTINGS_KEY,
  legacyMinutesOf,
  recordTextOf,
} from "../messaging/lock-messages.ts";
import { webext } from "../types/runtime-api.ts";

/** ADR 0110 §1's idle list and §2's delay (packages/core's `LOCK_SETTINGS_LIMITS`, not imported
 * here: this page does not load the core). */
const IDLE_MINUTES: readonly number[] = Object.freeze([1, 2, 5, 10, 15, 30, 60, 240]);
const LOCK_DISABLE_CONFIRM_DELAY_MS = 5_000;

/** The exact texts of ADR 0110 §1, §2 and §4.1 (extension line), shared with the web vault. */
const LOCK_TEXT: LockSettingsText = {
  title: t("lock.settings.title"),
  autoLock: t("lock.settings.autoLock"),
  idle: t("lock.settings.idle"),
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

function OptionsPage() {
  const [client] = useState(() => new ExtensionClient(createRuntimeTransport(webext())));
  const [value, setValue] = useState<LockSettingsValue | undefined>();
  const [error, setError] = useState<string | undefined>();

  useEffect(() => {
    // `storage` is typed optional (absent inside a `chrome.offscreen` document only) but present
    // here: the options page is a regular extension page.
    const storage = webext().storage;
    if (storage === undefined) {
      return;
    }
    void storage.local
      .get([LOCK_SETTINGS_KEY, LEGACY_AUTO_LOCK_KEY])
      .then((stored) => {
        const record = recordTextOf(stored[LOCK_SETTINGS_KEY]);
        const legacy = record === null ? legacyMinutesOf(stored[LEGACY_AUTO_LOCK_KEY]) : undefined;
        return client.lockSettings(record, legacy);
      })
      .then(setValue, () => setError(t("common.unknownError", { code: "lock_settings_failed" })));
  }, [client]);

  return (
    <main>
      <h1>rizzy-vault settings</h1>
      <LockSettingsGroup
        value={value}
        idleMinutes={IDLE_MINUTES}
        confirmDelayMs={LOCK_DISABLE_CONFIRM_DELAY_MS}
        text={LOCK_TEXT}
        onChange={(next) => {
          const storage = webext().storage;
          if (storage === undefined) {
            return;
          }
          void client
            .encodeLockSettings(next)
            .then(async (record) => {
              await storage.local.set({ [LOCK_SETTINGS_KEY]: record });
              await storage.local.remove(LEGACY_AUTO_LOCK_KEY);
              setValue(next);
              setError(undefined);
            })
            .catch(() => setError(t("common.unknownError", { code: "lock_settings_failed" })));
        }}
      />
      {error !== undefined ? <p role="alert">{error}</p> : undefined}
      <ThirdPartyNotices />
    </main>
  );
}

const root = document.getElementById("root");
if (root !== null) {
  createRoot(root).render(
    <StrictMode>
      <OptionsPage />
    </StrictMode>,
  );
}
