// The options page (ADR 0036 §3: auto-lock default 15 minutes, "user-configurable"). The stored
// value is read by the long-lived context at startup, validated and bounded
// (`core-host/core-context.ts`'s `startCoreContext` → `lifecycle.ts`'s `readAutoLockMs`), not
// the hard-coded default. Not security-relevant on its own (the timeout is not secret), so it is
// read from `storage.local`, not `storage.session`.
import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";

import {
  AUTO_LOCK_MINUTES_STORAGE_KEY,
  DEFAULT_AUTO_LOCK_MS,
  MAX_AUTO_LOCK_MINUTES,
  MIN_AUTO_LOCK_MINUTES,
  clampAutoLockMinutes,
} from "../core-host/lifecycle.ts";
import { webext } from "../types/runtime-api.ts";

function OptionsPage() {
  const [minutes, setMinutes] = useState(DEFAULT_AUTO_LOCK_MS / 60_000);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    // `storage` is typed optional (absent inside a `chrome.offscreen` document specifically,
    // per `types/webext.d.ts`'s comment) but present here: the options page is a regular
    // extension page, not an offscreen document.
    void webext()
      .storage!.local.get(AUTO_LOCK_MINUTES_STORAGE_KEY)
      .then((stored) => {
        const value = stored[AUTO_LOCK_MINUTES_STORAGE_KEY];
        if (typeof value === "number") {
          setMinutes(clampAutoLockMinutes(value));
        }
      });
  }, []);

  return (
    <main>
      <h1>rizzy-vault settings</h1>
      <label>
        Lock after inactivity (minutes)
        <input
          type="number"
          min={MIN_AUTO_LOCK_MINUTES}
          max={MAX_AUTO_LOCK_MINUTES}
          value={minutes}
          onChange={(e) => {
            setMinutes(Number(e.target.value));
            setSaved(false);
          }}
        />
      </label>
      <button
        type="button"
        onClick={() => {
          // Clamped again here, not only trusted to the `<input min/max>` the browser mostly
          // enforces: a saved value must be something `readAutoLockMs` can use even if this
          // field's DOM constraints were ever bypassed (e.g. a non-numeric paste coerced by
          // `Number(...)` above into `NaN`).
          const toSave = clampAutoLockMinutes(minutes);
          void webext()
            .storage!.local.set({ [AUTO_LOCK_MINUTES_STORAGE_KEY]: toSave })
            .then(() => {
              setMinutes(toSave);
              setSaved(true);
            });
        }}
      >
        Save
      </button>
      {saved ? <p>Saved.</p> : undefined}
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
