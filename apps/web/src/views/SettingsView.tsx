// Settings (redesign slice 2, item 5): Two-factor, Devices and Appearance, grouped under one
// sidebar entry instead of three. Each group is still its own panel; this view only lays them
// out together and adds the Appearance group (theme.ts module docs: memory-only for now).
import { isTheme, useThemeContext } from "../theme.ts";
import type { VaultContext } from "./VaultView.tsx";
import { DevicesPane } from "./DevicesPane.tsx";
import { TwoFactorPane } from "./TwoFactorPane.tsx";

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

/** Settings (module docs). */
export function SettingsView(props: { readonly ctx: VaultContext }) {
  return (
    <div className="settings-view">
      <h1>Settings</h1>
      <TwoFactorPane ctx={props.ctx} />
      <DevicesPane ctx={props.ctx} />
      <AppearanceGroup />
    </div>
  );
}
