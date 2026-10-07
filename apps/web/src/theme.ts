// The Appearance theme choice (redesign slice 2, item 5 / item 7 of the first slice's "Not yet
// done" list): "system" (the default), "light" or "dark".
//
// It is remembered in `localStorage` under {@link THEME_STORAGE_KEY}: CRYPTO.md §11.4 allows this
// one non-secret value (owner decision of 2026-10-07). Reads and writes are wrapped, so a storage
// that throws or is missing (private windows, blocked site data, tests) leaves the choice in
// memory only, and anything stored that is not a known theme reads as "system".
//
// It is applied by setting (or clearing) `data-theme` on `document.documentElement`; the token
// CSS (`packages/ui/src/tokens.css`) reads that attribute. "System" clears the attribute, so the
// existing `prefers-color-scheme` media query decides; "light"/"dark" force one scheme
// regardless of the system setting.
//
// `ThemeProvider` holds the one shared value (like `ToastProvider`, `@rizzy-vault/ui`'s
// `Toast.tsx`): every `useThemeContext()` call reads and sets the same state, rather than each
// giving its caller an independent one.
import {
  type ReactNode,
  createContext,
  createElement,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";

export type Theme = "system" | "light" | "dark";

const THEMES: readonly Theme[] = ["system", "light", "dark"];

/** Whether `value` is a recognised theme choice (used to validate anything coming from the UI,
 * e.g. a `<select>` value, before it is applied). */
export function isTheme(value: string): value is Theme {
  return (THEMES as readonly string[]).includes(value);
}

/** Sets `data-theme` on the document root for `theme` (module docs). Exported separately from
 * the context below so it can be unit tested without rendering anything, against a fake root. */
export function applyTheme(
  theme: Theme,
  root: { setAttribute: (n: string, v: string) => void; removeAttribute: (n: string) => void },
): void {
  if (theme === "system") {
    root.removeAttribute("data-theme");
  } else {
    root.setAttribute("data-theme", theme);
  }
}

/** The `localStorage` key of the theme choice (module docs). */
export const THEME_STORAGE_KEY = "rizzy-vault.theme";

/** The part of `Storage` the theme uses, so tests can pass a fake. */
export interface ThemeStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

/** The browser's `localStorage`, or `undefined` where reading it throws or it does not exist. */
function browserStore(): ThemeStore | undefined {
  try {
    return typeof localStorage === "undefined" ? undefined : localStorage;
  } catch {
    return undefined;
  }
}

/** The stored theme choice; "system" when nothing usable is stored or `store` throws. */
export function loadTheme(store: ThemeStore | undefined): Theme {
  try {
    const value = store?.getItem(THEME_STORAGE_KEY) ?? null;
    return value !== null && isTheme(value) ? value : "system";
  } catch {
    return "system";
  }
}

/** Stores `theme`; "system" removes the entry. A throwing `store` is ignored (module docs). */
export function saveTheme(theme: Theme, store: ThemeStore | undefined): void {
  try {
    if (theme === "system") {
      store?.removeItem(THEME_STORAGE_KEY);
    } else {
      store?.setItem(THEME_STORAGE_KEY, theme);
    }
  } catch {
    // Storage unavailable: the choice stays in memory for this session.
  }
}

interface ThemeContextValue {
  readonly theme: Theme;
  readonly setTheme: (next: Theme) => void;
}

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined);

/** Wraps the app once near its root, beside `ToastProvider`. */
export function ThemeProvider(props: { readonly children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(() => loadTheme(browserStore()));

  useEffect(() => {
    applyTheme(theme, document.documentElement);
    saveTheme(theme, browserStore());
  }, [theme]);

  const value = useMemo(() => ({ theme, setTheme }), [theme]);
  return createElement(ThemeContext.Provider, { value }, props.children);
}

/** Reads and sets the session's one theme choice. Throws outside {@link ThemeProvider}, the
 * same contract as `@rizzy-vault/ui`'s `useToast`. */
export function useThemeContext(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (ctx === undefined) {
    throw new Error("useThemeContext() called outside ThemeProvider");
  }
  return ctx;
}
