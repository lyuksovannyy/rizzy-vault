// The Appearance theme choice (redesign slice 2, item 5 / item 7 of the first slice's "Not yet
// done" list): "system" (the default), "light" or "dark".
//
// CRYPTO.md §11.4 says the web vault persists nothing; the owner has not yet said whether that
// line covers a non-secret UI preference like this one (apps/web/README.md "Not yet done",
// item 7). Until that is answered, this choice lives in memory only, for the current session —
// no `localStorage`, no `sessionStorage`, no `IndexedDB` — and resets to "system" on reload,
// exactly like every other piece of session state in this vault.
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

interface ThemeContextValue {
  readonly theme: Theme;
  readonly setTheme: (next: Theme) => void;
}

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined);

/** Wraps the app once near its root, beside `ToastProvider`. */
export function ThemeProvider(props: { readonly children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>("system");

  useEffect(() => {
    applyTheme(theme, document.documentElement);
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
