"use client";

import * as React from "react";

export type Theme = "light" | "dark" | "system";

export const THEME_STORAGE_KEY = "secure-evidence-theme";

function isTheme(value: unknown): value is Theme {
  return value === "light" || value === "dark" || value === "system";
}

function readStoredTheme(): Theme {
  if (typeof window === "undefined") {
    return "system";
  }
  try {
    const value = window.localStorage.getItem(THEME_STORAGE_KEY);
    return isTheme(value) ? value : "system";
  } catch {
    return "system";
  }
}

function systemPrefersDark(): boolean {
  return (
    typeof window !== "undefined" &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
  );
}

/** Applies the resolved theme to <html data-theme="…">. DOM-only side effect. */
export function applyTheme(theme: Theme): void {
  const resolved =
    theme === "dark" || (theme === "system" && systemPrefersDark())
      ? "dark"
      : "light";
  document.documentElement.dataset.theme = resolved;
}

// Hydration-safe external store. getServerSnapshot is constant ("system"), so
// the server markup and the hydration render always agree — nothing renders
// based on localStorage during SSR or the first client render. After
// hydration React swaps to the client snapshot and re-renders once when the
// stored theme differs, without a hydration mismatch.
const themeListeners = new Set<() => void>();

function subscribeTheme(onStoreChange: () => void): () => void {
  themeListeners.add(onStoreChange);
  const onStorage = () => onStoreChange();
  window.addEventListener("storage", onStorage);
  return () => {
    themeListeners.delete(onStoreChange);
    window.removeEventListener("storage", onStorage);
  };
}

function notifyTheme(): void {
  themeListeners.forEach((listener) => listener());
}

const serverThemeSnapshot: Theme = "system";

type ThemeContextValue = {
  theme: Theme;
  setTheme: (theme: Theme) => void;
};

const ThemeContext = React.createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const theme = React.useSyncExternalStore(
    subscribeTheme,
    readStoredTheme,
    () => serverThemeSnapshot,
  );

  // Keep <html data-theme="…"> in sync with the selected theme. Re-applies the
  // theme after the dev-mode StrictMode remount clears the attribute set by the
  // inline script in app/layout.tsx.
  React.useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  // Keep "system" in sync with live OS preference changes.
  React.useEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    if (typeof mq.addEventListener !== "function") {
      return;
    }
    const onChange = () => {
      if (theme === "system") {
        applyTheme("system");
      }
    };
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, [theme]);

  const setTheme = React.useCallback((next: Theme) => {
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, next);
    } catch {
      // localStorage may be unavailable; the theme still applies to this tab.
    }
    applyTheme(next);
    notifyTheme();
  }, []);

  const value = React.useMemo(
    () => ({ theme, setTheme }),
    [theme, setTheme],
  );

  return (
    <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
  );
}

export function useTheme(): ThemeContextValue {
  const context = React.useContext(ThemeContext);
  if (!context) {
    throw new Error("useTheme must be used within a ThemeProvider");
  }
  return context;
}