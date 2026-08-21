export type Theme = "light" | "dark";

export const THEME_KEY = "nexus-control-theme";

function osTheme(): Theme {
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function hasStoredTheme(): boolean {
  try {
    const value = localStorage.getItem(THEME_KEY);
    return value === "light" || value === "dark";
  } catch {
    return false;
  }
}

export function readTheme(): Theme {
  try {
    const value = localStorage.getItem(THEME_KEY);
    if (value === "light" || value === "dark") return value;
  } catch {
    /* private mode */
  }
  return osTheme();
}

export function applyTheme(theme: Theme): void {
  const root = document.documentElement;
  root.dataset.theme = theme;
  root.style.colorScheme = theme;
}

export function saveTheme(theme: Theme): void {
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    /* ignore quota */
  }
  applyTheme(theme);
}
