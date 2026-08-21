import { useEffect, useState } from "react";
import { applyTheme, hasStoredTheme, readTheme, saveTheme, type Theme } from "./theme";

function IconSun() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
    </svg>
  );
}

function IconMoon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
      <path d="M20 14.5A7.5 7.5 0 1 1 9.5 4 6.2 6.2 0 0 0 20 14.5Z" />
    </svg>
  );
}

export default function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(() => readTheme());

  useEffect(() => {
    applyTheme(theme);
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => {
      if (hasStoredTheme()) return;
      const next: Theme = mq.matches ? "dark" : "light";
      applyTheme(next);
      setTheme(next);
    };
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, [theme]);

  function choose(next: Theme) {
    saveTheme(next);
    setTheme(next);
  }

  return (
    <div className="theme-switch" role="group" aria-label="Тема оформления">
      <span className={`theme-switch-knob${theme === "dark" ? " is-dark" : ""}`} aria-hidden />
      <button
        type="button"
        className={theme === "light" ? "is-active" : ""}
        aria-pressed={theme === "light"}
        aria-label="Светлая тема"
        title="Светлая"
        onClick={() => choose("light")}
      >
        <IconSun />
      </button>
      <button
        type="button"
        className={theme === "dark" ? "is-active" : ""}
        aria-pressed={theme === "dark"}
        aria-label="Тёмная тема"
        title="Тёмная"
        onClick={() => choose("dark")}
      >
        <IconMoon />
      </button>
    </div>
  );
}
