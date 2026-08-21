import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useEffect, useState, type ReactNode, type SVGProps } from "react";
import BrandMark from "../BrandMark";
import ThemeToggle from "../ThemeToggle";
import { api } from "../api";
import type { Status } from "../types";

const iconProps: SVGProps<SVGSVGElement> = {
  width: 18,
  height: 18,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.75,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  "aria-hidden": true,
};

function IconOverview() {
  return (
    <svg {...iconProps}>
      <rect x="3" y="3" width="7" height="7" rx="1.5" />
      <rect x="14" y="3" width="7" height="7" rx="1.5" />
      <rect x="3" y="14" width="7" height="7" rx="1.5" />
      <rect x="14" y="14" width="7" height="7" rx="1.5" />
    </svg>
  );
}

function IconRepos() {
  return (
    <svg {...iconProps}>
      <ellipse cx="12" cy="6" rx="8" ry="3" />
      <path d="M4 6v6c0 1.66 3.58 3 8 3s8-1.34 8-3V6" />
      <path d="M4 12v6c0 1.66 3.58 3 8 3s8-1.34 8-3v-6" />
    </svg>
  );
}

function IconLabels() {
  return (
    <svg {...iconProps}>
      <path d="M20.59 13.41 13.42 20.58a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82Z" />
      <circle cx="7.5" cy="7.5" r="0.75" fill="currentColor" stroke="none" />
    </svg>
  );
}

function IconJobs() {
  return (
    <svg {...iconProps}>
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
    </svg>
  );
}

function IconSchedule() {
  return (
    <svg {...iconProps}>
      <rect x="3" y="4.5" width="18" height="16.5" rx="2" />
      <path d="M16 2.5v4M8 2.5v4M3 10h18" />
    </svg>
  );
}

function IconHistory() {
  return (
    <svg {...iconProps}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3.5 2" />
    </svg>
  );
}

function IconIntegrations() {
  return (
    <svg {...iconProps}>
      <path d="M10 13a5 5 0 0 0 7.07 0l1.41-1.41a5 5 0 0 0-7.07-7.07L10 5.93" />
      <path d="M14 11a5 5 0 0 0-7.07 0L5.5 12.43a5 5 0 0 0 7.07 7.07L14 18.07" />
    </svg>
  );
}

const GROUPS: {
  title: string;
  items: { to: string; label: string; icon: ReactNode }[];
}[] = [
  {
    title: "Каталог",
    items: [
      { to: "/", label: "Обзор", icon: <IconOverview /> },
      { to: "/repositories", label: "Репозитории", icon: <IconRepos /> },
      { to: "/labels", label: "Метки", icon: <IconLabels /> },
    ],
  },
  {
    title: "Автоматизация",
    items: [
      { to: "/jobs", label: "Задачи", icon: <IconJobs /> },
      { to: "/schedule", label: "Расписание", icon: <IconSchedule /> },
      { to: "/history", label: "История", icon: <IconHistory /> },
    ],
  },
  {
    title: "Система",
    items: [{ to: "/integrations", label: "Интеграции", icon: <IconIntegrations /> }],
  },
];

export default function AppShell() {
  const [status, setStatus] = useState<Status | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    api<Status>("/api/status")
      .then(setStatus)
      .catch((err: { status?: number }) => {
        if (err.status === 401) navigate("/login", { replace: true });
      });
  }, [navigate]);

  async function logout() {
    await api("/api/auth/logout", { method: "POST" });
    navigate("/login", { replace: true });
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <BrandMark className="brand-mark" />
          <strong>Nexus Control</strong>
        </div>
        <nav className="nav">
          {GROUPS.map((group) => (
            <div key={group.title}>
              <div className="nav-group">{group.title}</div>
              {group.items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.to === "/"}
                  className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}
                >
                  {item.icon}
                  {item.label}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-foot">
          <span className="theme-caption">Тема</span>
          <ThemeToggle />
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <div className="topbar-meta">
            <span className="nexus-chip">
              <span className="dot" />
              <span className="ellipsis">{status?.nexus_url ?? "Nexus"}</span>
            </span>
          </div>
          <div className="topbar-user">
            {status?.username ? (
              <span className="avatar" aria-hidden>
                {status.username.slice(0, 1).toUpperCase()}
              </span>
            ) : null}
            <span>{status?.username ?? ""}</span>
            <button type="button" className="btn ghost" onClick={() => void logout()}>
              Выйти
            </button>
          </div>
        </header>
        <div className="content">
          <Outlet />
        </div>
      </div>
    </div>
  );
}
