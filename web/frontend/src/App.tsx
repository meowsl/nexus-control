import type { ReactNode } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { useEffect, useState } from "react";
import { api, ApiError } from "./api";
import AppShell from "./layout/AppShell";
import LoginPage from "./pages/LoginPage";
import OverviewPage from "./pages/OverviewPage";
import RepositoriesPage from "./pages/RepositoriesPage";
import RepositoryDetailPage from "./pages/RepositoryDetailPage";
import LabelsPage from "./pages/LabelsPage";
import JobsPage from "./pages/JobsPage";
import SchedulePage from "./pages/SchedulePage";
import IntegrationsPage from "./pages/IntegrationsPage";
import HistoryPage, { HistoryDetailPage } from "./pages/HistoryPage";

function RequireAuth({ children }: { children: ReactNode }) {
  const [ok, setOk] = useState<boolean | null>(null);
  useEffect(() => {
    api("/api/auth/me")
      .then(() => setOk(true))
      .catch((err) => {
        if (err instanceof ApiError && err.status === 401) setOk(false);
        else setOk(false);
      });
  }, []);
  if (ok === null) return <div className="login-wrap">Загрузка…</div>;
  if (!ok) return <Navigate to="/login" replace />;
  return children;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <AppShell />
          </RequireAuth>
        }
      >
        <Route path="/" element={<OverviewPage />} />
        <Route path="/repositories" element={<RepositoriesPage />} />
        <Route path="/repositories/:name" element={<RepositoryDetailPage />} />
        <Route path="/labels" element={<LabelsPage />} />
        <Route path="/jobs" element={<JobsPage />} />
        <Route path="/schedule" element={<SchedulePage />} />
        <Route path="/history" element={<HistoryPage />} />
        <Route path="/history/:runId" element={<HistoryDetailPage />} />
        <Route path="/integrations" element={<IntegrationsPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
