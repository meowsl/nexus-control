import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { jobStatusLabel } from "../format";
import type { HistoryRun, Job, Repo, Status } from "../types";

export default function OverviewPage() {
  const [status, setStatus] = useState<Status | null>(null);
  const [repos, setRepos] = useState<Repo[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [history, setHistory] = useState<HistoryRun[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([
      api<Status>("/api/status"),
      api<Repo[]>("/api/repos"),
      api<Job[]>("/api/jobs"),
      api<HistoryRun[]>("/api/history?limit=8"),
    ])
      .then(([s, r, j, h]) => {
        setStatus(s);
        setRepos(r);
        setJobs(j);
        setHistory(h);
      })
      .catch((ex) => setError(ex instanceof Error ? ex.message : "Ошибка загрузки"));
  }, []);

  const hosted = repos.filter((r) => r.type === "hosted").length;
  const proxy = repos.filter((r) => r.type === "proxy").length;
  const group = repos.filter((r) => r.type === "group").length;
  const activeJobs = jobs.filter((j) => j.status === "queued" || j.status === "running");

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Обзор</h1>
          <p className="lede">Состояние репозиториев, очереди и недавних прогонов.</p>
        </div>
        <Link className="btn primary" to="/repositories">
          К репозиториям
        </Link>
      </div>
      {error ? <div className="banner error">{error}</div> : null}
      <section className="metrics-card">
        <article className="metric">
          <span>Репозитории</span>
          <strong>{repos.length}</strong>
          <small>
            hosted {hosted} · proxy {proxy} · group {group}
          </small>
        </article>
        <article className="metric">
          <span>Метки</span>
          <strong>{status?.counts.labels ?? "—"}</strong>
          <small>в нашем каталоге</small>
        </article>
        <article className="metric">
          <span>Активные задачи</span>
          <strong>{status?.counts.jobs ?? activeJobs.length}</strong>
          <small>ожидают и идут сейчас</small>
        </article>
        <article className="metric">
          <span>Правила cron</span>
          <strong>{status?.counts.schedule_rules ?? "—"}</strong>
          <small>расписание</small>
        </article>
        <article className="metric">
          <span>Интеграции</span>
          <strong>
            {[
              status?.integrations?.defectdojo ? "DD" : null,
              status?.integrations?.webhook ? "WH" : null,
              status?.integrations?.vk_teams ? "VK" : null,
            ]
              .filter(Boolean)
              .join(" · ") || "выкл"}
          </strong>
          <small>
            <Link to="/integrations">настроить</Link>
          </small>
        </article>
      </section>
      <div className="split">
        <section className="panel">
          <header>
            <h2>Последние задачи</h2>
            <Link to="/jobs">все</Link>
          </header>
          {activeJobs.length === 0 && jobs.length === 0 ? (
            <p className="empty">Задач ещё нет. Запустите verify со страницы репозитория.</p>
          ) : (
            <ul className="plain-list">
              {jobs.slice(0, 6).map((j) => (
                <li key={j.id}>
                  <Link to={`/repositories/${encodeURIComponent(j.repository)}`}>
                    {j.repository}
                  </Link>
                  <span className={`badge status-${j.status}`}>{jobStatusLabel(j.status)}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
        <section className="panel">
          <header>
            <h2>Последние сканы</h2>
            <Link to="/history">все</Link>
          </header>
          {history.length === 0 ? (
            <p className="empty">История пуста.</p>
          ) : (
            <ul className="plain-list">
              {history.map((h) => (
                <li key={h.run_id}>
                  <Link to={`/history/${h.run_id}`}>{h.repository}</Link>
                  <span className="muted">
                    PASS {h.totals.passed} · FAIL {h.totals.failed}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </>
  );
}
