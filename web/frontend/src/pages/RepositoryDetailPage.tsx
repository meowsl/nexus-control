import { FormEvent, useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import AssetBrowser from "../AssetBrowser";
import { api } from "../api";
import When from "../When";
import type { HistoryRun, Label, Repo } from "../types";

type Tab = "assets" | "labels" | "scan" | "history";

export default function RepositoryDetailPage() {
  const { name = "" } = useParams();
  const repoName = decodeURIComponent(name);
  const [tab, setTab] = useState<Tab>("assets");
  const [repo, setRepo] = useState<Repo | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setRepo(await api<Repo>(`/api/repos/${encodeURIComponent(repoName)}`));
    } catch (ex) {
      setError(ex instanceof Error ? ex.message : "Не найден");
    }
  }, [repoName]);

  useEffect(() => {
    void load();
  }, [load]);

  if (error && !repo) {
    return (
      <>
        <Link to="/repositories" className="back">
          ← Репозитории
        </Link>
        <div className="banner error">{error}</div>
      </>
    );
  }
  if (!repo) return <p className="muted">Загрузка…</p>;

  return (
    <>
      <Link to="/repositories" className="back">
        ← Репозитории
      </Link>
      <div className="page-head">
        <div>
          <h1>{repo.name}</h1>
          <p className="lede">
            <span className={`type type-${repo.type}`}>{repo.type}</span> {repo.format}
            {repo.url ? ` · ${repo.url}` : ""}
          </p>
          <div className="pill-row">
            {repo.labels.map((l) => (
              <span key={l.id} className="pill">
                <i style={{ background: l.color }} />
                {l.name}
              </span>
            ))}
          </div>
        </div>
      </div>
      <div className="tabs">
        {(
          [
            ["assets", "Артефакты"],
            ["labels", "Метки"],
            ["scan", "Сканирование"],
            ["history", "История"],
          ] as const
        ).map(([id, title]) => (
          <button
            key={id}
            type="button"
            className={tab === id ? "tab active" : "tab"}
            onClick={() => setTab(id)}
          >
            {title}
          </button>
        ))}
      </div>
      <div className={tab === "assets" ? "tab-panel is-active" : "tab-panel"}>
        <AssetBrowser key={repo.name} repo={repo.name} format={repo.format} />
      </div>
      {tab === "labels" && <LabelsTab repo={repo} onSaved={() => void load()} />}
      {tab === "scan" && <ScanTab repo={repo.name} />}
      {tab === "history" && <RepoHistoryTab repo={repo.name} />}
    </>
  );
}

function LabelsTab({ repo, onSaved }: { repo: Repo; onSaved: () => void }) {
  const [all, setAll] = useState<Label[]>([]);
  const [ids, setIds] = useState<string[]>(repo.labels.map((l) => l.id));
  const [msg, setMsg] = useState("");

  useEffect(() => {
    void api<Label[]>("/api/labels").then(setAll);
  }, []);
  useEffect(() => {
    setIds(repo.labels.map((l) => l.id));
  }, [repo]);

  async function save(e: FormEvent) {
    e.preventDefault();
    setMsg("");
    await api(`/api/repos/${encodeURIComponent(repo.name)}/labels`, {
      method: "PUT",
      body: JSON.stringify({ label_ids: ids }),
    });
    setMsg("Метки сохранены");
    onSaved();
  }

  return (
    <form onSubmit={save} className="panel">
      <p className="lede">Метки хранятся здесь, не в Nexus.</p>
      {all.length === 0 ? (
        <p className="empty">
          Сначала создайте метки на странице <Link to="/labels">Метки</Link>.
        </p>
      ) : (
        <div className="check-grid">
          {all.map((l) => (
            <label key={l.id} className="check">
              <input
                type="checkbox"
                checked={ids.includes(l.id)}
                onChange={(e) =>
                  setIds((prev) =>
                    e.target.checked ? [...prev, l.id] : prev.filter((x) => x !== l.id),
                  )
                }
              />
              <span className="pill">
                <i style={{ background: l.color }} />
                {l.name}
              </span>
              <span className="muted">{l.description}</span>
            </label>
          ))}
        </div>
      )}
      <button className="btn primary" type="submit">
        Сохранить
      </button>
      {msg ? <span className="ok">{msg}</span> : null}
    </form>
  );
}

function ScanTab({ repo }: { repo: string }) {
  const [upload, setUpload] = useState(true);
  const [scanMode, setScanMode] = useState("incremental");
  const [jobId, setJobId] = useState<string | null>(null);
  const [error, setError] = useState("");

  async function start(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      const job = await api<{ id: string }>("/api/jobs", {
        method: "POST",
        body: JSON.stringify({
          repository: repo,
          upload,
          scan_mode: scanMode,
        }),
      });
      setJobId(job.id);
    } catch (ex) {
      setError(ex instanceof Error ? ex.message : "Ошибка");
    }
  }

  return (
    <form className="panel" onSubmit={start}>
      <p className="lede">
        Скачивает артефакты, проверяет и{upload ? " заливает проверенную копию" : " оставляет отчёт"}.
      </p>
      {error ? <div className="banner error">{error}</div> : null}
      <div className="form-grid">
        <label>
          Режим
          <select value={scanMode} onChange={(e) => setScanMode(e.target.value)}>
            <option value="incremental">incremental — пропуск неизменённого PASS</option>
            <option value="full">full — полный rescan</option>
          </select>
        </label>
        <label className="check">
          <input type="checkbox" checked={upload} onChange={(e) => setUpload(e.target.checked)} />
          Загрузить PASS в *-verified
        </label>
      </div>
      <div className="form-actions">
        <button className="btn primary" type="submit">
          Запустить verify
        </button>
        {jobId ? (
          <p>
            Задача поставлена в очередь.{" "}
            <Link to="/jobs">Открыть список задач</Link>
          </p>
        ) : null}
      </div>
    </form>
  );
}

function RepoHistoryTab({ repo }: { repo: string }) {
  const [rows, setRows] = useState<HistoryRun[]>([]);
  useEffect(() => {
    void api<HistoryRun[]>(`/api/history?repo=${encodeURIComponent(repo)}`).then(setRows);
  }, [repo]);
  if (rows.length === 0) return <p className="empty">Нет прогонов по этому репозиторию.</p>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Когда</th>
            <th>Источник</th>
            <th>PASS</th>
            <th>FAIL</th>
            <th>Skip</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.run_id}>
              <td>
                <Link to={`/history/${r.run_id}`} className="when-link">
                  <When value={r.started_at} />
                </Link>
              </td>
              <td>{r.source}</td>
              <td>{r.totals.passed}</td>
              <td>{r.totals.failed}</td>
              <td>{r.totals.checkpoint_skipped}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
