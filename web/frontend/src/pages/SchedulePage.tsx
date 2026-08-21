import { FormEvent, useCallback, useEffect, useState } from "react";
import { api } from "../api";
import When from "../When";
import type { Rule } from "../types";

export default function SchedulePage() {
  const [rows, setRows] = useState<Rule[]>([]);
  const [id, setId] = useState("");
  const [cron, setCron] = useState("0 3 * * *");
  const [repos, setRepos] = useState("");
  const [action, setAction] = useState("verify_upload");
  const [scanMode, setScanMode] = useState("incremental");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setRows(await api<Rule[]>("/api/schedule"));
  }, []);

  useEffect(() => {
    load().catch((ex) => setError(ex instanceof Error ? ex.message : "Ошибка"));
  }, [load]);

  async function create(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await api("/api/schedule", {
        method: "POST",
        body: JSON.stringify({
          id,
          cron,
          repos: repos.split(",").map((s) => s.trim()).filter(Boolean),
          action,
          scan_mode: scanMode,
        }),
      });
      setId("");
      setRepos("");
      await load();
    } catch (ex) {
      setError(ex instanceof Error ? ex.message : "Ошибка");
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Расписание</h1>
          <p className="lede">
            Ночные и регулярные прогоны. В списке репозиториев можно указать{" "}
            <code>label:prod</code>, чтобы взять все с этой меткой.
          </p>
        </div>
      </div>
      {error ? <div className="banner error">{error}</div> : null}
      <form className="filters" onSubmit={create}>
        <label>
          Имя
          <input required placeholder="id" value={id} onChange={(e) => setId(e.target.value)} />
        </label>
        <label>
          Cron
          <input
            required
            className="mono"
            value={cron}
            onChange={(e) => setCron(e.target.value)}
          />
        </label>
        <label>
          Репозитории
          <input
            required
            placeholder="repos или label:prod"
            value={repos}
            onChange={(e) => setRepos(e.target.value)}
          />
        </label>
        <label>
          Действие
          <select value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="verify_upload">verify_upload</option>
            <option value="verify">verify</option>
            <option value="upload">upload</option>
          </select>
        </label>
        <label>
          Режим
          <select value={scanMode} onChange={(e) => setScanMode(e.target.value)}>
            <option value="incremental">incremental</option>
            <option value="full">full</option>
          </select>
        </label>
        <button className="btn primary" type="submit">
          Добавить
        </button>
      </form>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Имя</th>
              <th>Cron</th>
              <th>Репозитории</th>
              <th>Действие</th>
              <th>Последний запуск</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td>{r.id}</td>
                <td className="mono">{r.cron}</td>
                <td>{r.repos.join(", ")}</td>
                <td>
                  {r.action} / {r.scan_mode}
                </td>
                <td><When value={r.last_fire} /></td>
                <td>
                  <button
                    type="button"
                    className="btn ghost"
                    onClick={async () => {
                      await api(`/api/schedule/${r.id}`, { method: "DELETE" });
                      await load();
                    }}
                  >
                    Удалить
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 ? <p className="empty">Правил нет.</p> : null}
      </div>
    </>
  );
}
