import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { jobStatusLabel } from "../format";
import When from "../When";
import type { Job } from "../types";

export default function JobsPage() {
  const [rows, setRows] = useState<Job[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    const tick = () => {
      api<Job[]>("/api/jobs")
        .then(setRows)
        .catch((ex) => setError(ex instanceof Error ? ex.message : "Ошибка"));
    };
    tick();
    const id = setInterval(tick, 4000);
    return () => clearInterval(id);
  }, []);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Задачи</h1>
          <p className="lede">Проверки и выгрузки, которые сейчас в очереди или уже идут.</p>
        </div>
      </div>
      {error ? <div className="banner error">{error}</div> : null}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Репозиторий</th>
              <th>Статус</th>
              <th>Режим</th>
              <th>Прогресс</th>
              <th>Создана</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((j) => (
              <tr key={j.id}>
                <td>
                  <Link to={`/repositories/${encodeURIComponent(j.repository)}`}>
                    {j.repository}
                  </Link>
                </td>
                <td>
                  <span className={`badge status-${j.status}`}>{jobStatusLabel(j.status)}</span>
                </td>
                <td>
                  {j.scan_mode}
                  {j.upload ? " + upload" : ""}
                </td>
                <td>
                  <div className="progress">
                    <i style={{ width: `${Math.round(j.progress * 100)}%` }} />
                  </div>
                  <div className="muted">{j.progress_text || j.error || "—"}</div>
                </td>
                <td><When value={j.created_at} /></td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 ? <p className="empty">Очередь пуста.</p> : null}
      </div>
    </>
  );
}
