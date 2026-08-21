import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import type { HistoryRun } from "../types";

export default function HistoryPage() {
  const [rows, setRows] = useState<HistoryRun[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    api<HistoryRun[]>("/api/history")
      .then(setRows)
      .catch((ex) => setError(ex instanceof Error ? ex.message : "Ошибка"));
  }, []);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>История сканов</h1>
          <p className="lede">Прогоны из веба, планировщика и командной строки.</p>
        </div>
      </div>
      {error ? <div className="banner error">{error}</div> : null}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Когда</th>
              <th>Репозиторий</th>
              <th>Источник</th>
              <th>PASS</th>
              <th>FAIL</th>
              <th>ERROR</th>
              <th>Пропуск</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.run_id}>
                <td>
                  <Link to={`/history/${r.run_id}`}>{r.started_at}</Link>
                </td>
                <td>
                  <Link to={`/repositories/${encodeURIComponent(r.repository)}`}>
                    {r.repository}
                  </Link>
                </td>
                <td>{r.source}</td>
                <td>{r.totals.passed}</td>
                <td>{r.totals.failed}</td>
                <td>{r.totals.errors}</td>
                <td>{r.totals.checkpoint_skipped}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 ? <p className="empty">История пуста.</p> : null}
      </div>
    </>
  );
}

export function HistoryDetailPage() {
  const { runId = "" } = useParams();
  const [row, setRow] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api<Record<string, unknown>>(`/api/history/${runId}`)
      .then(setRow)
      .catch((ex) => setError(ex instanceof Error ? ex.message : "Не найден"));
  }, [runId]);

  return (
    <>
      <Link to="/history" className="back">
        ← История
      </Link>
      <div className="page-head">
        <div>
          <h1>Прогон {runId}</h1>
        </div>
      </div>
      {error ? <div className="banner error">{error}</div> : null}
      {row ? (
        <pre className="panel mono">{JSON.stringify(row, null, 2)}</pre>
      ) : null}
    </>
  );
}
