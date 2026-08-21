import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import Select from "../Select";
import type { Label, Repo } from "../types";

export default function RepositoriesPage() {
  const [repos, setRepos] = useState<Repo[]>([]);
  const [labels, setLabels] = useState<Label[]>([]);
  const [q, setQ] = useState("");
  const [fmt, setFmt] = useState("");
  const [kind, setKind] = useState("");
  const [error, setError] = useState("");
  const [params, setParams] = useSearchParams();
  const label = params.get("label") || "";

  useEffect(() => {
    Promise.all([api<Repo[]>("/api/repos"), api<Label[]>("/api/labels")])
      .then(([r, l]) => {
        setRepos(r);
        setLabels(l);
      })
      .catch((ex) => setError(ex instanceof Error ? ex.message : "Ошибка"));
  }, []);

  const formats = useMemo(
    () => [...new Set(repos.map((r) => r.format))].sort(),
    [repos],
  );

  const filtered = useMemo(() => {
    return repos.filter((r) => {
      if (q && !r.name.toLowerCase().includes(q.toLowerCase())) return false;
      if (fmt && r.format !== fmt) return false;
      if (kind && r.type !== kind) return false;
      if (label && !r.labels.some((x) => x.name === label)) return false;
      return true;
    });
  }, [repos, q, fmt, kind, label]);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Репозитории</h1>
          <p className="lede">
            Каталог Nexus
            {repos.length ? ` · показано ${filtered.length} из ${repos.length}` : ""}.
          </p>
        </div>
      </div>
      {error ? <div className="banner error">{error}</div> : null}
      <div className="filters">
        <label>
          Поиск
          <input
            placeholder="Поиск по имени"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </label>
        <label>
          Формат
          <Select
            value={fmt}
            onChange={setFmt}
            options={[
              { value: "", label: "Все форматы" },
              ...formats.map((f) => ({ value: f, label: f })),
            ]}
          />
        </label>
        <label>
          Тип
          <Select
            value={kind}
            onChange={setKind}
            options={[
              { value: "", label: "Все типы" },
              { value: "hosted", label: "hosted" },
              { value: "proxy", label: "proxy" },
              { value: "group", label: "group" },
            ]}
          />
        </label>
        <label>
          Метка
          <Select
            value={label}
            onChange={(next) => {
              const paramsNext = new URLSearchParams(params);
              if (next) paramsNext.set("label", next);
              else paramsNext.delete("label");
              setParams(paramsNext, { replace: true });
            }}
            options={[
              { value: "", label: "Все метки" },
              ...labels.map((l) => ({ value: l.name, label: l.name })),
            ]}
          />
        </label>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Имя</th>
              <th>Формат</th>
              <th>Тип</th>
              <th>Метки</th>
              <th>Поддержка</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((r) => (
              <tr key={r.name}>
                <td>
                  <Link className="repo-name" to={`/repositories/${encodeURIComponent(r.name)}`}>
                    {r.name}
                  </Link>
                </td>
                <td>{r.format}</td>
                <td>
                  <span className={`type type-${r.type}`}>{r.type}</span>
                </td>
                <td>
                  {r.labels.length === 0 ? (
                    <span className="muted">—</span>
                  ) : (
                    r.labels.map((l) => (
                      <span key={l.id} className="pill">
                        <i style={{ background: l.color }} />
                        {l.name}
                      </span>
                    ))
                  )}
                </td>
                <td className="muted">{r.support}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 ? (
          <p className="empty">Нет репозиториев по фильтру.</p>
        ) : null}
      </div>
    </>
  );
}
