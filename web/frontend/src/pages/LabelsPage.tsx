import { FormEvent, useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import type { Label } from "../types";

export default function LabelsPage() {
  const [rows, setRows] = useState<Label[]>([]);
  const [name, setName] = useState("");
  const [color, setColor] = useState("#3f3f46");
  const [description, setDescription] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setRows(await api<Label[]>("/api/labels"));
  }, []);

  useEffect(() => {
    load().catch((ex) => setError(ex instanceof Error ? ex.message : "Ошибка"));
  }, [load]);

  async function create(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await api("/api/labels", {
        method: "POST",
        body: JSON.stringify({ name, color, description }),
      });
      setName("");
      setDescription("");
      await load();
    } catch (ex) {
      setError(ex instanceof Error ? ex.message : "Ошибка");
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Метки</h1>
          <p className="lede">
            Цветные ярлыки для репозиториев. По ним можно фильтровать список и
            собирать расписание через <code>label:имя</code>.
          </p>
        </div>
      </div>
      {error ? <div className="banner error">{error}</div> : null}
      <form className="filters" onSubmit={create}>
        <label>
          Имя
          <input
            required
            placeholder="prod"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        <label>
          Цвет
          <input
            type="color"
            value={color}
            onChange={(e) => setColor(e.target.value)}
          />
        </label>
        <label>
          Описание
          <input
            placeholder="описание"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </label>
        <button className="btn primary" type="submit">
          Создать
        </button>
      </form>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Метка</th>
              <th>Описание</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((l) => (
              <tr key={l.id}>
                <td>
                  <span className="pill">
                    <i style={{ background: l.color }} />
                    {l.name}
                  </span>
                </td>
                <td>{l.description || "—"}</td>
                <td>
                  <Link to={`/repositories?label=${encodeURIComponent(l.name)}`}>
                    репозитории
                  </Link>{" "}
                  <button
                    type="button"
                    className="btn ghost"
                    onClick={async () => {
                      await api(`/api/labels/${l.id}`, { method: "DELETE" });
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
        {rows.length === 0 ? <p className="empty">Меток пока нет.</p> : null}
      </div>
    </>
  );
}
