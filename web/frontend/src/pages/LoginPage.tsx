import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import BrandMark from "../BrandMark";
import ThemeToggle from "../ThemeToggle";
import { api } from "../api";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const navigate = useNavigate();

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await api("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      navigate("/", { replace: true });
    } catch (ex) {
      setError(ex instanceof Error ? ex.message : "Ошибка входа");
    }
  }

  return (
    <div className="login">
      <aside className="login-aside">
        <div>
          <p className="login-product">
            <BrandMark className="login-mark" />
            Nexus Control
          </p>
          <p className="lede">
            Каталог, метки и расписание сканов — в одном месте. Артефакты по-прежнему
            в Nexus.
          </p>
        </div>
        <p className="login-foot">Управление репозиториями</p>
      </aside>
      <div className="login-form-col">
        <div className="login-theme">
          <ThemeToggle />
        </div>
        <form className="login-panel" onSubmit={onSubmit}>
          <h1>Вход</h1>
          <p className="lede">Учётная запись Nexus Repository.</p>
          {error ? <div className="banner error">{error}</div> : null}
          <label>
            Пользователь
            <input
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </label>
          <label>
            Пароль
            <input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </label>
          <button className="btn primary" type="submit">
            Войти
          </button>
        </form>
      </div>
    </div>
  );
}
