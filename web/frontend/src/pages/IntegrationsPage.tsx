import { FormEvent, useEffect, useState } from "react";
import { api } from "../api";
import Select from "../Select";

type DefectDojo = {
  enabled: boolean;
  url: string;
  verify_ssl: boolean;
  product_name: string;
  engagement_name: string;
  product_type_name: string;
  api_key_set: boolean;
  source: string;
};

type Webhook = {
  enabled: boolean;
  url: string;
  auth: string;
  verify_ssl: boolean;
  timeout: number;
  header_name: string;
  username: string;
  token_set: boolean;
  password_set: boolean;
  header_value_set: boolean;
  source: string;
};

type VkTeams = {
  enabled: boolean;
  notify: string;
  api_url: string;
  chat_id: string;
  upload_button: boolean;
  verify_ssl: boolean;
  timeout: number;
  token_set: boolean;
  source: string;
};

type Bundle = { defectdojo: DefectDojo; webhook: Webhook; vk_teams: VkTeams };

export default function IntegrationsPage() {
  const [data, setData] = useState<Bundle | null>(null);
  const [error, setError] = useState("");

  async function load() {
    setData(await api<Bundle>("/api/integrations"));
  }

  useEffect(() => {
    load().catch((ex) => setError(ex instanceof Error ? ex.message : "Ошибка"));
  }, []);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Интеграции</h1>
          <p className="lede">
            DefectDojo, исходящий webhook и VK Teams. Секреты шифруются; пустое поле
            не затирает уже сохранённый ключ.
          </p>
        </div>
      </div>
      {error ? <div className="banner error">{error}</div> : null}
      {!data ? (
        <p className="muted">Загрузка…</p>
      ) : (
        <div className="cards">
          <DefectDojoCard initial={data.defectdojo} onSaved={load} />
          <WebhookCard initial={data.webhook} onSaved={load} />
          <VkCard initial={data.vk_teams} onSaved={load} />
        </div>
      )}
    </>
  );
}

function Source({ source }: { source: string }) {
  return (
    <span className="muted">
      источник: {source === "web" ? "веб-настройки" : "env / config.toml"}
    </span>
  );
}

function DefectDojoCard({
  initial,
  onSaved,
}: {
  initial: DefectDojo;
  onSaved: () => Promise<void>;
}) {
  const [enabled, setEnabled] = useState(initial.enabled);
  const [url, setUrl] = useState(initial.url);
  const [verifySsl, setVerifySsl] = useState(initial.verify_ssl);
  const [product, setProduct] = useState(initial.product_name);
  const [engagement, setEngagement] = useState(initial.engagement_name);
  const [productType, setProductType] = useState(initial.product_type_name);
  const [apiKey, setApiKey] = useState("");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  useEffect(() => {
    setEnabled(initial.enabled);
    setUrl(initial.url);
    setVerifySsl(initial.verify_ssl);
    setProduct(initial.product_name);
    setEngagement(initial.engagement_name);
    setProductType(initial.product_type_name);
  }, [initial]);

  async function save(e: FormEvent) {
    e.preventDefault();
    setErr("");
    setMsg("");
    try {
      await api("/api/integrations/defectdojo", {
        method: "PUT",
        body: JSON.stringify({
          enabled,
          url,
          verify_ssl: verifySsl,
          product_name: product,
          engagement_name: engagement,
          product_type_name: productType,
          api_key: apiKey,
        }),
      });
      setApiKey("");
      setMsg("Сохранено");
      await onSaved();
    } catch (ex) {
      setErr(ex instanceof Error ? ex.message : "Ошибка");
    }
  }

  return (
    <form className="panel" onSubmit={save}>
      <header>
        <h2>DefectDojo</h2>
        <Source source={initial.source} />
      </header>
      <p className="lede">
        После verify FAIL-находки уходят в Generic Findings Import. API-ключ — из
        профиля DefectDojo.
      </p>
      {err ? <div className="banner error">{err}</div> : null}
      <div className="form-grid">
        <label className="check">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Включить
        </label>
        <label>
          URL
          <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://defectdojo.example" />
        </label>
        <label className="check">
          <input type="checkbox" checked={verifySsl} onChange={(e) => setVerifySsl(e.target.checked)} />
          Проверять TLS
        </label>
        <label>
          Product
          <input value={product} onChange={(e) => setProduct(e.target.value)} />
        </label>
        <label>
          Engagement (пусто = имя репозитория)
          <input value={engagement} onChange={(e) => setEngagement(e.target.value)} />
        </label>
        <label>
          Product type
          <input value={productType} onChange={(e) => setProductType(e.target.value)} />
        </label>
        <label>
          API key {initial.api_key_set ? "(задан)" : "(нет)"}
          <input
            type="password"
            autoComplete="new-password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder="оставьте пустым, чтобы не менять"
          />
        </label>
      </div>
      <div className="form-actions">
        <button className="btn primary" type="submit">
          Сохранить
        </button>
        <TestButton path="/api/integrations/defectdojo/test" />
        {msg ? <span className="ok">{msg}</span> : null}
      </div>
    </form>
  );
}

function WebhookCard({
  initial,
  onSaved,
}: {
  initial: Webhook;
  onSaved: () => Promise<void>;
}) {
  const [enabled, setEnabled] = useState(initial.enabled);
  const [url, setUrl] = useState(initial.url);
  const [auth, setAuth] = useState(initial.auth);
  const [verifySsl, setVerifySsl] = useState(initial.verify_ssl);
  const [timeout, setTimeoutSec] = useState(String(initial.timeout));
  const [headerName, setHeaderName] = useState(initial.header_name);
  const [username, setUsername] = useState(initial.username);
  const [token, setToken] = useState("");
  const [password, setPassword] = useState("");
  const [headerValue, setHeaderValue] = useState("");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  useEffect(() => {
    setEnabled(initial.enabled);
    setUrl(initial.url);
    setAuth(initial.auth);
    setVerifySsl(initial.verify_ssl);
    setTimeoutSec(String(initial.timeout));
    setHeaderName(initial.header_name);
    setUsername(initial.username);
  }, [initial]);

  async function save(e: FormEvent) {
    e.preventDefault();
    setErr("");
    setMsg("");
    try {
      await api("/api/integrations/webhook", {
        method: "PUT",
        body: JSON.stringify({
          enabled,
          url,
          auth,
          verify_ssl: verifySsl,
          timeout: Number(timeout) || 15,
          header_name: headerName,
          username,
          token,
          password,
          header_value: headerValue,
        }),
      });
      setToken("");
      setPassword("");
      setHeaderValue("");
      setMsg("Сохранено");
      await onSaved();
    } catch (ex) {
      setErr(ex instanceof Error ? ex.message : "Ошибка");
    }
  }

  return (
    <form className="panel" onSubmit={save}>
      <header>
        <h2>Webhook</h2>
        <Source source={initial.source} />
      </header>
      <p className="lede">POST JSON после каждого verify (тот же payload, что CLI webhook).</p>
      {err ? <div className="banner error">{err}</div> : null}
      <div className="form-grid">
        <label className="check">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Включить
        </label>
        <label>
          URL
          <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://hooks.example.com/scan" />
        </label>
        <label>
          Auth
          <Select
            value={auth}
            onChange={setAuth}
            options={[
              { value: "none", label: "none" },
              { value: "bearer", label: "bearer" },
              { value: "basic", label: "basic" },
              { value: "header", label: "header" },
            ]}
          />
        </label>
        {auth === "bearer" ? (
          <label>
            Token {initial.token_set ? "(задан)" : ""}
            <input type="password" value={token} onChange={(e) => setToken(e.target.value)} placeholder="оставьте пустым, чтобы не менять" />
          </label>
        ) : null}
        {auth === "basic" ? (
          <>
            <label>
              Username
              <input value={username} onChange={(e) => setUsername(e.target.value)} />
            </label>
            <label>
              Password {initial.password_set ? "(задан)" : ""}
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="оставьте пустым, чтобы не менять" />
            </label>
          </>
        ) : null}
        {auth === "header" ? (
          <>
            <label>
              Header name
              <input value={headerName} onChange={(e) => setHeaderName(e.target.value)} placeholder="X-Api-Key" />
            </label>
            <label>
              Header value {initial.header_value_set ? "(задан)" : ""}
              <input type="password" value={headerValue} onChange={(e) => setHeaderValue(e.target.value)} placeholder="оставьте пустым, чтобы не менять" />
            </label>
          </>
        ) : null}
        <label className="check">
          <input type="checkbox" checked={verifySsl} onChange={(e) => setVerifySsl(e.target.checked)} />
          Проверять TLS
        </label>
        <label>
          Timeout, сек
          <input type="number" min={1} max={120} value={timeout} onChange={(e) => setTimeoutSec(e.target.value)} />
        </label>
      </div>
      <div className="form-actions">
        <button className="btn primary" type="submit">
          Сохранить
        </button>
        <TestButton path="/api/integrations/webhook/test" />
        {msg ? <span className="ok">{msg}</span> : null}
      </div>
    </form>
  );
}

function VkCard({
  initial,
  onSaved,
}: {
  initial: VkTeams;
  onSaved: () => Promise<void>;
}) {
  const [enabled, setEnabled] = useState(initial.enabled);
  const [notify, setNotify] = useState(initial.notify === "off" ? "always" : initial.notify);
  const [apiUrl, setApiUrl] = useState(initial.api_url);
  const [chatId, setChatId] = useState(initial.chat_id);
  const [uploadButton, setUploadButton] = useState(initial.upload_button);
  const [verifySsl, setVerifySsl] = useState(initial.verify_ssl);
  const [token, setToken] = useState("");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  useEffect(() => {
    setEnabled(initial.enabled);
    setNotify(initial.notify === "off" ? "always" : initial.notify);
    setApiUrl(initial.api_url);
    setChatId(initial.chat_id);
    setUploadButton(initial.upload_button);
    setVerifySsl(initial.verify_ssl);
  }, [initial]);

  async function save(e: FormEvent) {
    e.preventDefault();
    setErr("");
    setMsg("");
    try {
      await api("/api/integrations/vk-teams", {
        method: "PUT",
        body: JSON.stringify({
          enabled,
          notify: enabled ? notify : "off",
          api_url: apiUrl,
          chat_id: chatId,
          upload_button: uploadButton,
          verify_ssl: verifySsl,
          token,
        }),
      });
      setToken("");
      setMsg("Сохранено");
      await onSaved();
    } catch (ex) {
      setErr(ex instanceof Error ? ex.message : "Ошибка");
    }
  }

  return (
    <form className="panel" onSubmit={save}>
      <header>
        <h2>VK Teams</h2>
        <Source source={initial.source} />
      </header>
      <p className="lede">Уведомления о прогонах и кнопка Upload (как в scheduler).</p>
      {err ? <div className="banner error">{err}</div> : null}
      <div className="form-grid">
        <label className="check">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Включить
        </label>
        <label>
          Когда слать
          <Select
            value={notify}
            onChange={setNotify}
            disabled={!enabled}
            options={[
              { value: "always", label: "always — каждый прогон" },
              { value: "failures", label: "failures — только FAIL" },
            ]}
          />
        </label>
        <label>
          API URL
          <input value={apiUrl} onChange={(e) => setApiUrl(e.target.value)} />
        </label>
        <label>
          Chat ID
          <input value={chatId} onChange={(e) => setChatId(e.target.value)} />
        </label>
        <label>
          Bot token {initial.token_set ? "(задан)" : "(нет)"}
          <input
            type="password"
            autoComplete="new-password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="оставьте пустым, чтобы не менять"
          />
        </label>
        <label className="check">
          <input type="checkbox" checked={uploadButton} onChange={(e) => setUploadButton(e.target.checked)} />
          Кнопка Upload в сообщении
        </label>
        <label className="check">
          <input type="checkbox" checked={verifySsl} onChange={(e) => setVerifySsl(e.target.checked)} />
          Проверять TLS
        </label>
      </div>
      <div className="form-actions">
        <button className="btn primary" type="submit">
          Сохранить
        </button>
        <TestButton path="/api/integrations/vk-teams/test" />
        {msg ? <span className="ok">{msg}</span> : null}
      </div>
    </form>
  );
}

function TestButton({ path }: { path: string }) {
  const [busy, setBusy] = useState(false);
  const [text, setText] = useState("");
  const [ok, setOk] = useState<boolean | null>(null);

  async function run() {
    setBusy(true);
    setText("");
    setOk(null);
    try {
      await api(path, { method: "POST" });
      setOk(true);
      setText("Связь есть");
    } catch (ex) {
      setOk(false);
      setText(ex instanceof Error ? ex.message : "Ошибка");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button type="button" className="btn" disabled={busy} onClick={() => void run()}>
        {busy ? "Проверка…" : "Проверить связь"}
      </button>
      {text ? <span className={ok ? "ok" : "muted"}>{text}</span> : null}
    </>
  );
}
