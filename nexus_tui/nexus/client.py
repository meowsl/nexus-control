"""HTTP-клиент для REST API Nexus Repository CE."""

from __future__ import annotations

import logging
from typing import Any, Iterator
from urllib.parse import urljoin

import httpx
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from nexus_tui.config import Settings
from nexus_tui.models import AuthType, DockerTag, NexusAsset, Repository
from nexus_tui.nexus.assets import parse_asset, parse_assets_page
from nexus_tui.nexus.repositories import parse_repositories
from nexus_tui.nexus.session import SessionCache, SessionStore

logger = logging.getLogger(__name__)


class NexusAPIError(Exception):
    """Базовая ошибка Nexus API с опциональным HTTP-статусом."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class NexusAuthError(NexusAPIError):
    """Ошибка аутентификации / авторизации."""


class NexusNotFoundError(NexusAPIError):
    """Ресурс не найден."""


class NexusNetworkError(NexusAPIError):
    """Ошибка подключения / транспорта."""


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, NexusAPIError) and exc.status_code is not None:
        return exc.status_code >= 500
    if isinstance(exc, (httpx.TimeoutException, httpx.NetworkError, httpx.TransportError)):
        return True
    return False


class NexusClient:
    """Синхронный REST-клиент Nexus для использования внутри Textual workers."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.session_store = SessionStore(settings.nexus_cache_dir)
        self._client: httpx.Client | None = None
        self._session: SessionCache | None = None
        self._reauth_attempts = 0
        self._max_reauth = 1

    # ------------------------------------------------------------------ жизненный цикл
    def open(self) -> None:
        """Создать HTTP-клиент и установить / восстановить сессию."""
        if self._client is not None:
            return
        self._client = httpx.Client(
            base_url=self.settings.nexus_url,
            timeout=self.settings.nexus_timeout,
            verify=self.settings.nexus_verify_ssl,
            headers={"Accept": "application/json", "User-Agent": "nexus-tui/1.0"},
            follow_redirects=True,
            auth=httpx.BasicAuth(
                self.settings.nexus_username,
                self.settings.nexus_password,
            ),
        )
        self._establish_session()

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> NexusClient:
        self.open()
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            raise RuntimeError("NexusClient is not open; call open() first")
        return self._client

    @property
    def session(self) -> SessionCache | None:
        return self._session

    # -------------------------------------------------------------- сессия
    def _establish_session(self) -> None:
        cached = self.session_store.load()
        if (
            cached
            and cached.schema_version >= 1
            and cached.matches(self.settings.nexus_url, self.settings.nexus_username)
            and not cached.is_expired()
        ):
            self._apply_cookies(cached)
            try:
                self._status_check()
                self._session = self.session_store.touch(cached)
                logger.info(
                    "Using cached Nexus session until %s",
                    cached.expires_at,
                )
                return
            except NexusAuthError:
                logger.info("Cached session rejected by server; re-authenticating")
                self.session_store.invalidate()
            except NexusAPIError as exc:
                # Сеть / 5xx при проверке: всё равно попробовать свежую аутентификацию
                logger.warning("Session verify failed (%s); re-authenticating", exc)

        self._authenticate()

    def _apply_cookies(self, session: SessionCache) -> None:
        for name, value in session.cookies.items():
            self.client.cookies.set(name, value)

    def _authenticate(self) -> None:
        """Проверить учётные данные лёгким status-запросом и закэшировать успех."""
        logger.info("Authenticating to Nexus as %s", self.settings.nexus_username)
        try:
            self._status_check()
        except NexusAuthError:
            self.session_store.invalidate()
            raise NexusAuthError(
                "Authentication failed: invalid username/password or insufficient "
                "permissions. Check NEXUS_USERNAME / NEXUS_PASSWORD."
            ) from None

        cookies = {c.name: c.value for c in self.client.cookies.jar}
        auth_type = AuthType.COOKIE if cookies else AuthType.BASIC
        self._session = self.session_store.create(
            nexus_url=self.settings.nexus_url,
            username=self.settings.nexus_username,
            ttl_seconds=self.settings.nexus_session_ttl,
            auth_type=auth_type,
            cookies=cookies,
        )
        self._reauth_attempts = 0
        logger.info("Nexus authentication successful (auth_type=%s)", auth_type.value)

    def _status_check(self) -> dict[str, Any]:
        """Лёгкий аутентифицированный запрос для проверки сессии."""
        # /status публичен на некоторых установках; /repositories требует auth и предпочтителен.
        return self._request_json("GET", "/service/rest/v1/repositories")

    def invalidate_and_reauth(self) -> None:
        self.session_store.invalidate()
        self._session = None
        self._authenticate()

    # -------------------------------------------------------------- HTTP
    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        allow_reauth: bool = True,
        stream: bool = False,
    ) -> httpx.Response:
        url = path if path.startswith("http") else path
        try:
            response = self.client.request(
                method,
                url,
                params=params,
                timeout=self.settings.nexus_timeout,
            )
        except httpx.TimeoutException as exc:
            raise NexusNetworkError(
                f"Nexus request timed out after {self.settings.nexus_timeout}s: {path}"
            ) from exc
        except httpx.RequestError as exc:
            raise NexusNetworkError(f"Network error talking to Nexus: {exc}") from exc

        if response.status_code in {401, 403} and allow_reauth:
            if self._reauth_attempts < self._max_reauth:
                self._reauth_attempts += 1
                logger.warning(
                    "Received %s; invalidating cache and re-authenticating once",
                    response.status_code,
                )
                try:
                    self.invalidate_and_reauth()
                except NexusAuthError:
                    raise
                return self._request(
                    method,
                    path,
                    params=params,
                    allow_reauth=False,
                    stream=stream,
                )
            if response.status_code == 401:
                raise NexusAuthError(
                    "Unauthorized (401) after re-authentication. Check credentials.",
                    status_code=401,
                )
            raise NexusAuthError(
                "Forbidden (403): your user cannot access this resource.",
                status_code=403,
            )

        if response.status_code == 404:
            raise NexusNotFoundError(
                f"Resource not found (404): {path}",
                status_code=404,
            )
        if response.status_code >= 500:
            raise NexusAPIError(
                f"Nexus server error ({response.status_code}) for {path}",
                status_code=response.status_code,
            )
        if response.status_code >= 400:
            detail = _safe_body(response)
            raise NexusAPIError(
                f"Nexus HTTP {response.status_code} for {path}: {detail}",
                status_code=response.status_code,
            )
        return response

    @retry(
        retry=retry_if_exception(_is_retryable),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.5, min=0.5, max=4),
        reraise=True,
    )
    def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> Any:
        response = self._request(method, path, params=params)
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise NexusAPIError(f"Invalid JSON from Nexus: {path}") from exc

    # -------------------------------------------------------------- API
    def list_repositories(self) -> list[Repository]:
        data = self._request_json("GET", "/service/rest/v1/repositories")
        repos = parse_repositories(data)
        repos.sort(key=lambda r: r.name.lower())
        return repos

    def iter_assets(self, repository: str) -> Iterator[NexusAsset]:
        """Перебирать все артефакты, следуя пагинации ``continuationToken``."""
        token: str | None = None
        while True:
            params: dict[str, Any] = {"repository": repository}
            if token:
                params["continuationToken"] = token
            data = self._request_json("GET", "/service/rest/v1/assets", params=params)
            items, token = parse_assets_page(data)
            for item in items:
                yield item
            if not token:
                break

    def list_assets(self, repository: str) -> list[NexusAsset]:
        return list(self.iter_assets(repository))

    def stream_download(self, url: str) -> httpx.Response:
        """Открыть потоковый GET для загрузки артефакта.

        Вызывающий код должен закрыть response. Повторы применяются только до
        передачи потока вызывающему (при ошибках подключения / HTTP-статуса).
        """
        last_exc: Exception | None = None
        for attempt in range(1, 4):
            try:
                request = self.client.build_request("GET", url)
                response = self.client.send(request, stream=True)
                if response.status_code in {401, 403} and self._reauth_attempts < self._max_reauth:
                    response.close()
                    self._reauth_attempts += 1
                    self.invalidate_and_reauth()
                    continue
                if response.status_code == 404:
                    response.close()
                    raise NexusNotFoundError(f"Download URL not found: {url}", 404)
                if response.status_code in {401, 403}:
                    response.close()
                    raise NexusAuthError(
                        f"Download unauthorized ({response.status_code}): {url}",
                        response.status_code,
                    )
                if response.status_code >= 500:
                    response.close()
                    raise NexusAPIError(
                        f"Server error {response.status_code} downloading {url}",
                        response.status_code,
                    )
                if response.status_code >= 400:
                    detail = _safe_body(response)
                    response.close()
                    raise NexusAPIError(
                        f"Download failed ({response.status_code}): {detail}",
                        response.status_code,
                    )
                return response
            except (httpx.TimeoutException, httpx.NetworkError, httpx.TransportError) as exc:
                last_exc = NexusNetworkError(f"Network error downloading {url}: {exc}")
                if attempt >= 3:
                    raise last_exc from exc
            except NexusAPIError as exc:
                if exc.status_code and exc.status_code >= 500 and attempt < 3:
                    last_exc = exc
                    continue
                raise
        raise last_exc or NexusNetworkError(f"Failed to download {url}")

    def resolve_download_url(self, asset: NexusAsset) -> str:
        if asset.download_url:
            return asset.download_url
        # Запасной вариант: шаблон URL контента Nexus (best-effort).
        # /repository/{repo}/{path}
        path = asset.path.lstrip("/")
        return urljoin(self.settings.nexus_url + "/", f"repository/{asset.repository}/{path}")

    # ------------------------------------------------------- docker-теги
    def list_docker_tags(self, repository: Repository) -> list[DockerTag]:
        """Список docker-тегов через Registry v2 API с запасным вариантом через assets API."""
        registry = self._docker_registry_host(repository)
        if registry:
            try:
                return self._list_tags_registry_v2(registry, repository.name)
            except NexusAPIError as exc:
                logger.warning(
                    "Docker Registry v2 tag listing failed (%s); falling back to assets API",
                    exc,
                )
        return self._list_tags_from_assets(repository.name, registry)

    def _docker_registry_host(self, repository: Repository) -> str | None:
        if self.settings.nexus_docker_registry.strip():
            return self.settings.nexus_docker_registry.strip().rstrip("/")
        attrs = repository.attributes or {}
        docker_attrs = attrs.get("docker") or attrs.get("dockerProxy") or {}
        if isinstance(docker_attrs, dict):
            port = docker_attrs.get("httpPort") or docker_attrs.get("httpsPort")
            if port:
                # Вывести хост из hostname NEXUS_URL
                host = httpx.URL(self.settings.nexus_url).host or "localhost"
                scheme_port = int(port)
                # Предпочтительно host:port без схемы для skopeo/docker refs.
                return f"{host}:{scheme_port}"
        # Крайний случай: некоторые установки expose docker на том же URL — не пригодно
        # для skopeo без выделенного порта connector.
        return None

    def _list_tags_registry_v2(self, registry: str, repository: str) -> list[DockerTag]:
        # registry может быть host:port — общаться по HTTP с docker connector Nexus.
        # Допущение: в lab-окружениях часто plain HTTP на порту connector.
        base = registry if registry.startswith("http") else f"http://{registry}"
        path = f"/v2/{repository}/tags/list"
        # Использовать кратковременный клиент без перезаписи base_url основного клиента.
        with httpx.Client(
            base_url=base,
            timeout=self.settings.nexus_timeout,
            verify=self.settings.nexus_verify_ssl,
            auth=httpx.BasicAuth(
                self.settings.nexus_username,
                self.settings.nexus_password,
            ),
            follow_redirects=True,
        ) as docker_client:
            try:
                response = docker_client.get(path)
            except httpx.RequestError as exc:
                raise NexusNetworkError(f"Docker registry unreachable at {base}: {exc}") from exc
            if response.status_code in {401, 403}:
                raise NexusAuthError(
                    f"Docker registry auth failed ({response.status_code}) at {base}",
                    status_code=response.status_code,
                )
            if response.status_code >= 400:
                raise NexusAPIError(
                    f"Docker tags list failed ({response.status_code}) at {base}{path}",
                    status_code=response.status_code,
                )
            data = response.json()
        tags = data.get("tags") or []
        host = registry.removeprefix("http://").removeprefix("https://")
        result = [
            DockerTag(
                repository=repository,
                tag=str(tag),
                image_ref=f"{host}/{repository}:{tag}",
            )
            for tag in tags
        ]
        result.sort(key=lambda t: t.tag.lower())
        return result

    def _list_tags_from_assets(
        self,
        repository: str,
        registry: str | None,
    ) -> list[DockerTag]:
        """Запасной вариант: вывести теги из путей артефактов вроде ``v2/<repo>/manifests/<tag>``."""
        tags: dict[str, DockerTag] = {}
        host = (registry or "unknown-registry").removeprefix("http://").removeprefix("https://")
        for asset in self.iter_assets(repository):
            path = asset.path.strip("/")
            parts = path.split("/")
            # Типичная структура docker-артефактов Nexus: v2/<name>/manifests/<tag>
            if "manifests" in parts:
                idx = parts.index("manifests")
                if idx + 1 < len(parts):
                    tag = parts[idx + 1]
                    if tag.startswith("sha256:"):
                        continue
                    tags[tag] = DockerTag(
                        repository=repository,
                        tag=tag,
                        image_ref=f"{host}/{repository}:{tag}",
                    )
        return sorted(tags.values(), key=lambda t: t.tag.lower())


def _safe_body(response: httpx.Response, limit: int = 200) -> str:
    try:
        text = response.text.strip().replace("\n", " ")
    except Exception:  # noqa: BLE001
        return ""
    return text[:limit]
