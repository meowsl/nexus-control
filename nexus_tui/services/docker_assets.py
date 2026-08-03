"""Загрузка docker-образов через skopeo (предпочтительно) или docker CLI."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path

from nexus_tui.config import Settings
from nexus_tui.models import DockerTag
from nexus_tui.utils.fs import ensure_parent_dir
from nexus_tui.utils.subprocess_runner import CommandError, run_command, which

logger = logging.getLogger(__name__)


class DockerAssetError(RuntimeError):
    pass


class DockerAssetService:
    """Загрузить docker-тег в локальный docker-archive ``.tar`` файл.

    Допущения по работе с учётными данными (описаны в README):
    - **skopeo**: временный auth JSON файл (mode 600), пароль никогда в argv.
    - **docker**: ``DOCKER_CONFIG`` указывает на временный каталог config с
      записью ``auths`` (base64 username:password), пароль никогда в argv.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def pull_to_archive(self, tag: DockerTag, dest: Path) -> str:
        ensure_parent_dir(dest)
        skopeo = which(self.settings.skopeo_binary)
        if skopeo:
            self._skopeo_copy(skopeo, tag, dest)
            return "skopeo"
        docker = which(self.settings.docker_binary)
        if docker:
            self._docker_pull_save(docker, tag, dest)
            return "docker"
        raise DockerAssetError(
            "Neither skopeo nor docker is available. Install skopeo (preferred) "
            "or docker to download images from docker repositories."
        )

    def _skopeo_copy(self, skopeo: str, tag: DockerTag, dest: Path) -> None:
        src = f"docker://{tag.image_ref}"
        # Пути docker-archive должны быть абсолютными для предсказуемости
        dst = f"docker-archive:{dest.resolve()}"
        with tempfile.TemporaryDirectory(prefix="nexus-tui-skopeo-") as tmp:
            auth_file = Path(tmp) / "auth.json"
            self._write_skopeo_auth(auth_file, tag.image_ref)
            argv = [
                skopeo,
                "copy",
                "--authfile",
                str(auth_file),
                src,
                dst,
            ]
            # Небезопасные registry часты в lab: разрешить, когда SSL verify выключен.
            if not self.settings.nexus_verify_ssl:
                argv.insert(2, "--src-tls-verify=false")
            try:
                run_command(argv, timeout=600, check=True)
            except CommandError as exc:
                raise DockerAssetError(f"skopeo copy failed: {exc}") from exc

    def _docker_pull_save(self, docker: str, tag: DockerTag, dest: Path) -> None:
        with tempfile.TemporaryDirectory(prefix="nexus-tui-docker-") as tmp:
            cfg_dir = Path(tmp)
            self._write_docker_config(cfg_dir, tag.image_ref)
            env = {**os.environ, "DOCKER_CONFIG": str(cfg_dir)}
            try:
                run_command(
                    [docker, "pull", tag.image_ref],
                    timeout=600,
                    check=True,
                    env=env,
                )
                run_command(
                    [docker, "save", "-o", str(dest.resolve()), tag.image_ref],
                    timeout=600,
                    check=True,
                    env=env,
                )
            except CommandError as exc:
                raise DockerAssetError(f"docker pull/save failed: {exc}") from exc

    def _write_skopeo_auth(self, path: Path, image_ref: str) -> None:
        registry = image_ref.split("/", 1)[0]
        # Формат skopeo auth.json
        payload = {
            "auths": {
                registry: {
                    "username": self.settings.nexus_username,
                    "password": self.settings.nexus_password,
                }
            }
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def _write_docker_config(self, cfg_dir: Path, image_ref: str) -> None:
        import base64

        registry = image_ref.split("/", 1)[0]
        token = base64.b64encode(
            f"{self.settings.nexus_username}:{self.settings.nexus_password}".encode()
        ).decode("ascii")
        payload = {"auths": {registry: {"auth": token}}}
        cfg = cfg_dir / "config.json"
        cfg.write_text(json.dumps(payload), encoding="utf-8")
        try:
            os.chmod(cfg, 0o600)
        except OSError:
            pass
