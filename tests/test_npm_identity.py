"""Tests for npm identity staging (Trivy/Grype lockfile)."""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

import pytest

from nexus_control.services.npm_identity import (
    NpmIdentityError,
    extract_npm_identity,
    is_npm_package_tarball,
    prepare_npm_identity_staging,
)


def _make_npm_tgz(path: Path, *, name: str, version: str) -> Path:
    pkg = {"name": name, "version": version, "description": "test"}
    inner = path.with_suffix(".dir")
    pkg_dir = inner / "package"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
    (pkg_dir / "index.js").write_text("module.exports = {}\n", encoding="utf-8")
    with tarfile.open(path, "w:gz") as tf:
        tf.add(pkg_dir, arcname="package")
    return path


def test_is_npm_package_tarball() -> None:
    assert is_npm_package_tarball(Path("lodash-4.17.11.tgz"))
    assert is_npm_package_tarball(Path("foo.tar.gz"))
    assert not is_npm_package_tarball(Path("foo.jar"))
    assert not is_npm_package_tarball(Path("foo.zip"))


def test_extract_and_staging(tmp_path: Path) -> None:
    tgz = _make_npm_tgz(tmp_path / "lodash-4.17.11.tgz", name="lodash", version="4.17.11")
    identity = extract_npm_identity(tgz)
    assert identity.name == "lodash"
    assert identity.version == "4.17.11"

    staging = tmp_path / "stage"
    ident2, out = prepare_npm_identity_staging(tgz, staging)
    assert ident2 == identity
    assert out == staging
    lock = json.loads((staging / "package-lock.json").read_text(encoding="utf-8"))
    assert lock["lockfileVersion"] == 2
    assert "node_modules/lodash" in lock["packages"]
    assert lock["packages"]["node_modules/lodash"]["version"] == "4.17.11"
    pkg = json.loads((staging / "package.json").read_text(encoding="utf-8"))
    assert pkg["dependencies"]["lodash"] == "4.17.11"


def test_scoped_package_staging(tmp_path: Path) -> None:
    tgz = _make_npm_tgz(
        tmp_path / "core-1.0.0.tgz", name="@babel/core", version="1.0.0"
    )
    identity, staging = prepare_npm_identity_staging(tgz, tmp_path / "stage")
    assert identity.node_modules_relpath == "node_modules/@babel/core"
    lock = json.loads((staging / "package-lock.json").read_text(encoding="utf-8"))
    assert "node_modules/@babel/core" in lock["packages"]


def test_missing_package_json(tmp_path: Path) -> None:
    tgz = tmp_path / "empty.tgz"
    junk = tmp_path / "junk"
    junk.mkdir()
    (junk / "readme.txt").write_text("x", encoding="utf-8")
    with tarfile.open(tgz, "w:gz") as tf:
        tf.add(junk / "readme.txt", arcname="readme.txt")
    with pytest.raises(NpmIdentityError, match="package.json"):
        extract_npm_identity(tgz)
