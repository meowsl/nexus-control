"""Tests for PyPI identity staging (Grype/Trivy requirements.txt, osv lockfile)."""

from __future__ import annotations

import json
import tarfile
import zipfile
from pathlib import Path

import pytest

from nexus_control.services.pypi_identity import (
    PypiIdentityError,
    extract_pypi_identity,
    is_pypi_package_file,
    prepare_pypi_identity_staging,
    write_pypi_osv_identity_lockfile,
)
from nexus_control.services.verified_uploader import expand_revoke_keys


def _make_wheel(path: Path, *, name: str, version: str) -> Path:
    dist = f"{name}-{version}.dist-info"
    metadata = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(f"{dist}/METADATA", metadata)
        zf.writestr(f"{name}/__init__.py", "# seed\n")
    return path


def test_is_pypi_package_file() -> None:
    assert is_pypi_package_file(Path("Jinja2-2.11.2-py2.py3-none-any.whl"))
    assert is_pypi_package_file(Path("pkg-1.0.tar.gz"))
    assert is_pypi_package_file(Path("pkg-1.0.zip"))
    assert not is_pypi_package_file(Path("lodash-4.17.21.tgz"))
    assert not is_pypi_package_file(Path("foo.jar"))


def test_extract_and_staging_wheel(tmp_path: Path) -> None:
    whl = _make_wheel(tmp_path / "Jinja2-2.11.2-py3-none-any.whl", name="Jinja2", version="2.11.2")
    identity = extract_pypi_identity(whl)
    assert identity.name == "Jinja2"
    assert identity.version == "2.11.2"

    staging = tmp_path / "stage"
    ident2, out = prepare_pypi_identity_staging(whl, staging)
    assert ident2 == identity
    assert out == staging
    assert (staging / "requirements.txt").read_text(encoding="utf-8") == "Jinja2==2.11.2\n"


def test_extract_sdist_pkg_info(tmp_path: Path) -> None:
    sdist = tmp_path / "PyYAML-5.3.1.tar.gz"
    inner = tmp_path / "tree"
    pkg = inner / "PyYAML-5.3.1"
    pkg.mkdir(parents=True)
    (pkg / "PKG-INFO").write_text(
        "Metadata-Version: 1.2\nName: PyYAML\nVersion: 5.3.1\n",
        encoding="utf-8",
    )
    with tarfile.open(sdist, "w:gz") as tf:
        tf.add(pkg / "PKG-INFO", arcname="PyYAML-5.3.1/PKG-INFO")
    identity = extract_pypi_identity(sdist)
    assert identity.name == "PyYAML"
    assert identity.version == "5.3.1"


def test_missing_metadata(tmp_path: Path) -> None:
    whl = tmp_path / "empty.whl"
    with zipfile.ZipFile(whl, "w") as zf:
        zf.writestr("readme.txt", "x")
    with pytest.raises(PypiIdentityError, match="METADATA"):
        extract_pypi_identity(whl)


def test_osv_lockfile(tmp_path: Path) -> None:
    whl = _make_wheel(tmp_path / "a.whl", name="urllib3", version="1.26.4")
    identity = extract_pypi_identity(whl)
    path = write_pypi_osv_identity_lockfile(identity, tmp_path / "lock.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    pkg = data["results"][0]["packages"][0]["package"]
    assert pkg == {"name": "urllib3", "version": "1.26.4", "ecosystem": "PyPI"}


def test_expand_revoke_keys_includes_pypi_metadata() -> None:
    keys = expand_revoke_keys(
        ["packages/jinja2/2.11.2/Jinja2-2.11.2-py2.py3-none-any.whl"],
        fmt="pypi",
    )
    assert (
        "packages/jinja2/2.11.2/Jinja2-2.11.2-py2.py3-none-any.whl.metadata"
        in keys
    )
    assert "packages/jinja2/2.11.2/Jinja2-2.11.2-py2.py3-none-any.whl" in keys
