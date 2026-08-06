"""Имена целевых репозиториев для Upload verified."""

from __future__ import annotations

import pytest

from nexus_control.services.verified_uploader import (
    normalize_upload_repo_name,
    verified_repo_name,
)
from nexus_control.utils.safe_path import UnsafePathError


def test_verified_repo_name_default() -> None:
    assert verified_repo_name("test-maven") == "test-maven-verified"
    assert verified_repo_name("my/repo") == "my_repo-verified"


def test_normalize_upload_repo_name_custom() -> None:
    assert normalize_upload_repo_name("  my-custom-verified  ") == "my-custom-verified"
    assert normalize_upload_repo_name("acme/prod verified!") == "acme_prod_verified"


def test_normalize_upload_repo_name_rejects_empty() -> None:
    with pytest.raises(UnsafePathError):
        normalize_upload_repo_name("...")
