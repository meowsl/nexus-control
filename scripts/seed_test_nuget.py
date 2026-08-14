#!/usr/bin/env python3
"""Создать hosted nuget-репозиторий и залить минимальные .nupkg (по умолчанию 100).

Пример:
  NEXUS_URL=http://localhost:8081 \\
  NEXUS_USERNAME=admin NEXUS_PASSWORD=… \\
  uv run python scripts/seed_test_nuget.py --repo test-nuget --count 100
"""

from __future__ import annotations

import argparse
import io
import os
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from xml.sax.saxutils import escape

import httpx


def _nuspec(package_id: str, version: str) -> str:
    return f"""<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>{escape(package_id)}</id>
    <version>{escape(version)}</version>
    <authors>nexus-control-seed</authors>
    <description>Seed package {escape(package_id)} for nexus-control tests</description>
  </metadata>
</package>
"""


def _nupkg_bytes(package_id: str, version: str) -> bytes:
    buf = io.BytesIO()
    nuspec_name = f"{package_id}.nuspec"
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "[Content_Types].xml",
            (
                '<?xml version="1.0" encoding="utf-8"?>'
                '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                '<Default Extension="psmdcp" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
                '<Default Extension="nuspec" ContentType="application/octet"/>'
                "</Types>"
            ),
        )
        zf.writestr(nuspec_name, _nuspec(package_id, version))
        zf.writestr(
            f"lib/netstandard2.0/{package_id}.txt",
            f"seed:{package_id}:{version}\n".encode(),
        )
    return buf.getvalue()


def _pkg(index: int) -> tuple[str, str, str]:
    """Return (package_id, version, filename)."""
    package_id = f"NexusControl.Seed.Pkg{index:03d}"
    version = f"1.0.{index}"
    filename = f"{package_id.lower()}.{version}.nupkg"
    return package_id, version, filename


def ensure_nuget_hosted(client: httpx.Client, name: str) -> None:
    existing = client.get(f"/service/rest/v1/repositories/{name}")
    if existing.status_code == 200:
        print(f"Repository {name!r} already exists")
        return
    payload = {
        "name": name,
        "online": True,
        "storage": {
            "blobStoreName": "default",
            "strictContentTypeValidation": False,
            "writePolicy": "ALLOW",
        },
        "component": {"proprietaryComponents": False},
    }
    response = client.post(
        "/service/rest/v1/repositories/nuget/hosted",
        json=payload,
        timeout=60.0,
    )
    if response.status_code not in {200, 201, 204}:
        raise SystemExit(
            f"Failed to create nuget hosted {name!r}: "
            f"HTTP {response.status_code} {response.text[:300]}"
        )
    print(f"Created nuget hosted repository {name!r}")


def upload_one(
    client: httpx.Client,
    repo: str,
    index: int,
) -> tuple[int, int, str]:
    package_id, version, filename = _pkg(index)
    content = _nupkg_bytes(package_id, version)
    response = client.post(
        "/service/rest/v1/components",
        params={"repository": repo},
        files={
            "nuget.asset": (filename, content, "application/octet-stream"),
        },
        timeout=120.0,
    )
    if response.status_code in {200, 201, 204, 400}:
        return index, response.status_code, filename
    return index, response.status_code, f"{filename}: {response.text[:160]}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default="test-nuget")
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument(
        "--url",
        default=os.environ.get("NEXUS_URL", "http://localhost:8081"),
    )
    parser.add_argument(
        "--username",
        default=os.environ.get("NEXUS_USERNAME", ""),
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("NEXUS_PASSWORD", ""),
    )
    args = parser.parse_args()

    if not args.username or not args.password:
        print(
            "NEXUS_USERNAME / NEXUS_PASSWORD required "
            "(env or --username/--password)",
            file=sys.stderr,
        )
        return 2

    base = args.url.rstrip("/")
    auth = (args.username, args.password)
    with httpx.Client(base_url=base, auth=auth, timeout=60.0) as client:
        status = client.get("/service/rest/v1/status")
        if status.status_code != 200:
            print(f"Nexus not ready: HTTP {status.status_code}", file=sys.stderr)
            return 1
        ensure_nuget_hosted(client, args.repo)

        indexes = list(range(args.start, args.start + args.count))
        ok = 0
        failed = 0
        print(
            f"Uploading {len(indexes)} nupkg → {base}/repository/{args.repo} "
            f"(workers={args.workers})"
        )
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            futures = [
                pool.submit(upload_one, client, args.repo, i) for i in indexes
            ]
            for fut in as_completed(futures):
                index, code, detail = fut.result()
                if code in {200, 201, 204, 400}:
                    ok += 1
                    if ok % 20 == 0 or ok == len(indexes):
                        print(f"  progress {ok}/{len(indexes)} (last={detail})")
                else:
                    failed += 1
                    print(f"  FAIL idx={index} HTTP {code}: {detail}", file=sys.stderr)

        # count assets
        listed = 0
        cont: str | None = None
        while True:
            params: dict[str, str] = {"repository": args.repo}
            if cont:
                params["continuationToken"] = cont
            page = client.get("/service/rest/v1/assets", params=params)
            page.raise_for_status()
            data = page.json()
            items = data.get("items") or []
            listed += len(items)
            cont = data.get("continuationToken")
            if not cont:
                break

    print(f"Done uploaded_ok≈{ok} failed={failed}; assets listed now={listed}")
    print(
        "Try:\n"
        f"  uv run nexus-control-cli verify --repo {args.repo} "
        f"--scanners osv --scan-limit 20\n"
        f"  uv run nexus-control-cli upload --repo {args.repo} "
        f"--target {args.repo}-verified"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
