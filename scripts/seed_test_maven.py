#!/usr/bin/env python3
"""Наполнить hosted maven-репозиторий тестовыми артефактами (до 1000).

Пример:
  NEXUS_URL=http://localhost:8081 \\
  NEXUS_USERNAME=admin NEXUS_PASSWORD=admin123 \\
  uv run python scripts/seed_test_maven.py --repo test-maven --count 1000
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx


def _jar_bytes(index: int) -> bytes:
    # Минимальный zip/jar (PK…) + уникальный хвост, чтобы checksumы различались.
    return (
        b"PK\x05\x06" + b"\x00" * 16 + f"nexus-control-seed-{index}\n".encode()
    )


def _asset_path(index: int) -> str:
    # Разветвлённое дерево: group/artifact/version/file — удобно для lazy tree.
    g1 = index % 20
    g2 = (index // 20) % 20
    art = index % 50
    ver = f"1.0.{index}"
    return f"com/seed/g{g1:02d}/g{g2:02d}/artifact-{art:02d}/{ver}/artifact-{art:02d}-{ver}.jar"


def upload_one(
    client: httpx.Client,
    repo: str,
    index: int,
) -> tuple[int, int, str]:
    path = _asset_path(index)
    url = f"/repository/{repo}/{path}"
    response = client.put(
        url,
        content=_jar_bytes(index),
        headers={"Content-Type": "application/java-archive"},
        timeout=60.0,
    )
    # 400 already exists — ок для повторного прогона
    if response.status_code in {200, 201, 204, 400}:
        return index, response.status_code, path
    return index, response.status_code, f"{path}: {response.text[:120]}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default="test-maven")
    parser.add_argument("--count", type=int, default=1000)
    parser.add_argument(
        "--start",
        type=int,
        default=0,
        help="First artifact index (use 1000 to append after a previous 0..999 seed)",
    )
    parser.add_argument("--workers", type=int, default=8)
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

    if args.count < 1 or args.count > 50_000:
        print("count must be 1..50000", file=sys.stderr)
        return 2
    if args.start < 0:
        print("start must be >= 0", file=sys.stderr)
        return 2
    if not args.username or not args.password:
        print(
            "Set NEXUS_USERNAME / NEXUS_PASSWORD (or --username/--password)",
            file=sys.stderr,
        )
        return 2

    base = args.url.rstrip("/")
    end = args.start + args.count
    print(
        f"Seeding {args.count} jars (index {args.start}..{end - 1}) → "
        f"{base} repo={args.repo} workers={args.workers}"
    )

    auth = httpx.BasicAuth(args.username, args.password)
    ok = 0
    fail = 0
    t0 = time.monotonic()

    with httpx.Client(base_url=base, auth=auth, follow_redirects=True, verify=False) as client:
        # Быстрая проверка репо
        check = client.get(f"/service/rest/v1/repositories/{args.repo}")
        if check.status_code == 404:
            # list endpoint shape varies; try repositories list
            repos = client.get("/service/rest/v1/repositories")
            names = []
            if repos.status_code == 200 and isinstance(repos.json(), list):
                names = [r.get("name") for r in repos.json() if isinstance(r, dict)]
            if args.repo not in names:
                print(
                    f"Repository {args.repo!r} not found. Available: {names[:30]}",
                    file=sys.stderr,
                )
                return 1
        elif check.status_code in {401, 403}:
            print(f"Auth failed: {check.status_code}", file=sys.stderr)
            return 1

        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [
                pool.submit(upload_one, client, args.repo, i)
                for i in range(args.start, end)
            ]
            for done, fut in enumerate(as_completed(futures), start=1):
                idx, status, detail = fut.result()
                if status in {200, 201, 204, 400}:
                    ok += 1
                else:
                    fail += 1
                    print(f"FAIL [{status}] #{idx} {detail}", file=sys.stderr)
                if done % 50 == 0 or done == args.count:
                    elapsed = time.monotonic() - t0
                    print(f"… {done}/{args.count} ok={ok} fail={fail} ({elapsed:.1f}s)")

    elapsed = time.monotonic() - t0
    print(f"Done: ok={ok} fail={fail} in {elapsed:.1f}s")
    print("Open test-maven in nexus-control (r to refresh) to test streaming tree.")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
