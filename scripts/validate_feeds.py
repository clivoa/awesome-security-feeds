#!/usr/bin/env python3
"""Validate feeds/*.yaml (required url + duplicates)."""
from __future__ import annotations

import sys
from pathlib import Path

try:
    from feed_utils import load_yaml_list, normalize_url
except ModuleNotFoundError:  # pragma: no cover - supports module execution
    from scripts.feed_utils import load_yaml_list, normalize_url

ROOT = Path(__file__).resolve().parents[1]
FEEDS_DIR = ROOT / "feeds"
ALLOWED_TYPES = {"rss", "atom", ""}


def main() -> None:
    paths = sorted(FEEDS_DIR.glob("*.yaml"))
    if not paths:
        print("[FAIL] No YAML files in feeds/")
        sys.exit(1)

    seen = {}
    errors = 0
    total = 0

    for p in paths:
        try:
            data = load_yaml_list(p)
        except SystemExit as exc:
            print(f"[FAIL] {exc}")
            errors += 1
            continue
        for i, it in enumerate(data, start=1):
            total += 1
            if not isinstance(it, dict):
                print(f"[FAIL] {p} #{i}: expected dict")
                errors += 1
                continue
            url_raw = str(it.get("url", "")).strip()
            if not url_raw:
                print(f"[FAIL] {p} #{i}: missing url")
                errors += 1
                continue
            url = normalize_url(url_raw)
            t = str(it.get("type", "")).strip().lower()
            if t not in ALLOWED_TYPES:
                print(f"[WARN] {p} #{i}: unusual type='{t}'")
            if url in seen:
                print(f"[FAIL] Duplicate URL: {url} ({p} #{i}) already in {seen[url]}")
                errors += 1
            else:
                seen[url] = f"{p.name} #{i}"

    if errors:
        print(f"[FAIL] {errors} error(s) across {total} items")
        sys.exit(1)
    print(f"[OK] {total} items, {len(seen)} unique URLs")


if __name__ == "__main__":
    main()
