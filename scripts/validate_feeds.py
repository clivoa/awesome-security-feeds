#!/usr/bin/env python3
"""Validate feeds/*.yaml (required url, canonical categories, duplicates)."""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urlparse

try:
    from feed_utils import load_yaml_list, normalize_url
except ModuleNotFoundError:  # pragma: no cover - supports module execution
    from scripts.feed_utils import load_yaml_list, normalize_url

ROOT = Path(__file__).resolve().parents[1]
FEEDS_DIR = ROOT / "feeds"
CATEGORIES_DOC = ROOT / "docs" / "categories.md"
ALLOWED_TYPES = {"rss", "atom", ""}

RE_CATEGORY_ROW = re.compile(r"^\|\s*([^|]+?)\s*\|[^|]*\|\s*`feeds/([^`]+\.yaml)`\s*\|\s*$")


def load_canonical_categories() -> dict[str, str]:
    """Parse the category table in docs/categories.md (file -> canonical name)."""
    mapping: dict[str, str] = {}
    for line in CATEGORIES_DOC.read_text(encoding="utf-8").splitlines():
        m = RE_CATEGORY_ROW.match(line)
        if m and m.group(1) != "Category":
            mapping[m.group(2)] = m.group(1)
    if not mapping:
        raise SystemExit(f"Could not parse category table from {CATEGORIES_DOC}")
    return mapping


def dedup_key(url: str) -> str:
    """Aggressive normalization: scheme/www/trailing-slash insensitive."""
    norm = normalize_url(url, force_https=True, strip_trailing_slash=True)
    parsed = urlparse(norm)
    netloc = parsed.netloc.removeprefix("www.")
    return f"{netloc}{parsed.path}" + (f"?{parsed.query}" if parsed.query else "")


def main() -> None:
    paths = sorted(FEEDS_DIR.glob("*.yaml"))
    if not paths:
        print("[FAIL] No YAML files in feeds/")
        sys.exit(1)

    canonical = load_canonical_categories()

    seen: dict[str, str] = {}
    host_title: dict[tuple[str, str], str] = {}
    errors = 0
    warnings = 0
    total = 0

    for p in paths:
        try:
            data = load_yaml_list(p)
        except SystemExit as exc:
            print(f"[FAIL] {exc}")
            errors += 1
            continue

        expected_category = canonical.get(p.name)
        if expected_category is None:
            print(
                f"[FAIL] {p.name}: not listed in docs/categories.md "
                "(add it to the category table)"
            )
            errors += 1

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

            category = str(it.get("category", "")).strip()
            if expected_category is not None and category != expected_category:
                print(
                    f"[FAIL] {p.name} #{i}: category '{category}' does not match "
                    f"canonical '{expected_category}' for this file"
                )
                errors += 1

            t = str(it.get("type", "")).strip().lower()
            if t not in ALLOWED_TYPES:
                print(f"[WARN] {p} #{i}: unusual type='{t}'")
                warnings += 1

            key = dedup_key(url_raw)
            if key in seen:
                print(f"[FAIL] Duplicate URL: {url_raw} ({p.name} #{i}) already in {seen[key]}")
                errors += 1
            else:
                seen[key] = f"{p.name} #{i}"

            title = str(it.get("title", "")).strip().lower()
            host = urlparse(normalize_url(url_raw)).netloc.removeprefix("www.")
            if title:
                ht = (host, title)
                if ht in host_title:
                    print(
                        f"[WARN] Possible duplicate feed (same host+title): {url_raw} "
                        f"({p.name} #{i}) also in {host_title[ht]}"
                    )
                    warnings += 1
                else:
                    host_title[ht] = f"{p.name} #{i}"

    if errors:
        print(f"[FAIL] {errors} error(s), {warnings} warning(s) across {total} items")
        sys.exit(1)
    print(f"[OK] {total} items, {len(seen)} unique URLs, {warnings} warning(s)")


if __name__ == "__main__":
    main()
