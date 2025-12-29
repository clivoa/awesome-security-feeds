#!/usr/bin/env python3
"""
Generate docs/awesome-feeds.md from feeds/*.yaml.

Usage:
  python scripts/build_awesome_page.py --out docs/awesome-feeds.md
"""

from __future__ import annotations

import argparse
import datetime as dt
import re
from pathlib import Path
from collections import defaultdict

import yaml


def load_yaml_list(path: Path) -> list[dict]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data is None:
        return []
    if not isinstance(data, list):
        raise SystemExit(f"{path}: expected a YAML list")
    return data


def md_escape(value: str) -> str:
    if not value:
        return ""
    return (
        str(value)
        .replace("\n", " ")
        .replace("|", "\\|")
        .strip()
    )


def slugify(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9\\s-]", "", text)
    return re.sub(r"\\s+", "-", text)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--feeds-dir", default="feeds")
    parser.add_argument("--out", default="docs/awesome-feeds.md")
    args = parser.parse_args()

    feeds_dir = Path(args.feeds_dir)
    out_path = Path(args.out)

    if not feeds_dir.exists():
        raise SystemExit(f"Missing feeds dir: {feeds_dir}")

    items: list[dict] = []
    for path in sorted(feeds_dir.glob("*.yaml")):
        for item in load_yaml_list(path):
            item = dict(item)
            item["_file"] = path.name
            items.append(item)

    by_category: dict[str, list[dict]] = defaultdict(list)
    for item in items:
        by_category[item.get("category", "Uncategorized")].append(item)

    categories = sorted(by_category.keys(), key=lambda s: s.lower())
    generated_at = dt.datetime.now(dt.timezone.utc).isoformat()

    lines: list[str] = []
    lines.append("# Awesome Security Feeds — Full List\n")
    lines.append("This page contains the full, categorized feed list maintained in this repository.\n")
    lines.append(f"**Generated:** `{generated_at}` (UTC)\n")
    lines.append("> Source of truth remains the YAML files under `feeds/`.\n")
    lines.append("\n---\n")

    lines.append("## Contents\n")
    for cat in categories:
        lines.append(f"- [{cat}](#{slugify(cat)}) ({len(by_category[cat])})")
    lines.append("\n---\n")

    for category in categories:
        feeds = sorted(
            by_category[category],
            key=lambda x: (str(x.get("title", "")).lower(), str(x.get("url", "")))
        )

        lines.append(f"## {category}\n")
        lines.append(f"Total: **{len(feeds)}**\n")

        # TABLE HEADER (NO BLANK LINE AFTER!)
        lines.append("| Feed | Description | Type | URL |")
        lines.append("|---|---|---:|---|")

        for feed in feeds:
            title = md_escape(feed.get("title", ""))
            desc = md_escape(feed.get("description", ""))
            ftype = md_escape(feed.get("type", "")).upper()
            url = md_escape(feed.get("url", ""))

            # optional: wrap URL to avoid markdown edge cases
            url = f"<{url}>" if url else ""

            lines.append(f"| {title} | {desc} | {ftype} | {url} |")

        lines.append("")  # blank line AFTER the table (this is OK)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")

    print(f"[OK] Wrote {out_path} ({len(items)} feeds)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
