#!/usr/bin/env python3
"""
Generate docs/awesome-feeds.md from feeds/*.yaml.

Usage:
  python scripts/build_awesome_page.py --out docs/awesome-feeds.md
"""
from __future__ import annotations

import argparse
import datetime as _dt
from pathlib import Path
from collections import defaultdict
import re

import yaml


def load_yaml_list(path: Path) -> list[dict]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data is None:
        return []
    if not isinstance(data, list):
        raise SystemExit(f"{path}: expected a YAML list, got {type(data).__name__}")
    return data


def md_escape(s: str) -> str:
    return (s or "").replace("\n", " ").strip().replace("|", "\\|")


def slugify(s: str) -> str:
    s = s.lower().strip()
    s = re.sub(r"[^a-z0-9\s-]", "", s)
    return re.sub(r"\s+", "-", s)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--feeds-dir", default="feeds", help="Directory containing *.yaml feed lists")
    ap.add_argument("--out", default="docs/awesome-feeds.md", help="Output markdown file")
    args = ap.parse_args()

    feeds_dir = Path(args.feeds_dir)
    out_path = Path(args.out)

    if not feeds_dir.exists():
        raise SystemExit(f"Missing feeds dir: {feeds_dir}")

    items: list[dict] = []
    for p in sorted(feeds_dir.glob("*.yaml")):
        for it in load_yaml_list(p):
            it = dict(it)
            it["_file"] = p.name
            items.append(it)

    by_cat: dict[str, list[dict]] = defaultdict(list)
    for it in items:
        by_cat[it.get("category", "Uncategorized")].append(it)

    categories = sorted(by_cat.keys(), key=lambda s: s.lower())
    generated_at = _dt.datetime.now(_dt.timezone.utc).isoformat()

    lines: list[str] = []
    lines.append("# Awesome Security Feeds — Full List\n")
    lines.append("This page contains the full, categorized feed list maintained in this repository.\n")
    lines.append(f"**Generated:** `{generated_at}` (UTC)\n")
    lines.append("> Source of truth remains the YAML files under `feeds/`.\n")
    lines.append("\n---\n")
    lines.append("## Contents\n")
    for cat in categories:
        lines.append(f"- [{cat}](#{slugify(cat)}) ({len(by_cat[cat])})")
    lines.append("\n---\n")

    for cat in categories:
        cat_items = sorted(by_cat[cat], key=lambda x: (str(x.get("title","")).lower(), str(x.get("url",""))))
        lines.append(f"## {cat}\n")
        lines.append(f"Total: **{len(cat_items)}**\n")
        lines.append("\n| Feed | Description | Type | URL |\n|---|---|---:|---|\n")
        for it in cat_items:
            title = md_escape(str(it.get("title", "")))
            desc = md_escape(str(it.get("description", "")))
            ftype = md_escape(str(it.get("type", ""))).upper()
            url = md_escape(str(it.get("url", "")))
            lines.append(f"| {title} | {desc} | {ftype} | {url} |")
        lines.append("\n")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[OK] Wrote {out_path} ({len(items)} feeds)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
