#!/usr/bin/env python3
"""
Import OPML (sec_feeds.xml-like) into YAML sources in feeds/*.yaml.

- Categories are top-level <outline> nodes under <body>
- Feed entries are <outline> nodes with xmlUrl (RSS/Atom URL)
- Writes one YAML file per category (slugified)
- Deduplicates by normalized URL (global, across categories)
- Keeps stable ordering (title then url)

Usage:
  python scripts/import_opml.py --in sec_feeds.xml --out-dir feeds
  python scripts/import_opml.py --in sec_feeds.xml --out-dir feeds --clear-out-dir
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse, urlunparse

import yaml
import xml.etree.ElementTree as ET


RE_WS = re.compile(r"\s+")


def clean_text(s: str) -> str:
    return RE_WS.sub(" ", (s or "").strip()).strip()


def norm_url(u: str) -> str:
    u = (u or "").strip()
    if not u:
        return u
    pu = urlparse(u)
    scheme = (pu.scheme or "http").lower()
    netloc = (pu.netloc or "").lower()

    # Drop default ports
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    if netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]

    # Keep query; drop fragment
    return urlunparse((scheme, netloc, pu.path or "", "", pu.query or "", ""))


def slugify(s: str) -> str:
    s = (s or "").strip().lower()
    s = s.replace("&", " and ")
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = re.sub(r"-{2,}", "-", s).strip("-")
    return s or "uncategorized"


def parse_opml(opml_path: Path) -> List[Tuple[str, List[Dict[str, Any]]]]:
    """
    Returns [(category_name, [feed_dict, ...]), ...]
    feed_dict has: url, title, description, type, category
    """
    # Strict ET parse is fine for valid OPML; if your XML may be malformed,
    # switch to lxml(recover=True). Keeping stdlib here for portability.
    tree = ET.parse(opml_path)
    root = tree.getroot()

    body = root.find("body")
    if body is None:
        # Some OPML exporters omit <body> wrapper
        body = root

    categories: List[Tuple[str, List[Dict[str, Any]]]] = []

    # Treat each top-level outline as category group
    for cat in body.findall("outline"):
        cat_name = clean_text(cat.get("title") or cat.get("text") or "Uncategorized")

        feeds: List[Dict[str, Any]] = []
        for o in cat.findall(".//outline"):
            url = o.get("xmlUrl") or o.get("url") or o.get("href")
            if not url:
                continue

            title = clean_text(o.get("title") or o.get("text") or "")
            desc = clean_text(o.get("description") or o.get("desc") or "")
            ftype = clean_text(o.get("type") or "").lower()

            feeds.append(
                {
                    "url": norm_url(url),
                    "title": title,
                    "description": desc,
                    "type": ftype,
                    "category": cat_name,
                }
            )

        if feeds:
            categories.append((cat_name, feeds))

    # Fallback: if no categories found, pull all feed outlines anywhere
    if not categories:
        feeds: List[Dict[str, Any]] = []
        for o in root.findall(".//outline"):
            url = o.get("xmlUrl") or o.get("url") or o.get("href")
            if not url:
                continue
            title = clean_text(o.get("title") or o.get("text") or "")
            desc = clean_text(o.get("description") or o.get("desc") or "")
            ftype = clean_text(o.get("type") or "").lower()
            feeds.append(
                {
                    "url": norm_url(url),
                    "title": title,
                    "description": desc,
                    "type": ftype,
                    "category": "Uncategorized",
                }
            )
        if feeds:
            categories = [("Uncategorized", feeds)]

    return categories


def dedupe_global(categories: List[Tuple[str, List[Dict[str, Any]]]]) -> List[Tuple[str, List[Dict[str, Any]]]]:
    """
    Deduplicate by URL across all categories.
    Keeps first occurrence; fills missing fields if later entries have data.
    """
    seen: Dict[str, Dict[str, Any]] = {}
    kept_by_cat: Dict[str, List[Dict[str, Any]]] = {}

    for cat_name, feeds in categories:
        for it in feeds:
            url = it["url"]
            if url not in seen:
                seen[url] = dict(it)
                kept_by_cat.setdefault(cat_name, []).append(seen[url])
                continue

            cur = seen[url]
            # Merge: fill blanks only
            for f in ("title", "description", "type", "category"):
                if not cur.get(f) and it.get(f):
                    cur[f] = it[f]

    # Stable category order
    out: List[Tuple[str, List[Dict[str, Any]]]] = []
    for cat_name in sorted(kept_by_cat.keys(), key=lambda s: s.lower()):
        feeds = kept_by_cat[cat_name]
        feeds_sorted = sorted(
            feeds,
            key=lambda x: ((x.get("title") or "").lower(), x["url"].lower()),
        )
        out.append((cat_name, feeds_sorted))
    return out


def write_yaml_files(categories: List[Tuple[str, List[Dict[str, Any]]]], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    slug_counts: Dict[str, int] = {}
    for cat_name, feeds in categories:
        slug = slugify(cat_name)
        slug_counts[slug] = slug_counts.get(slug, 0) + 1
        if slug_counts[slug] > 1:
            slug = f"{slug}-{slug_counts[slug]}"

        path = out_dir / f"{slug}.yaml"

        # Keep keys minimal and PR-friendly
        payload: List[Dict[str, Any]] = []
        for f in feeds:
            item: Dict[str, Any] = {"url": f["url"], "category": cat_name}
            if f.get("title"):
                item["title"] = f["title"]
            if f.get("description"):
                item["description"] = f["description"]
            if f.get("type"):
                item["type"] = f["type"]
            payload.append(item)

        path.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=True), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True, help="Input OPML file (e.g., sec_feeds.xml)")
    ap.add_argument("--out-dir", default="feeds", help="Output directory for YAML (default: feeds)")
    ap.add_argument(
        "--clear-out-dir",
        action="store_true",
        help="Delete existing *.yaml in out-dir before writing",
    )
    args = ap.parse_args()

    opml_path = Path(args.inp)
    if not opml_path.exists():
        raise SystemExit(f"Input OPML not found: {opml_path}")

    out_dir = Path(args.out_dir)

    if args.clear_out_dir and out_dir.exists():
        for p in out_dir.glob("*.yaml"):
            p.unlink()

    cats = parse_opml(opml_path)
    cats = dedupe_global(cats)

    write_yaml_files(cats, out_dir)

    total = sum(len(fs) for _, fs in cats)
    print(f"[OK] Imported {total} feeds into {out_dir} across {len(cats)} categories (deduped)")


if __name__ == "__main__":
    main()
