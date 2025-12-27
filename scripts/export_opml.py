#!/usr/bin/env python3
"""
Export feeds/*.yaml into an OPML (sec_feeds.xml-like) file.

Input:  feeds/*.yaml (list of dicts with url, title, description, type, category)
Output: sec_feeds.xml (OPML 2.0) with category outlines + feed outlines

Usage:
  python scripts/export_opml.py --out sec_feeds.xml
  python scripts/export_opml.py --feeds-dir feeds --out sec_feeds.xml --title "S33R Security Feeds"
"""

from __future__ import annotations

import argparse
import re
from datetime import datetime, timezone
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
import json

from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse, urlunparse

import yaml
from xml.sax.saxutils import escape

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

    # drop default ports
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    if netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]

    # keep query; drop fragment
    return urlunparse((scheme, netloc, pu.path or "", "", pu.query or "", ""))


def load_yaml_feeds(feeds_dir: Path) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for p in sorted(feeds_dir.glob("*.yaml")):
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or []
        if not isinstance(data, list):
            raise SystemExit(f"Invalid YAML in {p} (expected list)")
        for idx, it in enumerate(data, start=1):
            if not isinstance(it, dict):
                raise SystemExit(f"Invalid item in {p} #{idx} (expected dict)")
            url = norm_url(str(it.get("url", "")).strip())
            if not url:
                raise SystemExit(f"Missing url in {p} #{idx}")

            items.append(
                {
                    "url": url,
                    "title": clean_text(str(it.get("title", ""))),
                    "description": clean_text(str(it.get("description", ""))),
                    "type": clean_text(str(it.get("type", ""))).lower(),
                    "category": clean_text(str(it.get("category", ""))) or "Uncategorized",
                }
            )
    return items


def dedupe_by_url(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    for it in items:
        k = it["url"]
        if k not in seen:
            seen[k] = it
            continue
        cur = seen[k]
        # keep first but fill blanks
        for f in ("title", "description", "type", "category"):
            if not cur.get(f) and it.get(f):
                cur[f] = it[f]
    return list(seen.values())


def group_by_category(items: List[Dict[str, Any]]) -> List[Tuple[str, List[Dict[str, Any]]]]:
    cats: Dict[str, List[Dict[str, Any]]] = {}
    for it in items:
        cats.setdefault(it["category"], []).append(it)

    # stable sort: categories alpha; feeds by title then url
    grouped: List[Tuple[str, List[Dict[str, Any]]]] = []
    for cat in sorted(cats.keys(), key=lambda s: s.lower()):
        feeds = sorted(cats[cat], key=lambda x: ((x.get("title") or "").lower(), x["url"].lower()))
        grouped.append((cat, feeds))
    return grouped



def load_active_urls(status_path: Path) -> set[str]:
    """Load active feed URLs from data/feed_status.json."""
    if not status_path.exists():
        return set()
    try:
        data = json.loads(status_path.read_text(encoding="utf-8"))
    except Exception:
        return set()
    results = data.get("results") or {}
    active = set()
    if isinstance(results, dict):
        for url, info in results.items():
            try:
                if isinstance(info, dict) and (info.get("status") == "active"):
                    active.add(norm_url(str(url)))
            except Exception:
                continue
    return active
def opml_outline_feed(it: Dict[str, Any], indent: str = "      ") -> str:
    # OPML uses outline attributes; we emit xmlUrl + title/text + description + type
    url = escape(it["url"])
    title = escape(it.get("title") or it["url"])
    desc = escape(it.get("description") or "")
    ftype = escape(it.get("type") or "rss")

    # Keep attributes minimal & compatible (description optional)
    attrs = [
        f'title="{title}"',
        f'text="{title}"',
        f'type="{ftype}"',
        f'xmlUrl="{url}"',
    ]
    if desc:
        attrs.append(f'description="{desc}"')

    return f"{indent}<outline " + " ".join(attrs) + " />"


def build_opml(title: str, grouped: List[Tuple[str, List[Dict[str, Any]]]]) -> str:
    now = datetime.now(timezone.utc).isoformat()

    head = f"""<?xml version="1.0" encoding="utf-8"?>
<opml version="2.0">
  <head>
    <title>{escape(title)}</title>
    <dateCreated>{escape(now)}</dateCreated>
  </head>
  <body>
"""

    body_parts: List[str] = []
    for cat, feeds in grouped:
        cat_name = escape(cat)
        body_parts.append(f'    <outline title="{cat_name}" text="{cat_name}">')
        for it in feeds:
            body_parts.append(opml_outline_feed(it, indent="      "))
        body_parts.append("    </outline>")

    tail = """  </body>
</opml>
"""
    return head + "\n".join(body_parts) + "\n" + tail


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--feeds-dir", default="feeds", help="Directory with YAML feed lists (default: feeds)")
    ap.add_argument("--out", default="sec_feeds.xml", help="Output OPML/XML file (default: sec_feeds.xml)")
    ap.add_argument("--title", default="Security Feeds", help="OPML <title> value")
    ap.add_argument(
        "--status",
        choices=["all", "active"],
        default="all",
        help="Export all feeds or only active ones (requires data/feed_status.json)",
    )
    args = ap.parse_args()

    feeds_dir = Path(args.feeds_dir)
    if not feeds_dir.exists():
        raise SystemExit(f"Feeds dir not found: {feeds_dir}")

    items = load_yaml_feeds(feeds_dir)
    items = dedupe_by_url(items)

    # Optional: export only active feeds (based on data/feed_status.json)
    if args.status == "active":
        status_path = ROOT / "data" / "feed_status.json"
        active_urls = load_active_urls(status_path)
        if not active_urls:
            print("[WARN] args.status=active but no active URLs found (missing/empty feed_status.json) — exporting 0 feeds")
        items = [it for it in items if it.get("url") in active_urls]
    grouped = group_by_category(items)

    opml = build_opml(args.title, grouped)
    Path(args.out).write_text(opml, encoding="utf-8")

    total = sum(len(fs) for _, fs in grouped)
    print(f"[OK] Wrote {args.out} with {len(grouped)} categories and {total} feeds (deduped)")


if __name__ == "__main__":
    main()
