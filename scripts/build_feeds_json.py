#!/usr/bin/env python3
"""Build data/feeds.json (and minified) from feeds/*.yaml."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse, urlunparse

import yaml

ROOT = Path(__file__).resolve().parents[1]
FEEDS_DIR = ROOT / "feeds"
OUT_JSON = ROOT / "data" / "feeds.json"
OUT_MIN = ROOT / "data" / "feeds.min.json"
RE_WS = re.compile(r"\s+")

def norm_url(u: str) -> str:
    u = (u or "").strip()
    if not u:
        return u
    pu = urlparse(u)
    scheme = (pu.scheme or "http").lower()
    netloc = (pu.netloc or "").lower()
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    if netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]
    return urlunparse((scheme, netloc, pu.path or "", "", pu.query or "", ""))

def clean_text(s: str) -> str:
    return RE_WS.sub(" ", (s or "").strip()).strip()

def load_items() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for p in sorted(FEEDS_DIR.glob("*.yaml")):
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or []
        if not isinstance(data, list):
            raise SystemExit(f"Invalid YAML in {p} (expected list)")
        for idx, it in enumerate(data, start=1):
            if not isinstance(it, dict):
                raise SystemExit(f"Invalid item in {p} #{idx} (expected dict)")
            url = norm_url(str(it.get("url", "")).strip())
            if not url:
                raise SystemExit(f"Missing url in {p} #{idx}")
            items.append({
                "url": url,
                "title": clean_text(str(it.get("title", ""))),
                "description": clean_text(str(it.get("description", ""))),
                "type": clean_text(str(it.get("type", ""))).lower(),
                "category": clean_text(str(it.get("category", ""))),
            })
    return items

def dedupe(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    for it in items:
        k = it["url"]
        if k not in seen:
            seen[k] = it
            continue
        cur = seen[k]
        for f in ("title", "description", "type", "category"):
            if not cur.get(f) and it.get(f):
                cur[f] = it[f]
    return list(seen.values())

def stable_sort(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(items, key=lambda x: (
        (x.get("category") or "").lower(),
        (x.get("title") or "").lower(),
        x["url"].lower(),
    ))

def main() -> None:
    items = stable_sort(dedupe(load_items()))
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(items),
        "feeds": items,
    }
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    OUT_MIN.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"[OK] {OUT_JSON} ({len(items)} feeds)")

if __name__ == "__main__":
    main()
