#!/usr/bin/env python3
"""Build data/feeds.json (and minified) from feeds/*.yaml."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlencode, urlparse

try:
    from feed_utils import clean_text, load_yaml_list, normalize_url
except ModuleNotFoundError:  # pragma: no cover - supports module execution
    from scripts.feed_utils import clean_text, load_yaml_list, normalize_url

ROOT = Path(__file__).resolve().parents[1]
FEEDS_DIR = ROOT / "feeds"
OUT_JSON = ROOT / "data" / "feeds.json"
OUT_MIN = ROOT / "data" / "feeds.min.json"
TRACKING_QS_PREFIXES = ("utm_",)
TRACKING_QS_KEYS = {"fbclid", "gclid", "mc_cid", "mc_eid", "ref", "source"}


def canonical_dedupe_key(u: str) -> str:
    """Canonical key for dedupe:
    - ignore scheme (http/https)
    - normalize host casing and default ports (handled by norm_url)
    - normalize trailing slash
    - sort query params
    - drop common tracking params (utm_*, fbclid, gclid, etc.)
    """
    pu = urlparse(u)
    netloc = (pu.netloc or "").lower()
    path = pu.path or ""
    if path.endswith("/") and path != "/":
        path = path[:-1]

    q = []
    for k, v in parse_qsl(pu.query or "", keep_blank_values=True):
        lk = (k or "").lower()
        if any(lk.startswith(pfx) for pfx in TRACKING_QS_PREFIXES):
            continue
        if lk in TRACKING_QS_KEYS:
            continue
        q.append((k, v))
    q.sort(key=lambda kv: (kv[0].lower(), kv[1]))
    query = urlencode(q, doseq=True)

    return f"{netloc}{path}?{query}" if query else f"{netloc}{path}"


def load_items() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for p in sorted(FEEDS_DIR.glob("*.yaml")):
        data = load_yaml_list(p)
        for idx, it in enumerate(data, start=1):
            if not isinstance(it, dict):
                raise SystemExit(f"Invalid item in {p} #{idx} (expected dict)")
            url = normalize_url(str(it.get("url", "")).strip())
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
        k = canonical_dedupe_key(it["url"])
        if k not in seen:
            seen[k] = it
            continue
        cur = seen[k]

        # Prefer https when we have both http/https versions of the same feed
        try:
            cur_p = urlparse(cur["url"])
            it_p = urlparse(it["url"])
            if (cur_p.scheme == "http") and (it_p.scheme == "https"):
                cur["url"] = it["url"]
        except Exception:
            pass

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
