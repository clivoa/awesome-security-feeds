#!/usr/bin/env python3
"""
Daily feed health checker.

- Reads feeds from data/feeds.json (preferred) or feeds/*.yaml
- Checks HTTP status (timeout/redirects) + parses using feedparser
- Writes data/feed_status.json used by the GitHub Pages UI

Status logic (default):
- active: HTTP < 400 AND (not bozo OR entries > 0)
- down:   HTTP >= 400 OR timeout/network error OR (bozo AND entries == 0)

"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse, urlunparse

import feedparser
import requests
import yaml

ROOT = Path(__file__).resolve().parents[1]
FEEDS_DIR = ROOT / "feeds"
FEEDS_JSON = ROOT / "data" / "feeds.json"
OUT_STATUS = ROOT / "data" / "feed_status.json"

TIMEOUT_SECS = 10
MAX_FEEDS = 2500
USER_AGENT = "securityfeeds-checker/1.0"

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

def load_feeds() -> List[str]:
    urls: List[str] = []
    if FEEDS_JSON.exists():
        data = json.loads(FEEDS_JSON.read_text(encoding="utf-8"))
        for it in data.get("feeds", []) or []:
            u = norm_url(str(it.get("url", "")).strip())
            if u:
                urls.append(u)
    else:
        for p in sorted(FEEDS_DIR.glob("*.yaml")):
            items = yaml.safe_load(p.read_text(encoding="utf-8")) or []
            if not isinstance(items, list):
                continue
            for it in items:
                if not isinstance(it, dict):
                    continue
                u = norm_url(str(it.get("url", "")).strip())
                if u:
                    urls.append(u)

    seen = set()
    out = []
    for u in urls:
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out[:MAX_FEEDS]

def check_one(url: str) -> Dict[str, Any]:
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    started = time.time()

    result: Dict[str, Any] = {
        "status": "down",
        "http_status": None,
        "error": None,
        "bozo": None,
        "entries": None,
        "final_url": None,
        "content_type": None,
        "latency_ms": None,
    }

    try:
        r = requests.get(url, headers=headers, timeout=TIMEOUT_SECS, allow_redirects=True)
        result["http_status"] = r.status_code
        result["final_url"] = r.url
        result["content_type"] = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()

        if r.status_code >= 400:
            result["error"] = f"http_{r.status_code}"
            return result

        parsed = feedparser.parse(r.content)
        bozo = bool(getattr(parsed, "bozo", False))
        result["bozo"] = bozo

        be = getattr(parsed, "bozo_exception", None)
        if bozo and be is not None:
            result["error"] = f"bozo:{type(be).__name__}"
        elif bozo:
            result["error"] = "bozo"

        entries = getattr(parsed, "entries", None) or []
        result["entries"] = len(entries)

        # Default logic:
        # active if parse ok OR (bozo but still has entries)
        if (not bozo) or (result["entries"] and result["entries"] > 0):
            result["status"] = "active"
            # keep bozo info but don't treat as down
            return result

        # bozo + 0 entries
        result["status"] = "down"
        if not result["error"]:
            result["error"] = "empty_or_unparseable"
        return result

    except requests.exceptions.Timeout:
        result["error"] = "timeout"
        return result
    except requests.exceptions.RequestException as e:
        result["error"] = f"request:{type(e).__name__}"
        return result
    except Exception as e:
        result["error"] = f"unexpected:{type(e).__name__}"
        return result
    finally:
        result["latency_ms"] = int((time.time() - started) * 1000)

def main() -> None:
    urls = load_feeds()
    checked_at = datetime.now(timezone.utc).isoformat()

    results: Dict[str, Any] = {}
    active = 0
    down = 0

    for u in urls:
        res = check_one(u)
        results[u] = res
        if res["status"] == "active":
            active += 1
        else:
            down += 1

    payload = {
        "checked_at": checked_at,
        "total": len(urls),
        "active": active,
        "down": down,
        "results": results,
    }

    OUT_STATUS.parent.mkdir(parents=True, exist_ok=True)
    OUT_STATUS.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[OK] Wrote {OUT_STATUS} ({active} active / {down} down)")

if __name__ == "__main__":
    main()
