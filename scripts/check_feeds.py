#!/usr/bin/env python3
"""
Daily feed health checker.

- Reads feeds from data/feeds.json (preferred) or feeds/*.yaml
- Checks HTTP status + parses with feedparser; runs checks concurrently
- Writes data/feed_status.json used by the GitHub Pages UI
- Preserves history: consecutive_failures, down_since, last_seen_active

Status logic:
- active:       HTTP < 400 AND (not bozo OR entries > 0)
- rate_limited: HTTP 429 — server is up but throttling the checker
- down:         HTTP >= 400 (except 429) | timeout | network error | (bozo AND entries == 0)
"""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import feedparser
import requests

try:
    from feed_utils import load_yaml_list, normalize_url
except ModuleNotFoundError:
    from scripts.feed_utils import load_yaml_list, normalize_url

ROOT = Path(__file__).resolve().parents[1]
FEEDS_DIR = ROOT / "feeds"
FEEDS_JSON = ROOT / "data" / "feeds.json"
OUT_STATUS = ROOT / "data" / "feed_status.json"

TIMEOUT_SECS = 15
MAX_FEEDS = 2500
MAX_WORKERS = 30
RETRY_DELAY_SECS = 2
USER_AGENT = (
    "Mozilla/5.0 (compatible; securityfeeds-checker/2.0; "
    "+https://github.com/clivoa/awesome-security-feeds)"
)

_print_lock = threading.Lock()


def log(msg: str) -> None:
    with _print_lock:
        print(msg, flush=True)


def load_feeds() -> List[str]:
    urls: List[str] = []
    if FEEDS_JSON.exists():
        data = json.loads(FEEDS_JSON.read_text(encoding="utf-8"))
        for it in data.get("feeds", []) or []:
            u = normalize_url(str(it.get("url", "")).strip())
            if u:
                urls.append(u)
    else:
        for p in sorted(FEEDS_DIR.glob("*.yaml")):
            try:
                items = load_yaml_list(p)
            except SystemExit:
                continue
            for it in items:
                if not isinstance(it, dict):
                    continue
                u = normalize_url(str(it.get("url", "")).strip())
                if u:
                    urls.append(u)

    seen: set[str] = set()
    out: List[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out[:MAX_FEEDS]


def load_previous() -> Dict[str, Any]:
    """Return the previous results dict (url -> result) or empty dict."""
    if not OUT_STATUS.exists():
        return {}
    try:
        data = json.loads(OUT_STATUS.read_text(encoding="utf-8"))
        return data.get("results", {})
    except Exception:
        return {}


def _fetch_and_parse(url: str, headers: Dict[str, str]) -> Dict[str, Any]:
    """Single HTTP fetch + feedparser pass. Returns raw result fields."""
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
    started = time.time()
    try:
        r = requests.get(
            url,
            headers=headers,
            timeout=TIMEOUT_SECS,
            allow_redirects=True,
            stream=False,
        )
        result["http_status"] = r.status_code
        result["final_url"] = r.url
        result["content_type"] = (
            (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        )

        if r.status_code == 429:
            result["status"] = "rate_limited"
            result["error"] = "http_429"
            return result

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

        entries = len(getattr(parsed, "entries", None) or [])
        result["entries"] = entries

        if (not bozo) or entries > 0:
            result["status"] = "active"
        else:
            result["status"] = "down"
            if not result["error"]:
                result["error"] = "empty_or_unparseable"

    except requests.exceptions.Timeout:
        result["error"] = "timeout"
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"connection:{type(e).__name__}"
    except requests.exceptions.RequestException as e:
        result["error"] = f"request:{type(e).__name__}"
    except Exception as e:
        result["error"] = f"unexpected:{type(e).__name__}"
    finally:
        result["latency_ms"] = int((time.time() - started) * 1000)

    return result


def check_one(url: str) -> Dict[str, Any]:
    """Check a feed URL, retrying once on transient network errors."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
        "Accept-Encoding": "gzip, deflate",
    }

    result = _fetch_and_parse(url, headers)

    # Retry once on transient errors (timeout / connection issues)
    if result["status"] == "down" and result["error"] and (
        result["error"] == "timeout"
        or result["error"].startswith("connection:")
        or result["error"].startswith("request:")
    ):
        time.sleep(RETRY_DELAY_SECS)
        retry = _fetch_and_parse(url, headers)
        # Use retry result only if it improved (active/rate_limited) or gave more info
        if retry["status"] != "down" or retry["http_status"] is not None:
            result = retry
            result["retried"] = True

    return result


def merge_history(
    new: Dict[str, Any],
    prev: Optional[Dict[str, Any]],
    now_iso: str,
) -> Dict[str, Any]:
    """Attach persistent tracking fields (down_since, consecutive_failures, last_seen_active)."""
    if prev is None:
        prev = {}

    status = new["status"]
    prev_failures = prev.get("consecutive_failures", 0) or 0
    prev_down_since: Optional[str] = prev.get("down_since")
    prev_last_active: Optional[str] = prev.get("last_seen_active")

    if status == "active":
        new["consecutive_failures"] = 0
        new["down_since"] = None
        new["last_seen_active"] = now_iso
    elif status == "rate_limited":
        # Not really a failure — server is alive
        new["consecutive_failures"] = prev_failures
        new["down_since"] = prev_down_since
        new["last_seen_active"] = prev_last_active
    else:  # down
        new["consecutive_failures"] = prev_failures + 1
        new["down_since"] = prev_down_since or now_iso
        new["last_seen_active"] = prev_last_active

    return new


def main() -> None:
    urls = load_feeds()
    previous = load_previous()
    now_iso = datetime.now(timezone.utc).isoformat()

    total = len(urls)
    log(f"[*] Checking {total} feeds with {MAX_WORKERS} workers …")

    results: Dict[str, Any] = {}
    active = down = rate_limited = 0
    done = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        future_to_url = {pool.submit(check_one, u): u for u in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                res = future.result()
            except Exception as e:
                res = {
                    "status": "down",
                    "http_status": None,
                    "error": f"executor:{type(e).__name__}",
                    "bozo": None,
                    "entries": None,
                    "final_url": None,
                    "content_type": None,
                    "latency_ms": None,
                }

            res = merge_history(res, previous.get(url), now_iso)
            results[url] = res

            done += 1
            st = res["status"]
            if st == "active":
                active += 1
            elif st == "rate_limited":
                rate_limited += 1
            else:
                down += 1

            if done % 100 == 0 or done == total:
                log(
                    f"  [{done}/{total}] active={active} down={down}"
                    + (f" rate_limited={rate_limited}" if rate_limited else "")
                )

    # Sort output by URL for stable diffs
    sorted_results = dict(sorted(results.items()))

    payload: Dict[str, Any] = {
        "checked_at": now_iso,
        "total": total,
        "active": active,
        "down": down,
        "rate_limited": rate_limited,
        "results": sorted_results,
    }

    OUT_STATUS.parent.mkdir(parents=True, exist_ok=True)
    OUT_STATUS.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    summary = f"active={active} down={down}"
    if rate_limited:
        summary += f" rate_limited={rate_limited}"
    log(f"[OK] Wrote {OUT_STATUS} ({summary})")


if __name__ == "__main__":
    main()
