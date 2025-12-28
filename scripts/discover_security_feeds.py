#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
discover_security_feeds.py

Zero-input discovery of security-related RSS/Atom feeds (no need to provide domains).

What it does
- Crawls public "seed" pages (awesome lists, hubs) -> extracts outbound domains
- For each domain, attempts to discover RSS/Atom feeds via:
  - <link rel="alternate" ...> in homepage HTML
  - common feed paths (/feed, /rss.xml, /atom.xml, /index.xml, etc.)
- Validates feed with feedparser
- Detects feed type: rss | atom
- Scores security relevance based on keywords in recent entries
- Outputs:
  - data/discovery/feeds_candidates.json (full metadata)
  - data/discovery/feeds_seen.json       (cache/dedupe)
  - feeds/discovered.yaml                (YOUR FORMAT: list of {url, category, title, type, description})

Install
  pip install requests feedparser beautifulsoup4 pyyaml

Usage
  python scripts/discover_security_feeds.py --write-yaml --only-new
  python scripts/discover_security_feeds.py --write-yaml --max-sites 500 --min-score 6
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional
from urllib.parse import urljoin, urlparse

import feedparser
import requests
import yaml
from bs4 import BeautifulSoup

UA = "awesome-security-feeds-discovery/1.2 (+https://github.com/)"

# Seed pages that tend to link out to many security resources/blogs
DEFAULT_SEEDS = [
    "https://github.com/sbilly/awesome-security",
    "https://github.com/enaqx/awesome-pentest",
    "https://github.com/meirwah/awesome-incident-response",
    "https://github.com/tylerha97/awesome-malware-analysis",
    "https://github.com/paralax/awesome-honeypots",
    "https://github.com/jivoi/awesome-osint",
    "https://github.com/toolswatch/blackhat-arsenal-tools",
    "https://github.com/trailofbits/publications",
    "https://www.reddit.com/r/netsec/",
    "https://www.reddit.com/r/blueteamsec/",
]

COMMON_FEED_PATHS = [
    "/feed", "/feed/", "/rss", "/rss/", "/rss.xml", "/atom.xml", "/feed.xml", "/index.xml",
    "/blog/rss", "/blog/rss.xml", "/blog/atom.xml", "/blog/feed", "/blog/feed.xml",
    "/rss/index.xml",
]

FEED_HINT_RE = re.compile(r"(rss|atom|feed|\.xml)(\b|$)", re.IGNORECASE)

SECURITY_KEYWORDS = [
    # broad
    "cve-", "vulnerability", "vuln", "exploit", "0day", "zero-day", "advisory", "patch",
    "malware", "ransomware", "phishing", "botnet", "trojan", "backdoor", "loader", "infostealer",
    "apt", "threat actor", "intrusion", "breach", "incident", "ioc", "tactic", "technique",
    "reverse engineering", "pwn", "pentest", "red team", "blue team", "dfir", "forensics",
    "edr", "siem", "splunk", "kql", "sigma", "yara",
    "kubernetes", "docker", "cloud", "aws", "azure", "gcp", "critical vulnerability",
    "campaign", "payload", "initial access", "lateral movement", "persistence", "privilege escalation",
   
    # extra common terms
    "authentication", "bypass", "rce", "remote code execution", "xss", "sqli", "ssrf", "csrf",
    "privilege escalation", "lpe", "eop",
    
    # Supply chain / impacto grande
    "supply chain attack", "software supply chain",
    "supply-chain attack",

    # Vazamentos e mega incidentes
    "major breach", "data leak", "data leaks", "massive leak",

    # Ransom gangs (mais quentes)
    "ransom gang", "double extortion", "ransom note",
]

# Simple category suggestion rules (you can replace later with your SMART_GROUP_RULES)
CATEGORY_RULES = [
    ("Vulnerabilities, CVEs", [r"\bcve\b", r"vulnerab", r"\b0day\b", r"zero-?day", r"advisory", r"\bpatch\b", r"\brce\b"]),
    ("Exploits", [r"\bexploit\b", r"\bpoc\b", r"proof of concept", r"weaponiz"]),
    ("Malware & Ransomware", [r"malware", r"ransomware", r"infostealer", r"loader", r"botnet", r"trojan", r"backdoor"]),
    ("Threat Intel", [r"\bapt\b", r"threat actor", r"campaign", r"\bioc\b", r"tactic", r"technique"]),
    ("DFIR & Forensics", [r"\bdfir\b", r"forensic", r"incident", r"breach", r"\bedr\b", r"\bsiem\b", r"splunk", r"\bkql\b", r"sigma"]),
    ("Cloud Security", [r"kubernetes", r"docker", r"\baws\b", r"\bazure\b", r"\bgcp\b", r"supply chain"]),
    ("Offensive Security", [r"pentest", r"pwn", r"red team"]),
]

DATA_DIR = "data/discovery"
OUT_YAML = "feeds/discovered.yaml"
OUT_CANDIDATES_YAML_DIR = "feeds/_candidates"
OUT_CANDIDATES_JSON_DIR = "data/discovery/candidates"
DEFAULT_BLOCKED_DOMAINS = "data/discovery/blocked_domains.txt"
DEFAULT_BLOCKED_FEEDS = "data/discovery/blocked_feeds.txt"


@dataclass
class FeedCandidate:
    feed_url: str
    site_url: str
    title: str
    description: str
    language: str
    feed_type: str  # rss|atom
    score: int
    matched_keywords: list[str]
    suggested_category: str
    discovered_via: str
    entries_sample: list[dict]
    url_hash: str
    discovered_at: str  # ISO-8601 UTC


def sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()




def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_blocklist(path: str) -> set[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = []
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                lines.append(line.lower())
            return set(lines)
    except FileNotFoundError:
        return set()


def norm_host(u: str) -> str:
    try:
        host = urlparse(u).netloc.lower()
    except Exception:
        return ""
    if host.startswith("www."):
        host = host[4:]
    return host


_slug_re = re.compile(r"[^a-z0-9]+")


def slugify(s: str, max_len: int = 50) -> str:
    s = (s or "").strip().lower()
    s = _slug_re.sub("-", s).strip("-")
    if not s:
        return "feed"
    return s[:max_len].rstrip("-")


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def write_candidate_yaml_split(candidates: list["FeedCandidate"], out_dir: str, only_new: bool, seen: dict) -> int:
    """Write one YAML file per candidate feed (diff-friendly review).
    Each file contains a YAML *list* with a single item, matching the existing schema.
    Returns number of files written.
    """
    ensure_dir(out_dir)
    written = 0
    for c in candidates:
        if only_new and c.url_hash in seen:
            continue
        item = candidate_to_yaml_item(c)
        # Keep discovery metadata (ignored by consumers that don't care)
        item["discovery"] = {
            "discovered_at": c.discovered_at,
            "score": c.score,
            "matched_keywords": c.matched_keywords,
            "discovered_via": c.discovered_via,
            "url_hash": c.url_hash,
        }
        base = slugify(c.title or norm_host(c.site_url) or norm_host(c.feed_url))
        fname = f"{base}__{c.url_hash[:10]}.yaml"
        path = os.path.join(out_dir, fname)
        save_yaml_list(path, [item])
        written += 1
    return written


def write_candidate_json_split(candidates: list["FeedCandidate"], out_dir: str, only_new: bool, seen: dict) -> int:
    """Write one JSON evidence file per candidate (audit trail)."""
    ensure_dir(out_dir)
    written = 0
    for c in candidates:
        if only_new and c.url_hash in seen:
            continue
        path = os.path.join(out_dir, f"{c.url_hash}.json")
        save_json(path, asdict(c))
        written += 1
    return written

def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    p = urlparse(url)
    return p._replace(fragment="").geturl()


def base_origin(url: str) -> str:
    p = urlparse(url)
    scheme = p.scheme or "https"
    return f"{scheme}://{p.netloc}"


def polite_get(session: requests.Session, url: str, timeout: int, sleep_s: float) -> Optional[requests.Response]:
    time.sleep(sleep_s)
    try:
        return session.get(
            url,
            timeout=timeout,
            headers={"User-Agent": UA, "Accept": "*/*"},
            allow_redirects=True,
        )
    except requests.RequestException:
        return None


def is_probably_html(resp: requests.Response) -> bool:
    ct = (resp.headers.get("Content-Type") or "").lower()
    return ("text/html" in ct) or ("application/xhtml+xml" in ct) or ct.startswith("text/")


def extract_outbound_links(html: str, base: str) -> set[str]:
    soup = BeautifulSoup(html, "html.parser")
    urls: set[str] = set()

    for a in soup.select("a[href]"):
        href = (a.get("href") or "").strip()
        if not href or href.startswith("#") or href.startswith("mailto:") or href.startswith("javascript:"):
            continue

        u = normalize_url(urljoin(base, href))
        if not u:
            continue

        pu = urlparse(u)
        if pu.scheme not in ("http", "https"):
            continue

        # skip obvious assets
        if any(pu.path.lower().endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".ico", ".pdf", ".zip")):
            continue

        urls.add(u)

    return urls


def extract_rel_alternate_feeds(html: str, base: str) -> set[str]:
    soup = BeautifulSoup(html, "html.parser")
    feeds: set[str] = set()

    for link in soup.select('link[rel="alternate"][href]'):
        t = (link.get("type") or "").lower()
        href = (link.get("href") or "").strip()
        if not href:
            continue
        if ("rss" in t) or ("atom" in t) or ("xml" in t) or FEED_HINT_RE.search(href):
            feeds.add(normalize_url(urljoin(base, href)))

    # also catch <a> links that look like feeds
    for a in soup.select("a[href]"):
        href = (a.get("href") or "").strip()
        if href and FEED_HINT_RE.search(href):
            feeds.add(normalize_url(urljoin(base, href)))

    return {f for f in feeds if f}


def validate_feed(session: requests.Session, feed_url: str, timeout: int, sleep_s: float) -> Optional[feedparser.FeedParserDict]:
    resp = polite_get(session, feed_url, timeout=timeout, sleep_s=sleep_s)
    if not resp or resp.status_code != 200:
        return None

    text = resp.text or ""
    if len(text) < 80:
        return None

    parsed = feedparser.parse(text)
    if not parsed or not getattr(parsed, "entries", None) or len(parsed.entries) == 0:
        return None

    return parsed


def detect_feed_type(parsed: feedparser.FeedParserDict, feed_url: str) -> str:
    # 1) parsed.version (best)
    v = (getattr(parsed, "version", None) or "").lower()
    if v:
        if "atom" in v:
            return "atom"
        if "rss" in v:
            return "rss"

    # 2) namespaces (fallback)
    namespaces = parsed.get("namespaces", {}) or {}
    for ns in namespaces.values():
        if isinstance(ns, str) and "atom" in ns.lower():
            return "atom"

    # 3) heuristic by URL
    if "atom" in feed_url.lower():
        return "atom"

    return "rss"


def suggest_category(text_blob_lower: str) -> str:
    for cat, patterns in CATEGORY_RULES:
        for pat in patterns:
            if re.search(pat, text_blob_lower, re.IGNORECASE):
                return cat
    return "Security (General)"


def score_security(parsed: feedparser.FeedParserDict, max_entries: int = 15) -> tuple[int, list[str], list[dict], str]:
    entries = parsed.entries[:max_entries]
    blob_parts = []
    sample = []

    for e in entries:
        title = (e.get("title") or "").strip()
        summary = (e.get("summary") or e.get("description") or "").strip()
        link = (e.get("link") or "").strip()
        published = (e.get("published") or e.get("updated") or "").strip()

        blob_parts.append(f"{title} {summary}".lower())
        sample.append({"title": title, "link": link, "published": published})

    blob = " ".join(blob_parts)

    matched = []
    score = 0
    strong = {
        "cve", "exploit", "ransomware", "malware", "apt", "zero-day", "0day",
        "vulnerability", "advisory", "patch", "rce", "remote code execution",
    }

    for kw in SECURITY_KEYWORDS:
        if kw in blob:
            matched.append(kw)
            score += 3 if kw in strong else 1

    # density bonuses
    uniq = set(matched)
    if len(uniq) >= 8:
        score += 3
    if len(entries) >= 10:
        score += 1

    matched = sorted(uniq)[:25]
    category = suggest_category(blob)
    return score, matched, sample[:5], category


def discover_site_feeds(session: requests.Session, site_url: str, timeout: int, sleep_s: float, blocked_domains: set[str], blocked_feeds: set[str]) -> list[FeedCandidate]:
    site_url = normalize_url(site_url)
    if not site_url:
        return []

    origin = base_origin(site_url)
    rel_feeds: set[str] = set()

    resp = polite_get(session, origin, timeout=timeout, sleep_s=sleep_s)
    if resp and resp.status_code == 200 and is_probably_html(resp):
        rel_feeds = extract_rel_alternate_feeds(resp.text, origin)

    candidates: set[str] = set(rel_feeds)
    for p in COMMON_FEED_PATHS:
        candidates.add(normalize_url(urljoin(origin, p)))

    out: list[FeedCandidate] = []
    for feed_url in list(candidates):
        nurl = normalize_url(feed_url).lower()
        host = norm_host(nurl)
        if host and host in blocked_domains:
            continue
        if nurl in blocked_feeds or feed_url.lower() in blocked_feeds:
            continue
        parsed = validate_feed(session, feed_url, timeout=timeout, sleep_s=sleep_s)
        if not parsed:
            continue

        feed_type = detect_feed_type(parsed, feed_url)
        score, matched, sample, category = score_security(parsed)

        title = (parsed.feed.get("title") or "").strip()
        desc = (parsed.feed.get("subtitle") or parsed.feed.get("description") or "").strip()
        lang = (parsed.feed.get("language") or "").strip()

        discovered_via = "rel=alternate" if feed_url in rel_feeds else "common_path"

        out.append(
            FeedCandidate(
                feed_url=feed_url,
                site_url=origin,
                title=title,
                description=desc,
                language=lang,
                feed_type=feed_type,
                score=score,
                matched_keywords=matched,
                suggested_category=category,
                discovered_via=discovered_via,
                entries_sample=sample,
                url_hash=sha1(feed_url),
                discovered_at=utc_now_iso(),
            )
        )

    return out


def load_json(path: str, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path: str, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def load_yaml_list(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or []
        return data if isinstance(data, list) else []
    except Exception:
        return []


def save_yaml_list(path: str, items: list[dict]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(items, f, sort_keys=False, allow_unicode=True)


def normalize_item_description(desc: str, category: str, title: str) -> str:
    desc = (desc or "").strip()
    if desc:
        desc = re.sub(r"\s+", " ", desc)
        if len(desc) > 220:
            desc = desc[:217].rstrip() + "..."
        return desc
    cat_lower = (category or "security").lower()
    return f"Updates from {title} covering {cat_lower}."


def candidate_to_yaml_item(c: FeedCandidate) -> dict:
    title = (c.title or "").strip() or urlparse(c.site_url).netloc
    category = (c.suggested_category or "Security (General)").strip()
    return {
        "url": c.feed_url,
        "category": category,
        "title": title,
        "type": c.feed_type,  # rss|atom
        "description": normalize_item_description(c.description, category, title),
    }


def merge_by_url(existing: list[dict], new_items: list[dict]) -> tuple[list[dict], int]:
    seen = {str(i.get("url", "")).strip(): i for i in existing if i.get("url")}
    added = 0
    for it in new_items:
        u = str(it.get("url", "")).strip()
        if not u or u in seen:
            continue
        existing.append(it)
        seen[u] = it
        added += 1
    return existing, added


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds-file", default="", help="Optional seeds file (one URL per line)")
    ap.add_argument("--max-seeds", type=int, default=10)
    ap.add_argument("--max-sites", type=int, default=400)
    ap.add_argument("--min-score", type=int, default=6)
    ap.add_argument("--timeout", type=int, default=18)
    ap.add_argument("--sleep", type=float, default=0.35)

    ap.add_argument("--write-yaml", action="store_true", help="Write/merge feeds/discovered.yaml")
    ap.add_argument("--write-yaml-split", action="store_true", help="Write one YAML per candidate in feeds/_candidates/ (review-friendly)")
    ap.add_argument("--yaml-split-dir", default=OUT_CANDIDATES_YAML_DIR, help="Directory for per-feed YAML candidates")
    ap.add_argument("--write-json-split", action="store_true", help="Write one JSON evidence file per candidate in data/discovery/candidates/")
    ap.add_argument("--json-split-dir", default=OUT_CANDIDATES_JSON_DIR, help="Directory for per-feed JSON evidence")
    ap.add_argument("--blocked-domains-file", default=DEFAULT_BLOCKED_DOMAINS, help="Blocklist of domains to ignore (one per line)")
    ap.add_argument("--blocked-feeds-file", default=DEFAULT_BLOCKED_FEEDS, help="Blocklist of feed URLs to ignore (one per line)")
    ap.add_argument("--only-new", action="store_true", help="Only include URLs never seen before (cache)")
    ap.add_argument("--merge-existing", action="store_true", help="Merge into existing feeds/discovered.yaml (default true when --write-yaml)")
    args = ap.parse_args()

    print("[INFO] discover_security_feeds starting...", flush=True)
    print(f"[INFO] CWD={os.getcwd()}", flush=True)
    print(f"[INFO] DATA_DIR={DATA_DIR} OUT_YAML={OUT_YAML}", flush=True)


    os.makedirs(DATA_DIR, exist_ok=True)
    print(f"[INFO] Ensured directory exists: {DATA_DIR}", flush=True)


    # Seeds
    seeds: list[str] = []
    if args.seeds_file:
        with open(args.seeds_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    seeds.append(line)
    else:
        seeds = list(DEFAULT_SEEDS)
    seeds = seeds[: max(1, args.max_seeds)]

    session = requests.Session()

    # Cache/dedupe
    seen_path = os.path.join(DATA_DIR, "feeds_seen.json")
    seen = load_json(seen_path, default={})  # {url_hash: {...}}

    blocked_domains = load_blocklist(args.blocked_domains_file)
    blocked_feeds = load_blocklist(args.blocked_feeds_file)

    if blocked_domains:
        print(f"[INFO] Loaded blocked domains: {len(blocked_domains)} from {args.blocked_domains_file}")
    if blocked_feeds:
        print(f"[INFO] Loaded blocked feeds: {len(blocked_feeds)} from {args.blocked_feeds_file}")


    # 1) Crawl seeds -> candidate site origins
    candidate_sites: set[str] = set()
    for seed in seeds:
        seed = normalize_url(seed)
        if not seed:
            continue
        resp = polite_get(session, seed, timeout=args.timeout, sleep_s=args.sleep)
        if not resp or resp.status_code != 200 or not is_probably_html(resp):
            continue

        links = extract_outbound_links(resp.text, base_origin(seed))
        for u in links:
            candidate_sites.add(base_origin(u))
        if len(candidate_sites) >= args.max_sites:
            break

    site_list = list(candidate_sites)[: args.max_sites]

    # 2) Discover + validate feeds
    candidates: list[FeedCandidate] = []
    for site in site_list:
        discovered = discover_site_feeds(session, site, timeout=args.timeout, sleep_s=args.sleep, blocked_domains=blocked_domains, blocked_feeds=blocked_feeds)
        for c in discovered:
            if c.score < args.min_score:
                continue
            candidates.append(c)

    # 3) Deduplicate by feed URL hash; keep best score
    uniq: dict[str, FeedCandidate] = {}
    for c in candidates:
        prev = uniq.get(c.url_hash)
        if prev is None or c.score > prev.score:
            uniq[c.url_hash] = c

    final = sorted(uniq.values(), key=lambda x: x.score, reverse=True)

    # 4) Write candidates JSON
    candidates_path = os.path.join(DATA_DIR, "feeds_candidates.json")
    save_json(candidates_path, [asdict(x) for x in final])

    # 5) Prepare YAML items in your format
    yaml_items: list[dict] = []
    for c in final:
        if args.only_new and c.url_hash in seen:
            continue
        yaml_items.append(candidate_to_yaml_item(c))

    # Sort for diff-friendly output
    yaml_items.sort(key=lambda x: (x["category"].lower(), x["title"].lower(), x["type"].lower(), x["url"]))

    # 6) Write/merge discovered.yaml
    added = 0
    if args.write_yaml:
        existing = load_yaml_list(OUT_YAML)
        if args.merge_existing or True:
            merged, added = merge_by_url(existing, yaml_items)
            merged.sort(key=lambda x: (x["category"].lower(), x["title"].lower(), x["type"].lower(), x["url"]))
            save_yaml_list(OUT_YAML, merged)
        else:
            save_yaml_list(OUT_YAML, yaml_items)
            added = len(yaml_items)

    # 6b) Optional: split outputs for review/audit
    split_yaml_written = 0
    split_json_written = 0
    if args.write_yaml_split:
        split_yaml_written = write_candidate_yaml_split(final, args.yaml_split_dir, args.only_new, seen)
        print(f"[OK] Wrote YAML candidates (split): {split_yaml_written} → {args.yaml_split_dir}")
    if args.write_json_split:
        split_json_written = write_candidate_json_split(final, args.json_split_dir, args.only_new, seen)
        print(f"[OK] Wrote JSON evidence (split): {split_json_written} → {args.json_split_dir}")


    # 7) Update seen cache
    now_ts = int(time.time())
    for c in final:
        seen.setdefault(c.url_hash, {})
        seen[c.url_hash].update(
            {
                "feed_url": c.feed_url,
                "site_url": c.site_url,
                "title": c.title,
                "last_seen_ts": now_ts,
                "score": c.score,
                "feed_type": c.feed_type,
            }
        )
    save_json(seen_path, seen)

    # Summary
    print(f"[OK] Seeds scanned: {len(seeds)}")
    print(f"[OK] Candidate sites: {len(site_list)}")
    print(f"[OK] Candidate feeds kept (score>={args.min_score}): {len(final)}")
    print(f"[OK] Wrote: {candidates_path}")
    print(f"[OK] Wrote cache: {seen_path}")
    if args.write_yaml:
        print(f"[OK] Updated: {OUT_YAML} (added {added} new items)")


if __name__ == "__main__":
    main()
