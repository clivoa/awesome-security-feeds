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
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import feedparser
import requests
import yaml
try:
    from bs4 import BeautifulSoup
except ModuleNotFoundError:  # pragma: no cover - optional until runtime needs HTML parsing
    BeautifulSoup = None

UA = "awesome-security-feeds-discovery/1.2 (+https://github.com/)"

# Fallback seed pages (prefer data/discovery/seeds.txt when present).
DEFAULT_SEEDS = [
    "https://github.com/sbilly/awesome-security",
    "https://github.com/enaqx/awesome-pentest",
    "https://github.com/meirwah/awesome-incident-response",
    "https://github.com/tylerha97/awesome-malware-analysis",
    "https://github.com/hslatman/awesome-threat-intelligence",
    "https://github.com/fabacab/awesome-cybersecurity-blueteam",
    "https://github.com/0x4D31/awesome-threat-detection",
    "https://github.com/paralax/awesome-honeypots",
    "https://github.com/jivoi/awesome-osint",
    "https://github.com/toolswatch/blackhat-arsenal-tools",
    "https://github.com/trailofbits/publications",
]

# High-noise platforms/asset domains frequently present in "awesome" pages.
DISCOVERY_IGNORED_HOSTS = {
    "github.com",
    "gist.github.com",
    "raw.githubusercontent.com",
    "api.github.com",
    "reddit.com",
    "old.reddit.com",
    "np.reddit.com",
    "x.com",
    "twitter.com",
    "t.co",
    "linkedin.com",
    "www.linkedin.com",
    "facebook.com",
    "www.facebook.com",
    "youtube.com",
    "www.youtube.com",
    "youtu.be",
    "img.shields.io",
    "shields.io",
    "badge.fury.io",
}
DISCOVERY_IGNORED_FILE_EXTS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".ico",
    ".pdf", ".zip", ".tar", ".gz", ".tgz", ".bz2", ".7z",
)

COMMON_FEED_PATHS = [
    "/feed", "/feed/", "/rss", "/rss/", "/rss.xml", "/atom.xml", "/feed.xml", "/index.xml",
    "/blog/rss", "/blog/rss.xml", "/blog/atom.xml", "/blog/feed", "/blog/feed.xml",
    "/rss/index.xml",
]

FEED_HINT_RE = re.compile(r"(rss|atom|feed|\.xml)(\b|$)", re.IGNORECASE)

SECURITY_KEYWORDS = [
    # broad
    "cve", "vulnerability", "vuln", "exploit", "0day", "zero-day", "advisory", "patch",
    "malware", "ransomware", "phishing", "botnet", "trojan", "backdoor", "loader", "infostealer",
    "apt", "threat actor", "intrusion", "breach", "incident", "ioc", "tactic", "technique",
    "reverse engineering", "pwn", "pentest", "red team", "blue team", "dfir", "forensics",
    "edr", "siem", "splunk", "kql", "sigma", "yara",
    "kubernetes", "docker", "cloud", "aws", "azure", "gcp",
    "campaign", "payload", "initial access", "lateral movement", "persistence", "privilege escalation",
    # extra common terms
    "authentication", "bypass", "rce", "remote code execution", "xss", "sqli", "ssrf", "csrf",
    "privilege escalation", "denial of service", "data leak", "data exfiltration",
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

# Candidate bucket files (for PR review).
CANDIDATE_BUCKET_FILES = {
    "crypto-and-blockchain-security": "crypto-and-blockchain-security.yaml",
    "cybercrime-darknet-and-leaks": "cybercrime-darknet-and-leaks.yaml",
    "dfir-and-forensics": "dfir-and-forensics.yaml",
    "general-security-and-blogs": "general-security-and-blogs.yaml",
    "government-cert-and-advisories": "government-cert-and-advisories.yaml",
    "leaks-and-breaches": "leaks-and-breaches.yaml",
    "malware-and-threat-research": "malware-and-threat-research.yaml",
    "osint-communities-and-subreddits": "osint-communities-and-subreddits.yaml",
    "podcasts-and-youtube": "podcasts-and-youtube.yaml",
    "vendors-and-product-blogs": "vendors-and-product-blogs.yaml",
    "vulnerabilities-cves-and-exploits": "vulnerabilities-cves-and-exploits.yaml",
}

CANDIDATE_BUCKET_LABELS = {
    "crypto-and-blockchain-security": "Crypto & Blockchain Security",
    "cybercrime-darknet-and-leaks": "Cybercrime, Darknet & Leaks",
    "dfir-and-forensics": "DFIR & Forensics",
    "general-security-and-blogs": "Security (General) & Blogs",
    "government-cert-and-advisories": "Government / CERT & Advisories",
    "leaks-and-breaches": "Leaks & Breaches",
    "malware-and-threat-research": "Malware & Threat Research",
    "osint-communities-and-subreddits": "OSINT, Communities & Subreddits",
    "podcasts-and-youtube": "Podcasts & YouTube",
    "vendors-and-product-blogs": "Vendors & Product Blogs",
    "vulnerabilities-cves-and-exploits": "Vulnerabilities, CVEs & Exploits",
}

OUT_CANDIDATES_YAML_DIR = "feeds/_candidates"
OUT_CANDIDATES_JSON_DIR = "data/discovery/candidates"
DEFAULT_SEEDS_FILE = "data/discovery/seeds.txt"
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


def require_bs4() -> None:
    if BeautifulSoup is None:
        raise SystemExit("Missing dependency: beautifulsoup4 (pip install beautifulsoup4)")


def log_info(message: str) -> None:
    print(f"[INFO] {message}", flush=True)


def log_ok(message: str) -> None:
    print(f"[OK] {message}", flush=True)


def load_seed_urls(seeds_file: str, max_seeds: int) -> list[str]:
    seeds: list[str] = []
    if seeds_file:
        try:
            with open(seeds_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        seeds.append(line)
        except FileNotFoundError:
            # Fall back to built-in seeds so the workflow still runs on fresh clones.
            seeds = []

    if not seeds:
        seeds = list(DEFAULT_SEEDS)

    normalized: list[str] = []
    seen: set[str] = set()
    for seed in seeds:
        url = normalize_url(seed)
        if not url or url in seen:
            continue
        seen.add(url)
        normalized.append(url)
        if len(normalized) >= max(1, max_seeds):
            break
    return normalized


def is_blocked_host(host: str, blocked_domains: set[str]) -> bool:
    if not host:
        return True
    if host in blocked_domains:
        return True
    return any(host.endswith(f".{d}") for d in blocked_domains if d)


def should_skip_candidate_site(url: str, blocked_domains: set[str]) -> bool:
    host = norm_host(url)
    if not host or "." not in host:
        return True
    if host in DISCOVERY_IGNORED_HOSTS:
        return True
    if is_blocked_host(host, blocked_domains):
        return True
    return False


def sort_yaml_items(items: list[dict]) -> None:
    items.sort(
        key=lambda x: (
            str(x.get("category") or "").lower(),
            str(x.get("title") or "").lower(),
            str(x.get("type") or "").lower(),
            str(x.get("url") or ""),
        )
    )


def dedupe_candidates_keep_best(candidates: list["FeedCandidate"]) -> list["FeedCandidate"]:
    uniq: dict[str, FeedCandidate] = {}
    for candidate in candidates:
        prev = uniq.get(candidate.url_hash)
        if prev is None or candidate.score > prev.score:
            uniq[candidate.url_hash] = candidate
    return sorted(uniq.values(), key=lambda x: x.score, reverse=True)


def update_seen_cache(seen: dict[str, Any], candidates: list["FeedCandidate"]) -> None:
    now_ts = int(time.time())
    for c in candidates:
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


def bucket_for_candidate(c: "FeedCandidate") -> str:
    """Map a candidate to one of the fixed _candidates bucket files."""
    cat = (c.suggested_category or "").strip().lower()
    blob = " ".join([
        (c.title or ""),
        (c.description or ""),
        (c.site_url or ""),
        " ".join(c.matched_keywords or []),
        cat,
    ]).lower()

    # Strong signals first
    if any(k in blob for k in ("crypto", "blockchain", "web3", "defi", "wallet", "exchange")):
        return "crypto-and-blockchain-security"
    if any(k in blob for k in ("podcast", "youtube", "video", "episode")):
        return "podcasts-and-youtube"
    if any(k in blob for k in ("osint", "subreddit", "reddit", "community", "forum", "discord", "telegram")):
        return "osint-communities-and-subreddits"
    if any(k in blob for k in ("darknet", "carding", "fraud", "ransom", "extortion", "leak site", "cybercrime")):
        return "cybercrime-darknet-and-leaks"
    if any(k in blob for k in ("breach", "leak", "exposed", "data leak", "compromised")):
        return "leaks-and-breaches"
    if any(k in blob for k in ("cert", "cisa", "enisa", "nvd", "advisory", "bulletin", ".gov")):
        return "government-cert-and-advisories"

    # Category suggestions from rules
    if any(k in cat for k in ("vulnerab", "cves", "cve", "exploit", "offensive")):
        return "vulnerabilities-cves-and-exploits"
    if any(k in cat for k in ("dfir", "forensic")):
        return "dfir-and-forensics"
    if any(k in cat for k in ("malware", "ransom", "threat intel", "threat")):
        return "malware-and-threat-research"

    # Vendor-ish content
    if any(k in blob for k in ("release", "product", "vendor", "update", "changelog", "patch")):
        return "vendors-and-product-blogs"

    return "general-security-and-blogs"


def write_candidate_yaml_categorized(
    candidates: list["FeedCandidate"],
    out_dir: str,
    only_new: bool,
    seen: dict,
    max_new: int = 0,
) -> int:
    """Write candidates into fixed bucket YAML files (append/merge; no overwrite).

    Creates/updates files like:
      feeds/_candidates/vulnerabilities-cves-and-exploits.yaml

    Returns number of *new* items added across all bucket files.
    """
    ensure_dir(out_dir)

    # Load current content for each bucket file once
    bucket_items: dict[str, list[dict]] = {}
    bucket_seen_urls: dict[str, set[str]] = {}
    for bucket, fname in CANDIDATE_BUCKET_FILES.items():
        path = os.path.join(out_dir, fname)
        existing = load_yaml_list(path)
        bucket_items[bucket] = existing
        bucket_seen_urls[bucket] = { (it.get("url") or "").strip() for it in existing if isinstance(it, dict) }

    added_total = 0
    added_new = 0
    # Keep stable order: highest score first
    for c in sorted(candidates, key=lambda x: x.score, reverse=True):
        if only_new and c.url_hash in seen:
            continue
        bucket = bucket_for_candidate(c)
        url = (c.feed_url or "").strip()
        if not url or url in bucket_seen_urls[bucket]:
            continue

        item = candidate_to_yaml_item(c)
        # Override category to bucket label to make the file self-describing
        item["category"] = CANDIDATE_BUCKET_LABELS.get(bucket, item.get("category") or "")
        item["discovery"] = {
            "discovered_at": c.discovered_at,
            "score": c.score,
            "matched_keywords": c.matched_keywords,
            "discovered_via": c.discovered_via,
            "url_hash": c.url_hash,
        }
        bucket_items[bucket].append(item)
        bucket_seen_urls[bucket].add(url)
        added_total += 1
        added_new += 1
        if max_new and added_new >= max_new:
            break

    # Write back (sorted) only if we added something
    if added_total:
        for bucket, fname in CANDIDATE_BUCKET_FILES.items():
            items = bucket_items[bucket]
            if not items:
                continue
            items.sort(key=lambda x: (str(x.get("category") or "").lower(), str(x.get("title") or "").lower(), str(x.get("type") or "").lower(), str(x.get("url") or "")))
            path = os.path.join(out_dir, fname)
            save_yaml_list(path, items)

    return added_total


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
    if not p.netloc:
        return ""
    scheme = (p.scheme or "https").lower()
    netloc = (p.netloc or "").lower()
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    if netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]
    path = p.path or ""
    return p._replace(scheme=scheme, netloc=netloc, path=path, fragment="").geturl()


def base_origin(url: str) -> str:
    p = urlparse(url)
    scheme = (p.scheme or "https").lower()
    netloc = (p.netloc or "").lower()
    return f"{scheme}://{netloc}" if netloc else ""


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
    require_bs4()
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
        if any(pu.path.lower().endswith(ext) for ext in DISCOVERY_IGNORED_FILE_EXTS):
            continue

        urls.add(u)

    return urls


def extract_rel_alternate_feeds(html: str, base: str) -> set[str]:
    require_bs4()
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

    body = resp.content or b""
    if len(body) < 80:
        return None

    parsed = feedparser.parse(body)
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
    if not origin or should_skip_candidate_site(origin, blocked_domains):
        return []

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
        if is_blocked_host(host, blocked_domains):
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


def collect_candidate_sites(
    session: requests.Session,
    seeds: list[str],
    *,
    max_sites: int,
    timeout: int,
    sleep_s: float,
    blocked_domains: set[str],
) -> list[str]:
    candidate_sites: set[str] = set()

    for seed in seeds:
        resp = polite_get(session, seed, timeout=timeout, sleep_s=sleep_s)
        if not resp or resp.status_code != 200 or not is_probably_html(resp):
            continue

        seed_origin = base_origin(seed)
        if not seed_origin:
            continue

        for url in extract_outbound_links(resp.text, seed_origin):
            origin = base_origin(url)
            if not origin or should_skip_candidate_site(origin, blocked_domains):
                continue
            candidate_sites.add(origin)
            if len(candidate_sites) >= max_sites:
                break

        if len(candidate_sites) >= max_sites:
            break

    return sorted(candidate_sites)[:max_sites]


def collect_feed_candidates(
    session: requests.Session,
    site_list: list[str],
    *,
    timeout: int,
    sleep_s: float,
    min_score: int,
    blocked_domains: set[str],
    blocked_feeds: set[str],
) -> list[FeedCandidate]:
    candidates: list[FeedCandidate] = []
    for site in site_list:
        discovered = discover_site_feeds(
            session,
            site,
            timeout=timeout,
            sleep_s=sleep_s,
            blocked_domains=blocked_domains,
            blocked_feeds=blocked_feeds,
        )
        for c in discovered:
            if c.score >= min_score:
                candidates.append(c)
    return candidates


def load_existing_feed_urls(feeds_dir: str) -> set[str]:
    """Load already-known feed URLs from feeds/*.yaml and feeds/_candidates/*.yaml."""
    urls: set[str] = set()
    candidate_dirs = [feeds_dir, os.path.join(feeds_dir, "_candidates")]

    for directory in candidate_dirs:
        if not os.path.isdir(directory):
            continue
        for name in sorted(os.listdir(directory)):
            if not name.endswith(".yaml"):
                continue
            path = os.path.join(directory, name)
            for item in load_yaml_list(path):
                if not isinstance(item, dict):
                    continue
                url = normalize_url(str(item.get("url", "")))
                if url:
                    urls.add(url.lower())
    return urls


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


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--seeds-file",
        default=DEFAULT_SEEDS_FILE,
        help=f"Seeds file (one URL per line). Falls back to built-in list if missing. Default: {DEFAULT_SEEDS_FILE}",
    )
    ap.add_argument("--max-seeds", type=int, default=10)
    ap.add_argument("--max-sites", type=int, default=400)
    ap.add_argument("--min-score", type=int, default=6)
    ap.add_argument("--timeout", type=int, default=18)
    ap.add_argument("--sleep", type=float, default=0.35)

    ap.add_argument("--write-yaml", action="store_true", help="Write/merge feeds/discovered.yaml")
    # Candidate outputs (recommended for PR review): categorized bucket files under feeds/_candidates/
    ap.add_argument("--write-yaml-split", action="store_true", help="Write candidates into category bucket YAML files in feeds/_candidates/ (review-friendly)")
    ap.add_argument("--write-yaml-per-feed", action="store_true", help="(Legacy) Write one YAML file per candidate (can create many files)")
    ap.add_argument("--yaml-split-dir", default=OUT_CANDIDATES_YAML_DIR, help="Directory for candidate YAML outputs (default: feeds/_candidates)")
    ap.add_argument("--max-new-candidates", type=int, default=75, help="Max number of NEW candidate feeds to add to YAML outputs (0=unlimited)")

    # Evidence output
    ap.add_argument("--write-json-split", action="store_true", help="(Optional) Write one JSON evidence file per candidate (can create many files)")
    ap.add_argument("--json-split-dir", default=OUT_CANDIDATES_JSON_DIR, help="Directory for per-feed JSON evidence")

    # Filters / governance
    ap.add_argument("--blocked-domains-file", default=DEFAULT_BLOCKED_DOMAINS, help="Blocklist of domains to ignore (one per line)")
    ap.add_argument("--blocked-feeds-file", default=DEFAULT_BLOCKED_FEEDS, help="Blocklist of feed URLs to ignore (one per line)")
    ap.add_argument("--known-feeds-dir", default="feeds", help="Directory with existing feeds YAML files used to skip already-known feeds")
    ap.add_argument("--only-new", action="store_true", help="Only include URLs never seen before (cache)")
    ap.set_defaults(merge_existing=True)
    ap.add_argument("--merge-existing", dest="merge_existing", action="store_true", help="Merge into existing feeds/discovered.yaml (default)")
    ap.add_argument("--no-merge-existing", dest="merge_existing", action="store_false", help="Replace feeds/discovered.yaml instead of merging")
    return ap


def main() -> None:
    args = build_arg_parser().parse_args()

    log_info("discover_security_feeds starting...")
    log_info(f"CWD={os.getcwd()}")
    log_info(f"DATA_DIR={DATA_DIR} OUT_YAML={OUT_YAML}")

    ensure_dir(DATA_DIR)
    log_info(f"Ensured directory exists: {DATA_DIR}")
    seeds = load_seed_urls(args.seeds_file, args.max_seeds)
    if args.seeds_file and os.path.exists(args.seeds_file):
        log_info(f"Loaded seeds from {args.seeds_file}: {len(seeds)}")
    else:
        log_info(f"Using built-in seeds: {len(seeds)}")

    session = requests.Session()

    # Cache/dedupe
    seen_path = os.path.join(DATA_DIR, "feeds_seen.json")
    seen = load_json(seen_path, default={})  # {url_hash: {...}}

    blocked_domains = load_blocklist(args.blocked_domains_file)
    blocked_feeds = load_blocklist(args.blocked_feeds_file)

    if blocked_domains:
        log_info(f"Loaded blocked domains: {len(blocked_domains)} from {args.blocked_domains_file}")
    if blocked_feeds:
        log_info(f"Loaded blocked feeds: {len(blocked_feeds)} from {args.blocked_feeds_file}")

    # 1) Crawl seeds -> candidate site origins
    site_list = collect_candidate_sites(
        session,
        seeds,
        max_sites=args.max_sites,
        timeout=args.timeout,
        sleep_s=args.sleep,
        blocked_domains=blocked_domains,
    )

    # 2) Discover + validate feeds
    candidates = collect_feed_candidates(
        session,
        site_list,
        timeout=args.timeout,
        sleep_s=args.sleep,
        min_score=args.min_score,
        blocked_domains=blocked_domains,
        blocked_feeds=blocked_feeds,
    )

    # 3) Deduplicate by feed URL hash; keep best score
    final = dedupe_candidates_keep_best(candidates)

    # 3b) Skip feeds already present in repo (main feeds and current candidate buckets)
    known_feed_urls = load_existing_feed_urls(args.known_feeds_dir)
    if known_feed_urls:
        before_known_filter = len(final)
        final = [
            c for c in final
            if normalize_url(c.feed_url).lower() not in known_feed_urls
        ]
        skipped_known = before_known_filter - len(final)
        if skipped_known:
            log_info(f"Skipped already-known feeds from repo YAMLs: {skipped_known}")

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
    sort_yaml_items(yaml_items)

    # 6) Write/merge discovered.yaml
    added = 0
    if args.write_yaml:
        existing = load_yaml_list(OUT_YAML)
        if args.merge_existing:
            merged, added = merge_by_url(existing, yaml_items)
            sort_yaml_items(merged)
            save_yaml_list(OUT_YAML, merged)
        else:
            save_yaml_list(OUT_YAML, yaml_items)
            added = len(yaml_items)

    # 6b) Optional: candidate outputs for PR review / audit
    split_yaml_added = 0
    split_json_written = 0
    if args.write_yaml_split:
        if args.write_yaml_per_feed:
            # Legacy mode (many files): one YAML per candidate feed
            split_yaml_added = write_candidate_yaml_split(final, args.yaml_split_dir, args.only_new, seen)
            print(f"[OK] Wrote YAML candidates (per-feed): {split_yaml_added} → {args.yaml_split_dir}")
        else:
            # Recommended mode: append/merge into fixed category bucket files
            split_yaml_added = write_candidate_yaml_categorized(final, args.yaml_split_dir, args.only_new, seen, max_new=args.max_new_candidates)
            print(f"[OK] Updated YAML candidate buckets: +{split_yaml_added} new feeds → {args.yaml_split_dir}")
    if args.write_json_split:
        split_json_written = write_candidate_json_split(final, args.json_split_dir, args.only_new, seen)
        log_ok(f"Wrote JSON evidence (per-feed): {split_json_written} -> {args.json_split_dir}")

    # 7) Update seen cache
    update_seen_cache(seen, final)
    save_json(seen_path, seen)

    # Summary
    log_ok(f"Seeds scanned: {len(seeds)}")
    log_ok(f"Candidate sites: {len(site_list)}")
    log_ok(f"Candidate feeds kept (score>={args.min_score}): {len(final)}")
    log_ok(f"Wrote: {candidates_path}")
    log_ok(f"Wrote cache: {seen_path}")
    if args.write_yaml:
        log_ok(f"Updated: {OUT_YAML} (added {added} new items)")


if __name__ == "__main__":
    main()
