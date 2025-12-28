#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
discover_security_feeds.py

Zero-input discovery of security-related RSS/Atom feeds.

Features:
- Crawl public seed pages -> extract domains
- Discover feeds via rel=alternate + common paths
- Validate RSS/Atom feeds
- Detect feed type (rss|atom)
- Score security relevance
- Enforce strong-security signal + per-entry density
- Exclude noise via external rules file: data/exclude_feeds.txt
- Output candidates to feeds/discovered.yaml
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, asdict
from typing import Optional
from urllib.parse import urljoin, urlparse

import feedparser
import requests
import yaml
from bs4 import BeautifulSoup


# =========================
# CONFIG
# =========================

UA = "awesome-security-feeds-discovery/1.3 (+https://github.com/clivoa/awesome-security-feeds)"

DATA_DIR = "data/discovery"
OUT_YAML = "feeds/discovered.yaml"
EXCLUDE_FILE = "data/exclude_feeds.txt"

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
    "/feed", "/feed/", "/rss", "/rss/", "/rss.xml",
    "/atom.xml", "/feed.xml", "/index.xml",
    "/blog/rss", "/blog/rss.xml", "/blog/atom.xml",
    "/blog/feed", "/blog/feed.xml",
]

FEED_HINT_RE = re.compile(r"(rss|atom|feed|\.xml)(\b|$)", re.IGNORECASE)

STRONG_KEYWORDS = {
    "vulnerability", "malware", 
    "dfir", "forensics",
    "edr", "sigma", "yara",
    "zero-day", "zeroday", "0day",
    "critical vulnerability", "exploit",
    "cve-", "backdoor", "rce", 
    "remote code execution", "privilege escalation",
    "trojan", "wormable", "trojanized",

    # Supply chain / impacto grande
    "supply chain attack", "software supply chain",
    "supply-chain attack",

    # Vazamentos e mega incidentes
    "major breach", "data leak", "data leaks", "massive leak",

    # Ransom gangs (mais quentes)
    "ransom gang", "ransomware", "double extortion", "ransom note",
}

SECURITY_KEYWORDS = sorted(STRONG_KEYWORDS | {
    "patch", "advisory", "threat actor",
    "phishing", "backdoor", "botnet",
    "campaign", "lateral movement",
    "privilege escalation",
})

CATEGORY_RULES = [
    ("Vulnerabilities, CVEs", [r"\bcve\b", r"vulnerab", r"0day", r"zero-?day", r"rce"]),
    ("Exploits", [r"\bexploit\b", r"\bpoc\b"]),
    ("Malware & Ransomware", [r"malware", r"ransomware", r"botnet", r"infostealer"]),
    ("Threat Intel", [r"\bapt\b", r"campaign", r"\bioc\b"]),
    ("DFIR & Forensics", [r"\bdfir\b", r"forensic", r"incident", r"breach"]),
]


# =========================
# DATA MODELS
# =========================

@dataclass
class FeedCandidate:
    feed_url: str
    site_url: str
    title: str
    description: str
    language: str
    feed_type: str
    score: int
    matched_keywords: list[str]
    suggested_category: str
    discovered_via: str
    entries_sample: list[dict]
    url_hash: str


# =========================
# UTILS
# =========================

def sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()


def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    return urlparse(url)._replace(fragment="").geturl()


def base_origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme or 'https'}://{p.netloc}"


def polite_get(session, url, timeout, sleep):
    time.sleep(sleep)
    try:
        return session.get(url, timeout=timeout, headers={"User-Agent": UA})
    except Exception:
        return None


def is_html(resp):
    ct = (resp.headers.get("Content-Type") or "").lower()
    return "html" in ct


# =========================
# EXCLUSION RULES
# =========================

def load_exclusions(path: str):
    rules = {"domain": set(), "url_contains": set(), "title_contains": set()}
    if not os.path.exists(path):
        return rules

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            kind, value = line.split(":", 1)
            kind = kind.strip().lower()
            value = value.strip().lower()
            if kind in rules:
                rules[kind].add(value)
    return rules


def should_exclude(feed_url, title, site_url, rules):
    domain = (urlparse(site_url).netloc or "").lower()
    if domain in rules["domain"]:
        return True
    for s in rules["url_contains"]:
        if s in (feed_url or "").lower():
            return True
    for s in rules["title_contains"]:
        if s in (title or "").lower():
            return True
    return False


# =========================
# FEED LOGIC
# =========================

def detect_feed_type(parsed, feed_url):
    v = (parsed.version or "").lower()
    if "atom" in v:
        return "atom"
    if "rss" in v:
        return "rss"
    if "atom" in feed_url.lower():
        return "atom"
    return "rss"


def suggest_category(blob):
    for cat, patterns in CATEGORY_RULES:
        for p in patterns:
            if re.search(p, blob, re.I):
                return cat
    return "Security (General)"


def strong_hits(entries):
    hits = 0
    for e in entries:
        text = f"{e.get('title','')} {e.get('summary','')} {e.get('description','')}".lower()
        if any(k in text for k in STRONG_KEYWORDS):
            hits += 1
    return hits


def score_feed(parsed):
    entries = parsed.entries[:15]
    blob = " ".join(
        f"{e.get('title','')} {e.get('summary','')} {e.get('description','')}".lower()
        for e in entries
    )

    matched = [k for k in SECURITY_KEYWORDS if k in blob]
    has_strong = any(k in STRONG_KEYWORDS for k in matched)
    entry_hits = strong_hits(entries)

    score = len(matched) + (3 if has_strong else 0) + (2 if entry_hits >= 2 else 0)
    category = suggest_category(blob)

    return score, sorted(set(matched)), has_strong, entry_hits, category


# =========================
# DISCOVERY
# =========================

def extract_links(html, base):
    soup = BeautifulSoup(html, "html.parser")
    urls = set()
    for a in soup.select("a[href]"):
        href = a.get("href", "")
        if href.startswith(("mailto:", "javascript:", "#")):
            continue
        u = normalize_url(urljoin(base, href))
        if u.startswith("http"):
            urls.add(u)
    return urls


def extract_feeds(html, base):
    soup = BeautifulSoup(html, "html.parser")
    feeds = set()

    for link in soup.select('link[rel="alternate"][href]'):
        href = link.get("href", "")
        if FEED_HINT_RE.search(href):
            feeds.add(normalize_url(urljoin(base, href)))

    for a in soup.select("a[href]"):
        href = a.get("href", "")
        if FEED_HINT_RE.search(href):
            feeds.add(normalize_url(urljoin(base, href)))

    return feeds


def validate_feed(session, url, timeout, sleep):
    resp = polite_get(session, url, timeout, sleep)
    if not resp or resp.status_code != 200:
        return None
    parsed = feedparser.parse(resp.text)
    if not parsed.entries:
        return None
    return parsed


# =========================
# MAIN
# =========================

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-sites", type=int, default=400)
    ap.add_argument("--min-score", type=int, default=6)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--sleep", type=float, default=0.3)
    ap.add_argument("--write-yaml", action="store_true")
    ap.add_argument("--only-new", action="store_true")
    args = ap.parse_args()

    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(OUT_YAML), exist_ok=True)

    exclude_rules = load_exclusions(EXCLUDE_FILE)
    session = requests.Session()

    candidate_sites = set()
    for seed in DEFAULT_SEEDS:
        r = polite_get(session, seed, args.timeout, args.sleep)
        if r and r.status_code == 200 and is_html(r):
            candidate_sites |= {base_origin(u) for u in extract_links(r.text, seed)}
        if len(candidate_sites) >= args.max_sites:
            break

    feeds = []
    for site in list(candidate_sites)[: args.max_sites]:
        r = polite_get(session, site, args.timeout, args.sleep)
        if not r or not is_html(r):
            continue

        feed_urls = extract_feeds(r.text, site)
        for p in COMMON_FEED_PATHS:
            feed_urls.add(normalize_url(site + p))

        for feed_url in feed_urls:
            parsed = validate_feed(session, feed_url, args.timeout, args.sleep)
            if not parsed:
                continue

            title = (parsed.feed.get("title") or "").strip()
            desc = (parsed.feed.get("description") or "").strip()

            if should_exclude(feed_url, title, site, exclude_rules):
                continue

            score, matched, has_strong, entry_hits, category = score_feed(parsed)

            if score < args.min_score:
                continue
            if not has_strong or entry_hits < 1:
                continue

            feeds.append(
                FeedCandidate(
                    feed_url=feed_url,
                    site_url=site,
                    title=title or urlparse(site).netloc,
                    description=desc,
                    language=parsed.feed.get("language", ""),
                    feed_type=detect_feed_type(parsed, feed_url),
                    score=score,
                    matched_keywords=matched,
                    suggested_category=category,
                    discovered_via="auto",
                    entries_sample=[],
                    url_hash=sha1(feed_url),
                )
            )

    # Deduplicate by URL hash
    uniq = {}
    for f in feeds:
        if f.url_hash not in uniq or f.score > uniq[f.url_hash].score:
            uniq[f.url_hash] = f

    final = sorted(uniq.values(), key=lambda x: x.score, reverse=True)

    yaml_items = [
        {
            "url": f.feed_url,
            "category": f.suggested_category,
            "title": f.title,
            "type": f.feed_type,
            "description": f.description or f"Security updates from {f.title}.",
        }
        for f in final
    ]

    if args.write_yaml:
        with open(OUT_YAML, "w", encoding="utf-8") as f:
            yaml.safe_dump(yaml_items, f, sort_keys=False, allow_unicode=True)

    print(f"[OK] Candidate sites: {len(candidate_sites)}")
    print(f"[OK] Feeds accepted: {len(final)}")
    print(f"[OK] Written: {OUT_YAML if args.write_yaml else 'dry-run'}")


if __name__ == "__main__":
    main()
