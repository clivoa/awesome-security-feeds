# Categories

This repository groups feeds by **content intent** (what the source primarily publishes), to keep discovery and filtering consistent.

## Inclusion criteria

A feed is a good fit when it is:
- security-focused (or consistently security-relevant)
- original research, advisories, or high-signal reporting
- stable and machine-readable (RSS/Atom reachable, not HTML-only)

Feeds are **avoided/filtered** when they are:
- mostly marketing / product promos (unless high-signal advisories)
- SEO farms / scraped reposts
- consistently broken or rate-limited without a stable alternative

## Category list

| Category | Purpose | YAML file |
|---|---|---|
| General Security & Blogs | broad security blogs, mixed topics, personal notes | `feeds/general-security-and-blogs.yaml` |
| Vulnerabilities, CVEs & Exploits | CVE coverage, exploit writeups, vuln advisories | `feeds/vulnerabilities-cves-and-exploits.yaml` |
| Malware & Threat Research | malware analysis, campaigns, threat actor research | `feeds/malware-and-threat-research.yaml` |
| DFIR & Forensics | incident response, forensics, tooling, case studies | `feeds/dfir-and-forensics.yaml` |
| Government, CERT & Advisories | official advisories, CERTs, national CSIRTs | `feeds/government-cert-and-advisories.yaml` |
| Cybercrime, Darknet & Leaks | cybercrime reporting, leak monitoring, underground trends | `feeds/cybercrime-darknet-and-leaks.yaml` |
| Leaks & Breaches | breach reporting and related tracking | `feeds/leaks-and-breaches.yaml` |
| Crypto & Blockchain Security | smart contracts, chain attacks, wallet security | `feeds/crypto-and-blockchain-security.yaml` |
| OSINT, Communities & Subreddits | community sources, OSINT hubs (use sparingly) | `feeds/osint-communities-and-subreddits.yaml` |
| Vendors & Product Blogs | vendor blogs (kept only if high-signal) | `feeds/vendors-and-product-blogs.yaml` |
| Podcasts & YouTube | audio/video sources with consistent security content | `feeds/podcasts-and-youtube.yaml` |

## Notes on “Vendors & Product Blogs”

This category exists for completeness, but the curation goal remains **signal-first**:
- prefer vulnerability advisories, hard technical posts, incident writeups
- avoid pure product marketing and repetitive announcements

## Adding a new category

If a new class of sources emerges (e.g. “AI Security Research”), add a new `feeds/<name>.yaml` file and include it in your PR with:
- a short rationale
- a few representative feeds
