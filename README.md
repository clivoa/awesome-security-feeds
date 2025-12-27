# Awesome Security Feeds

[![Feed Check](https://github.com/clivoa/awesome-security-feeds/actions/workflows/feed_check.yml/badge.svg)](https://github.com/clivoa/awesome-security-feeds/actions/workflows/feed_check.yml)
[![Export OPML](https://github.com/clivoa/awesome-security-feeds/actions/workflows/export_opml.yml/badge.svg)](https://github.com/clivoa/awesome-security-feeds/actions/workflows/export_opml.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.11%2B-brightgreen)

A **curated, structured and automation-friendly** collection of security RSS/Atom sources.

This repository is **independent** (it can be used on its own), but the generated lists are also consumed downstream by projects such as **S33R** (security news aggregation / briefings).

---

## What you get

- ✅ **Source of truth in YAML** (`feeds/*.yaml`) for easy review in PRs
- ✅ **Prebuilt JSON** for fast UIs and tooling (`data/feeds.json`, `data/feeds.min.json`)
- ✅ **OPML/XML exports** for feed readers and automation (`data/sec_feeds_*.xml`)
- ✅ **Daily feed health checks** (`data/feed_status.json`)
- ✅ Static GitHub Pages UI (`index.html`) with search & filters

---

## Repository structure

```text
.
├── feeds/                      # source of truth (YAML lists)
├── scripts/                    # validation, health check, exports
├── data/                       # generated artifacts (JSON + OPML/XML + status)
│   ├── feeds.json
│   ├── feeds.min.json
│   ├── feed_status.json
│   ├── sec_feeds_full.xml
│   └── sec_feeds_active.xml
├── index.html                  # static UI
├── CONTRIBUTING.md
└── README.md
```

---

## Categories

This repo groups feeds by **content intent** (not by vendor branding).

See: **`docs/categories.md`** for the category list, inclusion criteria, and mapping to YAML files.

---

## Local usage

### 1) Setup

```bash
python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

> Requirements are minimal: `pyyaml`, `requests`, `feedparser`.

### 2) Validate YAML (duplicates/schema)

```bash
python scripts/validate_feeds.py
```

### 3) Build the JSON artifacts used by the UI

```bash
python scripts/build_feeds_json.py
```

Outputs:
- `data/feeds.json`
- `data/feeds.min.json`
- updates `data/manifest.json` (if used by the UI)

### 4) Run the UI locally

```bash
python -m http.server 8000
```

Open: `http://localhost:8000`

### 5) Check feed health (active/down/unknown)

```bash
python scripts/check_feeds.py
```

Outputs:
- `data/feed_status.json`

### 6) Export OPML/XML

```bash
# full list
python scripts/export_opml.py --out data/sec_feeds_full.xml --title "Security Feeds (Full)" --status all

# only active feeds (based on feed_status.json)
python scripts/export_opml.py --out data/sec_feeds_active.xml --title "Security Feeds (Active only)" --status active
```

### 7) Import OPML into YAML (optional)

```bash
python scripts/import_opml.py --in path/to/file.opml
```

Useful when you have an OPML from a feed reader and want to bootstrap YAML lists.

---

## Download the generated artifacts

These are already committed/generated for convenience:

- `data/feeds.json` (readable)
- `data/feeds.min.json` (minified)
- `data/sec_feeds_full.xml` (OPML/XML export)
- `data/sec_feeds_active.xml` (active-only export)
- `data/feed_status.json` (health check results)

If you host this on GitHub, you can fetch them via raw URLs (example):
```text
https://raw.githubusercontent.com/<org>/<repo>/main/data/feeds.json
```

---

## Contribution workflow (quick)

1. Add or edit feeds in `feeds/*.yaml`
2. Run:
   ```bash
   python scripts/validate_feeds.py
   python scripts/build_feeds_json.py
   ```
3. Open a PR

Guidelines and review criteria live in `CONTRIBUTING.md`.

---

## License

MIT License (see `LICENSE.md`).
