# Awesome Security Feeds

[![Build feeds JSON](https://github.com/clivoa/awesome-security-feeds/actions/workflows/build_feeds_json.yml/badge.svg)](https://github.com/clivoa/awesome-security-feeds/actions/workflows/build_feeds_json.yml)
[![Feed Check](https://github.com/clivoa/awesome-security-feeds/actions/workflows/feed_check.yml/badge.svg)](https://github.com/clivoa/awesome-security-feeds/actions/workflows/feed_check.yml)
[![Export OPML](https://github.com/clivoa/awesome-security-feeds/actions/workflows/export_opml.yml/badge.svg)](https://github.com/clivoa/awesome-security-feeds/actions/workflows/export_opml.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE.md)

A **curated, structured and automation-friendly** collection of security RSS/Atom sources.

This repository is **independent** (it can be used on its own). Based on https://securityfeeds.org/
The generated artifacts are also consumed downstream by projects such as [**S33R**](https://github.com/clivoa/S33R/) (security news aggregation / briefings).

---

## Quick links

- **Full feed list (Awesome page):** `docs/awesome-feeds.md`
- **Architecture & CI flow:** `docs/architecture.md`
- **Docs index:** `docs/README.md`
- **Categories & criteria:** `docs/categories.md`

---

## What you get

- ✅ **Source of truth in YAML** (`feeds/*.yaml`) for easy review in PRs  
- ✅ **Prebuilt JSON** for fast UIs and tooling (`data/feeds.json`, `data/feeds.min.json`)  
- ✅ **OPML/XML exports** for feed readers (`data/sec_feeds_full.xml`, `data/sec_feeds_active.xml`)  
- ✅ **Feed health checks** (`data/feed_status.json`)  
- ✅ Static UI (`index.html`) with search & filters

---

## Repository structure

```text
.
├── feeds/                      # source of truth (YAML lists)
├── scripts/                    # validation, health check, exports
├── data/                       # generated artifacts (JSON + OPML/XML + status)
├── docs/                       # documentation (architecture, categories, full list)
├── index.html                  # static UI
└── README.md
```

---

## Consume the artifacts

If you host this repository on GitHub, you can fetch artifacts via raw URLs:

```text
https://raw.githubusercontent.com/clivoa/awesome-security-feeds/main/data/feeds.json
https://raw.githubusercontent.com/clivoa/awesome-security-feeds/main/data/feeds.min.json
https://raw.githubusercontent.com/clivoa/awesome-security-feeds/main/data/sec_feeds_full.xml
https://raw.githubusercontent.com/clivoa/awesome-security-feeds/main/data/sec_feeds_active.xml
https://raw.githubusercontent.com/clivoa/awesome-security-feeds/main/data/feed_status.json
```

---

## Local usage

### 1) Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2) Validate YAML (duplicates/schema)

```bash
python scripts/validate_feeds.py
```

### 3) Build JSON artifacts (used by `index.html`)

```bash
python scripts/build_feeds_json.py
```

Outputs:
- `data/feeds.json`
- `data/feeds.min.json`
- `data/manifest.json`

### 4) Run the UI locally

```bash
python -m http.server 8000
```

Open: `http://localhost:8000`

### 5) Check feed health

```bash
python scripts/check_feeds.py
```

Outputs:
- `data/feed_status.json`

### 6) Export OPML/XML

```bash
python scripts/export_opml.py --out data/sec_feeds_full.xml --title "Security Feeds (Full)" --status all
python scripts/export_opml.py --out data/sec_feeds_active.xml --title "Security Feeds (Active only)" --status active
```

### 7) (Optional) Generate the full “Awesome” table page

```bash
python scripts/build_awesome_page.py --out docs/awesome-feeds.md
```

---

## Contributing

1. Add or edit feeds in `feeds/*.yaml`
2. Run locally:
   ```bash
   python scripts/validate_feeds.py
   python scripts/build_feeds_json.py
   python scripts/build_awesome_page.py --out docs/awesome-feeds.md
   ```
3. Open a PR

Guidelines: `CONTRIBUTING.md`

---

## License

MIT License (see `LICENSE.md`).
