# awesome security feeds

[![Feed Check](https://github.com/clivoa/awesome-security-feeds/actions/workflows/feed_check.yml/badge.svg)](https://github.com/clivoa/awesome-security-feeds/actions/workflows/feed_check.yml)
[![Export OPML](https://github.com/clivoa/awesome-security-feeds/actions/workflows/export_opml.yml/badge.svg)](https://github.com/clivoa/awesome-security-feeds/actions/workflows/export_opml.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.11%2B-brightgreen)

Static GitHub Pages site that lists security RSS/Atom feeds with fast search & filters.

## Design

- **Source of truth**: `feeds/*.yaml` (easy PR review)
- **PR validation**: `.github/workflows/validate.yml` (schema/duplicates)
- **Build & deploy**: `.github/workflows/pages.yml` (generates `data/feeds.json` then deploys Pages)

## Local run

```bash
python -m pip install pyyaml
python scripts/build_feeds_json.py
python -m http.server 8000
```

python scripts/export_opml.py --out data/sec_feeds_full.xml --title "Security Feeds (Full)" --status all


python scripts/export_opml.py --out data/sec_feeds_active.xml --title "Security Feeds (Active only)" --status active


## Feed health status

A daily GitHub Action runs `scripts/check_feeds.py` and writes `data/feed_status.json`.
The UI shows a status badge per feed (active/down/unknown) and allows filtering "down only".
