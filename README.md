# securityfeeds

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

## Feed health status

A daily GitHub Action runs `scripts/check_feeds.py` and writes `data/feed_status.json`.
The UI shows a status badge per feed (active/down/unknown) and allows filtering "down only".
