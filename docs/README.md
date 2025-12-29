# Documentation

Welcome to the documentation for **Awesome Security Feeds**.

## Start here

- **Architecture & data flow:** `architecture.md`
- **Categories & inclusion criteria:** `categories.md`
- **Full feed list (Awesome page):** `awesome-feeds.md`

## Scripts

These scripts live under `scripts/` and are used by CI and local workflows:

- `validate_feeds.py` — schema checks and duplicate detection
- `build_feeds_json.py` — builds `data/feeds.json`, `data/feeds.min.json`, `data/manifest.json`
- `check_feeds.py` — produces `data/feed_status.json`
- `export_opml.py` — exports OPML/XML lists (`data/sec_feeds_*.xml`)
- `import_opml.py` — converts OPML to YAML entries
- `discover_security_feeds.py` — feed discovery (creates candidates for review)
- `build_awesome_page.py` — generates `docs/awesome-feeds.md` from YAML

## GitHub Actions

Workflows live under `.github/workflows/`:

- `validate.yml` — run on PRs; blocks invalid feed changes
- `build_feeds_json.yml` — run on main; regenerates JSON artifacts
- `feed_check.yml` — run on schedule/main; checks feed health
- `export_opml.yml` — run on main; regenerates OPML/XML exports
- `discover_security_feeds.yml` — scheduled discovery; opens PRs with `_candidates/` (if enabled)
- `build_awesome_page.yml` — (proposed) keeps docs feed table in sync

