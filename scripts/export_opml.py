#!/usr/bin/env python3
"""Export feeds/*.yaml into an OPML (sec_feeds.xml-like) file.

Input:  feeds/*.yaml (list of dicts with url, title, description, type, category)
Output: OPML 2.0 with category outlines + feed outlines

Optional: Promote candidate feeds from feeds/_candidates/*.yaml into the main
feeds/*.yaml files (deduped), then (optionally) remove the candidate files.

Optional: Cleanup discovery JSON state files (data/discovery/feeds_candidates.json
and data/discovery/feeds_seen.json). This is safe even when files don't exist.

Usage:
  python scripts/export_opml.py --out sec_feeds.xml
  python scripts/export_opml.py --feeds-dir feeds --out sec_feeds.xml --title "Awesome Security Feeds"

  # Promote candidates → main YAMLs (deduped) + clean up candidate bucket files
  python scripts/export_opml.py --feeds-dir feeds --promote-candidates --cleanup-candidates --out sec_feeds.xml

  # ...and optionally remove discovery JSON state files
  python scripts/export_opml.py --feeds-dir feeds --promote-candidates --cleanup-candidates --cleanup-discovery --out sec_feeds.xml
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml
try:
    from feed_utils import clean_text, load_yaml_list, normalize_url
except ModuleNotFoundError:  # pragma: no cover - supports module execution
    from scripts.feed_utils import clean_text, load_yaml_list, normalize_url


def norm_url(url: str) -> str:
    return normalize_url(
        url,
        force_https=True,
        strip_trailing_slash=True,
        drop_fragment=True,
    )


def _ordered_item(it: Dict[str, Any]) -> Dict[str, Any]:
    """Write items in a consistent key order."""
    return {
        "url": it.get("url", ""),
        "category": it.get("category", ""),
        "title": it.get("title", ""),
        "type": it.get("type", ""),
        "description": it.get("description", ""),
    }


def _load_yaml_list(path: Path) -> List[Dict[str, Any]]:
    data = load_yaml_list(path)
    out: List[Dict[str, Any]] = []
    for idx, it in enumerate(data, start=1):
        if not isinstance(it, dict):
            raise SystemExit(f"Invalid item in {path} #{idx} (expected dict)")
        url = norm_url(str(it.get("url", "")).strip())
        if not url:
            raise SystemExit(f"Missing url in {path} #{idx}")
        out.append(
            {
                "url": url,
                "title": clean_text(str(it.get("title", ""))),
                "description": clean_text(str(it.get("description", ""))),
                "type": clean_text(str(it.get("type", ""))).lower(),
                "category": clean_text(str(it.get("category", ""))) or "Uncategorized",
            }
        )
    return out


def load_yaml_feeds(feeds_dir: Path) -> List[Dict[str, Any]]:
    """Load feed items from feeds_dir/*.yaml (excluding feeds/_candidates)."""
    items: List[Dict[str, Any]] = []
    for p in sorted(feeds_dir.glob("*.yaml")):
        items.extend(_load_yaml_list(p))
    return items


def load_candidate_files(feeds_dir: Path) -> List[Path]:
    cand_dir = feeds_dir / "_candidates"
    if not cand_dir.exists() or not cand_dir.is_dir():
        return []
    return sorted(cand_dir.glob("*.yaml"))


def promote_candidates(feeds_dir: Path, cleanup: bool = False) -> Tuple[int, int]:
    """Promote candidates from feeds/_candidates/*.yaml into feeds/*.yaml.

    - Dedupes by normalized URL (global dedupe across ALL main YAMLs)
    - Writes updated/created bucket files in feeds/*.yaml (bucket filename matches)
    - If cleanup=True, deletes processed candidate bucket files

    Returns: (added_count, removed_candidate_files_count)
    """
    cand_files = load_candidate_files(feeds_dir)
    if not cand_files:
        return (0, 0)

    # Load ALL main feeds and build a global seen set.
    main_files = sorted(feeds_dir.glob("*.yaml"))
    main_by_file: Dict[Path, List[Dict[str, Any]]] = {}
    seen: set[str] = set()

    for p in main_files:
        items = _load_yaml_list(p)
        main_by_file[p] = items
        for it in items:
            seen.add(norm_url(it["url"]))

    added = 0

    for cand_path in cand_files:
        cand_items = _load_yaml_list(cand_path)

        target_path = feeds_dir / cand_path.name  # same bucket name
        target_items = main_by_file.get(target_path)
        if target_items is None:
            target_items = []
            main_by_file[target_path] = target_items

        for it in cand_items:
            u = norm_url(it["url"])
            if u in seen:
                continue
            seen.add(u)
            target_items.append(it)
            added += 1

    # Write updated main YAMLs (including newly created ones).
    for path, items in sorted(main_by_file.items(), key=lambda kv: kv[0].name):
        items_sorted = sorted(
            (_ordered_item(it) for it in items),
            key=lambda d: (
                (d.get("category") or "").lower(),
                (d.get("title") or "").lower(),
                (d.get("url") or "").lower(),
            ),
        )
        path.write_text(
            yaml.safe_dump(items_sorted, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )

    removed = 0
    if cleanup:
        for cand_path in cand_files:
            try:
                cand_path.unlink()
                removed += 1
            except Exception:
                pass
        # remove folder if empty
        cand_dir = feeds_dir / "_candidates"
        try:
            if cand_dir.exists() and not any(cand_dir.iterdir()):
                cand_dir.rmdir()
        except Exception:
            pass

    return (added, removed)


def dedupe_by_url(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set[str] = set()
    out: List[Dict[str, Any]] = []
    for it in items:
        u = norm_url(it.get("url", ""))
        if not u or u in seen:
            continue
        seen.add(u)
        it2 = dict(it)
        it2["url"] = u
        out.append(it2)
    return out


def group_by_category(items: List[Dict[str, Any]]) -> List[Tuple[str, List[Dict[str, Any]]]]:
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for it in items:
        cat = clean_text(str(it.get("category", ""))) or "Uncategorized"
        groups[cat].append(it)

    grouped: List[Tuple[str, List[Dict[str, Any]]]] = []
    for cat in sorted(groups.keys(), key=lambda s: s.lower()):
        feeds = sorted(groups[cat], key=lambda d: (d.get("title") or "").lower())
        grouped.append((cat, feeds))
    return grouped


def load_active_urls(status_path: Path) -> set[str]:
    """Load active feed URLs from data/feed_status.json."""
    if not status_path.exists():
        return set()
    try:
        data = json.loads(status_path.read_text(encoding="utf-8"))
    except Exception:
        return set()
    results = data.get("results") or {}
    active: set[str] = set()
    if isinstance(results, dict):
        for url, info in results.items():
            try:
                if isinstance(info, dict) and (info.get("status") == "active"):
                    active.add(norm_url(str(url)))
            except Exception:
                pass
    return active


def opml_outline_feed(it: Dict[str, Any]) -> str:
    title = clean_text(it.get("title") or it.get("url") or "")
    xml_url = it.get("url") or ""
    html_url = it.get("url") or ""
    ftype = clean_text(it.get("type") or "rss")
    desc = clean_text(it.get("description") or "")

    def esc(x: str) -> str:
        return (
            x.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    attrs = {
        "text": title,
        "title": title,
        "type": ftype,
        "xmlUrl": xml_url,
        "htmlUrl": html_url,
    }
    if desc:
        attrs["description"] = desc

    return "<outline " + " ".join(f"{k}=\"{esc(v)}\"" for k, v in attrs.items() if v) + " />"


def build_opml(title: str, grouped: List[Tuple[str, List[Dict[str, Any]]]]) -> str:
    def esc(x: str) -> str:
        return (
            (x or "")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    lines: List[str] = []
    lines.append('<?xml version="1.0" encoding="UTF-8"?>')
    lines.append('<opml version="2.0">')
    lines.append("  <head>")
    lines.append(f"    <title>{esc(title)}</title>")
    lines.append("  </head>")
    lines.append("  <body>")

    for cat, feeds in grouped:
        lines.append(f"    <outline text=\"{esc(cat)}\" title=\"{esc(cat)}\">")
        for it in feeds:
            lines.append("      " + opml_outline_feed(it))
        lines.append("    </outline>")

    lines.append("  </body>")
    lines.append("</opml>")
    return "\n".join(lines) + "\n"


DISCOVERY_FILES = [
    Path("data/discovery/feeds_candidates.json"),
    Path("data/discovery/feeds_seen.json"),
]


def cleanup_discovery_files() -> int:
    removed = 0
    for path in DISCOVERY_FILES:
        try:
            if path.exists():
                path.unlink()
                removed += 1
                print(f"[CLEANUP] Removed {path}")
        except Exception:
            pass
    return removed


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--feeds-dir", default="feeds", help="Directory containing feeds/*.yaml")
    ap.add_argument("--out", default="sec_feeds.xml", help="Output OPML file path")
    ap.add_argument("--title", default="Awesome Security Feeds", help="OPML title")
    ap.add_argument(
        "--status",
        choices=["all", "active"],
        default="all",
        help="Export all feeds or only active feeds (from data/feed_status.json)",
    )
    ap.add_argument(
        "--promote-candidates",
        action="store_true",
        help="Merge feeds/_candidates/*.yaml into feeds/*.yaml (deduped)",
    )
    ap.add_argument(
        "--cleanup-candidates",
        action="store_true",
        help="When used with --promote-candidates, delete processed candidate bucket files",
    )
    ap.add_argument(
        "--cleanup-discovery",
        action="store_true",
        help="Remove discovery artifacts after promotion (feeds_candidates.json, feeds_seen.json)",
    )

    args = ap.parse_args()

    feeds_dir = Path(args.feeds_dir)

    if args.cleanup_candidates and not args.promote_candidates:
        raise SystemExit("--cleanup-candidates requires --promote-candidates")

    if args.promote_candidates:
        added, removed = promote_candidates(feeds_dir, cleanup=args.cleanup_candidates)
        print(f"[OK] Promoted {added} candidate feed(s) into feeds/*.yaml (removed candidate files: {removed})")

        if args.cleanup_discovery:
            removed_json = cleanup_discovery_files()
            if removed_json:
                print(f"[OK] Removed {removed_json} discovery JSON file(s)")

    items = load_yaml_feeds(feeds_dir)
    items = dedupe_by_url(items)

    if args.status == "active":
        active_urls = load_active_urls(Path("data") / "feed_status.json")
        if not active_urls:
            print("[WARN] args.status=active but no active URLs found (missing/empty feed_status.json) — exporting 0 feeds")
        items = [it for it in items if it.get("url") in active_urls]

    grouped = group_by_category(items)
    opml = build_opml(args.title, grouped)
    Path(args.out).write_text(opml, encoding="utf-8")

    total = sum(len(fs) for _, fs in grouped)
    print(f"[OK] Wrote {args.out} with {len(grouped)} categories and {total} feeds (deduped)")


if __name__ == "__main__":
    main()
