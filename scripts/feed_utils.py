#!/usr/bin/env python3
"""Shared helpers for feed-related scripts."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import yaml

RE_WS = re.compile(r"\s+")


def clean_text(value: str) -> str:
    """Trim and collapse whitespace."""
    return RE_WS.sub(" ", (value or "").strip()).strip()


def normalize_url(
    url: str,
    *,
    default_scheme: str = "http",
    drop_fragment: bool = True,
    force_https: bool = False,
    strip_trailing_slash: bool = False,
) -> str:
    """Normalize feed URLs for comparisons and output stability."""
    url = (url or "").strip()
    if not url:
        return url

    parsed = urlparse(url)
    scheme = (parsed.scheme or default_scheme).lower()
    if force_https and scheme == "http":
        scheme = "https"

    netloc = (parsed.netloc or "").lower()
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    if netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]

    path = parsed.path or ""
    if strip_trailing_slash and path.endswith("/"):
        path = path.rstrip("/")

    fragment = "" if drop_fragment else (parsed.fragment or "")
    return urlunparse((scheme, netloc, path, "", parsed.query or "", fragment))


def slugify(text: str, *, fallback: str = "", ampersand_to_and: bool = False) -> str:
    """Create a stable ASCII slug from arbitrary text."""
    value = (text or "").strip().lower()
    if ampersand_to_and:
        value = value.replace("&", " and ")
    value = re.sub(r"[^a-z0-9\s-]+", "-", value)
    value = re.sub(r"[\s-]+", "-", value).strip("-")
    return value or fallback


def load_yaml_list(path: Path) -> list[Any]:
    """Load a YAML file that must contain a list (or be empty)."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data is None:
        return []
    if not isinstance(data, list):
        raise SystemExit(f"Invalid YAML in {path} (expected list)")
    return data
