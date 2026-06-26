"""Content hashes for HTML responses — Shodan-style MMH3 signed 32-bit ints.

Computes favicon-compatible hashes for the HTML body, a normalized DOM
(scripts/styles/comments stripped, whitespace collapsed), and the page title.
Used by the fingerprinter to attach `html_hash`, `dom_hash`, and `title_hash`
to each `Fingerprint` for cross-target correlation.
"""
import re
from typing import Optional, Tuple

import mmh3

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_SCRIPT_RE = re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)
_STYLE_RE = re.compile(r"<style[^>]*>.*?</style>", re.IGNORECASE | re.DOTALL)
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_WS_RE = re.compile(r"\s+")


def extract_title(html: str) -> Optional[str]:
    m = _TITLE_RE.search(html)
    if not m:
        return None
    title = _WS_RE.sub(" ", m.group(1)).strip()
    return title or None


def normalize_dom(html: str) -> str:
    s = _SCRIPT_RE.sub("", html)
    s = _STYLE_RE.sub("", s)
    s = _COMMENT_RE.sub("", s)
    s = _WS_RE.sub(" ", s)
    return s.strip()


def compute_html_hashes(
    html: Optional[str],
) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    """Returns (html_hash, dom_hash, title_hash). Slots are None when the
    corresponding bytes are unavailable. Never raises."""
    if not html:
        return None, None, None

    raw = html.encode("utf-8", errors="replace")
    html_h = mmh3.hash(raw)

    dom = normalize_dom(html)
    dom_h = mmh3.hash(dom.encode("utf-8", errors="replace")) if dom else None

    title = extract_title(html)
    title_h = mmh3.hash(title.encode("utf-8", errors="replace")) if title else None

    return html_h, dom_h, title_h
