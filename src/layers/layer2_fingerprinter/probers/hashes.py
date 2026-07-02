"""Content hashes for HTTP responses — Shodan-style MMH3 signed 32-bit ints.

Computes favicon-compatible hashes for the HTML body and the page title.
Attached to each Fingerprint for cross-target correlation.

Hash conventions:
  - html_hash:   mmh3 over the raw HTML bytes — matches Shodan's http.html_hash
                 (~96% on real data; HTTPS-port poisoning and server-side drift
                 account for the remainder).
  - title_hash:  mmh3 over the RAW bytes between <title> and </title>, no
                 whitespace collapse. Matches Shodan's http.title_hash 100%
                 on records where the title tag exists. Empty/missing title
                 yields hash 0 — same convention as Shodan (mmh3 of b"" is 0).
"""
import re
from typing import Optional, Tuple

import mmh3

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def extract_title(html: str) -> str:
    """Raw bytes between <title> tags. Empty string when no title or empty title.

    Always returns a string — caller hashes it, getting 0 for empty input
    (mmh3 of empty bytes is 0), matching Shodan's title_hash==0 convention.
    """
    if not html:
        return ""
    m = _TITLE_RE.search(html)
    if not m:
        return ""
    return m.group(1) or ""


def compute_html_hashes(html: Optional[str]) -> Tuple[Optional[int], Optional[int]]:
    """Returns (html_hash, title_hash).

    html_hash is None only when html is None/empty (no body fetched).
    title_hash is always an int when html is non-None — 0 for empty/missing
    title, matching Shodan's convention. Never raises."""
    if not html:
        return None, None

    html_h = mmh3.hash(html.encode("utf-8", errors="replace"))

    title = extract_title(html)
    title_h = mmh3.hash(title.encode("utf-8", errors="replace"))

    return html_h, title_h
