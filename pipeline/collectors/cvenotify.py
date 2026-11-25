#!/usr/bin/env python3
"""
pipeline/collectors/cvenotify.py

Collects from the cveNotify Telegram channel's PUBLIC web preview
(https://t.me/s/cveNotify) — a high-speed community CVE alert channel
(owner-requested source, mapped to VulnRadar as its correct project
fit). Each post is one CVE alert: CVE id + short description + an
advisory/vendor link. This collector is read-only: no account, no
join, no posting, no Telegram API — just the same public page any
browser can open, fetched manually or in the existing daily run.

Role in the merge: a LOW-priority speed/community signal. It carries
no structured vendor/product/CPE data, so it is merged at the bottom
of the priority ladder (below nuclei_templates) — it can add a CVE
sighting early, but must never override any structured source's
fields. Every sighting still records 'cvenotify' in 'sources'.

Provenance: every entry carries the real post date ('date_added') and
the exact post URL + first advisory link in 'references'. Post text
is DATA ONLY — control characters are stripped and text is capped,
never interpreted, executed, or followed as instructions.

Failure contract (same as every other collector): fetch_normalized
returns (entries, error) — entries is [] on failure (never None) and
error is a short string, so one failing source never stops the run.
A structurally valid page with zero CVE posts is NOT an error (a
promo-only day is valid data); a page whose widget markup is gone IS
an error ("feed format may have changed").
"""
import html as html_lib
import re
import urllib.error
import urllib.request

from pipeline.collectors import http_utils
from pipeline.recon.user_agents import random_ua

CVENOTIFY_URL = "https://t.me/s/cveNotify"

MAX_TEXT_LEN = 400
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_CVE_RE = re.compile(r"CVE-20\d\d-\d{4,}")
_WIDGET_RE = re.compile(
    r'<div class="tgme_widget_message_wrap.*?(?=<div class="tgme_widget_message_wrap|$)',
    re.S,
)
_TAG_RE = re.compile(r"<[^>]+>")
_URL_RE = re.compile(r"https?://[^\s<>\"']+")


def _clean_text(raw: str) -> str:
    """Post text is data-only: strip markup, entities, control chars,
    collapse whitespace, cap length. Never interpreted."""
    text = _TAG_RE.sub(" ", raw)
    text = html_lib.unescape(text)
    text = _CONTROL_CHARS.sub("", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:MAX_TEXT_LEN]


def parse_posts(page_html: str) -> list:
    """Parses the public preview HTML into raw post dicts:
    {post_url, date, cve_ids, text, links}. Only posts carrying at
    least one CVE id survive; everything else is skipped."""
    posts = []
    for block in _WIDGET_RE.findall(page_html):
        cve_ids = sorted(set(_CVE_RE.findall(block)))
        if not cve_ids:
            continue
        post_match = re.search(r'data-post="([^"]+)"', block)
        date_match = re.search(r'datetime="([^"]+)"', block)
        text_match = re.search(
            r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>',
            block, re.S,
        )
        raw_text = text_match.group(1) if text_match else ""
        text = _clean_text(raw_text)
        # Advisory links live inside the message text (the CVE id itself
        # is an <a href> to the advisory). Links elsewhere in the block
        # (media CDN, channel avatar) are NOT advisories.
        links = re.findall(r'href="([^"]+)"', raw_text)
        links += _URL_RE.findall(html_lib.unescape(raw_text))
        advisory = next((u for u in links if "t.me" not in u), "")
        posts.append({
            "post_url": f"https://t.me/{post_match.group(1)}" if post_match else "",
            "date": date_match.group(1) if date_match else "",
            "cve_ids": cve_ids,
            "text": text,
            "advisory_url": advisory,
        })
    return posts


def normalize_post(post: dict) -> list:
    """One post -> one normalized entry PER CVE id (the internal
    schema, matching the other collectors)."""
    entries = []
    for cve in post["cve_ids"]:
        references = [u for u in (post["advisory_url"], post["post_url"]) if u]
        entries.append({
            "cve": cve,
            "vendor": "",
            "product": "",
            "name": f"{cve} (cveNotify alert)",
            "description": post["text"],
            "date_added": post["date"],
            "references": references,
            "source": "cvenotify",
        })
    return entries


def normalize_page(page_html: str) -> list:
    """Whole page -> entries, deduped by CVE id (first post wins —
    posts are newest-first on the preview page)."""
    seen, entries = set(), []
    for post in parse_posts(page_html):
        for entry in normalize_post(post):
            if entry["cve"] not in seen:
                seen.add(entry["cve"])
                entries.append(entry)
    return entries


def fetch_normalized(url: str = CVENOTIFY_URL, timeout: int = 20, _html: str = None):
    """Returns (entries, error). _html injects page content for tests
    so they never touch the network."""
    if _html is None:
        req = urllib.request.Request(url, headers={"User-Agent": random_ua()})
        try:
            body = http_utils.request_with_retry(req, timeout=timeout)
            _html = body.decode("utf-8", errors="replace")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
            return [], f"fetch failed: {e}"
    if "tgme_widget_message" not in _html:
        return [], "preview page had no message widgets — feed format may have changed"
    return normalize_page(_html), None


def load_from_file(path: str):
    """Same normalization from a local HTML file (tests / reprocessing
    a snapshot without another network hit)."""
    with open(path, "r", encoding="utf-8") as f:
        return normalize_page(f.read())


if __name__ == "__main__":
    entries, error = fetch_normalized()
    if error:
        print(f"⚠️ {error}")
    else:
        print(f"✅ fetched {len(entries)} CVE alerts from cveNotify")
