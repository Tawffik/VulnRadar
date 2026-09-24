#!/usr/bin/env python3
"""
pipeline/collectors/nuclei_templates.py

Monitors https://github.com/projectdiscovery/nuclei-templates for newly
ADDED templates under http/cves/<year>/CVE-<year>-<id>.yaml. This is a
different kind of signal than the other three collectors: a new Nuclei
template for a CVE means the security community has already built a
working, automatable detection/PoC for it — often within hours of
public disclosure, sometimes before NVD has even scored it. It's a
strong "this is real and exploitable enough that someone already
automated checking for it" signal, layered on top of whatever the
other sources already know about the CVE.

Vendor/product for this source is a best-effort heuristic, NOT as
reliable as the other three collectors: it's derived from the
template's own `tags` field (e.g. "cve,wordpress,rce" -> vendor
guessed as "wordpress"), since nuclei-templates' YAML files don't
carry a structured vendor/product field the way CVE records do. This
is documented here so it's never mistaken for the same confidence
level as cisa_kev.py/cve_org.py's proper vendor/product extraction.

HONESTY NOTE (same as nvd.py/github_advisories.py): built against
GitHub's documented Commits API schema, not verified against a live
fetch during development — the dev sandbox's shared IP was rate-limited
against api.github.com at build time (the same issue github_advisories.py
hit). Verify the first real CI run's output (which will have a proper
GITHUB_TOKEN and a much higher rate limit) before trusting this the way
the two live-tested collectors are trusted.
"""
import json
import os
import re
import urllib.request
import urllib.error

from pipeline.collectors import http_utils

REPO = "projectdiscovery/nuclei-templates"
CVE_TEMPLATE_RE = re.compile(r"http/cves/\d{4}/(CVE-\d{4}-\d+)\.ya?ml$", re.IGNORECASE)

GENERIC_TAGS = {"cve", "rce", "lfi", "xss", "sqli", "ssrf", "xxe", "ssti",
                 "vuln", "kev", "intrusive", "packetstorm", "misconfig", "exposure",
                 "unauth", "unauthenticated", "auth-bypass", "authbypass", "bypass",
                 "info-leak", "disclosure", "generic", "network", "dos"}
GENERIC_TAG_RE = re.compile(r"^cve\d{0,4}$")  # matches "cve", "cve2024", "cve24", etc.


def _fetch_json(url: str, token: str = None, timeout: int = 20):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "VulnRadar/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    body = http_utils.request_with_retry(req, timeout=timeout)
    return json.loads(body.decode("utf-8"))


def _fetch_text(url: str, timeout: int = 20):
    req = urllib.request.Request(url, headers={"User-Agent": "VulnRadar/1.0"})
    body = http_utils.request_with_retry(req, timeout=timeout)
    return body.decode("utf-8", errors="ignore")


def _guess_vendor_from_tags(tags_line: str) -> str:
    tags = [t.strip().lower() for t in (tags_line or "").split(",") if t.strip()]
    for t in tags:
        if t in GENERIC_TAGS or GENERIC_TAG_RE.match(t):
            continue
        return t
    return "unknown"


def _parse_template_yaml(text: str) -> dict:
    """Deliberately NOT a full YAML parse (nuclei templates have complex
    nested matchers/extractors that a generic YAML library sometimes
    trips on) — just pulls the small 'info:' block's name/tags with a
    tolerant line-based scan, which is all this collector needs."""
    name, tags = "", ""
    in_info = False
    for line in text.splitlines():
        if line.strip() == "info:":
            in_info = True
            continue
        if in_info:
            if line.startswith("  name:"):
                name = line.split(":", 1)[1].strip().strip('"').strip("'")
            elif line.startswith("  tags:"):
                tags = line.split(":", 1)[1].strip().strip('"').strip("'")
            elif line and not line.startswith(" "):
                break  # left the info: block
    return {"name": name, "tags": tags}


def fetch_normalized(repo: str = REPO, token: str = None, timeout: int = 20,
                      _commits_loader=None, _commit_detail_loader=None, _template_loader=None):
    """_commits_loader/_commit_detail_loader/_template_loader are
    injectable for tests, same pattern as the other three collectors.

    Two-step API call, because GitHub's commit LIST endpoint does not
    include per-commit file changes — only the single-commit detail
    endpoint (/commits/{sha}) does. Fetching detail for every commit
    costs one extra API call each, acceptable at this project's polling
    volume (typically a handful of commits touching http/cves/ per
    15-minute window) well within the 5000/hr authenticated limit."""
    token = token or os.environ.get("GITHUB_TOKEN")
    commits_loader = _commits_loader or (
        lambda: _fetch_json(f"https://api.github.com/repos/{repo}/commits?path=http/cves&per_page=30", token, timeout))
    commit_detail_loader = _commit_detail_loader or (
        lambda sha: _fetch_json(f"https://api.github.com/repos/{repo}/commits/{sha}", token, timeout))
    template_loader = _template_loader or (lambda url: _fetch_text(url, timeout))

    try:
        commit_list = commits_loader()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        return [], f"nuclei-templates commits fetch failed: {e}"
    except json.JSONDecodeError as e:
        return [], f"response was not valid JSON: {e}"

    if isinstance(commit_list, dict) and commit_list.get("message"):
        return [], f"GitHub API error: {commit_list['message']}"

    seen_cves = set()
    entries = []
    detail_errors = 0
    for commit_stub in commit_list:
        sha = commit_stub.get("sha")
        if not sha:
            continue
        try:
            commit = commit_detail_loader(sha)
        except Exception:
            detail_errors += 1
            continue  # one bad commit-detail fetch must not stop the rest

        for f in commit.get("files", []) or []:
            if f.get("status") != "added":
                continue
            m = CVE_TEMPLATE_RE.search(f.get("filename", ""))
            if not m:
                continue
            cve_id = m.group(1).upper()
            if cve_id in seen_cves:
                continue  # a CVE's template rarely changes filename twice in one poll window
            seen_cves.add(cve_id)

            raw_url = f.get("raw_url") or (
                f"https://raw.githubusercontent.com/{repo}/main/{f['filename']}")
            try:
                text = template_loader(raw_url)
                parsed = _parse_template_yaml(text)
            except Exception:
                parsed = {"name": "", "tags": ""}

            entries.append({
                "cve": cve_id,
                "vendor": _guess_vendor_from_tags(parsed["tags"]),
                "product": "nuclei-template",
                "name": parsed["name"] or f"Nuclei template for {cve_id}",
                "date_added": commit.get("commit", {}).get("author", {}).get("date", ""),
                "due_date": "",
                "description": f"A Nuclei detection template now exists for {cve_id} "
                                f"({parsed['tags'] or 'no tags'}) — a working, automatable "
                                f"PoC/detection method is publicly available.",
                "required_action": "",
                "ransomware_use": "Unknown",
                "cwes": [],
                "cvss_score": None,
                "cvss_severity": None,
                "source": "nuclei_templates",
                "template_url": raw_url,
            })

    if detail_errors:
        print(f"⚠️ {detail_errors} of {len(commit_list)} commit-detail fetch(es) failed (skipped, not fatal)")

    return entries, None


if __name__ == "__main__":
    entries, error = fetch_normalized()
    if error:
        print(f"⚠️ {error}")
    else:
        print(f"✅ fetched {len(entries)} new Nuclei CVE templates")
