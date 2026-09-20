# VulnRadar Roadmap

## What V1 delivered (this session)

- **Five collectors merged by priority** (ascending: nuclei_templates <
  cve_org < github_advisories < nvd < cisa_kev — see `merge_sources()`):
  - CISA KEV — confirmed-exploitation, authoritative
  - CVE.org (`cve_org`) — the speed source, ~7min cadence, live-tested
  - GitHub Security Advisories — dependency/library CVEs, schema-based
    (not live-verified in the dev sandbox — see the honesty note in
    `github_advisories.py`)
  - NVD — structured CPE version-range data, schema-based (also not
    live-verified — `services.nvd.nist.gov` unreachable from the dev
    sandbox)
  - Nuclei Templates (`nuclei_templates`) — a new public Nuclei
    detection template for a CVE means a working PoC/detection method
    already exists, often within hours of disclosure. Vendor/product is
    a tag-based heuristic guess here, weaker than the other four's
    structured data (see the file's own docstring). Schema-based, not
    live-verified (same GitHub API rate-limit issue as
    github_advisories.py hit during development).
- State/diff engine: NEW entries, and UPDATED entries (ransomware-use
  flag change specifically)
- Technology matcher: vendor/product substring matching against
  `targets/*.yaml`
- Prioritized `hunter_queue.md` renderer
- Scheduled GitHub Actions workflow (every 15 minutes) that commits
  state back, PLUS a **workflow_dispatch UI** (Actions tab → Run
  workflow) to type in a one-off target domain + technologies without
  editing any YAML, with an option to save it as a permanent target
- 46 tests, including against real fixture data captured from live
  fetches of CISA KEV and the actual MITRE cvelistV5 feed (real schema, not invented)

## Deferred, in priority order

### Priority 1 — makes existing matches trustworthy, not just present

1. **Wire NVD's already-captured version data into the matcher.** The
   data is no longer missing — `nvd.py` already extracts
   `versionStartIncluding`/`versionEndExcluding`/etc. into each
   entry's `cpe_version_range` field. What's NOT done: a target
   declaring its actual deployed version in `targets/*.yaml` (a new
   optional `version:` field per technology), and
   `technology_matcher.py` comparing that version against the range
   before flagging a match — right now a name match alone is still the
   whole signal, same as before this session's NVD collector was
   added. This is now a smaller, more precise task than it was: parse
   + compare, not "find a version-range data source" (that part is
   done).
2. **Verify `nvd.py` and `github_advisories.py` against real live
   output.** Both were built against each service's documented schema
   but never fetched live during development (sandbox network
   restrictions — see each file's own docstring). Check the first real
   CI run's logs for either printing an unexpected error before relying
   on them the way `cisa_kev.py`/`cve_org.py` (both live-tested) are
   trusted.

### Priority 2 — broadens coverage, straightforward given V1's architecture

3. **Multiple target files at scale** — V1 already loads every
   `*.yaml` in `targets/`, so this is more a matter of actually adding
   more target files than new code, once there's more than one real
   target to track.

### Priority 3 — real value, larger scope, needs product decisions first

5. **Exploit Intelligence layer** (PoC/advisory references, confidence
   scoring) — matters much more once NVD is a source (KEV entries are
   already-confirmed-exploited by definition, so this layer adds less
   value there). Needs a decision on which reference sources count
   toward confidence before any code.
6. **Detection orchestration (Nuclei adapter)** — actually attempting
   to verify a candidate against a live target. This is a significant
   scope and safety decision (active scanning against real
   infrastructure) that shouldn't be added casually — confirm the
   authorization/scope model first, mirroring BugBountyCI's own
   safety rules (`docs/V2_ROADMAP.md` in that repo) rather than
   re-deriving them independently.

### Priority 4 — defer until there's a second project actually needing it

7. **Shared `security-intelligence-core` package** with BugBountyCI
   (technology detection, evidence schema, signal classification,
   reporting patterns). The original brief suggested this, but
   extracting a shared package before there's a second concrete
   consumer risks over-engineering an abstraction around assumptions
   that don't hold once actually needed. Revisit once VulnRadar's
   `technology_matcher.py` and BugBountyCI's `target_profile.py`
   have both matured independently and the overlap is obvious in
   practice, not just in the original design brief.

## Explicit non-goals (carried over from the original design brief)

- Not a CVE scanner — value is relevance + diff + correlation, not
  volume or automatic exploitation
- Never claim CONFIRMED from a name/vendor match alone
- No destructive or unauthorized testing of any kind
