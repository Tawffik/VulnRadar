# VulnRadar Roadmap

## What V1 delivered (this session)

- CISA KEV collector, normalized to an internal schema
- **CVE.org (`cve_org`) collector — the speed source**, polling
  MITRE's official `cvelistV5` delta feed (~7min cadence), merged with
  KEV via `merge_sources()` (KEV wins on conflict, both sources tagged)
- State/diff engine: NEW entries, and UPDATED entries (ransomware-use
  flag change specifically — the one field change actually worth
  re-flagging)
- Technology matcher: vendor/product substring matching against
  `targets/*.yaml`
- Prioritized `hunter_queue.md` renderer (matched+ransomware > matched
  > ransomware-only-unmatched; everything else summarized but not
  individually listed)
- Scheduled GitHub Actions workflow (every 15 minutes, matching
  cve_org's own update cadence) that commits state back
- 26 tests, including against real fixture data captured from a live
  fetch of both CISA KEV and the actual MITRE cvelistV5 feed (real schema, not invented)

## Deferred, in priority order

### Priority 1 — makes existing matches trustworthy, not just present

1. **Version Intelligence.** Right now a vendor/product name match is
   the whole signal — no version-range checking at all. This is the
   single most valuable next step: parse the affected version range
   (CISA's KEV entries don't always include this cleanly — may need to
   cross-reference the CVE's NVD record for CPE/version data) and
   compare against a version the target declares in `targets/*.yaml`,
   downgrading a match to "POSSIBLY AFFECTED" only within range, not
   just same product.
2. **NVD as a version-data source (not a speed source anymore — cve_org
   already covers that).** Needed specifically for version intelligence
   above: NVD's CPE data has structured version ranges neither KEV nor
   cve.org's own records reliably include. Requires an NVD API key for
   reasonable rate limits; keep it a third collector, not a replacement
   for either existing one.

### Priority 2 — broadens coverage, straightforward given V1's architecture

3. **GitHub Security Advisories collector** — useful for
   dependency/library-level CVEs KEV/NVD often lag on, especially for
   anything in a target's actual dependency tree (would need a
   target's `package.json`/`requirements.txt`/etc as an additional
   input, not just a vendor/product name).
4. **Multiple target files at scale** — V1 already loads every
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
