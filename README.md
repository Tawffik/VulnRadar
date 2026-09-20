# VulnRadar

CVE Intelligence + Target Correlation, not a CVE scanner.

VulnRadar tracks **four CVE sources together**, merged by priority
(highest wins on conflict, all contributing sources still recorded):

| Source | Role | Speed |
|---|---|---|
| **[CVE.org](https://www.cve.org/) (`cve_org`)** | Speed source | ~7min cadence — often hours/days ahead of KEV |
| **GitHub Security Advisories (`github_advisories`)** | Dependency/library CVEs (npm, PyPI, Maven, ...) neither KEV nor cve.org's schema covers well | Fast |
| **NVD (`nvd`)** | Structured CPE version-range data — feeds the upcoming Version Intelligence matching | Moderate |
| **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (`cisa_kev`)** | Confirmation source: every entry is already confirmed actively exploited | Slow by design, highest confidence |

It diffs each run against the last one so you only ever see what's
genuinely **new or changed**, and correlates new/updated entries
against a list of technologies you actually run, so you get a short,
relevant `hunter_queue.md` instead of a full feed dump.

> ⚠️ **Honesty note on verification:** `cisa_kev.py` and `cve_org.py`
> were both tested against LIVE data during development. `nvd.py` and
> `github_advisories.py` were built against each service's officially
> documented, stable API schema, but could not be verified against a
> live fetch during development (sandbox network restrictions). Verify
> their first real CI run's output before fully trusting them — see
> each file's own docstring and `docs/ROADMAP.md`.

> **Known limitation, not hidden:** `cve_org`'s `delta.json` is a
> rolling snapshot, not a complete change log — polling less often than
> its own ~7-minute update cadence risks missing an entry that got
> superseded between polls. The workflow runs every 15 minutes to stay
> close to that cadence, and a gap-detection warning fires if a poll is
> ever skipped/delayed. See `pipeline/collectors/cve_org.py`'s
> docstring for the full explanation and the roadmap for the more
> robust (git-clone-and-diff) approach if this ever needs to be
> airtight.

## Design principle

> CVE Intelligence + Target Correlation + Detection Orchestration —
> not a CVE Scanner.

A name/vendor match against the KEV catalog is a **candidate that
needs manual version verification**, never a confirmed finding. This
project does not run exploitation, does not guess affected version
ranges, and does not auto-validate anything. See
`pipeline/reporting/hunter_queue.py`'s docstring for the exact priority
rules.

## How it works

```
cve_org.py    github_advisories.py    nvd.py    cisa_kev.py
(speed)        (dependency CVEs)     (CPE data)   (confirmed)
    │                │                  │             │
    └────────────────┴──── merge_sources() ───────────┘
         (ascending priority: cve_org < github_advisories < nvd < kev;
          highest-priority source wins on conflict, all sources tagged)
                              ↓
pipeline/intelligence/state_diff.py    — diff against data/state/kev_state.json
        ↓                                (NEW entries / ransomware-flag UPDATED entries)
pipeline/intelligence/technology_matcher.py
        ↓                                — match against targets/*.yaml
pipeline/reporting/hunter_queue.py
        ↓
output/hunter_queue.md                 — prioritized, target-relevant, human-readable
```

## Setup

### Option A: permanent target (tracked every scheduled run)

1. Copy `targets/example.yaml`, rename it, and fill in the
   vendor/product names for the technologies you actually run. One
   file per target/organization.
2. Push it. `.github/workflows/vulnradar-hunt.yml` runs automatically
   every 15 minutes once this is pushed to GitHub (uses the repo's own
   built-in `GITHUB_TOKEN`, no extra setup needed), and commits the
   updated state + `hunter_queue.md` back to the repo each run so state
   persists between runs (GitHub Actions runners are ephemeral —
   without committing state back, every run would think everything is
   new again).

### Option B: one-off target from the Actions UI (no YAML editing)

Go to the repo's **Actions → VulnRadar Hunt → Run workflow** button and
fill in:

- **Target domain** — e.g. `example.com`
- **Technologies** — comma-separated `vendor:product` pairs, e.g.
  `nginx:nginx,Apache:HTTP Server`. Leave the product blank for a
  vendor-only match: `nginx:,Apache:HTTP Server`
- **Save as permanent target?** — check this to also write a real
  `targets/*.yaml` file (committed automatically) so future scheduled
  runs include it too; leave unchecked for a single throwaway check

This mirrors the manual-dispatch pattern already used in the sibling
BugBountyCI project's own workflow UI. Requires no local setup at all —
type a domain, click Run workflow.

**Cost note:** a 15-minute schedule means ~96 workflow runs/day. On
a private repo this consumes GitHub Actions minutes from your
account's quota (each run is fast, well under a minute of actual
compute, but still counts). On a public repo, Actions minutes are
free/unlimited. If this matters, widen the cron schedule in
`.github/workflows/vulnradar-hunt.yml`.

## Running locally

```bash
pip install -r requirements.txt
python3 pipeline/run_hunt.py
cat output/hunter_queue.md
```

Use `--kev-file path/to/snapshot.json` to run against a local KEV
snapshot instead of fetching live (useful for testing, or reprocessing
a previous day's data). Use `--adhoc-target example.com --adhoc-tech
"nginx:nginx"` to test the Option B flow locally without pushing
anything.

## Testing

```bash
python3 pipeline/tests/test_vulnradar.py
python3 pipeline/tests/test_cve_org.py
python3 pipeline/tests/test_github_advisories.py
python3 pipeline/tests/test_nvd.py
python3 pipeline/tests/test_merge_sources.py
```

46 tests total. `test_cve_org.py` runs against a fixture captured from
a LIVE fetch of the real MITRE feed during development. `test_nvd.py`
and `test_github_advisories.py` run against fixtures built from each
service's documented schema (not live-verified — see the honesty note
above the source table).

## What V1 deliberately does NOT do

- Version-range MATCHING isn't wired yet — `nvd.py` already captures
  structured CPE version ranges (`cpe_version_range` on each entry),
  but `technology_matcher.py` still only does name-based matching for
  V1. Wiring the two together is the next real step.
- No exploit/PoC intelligence layer (KEV entries are already
  confirmed-exploited by definition, so this matters less for V1 than
  it would for a broader NVD-based feed)
- No detection/Nuclei orchestration — matching a target to a CVE stops
  at "here's a candidate," it doesn't attempt to verify the finding
- No shared component library with BugBountyCI yet (the original brief
  suggested extracting `technology_matcher`-equivalent logic into a
  shared `security-intelligence-core` package eventually — not done
  for V1, two independent codebases for now)

See `docs/ROADMAP.md` for what's next, in priority order.
