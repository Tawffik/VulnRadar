# VulnRadar

CVE Intelligence + Target Correlation, not a CVE scanner.

VulnRadar tracks [CISA's Known Exploited Vulnerabilities (KEV)
catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
— the single highest-signal CVE feed that exists, since every entry on
it is already confirmed to be actively exploited in the wild, not just
theoretically severe. It diffs each run against the last one so you
only ever see what's genuinely **new**, and correlates new/updated
entries against a list of technologies you actually run, so you get a
short, relevant `hunter_queue.md` instead of the full multi-thousand-
entry catalog.

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
CISA KEV feed (live JSON, no API key)
        ↓
pipeline/collectors/cisa_kev.py       — fetch + normalize
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

1. Copy `targets/example.yaml`, rename it, and fill in the
   vendor/product names for the technologies you actually run. One
   file per target/organization.
2. That's it for local use — `.github/workflows/vulnradar-hunt.yml`
   runs automatically every 6 hours once this is pushed to GitHub
   (uses the repo's own built-in `GITHUB_TOKEN`, no extra setup
   needed), and commits the updated state + `hunter_queue.md` back to
   the repo each run so state persists between runs (GitHub Actions
   runners are ephemeral — without committing state back, every run
   would think everything is new again).

## Running locally

```bash
pip install -r requirements.txt
python3 pipeline/run_hunt.py
cat output/hunter_queue.md
```

Use `--kev-file path/to/snapshot.json` to run against a local KEV
snapshot instead of fetching live (useful for testing, or reprocessing
a previous day's data).

## Testing

```bash
python3 pipeline/tests/test_vulnradar.py
```

13 tests, run against a realistic KEV fixture matching the real CISA
schema exactly (`pipeline/tests/fixtures/kev_sample.json`) — not
invented test data.

## What V1 deliberately does NOT do

- No version-range checking (a vendor/product name match is flagged as
  a candidate; verifying the actual deployed version against the
  affected range is a manual step for now — see the roadmap)
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
