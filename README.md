# VulnRadar

CVE Intelligence + Target Correlation, not a CVE scanner.

VulnRadar tracks **two CVE sources together** to balance speed and
confirmation:

- **[CVE.org](https://www.cve.org/) (`cve_org`)** — the official CVE
  record feed, updated roughly every 7 minutes via
  [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5)'s
  `delta.json`. This is the **speed source**: a new CVE can show up
  here hours or days before it's confirmed as actively exploited.
- **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  (`cisa_kev`)** — the **confirmation source**: every entry is already
  known to be actively exploited in the wild, not just theoretically
  severe. Slower by design (CISA only adds a CVE after confirming
  exploitation), but the highest-confidence signal that exists.

If the same CVE shows up in both, KEV's data wins (it carries the
authoritative "known ransomware use" flag cve_org never has), but the
entry is tagged with both sources so you can see it was actually caught
early by the speed source. It diffs each run against the last one so
you only ever see what's genuinely **new or changed**, and correlates
new/updated entries against a list of technologies you actually run, so
you get a short, relevant `hunter_queue.md` instead of a full feed dump.

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
CISA KEV feed (confirmed-exploited source)     CVE.org delta.json (speed source, ~7min cadence)
        ↓                                              ↓
pipeline/collectors/cisa_kev.py               pipeline/collectors/cve_org.py
        ↓                                              ↓
        └──────────────── merge_sources() ─────────────┘
                    (KEV wins on conflict, both sources tagged)
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
   runs automatically every 15 minutes once this is pushed to GitHub
   (uses the repo's own built-in `GITHUB_TOKEN`, no extra setup
   needed), and commits the updated state + `hunter_queue.md` back to
   the repo each run so state persists between runs (GitHub Actions
   runners are ephemeral — without committing state back, every run
   would think everything is new again).

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
a previous day's data).

## Testing

```bash
python3 pipeline/tests/test_vulnradar.py
python3 pipeline/tests/test_cve_org.py
python3 pipeline/tests/test_merge_sources.py
```

26 tests total. `test_cve_org.py` runs against a fixture captured from
a LIVE fetch of the real MITRE feed during development — not invented
test data.

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
