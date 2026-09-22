# VulnRadar

CVE Intelligence + Target Correlation, not a CVE scanner.

VulnRadar tracks **four CVE sources together**, merged by priority
(highest wins on conflict, all contributing sources still recorded):

| Source | Role | Speed |
|---|---|---|
| **[CVE.org](https://www.cve.org/) (`cve_org`)** | Speed source | ~7min cadence — often hours/days ahead of KEV |
| **GitHub Security Advisories (`github_advisories`)** | Dependency/library CVEs (npm, PyPI, Maven, ...) neither KEV nor cve.org's schema covers well | Fast |
| **NVD (`nvd`)** | Structured CPE version-range data — feeds the upcoming Version Intelligence matching | Moderate |
| **[Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates) (`nuclei_templates`)** | A new PoC/detection method already exists for this CVE | Very fast — often within hours of disclosure |
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

55 tests total. `test_cve_org.py` runs against a fixture captured from
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

## Fingerprinting, version checking, live verification (V2)

Three additions close the gaps from V1:

- **Auto fingerprinting** (`pipeline/recon/fingerprint.py`): runs
  ProjectDiscovery's `httpx -tech-detect` against each target and
  rewrites `targets/*.yaml`'s technology list automatically, including
  detected versions. Run manually:
  `python3 scripts/refresh_target_fingerprints.py`
  (needs `httpx` on PATH — `scripts/install_httpx.sh` installs it). The
  workflow also runs this itself, roughly every 6 hours on schedule.
- **Version-aware matching** (`pipeline/intelligence/version_check.py`):
  compares a target's fingerprinted `version:` against NVD's CPE
  version-range data (already collected by `nvd.py`, previously
  unused) to label each hit `confirmed`, `safe`, or `unknown` instead
  of always "needs manual verification".
- **Live nuclei verification** (`pipeline/verify/nuclei_runner.py`):
  for a CVE that matched a target AND that target has a nuclei
  template, runs it and reports `vulnerable` / `not-vulnerable`
  instead of a guess. **Opt-in only**: a target must set
  `scan_allowed: true` in its yaml file — this is only safe when you
  are authorized to actively test that target (in-scope bug bounty
  program, or your own infrastructure). Never runs against anything
  not already listed in `targets/*.yaml`.

All three degrade gracefully: if `httpx`/`nuclei` aren't installed, or
a target is unreachable, or scanning isn't opted in, the pipeline
falls back to V1's name-match-only behavior and prints a notice — it
never fails the run.

## Discord alerts

Set the `DISCORD_WEBHOOK_URL` repo secret to get alerts for CVEs that
are target-matched or have known ransomware use (not every CVE — see
`pipeline/notifiers/discord.py`). A live nuclei hit or a
version-confirmed match is called out and ranked first. A Discord
failure never breaks the hunt.

## Passive exposure scanning (from BugBountyCI, trimmed down)

`pipeline/recon/exposure_scan.py` — ported and simplified from a
separate, much larger active-scanning repo. Kept: plain-GET checks for
git exposure (`/.git/HEAD`, `/.git/config`), exposed sensitive files
(`.env`, `wp-config.php`, etc, with soft-404/SPA-shell filtering), and
JS source-map discovery with API-key/JWT pattern scanning inside them.
Dropped entirely, on purpose: Tor/proxychains IP rotation, WAF-bypass
header spoofing, and every active injection technique (XSS/SQLi/SSTI/
SSRF/command injection). Those are active testing, need per-target
authorization, and don't belong in an unattended cron job — this
scanner only ever sends read-only GET requests, so unlike nuclei
verification it runs on every target regardless of `scan_allowed`.

Findings appear in `hunter_queue.md` under "Passive Exposure Findings"
and, if `DISCORD_WEBHOOK_URL` is set, as their own alert - independent
of whether any CVE matched that run.
