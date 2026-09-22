# VulnRadar — Project Plan & Decision Log

This is the single reference for what VulnRadar is, what's built, what's
open, and — most importantly — the decisions already made and why, so we
don't re-debate them or re-walk paths that were already rejected. If a
new idea contradicts something in "Rejected / Out of Scope" below, that's
a signal to re-read this file before building it.

## 1. Goal

Automatically watch for newly disclosed / newly exploited CVEs, tell you
**which of your own bug-bounty targets are actually affected** (not just
"a CVE exists somewhere"), and verify that as much as possible without a
human — while staying strictly passive/read-only by default and never
running anything invasive without an explicit per-target opt-in.

Not the goal: being a general-purpose active vulnerability scanner, or
being the fastest possible CVE alerting service. Correctness and staying
inside program scope matter more than speed.

## 2. Pipeline, in order (what actually runs each cycle)

1. **Fingerprint targets** (`pipeline/recon/fingerprint.py`, driven by
   `scripts/refresh_target_fingerprints.py`) — `httpx -tech-detect`
   against each `targets/*.yaml`'s domain, filtered for noise (CDN/WAF
   banners) and normalized to CISA/NVD naming, writes `technologies:`
   back into the yaml file. Optional passive subdomain discovery
   (`pipeline/recon/subdomains.py`, `subfinder -passive`) when a target
   sets `discover_subdomains: true`, so a protected apex domain still has
   a chance of exposing its stack via a subdomain.
2. **Fetch CVEs** from 5 sources (`pipeline/collectors/`): CISA KEV,
   cve.org, GitHub Advisories, NVD, Nuclei Templates.
3. **Diff against saved state** (`pipeline/intelligence/state_diff.py`) —
   only new/changed entries proceed, so the same CVE is never re-reported.
4. **Match targets** (`pipeline/intelligence/technology_matcher.py`) —
   substring-match each CVE's vendor/product against each target's
   `technologies:` list from step 1.
5. **Version check** (`pipeline/intelligence/version_check.py`) — for a
   matched entry, compares the target's fingerprinted `version:` against
   NVD's CPE version-range data → `confirmed` / `safe` / `unknown`.
6. **Passive exposure scan** (`pipeline/recon/exposure_scan.py`) — plain
   GET requests for git exposure, sensitive files, and JS source maps.
   Runs on every target regardless of tech match (doesn't need
   `scan_allowed`, unlike step 7 — see the risk-tier table below).
7. **Live nuclei verification** (`pipeline/verify/nuclei_runner.py`) —
   only for entries that matched a target **and** that target has
   `scan_allowed: true`. Runs `nuclei -id <CVE>` against it for a real
   `vulnerable` / `not-vulnerable` verdict instead of a guess.
8. **Report + notify** — `pipeline/reporting/hunter_queue.py` renders
   `output/hunter_queue.md`; `pipeline/notifiers/discord.py` sends an
   alert only for target-matched, ransomware-known, or exposure findings
   (never every CVE — see `NOTIFY_ALL` if that's ever wanted).
9. **Commit** state/output/targets back to the repo, with retry+rebase
   on push conflicts (races between scheduled/manual runs).

## 3. Risk tiers — why some things are automatic and some require opt-in

This is the most important thing to keep straight, because most of the
"why did/didn't you build X" questions in this project come back to it.

| Tier | Examples | Runs automatically? | Needs `scan_allowed: true`? |
|---|---|---|---|
| **Passive, read-only** | httpx fingerprint, subfinder (passive sources only), exposure_scan's GET requests | Yes, every run | No |
| **Active, but scoped to a known CVE** | nuclei `-id <CVE>` | Yes, IF opted in | **Yes** |
| **Active, broad/invasive** | XSS/SQLi/SSTI/SSRF/command-injection payload testing | **Never in this project** | N/A — not built here at all |
| **Anonymization / IP rotation** | Tor, proxychains | **Rejected outright** | N/A |
| **Non-attributable request cosmetics** | Rotating a normal browser User-Agent string | Yes, every run | No — doesn't touch IP/attribution |

## 4. Decisions already made (don't re-litigate these without a reason)

- **No Tor / IP rotation, ever, in this repo.** Considered explicitly
  (BugBountyCI's `tor-setup` action was reviewed) and rejected: it
  changes the attribution of the request, many bounty programs forbid
  anonymizers even for passive recon, and it doesn't belong in an
  unattended cron job nobody is watching in real time. If GitHub Actions'
  IP range is genuinely blocked by a target, the correct fix is a
  self-hosted runner (not yet built — see Open Items), not evasion.
- **User-Agent rotation is fine and was added** (`pipeline/recon/user_agents.py`).
  This is explicitly *not* the same category as Tor: the IP is unchanged,
  nothing about rate-limiting or WAF rules is being defeated. It only
  avoids every request carrying the literal string "httpx/1.6.9".
- **No active injection testing (SQLi/XSS/SSTI/SSRF/command injection)
  was ported from BugBountyCI, and none will be.** That repo's engine
  was reviewed in full; only the passive exposure-scan logic (git/
  sensitive-files/source-maps, all plain GETs) was ported, deliberately
  trimmed of Tor and WAF-bypass header spoofing.
- **`nuclei` only ever runs against a domain already in `targets/*.yaml`
  with `scan_allowed: true`.** Default is `false`. This is enforced in
  code (`nuclei_runner.target_allows_scanning`), not just documented.
- **A target with an empty `technologies: []` is still loaded**, not
  skipped — this was a real bug (see Bugs Fixed) that silently made
  freshly-fingerprinted targets invisible to matching forever.
- **CVE sources: CISA KEV + cve.org + GitHub Advisories + NVD + Nuclei
  Templates.** KEV alone was rejected early on as too slow (confirmed-
  exploitation only, days/weeks of lag) for the "closer to real-time"
  goal.

## 5. What each piece is named (for consistent naming going forward)

- **VulnRadar** = the whole project / repo name.
- **Collector** = a module in `pipeline/collectors/` that fetches raw CVE
  data from one source.
- **Target** = one file in `targets/*.yaml`, one domain/organization being
  tracked. Has `technologies:` (auto-filled), `scan_allowed:` (opt-in
  gate for nuclei), optionally `discover_subdomains:`.
- **Fingerprint** = the auto-detected tech stack for a target (step 1).
- **Match** = a CVE whose vendor/product string overlaps a target's
  fingerprinted technologies.
- **Verify** = the *live* confirmation step (nuclei), as opposed to match
  (name overlap) or version-check (range comparison) which are both
  inference, not proof.
- **Exposure finding** = something from the passive exposure_scan (git,
  sensitive files, source maps) — separate track from CVE matching
  entirely, no version/nuclei step applies to it.
- **hunter_queue.md** = the single human-readable output file per run.

## 6. Bugs found and fixed so far (so the same class of bug isn't reintroduced)

1. `github_advisories.py` crashed on the live API's actual response shape
   (`first_patched_version` as a string, not an object) — fixture had the
   wrong shape, so tests passed while production crashed. **Lesson: a
   fixture is not a substitute for one live run before declaring
   something done.**
2. Ad-hoc workflow_dispatch inputs were interpolated into `eval` — shell
   injection risk. Fixed by moving everything through `env:`.
3. `%` used in a GitHub Actions `if:` expression — not supported syntax,
   silently rejects every dispatch with a 422. Actions expressions have
   no modulo operator.
4. Automated commits raced when a manual dispatch and a push/schedule
   trigger landed close together — fixed with `concurrency:` + retry-with-
   rebase (`-X ours` on the generated files specifically) on push.
5. `load_all_targets()` silently dropped any target with an empty
   `technologies: []` — meaning a target could never start matching even
   *after* a successful fingerprint scan populated it later in the same
   run, because the drop happened at load time, before fingerprinting's
   result was even considered relevant. This was the actual reason
   okx.com never matched anything, independent of whether httpx found
   its stack.
6. Noise filtering in `fingerprint.py` used exact-string matching only —
   missed WAF/CDN banner variants like `AkamaiGHost` (only `akamai` was
   listed). Fixed with a substring fallback. Found via a stale target
   file (`superdrug-com.yaml`) that had `AkamaiGHost` sitting in its
   technologies list from an earlier run.
7. `scripts/save_target.py` pushed with plain `git push` and no retry,
   unlike the main workflow's commit step — a race could silently lose
   an ad-hoc-saved target with no error surfaced (`os.system` ignores
   exit codes). Hardened to match the main commit step's retry+rebase.

## 7. Open items / known unresolved

- **okx.com fingerprinting is still empty** (`targets/okx-com.yaml`).
  Confirmed the workflow runs correctly (httpx executes, no crash) but
  produces zero detected technologies. Root cause not yet isolated
  between: (a) genuine WAF/IP-based blocking of GitHub Actions' IP
  range, or (b) the site simply not leaking enough signal for passive
  fingerprinting regardless of source IP. User-Agent rotation was added
  as one candidate fix; **not yet confirmed whether it changed anything**
  because we haven't compared a run's actual httpx output before/after.
  **Next step before doing anything else here: run
  `curl -sI https://okx.com` and `httpx -u okx.com -tech-detect -json
  -silent -debug-resp` directly (from Actions or elsewhere) to see the
  actual HTTP status code, not guess from silence.**
- **Self-hosted runner** — proposed as the correct fix if okx.com's block
  turns out to be IP-based, not yet built.
- **3 of 5 CVE sources (NVD, cve.org, Nuclei Templates) still only
  partially exercised live inside Actions** vs. locally — worth a
  dedicated live-verification pass the same way github_advisories.py's
  live bug was caught.
- **Exposure scan has found zero results on all 3 current targets.**
  Consistent with those targets being well-protected, not evidence of a
  bug — but also not yet proven against a deliberately-vulnerable test
  target, so the positive-detection path (not just the negative/clean
  path) is still unverified end-to-end.

## 8. How to use this file going forward

Before proposing something that sounds like "add IP rotation", "add
active scanning", "change what nuclei runs against", or "change what's
automatic vs. opt-in" — check section 3 and 4 first. If the new idea
doesn't fit the existing risk-tier table, that's the discussion to have
explicitly, not something to fold in quietly.

When a bug is found and fixed, add it to section 6 with the *root cause*,
not just the symptom — several bugs here looked like a different problem
at first (okx.com "not matching" was actually two separate bugs: the
empty-technologies load bug, and the httpx noise-filter bug).
