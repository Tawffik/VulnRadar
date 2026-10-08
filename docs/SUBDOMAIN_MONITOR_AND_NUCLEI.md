# VulnRadar — Subdomain Monitor + Nuclei Track

## Why this lives here (not in BugBountyCI Zero Track)

| Concern | BugBountyCI Zero Track | VulnRadar |
|---------|------------------------|-----------|
| Goal | Recon → model → relationships → Hunter research queue | Continuous **asset change** + **CVE-relevant** verification |
| Nuclei | Full-template dump timed out → 0 findings, DEGRADED | `nuclei -id <CVE>` only, opt-in `scan_allowed` |
| Subdomains | One-shot discovery inside a long hunt | **Baseline diff**: new / removed / takeover candidates over time |
| Schedule | Heavy manual/authorized campaigns | Light recurring monitor + on-demand verify |

Moving both here keeps Zero Track focused on intelligence quality and gives
Monitor+Nuclei a workflow that can finish its full cycle.

## Architecture

```
targets/*.yaml  (or inventory list)
        │
        ▼
┌─────────────────────── VulnRadar Monitor Workflow ───────────────────────┐
│ 1. Subdomain Monitor (passive)                                           │
│    subfinder -passive → dnsx → httpx live                                │
│    baseline state per target: prev live set                              │
│    emit: new / removed / still-live                                      │
│    optional: subzy-style takeover check on NEW only                      │
│ 2. Fingerprint (existing)                                                │
│    httpx -tech-detect on apex + sample of new hosts                      │
│ 3. CVE cycle (existing hunt)                                             │
│    KEV / NVD / GH / cve.org / nuclei-templates → match → version check   │
│ 4. Nuclei verify (existing nuclei_runner)                                │
│    ONLY matched CVEs × targets with scan_allowed: true                   │
│    NEVER unrestricted -severity critical,high template floods             │
│ 5. Hunter queue + Discord (existing)                                     │
└──────────────────────────────────────────────────────────────────────────┘
```

## Subdomain Monitor contract

Per target domain `D`:

| Artifact | Meaning |
|----------|---------|
| `data/monitor/<D>/subdomains.txt` | Discovery candidates (passive) |
| `data/monitor/<D>/live.txt` | Currently resolved+live hosts |
| `data/monitor/<D>/prev.txt` | Previous run's live set (baseline) |
| `data/monitor/<D>/new.txt` | In live, not in prev |
| `data/monitor/<D>/removed.txt` | In prev, not in live |
| `data/monitor/<D>/state.json` | counts, timestamps, status COMPLETE/INCOMPLETE |

Rules:
- Passive discovery only (subfinder `-passive`) unless future opt-in says otherwise.
- Scope: only `D` and hosts ending in `.<D>`.
- Incomplete (dnsx=0, tool missing) must never look like "clean / no assets".
- Nuclei is **never** run on every new subdomain automatically.
- `scan_allowed` remains apex-level opt-in for CVE nuclei only (existing rule).

## Nuclei contract (unchanged intent, stronger placement)

Already implemented in `pipeline/verify/nuclei_runner.py`:

- Requires `scan_allowed: true` on the target yaml.
- Runs `nuclei -id <CVE>` only for matched CVEs.
- Verdicts: vulnerable / not-vulnerable / no-template / skipped / error.
- Missing binary → stage UNAVAILABLE, not fake clean.

BugBountyCI Zero Track must **not** re-run a bulk Nuclei campaign.

## Workflow design (target state)

| Workflow | Trigger | Job |
|----------|---------|-----|
| `vulnradar-hunt.yml` | daily + dispatch | CVE collectors + match + version + exposure + nuclei verify |
| `vulnradar-monitor.yml` (new) | schedule (e.g. 2–4×/day) + dispatch | Subdomain baseline monitor for all targets / optional single domain |
| Optional chain | monitor completes → workflow_call hunt | Fingerprint new hosts then hunt |

Runner: `ubuntu-latest` until Sengi quota returns; document `runs-on` like BBCI interim.

## Migration from BugBountyCI

| Source | Action |
|--------|--------|
| `.github/workflows/01.yml` (Subdomain Monitor) | Deprecated in BBCI; logic re-implemented as Python under `pipeline/monitor/` |
| `targets-bb.txt` | Port selected authorized domains into `targets/*.yaml` as needed |
| Zero Track Nuclei step | Replaced with explicit **MOVED → VulnRadar** / `NOT_RUN` phase (no bulk scan) |
| `nuclei_track_summary` | May remain as "track external / not executed here" |

## Non-goals

- Not re-creating Zero Track inside VulnRadar.
- Not unrestricted nuclei template packs on every live host.
- Not importing SRA / BBCI response-intelligence engines.
