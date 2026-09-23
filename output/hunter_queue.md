# VulnRadar Hunter Queue

Generated: 2026-09-23T14:47:57+00:00
Targets loaded: 3
New KEV entries this run: 54
Updated KEV entries this run (ransomware flag changed): 1
Entries below (target-matched or known-ransomware): 1

> A CVE affecting a matched technology is a candidate needing manual version verification, not a confirmed vulnerability. This project does not run exploitation — see 'Next Safe Action' on each entry.

## 1. CVE-2026-63077 — UPDATED — now flagged for known ransomware use

**Vendor / Product:** JetBrains / TeamCity
**Name:** JetBrains TeamCity Deserialization of Untrusted Data Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Version check:** unknown — no fingerprinted version or no NVD version-range data
**Nuclei verification:** (not run — nuclei unavailable or target not opted into scanning)
**Date added to KEV:** 2026-08-05
**CISA required action:** Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

**Description:** JetBrains TeamCity contains a deserialization of untrusted data vulnerability that could allow unauthenticated remote code execution via the agent polling protocol.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---
