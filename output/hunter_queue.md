# VulnRadar Hunter Queue

Generated: 2026-11-08T09:56:33+00:00
Targets loaded: 24
New KEV entries this run: 138
Updated KEV entries this run (ransomware flag changed): 0
Entries below (target-matched or known-ransomware): 3

> A CVE affecting a matched technology is a candidate needing manual version verification, not a confirmed vulnerability. This project does not run exploitation — see 'Next Safe Action' on each entry.

## 1. CVE-2026-119977 — NEW

**Vendor / Product:** WordPress / WordPress Core
**Name:** WordPress WordPress Core Time-of-check Time-of-use (TOCTOU) Race Condition Vulnerability
**Matched target(s):** atlassian.com, cloudinary.com, doctolib.com, elementor.com
**Known ransomware use:** Unknown
**Version check:** unknown — no fingerprinted version or no NVD version-range data
**Nuclei verification:** (not run — nuclei unavailable or target not opted into scanning)
**Date added to KEV:** 2026-11-03
**CISA required action:** Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

**Description:** WordPress WordPress Core contains a time-of-check time-of-use (TOCTOU) race condition vulnerability that could allow unauthenticated attackers to execute code on the server during the upgrade window. This is due to predictable, web-accessible staging paths used during full-package core upgrades.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 2. CVE-2026-109618 — NEW

**Vendor / Product:** PHP Group / PHP
**Name:** PHP Memory Corruption Vulnerability
**Matched target(s):** cloudinary.com, doctolib.com, elementor.com
**Known ransomware use:** Unknown
**Version check:** unknown — no fingerprinted version or no NVD version-range data
**Nuclei verification:** (not run — nuclei unavailable or target not opted into scanning)
**Date added to KEV:** 2026-10-26
**CISA required action:** Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

**Description:** PHP contains an out-of-memory corruption vulnerability that allows for unauthenticated remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 3. CVE-2026-109619 — NEW

**Vendor / Product:** PHP Group / PHP
**Name:** PHP Stale Internal Request-State Vulnerability
**Matched target(s):** cloudinary.com, doctolib.com, elementor.com
**Known ransomware use:** Unknown
**Version check:** unknown — no fingerprinted version or no NVD version-range data
**Nuclei verification:** (not run — nuclei unavailable or target not opted into scanning)
**Date added to KEV:** 2026-10-26
**CISA required action:** Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

**Description:** PHP contains a stale internal request-state vulnerability that allows for unauthenticated remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

---

## Passive Exposure Findings

Plain GET requests to well-known paths — no injection, no scan_allowed needed. Verify manually before reporting; a 200 response is not proof of a working exploit.

### arlo.com

**Source maps found:** 1 — https://integrations.etrusted.com/applications/widget.js/v2.map

### asana.com

**Source maps found:** 18 — https://www.google.com/recaptcha/enterprise.js?render=6Lf1FtQZAAAAAKGsW3JoCdtQfzfCb2umWbEoyOjE.map, https://asana.com/_next/static/chunks/polyfills-42372ed130431b0a.js?dpl=5e2f67c79f3511dd9c8906e375c5a7ea9dd6652366d239b8c8215a6616c86e8f366165653066326461623833666266316230383164313332.map, https://asana.com/_next/static/chunks/99283-197d890b88e8395a.js?dpl=5e2f67c79f3511dd9c8906e375c5a7ea9dd6652366d239b8c8215a6616c86e8f366165653066326461623833666266316230383164313332.map, https://asana.com/_next/static/chunks/59643-baacc11ca780467e.js?dpl=5e2f67c79f3511dd9c8906e375c5a7ea9dd6652366d239b8c8215a6616c86e8f366165653066326461623833666266316230383164313332.map, https://asana.com/_next/static/chunks/34013-23a783415d5a4b58.js?dpl=5e2f67c79f3511dd9c8906e375c5a7ea9dd6652366d239b8c8215a6616c86e8f366165653066326461623833666266316230383164313332.map

### cloudinary.com

**Source maps found:** 2 — https://cloudinary.com/wp-content/themes/cld-2021/assets/js/jquery-3.4.1.min.js?ver=3.4.1.map, https://cloudinary.com/wp-content/themes/cld-2021/assets/js/bootstrap.min.js?ver=4.3.1.map

### decathlon.com

**Sensitive files:**
- https://decathlon.com/.env

### elementor.com

**Source maps found:** 3 — https://elementor.com/wp-content/plugins/weglot/dist/front-js.js?ver=6.4.3.map, https://elementor.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1.map, https://elementor.com/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1.map

### fivetran.com

**Source maps found:** 2 — https://d3e54v103j8qbb.cloudfront.net/js/jquery-3.5.1.min.dc5e7f18c8.js?site=6130fa1501794ed4d11867ba.map, https://fivetran-com.s3.amazonaws.com/js/scripts.js?47.map

### gearset.com

**Source maps found:** 5 — https://cmp.osano.com/6okapU34JmZx4cWG/4693432c-ab0c-40c3-a4a1-99cc77801085/osano.js.map, https://gearset.com/assets/index-D76r56YY.js.map, https://www.google.com/recaptcha/api.js?render=6LdgPY4oAAAAAPSJC_kJKTNKk3BKUCF8qmpeAYaI.map, https://gearset.com/assets/polyfills-legacy-CGzxiYTs.js.map, https://gearset.com/assets/index-legacy-lAkEdfuC.js.map

### glean.com

**Source maps found:** 4 — https://cmp.osano.com/16CXuzUWVmvBc5GOi/2cb189d0-529f-40a5-9353-12a933c5cb8e/osano.js.map, https://js.qualified.com/qualified.js?token=aRmANoPv4oA76kXK.map, https://cdn.jsdelivr.net/npm/gsap@3.13.0/dist/gsap.min.js.map, https://cdn.jsdelivr.net/npm/gsap@3.13.0/dist/Flip.min.js.map

### ibotta.com

**Source maps found:** 12 — https://ibotta.com/corporate-assets/_next/static/chunks/1dd3208c-44feaec1dc44dc9f.js.map, https://ibotta.com/corporate-assets/_next/static/chunks/528-bdfc7515b5261e3b.js.map, https://ibotta.com/corporate-assets/_next/static/chunks/main-app-6f35475d6b240635.js.map, https://ibotta.com/corporate-assets/_next/static/chunks/154-cea128311a5f1ae0.js.map, https://ibotta.com/corporate-assets/_next/static/chunks/145-cec10e57a4c8c455.js.map

### klaviyo.com

**Source maps found:** 2 — https://transcend-cdn.com/cm/f3c1005b-8270-469c-85a4-81fe6c9b70e7/airgap.js?cacheBust=1794039851877.map, https://www.google.com/recaptcha/api.js?render=6Lc-vxErAAAAAKq79hQ2CEfaUCBld0hVMtRboXtB&amp;hl=en-US.map



## Pipeline Health

**Overall: SUCCESS**

| Component | Status |
|---|---|
| cisa_kev | SUCCESS |
| cve_org | SUCCESS |
| github_advisories | SUCCESS |
| nvd | EMPTY |
| nuclei_templates | SUCCESS |
| matching | SUCCESS |
| version_check | SUCCESS |
| nuclei_verification | UNAVAILABLE |
| exposure_scan | SUCCESS |

| Target | Status |
|---|---|
| ably.com | SUCCESS |
| aiven.io | SUCCESS |
| arlo.com | SUCCESS |
| asana.com | SUCCESS |
| atlassian.com | SUCCESS |
| classdojo.com | SUCCESS |
| cloudinary.com | SUCCESS |
| datadome.co | SUCCESS |
| decathlon.com | SUCCESS |
| doctolib.com | SUCCESS |
| elementor.com | SUCCESS |
| example.com | SUCCESS |
| expressvpn.com | SUCCESS |
| fivetran.com | SUCCESS |
| gearset.com | SUCCESS |
| glean.com | SUCCESS |
| ibotta.com | SUCCESS |
| ifood.com.br | SUCCESS |
| indeed.com | SUCCESS |
| intercom.com | SUCCESS |
| klaviyo.com | SUCCESS |
| okx.com | SUCCESS |
| shopify.com | SUCCESS |
| Superdrug.com | SUCCESS |

**Counts:**
- new_cves: 138
- updated_cves: 0

**Warnings:**
- ⚠️ 50271 minutes since the last successful cve_org fetch (threshold: 1500min) — some CVEs published in between may have been missed since delta.json is a snapshot, not a full log. See cve_org.py's module docstring.
