# VulnRadar Hunter Queue

Generated: 2026-11-26T16:05:24+00:00
Targets loaded: 24
New KEV entries this run: 3
Updated KEV entries this run (ransomware flag changed): 1
Entries below (target-matched or known-ransomware): 1

> A CVE affecting a matched technology is a candidate needing manual version verification, not a confirmed vulnerability. This project does not run exploitation — see 'Next Safe Action' on each entry.

## 1. CVE-2026-59310 — UPDATED — now flagged for known ransomware use

**Vendor / Product:** Broadcom / VMware vCenter
**Name:** Broadcom VMware vCenter Path Traversal Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**EPSS:** unavailable
**Public PoCs:** none found
**Version check:** unknown — no fingerprinted version or no NVD version-range data
**Nuclei verification:** (not run — nuclei unavailable or target not opted into scanning)
**Date added to KEV:** 2026-08-18
**CISA required action:** Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

**Description:** Broadcom VMware vCenter contains a path traversal vulnerability which could allow a threat actor with network access to vCenter to execute arbitrary code.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

---

## Passive Exposure Findings

Plain GET requests to well-known paths — no injection, no scan_allowed needed. Verify manually before reporting; a 200 response is not proof of a working exploit.

### arlo.com

**Source maps found:** 2 — https://cdn.deepconverse.com/v1/assets/js/loader/converseapps-bot.js?applicationId=42DA21E7&siteId=7250aa109075cf41&botName=chat-v1.map, https://arlo.com/assets/index-CSV9pvLE.js.map

### asana.com

**Source maps found:** 18 — https://www.google.com/recaptcha/enterprise.js?render=6Lf1FtQZAAAAAKGsW3JoCdtQfzfCb2umWbEoyOjE.map, https://asana.com/_next/static/chunks/polyfills-42372ed130431b0a.js?dpl=48e45be14fd4655bb275ba95f87669abb08ebff99dab8358f35eb85060306e91366230373136303832633934613635356166393066343839.map, https://asana.com/_next/static/chunks/54858-ea606363a9c7a5ab.js?dpl=48e45be14fd4655bb275ba95f87669abb08ebff99dab8358f35eb85060306e91366230373136303832633934613635356166393066343839.map, https://asana.com/_next/static/chunks/90495-8bfac6c8eb0c8795.js?dpl=48e45be14fd4655bb275ba95f87669abb08ebff99dab8358f35eb85060306e91366230373136303832633934613635356166393066343839.map, https://asana.com/_next/static/chunks/59643-baacc11ca780467e.js?dpl=48e45be14fd4655bb275ba95f87669abb08ebff99dab8358f35eb85060306e91366230373136303832633934613635356166393066343839.map

### cloudinary.com

**Source maps found:** 2 — https://cloudinary.com/wp-content/themes/cld-2021/assets/js/jquery-3.4.1.min.js?ver=3.4.1.map, https://cloudinary.com/wp-content/themes/cld-2021/assets/js/bootstrap.min.js?ver=4.3.1.map

### elementor.com

**Source maps found:** 3 — https://elementor.com/wp-content/plugins/weglot/dist/front-js.js?ver=6.4.3.map, https://elementor.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1.map, https://elementor.com/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1.map

### expressvpn.com

**Source maps found:** 2 — https://expressvpn.com/wp-ws-cache/themes/expressvpn/assets/js/general.js?ver=1795607143.map, https://expressvpn.com/wp-ws-cache/themes/expressvpn/assets/js/swiperJs.js?ver=1795607149.map

### fivetran.com

**Source maps found:** 2 — https://d3e54v103j8qbb.cloudfront.net/js/jquery-3.5.1.min.dc5e7f18c8.js?site=6130fa1501794ed4d11867ba.map, https://fivetran-com.s3.amazonaws.com/js/scripts.js?59.map

### gearset.com

**Source maps found:** 5 — https://cmp.osano.com/6okapU34JmZx4cWG/4693432c-ab0c-40c3-a4a1-99cc77801085/osano.js.map, https://gearset.com/assets/index-C4W6cXLc.js.map, https://www.google.com/recaptcha/api.js?render=6LdgPY4oAAAAAPSJC_kJKTNKk3BKUCF8qmpeAYaI.map, https://gearset.com/assets/polyfills-legacy-BsMNi2G7.js.map, https://gearset.com/assets/index-legacy-mxf1adxv.js.map

### glean.com

**Source maps found:** 3 — https://cmp.osano.com/16CXuzUWVmvBc5GOi/2cb189d0-529f-40a5-9353-12a933c5cb8e/osano.js.map, https://cdn.jsdelivr.net/npm/gsap@3.13.0/dist/gsap.min.js.map, https://cdn.jsdelivr.net/npm/gsap@3.13.0/dist/Flip.min.js.map

### ibotta.com

**Source maps found:** 12 — https://ibotta.com/corporate-assets/_next/static/chunks/1dd3208c-44feaec1dc44dc9f.js.map, https://ibotta.com/corporate-assets/_next/static/chunks/528-bdfc7515b5261e3b.js.map, https://ibotta.com/corporate-assets/_next/static/chunks/main-app-6f35475d6b240635.js.map, https://ibotta.com/corporate-assets/_next/static/chunks/154-cea128311a5f1ae0.js.map, https://ibotta.com/corporate-assets/_next/static/chunks/145-cec10e57a4c8c455.js.map

### klaviyo.com

**Source maps found:** 2 — https://transcend-cdn.com/cm/f3c1005b-8270-469c-85a4-81fe6c9b70e7/airgap.js?cacheBust=1795709034584.map, https://www.google.com/recaptcha/api.js?render=6Lc-vxErAAAAAKq79hQ2CEfaUCBld0hVMtRboXtB&amp;hl=en-US.map



## Pipeline Health

**Overall: SUCCESS**

| Component | Status |
|---|---|
| cisa_kev | SUCCESS |
| cve_org | SUCCESS |
| github_advisories | SUCCESS |
| nvd | EMPTY |
| nuclei_templates | SUCCESS |
| cvenotify | EMPTY |
| matching | SUCCESS |
| epss | SUCCESS |
| poc_github | SUCCESS |
| version_check | SUCCESS |
| nuclei_verification | SUCCESS |
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
- new_cves: 3
- updated_cves: 1
