# VulnRadar Hunter Queue

Generated: 2026-11-24T16:46:47+00:00
Targets loaded: 24
New KEV entries this run: 169
Updated KEV entries this run (ransomware flag changed): 2
Entries below (target-matched or known-ransomware): 2

> A CVE affecting a matched technology is a candidate needing manual version verification, not a confirmed vulnerability. This project does not run exploitation — see 'Next Safe Action' on each entry.

## 1. CVE-2018-8581 — UPDATED — now flagged for known ransomware use

**Vendor / Product:** Microsoft / Exchange Server
**Name:** Microsoft Exchange Server Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**EPSS:** unavailable
**Public PoCs:** none found
**Version check:** unknown — no fingerprinted version or no NVD version-range data
**Nuclei verification:** (not run — nuclei unavailable or target not opted into scanning)
**Date added to KEV:** 2022-03-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** A privilege escalation vulnerability exists in Microsoft Exchange Server. An attacker who successfully exploited this vulnerability could attempt to impersonate any other user of the Exchange server.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 2. CVE-2021-22893 — UPDATED — now flagged for known ransomware use

**Vendor / Product:** Ivanti / Pulse Connect Secure
**Name:** Ivanti Pulse Connect Secure Use-After-Free Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**EPSS:** unavailable
**Public PoCs:** none found
**Version check:** unknown — no fingerprinted version or no NVD version-range data
**Nuclei verification:** (not run — nuclei unavailable or target not opted into scanning)
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Ivanti Pulse Connect Secure contains a use-after-free vulnerability that allow a remote, unauthenticated attacker to execute code via license services.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

---

## Passive Exposure Findings

Plain GET requests to well-known paths — no injection, no scan_allowed needed. Verify manually before reporting; a 200 response is not proof of a working exploit.

### arlo.com

**Source maps found:** 2 — https://cdn.deepconverse.com/v1/assets/js/loader/converseapps-bot.js?applicationId=42DA21E7&siteId=7250aa109075cf41&botName=chat-v1.map, https://arlo.com/assets/index-CSV9pvLE.js.map

### asana.com

**Source maps found:** 18 — https://www.google.com/recaptcha/enterprise.js?render=6Lf1FtQZAAAAAKGsW3JoCdtQfzfCb2umWbEoyOjE.map, https://asana.com/_next/static/chunks/polyfills-42372ed130431b0a.js?dpl=92ce93bade11aaa76d4a20b76655398d79905491b173db9f5b024f48e3f92e1a366230343734613230343365386464363532343336613866.map, https://asana.com/_next/static/chunks/54858-ea606363a9c7a5ab.js?dpl=92ce93bade11aaa76d4a20b76655398d79905491b173db9f5b024f48e3f92e1a366230343734613230343365386464363532343336613866.map, https://asana.com/_next/static/chunks/90495-8bfac6c8eb0c8795.js?dpl=92ce93bade11aaa76d4a20b76655398d79905491b173db9f5b024f48e3f92e1a366230343734613230343365386464363532343336613866.map, https://asana.com/_next/static/chunks/59643-baacc11ca780467e.js?dpl=92ce93bade11aaa76d4a20b76655398d79905491b173db9f5b024f48e3f92e1a366230343734613230343365386464363532343336613866.map

### cloudinary.com

**Source maps found:** 2 — https://cloudinary.com/wp-content/themes/cld-2021/assets/js/jquery-3.4.1.min.js?ver=3.4.1.map, https://cloudinary.com/wp-content/themes/cld-2021/assets/js/bootstrap.min.js?ver=4.3.1.map

### elementor.com

**Source maps found:** 3 — https://elementor.com/wp-content/plugins/weglot/dist/front-js.js?ver=6.4.3.map, https://elementor.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1.map, https://elementor.com/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1.map

### expressvpn.com

**Source maps found:** 2 — https://expressvpn.com/wp-ws-cache/themes/expressvpn/assets/js/general.js?ver=1795535197.map, https://expressvpn.com/wp-ws-cache/themes/expressvpn/assets/js/swiperJs.js?ver=1795535204.map

### fivetran.com

**Source maps found:** 2 — https://d3e54v103j8qbb.cloudfront.net/js/jquery-3.5.1.min.dc5e7f18c8.js?site=6130fa1501794ed4d11867ba.map, https://fivetran-com.s3.amazonaws.com/js/scripts.js?59.map

### gearset.com

**Source maps found:** 5 — https://cmp.osano.com/6okapU34JmZx4cWG/4693432c-ab0c-40c3-a4a1-99cc77801085/osano.js.map, https://gearset.com/assets/index-w8EzgZ0k.js.map, https://www.google.com/recaptcha/api.js?render=6LdgPY4oAAAAAPSJC_kJKTNKk3BKUCF8qmpeAYaI.map, https://gearset.com/assets/polyfills-legacy-BsMNi2G7.js.map, https://gearset.com/assets/index-legacy-Cf_F8r72.js.map

### glean.com

**Source maps found:** 3 — https://cmp.osano.com/16CXuzUWVmvBc5GOi/2cb189d0-529f-40a5-9353-12a933c5cb8e/osano.js.map, https://cdn.jsdelivr.net/npm/gsap@3.13.0/dist/gsap.min.js.map, https://cdn.jsdelivr.net/npm/gsap@3.13.0/dist/Flip.min.js.map

### ibotta.com

**Source maps found:** 12 — https://ibotta.com/corporate-assets/_next/static/chunks/1dd3208c-44feaec1dc44dc9f.js.map, https://ibotta.com/corporate-assets/_next/static/chunks/528-bdfc7515b5261e3b.js.map, https://ibotta.com/corporate-assets/_next/static/chunks/main-app-6f35475d6b240635.js.map, https://ibotta.com/corporate-assets/_next/static/chunks/154-cea128311a5f1ae0.js.map, https://ibotta.com/corporate-assets/_next/static/chunks/145-cec10e57a4c8c455.js.map

### klaviyo.com

**Source maps found:** 2 — https://transcend-cdn.com/cm/f3c1005b-8270-469c-85a4-81fe6c9b70e7/airgap.js?cacheBust=1795538514393.map, https://www.google.com/recaptcha/api.js?render=6Lc-vxErAAAAAKq79hQ2CEfaUCBld0hVMtRboXtB&amp;hl=en-US.map



## Pipeline Health

**Overall: SUCCESS**

| Component | Status |
|---|---|
| cisa_kev | SUCCESS |
| cve_org | SUCCESS |
| github_advisories | SUCCESS |
| nvd | SUCCESS |
| nuclei_templates | SUCCESS |
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
- new_cves: 169
- updated_cves: 2
