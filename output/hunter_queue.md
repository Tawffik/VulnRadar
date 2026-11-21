# VulnRadar Hunter Queue

Generated: 2026-11-21T13:58:52+00:00
Targets loaded: 24
New KEV entries this run: 3
Updated KEV entries this run (ransomware flag changed): 0
Entries below (target-matched or known-ransomware): 0

> A CVE affecting a matched technology is a candidate needing manual version verification, not a confirmed vulnerability. This project does not run exploitation — see 'Next Safe Action' on each entry.

No target-relevant or high-priority KEV entries this run.

---

## Passive Exposure Findings

Plain GET requests to well-known paths — no injection, no scan_allowed needed. Verify manually before reporting; a 200 response is not proof of a working exploit.

### arlo.com

**Source maps found:** 2 — https://cdn.deepconverse.com/v1/assets/js/loader/converseapps-bot.js?applicationId=42DA21E7&siteId=7250aa109075cf41&botName=chat-v1.map, https://arlo.com/assets/index-CSV9pvLE.js.map

### asana.com

**Source maps found:** 18 — https://www.google.com/recaptcha/enterprise.js?render=6Lf1FtQZAAAAAKGsW3JoCdtQfzfCb2umWbEoyOjE.map, https://asana.com/_next/static/chunks/polyfills-42372ed130431b0a.js?dpl=3730b23f82c18173d839238475eb3bdbd302b449b340c95b17f0da39625431a1366230306238366239656161323032653830386531633763.map, https://asana.com/_next/static/chunks/99283-197d890b88e8395a.js?dpl=3730b23f82c18173d839238475eb3bdbd302b449b340c95b17f0da39625431a1366230306238366239656161323032653830386531633763.map, https://asana.com/_next/static/chunks/59643-baacc11ca780467e.js?dpl=3730b23f82c18173d839238475eb3bdbd302b449b340c95b17f0da39625431a1366230306238366239656161323032653830386531633763.map, https://asana.com/_next/static/chunks/34013-23a783415d5a4b58.js?dpl=3730b23f82c18173d839238475eb3bdbd302b449b340c95b17f0da39625431a1366230306238366239656161323032653830386531633763.map

### cloudinary.com

**Source maps found:** 2 — https://cloudinary.com/wp-content/themes/cld-2021/assets/js/jquery-3.4.1.min.js?ver=3.4.1.map, https://cloudinary.com/wp-content/themes/cld-2021/assets/js/bootstrap.min.js?ver=4.3.1.map

### elementor.com

**Source maps found:** 3 — https://elementor.com/wp-content/plugins/weglot/dist/front-js.js?ver=6.4.3.map, https://elementor.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1.map, https://elementor.com/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1.map

### expressvpn.com

**Source maps found:** 2 — https://expressvpn.com/wp-ws-cache/themes/expressvpn/assets/js/general.js?ver=1795175356.map, https://expressvpn.com/wp-ws-cache/themes/expressvpn/assets/js/swiperJs.js?ver=1795175363.map

### fivetran.com

**Source maps found:** 2 — https://d3e54v103j8qbb.cloudfront.net/js/jquery-3.5.1.min.dc5e7f18c8.js?site=6130fa1501794ed4d11867ba.map, https://fivetran-com.s3.amazonaws.com/js/scripts.js?58.map

### gearset.com

**Source maps found:** 5 — https://cmp.osano.com/6okapU34JmZx4cWG/4693432c-ab0c-40c3-a4a1-99cc77801085/osano.js.map, https://gearset.com/assets/index-CD8xx4zG.js.map, https://www.google.com/recaptcha/api.js?render=6LdgPY4oAAAAAPSJC_kJKTNKk3BKUCF8qmpeAYaI.map, https://gearset.com/assets/polyfills-legacy-D5B3c9U_.js.map, https://gearset.com/assets/index-legacy-C5NpeDAs.js.map

### glean.com

**Source maps found:** 3 — https://cmp.osano.com/16CXuzUWVmvBc5GOi/2cb189d0-529f-40a5-9353-12a933c5cb8e/osano.js.map, https://cdn.jsdelivr.net/npm/gsap@3.13.0/dist/gsap.min.js.map, https://cdn.jsdelivr.net/npm/gsap@3.13.0/dist/Flip.min.js.map

### ibotta.com

**Source maps found:** 12 — https://ibotta.com/corporate-assets/_next/static/chunks/1dd3208c-44feaec1dc44dc9f.js.map, https://ibotta.com/corporate-assets/_next/static/chunks/528-bdfc7515b5261e3b.js.map, https://ibotta.com/corporate-assets/_next/static/chunks/main-app-6f35475d6b240635.js.map, https://ibotta.com/corporate-assets/_next/static/chunks/154-cea128311a5f1ae0.js.map, https://ibotta.com/corporate-assets/_next/static/chunks/145-cec10e57a4c8c455.js.map

### klaviyo.com

**Source maps found:** 2 — https://transcend-cdn.com/cm/f3c1005b-8270-469c-85a4-81fe6c9b70e7/airgap.js?cacheBust=1795269265864.map, https://www.google.com/recaptcha/api.js?render=6Lc-vxErAAAAAKq79hQ2CEfaUCBld0hVMtRboXtB&amp;hl=en-US.map



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
- updated_cves: 0
