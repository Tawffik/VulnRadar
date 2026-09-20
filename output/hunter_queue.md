# VulnRadar Hunter Queue

Generated: 2026-09-20T13:29:21+00:00
Targets loaded: 1
New KEV entries this run: 1716
Updated KEV entries this run (ransomware flag changed): 0
Entries below (target-matched or known-ransomware): 362

> A CVE affecting a matched technology is a candidate needing manual version verification, not a confirmed vulnerability. This project does not run exploitation — see 'Next Safe Action' on each entry.

## 1. CVE-2021-42013 — NEW

**Vendor / Product:** Apache / HTTP Server
**Name:** Apache HTTP Server Path Traversal Vulnerability
**Matched target(s):** example.com
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Apache HTTP Server contains a path traversal vulnerability that allows an attacker to perform remote code execution if files outside directories configured by Alias-like directives are not under default require all denied or if CGI scripts are enabled. This CVE ID resolves an incomplete patch for CVE-2021-41773.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 2. CVE-2021-41773 — NEW

**Vendor / Product:** Apache / HTTP Server
**Name:** Apache HTTP Server Path Traversal Vulnerability
**Matched target(s):** example.com
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Apache HTTP Server contains a path traversal vulnerability that allows an attacker to perform remote code execution if files outside directories configured by Alias-like directives are not under default �require all denied� or if CGI scripts are enabled. The original patch issued under this CVE ID is insufficient, please review remediation information under CVE-2021-42013.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 3. CVE-2024-38475 — NEW

**Vendor / Product:** Apache / HTTP Server
**Name:** Apache HTTP Server Improper Escaping of Output Vulnerability
**Matched target(s):** example.com
**Known ransomware use:** Unknown
**Date added to KEV:** 2025-05-01
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** Apache HTTP Server contains an improper escaping of output vulnerability in mod_rewrite that allows an attacker to map URLs to filesystem locations that are permitted to be served by the server but are not intentionally/directly reachable by any URL, resulting in code execution or source code disclosure.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 4. CVE-2019-0211 — NEW

**Vendor / Product:** Apache / HTTP Server
**Name:** Apache HTTP Server Privilege Escalation Vulnerability
**Matched target(s):** example.com
**Known ransomware use:** Unknown
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Apache HTTP Server, with MPM event, worker or prefork, code executing in less-privileged child processes or threads (including scripts executed by an in-process scripting interpreter) could execute code with the privileges of the parent process (usually root) by manipulating the scoreboard.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 5. CVE-2026-59310 — NEW

**Vendor / Product:** Broadcom / VMware vCenter
**Name:** Broadcom VMware vCenter Path Traversal Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-08-18
**CISA required action:** Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

**Description:** Broadcom VMware vCenter contains a path traversal vulnerability which could allow a threat actor with network access to vCenter to execute arbitrary code.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 6. CVE-2026-20316 — NEW

**Vendor / Product:** Cisco / Secure Firewall Management Center (FMC)
**Name:** Cisco Secure Firewall Management Center Use of Hard-coded Password Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-07-29
**CISA required action:** Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

**Description:** Cisco Secure Firewall Management Center (FMC) formerly known as Firepower Management Center contains a use of hard-coded password vulnerability that could allow an unauthenticated, remote attacker to log in to an affected device using a low-privileged account to access sensitive data within the impacted systems.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 7. CVE-2026-15409 — NEW

**Vendor / Product:** SonicWall / SMA1000 Appliances
**Name:** SonicWall SMA1000 Appliances Server-Side Request Forgery Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-07-14
**CISA required action:** Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

**Description:** SonicWall SMA1000 Appliances contain a server-side request forgery vulnerability that could allow a remote unauthenticated attacker to potentially cause the appliance to make requests to unintended location.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 8. CVE-2026-15410 — NEW

**Vendor / Product:** SonicWall / SMA1000 Appliances
**Name:** SonicWall SMA1000 Appliances Code Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-07-14
**CISA required action:** Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

**Description:** SonicWall SMA1000 Appliances contain a code injection vulnerability which in specific conditions could potentially enable a remote authenticated attacker as administrator to execute arbitrary OS commands.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 9. CVE-2026-45659 — NEW

**Vendor / Product:** Microsoft / SharePoint Server
**Name:** Microsoft SharePoint Server Deserialization of Untrusted Data Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-07-01
**CISA required action:** Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

**Description:** Microsoft SharePoint Server contains a deserialization of untrusted data vulnerability which allows an authorized attacker to execute code over a network.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 10. CVE-2026-12569 — NEW

**Vendor / Product:** PTC / Windchill and FlexPLM
**Name:** PTC Windchill and FlexPLM Improper Input Validation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-06-25
**CISA required action:** Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

**Description:** PTC Windchill and FlexPLM contains an improper input validation vulnerability allowing an unauthenticated, remote attacker to execute arbitrary code by sending a malicious request to the network.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 11. CVE-2026-35273 — NEW

**Vendor / Product:** Oracle / PeopleSoft Enterprise PeopleTools
**Name:** Oracle PeopleSoft Enterprise PeopleTools Missing Authentication for Critical Function Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-06-12
**CISA required action:** Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.

**Description:** Oracle PeopleSoft Enterprise PeopleTools contains a missing authentication for critical function vulnerability which could allow an unauthenticated attacker to obtain takeover of PeopleSoft Enterprise PeopleTools.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 12. CVE-2026-50751 — NEW

**Vendor / Product:** Check Point / Security Gateway
**Name:** Check Point Security Gateway Improper Authentication Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-06-08
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** Check Point Security Gateway contains an improper authentication vulnerability in IKEv1 key exchange that could allow an unauthenticated remote attacker to bypass user authentication and establish a remote access VPN connection without a valid user password.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 13. CVE-2026-0257 — NEW

**Vendor / Product:** Palo Alto Networks / PAN-OS
**Name:** Palo Alto Networks PAN-OS Authentication Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-05-29
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** Palo Alto Networks PAN-OS contains an authentication bypass vulnerability that allows attackers to bypass security restrictions and establish an unauthorized VPN connection.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 14. CVE-2026-48027 — NEW

**Vendor / Product:** Nx / Nx Console
**Name:** Nx Console Embedded Malicious Code Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-05-27
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** Nx Console contains an embedded malicious code vulnerability that allowed a malicious version of Nx Console to be published. The compromised extension fetched an obfuscated payload that could harvested credentials from multiple sources on disk and in memory.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 15. CVE-2026-45321 — NEW

**Vendor / Product:** TanStack / TanStack
**Name:** TanStack Unspecified Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-05-27
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** TanStack contains an unspecified vulnerability that allowed malicious versions of the product to be published to the npm registry to publish credential-stealing malware under a trusted identity.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 16. CVE-2026-41940 — NEW

**Vendor / Product:** WebPros / cPanel & WHM and WP2 (WordPress Squared)
**Name:** WebPros cPanel & WHM and WP2 (WordPress Squared) Missing Authentication for Critical Function Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-04-30
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** WebPros cPanel & WHM (WebHost Manager) and WP2 (WordPress Squared) contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 17. CVE-2024-1708 — NEW

**Vendor / Product:** ConnectWise / ScreenConnect
**Name:** ConnectWise ScreenConnect Path Traversal Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-04-28
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** ConnectWise ScreenConnect contains a path traversal vulnerability which could allow an attacker to execute remote code or directly impact confidential data and critical systems.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 18. CVE-2024-57728 — NEW

**Vendor / Product:** SimpleHelp / SimpleHelp
**Name:** SimpleHelp Path Traversal Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-04-24
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** SimpleHelp contains a path traversal vulnerability that allows admin users to upload arbitrary files anywhere on the file system by uploading a crafted zip file (i.e. zip slip). This can be exploited to execute arbitrary code on the host in the context of the SimpleHelp server user.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 19. CVE-2024-57726 — NEW

**Vendor / Product:** SimpleHelp / SimpleHelp
**Name:** SimpleHelp Missing Authorization Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-04-24
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** SimpleHelp contains a missing authorization vulnerability that could allow low-privileged technicians to create API keys with excessive permissions. These API keys can be used to escalate privileges to the server admin role.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 20. CVE-2026-33825 — NEW

**Vendor / Product:** Microsoft / Defender
**Name:** Microsoft Defender Insufficient Granularity of Access Control Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-04-22
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** Microsoft Defender contains an insufficient granularity of access control vulnerability that could allow an authorized attacker to escalate privileges locally.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 21. CVE-2023-27351 — NEW

**Vendor / Product:** PaperCut / NG/MF
**Name:** PaperCut NG/MF Improper Authentication Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-04-20
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** PaperCut NG/MF contains an improper authentication vulnerability that could allow remote attackers to bypass authentication on affected installations via the SecurityRequestFilter class.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 22. CVE-2024-27199 — NEW

**Vendor / Product:** JetBrains / TeamCity
**Name:** JetBrains TeamCity Relative Path Traversal Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-04-20
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** JetBrains TeamCity contains a relative path traversal vulnerability that could allow limited admin actions to be performed.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 23. CVE-2025-60710 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Link Following Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-04-13
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** Microsoft Windows contains a link following vulnerability that allows for privilege escalation

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 24. CVE-2023-21529 — NEW

**Vendor / Product:** Microsoft / Exchange Server
**Name:** Microsoft Exchange Server Deserialization of Untrusted Data Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-04-13
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** Microsoft Exchange Server contains a deserialization of untrusted data that allows an authenticated attacker to achieve remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 25. CVE-2026-20131 — NEW

**Vendor / Product:** Cisco / Secure Firewall Management Center (FMC)
**Name:** Cisco Secure Firewall Management Center (FMC) Software and Cisco Security Cloud Control (SCC) Firewall Management Deserialization of Untrusted Data Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-03-19
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** Cisco Secure Firewall Management Center (FMC) Software and Cisco Security Cloud Control (SCC) Firewall Management contain a deserialization of untrusted data vulnerability in the web-based management interface that could allow an unauthenticated, remote attacker to execute arbitrary Java code as root on an affected device.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 26. CVE-2025-26399 — NEW

**Vendor / Product:** SolarWinds / Web Help Desk
**Name:** SolarWinds Web Help Desk Deserialization of Untrusted Data Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-03-09
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** SolarWinds Web Help Desk contain a deserialization of untrusted data vulnerability in AjaxProxy that could allow an attacker to run commands on the host machine.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 27. CVE-2026-1731 — NEW

**Vendor / Product:** BeyondTrust / Remote Support (RS) and Privileged Remote Access (PRA)
**Name:** BeyondTrust Remote Support (RS) and Privileged Remote Access (PRA) OS Command Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-02-13
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** BeyondTrust Remote Support (RS) and Privileged Remote Access (PRA)contain an OS command injection vulnerability. Successful exploitation could allow an unauthenticated remote attacker to execute operating system commands in the context of the site user. Successful exploitation requires no authentication or user interaction and may lead to system compromise, including unauthorized access, data exfiltration, and service disruption.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 28. CVE-2026-24423 — NEW

**Vendor / Product:** SmarterTools / SmarterMail
**Name:** SmarterTools SmarterMail Missing Authentication for Critical Function Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-02-05
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** SmarterTools SmarterMail contains a missing authentication for critical function vulnerability in the ConnectToHub API method. This could allow the attacker to point the SmarterMail instance to a malicious HTTP server which serves the malicious OS command and could lead to command execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 29. CVE-2025-52691 — NEW

**Vendor / Product:** SmarterTools / SmarterMail
**Name:** SmarterTools SmarterMail Unrestricted Upload of File with Dangerous Type Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-01-26
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** SmarterTools SmarterMail contains an unrestricted upload of file with dangerous type vulnerability that could allow an unauthenticated attacker to upload arbitrary files to any location on the mail server, potentially enabling remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 30. CVE-2026-23760 — NEW

**Vendor / Product:** SmarterTools / SmarterMail
**Name:** SmarterTools SmarterMail Authentication Bypass Using an Alternate Path or Channel Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2026-01-26
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** SmarterTools SmarterMail contains an authentication bypass using an alternate path or channel vulnerability in the password reset API. The force-reset-password endpoint permits anonymous requests and fails to verify the existing password or a reset token when resetting system administrator accounts. This could allow an unauthenticated attacker to supply a target administrator username and a new password to reset the account, resulting in full administrative compromise of the SmarterMail instance.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 31. CVE-2025-14733 — NEW

**Vendor / Product:** WatchGuard / Firebox
**Name:** WatchGuard Firebox Out of Bounds Write Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-12-19
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** WatchGuard Fireware OS iked process contains an out of bounds write vulnerability in the OS iked process. This vulnerability may allow a remote unauthenticated attacker to execute arbitrary code and affects both the mobile user VPN with IKEv2 and the branch office VPN using IKEv2 when configured with a dynamic gateway peer.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 32. CVE-2025-55182 — NEW

**Vendor / Product:** Meta / React Server Components
**Name:** Meta React Server Components Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-12-05
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** Meta React Server Components contains a remote code execution vulnerability that could allow unauthenticated remote code execution by exploiting a flaw in how React decodes payloads sent to React Server Function endpoints. Please note CVE-2025-66478 has been rejected, but it is associated with CVE-2025- 55182.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 33. CVE-2025-61884 — NEW

**Vendor / Product:** Oracle / E-Business Suite
**Name:** Oracle E-Business Suite Server-Side Request Forgery (SSRF) Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-10-20
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** Oracle E-Business Suite contains a server-side request forgery (SSRF) vulnerability in the Runtime component of Oracle Configurator. This vulnerability is remotely exploitable without authentication.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 34. CVE-2021-43226 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-10-06
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** Microsoft Windows Common Log File System Driver contains a privilege escalation vulnerability that could allow a local, privileged attacker to bypass certain security mechanisms.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 35. CVE-2025-61882 — NEW

**Vendor / Product:** Oracle / E-Business Suite
**Name:** Oracle E-Business Suite Unspecified Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-10-06
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** Oracle E-Business Suite contains an unspecified vulnerability in the BI Publisher Integration component. The vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Concurrent Processing. Successful attacks can result in takeover of Oracle Concurrent Processing.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 36. CVE-2025-10035 — NEW

**Vendor / Product:** Fortra / GoAnywhere MFT
**Name:** Fortra GoAnywhere MFT Deserialization of Untrusted Data Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-09-29
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** Fortra GoAnywhere MFT contains a deserialization of untrusted data vulnerability allows an actor with a validly forged license response signature to deserialize an arbitrary actor-controlled object, possibly leading to command injection.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 37. CVE-2025-8088 — NEW

**Vendor / Product:** RARLAB / WinRAR
**Name:** RARLAB WinRAR Path Traversal Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-08-12
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** RARLAB WinRAR contains a path traversal vulnerability affecting the Windows version of WinRAR. This vulnerability could allow an attacker to execute arbitrary code by crafting malicious archive files.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 38. CVE-2025-49704 — NEW

**Vendor / Product:** Microsoft / SharePoint
**Name:** Microsoft SharePoint Code Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-07-22
**CISA required action:** Disconnect public-facing versions of SharePoint Server that have reached their end-of-life (EOL) or end-of-service (EOS) to include SharePoint Server 2013 and earlier versions. For supported versions, please follow the mitigations according to CISA (URL listed below in Notes) and vendor instructions (URL listed below in Notes). Adhere to the applicable BOD 22-01 guidance for cloud services or discontinue use of the product if mitigations are not available.

**Description:** Microsoft SharePoint contains a code injection vulnerability that could allow an authorized attacker to execute code over a network. This vulnerability could be chained with CVE-2025-49706. CVE-2025-53770 is a patch bypass for CVE-2025-49704, and the updates for CVE-2025-53770 include more robust protection than those for CVE-2025-49704.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 39. CVE-2025-49706 — NEW

**Vendor / Product:** Microsoft / SharePoint
**Name:** Microsoft SharePoint Improper Authentication Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-07-22
**CISA required action:** Disconnect public-facing versions of SharePoint Server that have reached their end-of-life (EOL) or end-of-service (EOS) to include SharePoint Server 2013 and earlier versions. For supported versions, please follow the mitigations according to CISA (URL listed below in Notes) and vendor instructions (URL listed below in Notes). Adhere to the applicable BOD 22-01 guidance for cloud services or discontinue use of the product if mitigations are not available.

**Description:** Microsoft SharePoint contains an improper authentication vulnerability that allows an authorized attacker to perform spoofing over a network. Successfully exploitation could allow an attacker to view sensitive information and make some changes to disclosed information. This vulnerability could be chained with CVE-2025-49704. CVE-2025-53771 is a patch bypass for CVE-2025-49706, and the updates for CVE-2025-53771 include more robust protection than those for CVE-2025-49706.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 40. CVE-2025-53770 — NEW

**Vendor / Product:** Microsoft / SharePoint
**Name:** Microsoft SharePoint Deserialization of Untrusted Data Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-07-20
**CISA required action:** Disconnect public-facing versions of SharePoint Server that have reached their end-of-life (EOL) or end-of-service (EOS) to include SharePoint Server 2013 and earlier versions. For supported versions, please follow the mitigations according to CISA (URL listed below in Notes) and vendor instructions (URL listed below in Notes). Adhere to the applicable BOD 22-01 guidance for cloud services or discontinue use of the product if mitigations are not available.

**Description:** Microsoft SharePoint Server on-premises contains a deserialization of untrusted data vulnerability that could allow an unauthorized attacker to execute code over a network. This vulnerability could be chained with CVE-2025-53771. CVE-2025-53770 is a patch bypass for CVE-2025-49704, and the updates for CVE-2025-53770 include more robust protection than those for CVE-2025-49704.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 41. CVE-2025-5777 — NEW

**Vendor / Product:** Citrix / NetScaler ADC and Gateway
**Name:** Citrix NetScaler ADC and Gateway Out-of-Bounds Read Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-07-10
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** Citrix NetScaler ADC and Gateway contain an out-of-bounds read vulnerability due to insufficient input validation. This vulnerability can lead to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 42. CVE-2019-6693 — NEW

**Vendor / Product:** Fortinet / FortiOS
**Name:** Fortinet FortiOS Use of Hard-Coded Credentials Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-06-25
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** Fortinet FortiOS contains a use of hard-coded credentials vulnerability that could allow an attacker to cipher sensitive data in FortiOS configuration backup file via knowledge of the hard-coded key.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 43. CVE-2025-42999 — NEW

**Vendor / Product:** SAP / NetWeaver
**Name:** SAP NetWeaver Deserialization Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-05-15
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** SAP NetWeaver Visual Composer Metadata Uploader contains a deserialization vulnerability that allows a privileged attacker to compromise the confidentiality, integrity, and availability of the host system by deserializing untrusted or malicious content.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 44. CVE-2025-3248 — NEW

**Vendor / Product:** Langflow / Langflow
**Name:** Langflow Missing Authentication Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-05-05
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** Langflow contains a missing authentication vulnerability in the /api/v1/validate/code endpoint that allows a remote, unauthenticated attacker to execute arbitrary code via crafted HTTP requests.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 45. CVE-2025-31324 — NEW

**Vendor / Product:** SAP / NetWeaver
**Name:** SAP NetWeaver Unrestricted File Upload Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-04-29
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** SAP NetWeaver Visual Composer Metadata Uploader contains an unrestricted file upload vulnerability that allows an unauthenticated agent to upload potentially malicious executable binaries.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 46. CVE-2025-29824 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Common Log File System (CLFS) Driver Use-After-Free Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-04-08
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** Microsoft Windows Common Log File System (CLFS) Driver contains a use-after-free vulnerability that allows an authorized attacker to elevate privileges locally.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 47. CVE-2025-31161 — NEW

**Vendor / Product:** CrushFTP / CrushFTP
**Name:** CrushFTP Authentication Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-04-07
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** CrushFTP contains an authentication bypass vulnerability in the HTTP authorization header that allows a remote unauthenticated attacker to authenticate to any known or guessable user account (e.g., crushadmin), potentially leading to a full compromise.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 48. CVE-2025-22457 — NEW

**Vendor / Product:** Ivanti / Connect Secure, Policy Secure, and ZTA Gateways
**Name:** Ivanti Connect Secure, Policy Secure, and ZTA Gateways Stack-Based Buffer Overflow Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-04-04
**CISA required action:** Apply mitigations as set forth in the CISA instructions linked below.

**Description:** Ivanti Connect Secure, Policy Secure, and ZTA Gateways contains a stack-based buffer overflow vulnerability that allows a remote unauthenticated attacker to achieve remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 49. CVE-2025-24472 — NEW

**Vendor / Product:** Fortinet / FortiOS and FortiProxy
**Name:** Fortinet FortiOS and FortiProxy Authentication Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-03-18
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** Fortinet FortiOS and FortiProxy contain an authentication bypass vulnerability that allows a remote attacker to gain super-admin privileges via crafted CSF proxy requests.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 50. CVE-2025-26633 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Management Console (MMC) Improper Neutralization Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-03-11
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** Microsoft Windows Management Console (MMC) contains an improper neutralization vulnerability that allows an unauthorized attacker to bypass a security feature locally.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 51. CVE-2025-22225 — NEW

**Vendor / Product:** VMware / ESXi
**Name:** VMware ESXi Arbitrary Write Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-03-04
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** VMware ESXi contains an arbitrary write vulnerability. Successful exploitation allows an attacker with privileges within the VMX process to trigger an arbitrary kernel write leading to an escape of the sandbox.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 52. CVE-2018-8639 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Win32k Improper Resource Shutdown or Release Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-03-03
**CISA required action:** Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.

**Description:** Microsoft Windows Win32k contains an improper resource shutdown or release vulnerability that allows for local, authenticated privilege escalation. An attacker who successfully exploited this vulnerability could run arbitrary code in kernel mode.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 53. CVE-2024-53704 — NEW

**Vendor / Product:** SonicWall / SonicOS
**Name:** SonicWall SonicOS SSLVPN Improper Authentication Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-02-18
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** SonicWall SonicOS contains an improper authentication vulnerability in the SSLVPN authentication mechanism that allows a remote attacker to bypass authentication.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 54. CVE-2024-57727 — NEW

**Vendor / Product:** SimpleHelp / SimpleHelp
**Name:** SimpleHelp Path Traversal Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-02-13
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** SimpleHelp remote support software contains multiple path traversal vulnerabilities that allow unauthenticated remote attackers to download arbitrary files from the SimpleHelp host via crafted HTTP requests. These files may include server configuration files and hashed user passwords.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 55. CVE-2020-29574 — NEW

**Vendor / Product:** Sophos / CyberoamOS
**Name:** CyberoamOS (CROS) SQL Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-02-06
**CISA required action:** The impacted product is end-of-life (EoL) and/or end-of-service (EoS). Users should discontinue utilization of the product.

**Description:** CyberoamOS (CROS) contains a SQL injection vulnerability in the WebAdmin that allows an unauthenticated attacker to execute arbitrary SQL statements remotely.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 56. CVE-2025-23006 — NEW

**Vendor / Product:** SonicWall / SMA1000 Appliances
**Name:** SonicWall SMA1000 Appliances Deserialization Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-01-24
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** SonicWall SMA1000 Appliance Management Console (AMC) and Central Management Console (CMC) contain a deserialization of untrusted data vulnerability, which can enable a remote, unauthenticated attacker to execute arbitrary OS commands.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 57. CVE-2024-55591 — NEW

**Vendor / Product:** Fortinet / FortiOS and FortiProxy
**Name:** Fortinet FortiOS and FortiProxy Authentication Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-01-14
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Fortinet FortiOS and FortiProxy contain an authentication bypass vulnerability that may allow an unauthenticated, remote attacker to gain super-admin privileges via crafted requests to Node.js websocket module.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 58. CVE-2023-48365 — NEW

**Vendor / Product:** Qlik / Sense
**Name:** Qlik Sense HTTP Tunneling Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-01-13
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Qlik Sense contains an HTTP tunneling vulnerability that allows an attacker to escalate privileges and execute HTTP requests on the backend server hosting the software.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 59. CVE-2025-0282 — NEW

**Vendor / Product:** Ivanti / Connect Secure, Policy Secure, and ZTA Gateways
**Name:** Ivanti Connect Secure, Policy Secure, and ZTA Gateways Stack-Based Buffer Overflow Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-01-08
**CISA required action:** Apply mitigations as set forth in the CISA instructions linked below to include conducting hunt activities, taking remediation actions if applicable, and applying updates prior to returning a device to service.

**Description:** Ivanti Connect Secure, Policy Secure, and ZTA Gateways contain a stack-based buffer overflow which can lead to unauthenticated remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 60. CVE-2024-55550 — NEW

**Vendor / Product:** Mitel / MiCollab
**Name:** Mitel MiCollab Path Traversal Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-01-07
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Mitel MiCollab contains a path traversal vulnerability that could allow an authenticated attacker with administrative privileges to read local files within the system due to insufficient input sanitization. This vulnerability can be chained with CVE-2024-41713, which allows an unauthenticated, remote attacker to read arbitrary files on the server.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 61. CVE-2024-41713 — NEW

**Vendor / Product:** Mitel / MiCollab
**Name:** Mitel MiCollab Path Traversal Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2025-01-07
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Mitel MiCollab contains a path traversal vulnerability that could allow an attacker to gain unauthorized and unauthenticated access. This vulnerability can be chained with CVE-2024-55550, which allows an unauthenticated, remote attacker to read arbitrary files on the server.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 62. CVE-2024-55956 — NEW

**Vendor / Product:** Cleo / Multiple Products
**Name:** Cleo Multiple Products Unauthenticated File Upload Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-12-17
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Cleo Harmony, VLTrader, and LexiCom, which are managed file transfer products, contain an unrestricted file upload vulnerability that could allow an unauthenticated user to import and execute arbitrary bash or PowerShell commands on the host system by leveraging the default settings of the Autorun directory.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 63. CVE-2024-50623 — NEW

**Vendor / Product:** Cleo / Multiple Products
**Name:** Cleo Multiple Products Unrestricted File Upload Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-12-13
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Cleo Harmony, VLTrader, and LexiCom, which are managed file transfer products, contain an unrestricted file upload and download vulnerability that can lead to remote code execution with elevated privileges.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 64. CVE-2024-51378 — NEW

**Vendor / Product:** CyberPersons / CyberPanel
**Name:** CyberPanel Incorrect Default Permissions Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-12-04
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** CyberPanel contains an incorrect default permissions vulnerability that allows for authentication bypass and the execution of arbitrary commands using shell metacharacters in the statusfile property.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 65. CVE-2024-11667 — NEW

**Vendor / Product:** Zyxel / Multiple Firewalls
**Name:** Zyxel Multiple Firewalls Path Traversal Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-12-03
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Multiple Zyxel firewalls contain a path traversal vulnerability in the web management interface that could allow an attacker to download or upload files via a crafted URL.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 66. CVE-2023-28461 — NEW

**Vendor / Product:** Array Networks / AG/vxAG ArrayOS
**Name:** Array Networks AG and vxAG ArrayOS Missing Authentication for Critical Function Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-11-25
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Array Networks AG and vxAG ArrayOS contain a missing authentication for critical function vulnerability that allows an attacker to read local files and execute code on the SSL VPN gateway.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 67. CVE-2024-9474 — NEW

**Vendor / Product:** Palo Alto Networks / PAN-OS
**Name:** Palo Alto Networks PAN-OS Management Interface OS Command Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-11-18
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable. Additionally, the management interfaces for affected devices should not be exposed to untrusted networks, including the internet.

**Description:** Palo Alto Networks PAN-OS contains an OS command injection vulnerability that allows for privilege escalation through the web-based management interface for several PAN products, including firewalls and VPN concentrators.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 68. CVE-2024-0012 — NEW

**Vendor / Product:** Palo Alto Networks / PAN-OS
**Name:** Palo Alto Networks PAN-OS Management Interface Authentication Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-11-18
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable. Additionally, management interface for affected devices should not be exposed to untrusted networks, including the internet.

**Description:** Palo Alto Networks PAN-OS contains an authentication bypass vulnerability in the web-based management interface for several PAN-OS products, including firewalls and VPN concentrators.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 69. CVE-2024-49039 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Task Scheduler Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-11-12
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Microsoft Windows Task Scheduler contains a privilege escalation vulnerability that can allow an attacker-provided, local application to escalate privileges outside of its AppContainer, and access privileged RPC functions.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 70. CVE-2024-51567 — NEW

**Vendor / Product:** CyberPersons / CyberPanel
**Name:** CyberPanel Incorrect Default Permissions Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-11-07
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** CyberPanel contains an incorrect default permissions vulnerability that allows a remote, unauthenticated attacker to execute commands as root.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 71. CVE-2024-38094 — NEW

**Vendor / Product:** Microsoft / SharePoint
**Name:** Microsoft SharePoint Deserialization Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-10-22
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Microsoft SharePoint contains a deserialization vulnerability that allows for remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 72. CVE-2024-40711 — NEW

**Vendor / Product:** Veeam / Backup & Replication
**Name:** Veeam Backup and Replication Deserialization Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-10-17
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Veeam Backup and Replication contains a deserialization vulnerability allowing an unauthenticated user to perform remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 73. CVE-2024-9680 — NEW

**Vendor / Product:** Mozilla / Firefox
**Name:** Mozilla Firefox Use-After-Free Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-10-15
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Mozilla Firefox and Firefox ESR contain a use-after-free vulnerability in Animation timelines that allows for code execution in the content process.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 74. CVE-2024-30088 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Kernel TOCTOU Race Condition Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-10-15
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Microsoft Windows Kernel contains a time-of-check to time-of-use (TOCTOU) race condition vulnerability that could allow for privilege escalation.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 75. CVE-2020-0618 — NEW

**Vendor / Product:** Microsoft / SQL Server
**Name:** Microsoft SQL Server Reporting Services Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-09-18
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Microsoft SQL Server Reporting Services contains a deserialization vulnerability when handling page requests incorrectly. An authenticated attacker can exploit this vulnerability to execute code in the context of the Report Server service account.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 76. CVE-2024-6670 — NEW

**Vendor / Product:** Progress / WhatsUp Gold
**Name:** Progress WhatsUp Gold SQL Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-09-16
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Progress WhatsUp Gold contains a SQL injection vulnerability that allows an unauthenticated attacker to retrieve the user's encrypted password if the application is configured with only a single user.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 77. CVE-2024-40766 — NEW

**Vendor / Product:** SonicWall / SonicOS
**Name:** SonicWall SonicOS Improper Access Control Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-09-09
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** SonicWall SonicOS contains an improper access control vulnerability that could lead to unauthorized resource access and, under certain conditions, may cause the firewall to crash.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 78. CVE-2017-1000253 — NEW

**Vendor / Product:** Linux / Kernel
**Name:** Linux Kernel PIE Stack Buffer Corruption Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-09-09
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Linux kernel contains a position-independent executable (PIE) stack buffer corruption vulnerability in load_elf_ binary() that allows a local attacker to escalate privileges.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 79. CVE-2024-23897 — NEW

**Vendor / Product:** Jenkins / Jenkins Command Line Interface (CLI)
**Name:** Jenkins Command Line Interface (CLI) Path Traversal Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-08-19
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Jenkins Command Line Interface (CLI) contains a path traversal vulnerability that allows attackers limited read access to certain files, which can lead to code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 80. CVE-2024-37085 — NEW

**Vendor / Product:** VMware / ESXi
**Name:** VMware ESXi Authentication Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-07-30
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** VMware ESXi contains an authentication bypass vulnerability. A malicious actor with sufficient Active Directory (AD) permissions can gain full access to an ESXi host that was previously configured to use AD for user management by re-creating the configured AD group ('ESXi Admins' by default) after it was deleted from AD.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 81. CVE-2024-23692 — NEW

**Vendor / Product:** Rejetto / HTTP File Server
**Name:** Rejetto HTTP File Server Improper Neutralization of Special Elements Used in a Template Engine Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-07-09
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Rejetto HTTP File Server contains an improper neutralization of special elements used in a template engine vulnerability. This allows a remote, unauthenticated attacker to execute commands on the affected system by sending a specially crafted HTTP request.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 82. CVE-2024-26169 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Error Reporting Service Improper Privilege Management Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-06-13
**CISA required action:** Apply updates per vendor instructions or discontinue use of the product if updates are unavailable.

**Description:** Microsoft Windows Error Reporting Service contains an improper privilege management vulnerability that allows a local attacker with user permissions to gain SYSTEM privileges.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 83. CVE-2024-4577 — NEW

**Vendor / Product:** PHP Group / PHP
**Name:** PHP-CGI OS Command Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-06-12
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** PHP, specifically Windows-based PHP used in CGI mode, contains an OS command injection vulnerability that allows for arbitrary code execution. This vulnerability is a patch bypass for CVE-2012-1823.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 84. CVE-2024-1086 — NEW

**Vendor / Product:** Linux / Kernel
**Name:** Linux Kernel Use-After-Free Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-05-30
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Linux kernel contains a use-after-free vulnerability in the netfilter: nf_tables component that allows an attacker to achieve local privilege escalation.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 85. CVE-2024-24919 — NEW

**Vendor / Product:** Check Point / Quantum Security Gateways
**Name:** Check Point Quantum Security Gateways Information Disclosure Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-05-30
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Check Point Quantum Security Gateways contain an unspecified information disclosure vulnerability. The vulnerability potentially allows an attacker to access information on Gateways connected to the internet, with IPSec VPN, Remote Access VPN or Mobile Access enabled. This issue affects several product lines from Check Point, including CloudGuard Network, Quantum Scalable Chassis, Quantum Security Gateways, and Quantum Spark Appliances.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 86. CVE-2023-43208 — NEW

**Vendor / Product:** NextGen Healthcare / Mirth Connect
**Name:** NextGen Healthcare Mirth Connect Deserialization of Untrusted Data Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-05-20
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** NextGen Healthcare Mirth Connect contains a deserialization of untrusted data vulnerability that allows for unauthenticated remote code execution via a specially crafted request.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 87. CVE-2024-30051 — NEW

**Vendor / Product:** Microsoft / DWM Core Library
**Name:** Microsoft DWM Core Library Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-05-14
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Microsoft DWM Core Library contains a privilege escalation vulnerability that allows an attacker to gain SYSTEM privileges.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 88. CVE-2024-3400 — NEW

**Vendor / Product:** Palo Alto Networks / PAN-OS
**Name:** Palo Alto Networks PAN-OS Command Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-04-12
**CISA required action:** Apply mitigations per vendor instructions as they become available. Otherwise, users with vulnerable versions of affected devices should enable Threat Prevention IDs available from the vendor. See the vendor bulletin for more details and a patch release schedule.

**Description:** Palo Alto Networks PAN-OS GlobalProtect feature contains a command injection vulnerability that allows an unauthenticated attacker to execute commands with root privileges on the firewall.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 89. CVE-2023-24955 — NEW

**Vendor / Product:** Microsoft / SharePoint Server
**Name:** Microsoft SharePoint Server Code Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-03-26
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Microsoft SharePoint Server contains a code injection vulnerability that allows an authenticated attacker with Site Owner privileges to execute code remotely.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 90. CVE-2021-44529 — NEW

**Vendor / Product:** Ivanti / Endpoint Manager Cloud Service Appliance (EPM CSA)
**Name:** Ivanti Endpoint Manager Cloud Service Appliance (EPM CSA) Code Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-03-25
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Ivanti Endpoint Manager Cloud Service Appliance (EPM CSA) contains a code injection vulnerability that allows an unauthenticated user to execute malicious code with limited permissions (nobody).

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 91. CVE-2023-48788 — NEW

**Vendor / Product:** Fortinet / FortiClient EMS
**Name:** Fortinet FortiClient EMS SQL Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-03-25
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Fortinet FortiClient EMS contains a SQL injection vulnerability that allows an unauthenticated attacker to execute commands as SYSTEM via specifically crafted requests.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 92. CVE-2024-27198 — NEW

**Vendor / Product:** JetBrains / TeamCity
**Name:** JetBrains TeamCity Authentication Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-03-07
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** JetBrains TeamCity contains an authentication bypass vulnerability that allows an attacker to perform admin actions.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 93. CVE-2024-21338 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Kernel Exposed IOCTL with Insufficient Access Control Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-03-04
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Microsoft Windows Kernel contains an exposed IOCTL with insufficient access control vulnerability within the IOCTL (input and output control) dispatcher in appid.sys that allows a local attacker to achieve privilege escalation.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 94. CVE-2024-1709 — NEW

**Vendor / Product:** ConnectWise / ScreenConnect
**Name:** ConnectWise ScreenConnect Authentication Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-02-22
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** ConnectWise ScreenConnect contains an authentication bypass vulnerability that allows an attacker with network access to the management interface to create a new, administrator-level account on affected devices.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 95. CVE-2020-3259 — NEW

**Vendor / Product:** Cisco / Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD)
**Name:** Cisco ASA and FTD Information Disclosure Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-02-15
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) contain an information disclosure vulnerability. An attacker could retrieve memory contents on an affected device, which could lead to the disclosure of confidential information due to a buffer tracking issue when the software parses invalid URLs that are requested from the web services interface. This vulnerability affects only specific AnyConnect and WebVPN configurations.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 96. CVE-2024-21412 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Internet Shortcut Files Security Feature Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-02-13
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Microsoft Windows Internet Shortcut Files contains an unspecified vulnerability that allows for a security feature bypass.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 97. CVE-2024-21762 — NEW

**Vendor / Product:** Fortinet / FortiOS
**Name:** Fortinet FortiOS Out-of-Bound Write Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-02-09
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Fortinet FortiOS contains an out-of-bound write vulnerability that allows a remote unauthenticated attacker to execute code or commands via specially crafted HTTP requests.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 98. CVE-2024-21893 — NEW

**Vendor / Product:** Ivanti / Connect Secure, Policy Secure, and Neurons
**Name:** Ivanti Connect Secure, Policy Secure, and Neurons Server-Side Request Forgery (SSRF) Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-01-31
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Ivanti Connect Secure (ICS, formerly known as Pulse Connect Secure), Ivanti Policy Secure, and Ivanti Neurons contain a server-side request forgery (SSRF) vulnerability in the SAML component that allows an attacker to access certain restricted resources without authentication.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 99. CVE-2023-22527 — NEW

**Vendor / Product:** Atlassian / Confluence Data Center and Server
**Name:** Atlassian Confluence Data Center and Server Template Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-01-24
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Atlassian Confluence Data Center and Server contain an unauthenticated OGNL template injection vulnerability that can lead to remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 100. CVE-2023-35082 — NEW

**Vendor / Product:** Ivanti / Endpoint Manager Mobile (EPMM) and MobileIron Core
**Name:** Ivanti Endpoint Manager Mobile (EPMM) and MobileIron Core Authentication Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-01-18
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Ivanti Endpoint Manager Mobile (EPMM) and MobileIron Core contain an authentication bypass vulnerability that allows unauthorized users to access restricted functionality or resources of the application.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 101. CVE-2023-29357 — NEW

**Vendor / Product:** Microsoft / SharePoint Server
**Name:** Microsoft SharePoint Server Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-01-10
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Microsoft SharePoint Server contains an unspecified vulnerability that allows an unauthenticated attacker, who has gained access to spoofed JWT authentication tokens, to use them for executing a network attack. This attack bypasses authentication, enabling the attacker to gain administrator privileges.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 102. CVE-2023-46805 — NEW

**Vendor / Product:** Ivanti / Connect Secure and Policy Secure
**Name:** Ivanti Connect Secure and Policy Secure Authentication Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-01-10
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Ivanti Connect Secure (ICS, formerly known as Pulse Connect Secure) and Ivanti Policy Secure gateways contain an authentication bypass vulnerability in the web component that allows an attacker to access restricted resources by bypassing control checks. This vulnerability can be leveraged in conjunction with CVE-2024-21887, a command injection vulnerability.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 103. CVE-2024-21887 — NEW

**Vendor / Product:** Ivanti / Connect Secure and Policy Secure
**Name:** Ivanti Connect Secure and Policy Secure Command Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-01-10
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Ivanti Connect Secure (ICS, formerly known as Pulse Connect Secure) and Ivanti Policy Secure contain a command injection vulnerability in the web components of these products, which can allow an authenticated administrator to send crafted requests to execute code on affected appliances. This vulnerability can be leveraged in conjunction with CVE-2023-46805, an authenticated bypass issue.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 104. CVE-2023-29300 — NEW

**Vendor / Product:** Adobe / ColdFusion
**Name:** Adobe ColdFusion Deserialization of Untrusted Data Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-01-08
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Adobe ColdFusion contains a deserialization of untrusted data vulnerability that allows for code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 105. CVE-2023-38203 — NEW

**Vendor / Product:** Adobe / ColdFusion
**Name:** Adobe ColdFusion Deserialization of Untrusted Data Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2024-01-08
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Adobe ColdFusion contains a deserialization of untrusted data vulnerability that allows for code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 106. CVE-2023-41266 — NEW

**Vendor / Product:** Qlik / Sense
**Name:** Qlik Sense Path Traversal Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-12-07
**CISA required action:** Apply remediations or mitigations per vendor instructions or discontinue use of the product if remediation or mitigations are unavailable.

**Description:** Qlik Sense contains a path traversal vulnerability that allows a remote, unauthenticated attacker to create an anonymous session by sending maliciously crafted HTTP requests. This anonymous session could allow the attacker to send further requests to unauthorized endpoints.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 107. CVE-2023-41265 — NEW

**Vendor / Product:** Qlik / Sense
**Name:** Qlik Sense HTTP Tunneling Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-12-07
**CISA required action:** Apply remediations or mitigations per vendor instructions or discontinue use of the product if remediation or mitigations are unavailable.

**Description:** Qlik Sense contains an HTTP tunneling vulnerability that allows an attacker to escalate privileges and execute HTTP requests on the backend server hosting the software.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 108. CVE-2023-47246 — NEW

**Vendor / Product:** SysAid / SysAid Server
**Name:** SysAid Server Path Traversal Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-11-13
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** SysAid Server (on-premises version) contains a path traversal vulnerability that leads to code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 109. CVE-2023-22518 — NEW

**Vendor / Product:** Atlassian / Confluence Data Center and Server
**Name:** Atlassian Confluence Data Center and Server Improper Authorization Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-11-07
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Atlassian Confluence Data Center and Server contain an improper authorization vulnerability that can result in significant data loss when exploited by an unauthenticated attacker. There is no impact on confidentiality since the attacker cannot exfiltrate any data.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 110. CVE-2023-46604 — NEW

**Vendor / Product:** Apache / ActiveMQ
**Name:** Apache ActiveMQ Deserialization of Untrusted Data Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-11-02
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Apache ActiveMQ contains a deserialization of untrusted data vulnerability that may allow a remote attacker with network access to a broker to run shell commands by manipulating serialized class types in the OpenWire protocol to cause the broker to instantiate any class on the classpath.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 111. CVE-2023-46747 — NEW

**Vendor / Product:** F5 / BIG-IP Configuration Utility
**Name:** F5 BIG-IP Configuration Utility Authentication Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-10-31
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** F5 BIG-IP Configuration utility contains an authentication bypass using an alternate path or channel vulnerability due to undisclosed requests that may allow an unauthenticated attacker with network access to the BIG-IP system through the management port and/or self IP addresses to execute system commands. This vulnerability can be used in conjunction with CVE-2023-46748.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 112. CVE-2023-4966 — NEW

**Vendor / Product:** Citrix / NetScaler ADC and NetScaler Gateway
**Name:** Citrix NetScaler ADC and NetScaler Gateway Buffer Overflow Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-10-18
**CISA required action:** Apply mitigations and kill all active and persistent sessions per vendor instructions [https://www.netscaler.com/blog/news/cve-2023-4966-critical-security-update-now-available-for-netscaler-adc-and-netscaler-gateway/] OR discontinue use of the product if mitigations are unavailable.

**Description:** Citrix NetScaler ADC and NetScaler Gateway contain a buffer overflow vulnerability that allows for sensitive information disclosure when configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) or AAA virtual server.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 113. CVE-2023-22515 — NEW

**Vendor / Product:** Atlassian / Confluence Data Center and Server
**Name:** Atlassian Confluence Data Center and Server Broken Access Control Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-10-05
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable. Check all affected Confluence instances for evidence of compromise per vendor instructions and report any positive findings to CISA.

**Description:** Atlassian Confluence Data Center and Server contains a broken access control vulnerability that allows an attacker to create unauthorized Confluence administrator accounts and access Confluence.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 114. CVE-2023-40044 — NEW

**Vendor / Product:** Progress / WS_FTP Server
**Name:** Progress WS_FTP Server Deserialization of Untrusted Data Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-10-05
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Progress WS_FTP Server contains a deserialization of untrusted data vulnerability in the Ad Hoc Transfer module that allows an authenticated attacker to execute remote commands on the underlying operating system.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 115. CVE-2023-42793 — NEW

**Vendor / Product:** JetBrains / TeamCity
**Name:** JetBrains TeamCity Authentication Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-10-04
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** JetBrains TeamCity contains an authentication bypass vulnerability that allows for remote code execution on TeamCity Server.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 116. CVE-2017-6884 — NEW

**Vendor / Product:** Zyxel / EMG2926 Routers
**Name:** Zyxel EMG2926 Routers Command Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-09-18
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Zyxel EMG2926 routers contain a command injection vulnerability located in the diagnostic tools, specifically the nslookup function. A malicious user may exploit numerous vectors to execute malicious commands on the router, such as the ping_ip parameter to the expert/maintenance/diagnostic/nslookup URI.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 117. CVE-2021-3129 — NEW

**Vendor / Product:** Laravel / Ignition
**Name:** Laravel Ignition File Upload Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-09-18
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Laravel Ignition contains a file upload vulnerability that allows unauthenticated remote attackers to execute malicious code due to insecure usage of file_get_contents() and file_put_contents().

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 118. CVE-2023-20269 — NEW

**Vendor / Product:** Cisco / Adaptive Security Appliance and Firepower Threat Defense
**Name:** Cisco Adaptive Security Appliance and Firepower Threat Defense Unauthorized Access Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-09-13
**CISA required action:** Apply mitigations per vendor instructions for group-lock and vpn-simultaneous-logins or discontinue use of the product for unsupported devices.

**Description:** Cisco Adaptive Security Appliance and Firepower Threat Defense contain an unauthorized access vulnerability that could allow an unauthenticated, remote attacker to conduct a brute force attack in an attempt to identify valid username and password combinations or establish a clientless SSL VPN session with an unauthorized user.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 119. CVE-2023-38831 — NEW

**Vendor / Product:** RARLAB / WinRAR
**Name:** RARLAB WinRAR Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-08-24
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** RARLAB WinRAR contains an unspecified vulnerability that allows an attacker to execute code when a user attempts to view a benign file within a ZIP archive.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 120. CVE-2023-38035 — NEW

**Vendor / Product:** Ivanti / Sentry
**Name:** Ivanti Sentry Authentication Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-08-22
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Ivanti Sentry, formerly known as MobileIron Sentry, contains an authentication bypass vulnerability that may allow an attacker to bypass authentication controls on the administrative interface due to an insufficiently restrictive Apache HTTPD configuration.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 121. CVE-2023-27532 — NEW

**Vendor / Product:** Veeam / Backup & Replication
**Name:** Veeam Backup & Replication Cloud Connect Missing Authentication for Critical Function Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-08-22
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Veeam Backup & Replication Cloud Connect component contains a missing authentication for critical function vulnerability that allows an unauthenticated user operating within the backup infrastructure network perimeter to obtain encrypted credentials stored in the configuration database. This may lead to an attacker gaining access to the backup infrastructure hosts.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 122. CVE-2023-35078 — NEW

**Vendor / Product:** Ivanti / Endpoint Manager Mobile (EPMM)
**Name:** Ivanti Endpoint Manager Mobile Authentication Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-07-25
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Ivanti Endpoint Manager Mobile (EPMM, previously branded MobileIron Core) contains an authentication bypass vulnerability that allows unauthenticated access to specific API paths. An attacker with access to these API paths can access personally identifiable information (PII) such as names, phone numbers, and other mobile device details for users on a vulnerable system. An attacker can also make other configuration changes including installing software and modifying security profiles on registered devices.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 123. CVE-2023-3519 — NEW

**Vendor / Product:** Citrix / NetScaler ADC and NetScaler Gateway
**Name:** Citrix NetScaler ADC and NetScaler Gateway Code Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-07-19
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Citrix NetScaler ADC and NetScaler Gateway contains a code injection vulnerability that allows for unauthenticated remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 124. CVE-2023-36884 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Search Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-07-17
**CISA required action:** Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.

**Description:** Microsoft Windows Search contains an unspecified vulnerability that could allow an attacker to evade Mark of the Web (MOTW) defenses via a specially crafted malicious file, leading to remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 125. CVE-2022-31199 — NEW

**Vendor / Product:** Netwrix / Auditor
**Name:** Netwrix Auditor Insecure Object Deserialization Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-07-11
**CISA required action:** Apply updates per vendor instructions or discontinue use of the product if updates are unavailable.

**Description:** Netwrix Auditor User Activity Video Recording component contains an insecure objection deserialization vulnerability that allows an unauthenticated, remote attacker to execute code as the NT AUTHORITY\SYSTEM user. Successful exploitation requires that the attacker is able to reach port 9004/TCP, which is commonly blocked by standard enterprise firewalling.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 126. CVE-2023-27997 — NEW

**Vendor / Product:** Fortinet / FortiOS and FortiProxy SSL-VPN
**Name:** Fortinet FortiOS and FortiProxy SSL-VPN Heap-Based Buffer Overflow Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-06-13
**CISA required action:** Apply updates per vendor instructions.

**Description:** Fortinet FortiOS and FortiProxy SSL-VPN contain a heap-based buffer overflow vulnerability which can allow an unauthenticated, remote attacker to execute code or commands via specifically crafted requests.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 127. CVE-2023-34362 — NEW

**Vendor / Product:** Progress / MOVEit Transfer
**Name:** Progress MOVEit Transfer SQL Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-06-02
**CISA required action:** Apply updates per vendor instructions.

**Description:** Progress MOVEit Transfer contains a SQL injection vulnerability that could allow an unauthenticated attacker to gain unauthorized access to MOVEit Transfer's database. Depending on the database engine being used (MySQL, Microsoft SQL Server, or Azure SQL), an attacker may be able to infer information about the structure and contents of the database in addition to executing SQL statements that alter or delete database elements.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 128. CVE-2021-45046 — NEW

**Vendor / Product:** Apache / Log4j2
**Name:** Apache Log4j2 Deserialization of Untrusted Data Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-05-01
**CISA required action:** Apply updates per vendor instructions.

**Description:** Apache Log4j2 contains a deserialization of untrusted data vulnerability due to the incomplete fix of CVE-2021-44228, where the Thread Context Lookup Pattern is vulnerable to remote code execution in certain non-default configurations.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 129. CVE-2023-27350 — NEW

**Vendor / Product:** PaperCut / MF/NG
**Name:** PaperCut MF/NG Improper Access Control Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-04-21
**CISA required action:** Apply updates per vendor instructions.

**Description:** PaperCut MF/NG contains an improper access control vulnerability within the SetupCompleted class that allows authentication bypass and code execution in the context of system.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 130. CVE-2023-28252 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Common Log File System (CLFS) Driver Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-04-11
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Windows Common Log File System (CLFS) driver contains an unspecified vulnerability that allows for privilege escalation.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 131. CVE-2021-27876 — NEW

**Vendor / Product:** Veritas / Backup Exec Agent
**Name:** Veritas Backup Exec Agent File Access Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-04-07
**CISA required action:** Apply updates per vendor instructions.

**Description:** Veritas Backup Exec (BE) Agent contains a file access vulnerability that could allow an attacker to specially craft input parameters on a data management protocol command to access files on the BE Agent machine.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 132. CVE-2021-27877 — NEW

**Vendor / Product:** Veritas / Backup Exec Agent
**Name:** Veritas Backup Exec Agent Improper Authentication Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-04-07
**CISA required action:** Apply updates per vendor instructions.

**Description:** Veritas Backup Exec (BE) Agent contains an improper authentication vulnerability that could allow an attacker unauthorized access to the BE Agent via SHA authentication scheme.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 133. CVE-2021-27878 — NEW

**Vendor / Product:** Veritas / Backup Exec Agent
**Name:** Veritas Backup Exec Agent Command Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-04-07
**CISA required action:** Apply updates per vendor instructions.

**Description:** Veritas Backup Exec (BE) Agent contains a command execution vulnerability that could allow an attacker to use a data management protocol command to execute a command on the BE Agent machine.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 134. CVE-2019-1388 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Certificate Dialog Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-04-07
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Windows Certificate Dialog contains a privilege escalation vulnerability, allowing attackers to run processes in an elevated context.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 135. CVE-2017-7494 — NEW

**Vendor / Product:** Samba / Samba
**Name:** Samba Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-03-30
**CISA required action:** Apply updates per vendor instructions.

**Description:** Samba contains a remote code execution vulnerability, allowing a malicious client to upload a shared library to a writable share and then cause the server to load and execute it.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 136. CVE-2023-24880 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows SmartScreen Security Feature Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-03-14
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Windows SmartScreen contains a security feature bypass vulnerability that could allow an attacker to evade Mark of the Web (MOTW) defenses via a specially crafted malicious file.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 137. CVE-2022-36537 — NEW

**Vendor / Product:** ZK Framework / AuUploader
**Name:** ZK Framework AuUploader Unspecified Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-02-27
**CISA required action:** Apply updates per vendor instructions.

**Description:** ZK Framework AuUploader servlets contain an unspecified vulnerability that could allow an attacker to retrieve the content of a file located in the web context. The ZK Framework is an open-source Java framework. This vulnerability can impact multiple products, including but not limited to ConnectWise R1Soft Server Backup Manager.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 138. CVE-2022-47986 — NEW

**Vendor / Product:** IBM / Aspera Faspex
**Name:** IBM Aspera Faspex Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-02-21
**CISA required action:** Apply updates per vendor instructions.

**Description:** IBM Aspera Faspex could allow a remote attacker to execute code on the system, caused by a YAML deserialization flaw.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 139. CVE-2022-41223 — NEW

**Vendor / Product:** Mitel / MiVoice Connect
**Name:** Mitel MiVoice Connect Code Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-02-21
**CISA required action:** Apply updates per vendor instructions.

**Description:** The Director component in Mitel MiVoice Connect allows an authenticated attacker with internal network access to execute code within the context of the application.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 140. CVE-2022-40765 — NEW

**Vendor / Product:** Mitel / MiVoice Connect
**Name:** Mitel MiVoice Connect Command Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-02-21
**CISA required action:** Apply updates per vendor instructions.

**Description:** The Mitel Edge Gateway component of MiVoice Connect allows an authenticated attacker with internal network access to execute commands within the context of the system.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 141. CVE-2023-23376 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Common Log File System (CLFS) Driver Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-02-14
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Windows Common Log File System (CLFS) driver contains an unspecified vulnerability that allows for privilege escalation.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 142. CVE-2015-2291 — NEW

**Vendor / Product:** Intel / Ethernet Diagnostics Driver for Windows
**Name:** Intel Ethernet Diagnostics Driver for Windows Denial-of-Service Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-02-10
**CISA required action:** Apply updates per vendor instructions.

**Description:** Intel ethernet diagnostics driver for Windows IQVW32.sys and IQVW64.sys contain an unspecified vulnerability that allows for a denial-of-service (DoS).

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 143. CVE-2022-24990 — NEW

**Vendor / Product:** TerraMaster / TerraMaster OS
**Name:** TerraMaster OS Remote Command Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-02-10
**CISA required action:** Apply updates per vendor instructions.

**Description:** TerraMaster OS contains a remote command execution vulnerability that allows an unauthenticated user to execute commands on the target endpoint.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 144. CVE-2023-0669 — NEW

**Vendor / Product:** Fortra / GoAnywhere MFT
**Name:** Fortra GoAnywhere MFT Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-02-10
**CISA required action:** Apply updates per vendor instructions.

**Description:** Fortra (formerly, HelpSystems) GoAnywhere MFT contains a pre-authentication remote code execution vulnerability in the License Response Servlet due to deserializing an attacker-controlled object.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 145. CVE-2022-21587 — NEW

**Vendor / Product:** Oracle / E-Business Suite
**Name:** Oracle E-Business Suite Unspecified Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-02-02
**CISA required action:** Apply updates per vendor instructions.

**Description:** Oracle E-Business Suite contains an unspecified vulnerability that allows an unauthenticated attacker with network access via HTTP to compromise Oracle Web Applications Desktop Integrator.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 146. CVE-2017-11357 — NEW

**Vendor / Product:** Telerik / User Interface (UI) for ASP.NET AJAX
**Name:** Telerik UI for ASP.NET AJAX Insecure Direct Object Reference Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-01-26
**CISA required action:** Apply updates per vendor instructions.

**Description:** Telerik UI for ASP.NET AJAX contains an insecure direct object reference vulnerability in RadAsyncUpload that can result in file uploads in a limited location and/or remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 147. CVE-2022-47966 — NEW

**Vendor / Product:** Zoho / ManageEngine
**Name:** Zoho ManageEngine Multiple Products Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-01-23
**CISA required action:** Apply updates per vendor instructions.

**Description:** Multiple Zoho ManageEngine products contain an unauthenticated remote code execution vulnerability due to the usage of an outdated third-party dependency, Apache Santuario.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 148. CVE-2022-41080 — NEW

**Vendor / Product:** Microsoft / Exchange Server
**Name:** Microsoft Exchange Server Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2023-01-10
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Exchange Server contains an unspecified vulnerability that allows for privilege escalation. This vulnerability is chainable with CVE-2022-41082, which allows for remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 149. CVE-2022-42475 — NEW

**Vendor / Product:** Fortinet / FortiOS
**Name:** Fortinet FortiOS Heap-Based Buffer Overflow Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-12-13
**CISA required action:** Apply updates per vendor instructions.

**Description:** Multiple versions of Fortinet FortiOS SSL-VPN contain a heap-based buffer overflow vulnerability which can allow an unauthenticated, remote attacker to execute arbitrary code or commands via specifically crafted requests.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 150. CVE-2022-44698 — NEW

**Vendor / Product:** Microsoft / Defender
**Name:** Microsoft Defender SmartScreen Security Feature Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-12-13
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Defender SmartScreen contains a security feature bypass vulnerability that could allow an attacker to evade Mark of the Web (MOTW) defenses via a specially crafted malicious file.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 151. CVE-2022-26500 — NEW

**Vendor / Product:** Veeam / Backup & Replication
**Name:** Veeam Backup & Replication Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-12-13
**CISA required action:** Apply updates per vendor instructions.

**Description:** The Veeam Distribution Service in the Backup & Replication application allows unauthenticated users to access internal API functions. A remote attacker can send input to the internal API which may lead to uploading and executing of malicious code.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 152. CVE-2022-26501 — NEW

**Vendor / Product:** Veeam / Backup & Replication
**Name:** Veeam Backup & Replication Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-12-13
**CISA required action:** Apply updates per vendor instructions.

**Description:** The Veeam Distribution Service in the Backup & Replication application allows unauthenticated users to access internal API functions. A remote attacker can send input to the internal API which may lead to uploading and executing of malicious code.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 153. CVE-2022-41091 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Mark of the Web (MOTW) Security Feature Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-11-08
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Windows Mark of the Web (MOTW) contains a security feature bypass vulnerability resulting in a limited loss of integrity and availability of security features.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 154. CVE-2022-41073 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Print Spooler Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-11-08
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Windows Print Spooler contains an unspecified vulnerability that allows an attacker to gain SYSTEM-level privileges.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 155. CVE-2020-3433 — NEW

**Vendor / Product:** Cisco / AnyConnect Secure
**Name:** Cisco AnyConnect Secure Mobility Client for Windows DLL Hijacking Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-10-24
**CISA required action:** Apply updates per vendor instructions.

**Description:** Cisco AnyConnect Secure Mobility Client for Windows interprocess communication (IPC) channel allows for insufficient validation of resources that are loaded by the application at run time. An attacker with valid credentials on Windows could execute code on the affected machine with SYSTEM privileges.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 156. CVE-2020-3153 — NEW

**Vendor / Product:** Cisco / AnyConnect Secure
**Name:** Cisco AnyConnect Secure Mobility Client for Windows Uncontrolled Search Path Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-10-24
**CISA required action:** Apply updates per vendor instructions.

**Description:** Cisco AnyConnect Secure Mobility Client for Windows allows for incorrect handling of directory paths. An attacker with valid credentials on Windows would be able to copy malicious files to arbitrary locations with system level privileges. This could include DLL pre-loading, DLL hijacking, and other related attacks.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 157. CVE-2018-19323 — NEW

**Vendor / Product:** GIGABYTE / Multiple Products
**Name:** GIGABYTE Multiple Products Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-10-24
**CISA required action:** Apply updates per vendor instructions.

**Description:** The GPCIDrv and GDrv low-level drivers in GIGABYTE App Center, AORUS Graphics Engine, XTREME Gaming Engine, and OC GURU expose functionality to read and write arbitrary physical memory. This could be leveraged by a local attacker to elevate privileges.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 158. CVE-2018-19322 — NEW

**Vendor / Product:** GIGABYTE / Multiple Products
**Name:** GIGABYTE Multiple Products Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-10-24
**CISA required action:** Apply updates per vendor instructions.

**Description:** The GPCIDrv and GDrv low-level drivers in GIGABYTE App Center, AORUS Graphics Engine, XTREME Gaming Engine, and OC GURU II expose functionality to read/write data from/to IO ports. This could be leveraged in a number of ways to ultimately run code with elevated privileges.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 159. CVE-2018-19321 — NEW

**Vendor / Product:** GIGABYTE / Multiple Products
**Name:** GIGABYTE Multiple Products Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-10-24
**CISA required action:** Apply updates per vendor instructions.

**Description:** The GPCIDrv and GDrv low-level drivers in GIGABYTE App Center, AORUS Graphics Engine, XTREME Gaming Engine, and OC GURU II expose functionality to read and write arbitrary physical memory. This could be leveraged by a local attacker to elevate privileges.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 160. CVE-2018-19320 — NEW

**Vendor / Product:** GIGABYTE / Multiple Products
**Name:** GIGABYTE Multiple Products Unspecified Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-10-24
**CISA required action:** Apply updates per vendor instructions.

**Description:** The GDrv low-level driver in GIGABYTE App Center, AORUS Graphics Engine, XTREME Gaming Engine, and OC GURU II exposes ring0 memcpy-like functionality that could allow a local attacker to take complete control of the affected system.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 161. CVE-2022-41352 — NEW

**Vendor / Product:** Synacor / Zimbra Collaboration Suite (ZCS)
**Name:** Synacor Zimbra Collaboration Suite (ZCS) Arbitrary File Upload Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-10-20
**CISA required action:** Apply updates per vendor instructions.

**Description:** Synacor Zimbra Collaboration Suite (ZCS) allows an attacker to upload arbitrary files using cpio package to gain incorrect access to any other user accounts.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 162. CVE-2022-40684 — NEW

**Vendor / Product:** Fortinet / Multiple Products
**Name:** Fortinet Multiple Products Authentication Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-10-11
**CISA required action:** Apply updates per vendor instructions.

**Description:** Fortinet FortiOS, FortiProxy, and FortiSwitchManager contain an authentication bypass vulnerability that could allow an unauthenticated attacker to perform operations on the administrative interface via specially crafted HTTP or HTTPS requests.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 163. CVE-2022-41082 — NEW

**Vendor / Product:** Microsoft / Exchange Server
**Name:** Microsoft Exchange Server Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-09-30
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Exchange Server contains an unspecified vulnerability that allows for authenticated remote code execution. Dubbed "ProxyNotShell," this vulnerability is chainable with CVE-2022-41040 which allows for the remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 164. CVE-2022-41040 — NEW

**Vendor / Product:** Microsoft / Exchange Server
**Name:** Microsoft Exchange Server Server-Side Request Forgery Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-09-30
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Exchange Server allows for server-side request forgery. Dubbed "ProxyNotShell," this vulnerability is chainable with CVE-2022-41082 which allows for remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 165. CVE-2022-37969 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Common Log File System (CLFS) Driver Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-09-14
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Windows Common Log File System (CLFS) driver contains an unspecified vulnerability that allows for privilege escalation.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 166. CVE-2022-27593 — NEW

**Vendor / Product:** QNAP / Photo Station
**Name:** QNAP Photo Station Externally Controlled Reference Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-09-08
**CISA required action:** Apply updates per vendor instructions.

**Description:** Certain QNAP NAS running Photo Station with internet exposure contain an externally controlled reference to a resource vulnerability which can allow an attacker to modify system files. This vulnerability was observed being utilized in a Deadbolt ransomware campaign.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 167. CVE-2018-6530 — NEW

**Vendor / Product:** D-Link / Multiple Routers
**Name:** D-Link Multiple Routers OS Command Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-09-08
**CISA required action:** The vendor D-Link published an advisory stating the fix under CVE-2018-20114 properly patches KEV entry CVE-2018-6530. If the device is still supported, apply updates per vendor instructions. If the affected device has since entered its end-of-life, it should be disconnected if still in use.

**Description:** Multiple D-Link routers contain an unspecified vulnerability that allows for execution of OS commands.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 168. CVE-2018-13374 — NEW

**Vendor / Product:** Fortinet / FortiOS and FortiADC
**Name:** Fortinet FortiOS and FortiADC Improper Access Control Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-09-08
**CISA required action:** Apply updates per vendor instructions.

**Description:** Fortinet FortiOS and FortiADC contain an improper access control vulnerability that allows attackers to obtain the LDAP server login credentials configured in FortiGate by pointing a LDAP server connectivity test request to a rogue LDAP server.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 169. CVE-2022-26352 — NEW

**Vendor / Product:** dotCMS / dotCMS
**Name:** dotCMS Unrestricted Upload of File Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-08-25
**CISA required action:** Apply updates per vendor instructions.

**Description:** dotCMS ContentResource API contains an unrestricted upload of file with a dangerous type vulnerability that allows for directory traversal, in which the file is saved outside of the intended storage location. Exploitation allows for remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 170. CVE-2022-2294 — NEW

**Vendor / Product:** WebRTC / WebRTC
**Name:** WebRTC Heap Buffer Overflow Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-08-25
**CISA required action:** Apply updates per vendor instructions.

**Description:** WebRTC, an open-source project providing web browsers with real-time communication, contains a heap buffer overflow vulnerability that allows an attacker to perform shellcode execution. This vulnerability impacts web browsers using WebRTC including but not limited to Google Chrome.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 171. CVE-2022-27925 — NEW

**Vendor / Product:** Synacor / Zimbra Collaboration Suite (ZCS)
**Name:** Synacor Zimbra Collaboration Suite (ZCS) Arbitrary File Upload Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-08-11
**CISA required action:** Apply updates per vendor instructions.

**Description:** Synacor Zimbra Collaboration Suite (ZCS) contains flaw in the mboximport functionality, allowing an authenticated attacker to upload arbitrary files to perform remote code execution. This vulnerability was chained with CVE-2022-37042 which allows for unauthenticated remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 172. CVE-2022-37042 — NEW

**Vendor / Product:** Synacor / Zimbra Collaboration Suite (ZCS)
**Name:** Synacor Zimbra Collaboration Suite (ZCS) Authentication Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-08-11
**CISA required action:** Apply updates per vendor instructions.

**Description:** Synacor Zimbra Collaboration Suite (ZCS) contains an authentication bypass vulnerability in MailboxImportServlet. This vulnerability was chained with CVE-2022-27925 which allows for unauthenticated remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 173. CVE-2022-30333 — NEW

**Vendor / Product:** RARLAB / UnRAR
**Name:** RARLAB UnRAR Directory Traversal Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-08-09
**CISA required action:** Apply updates per vendor instructions.

**Description:** RARLAB UnRAR on Linux and UNIX contains a directory traversal vulnerability, allowing an attacker to write to files during an extract (unpack) operation.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 174. CVE-2022-27924 — NEW

**Vendor / Product:** Synacor / Zimbra Collaboration Suite (ZCS)
**Name:** Synacor Zimbra Collaboration Suite (ZCS) Command Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-08-04
**CISA required action:** Apply updates per vendor instructions.

**Description:** Synacor Zimbra Collaboration Suite (ZCS) allows an attacker to inject memcache commands into a targeted instance which causes an overwrite of arbitrary cached entries.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 175. CVE-2022-29499 — NEW

**Vendor / Product:** Mitel / MiVoice Connect
**Name:** Mitel MiVoice Connect Data Validation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-06-27
**CISA required action:** Apply updates per vendor instructions.

**Description:** The Service Appliance component in Mitel MiVoice Connect allows remote code execution due to incorrect data validation.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 176. CVE-2021-4034 — NEW

**Vendor / Product:** Red Hat / Polkit
**Name:** Red Hat Polkit Out-of-Bounds Read and Write Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-06-27
**CISA required action:** Apply updates per vendor instructions.

**Description:** The Red Hat polkit pkexec utility contains an out-of-bounds read and write vulnerability that allows for privilege escalation with administrative rights.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 177. CVE-2022-30190 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-06-14
**CISA required action:** Apply updates per vendor instructions.

**Description:** A remote code execution vulnerability exists when MSDT is called using the URL protocol from a calling application such as Word. An attacker who successfully exploits this vulnerability can run code with the privileges of the calling application.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 178. CVE-2019-7195 — NEW

**Vendor / Product:** QNAP / Photo Station
**Name:** QNAP Photo Station Path Traversal Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-06-08
**CISA required action:** Apply updates per vendor instructions.

**Description:** QNAP devices running Photo Station contain an external control of file name or path vulnerability allowing remote attackers to access or modify system files.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 179. CVE-2019-7194 — NEW

**Vendor / Product:** QNAP / Photo Station
**Name:** QNAP Photo Station Path Traversal Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-06-08
**CISA required action:** Apply updates per vendor instructions.

**Description:** QNAP devices running Photo Station contain an external control of file name or path vulnerability allowing remote attackers to access or modify system files.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 180. CVE-2019-7193 — NEW

**Vendor / Product:** QNAP / QTS
**Name:** QNAP QTS Improper Input Validation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-06-08
**CISA required action:** Apply updates per vendor instructions.

**Description:** QNAP QTS contains an improper input validation vulnerability allowing remote attackers to inject code on the system.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 181. CVE-2019-7192 — NEW

**Vendor / Product:** QNAP / Photo Station
**Name:** QNAP Photo Station Improper Access Control Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-06-08
**CISA required action:** Apply updates per vendor instructions.

**Description:** QNAP NAS devices running Photo Station contain an improper access control vulnerability allowing remote attackers to gain unauthorized access to the system.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 182. CVE-2022-26134 — NEW

**Vendor / Product:** Atlassian / Confluence Server/Data Center
**Name:** Atlassian Confluence Server and Data Center Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-06-02
**CISA required action:** Immediately block all internet traffic to and from affected products AND apply the update per vendor instructions [https://confluence.atlassian.com/doc/confluence-security-advisory-2022-06-02-1130377146.html] OR remove the affected products by the due date on the right. Note: Once the update is successfully deployed, agencies can reassess the internet blocking rules.

**Description:** Atlassian Confluence Server and Data Center contain a remote code execution vulnerability that allows for an unauthenticated attacker to perform remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 183. CVE-2016-0034 — NEW

**Vendor / Product:** Microsoft / Silverlight
**Name:** Microsoft Silverlight Runtime Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-05-25
**CISA required action:** The impacted products are end-of-life and should be disconnected if still in use.

**Description:** Microsoft Silverlight mishandles negative offsets during decoding, which allows attackers to execute remote code or cause a denial-of-service (DoS).

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 184. CVE-2013-3993 — NEW

**Vendor / Product:** IBM / InfoSphere BigInsights
**Name:** IBM InfoSphere BigInsights Invalid Input Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-05-25
**CISA required action:** The impacted product is end-of-life and should be disconnected if still in use.

**Description:** Certain APIs within BigInsights can take invalid input that might allow attackers unauthorized access to read, write, modify, or delete data.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 185. CVE-2013-0431 — NEW

**Vendor / Product:** Oracle / Java Runtime Environment (JRE)
**Name:** Oracle JRE Sandbox Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-05-25
**CISA required action:** Apply updates per vendor instructions.

**Description:** Unspecified vulnerability in the Java Runtime Environment (JRE) component in Oracle allows remote attackers to bypass the Java security sandbox.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 186. CVE-2013-0422 — NEW

**Vendor / Product:** Oracle / Java Runtime Environment (JRE)
**Name:** Oracle JRE Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-05-25
**CISA required action:** Apply updates per vendor instructions.

**Description:** A vulnerability in the way Java restricts the permissions of Java applets could allow an attacker to execute commands on a vulnerable system.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 187. CVE-2013-0074 — NEW

**Vendor / Product:** Microsoft / Silverlight
**Name:** Microsoft Silverlight Double Dereference Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-05-25
**CISA required action:** The impacted product is end-of-life and should be disconnected if still in use.

**Description:** Microsoft Silverlight does not properly validate pointers during HTML object rendering, which allows remote attackers to execute code via a crafted Silverlight application.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 188. CVE-2012-1710 — NEW

**Vendor / Product:** Oracle / Fusion Middleware
**Name:** Oracle Fusion Middleware Unspecified Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-05-25
**CISA required action:** Apply updates per vendor instructions.

**Description:** Unspecified vulnerability in the Oracle WebCenter Forms Recognition component in Oracle Fusion Middleware allows remote attackers to affect confidentiality, integrity, and availability via Unknown vectors related to Designer.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 189. CVE-2010-1428 — NEW

**Vendor / Product:** Red Hat / JBoss
**Name:** Red Hat JBoss Information Disclosure Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-05-25
**CISA required action:** Apply updates per vendor instructions.

**Description:** Unauthenticated access to the JBoss Application Server Web Console (/web-console) is blocked by default. However, it was found that this block was incomplete, and only blocked GET and POST HTTP verbs. A remote attacker could use this flaw to gain access to sensitive information.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 190. CVE-2010-0738 — NEW

**Vendor / Product:** Red Hat / JBoss
**Name:** Red Hat JBoss Authentication Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-05-25
**CISA required action:** Apply updates per vendor instructions.

**Description:** The JMX-Console web application in JBossAs in Red Hat JBoss Enterprise Application Platform performs access control only for the GET and POST methods, which allows remote attackers to send requests to this application's GET handler by using a different method.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 191. CVE-2018-19953 — NEW

**Vendor / Product:** QNAP / Network Attached Storage (NAS)
**Name:** QNAP NAS File Station Cross-Site Scripting Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-05-24
**CISA required action:** Apply updates per vendor instructions.

**Description:** A cross-site scripting vulnerability affecting QNAP NAS File Station could allow remote attackers to inject malicious code.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 192. CVE-2018-19949 — NEW

**Vendor / Product:** QNAP / Network Attached Storage (NAS)
**Name:** QNAP NAS File Station Command Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-05-24
**CISA required action:** Apply updates per vendor instructions.

**Description:** A command injection vulnerability affecting QNAP NAS File Station could allow remote attackers to run commands.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 193. CVE-2018-19943 — NEW

**Vendor / Product:** QNAP / Network Attached Storage (NAS)
**Name:** QNAP NAS File Station Cross-Site Scripting Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-05-24
**CISA required action:** Apply updates per vendor instructions.

**Description:** A cross-site scripting vulnerability affecting QNAP NAS File Station could allow remote attackers to inject malicious code.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 194. CVE-2017-0147 — NEW

**Vendor / Product:** Microsoft / SMBv1 server
**Name:** Microsoft Windows SMBv1 Information Disclosure Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-05-24
**CISA required action:** Apply updates per vendor instructions.

**Description:** The SMBv1 server in Microsoft Windows allows remote attackers to obtain sensitive information from process memory via a crafted packet.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 195. CVE-2017-18362 — NEW

**Vendor / Product:** Kaseya / Virtual System/Server Administrator (VSA)
**Name:** Kaseya VSA SQL Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-05-24
**CISA required action:** The impacted product is end-of-life and should be disconnected if still in use.

**Description:** ConnectWise ManagedITSync integration for Kaseya VSA is vulnerable to unauthenticated remote commands that allow full direct access to the Kaseya VSA database.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 196. CVE-2016-3351 — NEW

**Vendor / Product:** Microsoft / Internet Explorer and Edge
**Name:** Microsoft Internet Explorer and Edge Information Disclosure Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-05-24
**CISA required action:** Apply updates per vendor instructions.

**Description:** An information disclosure vulnerability exists in the way that certain functions in Internet Explorer and Edge handle objects in memory. The vulnerability could allow an attacker to detect specific files on the user's computer.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 197. CVE-2020-0638 — NEW

**Vendor / Product:** Microsoft / Update Notification Manager
**Name:** Microsoft Update Notification Manager Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-05-23
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Update Notification Manager contains an unspecified vulnerability that allows for privilege escalation.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 198. CVE-2019-1385 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows AppX Deployment Extensions Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-05-23
**CISA required action:** Apply updates per vendor instructions.

**Description:** A privilege escalation vulnerability exists when the Windows AppX Deployment Extensions improperly performs privilege management, resulting in access to system files.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 199. CVE-2019-1130 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows AppX Deployment Service Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-05-23
**CISA required action:** Apply updates per vendor instructions.

**Description:** A privilege escalation vulnerability exists when Windows AppX Deployment Service (AppXSVC) improperly handles hard links.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 200. CVE-2022-1388 — NEW

**Vendor / Product:** F5 / BIG-IP
**Name:** F5 BIG-IP Missing Authentication Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-05-10
**CISA required action:** Apply updates per vendor instructions.

**Description:** F5 BIG-IP contains a missing authentication in critical function vulnerability which can allow for remote code execution, creation or deletion of files, or disabling services.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 201. CVE-2022-29464 — NEW

**Vendor / Product:** WSO2 / Multiple Products
**Name:** WSO2 Multiple Products Unrestrictive Upload of File Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-04-25
**CISA required action:** Apply updates per vendor instructions.

**Description:** Multiple WSO2 products allow for unrestricted file upload, resulting in remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 202. CVE-2018-6882 — NEW

**Vendor / Product:** Synacor / Zimbra Collaboration Suite (ZCS)
**Name:** Synacor Zimbra Collaboration Suite (ZCS) Cross-Site Scripting (XSS) Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-04-19
**CISA required action:** Apply updates per vendor instructions.

**Description:** Synacor Zimbra Collaboration Suite (ZCS) contains a cross-site scripting vulnerability that might allow remote attackers to inject arbitrary web script or HTML.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 203. CVE-2019-16057 — NEW

**Vendor / Product:** D-Link / DNS-320 Storage Device
**Name:** D-Link DNS-320 Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-04-15
**CISA required action:** The impacted product is end-of-life and should be disconnected if still in use.

**Description:** The login_mgr.cgi script in D-Link DNS-320 is vulnerable to remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 204. CVE-2022-22954 — NEW

**Vendor / Product:** VMware / Workspace ONE Access and Identity Manager
**Name:** VMware Workspace ONE Access and Identity Manager Server-Side Template Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-04-14
**CISA required action:** Apply updates per vendor instructions.

**Description:** VMware Workspace ONE Access and Identity Manager allow for remote code execution due to server-side template injection.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 205. CVE-2022-24521 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows CLFS Driver Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-04-13
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Windows Common Log File System (CLFS) Driver contains an unspecified vulnerability that allows for privilege escalation.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 206. CVE-2018-7602 — NEW

**Vendor / Product:** Drupal / Core
**Name:** Drupal Core Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-04-13
**CISA required action:** Apply updates per vendor instructions.

**Description:** A remote code execution vulnerability exists within multiple subsystems of Drupal that can allow attackers to exploit multiple attack vectors on a Drupal site.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 207. CVE-2018-20753 — NEW

**Vendor / Product:** Kaseya / Virtual System/Server Administrator (VSA)
**Name:** Kaseya VSA Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-04-13
**CISA required action:** Apply updates per vendor instructions.

**Description:** Kaseya VSA RMM allows unprivileged remote attackers to execute PowerShell payloads on all managed devices.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 208. CVE-2021-42287 — NEW

**Vendor / Product:** Microsoft / Active Directory
**Name:** Microsoft Active Directory Domain Services Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-04-11
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Active Directory Domain Services contains an unspecified vulnerability that allows for privilege escalation.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 209. CVE-2021-42278 — NEW

**Vendor / Product:** Microsoft / Active Directory
**Name:** Microsoft Active Directory Domain Services Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-04-11
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Active Directory Domain Services contains an unspecified vulnerability that allows for privilege escalation.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 210. CVE-2017-0148 — NEW

**Vendor / Product:** Microsoft / SMBv1 server
**Name:** Microsoft SMBv1 Server Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-04-06
**CISA required action:** Apply updates per vendor instructions.

**Description:** The SMBv1 server in Microsoft allows remote attackers to execute arbitrary code via crafted packets.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 211. CVE-2021-28799 — NEW

**Vendor / Product:** QNAP / Network Attached Storage (NAS)
**Name:** QNAP NAS Improper Authorization Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-31
**CISA required action:** Apply updates per vendor instructions.

**Description:** QNAP NAS running HBS 3 contains an improper authorization vulnerability which can allow remote attackers to log in to a device.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 212. CVE-2018-10562 — NEW

**Vendor / Product:** Dasan / Gigabit Passive Optical Network (GPON) Routers
**Name:** Dasan GPON Routers Command Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-31
**CISA required action:** The impacted product is end-of-life and should be disconnected if still in use.

**Description:** Dasan GPON Routers contain an authentication bypass vulnerability. When combined with CVE-2018-10561, exploitation can allow an attacker to perform remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 213. CVE-2021-38646 — NEW

**Vendor / Product:** Microsoft / Office
**Name:** Microsoft Office Access Connectivity Engine Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-28
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Office Access Connectivity Engine contains an unspecified vulnerability which can allow for remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 214. CVE-2021-26085 — NEW

**Vendor / Product:** Atlassian / Confluence Server
**Name:** Atlassian Confluence Server Pre-Authorization Arbitrary File Read Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-28
**CISA required action:** Apply updates per vendor instructions.

**Description:** Affected versions of Atlassian Confluence Server allow remote attackers to view restricted resources via a pre-authorization arbitrary file read vulnerability in the /s/ endpoint.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 215. CVE-2021-20028 — NEW

**Vendor / Product:** SonicWall / Secure Remote Access (SRA)
**Name:** SonicWall Secure Remote Access (SRA) SQL Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-28
**CISA required action:** The impacted product is end-of-life and should be disconnected if still in use.

**Description:** SonicWall Secure Remote Access (SRA) products contain an improper neutralization of a SQL Command leading to SQL injection.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 216. CVE-2018-8440 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-28
**CISA required action:** Apply updates per vendor instructions.

**Description:** An elevation of privilege vulnerability exists when Windows improperly handles calls to Advanced Local Procedure Call (ALPC).

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 217. CVE-2018-8406 — NEW

**Vendor / Product:** Microsoft / DirectX Graphics Kernel (DXGKRNL)
**Name:** Microsoft DirectX Graphics Kernel Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-28
**CISA required action:** Apply updates per vendor instructions.

**Description:** An elevation of privilege vulnerability exists when the DirectX Graphics Kernel (DXGKRNL) driver improperly handles objects in memory.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 218. CVE-2018-8405 — NEW

**Vendor / Product:** Microsoft / DirectX Graphics Kernel (DXGKRNL)
**Name:** Microsoft DirectX Graphics Kernel Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-28
**CISA required action:** Apply updates per vendor instructions.

**Description:** An elevation of privilege vulnerability exists when the DirectX Graphics Kernel (DXGKRNL) driver improperly handles objects in memory.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 219. CVE-2017-0213 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-28
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Windows COM Aggregate Marshaler allows for privilege escalation when an attacker runs a specially crafted application.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 220. CVE-2016-0189 — NEW

**Vendor / Product:** Microsoft / Internet Explorer
**Name:** Microsoft Internet Explorer Memory Corruption Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-28
**CISA required action:** Apply updates per vendor instructions.

**Description:** The Microsoft JScript nd VBScript engines, as used in Internet Explorer and other products, allow attackers to execute remote code or cause a denial of service (memory corruption) via a crafted web site.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 221. CVE-2016-0151 — NEW

**Vendor / Product:** Microsoft / Client-Server Run-time Subsystem (CSRSS)
**Name:** Microsoft Windows CSRSS Security Feature Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-28
**CISA required action:** Apply updates per vendor instructions.

**Description:** The Client-Server Run-time Subsystem (CSRSS) in Microsoft mismanages process tokens, which allows local users to gain privileges via a crafted application.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 222. CVE-2013-2551 — NEW

**Vendor / Product:** Microsoft / Internet Explorer
**Name:** Microsoft Internet Explorer Use-After-Free Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-28
**CISA required action:** Apply updates per vendor instructions.

**Description:** Use-after-free vulnerability in Microsoft Internet Explorer allows remote attackers to execute remote code via a crafted web site that triggers access to a deleted object.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 223. CVE-2013-2465 — NEW

**Vendor / Product:** Oracle / Java SE
**Name:** Oracle Java SE Unspecified Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-28
**CISA required action:** Apply updates per vendor instructions.

**Description:** Unspecified vulnerability in the Java Runtime Environment (JRE) component in Oracle Java SE allows remote attackers to affect confidentiality, integrity, and availability via Unknown vectors related to 2D

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 224. CVE-2022-21999 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Print Spooler Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-25
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Windows Print Spooler contains an unspecified vulnerability which can allow for privilege escalation.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 225. CVE-2021-42237 — NEW

**Vendor / Product:** Sitecore / XP
**Name:** Sitecore XP Remote Command Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-25
**CISA required action:** Apply updates per vendor instructions.

**Description:** Sitcore XP contains an insecure deserialization vulnerability which can allow for remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 226. CVE-2021-22941 — NEW

**Vendor / Product:** Citrix / ShareFile
**Name:** Citrix ShareFile Improper Access Control Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-25
**CISA required action:** Apply updates per vendor instructions.

**Description:** Improper Access Control in Citrix ShareFile storage zones controller may allow an unauthenticated attacker to remotely compromise the storage zones controller.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 227. CVE-2020-2021 — NEW

**Vendor / Product:** Palo Alto Networks / PAN-OS
**Name:** Palo Alto Networks PAN-OS Authentication Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-25
**CISA required action:** Apply updates per vendor instructions.

**Description:** Palo Alto Networks PAN-OS contains a vulnerability in SAML which allows an attacker to bypass authentication.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 228. CVE-2019-15107 — NEW

**Vendor / Product:** Webmin / Webmin
**Name:** Webmin Command Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-25
**CISA required action:** Apply updates per vendor instructions.

**Description:** An issue was discovered in Webmin. The parameter old in password_change.cgi contains a command injection vulnerability.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 229. CVE-2019-11043 — NEW

**Vendor / Product:** PHP / FastCGI Process Manager (FPM)
**Name:** PHP FastCGI Process Manager (FPM) Buffer Overflow Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-25
**CISA required action:** Apply updates per vendor instructions.

**Description:** In some versions of PHP in certain configurations of FPM setup, it is possible to cause FPM module to write past allocated buffers allowing the possibility of remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 230. CVE-2018-1273 — NEW

**Vendor / Product:** VMware Tanzu / Spring Data Commons
**Name:** VMware Tanzu Spring Data Commons Property Binder Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-25
**CISA required action:** Apply updates per vendor instructions.

**Description:** Spring Data Commons contains a property binder vulnerability which can allow an attacker to perform remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 231. CVE-2018-11138 — NEW

**Vendor / Product:** Quest / KACE System Management Appliance
**Name:** Quest KACE System Management Appliance Remote Command Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-25
**CISA required action:** Apply updates per vendor instructions.

**Description:** The '/common/download_agent_installer.php' script in the Quest KACE System Management Appliance is accessible by anonymous users and can be abused to perform remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 232. CVE-2017-12615 — NEW

**Vendor / Product:** Apache / Tomcat
**Name:** Apache Tomcat on Windows Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-25
**CISA required action:** Apply updates per vendor instructions.

**Description:** When running Apache Tomcat on Windows with HTTP PUTs enabled, it is possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 233. CVE-2017-0146 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows SMB Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-25
**CISA required action:** Apply updates per vendor instructions.

**Description:** The SMBv1 server in Microsoft Windows allows remote attackers to perform remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 234. CVE-2010-2861 — NEW

**Vendor / Product:** Adobe / ColdFusion
**Name:** Adobe ColdFusion Directory Traversal Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-25
**CISA required action:** Apply updates per vendor instructions.

**Description:** A directory traversal vulnerability exists in the administrator console in Adobe ColdFusion which allows remote attackers to read arbitrary files.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 235. CVE-2020-5135 — NEW

**Vendor / Product:** SonicWall / SonicOS
**Name:** SonicWall SonicOS Buffer Overflow Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-15
**CISA required action:** Apply updates per vendor instructions.

**Description:** A buffer overflow vulnerability in SonicOS allows a remote attacker to cause Denial of Service (DoS) and potentially execute arbitrary code by sending a malicious request to the firewall.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 236. CVE-2019-1405 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Universal Plug and Play (UPnP) Service Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-15
**CISA required action:** Apply updates per vendor instructions.

**Description:** A privilege escalation vulnerability exists when the Windows UPnP service improperly allows COM object creation.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 237. CVE-2019-1322 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-15
**CISA required action:** Apply updates per vendor instructions.

**Description:** A privilege escalation vulnerability exists when Windows improperly handles authentication requests. An attacker who successfully exploited this vulnerability could run processes in an elevated context.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 238. CVE-2019-1315 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Error Reporting Manager Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-15
**CISA required action:** Apply updates per vendor instructions.

**Description:** A privilege escalation vulnerability exists when Windows Error Reporting manager improperly handles hard links. An attacker who successfully exploited this vulnerability could overwrite a targeted file leading to an elevated status.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 239. CVE-2019-1253 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows AppX Deployment Server Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-15
**CISA required action:** Apply updates per vendor instructions.

**Description:** A privilege escalation vulnerability exists when the Windows AppX Deployment Server improperly handles junctions.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 240. CVE-2019-1129 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows AppX Deployment Service (AppXSVC) Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-15
**CISA required action:** Apply updates per vendor instructions.

**Description:** A privilege escalation vulnerability exists when Windows AppXSVC improperly handles hard links. An attacker who successfully exploited this vulnerability could run processes in an elevated context.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 241. CVE-2019-1069 — NEW

**Vendor / Product:** Microsoft / Task Scheduler
**Name:** Microsoft Task Scheduler Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-15
**CISA required action:** Apply updates per vendor instructions.

**Description:** A privilege escalation vulnerability exists in the way the Task Scheduler Service validates certain file operations.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 242. CVE-2019-1064 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows AppX Deployment Service (AppXSVC) Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-15
**CISA required action:** Apply updates per vendor instructions.

**Description:** A privilege escalation vulnerability exists when Windows AppXSVC improperly handles hard links. An attacker who successfully exploited this vulnerability could run processes in an elevated context.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 243. CVE-2019-0841 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows AppX Deployment Service (AppXSVC) Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-15
**CISA required action:** Apply updates per vendor instructions.

**Description:** A privilege escalation vulnerability exists when Windows AppXSVC improperly handles hard links. An attacker who successfully exploited this vulnerability could run processes in an elevated context.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 244. CVE-2019-0543 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-15
**CISA required action:** Apply updates per vendor instructions.

**Description:** A privilege escalation vulnerability exists when Windows improperly handles authentication requests. An attacker who successfully exploited this vulnerability could run processes in an elevated context.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 245. CVE-2018-8120 — NEW

**Vendor / Product:** Microsoft / Win32k
**Name:** Microsoft Win32k Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-15
**CISA required action:** Apply updates per vendor instructions.

**Description:** A privilege escalation vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 246. CVE-2017-0101 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Transaction Manager Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-15
**CISA required action:** Apply updates per vendor instructions.

**Description:** A privilege escalation vulnerability exists when the Windows Transaction Manager improperly handles objects in memory.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 247. CVE-2016-3309 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Kernel Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-15
**CISA required action:** Apply updates per vendor instructions.

**Description:** A privilege escalation vulnerability exists when the Windows kernel fails to properly handle objects in memory. An attacker who successfully exploited this vulnerability could run arbitrary code in kernel mode.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 248. CVE-2015-2546 — NEW

**Vendor / Product:** Microsoft / Win32k
**Name:** Microsoft Win32k Memory Corruption Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-15
**CISA required action:** Apply updates per vendor instructions.

**Description:** The kernel-mode driver in Microsoft Windows OS and Server allows local users to gain privileges via a crafted application.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 249. CVE-2009-3960 — NEW

**Vendor / Product:** Adobe / BlazeDS
**Name:** Adobe BlazeDS Information Disclosure Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-07
**CISA required action:** Apply updates per vendor instructions.

**Description:** Adobe BlazeDS, which is utilized in LifeCycle and Coldfusion, contains a vulnerability that allows for information disclosure.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 250. CVE-2021-41379 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Installer Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Windows Installer contains an unspecified vulnerability that allows for privilege escalation.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 251. CVE-2018-8581 — NEW

**Vendor / Product:** Microsoft / Exchange Server
**Name:** Microsoft Exchange Server Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** A privilege escalation vulnerability exists in Microsoft Exchange Server. An attacker who successfully exploited this vulnerability could attempt to impersonate any other user of the Exchange server.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 252. CVE-2016-4117 — NEW

**Vendor / Product:** Adobe / Flash Player
**Name:** Adobe Flash Player Arbitrary Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-03
**CISA required action:** The impacted product is end-of-life and should be disconnected if still in use.

**Description:** An access of resource using incompatible type vulnerability exists within Adobe Flash Player that allows an attacker to perform remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 253. CVE-2016-1019 — NEW

**Vendor / Product:** Adobe / Flash Player
**Name:** Adobe Flash Player Arbitrary Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-03
**CISA required action:** The impacted product is end-of-life and should be disconnected if still in use.

**Description:** Adobe Flash Player allows remote attackers to cause a denial of service or possibly execute arbitrary code.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 254. CVE-2016-0099 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Secondary Logon Service Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** A privilege escalation vulnerability exists in Microsoft Windows if the Windows Secondary Logon Service fails to properly manage request handles in memory. An attacker who successfully exploited this vulnerability could run arbitrary code as an administrator.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 255. CVE-2015-7645 — NEW

**Vendor / Product:** Adobe / Flash Player
**Name:** Adobe Flash Player Arbitrary Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-03
**CISA required action:** The impacted product is end-of-life and should be disconnected if still in use.

**Description:** Adobe Flash Player allows remote attackers to execute arbitrary code via a crafted SWF file.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 256. CVE-2015-1701 — NEW

**Vendor / Product:** Microsoft / Win32k
**Name:** Microsoft Win32k Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** An unspecified vulnerability exists in the Win32k.sys kernel-mode driver in Microsoft Windows Server that allows a local attacker to execute arbitrary code with elevated privileges.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 257. CVE-2012-4681 — NEW

**Vendor / Product:** Oracle / Java SE
**Name:** Oracle Java SE Runtime Environment (JRE) Arbitrary Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** The Java Runtime Environment (JRE) component in Oracle Java SE allow for remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 258. CVE-2012-1723 — NEW

**Vendor / Product:** Oracle / Java SE
**Name:** Oracle Java SE Runtime Environment (JRE) Arbitrary Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Unspecified vulnerability in the Java Runtime Environment (JRE) component in Oracle Java SE allows remote attackers to affect confidentiality, integrity, and availability via Unknown vectors related to Hotspot.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 259. CVE-2012-0507 — NEW

**Vendor / Product:** Oracle / Java SE
**Name:** Oracle Java SE Runtime Environment (JRE) Arbitrary Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** An incorrect type vulnerability exists in the Concurrency component of Oracle's Java Runtime Environment allows an attacker to remotely execute arbitrary code.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 260. CVE-2010-0188 — NEW

**Vendor / Product:** Adobe / Reader and Acrobat
**Name:** Adobe Reader and Acrobat Arbitrary Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Unspecified vulnerability in Adobe Reader and Acrobat allows attackers to cause a denial of service or possibly execute arbitrary code.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 261. CVE-2008-2992 — NEW

**Vendor / Product:** Adobe / Acrobat and Reader
**Name:** Adobe Reader and Acrobat Input Validation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-03-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Adobe Acrobat and Reader contain an input validation issue in a JavaScript method that could potentially lead to remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 262. CVE-2022-24682 — NEW

**Vendor / Product:** Synacor / Zimbra Collaborate Suite (ZCS)
**Name:** Synacor Zimbra Collaborate Suite (ZCS) Cross-Site Scripting Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-02-25
**CISA required action:** Apply updates per vendor instructions.

**Description:** Synacor Zimbra Collaboration Suite (ZCS) contains a cross-site scripting (XSS) vulnerability in the Calendar feature that allows an attacker to execute arbitrary code.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 263. CVE-2019-0752 — NEW

**Vendor / Product:** Microsoft / Internet Explorer
**Name:** Microsoft Internet Explorer Type Confusion Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-02-15
**CISA required action:** Apply updates per vendor instructions.

**Description:** A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Internet Explorer

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 264. CVE-2018-8174 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows VBScript Engine Out-of-Bounds Write Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-02-15
**CISA required action:** Apply updates per vendor instructions.

**Description:** A remote code execution vulnerability exists in the way that the VBScript engine handles objects in memory, aka "Windows VBScript Engine Remote Code Execution"

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 265. CVE-2018-20250 — NEW

**Vendor / Product:** RARLAB / WinRAR
**Name:** WinRAR Absolute Path Traversal Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-02-15
**CISA required action:** Apply updates per vendor instructions.

**Description:** WinRAR Absolute Path Traversal vulnerability leads to Remote Code Execution

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 266. CVE-2018-15982 — NEW

**Vendor / Product:** Adobe / Flash Player
**Name:** Adobe Flash Player Use-After-Free Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-02-15
**CISA required action:** The impacted product is end-of-life and should be disconnected if still in use.

**Description:** Adobe Flash Player com.adobe.tvsdk.mediacore.metadata Use After Free Vulnerability

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 267. CVE-2020-0796 — NEW

**Vendor / Product:** Microsoft / SMBv3
**Name:** Microsoft SMBv3 Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-02-10
**CISA required action:** Apply updates per vendor instructions.

**Description:** A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests. An attacker who successfully exploited the vulnerability could gain the ability to execute code on the target server or client.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 268. CVE-2017-10271 — NEW

**Vendor / Product:** Oracle / WebLogic Server
**Name:** Oracle Corporation WebLogic Server Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-02-10
**CISA required action:** Apply updates per vendor instructions.

**Description:** Oracle Corporation WebLogic Server contains a vulnerability that allows for remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 269. CVE-2017-0145 — NEW

**Vendor / Product:** Microsoft / SMBv1
**Name:** Microsoft SMBv1 Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-02-10
**CISA required action:** Apply updates per vendor instructions.

**Description:** The SMBv1 server in multiple Microsoft Windows versions allows remote attackers to execute arbitrary code via crafted packets.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 270. CVE-2017-0144 — NEW

**Vendor / Product:** Microsoft / SMBv1
**Name:** Microsoft SMBv1 Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-02-10
**CISA required action:** Apply updates per vendor instructions.

**Description:** The SMBv1 server in multiple Microsoft Windows versions allows remote attackers to execute arbitrary code via crafted packets.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 271. CVE-2022-21882 — NEW

**Vendor / Product:** Microsoft / Win32k
**Name:** Microsoft Win32k Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-02-04
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Win32k contains an unspecified vulnerability that allows for privilege escalation.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 272. CVE-2021-20038 — NEW

**Vendor / Product:** SonicWall / SMA 100 Appliances
**Name:** SonicWall SMA 100 Appliances Stack-Based Buffer Overflow Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-01-28
**CISA required action:** Apply updates per vendor instructions.

**Description:** SonicWall SMA 100 devies are vulnerable to an unauthenticated stack-based buffer overflow vulnerability where exploitation can result in code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 273. CVE-2020-0787 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Background Intelligent Transfer Service (BITS) Improper Privilege Management Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-01-28
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Windows BITS is vulnerable to to a privilege elevation vulnerability if it improperly handles symbolic links. An actor can exploit this vulnerability to execute arbitrary code with system-level privileges.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 274. CVE-2018-8453 — NEW

**Vendor / Product:** Microsoft / Win32k
**Name:** Microsoft Win32k Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-01-21
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Windows Win32k contains a vulnerability that allows an attacker to escalate privileges.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 275. CVE-2021-21975 — NEW

**Vendor / Product:** VMware / vRealize Operations Manager API
**Name:** VMware Server Side Request Forgery in vRealize Operations Manager API
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-01-18
**CISA required action:** Apply updates per vendor instructions.

**Description:** Server Side Request Forgery (SSRF) in vRealize Operations Manager API prior to 8.4 may allow a malicious actor with network access to the vRealize Operations Manager API to perform a SSRF attack to steal administrative credentials.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 276. CVE-2019-1458 — NEW

**Vendor / Product:** Microsoft / Win32k
**Name:** Microsoft Win32k Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-01-10
**CISA required action:** Apply updates per vendor instructions.

**Description:** A privilege escalation vulnerability exists in Windows when the Win32k component fails to properly handle objects in memory, aka 'Win32k EoP.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 277. CVE-2019-2725 — NEW

**Vendor / Product:** Oracle / WebLogic Server
**Name:** Oracle WebLogic Server, Injection
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-01-10
**CISA required action:** Apply updates per vendor instructions.

**Description:** Injection vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: Web Services).

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 278. CVE-2018-13382 — NEW

**Vendor / Product:** Fortinet / FortiOS and FortiProxy
**Name:** Fortinet FortiOS and FortiProxy Improper Authorization
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-01-10
**CISA required action:** Apply updates per vendor instructions.

**Description:** An Improper Authorization vulnerability in Fortinet FortiOS and FortiProxy under SSL VPN web portal allows an unauthenticated attacker to modify the password.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 279. CVE-2018-13383 — NEW

**Vendor / Product:** Fortinet / FortiOS and FortiProxy
**Name:** Fortinet FortiOS and FortiProxy Out-of-bounds Write
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-01-10
**CISA required action:** Apply updates per vendor instructions.

**Description:** A heap buffer overflow in Fortinet FortiOS and FortiProxy may cause the SSL VPN web service termination for logged in users.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 280. CVE-2019-1579 — NEW

**Vendor / Product:** Palo Alto Networks / PAN-OS
**Name:** Palo Alto Networks PAN-OS Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2022-01-10
**CISA required action:** Apply updates per vendor instructions.

**Description:** Remote Code Execution in PAN-OS with GlobalProtect Portal or GlobalProtect Gateway Interface enabled.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 281. CVE-2021-43890 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows AppX Installer Spoofing Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-12-15
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Windows AppX Installer contains a spoofing vulnerability which has a high impacts to confidentiality, integrity, and availability.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 282. CVE-2017-12149 — NEW

**Vendor / Product:** Red Hat / JBoss Application Server
**Name:** Red Hat JBoss Application Server Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-12-10
**CISA required action:** Apply updates per vendor instructions.

**Description:** The JBoss Application Server, shipped with Red Hat Enterprise Application Platform 5.2, allows an attacker to execute arbitrary code via crafted serialized data.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 283. CVE-2021-44228 — NEW

**Vendor / Product:** Apache / Log4j2
**Name:** Apache Log4j2 Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-12-10
**CISA required action:** For all affected software assets for which updates exist, the only acceptable remediation actions are: 1) Apply updates; OR 2) remove affected assets from agency networks. Temporary mitigations using one of the measures provided at https://www.cisa.gov/uscert/ed-22-02-apache-log4j-recommended-mitigation-measures are only acceptable until updates are available.

**Description:** Apache Log4j2 contains a vulnerability where JNDI features do not protect against attacker-controlled JNDI-related endpoints, allowing for remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 284. CVE-2021-40438 — NEW

**Vendor / Product:** Apache / Apache
**Name:** Apache HTTP Server-Side Request Forgery (SSRF)
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-12-01
**CISA required action:** Apply updates per vendor instructions.

**Description:** A crafted request uri-path can cause mod_proxy to forward the request to an origin server choosen by the remote user. This issue affects Apache HTTP Server 2.4.48 and earlier.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 285. CVE-2021-40449 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Win32k Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-17
**CISA required action:** Apply updates per vendor instructions.

**Description:** Unspecified vulnerability allows for an authenticated user to escalate privileges.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 286. CVE-2021-42321 — NEW

**Vendor / Product:** Microsoft / Exchange
**Name:** Microsoft Exchange Server Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-17
**CISA required action:** Apply updates per vendor instructions.

**Description:** An authenticated attacker could leverage improper validation in cmdlet arguments within Microsoft Exchange and perform remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 287. CVE-2021-27104 — NEW

**Vendor / Product:** Accellion / FTA
**Name:** Accellion FTA OS Command Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Accellion FTA contains an OS command injection vulnerability exploited via a crafted POST request to various admin endpoints.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 288. CVE-2021-27102 — NEW

**Vendor / Product:** Accellion / FTA
**Name:** Accellion FTA OS Command Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Accellion FTA contains an OS command injection vulnerability exploited via a local web service call.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 289. CVE-2021-27101 — NEW

**Vendor / Product:** Accellion / FTA
**Name:** Accellion FTA SQL Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Accellion FTA contains a SQL injection vulnerability exploited via a crafted host header in a request to document_root.html.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 290. CVE-2021-27103 — NEW

**Vendor / Product:** Accellion / FTA
**Name:** Accellion FTA Server-Side Request Forgery (SSRF) Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Accellion FTA contains a server-side request forgery (SSRF) vulnerability exploited via a crafted POST request to wmProgressstat.html.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 291. CVE-2018-4878 — NEW

**Vendor / Product:** Adobe / Flash Player
**Name:** Adobe Flash Player Use-After-Free Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** The impacted product is end-of-life and should be disconnected if still in use.

**Description:** Adobe Flash Player contains a use-after-free vulnerability that could allow for code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 292. CVE-2017-5638 — NEW

**Vendor / Product:** Apache / Struts
**Name:** Apache Struts Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Apache Struts Jakarta Multipart parser allows for malicious file upload using the Content-Type value, leading to remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 293. CVE-2021-26084 — NEW

**Vendor / Product:** Atlassian / Confluence Server and Data Center
**Name:** Atlassian Confluence Server and Data Center Object-Graph Navigation Language (OGNL) Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Atlassian Confluence Server and Data Server contain an Object-Graph Navigation Language (OGNL) injection vulnerability that may allow an unauthenticated attacker to execute code.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 294. CVE-2019-11580 — NEW

**Vendor / Product:** Atlassian / Crowd and Crowd Data Center
**Name:** Atlassian Crowd and Crowd Data Center Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Atlassian Crowd and Crowd Data Center contain a remote code execution vulnerability resulting from a pdkinstall development plugin being incorrectly enabled in release builds.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 295. CVE-2019-3396 — NEW

**Vendor / Product:** Atlassian / Confluence Server and Data Server
**Name:** Atlassian Confluence Server and Data Center Server-Side Template Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Atlassian Confluence Server and Data Center contain a server-side template injection vulnerability that may allow an attacker to achieve path traversal and remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 296. CVE-2021-42258 — NEW

**Vendor / Product:** BQE / BillQuick Web Suite
**Name:** BQE BillQuick Web Suite SQL Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** BQE BillQuick Web Suite contains an SQL injection vulnerability when accessing the username parameter that may allow for unauthenticated, remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 297. CVE-2020-3580 — NEW

**Vendor / Product:** Cisco / Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD)
**Name:** Cisco ASA and FTD Cross-Site Scripting (XSS) Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) contain an insufficient input validation vulnerability for user-supplied input by the web services interface.  Successful exploitation could allow an attacker to perform cross-site scripting (XSS) in the context of the interface or access sensitive browser-based information.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 298. CVE-2019-13608 — NEW

**Vendor / Product:** Citrix / StoreFront Server
**Name:** Citrix StoreFront Server XML External Entity (XXE) Processing Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Citrix StoreFront Server contains an XML External Entity (XXE) processing vulnerability that may allow an unauthenticated attacker to retrieve potentially sensitive information.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 299. CVE-2019-19781 — NEW

**Vendor / Product:** Citrix / Application Delivery Controller (ADC), Gateway, and SD-WAN WANOP Appliance
**Name:** Citrix ADC, Gateway, and SD-WAN WANOP Appliance Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Citrix ADC, Citrix Gateway, and multiple Citrix SD-WAN WANOP appliance models contain an unspecified vulnerability that could allow an unauthenticated attacker to perform code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 300. CVE-2019-11634 — NEW

**Vendor / Product:** Citrix / Workspace Application and Receiver for Windows
**Name:** Citrix Workspace Application and Receiver for Windows Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Citrix Workspace Application and Receiver for Windows contains remote code execution vulnerability resulting from local drive access preferences not being enforced into the clients' local drives.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 301. CVE-2017-9822 — NEW

**Vendor / Product:** DotNetNuke (DNN) / DotNetNuke (DNN)
**Name:** DotNetNuke (DNN) Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** DotNetNuke (DNN) contains a vulnerability that may allow for remote code execution via cookie deserialization.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 302. CVE-2018-7600 — NEW

**Vendor / Product:** Drupal / Drupal Core
**Name:** Drupal Core Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Drupal Core contains a remote code execution vulnerability that could allow an attacker to exploit multiple attack vectors on a Drupal site, resulting in complete site compromise.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 303. CVE-2021-22205 — NEW

**Vendor / Product:** GitLab / Community and Enterprise Editions
**Name:** GitLab Community and Enterprise Editions Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** GitHub Community and Enterprise Editions that utilize the ability to upload images through GitLab Workhorse are vulnerable to remote code execution. Workhorse passes image file extensions through ExifTool, which improperly validates the image files.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 304. CVE-2018-6789 — NEW

**Vendor / Product:** Exim / Exim
**Name:** Exim Buffer Overflow Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Exim contains a buffer overflow vulnerability in the base64d function part of the SMTP listener that may allow for remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 305. CVE-2020-5902 — NEW

**Vendor / Product:** F5 / BIG-IP
**Name:** F5 BIG-IP Traffic Management User Interface (TMUI) Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** F5 BIG-IP Traffic Management User Interface (TMUI) contains a remote code execution vulnerability in undisclosed pages.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 306. CVE-2021-22986 — NEW

**Vendor / Product:** F5 / BIG-IP and BIG-IQ Centralized Management
**Name:** F5 BIG-IP and BIG-IQ Centralized Management iControl REST Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** F5 BIG-IP and BIG-IQ Centralized Management contain a remote code execution vulnerability in the iControl REST interface that allows unauthenticated attackers with network access to execute system commands, create or delete files, and disable services.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 307. CVE-2021-35464 — NEW

**Vendor / Product:** ForgeRock / Access Management (AM)
**Name:** ForgeRock Access Management (AM) Core Server Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** ForgeRock Access Management (AM) Core Server allows an attacker who sends a specially crafted HTTP request to one of three endpoints (/ccversion/Version, /ccversion/Masthead, or /ccversion/ButtonFrame) to execute code in the context of the current user (unless ForgeRock AM is running as root user, which the vendor does not recommend).

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 308. CVE-2019-5591 — NEW

**Vendor / Product:** Fortinet / FortiOS
**Name:** Fortinet FortiOS Default Configuration Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Fortinet FortiOS contains a default configuration vulnerability that may allow an unauthenticated attacker on the same subnet to intercept sensitive information by impersonating the Lightweight Directory Access Protocol (LDAP) server.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 309. CVE-2020-12812 — NEW

**Vendor / Product:** Fortinet / FortiOS
**Name:** Fortinet FortiOS SSL VPN Improper Authentication Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Fortinet FortiOS SSL VPN contains an improper authentication vulnerability that may allow a user to login successfully without being prompted for the second factor of authentication (FortiToken) if they change the case in their username.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 310. CVE-2018-13379 — NEW

**Vendor / Product:** Fortinet / FortiOS
**Name:** Fortinet FortiOS SSL VPN Path Traversal Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Fortinet FortiOS SSL VPN web portal contains a path traversal vulnerability that may allow an unauthenticated attacker to download FortiOS system files through specially crafted HTTP resource requests.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 311. CVE-2021-30116 — NEW

**Vendor / Product:** Kaseya / Virtual System/Server Administrator (VSA)
**Name:** Kaseya Virtual System/Server Administrator (VSA) Information Disclosure Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Kaseya Virtual System/Server Administrator (VSA) contains an information disclosure vulnerability allowing an attacker to obtain the sessionId that can be used to execute further attacks against the system.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 312. CVE-2014-1812 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Group Policy Preferences Password Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Windows Active Directory contains a privilege escalation vulnerability due to the way it distributes passwords that are configured using Group Policy preferences. An authenticated attacker who successfully exploits the vulnerability could decrypt the passwords and use them to elevate privileges on the domain.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 313. CVE-2021-38647 — NEW

**Vendor / Product:** Microsoft / Open Management Infrastructure (OMI)
**Name:** Microsoft Open Management Infrastructure (OMI) Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Open Management Infrastructure (OMI) within Azure VM Management Extensions contains an unspecified vulnerability allowing remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 314. CVE-2016-0167 — NEW

**Vendor / Product:** Microsoft / Win32k
**Name:** Microsoft Win32k Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Win32k contains an unspecified vulnerability that allows for privilege escalation via a crafted application

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 315. CVE-2020-0878 — NEW

**Vendor / Product:** Microsoft / Edge and Internet Explorer
**Name:** Microsoft Edge and Internet Explorer Memory Corruption Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Edge and Internet Explorer contain a memory corruption vulnerability that allows attackers to execute code in the context of the current user.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 316. CVE-2021-34523 — NEW

**Vendor / Product:** Microsoft / Exchange Server
**Name:** Microsoft Exchange Server Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Exchange Server contains an unspecified vulnerability that allows for privilege escalation.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 317. CVE-2020-0688 — NEW

**Vendor / Product:** Microsoft / Exchange Server
**Name:** Microsoft Exchange Server Validation Key Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Exchange Server Validation Key fails to properly create unique keys at install time, allowing for remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 318. CVE-2017-0143 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Server Message Block (SMBv1) Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Windows Server Message Block 1.0 (SMBv1) contains an unspecified vulnerability that allows for remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 319. CVE-2016-7255 — NEW

**Vendor / Product:** Microsoft / Win32k
**Name:** Microsoft Win32k Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Win32k kernel-mode driver fails to properly handle objects in memory which allows for privilege escalation. Successful exploitation allows an attacker to run code in kernel mode.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 320. CVE-2019-0708 — NEW

**Vendor / Product:** Microsoft / Remote Desktop Services
**Name:** Microsoft Remote Desktop Services Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Remote Desktop Services, formerly known as Terminal Service, contains an unspecified vulnerability that allows an unauthenticated attacker to connect to the target system using RDP and send specially crafted requests. Successful exploitation allows for remote code execution. The vulnerability is also known under the moniker of BlueKeep.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 321. CVE-2021-34473 — NEW

**Vendor / Product:** Microsoft / Exchange Server
**Name:** Microsoft Exchange Server Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Exchange Server contains an unspecified vulnerability that allows for remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 322. CVE-2021-1732 — NEW

**Vendor / Product:** Microsoft / Win32k
**Name:** Microsoft Win32k Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Win32k contains an unspecified vulnerability that allows for privilege escalation.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 323. CVE-2021-34527 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Print Spooler Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Windows Print Spooler contains an unspecified vulnerability due to the Windows Print Spooler service improperly performing privileged file operations. Successful exploitation allows an attacker to perform remote code execution with SYSTEM privileges. The vulnerability is also known under the moniker of PrintNightmare.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 324. CVE-2021-31207 — NEW

**Vendor / Product:** Microsoft / Exchange Server
**Name:** Microsoft Exchange Server Security Feature Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Exchange Server contains an unspecified vulnerability that allows for security feature bypass.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 325. CVE-2019-0803 — NEW

**Vendor / Product:** Microsoft / Win32k
**Name:** Microsoft Win32k Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Win32k contains an unspecified vulnerability due to it failing to properly handle objects in memory causing privilege escalation. Successful exploitation allows an attacker to run code in kernel mode.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 326. CVE-2021-26411 — NEW

**Vendor / Product:** Microsoft / Internet Explorer
**Name:** Microsoft Internet Explorer Memory Corruption Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Internet Explorer contains an unspecified vulnerability that allows for memory corruption.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 327. CVE-2019-0859 — NEW

**Vendor / Product:** Microsoft / Win32k
**Name:** Microsoft Win32k Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Win32k fails to properly handle objects in memory causing privilege escalation. Successful exploitation allows an attacker to run code in kernel mode.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 328. CVE-2021-40444 — NEW

**Vendor / Product:** Microsoft / MSHTML
**Name:** Microsoft MSHTML Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft MSHTML contains a unspecified vulnerability that allows for remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 329. CVE-2021-36942 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Local Security Authority (LSA) Spoofing Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Windows Local Security Authority (LSA) contains a spoofing vulnerability allowing an unauthenticated attacker to call a method on the LSARPC interface and coerce the domain controller to authenticate against another server using NTLM.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 330. CVE-2019-1215 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Windows contains an unspecified vulnerability due to the way ws2ifsl.sys (Winsock) handles objects in memory, allowing for privilege escalation. Successful exploitation allows an attacker to execute code with elevated privileges.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 331. CVE-2018-0802 — NEW

**Vendor / Product:** Microsoft / Office
**Name:** Microsoft Office Memory Corruption Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Office contains a memory corruption vulnerability due to the way objects are handled in memory. Successful exploitation allows for remote code execution in the context of the current user. This vulnerability is known to be chained with CVE-2018-0798.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 332. CVE-2012-0158 — NEW

**Vendor / Product:** Microsoft / MSCOMCTL.OCX
**Name:** Microsoft MSCOMCTL.OCX Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft MSCOMCTL.OCX contains an unspecified vulnerability that allows for remote code execution, allowing an attacker to take complete control of an affected system under the context of the current user.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 333. CVE-2017-11882 — NEW

**Vendor / Product:** Microsoft / Office
**Name:** Microsoft Office Memory Corruption Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Office contains a memory corruption vulnerability that allows remote code execution in the context of the current user.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 334. CVE-2019-1367 — NEW

**Vendor / Product:** Microsoft / Internet Explorer
**Name:** Microsoft Internet Explorer Scripting Engine Memory Corruption Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Internet Explorer contains a memory corruption vulnerability in how the scripting engine handles objects in memory. Successful exploitation allows for remote code execution in the context of the current user.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 335. CVE-2017-0199 — NEW

**Vendor / Product:** Microsoft / Office and WordPad
**Name:** Microsoft Office and WordPad Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Office and WordPad contain an unspecified vulnerability due to the way the applications parse specially crafted files. Successful exploitation allows for remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 336. CVE-2020-0968 — NEW

**Vendor / Product:** Microsoft / Internet Explorer
**Name:** Microsoft Internet Explorer Scripting Engine Memory Corruption Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Internet Explorer contains a memory corruption vulnerability due to how the Scripting Engine handles objects in memory, leading to remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 337. CVE-2020-1472 — NEW

**Vendor / Product:** Microsoft / Netlogon
**Name:** Microsoft Netlogon Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft's Netlogon Remote Protocol (MS-NRPC) contains a privilege escalation vulnerability when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller. An attacker who successfully exploits the vulnerability could run a specially crafted application on a device on the network. The vulnerability is also known under the moniker of Zerologon.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 338. CVE-2021-26855 — NEW

**Vendor / Product:** Microsoft / Exchange Server
**Name:** Microsoft Exchange Server Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Exchange Server contains an unspecified vulnerability that allows for remote code execution. This vulnerability is part of the ProxyLogon exploit chain.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 339. CVE-2021-26858 — NEW

**Vendor / Product:** Microsoft / Exchange Server
**Name:** Microsoft Exchange Server Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Exchange Server contains an unspecified vulnerability that allows for remote code execution. This vulnerability is part of the ProxyLogon exploit chain.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 340. CVE-2021-27065 — NEW

**Vendor / Product:** Microsoft / Exchange Server
**Name:** Microsoft Exchange Server Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Exchange Server contains an unspecified vulnerability that allows for remote code execution. This vulnerability is part of the ProxyLogon exploit chain.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 341. CVE-2021-1675 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Print Spooler Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Windows Print Spooler contains an unspecified vulnerability that allows for remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 342. CVE-2019-0604 — NEW

**Vendor / Product:** Microsoft / SharePoint
**Name:** Microsoft SharePoint Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft SharePoint fails to check the source markup of an application package. An attacker who successfully exploits the vulnerability could run remote code in the context of the SharePoint application pool and the SharePoint server farm account.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 343. CVE-2021-26857 — NEW

**Vendor / Product:** Microsoft / Exchange Server
**Name:** Microsoft Exchange Server Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Exchange Server contains an unspecified vulnerability that allows for remote code execution. This vulnerability is part of the ProxyLogon exploit chain.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 344. CVE-2021-36955 — NEW

**Vendor / Product:** Microsoft / Windows
**Name:** Microsoft Windows Common Log File System (CLFS) Driver Privilege Escalation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Microsoft Windows Common Log File System (CLFS) driver contains an unspecified vulnerability that allows for privilege escalation.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 345. CVE-2019-18935 — NEW

**Vendor / Product:** Progress / Telerik UI for ASP.NET AJAX
**Name:** Progress Telerik UI for ASP.NET AJAX Deserialization of Untrusted Data Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Progress Telerik UI for ASP.NET AJAX contains a deserialization of untrusted data vulnerability through RadAsyncUpload which leads to code execution on the server in the context of the w3wp.exe process.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 346. CVE-2021-22893 — NEW

**Vendor / Product:** Ivanti / Pulse Connect Secure
**Name:** Ivanti Pulse Connect Secure Use-After-Free Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Ivanti Pulse Connect Secure contains a use-after-free vulnerability that allow a remote, unauthenticated attacker to execute code via license services.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 347. CVE-2019-11510 — NEW

**Vendor / Product:** Ivanti / Pulse Connect Secure
**Name:** Ivanti Pulse Connect Secure Arbitrary File Read Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Ivanti Pulse Connect Secure contains an arbitrary file read vulnerability that allows an unauthenticated remote attacker with network access via HTTPS to send a specially crafted URI.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 348. CVE-2019-11539 — NEW

**Vendor / Product:** Ivanti / Pulse Connect Secure and Pulse Policy Secure
**Name:** Ivanti Pulse Connect Secure and Policy Secure Command Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Ivanti Pulse Connect Secure and Policy Secure allows an authenticated attacker from the admin web interface to inject and execute commands.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 349. CVE-2018-2380 — NEW

**Vendor / Product:** SAP / Customer Relationship Management (CRM)
**Name:** SAP Customer Relationship Management (CRM) Path Traversal Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** SAP Customer Relationship Management (CRM) contains a path traversal vulnerability that allows an attacker to exploit insufficient validation of path information provided by users.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 350. CVE-2021-35211 — NEW

**Vendor / Product:** SolarWinds / Serv-U
**Name:** SolarWinds Serv-U Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** SolarWinds Serv-U contains an unspecified memory escape vulnerability which can allow for remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 351. CVE-2021-20021 — NEW

**Vendor / Product:** SonicWall / SonicWall Email Security
**Name:** SonicWall Email Security Improper Privilege Management Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** SonicWall Email Security contains an improper privilege management vulnerability that allows an attacker to create an administrative account by sending a crafted HTTP request to the remote host. This vulnerability has known usage in a SonicWall Email Security exploit chain along with CVE-2021-20022 and CVE-2021-20023 to achieve privilege escalation.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 352. CVE-2019-7481 — NEW

**Vendor / Product:** SonicWall / SMA100
**Name:** SonicWall SMA100 SQL Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** SonicWall SMA100 contains a SQL injection vulnerability allowing an unauthenticated user to gain read-only access to unauthorized resources.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 353. CVE-2021-20022 — NEW

**Vendor / Product:** SonicWall / SonicWall Email Security
**Name:** SonicWall Email Security Unrestricted Upload of File Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** SonicWall Email Security contains an unrestricted upload of file with dangerous type vulnerability that allows a post-authenticated attacker to upload a file to the remote host. This vulnerability has known usage in a SonicWall Email Security exploit chain along with CVE-2021-20021 and CVE-2021-20023 to achieve privilege escalation.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 354. CVE-2021-20023 — NEW

**Vendor / Product:** SonicWall / SonicWall Email Security
**Name:** SonicWall Email Security Path Traversal Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** SonicWall Email Security contains a path traversal vulnerability that allows a post-authenticated attacker to read files on the remote host. This vulnerability has known usage in a SonicWall Email Security exploit chain along with CVE-2021-20021 and CVE-2021-20022 to achieve privilege escalation.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 355. CVE-2021-20016 — NEW

**Vendor / Product:** SonicWall / SSLVPN SMA100
**Name:** SonicWall SSLVPN SMA100 SQL Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** SonicWall SSLVPN SMA100 contains a SQL injection vulnerability that allows remote exploitation for credential access by an unauthenticated attacker.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 356. CVE-2020-12271 — NEW

**Vendor / Product:** Sophos / SFOS
**Name:** Sophos SFOS SQL Injection Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Sophos Firewall operating system (SFOS) firmware contains a SQL injection vulnerability when configured with either the administration (HTTPS) service or the User Portal is exposed on the WAN zone. Successful exploitation may cause remote code execution to exfiltrate usernames and hashed passwords for the local device admin(s), portal admins, and user accounts used for remote access (but not external Active Directory or LDAP passwords).

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 357. CVE-2019-5544 — NEW

**Vendor / Product:** VMware / VMware ESXi and Horizon DaaS
**Name:** VMware ESXi and Horizon DaaS OpenSLP Heap-Based Buffer Overflow Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** VMware ESXi and Horizon Desktop as a Service (DaaS) OpenSLP contains a heap-based buffer overflow vulnerability that allows an attacker with network access to port 427 to overwrite the heap of the OpenSLP service to perform remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 358. CVE-2020-3992 — NEW

**Vendor / Product:** VMware / ESXi
**Name:** VMware ESXi OpenSLP Use-After-Free Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** VMware ESXi OpenSLP contains a use-after-free vulnerability that allows an attacker residing in the management network with access to port 427 to perform remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 359. CVE-2021-22005 — NEW

**Vendor / Product:** VMware / vCenter Server
**Name:** VMware vCenter Server File Upload Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** VMware vCenter Server contains a file upload vulnerability in the Analytics service that allows a user with network access to port 443 to execute code.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 360. CVE-2021-21972 — NEW

**Vendor / Product:** VMware / vCenter Server
**Name:** VMware vCenter Server Remote Code Execution Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** VMware vCenter Server vSphere Client contains a remote code execution vulnerability in a vCenter Server plugin which allows an attacker with network access to port 443 to execute commands with unrestricted privileges on the underlying operating system.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 361. CVE-2021-21985 — NEW

**Vendor / Product:** VMware / vCenter Server
**Name:** VMware vCenter Server Improper Input Validation Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** VMware vSphere Client contains an improper input validation vulnerability in the Virtual SAN Health Check plug-in, which is enabled by default in vCenter Server, which allows for remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---

## 362. CVE-2021-40539 — NEW

**Vendor / Product:** Zoho / ManageEngine
**Name:** Zoho ManageEngine ADSelfService Plus Authentication Bypass Vulnerability
**Matched target(s):** (no configured target matched — reference only)
**Known ransomware use:** Known
**Date added to KEV:** 2021-11-03
**CISA required action:** Apply updates per vendor instructions.

**Description:** Zoho ManageEngine ADSelfService Plus contains an authentication bypass vulnerability affecting the REST API URLs which allow for remote code execution.

**Next Safe Action:** Verify the exact deployed version on the matched target(s) falls within the affected range before treating this as a real finding. Reproduce only within authorized scope.

---
