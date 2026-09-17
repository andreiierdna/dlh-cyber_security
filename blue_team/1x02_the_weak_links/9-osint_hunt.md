# Task 9 — The OSINT Hunt

**Research date:** September 17, 2026

## 1. FortiGate FortiOS — CVE-2024-55591 Authentication Bypass

**Source:** NIST National Vulnerability Database — CVE-2024-55591; Fortinet PSIRT advisory FG-IR-24-535; CISA Known Exploited Vulnerabilities Catalog. [NVD — CVE-2024-55591](https://nvd.nist.gov/vuln/detail/CVE-2024-55591?utm_source=chatgpt.com) [Fortinet PSIRT — FG-IR-24-535](https://www.fortiguard.com/psirt/FG-IR-24-535?utm_source=chatgpt.com)

**CVE:** CVE-2024-55591

**Affected Product / MedDefense Asset:** **AST-043 — FortiGate 100F**, MedDefense's single Internet firewall and VPN termination point for Central, Westside, and HQ. The Asset Registry confirms that it runs FortiOS, but the installed FortiOS version is not documented.

CVE-2024-55591 affects **FortiOS 7.0.0 through 7.0.16**. It is an authentication-bypass vulnerability in the Node.js WebSocket module that can permit a remote attacker to obtain super-administrator privileges through crafted requests. NVD assigns it **CVSS 9.8 Critical**. Fortinet independently classifies the advisory as Critical, confirms exploitation in the wild, and directs FortiOS 7.0 installations to upgrade to **7.0.17 or later**. CISA added the CVE to the Known Exploited Vulnerabilities catalog on January 14, 2025.

**Why the Scan Missed It:** The FortiGate was not identified as a named responsive host in the vulnerability scan. The 1x00 Asset Registry explicitly notes that the FortiGate and several other network assets are absent from the Nmap host list. The firewall's exact FortiOS release is also undocumented, meaning the scanner could not demonstrate whether the installed firmware falls within the vulnerable 7.0.0–7.0.16 range.

**CVSS / Severity:** **9.8 Critical — NVD.** Fortinet's PSIRT advisory also classifies the issue as Critical and reports known exploitation.
**MedDefense Impact:** If AST-043 runs an affected FortiOS version, exploitation could give an external attacker super-admin control over the device protecting MedDefense's network perimeter. Fortinet reports observed attacker activity including creating administrator and local accounts, changing firewall policies, adding users to SSL-VPN groups, and then using those accounts to establish VPN tunnels into internal networks. For MedDefense, that could bypass the perimeter and provide direct access toward EHR, Active Directory, billing, backup, and medical-device networks.

This directly connects to **GAP-003 — Network Core Is Exposed to Unauthorized Administrative Control**, because AST-043 is part of the Critical network-core infrastructure and unauthorized firewall configuration changes can affect the confidentiality, integrity, and availability of multiple downstream assets. It also maps directly to the 1x01 **Ransomware Group** threat model, which specifically identifies FortiGate/VPN exploitation as a likely initial-access path and names AST-043 as MedDefense's single firewall and VPN termination point.

**Recommendation:** Immediately identify and record the exact FortiOS version running on AST-043. If it is FortiOS 7.0.0–7.0.16, upgrade using Fortinet's supported upgrade path to at least 7.0.17 or a current supported release. Review FortiGate logs for the indicators and unexpected administrator/local accounts described by Fortinet. Restrict HTTP/HTTPS administrative access to dedicated management addresses or a management network rather than exposing the GUI broadly. Because CISA lists this vulnerability as actively exploited, remediation should be treated as urgent if the installed firmware is vulnerable.

---

## 2. Microsoft Office 365 / Entra ID — Adversary-in-the-Middle Token Theft

**Source:** Microsoft Security Blog, *Defending against evolving identity attack techniques*, May 29, 2025; Microsoft Entra documentation on token theft and protection. [Microsoft — Defending against evolving identity attack techniques](https://www.microsoft.com/en-us/security/blog/2025/05/29/defending-against-evolving-identity-attack-techniques/?utm_source=chatgpt.com) [Microsoft Entra — Understanding tokens](https://learn.microsoft.com/en-us/entra/identity/devices/concept-tokens-microsoft-entra-id?utm_source=chatgpt.com)

**CVE:** **N/A — attack technique rather than a software vulnerability.**

**Affected Product / MedDefense Asset:** **AST-024 — Microsoft O365 E3**, used organization-wide for email, SharePoint, OneDrive, and productivity services.

The relevant attack technique is **Adversary-in-the-Middle (AiTM) phishing and authentication-token theft**. In an AiTM attack, a malicious reverse proxy sits between the victim and the legitimate Microsoft authentication service. The victim enters valid credentials and may even complete MFA; the attacker relays the authentication process and captures the resulting authenticated session token. Microsoft states that AiTM techniques can capture credentials and session cookies and can bypass some traditional MFA protections through session-token replay.

Microsoft also reported in May 2025 that AiTM phishing kits such as Evilginx were being used by multiple threat actors and recommended stronger controls such as risk-based Conditional Access and phishing-resistant authentication.

**Why the Scan Missed It:** This was explicitly outside the scanner's scope. The vulnerability report states that **cloud services (O365)** were not covered. A network vulnerability scanner examining `10.10.0.0/16` also cannot determine whether users can be socially engineered into authenticating through an attacker-controlled reverse proxy, whether stolen cloud tokens can be replayed, or whether tenant Conditional Access policies sufficiently constrain those sessions.

**CVSS / Severity:** **No CVSS score.** AiTM is an attack technique, not an implementation defect assigned a CVE. Its practical severity depends on identity configuration, MFA type, Conditional Access, device compliance controls, session protections, and the privileges of the victim.

**MedDefense Impact:** Compromise of an Office 365 session could expose organization-wide email, SharePoint, or OneDrive data accessible by the victim. AST-024 is an organization-wide service and is also excluded from MedDefense's Veeam backup scope. A compromised administrator or senior user's session could additionally facilitate internal phishing, mailbox-rule creation, data theft, persistence through malicious OAuth applications, or further credential harvesting.

The closest established 1x00 control gap is **GAP-007 — Active Directory Relies on Passwords Without Mandatory MFA or Centralized Alerting**. Although GAP-007 is primarily scoped to MedDefense's Active Directory assets, it establishes the broader MedDefense identity weakness: strong MFA and automated identity-event detection are incomplete. The 1x01 Nation-State APT assessment also identifies **Microsoft/O365 as an organization-wide information repository and a possible trusted access channel**, while mapping weak identity alerting to GAP-007 and monitoring weaknesses to GAP-016.

**Recommendation:** Require phishing-resistant MFA wherever the tenant and licensing support it, prioritizing privileged and administrative accounts. Microsoft recommends stronger methods and Conditional Access controls because ordinary credential-plus-MFA flows can still be targeted by AiTM techniques. Evaluate Entra Conditional Access policies for device compliance, sign-in risk, unusual locations, and token-replay indicators. Restrict or disable device-code authentication where it is not operationally necessary, review OAuth application consent, monitor unusual mailbox and sign-in activity, and ensure privileged accounts use separate administrative identities. MedDefense should also validate exactly which Entra security capabilities are included in its actual O365 licensing rather than assuming a particular feature is available.

---

## 3. Synology DSM 7 — CVE-2024-45538 WebAPI CSRF / Arbitrary Code Execution

**Source:** Synology Product Security Advisory **Synology-SA-24:27** and NVD CVE record. [Synology-SA-24:27 DSM Advisory](https://www.synology.com/en-uk/security/advisory/Synology_SA_24_27?utm_source=chatgpt.com) [NVD — CVE-2024-45538](https://nvd.nist.gov/vuln/detail/CVE-2024-45538?utm_source=chatgpt.com)

**CVE:** CVE-2024-45538

**Affected Product / MedDefense Asset:** **AST-010 — NAS-01**, a Synology DS1621+ running DSM 7 and serving as MedDefense's primary backup repository. The exact DSM 7 release/build is not documented.

Synology states that CVE-2024-45538 is a **Cross-Site Request Forgery vulnerability in the DSM WebAPI Framework** that can allow a remote attacker to execute arbitrary code through unspecified vectors. The affected releases include DSM versions before **7.2.1-69057-2** and **7.2.2-72806**. Synology assigns the vulnerability a **CVSS 3.1 base score of 9.6** with high confidentiality, integrity, and availability impact.

**Why the Scan Missed It:** The vulnerability scan detected the DSM management interface and identified the platform only generally as Synology DSM. It did not report CVE-2024-45538. Because the MedDefense inventory records only **"Synology DSM 7"** rather than an exact build, the available evidence does not establish whether NAS-01 is vulnerable. The assessment therefore requires manual build verification against the Synology advisory rather than treating this CVE as a confirmed positive.

**CVSS / Severity:** **9.6 Critical by CVSS numerical range**, although Synology labels the overall advisory **Important**. The vendor's CVSS vector is `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`.

**MedDefense Impact:** NAS-01 is not ordinary file storage. It is MedDefense's **primary backup repository** and contains recovery copies of important enterprise systems. If the installed DSM build were vulnerable and the exploitation prerequisites were met, arbitrary code execution on the NAS could allow an attacker to manipulate or destroy backup data, alter DSM configuration, establish persistence, or interfere with recovery operations.

This directly compounds **GAP-004 — Production and Backup Copies Share the Same Failure Domain**. The 1x00 Gap Analysis identifies AST-009 and AST-010 as Critical backup and recovery infrastructure and warns that ransomware could affect both production systems and their primary backups because they are not adequately isolated. The 1x01 ransomware assessment explicitly includes GAP-004 in the attack chain and identifies reachable backup infrastructure as a factor that can turn a system compromise into a prolonged clinical outage.

**Recommendation:** Determine NAS-01's exact DSM version and build number immediately. For affected DSM 7.2.1 systems, upgrade to **7.2.1-69057-2 or later**; for DSM 7.2.2, upgrade to **7.2.2-72806 or later**, following Synology's supported update guidance. Restrict the DSM administrative interface to dedicated administrative systems or a management VLAN, consistent with the previously identified Finding 015. Verify that automatic DSM security updates are enabled where operationally appropriate, review administrator accounts and DSM logs, and strengthen backup architecture with immutable or offline copies so compromise of a single NAS does not eliminate MedDefense's recovery capability.

## OSINT Assessment Conclusion

The OSINT review demonstrates three different ways automated scanning can produce an incomplete vulnerability picture. **CVE-2024-55591** may affect MedDefense's perimeter firewall, but the FortiGate was not adequately fingerprinted and its firmware version is undocumented. **AiTM token theft against Microsoft 365/Entra ID** has no CVE at all and was invisible because Office 365 was explicitly outside the scan scope. **CVE-2024-45538** potentially affects DSM 7 on the primary backup NAS, but applicability depends on an exact DSM build that the automated results did not establish. These findings reinforce the earlier 1x00 and 1x01 conclusions: vulnerability management must be tied to asset inventory, identity architecture, threat intelligence, cloud-service assessment, and recovery infrastructure rather than relying solely on the list of CVEs generated by one network scan.
