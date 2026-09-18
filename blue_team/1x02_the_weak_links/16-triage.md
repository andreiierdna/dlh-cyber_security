# Task 16 — The Noise Filter

## Full Finding Triage

Finding 001 | CVSS 9.8 / Critical | billing-srv-01 (10.10.2.15) | Category: AC | Reason: Unauthenticated Apache mod_lua RCE is confirmed on a previously compromised billing server and combines directly with Finding 002 for root compromise.

Finding 002 | CVSS 7.8 / Critical | billing-srv-01 (10.10.2.15) | Category: AC | Reason: Confirmed Apache privilege escalation can convert the Finding 001 web-service foothold into root access and therefore completes a practical compromise chain.

Finding 003 | Critical / No CVSS | ehr-db-01 (10.10.2.11) | Category: AC | Reason: The EHR database containing PHI accepts PostgreSQL connections from the entire 10.10.0.0/16 network, giving any compromised internal host direct network access to a Critical data store.

Finding 004 | Critical / Multiple CVEs | WS-RAD-01 (10.10.1.70) | Category: AC | Reason: The unsupported Windows XP MRI workstation exposes multiple weaponized RCE vulnerabilities including EternalBlue, BlueKeep and MS08-067 while remaining unsegmented from ordinary workstations.

Finding 005 | CVSS 7.5 / High | web-srv-01 (10.10.2.50) | Category: AS | Reason: TLS 1.0 remains enabled on the Internet-facing patient portal and should be removed through planned TLS hardening.

Finding 006 | High / No CVSS | billing-srv-01 (10.10.2.15) | Category: AS | Reason: MySQL listens on all interfaces and is reachable broadly across the flat network, unnecessarily exposing Restricted billing data.

Finding 007 | High / No CVSS | ad-dc-01 (10.10.2.20) | Category: AC | Reason: LDAP signing is not required on a Critical Domain Controller, increasing relay and directory-manipulation risk across the flat internal network.

Finding 008 | High / CVE-2021-34527 8.8 | print-srv-01 (10.10.2.31) | Category: AS | Reason: The end-of-support Windows Server 2012 R2 print server runs the Print Spooler and has a known weaponized PrintNightmare exposure requiring planned but expedited remediation.

Finding 009 | High / No CVSS | billing-srv-01 (10.10.2.15) | Category: AS | Reason: Password-based SSH with no account lockout creates an avoidable brute-force and credential-compromise path on an already high-risk server.

Finding 010 | CVSS 7.5 / High | BD Alaris pumps (10.10.3.40-46) | Category: AS | Reason: The reported CVE applicability is questionable for firmware 12.1.2, but all seven tested pumps use default admin/admin credentials and remain insufficiently segmented, so the overall finding still requires remediation.

Finding 011 | High / No CVSS | billing-srv-01 (10.10.2.15) | Category: AS | Reason: Ubuntu 18.04 is outside standard support, ESM is not enabled, and the server is therefore not receiving normal OS security updates.

Finding 012 | Medium / No CVSS | web-srv-01 (10.10.2.50) | Category: AS | Reason: Missing CSP, HSTS, X-Frame-Options and related headers remove useful browser-side defenses on the Internet-facing patient portal.

Finding 013 | Medium / No CVSS | web-srv-01 (10.10.2.50) | Category: AS | Reason: The patient-portal certificate expires in 23 days with no automatic renewal, creating an imminent availability and trust problem.

Finding 014 | Medium / No CVSS | Westside Netgear router (10.10.10.1) | Category: AS | Reason: A consumer-grade perimeter device with an internally reachable administration interface terminates the trusted VPN into Central and lacks enterprise security capabilities.

Finding 015 | Medium / No CVSS | NAS-01 (10.10.2.41) | Category: AS | Reason: The DSM administration interface for the primary backup repository is reachable throughout the internal network and the stored backups are unencrypted.

Finding 016 | Medium / No CVSS | Philips IntelliVue monitors (10.10.3.10-32) | Category: AC | Reason: Unauthenticated clinical management and HL7 interfaces are broadly reachable on the flat network, creating confidentiality, availability and potential patient-safety consequences on Critical medical IoT.

Finding 017 | Medium / No CVSS | ehr-srv-01 (10.10.2.10) | Category: AS | Reason: Tomcat error pages disclose exact software-version and internal-path information that materially assists targeted vulnerability research against the Critical EHR server.

Finding 018 | Medium / No CVSS | ad-dc-01 and ad-dc-02 (10.10.2.20-21) | Category: AS | Reason: DES and RC4 Kerberos support increases offline credential-cracking and Kerberoasting risk on Critical identity infrastructure.

Finding 019 | Medium / No CVSS | Multiple RDP hosts | Category: I | Reason: RDP is enabled on five systems but Network Level Authentication is also enabled, so the observation should be documented and monitored rather than treated as a standalone confirmed vulnerability.

Finding 020 | CVSS 9.8 / Medium | backup-srv-01 (10.10.2.40) | Category: FP | Reason: CVE-2023-38408 depends on forwarded ssh-agent/PKCS#11 conditions that SecurePoint identified as unlikely in this server's operational context, so it should be closed after confirming agent forwarding is not used.

Finding 021 | Medium / No CVSS | web-srv-01 (10.10.2.50) | Category: I | Reason: HTTP TRACE is low risk by itself and normally becomes useful only when combined with another web weakness such as XSS, which the scan did not demonstrate.

Finding 022 | Low / No CVSS | ehr-srv-01 (10.10.2.10) | Category: I | Reason: A 47-second clock skew is a real operational observation but does not represent a material security vulnerability by itself.

Finding 023 | Low / No CVSS | Approximately 280 clinical workstations | Category: AS | Reason: Unrestricted USB mass storage creates a real malware-entry and data-exfiltration path across a large clinical endpoint population.

Finding 024 | Low / No CVSS | pacs-srv-01 (10.10.2.12) | Category: AS | Reason: DICOM traffic containing patient identifiers and medical images crosses the network without TLS encryption and should be protected as Restricted clinical data.

Finding 025 | Low / No CVSS | ad-dc-01 (10.10.2.20) | Category: AS | Reason: Unrestricted DNS zone transfers disclose internal hostnames, addresses and network structure and can materially improve attacker reconnaissance.

Finding 026 | Low / Multiple CVEs | billing-srv-01 (10.10.2.15) | Category: AS | Reason: The outdated Linux kernel contains numerous known vulnerabilities and compounds the server's existing Findings 001, 002 and 011 even though most require local access.

Finding 027 | Informational | Windows workstation fleet | Category: I | Reason: Sophos is the intended primary antivirus and Windows Defender not being primary is expected, although the 15 inactive Sophos agents should continue to be monitored.

Finding 028 | Informational | UNKNOWN-01 (10.10.2.99) | Category: AS | Reason: An unmanaged Linux system exposing SSH, Cockpit and a probable Jupyter Notebook on the server subnet requires ownership identification and security review rather than simple documentation.

Finding 029 | Informational / CVE-2021-43798 7.5 | Unknown Westside host (10.10.10.200) | Category: AS | Reason: The undocumented Grafana 8.2.0 host is associated with a publicly exploitable unauthenticated path-traversal vulnerability and therefore requires validation and remediation.

Finding 030 | Informational | ehr-srv-01 (10.10.2.10) | Category: I | Reason: The certificate common-name warning occurs when clients use the IP address instead of the intended hostname and the scan explicitly identifies it as an operational rather than security vulnerability.

Finding 031 | CVSS 9.8 / High | ehr-srv-01 (10.10.2.10) | Category: FP | Reason: Prior validation found that the reported Tomcat 9.0.31 release is outside the vulnerable Ghostcat range, so an active AJP connector alone does not establish CVE-2020-1938.

---

# Triage Summary

Actionable Critical (AC): 6 findings

Actionable Standard (AS): 18 findings

Informational (I): 5 findings

False Positive (FP): 2 findings

Total: 31 findings

6 AC + 18 AS + 5 I + 2 FP = 31 total findings.

---

# Actionable Findings List

## Actionable Critical — Immediate Remediation (24-48 Hours)

1. Finding 004 — Windows XP MRI workstation with multiple weaponized RCE vulnerabilities.
2. Finding 003 — EHR PostgreSQL database reachable across the entire internal network.
3. Finding 007 — LDAP signing not required on the primary Domain Controller.
4. Finding 016 — Philips IntelliVue clinical interfaces broadly reachable without meaningful network protection.
5. Finding 001 — Apache mod_lua remote code execution on billing-srv-01.
6. Finding 002 — Apache privilege escalation completing the billing-srv-01 RCE-to-root chain.

Findings 001 and 002 should be remediated together because the scan explicitly identifies them as a chained attack path rather than independent weaknesses.

## Actionable Standard — Scheduled Remediation (7-30 Days)

1. Finding 010 — BD Alaris default credentials and inadequate medical-device isolation.
2. Finding 015 — Backup NAS management interface broadly reachable.
3. Finding 008 — End-of-support print server and PrintNightmare exposure.
4. Finding 006 — MySQL unrestricted network binding.
5. Finding 011 — Ubuntu 18.04 without Extended Security Maintenance.
6. Finding 029 — Undocumented Grafana 8.2.0 system with CVE-2021-43798 exposure.
7. Finding 018 — Weak Kerberos encryption on both Domain Controllers.
8. Finding 009 — Password-based SSH without account lockout.
9. Finding 024 — Unencrypted DICOM clinical traffic.
10. Finding 014 — Consumer-grade Westside perimeter/VPN router.
11. Finding 005 — TLS 1.0 on the Internet-facing patient portal.
12. Finding 013 — Patient-portal certificate nearing expiration.
13. Finding 025 — DNS zone transfers permitted to arbitrary requesters.
14. Finding 017 — Tomcat version and internal-path information disclosure.
15. Finding 023 — USB mass storage unrestricted across clinical endpoints.
16. Finding 026 — Outdated billing-server kernel with numerous known CVEs.
17. Finding 028 — Unmanaged Linux/Jupyter/Cockpit server on the server network.
18. Finding 012 — Missing HTTP security headers on the patient portal.

---

# Triage Interpretation

The triage reduces the original 31-item scanner output to **24 findings requiring remediation**, of which six warrant immediate attention and eighteen can enter planned remediation. Five observations are retained for monitoring rather than being treated as active vulnerabilities, and two findings can be removed from the remediation queue after false-positive validation. This demonstrates the purpose of vulnerability triage: scanner severity alone does not determine action. Asset criticality, exploitability, attack chaining, network exposure, patient-safety impact and validation evidence determine whether a finding becomes an emergency change, a scheduled fix, a monitoring item or a documented false positive.
