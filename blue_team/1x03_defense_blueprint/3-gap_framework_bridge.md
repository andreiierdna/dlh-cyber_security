# MedDefense Health Systems  
## Task 3 — The Gap-to-Framework Bridge

### Purpose

This analysis connects the eight highest-priority gaps identified by the threat-informed re-prioritization in Project 1x01 T15 to the technical evidence from Project 1x02 and to specific NIST CSF 2.0 and CIS Controls.

The resulting traceability chain is:

**Gap → Vulnerability → Threat → Framework Control → Recommended Action**

The eight gaps are taken directly from the T15 threat-informed ranking. The ordering is:

1. GAP-016 — Centralized monitoring/log correlation  
2. GAP-003 — Network-core/internal isolation  
3. GAP-007 — Active Directory/MFA identity protection  
4. GAP-011 — Vulnerability/patch management  
5. GAP-006 — EHR database reachability  
6. GAP-014 — DLP/bulk Restricted-data extraction  
7. GAP-004 — Backup failure-domain isolation  
8. GAP-002 — Medical IoT segmentation/monitoring/recovery  

T15 ranked these gaps according to threat-informed risk, attack-path concentration, actor likelihood, Critical-asset exposure, and ability to interrupt multiple stages of an attack.

---

# 1. GAP-016 — No Centralized Security Monitoring or Log Correlation

**Gap Reference:** GAP-016

**Description:** MedDefense lacks centralized collection, correlation, and alerting across its security-relevant logs, allowing malicious events to remain isolated across individual systems.

**Vulnerability Evidence:** Findings **001, 002, 003, 004, 007, 015, and 016** demonstrate high-value conditions for which centralized monitoring would provide detection opportunities: the billing-server RCE-to-root chain, unrestricted EHR database exposure, weaponized MRI vulnerabilities, Active Directory weaknesses, exposed backup management, and broadly reachable medical-device interfaces. There is no single scanner finding for “missing SIEM”; rather, these findings represent the attack activity that GAP-016 prevents MedDefense from correlating effectively. The wider posture assessment also documents that unauthorized cryptomining on `billing-srv-01` operated for at least two weeks and was discovered from performance degradation rather than a security alert. 

**Threat Context:** TA-1 Ransomware, TA-2 Nation-State APT, TA-3 Malicious Insider, TA-5 Hacktivist, and TA-6 Opportunistic Attacker. GAP-016 intersects **all five T10 kill chains: KC-1 + KC-2 + KC-3 + KC-4 + KC-5 = 5 kill-chain correlations**. It also appears in all three T14 scenarios, producing **5 kill chains + 3 scenarios = 8 modeled correlations**, the highest concentration of any MedDefense gap.

**NIST CSF Function:** **Detect — DE.CM, Continuous Monitoring; DE.AE, Adverse Event Analysis.** NIST CSF 2.0 expects networks and systems to be monitored and security events to be analyzed and correlated.

**CIS Control:** **CIS Control 8 — Audit Log Management**

**Recommended Action:** Centralize high-value FortiGate, Active Directory, EHR, server, endpoint, backup, PACS, and medical-device security logs and implement alerts for the specific reconnaissance, privilege escalation, exfiltration, recovery-destruction, and configuration-change behaviors modeled in the five MedDefense kill chains.

---

# 2. GAP-003 — Network Core Exposed to Unauthorized Administration and Insufficient Internal Isolation

**Gap Reference:** GAP-003

**Description:** MedDefense's flat internal architecture and insufficiently protected network-management plane allow an isolated compromise to develop into lateral movement toward Critical systems.

**Vulnerability Evidence:** Finding **004** places the vulnerable Windows XP MRI workstation on the ordinary workstation network without effective VLAN isolation. Finding **016** confirms that Philips IntelliVue clinical interfaces are broadly reachable. Finding **015** exposes backup-management interfaces throughout the internal network, while Finding **003** shows that the Critical EHR database accepts connections across `10.10.0.0/16`. Together, these findings demonstrate that segmentation weaknesses exist across clinical, recovery, and server environments rather than in one isolated subnet.

**Threat Context:** TA-1 Ransomware, TA-2 Nation-State APT, TA-3 Malicious Insider, TA-4 Negligent Insider, and TA-6 Opportunistic Attacker. T15 maps GAP-003 to **KC-1, KC-2, KC-3, KC-4, and KC-5**, meaning it intersects **5 of 5 kill chains**. It also appears in S-1 and S-3. T15 therefore ranks GAP-003 second overall because the flat architecture repeatedly converts local compromise into enterprise compromise.

**NIST CSF Function:** **Protect — PR.IR, Technology Infrastructure Resilience**

**CIS Control:** **CIS Control 12 — Network Infrastructure Management**

**Recommended Action:** Implement a secure internal network architecture using default-deny segmentation between user, EHR, Active Directory, backup, Radiology/PACS, medical-device, and management zones while restricting network-device administration to controlled privileged paths.

---

# 3. GAP-007 — Active Directory Relies on Passwords Without Mandatory MFA or Centralized Alerting

**Gap Reference:** GAP-007

**Description:** Password-centric authentication and insufficient privileged identity controls allow stolen or retained credentials to become enterprise-level authority.

**Vulnerability Evidence:** Finding **007** confirms that LDAP signing is not required on `ad-dc-01`, increasing relay and directory-manipulation exposure. Finding **018** confirms that the Domain Controllers continue to support weak DES and RC4 Kerberos encryption types, increasing credential-cracking exposure.

**Threat Context:** TA-1 Ransomware, TA-2 Nation-State APT, TA-3 Malicious Insider, TA-4 Negligent Insider, and TA-6 Opportunistic Attacker. GAP-007 appears in **KC-1, KC-2, and KC-4 = 3 kill chains**, and in **S-1, S-2, and S-3 = 3 scenarios**. Therefore:

**3 kill chains + 3 scenarios = 6 modeled correlations.**

T15 consequently upgrades GAP-007 from High to **Critical** and ranks it third overall.

**NIST CSF Function:** **Protect — PR.AA, Identity Management, Authentication, and Access Control**

**CIS Control:** **CIS Control 6 — Access Control Management**

**Recommended Action:** Require MFA for privileged and remote administrative access, separate administrative identities from ordinary user accounts, require LDAP signing after dependency validation, eliminate weak authentication protocols, and centrally alert on privileged Active Directory activity.

---

# 4. GAP-011 — No Evidenced Enterprise Vulnerability and Patch-Management Program

**Gap Reference:** GAP-011

**Description:** MedDefense lacks a repeatable enterprise process for discovering, prioritizing, remediating, and verifying vulnerabilities across traditional IT and legacy clinical systems.

**Vulnerability Evidence:** Findings **001 and 002** create a practical remote-code-execution-to-root compromise chain on `billing-srv-01`. Finding **004** exposes the Windows XP MRI workstation to BlueKeep, EternalBlue, and MS08-067. Finding **008** identifies an end-of-support Windows Server with PrintNightmare exposure, while Finding **011** shows that the billing server runs Ubuntu 18.04 outside normal support without ESM. These are different manifestations of the same lifecycle-management weakness.

Project 1x02 triaged **6 Actionable Critical + 18 Actionable Standard = 24 actionable findings**, demonstrating that the problem extends beyond a single missed patch.

**Threat Context:** TA-1 Ransomware, TA-2 Nation-State APT, TA-5 Hacktivist, and TA-6 Opportunistic Attacker. T15 maps GAP-011 directly to **KC-1** and to the legacy-vulnerability component of **KC-3**. S-1 also begins with exploitation of an unremediated FortiGate vulnerability.

**NIST CSF Function:** **Identify — ID.RA, Risk Assessment**

**CIS Control:** **CIS Control 7 — Continuous Vulnerability Management**

**Recommended Action:** Establish continuous vulnerability management with authenticated recurring scanning, risk-based remediation deadlines, patch verification, ownership, and documented exceptions with compensating controls for systems that cannot be conventionally patched.

---

# 5. GAP-006 — EHR Database Reachable from More Systems Than Operationally Required

**Gap Reference:** GAP-006

**Description:** The Critical EHR PostgreSQL database permits direct network connections from substantially more systems than are necessary to operate the EHR.

**Vulnerability Evidence:** Finding **003** directly confirms:

`pg_hba.conf: host all all 10.10.0.0/16 md5`

and:

`listen_addresses = '*'`

No additional network ACL restricts TCP/5432 to the EHR application server. Any compromised host on the routed MedDefense network can therefore establish direct network connectivity to the database service.

**Threat Context:** TA-1 Ransomware and TA-2 Nation-State APT. GAP-006 maps directly to **KC-1 — FortiGate VPN Exploitation → EHR Database Compromise**. T15 also maps it to S-1 and S-3 and upgrades the gap from High to **Critical**, because unnecessary PostgreSQL reachability becomes a direct objective-stage attack enabler against MedDefense's highest-priority data environment.

**NIST CSF Function:** **Protect — PR.IR, Technology Infrastructure Resilience**

**CIS Control:** **CIS Control 12 — Network Infrastructure Management**

**Recommended Action:** Replace the `/16` PostgreSQL access rule with explicit approved source addresses, restrict TCP/5432 at host and network firewalls, and permit database connectivity only from documented EHR application and authorized administrative systems.

---

# 6. GAP-014 — No Evidenced DLP for Bulk Restricted-Data Extraction

**Gap Reference:** GAP-014

**Description:** MedDefense lacks controls capable of identifying or preventing abnormal bulk extraction of Restricted data through approved applications, removable media, or other authorized communication paths.

**Vulnerability Evidence:** Finding **023** establishes a directly relevant technical condition: USB mass storage is unrestricted across approximately 280 clinical workstations. This creates a practical physical-medium exfiltration route from systems capable of accessing sensitive information. The 1x01 insider scenario confirms the consequence by modeling large-scale patient-data export to removable media.

**Threat Context:** TA-1 Ransomware, TA-2 Nation-State APT, and TA-3 Malicious Insider. T15 does **not** assign GAP-014 a dedicated T10 kill chain, and one should not be invented. Instead, the threat correlation is scenario-wide: GAP-014 appears in **S-1 + S-2 + S-3 = 3 of 3 formal threat scenarios**. Ransomware steals information before encryption, the malicious insider exports PHI directly, and the APT performs covert collection. T15 therefore upgrades GAP-014 from High to **Critical**.

**NIST CSF Function:** **Protect — PR.DS, Data Security**

**CIS Control:** **CIS Control 3 — Data Protection**

**Recommended Action:** Implement monitored controls for bulk Restricted-data export, beginning with EHR and billing export activity and removable media, with approved clinical exceptions and alerting for abnormal transfer volume or destinations.

---

# 7. GAP-004 — Production and Backup Copies Share the Same Failure Domain

**Gap Reference:** GAP-004

**Description:** Production systems and their primary recovery copies can be reached and affected through the same network and administrative environment.

**Vulnerability Evidence:** Finding **015** confirms that the DSM management interface for `NAS-01` is accessible from the entire internal network on TCP/5000 and TCP/5001 and that the NAS stores MedDefense server backups. The asset evidence further places the backup repository in the same Central environment as production systems. 

**Threat Context:** TA-1 Ransomware and TA-3 Malicious Insider/saboteur. GAP-004 maps directly to **KC-4 — Phished IT Administrator → Backup Destruction** and to S-1. KC-4 models the attacker reaching `backup-srv-01` and `NAS-01`, destroying recovery data, and then deploying ransomware against production.

**NIST CSF Function:** **Recover — RC.RP, Incident Recovery Plan Execution**

**CIS Control:** **CIS Control 11 — Data Recovery**

**Recommended Action:** Maintain an isolated or immutable secondary recovery copy using credentials separated from the production trust environment, restrict backup administration to dedicated systems, and perform recurring restoration tests.

---

# 8. GAP-002 — Medical IoT Is Not Adequately Segmented, Monitored, or Recoverable

**Gap Reference:** GAP-002

**Description:** MedDefense's connected medical devices lack adequate network isolation, dedicated monitoring, and reliable recovery/configuration controls despite directly supporting patient care.

**Vulnerability Evidence:** Finding **016** confirms that Philips IntelliVue management and HL7 interfaces are broadly reachable from the internal network. Finding **010** found all seven tested Alaris pumps using default `admin/admin` credentials and inadequate isolation. Finding **024** further identifies unencrypted DICOM communications associated with the imaging environment.

The medical-device assessment concludes that the problem is architectural rather than simply a collection of CVEs: clinical technology relying heavily on network trust is operating inside a broadly reachable environment.

**Threat Context:** TA-1 Ransomware and TA-6 Opportunistic Attacker following an internal foothold. T15 explicitly states that there is **no dedicated Medical-IoT T10 kill chain**, so one should not be fabricated. Instead, GAP-002 is a cross-chain segmentation weakness and appears in S-1 as downstream ransomware blast radius. The gap remains Critical because compromise can affect patient monitoring, medication-related workflows, and clinical availability.

**NIST CSF Function:** **Protect — PR.IR, Technology Infrastructure Resilience**

**CIS Control:** **CIS Control 12 — Network Infrastructure Management**

**Recommended Action:** Place medical-device classes in dedicated default-deny security zones, permit only documented clinical and management communications, eliminate default credentials where supported, monitor abnormal device traffic, and maintain vendor-approved configuration and recovery procedures.

---

# Traceability Summary Table

| Priority | Gap → Description | 1x02 Vulnerability Evidence | 1x01 Threat Context | NIST CSF | CIS Control | Recommended Action |
|---:|---|---|---|---|---|---|
| **1** | **GAP-016 — No centralized monitoring/log correlation** | Findings **001, 002, 003, 004, 007, 015, 016** provide high-value detectable attack conditions | TA-1/2/3/5/6; **KC-1, KC-2, KC-3, KC-4, KC-5**; S-1/S-2/S-3 | **Detect — DE.CM / DE.AE** | **8 — Audit Log Management** | Centralize and correlate high-value security telemetry and alert on the modeled kill-chain behaviors. |
| **2** | **GAP-003 — Network-core/internal isolation weakness** | Findings **003, 004, 015, 016** | TA-1/2/3/4/6; **KC-1 through KC-5**; S-1/S-3 | **Protect — PR.IR** | **12 — Network Infrastructure Management** | Segment Critical environments and tightly control network-administration paths. |
| **3** | **GAP-007 — Password-centric AD/MFA deficiency** | Findings **007, 018** | TA-1/2/3/4/6; **KC-1, KC-2, KC-4**; S-1/S-2/S-3 | **Protect — PR.AA** | **6 — Access Control Management** | Require privileged/remote MFA, harden AD authentication, and monitor privileged identity activity. |
| **4** | **GAP-011 — Vulnerability/patch management deficiency** | Findings **001, 002, 004, 008, 011** | TA-1/2/5/6; **KC-1 and KC-3 legacy component**; S-1 | **Identify — ID.RA** | **7 — Continuous Vulnerability Management** | Establish recurring discovery, risk-based remediation, verification, and exception management. |
| **5** | **GAP-006 — Excessive EHR database reachability** | Finding **003** | TA-1/TA-2; **KC-1**; S-1/S-3 | **Protect — PR.IR** | **12 — Network Infrastructure Management** | Restrict PostgreSQL to explicit EHR dependencies and authorized administration sources. |
| **6** | **GAP-014 — No DLP for bulk Restricted-data extraction** | Finding **023** | TA-1/TA-2/TA-3; **no dedicated T10 KC**; S-1/S-2/S-3 | **Protect — PR.DS** | **3 — Data Protection** | Monitor and control abnormal Restricted-data exports and removable-media transfer. |
| **7** | **GAP-004 — Backups share production failure domain** | Finding **015** | TA-1/TA-3; **KC-4**; S-1 | **Recover — RC.RP** | **11 — Data Recovery** | Create isolated/immutable recovery copies with separate credentials and tested restores. |
| **8** | **GAP-002 — Medical IoT insufficiently segmented/monitored/recoverable** | Findings **010, 016, 024** | TA-1/TA-6; **no dedicated T10 KC; cross-chain segmentation issue**; S-1 blast radius | **Protect — PR.IR** | **12 — Network Infrastructure Management** | Isolate medical devices, restrict required flows, monitor the zone, and establish vendor-approved recovery controls. |

## Strategic Interpretation

The corrected bridge confirms the central conclusion of T15: MedDefense's highest risks are concentrated rather than independent.

**GAP-016 and GAP-003 each intersect all 5 T10 kill chains.** GAP-016 additionally appears in all 3 T14 scenarios, giving it:

**5 kill-chain correlations + 3 scenario correlations = 8 total modeled correlations.**

GAP-003 appears in 5 kill chains and 2 scenarios:

**5 + 2 = 7 modeled correlations.**

GAP-007 appears in 3 kill chains and all 3 scenarios:

**3 + 3 = 6 modeled correlations.**

These calculations explain why monitoring, segmentation, and identity protection occupy the first three positions in the threat-informed strategy rather than merely being selected because a framework recommends them.

The remaining five gaps protect specific high-consequence stages. GAP-011 reduces exploitable entry points; GAP-006 removes unnecessary direct access to the EHR database; GAP-014 reduces the ability of three different actor types to remove Restricted information; GAP-004 preserves recovery after ransomware; and GAP-002 prevents enterprise compromise from reaching systems whose failure can affect patient care.

The resulting framework controls therefore follow directly from MedDefense's observed weaknesses and modeled threats:

**exploitable weakness → initial foothold → unrestricted movement → identity escalation → undetected access/exfiltration → recovery destruction → clinical impact.**

The purpose of the framework is to structure the response to that demonstrated attack path—not to substitute a generic framework checklist for MedDefense-specific risk analysis.
