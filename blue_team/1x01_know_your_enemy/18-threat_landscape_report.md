# MedDefense Health Systems

## Threat Landscape Report

**Prepared for:** Executive Leadership and Board of Directors  
**Assessment date:** 9 September 2026  
**Classification:** Confidential

# Document Control

| **Field**          | **Value**                                                                                                                                                                                     |
|--------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Document           | MedDefense Health Systems - Threat Landscape Report                                                                                                                                           |
| Task               | 18                                                                                                                                                                                            |
| Companion document | Project 0x00 - Security Posture Assessment                                                                                                                                                    |
| Scope              | Central Hospital, Westside Clinic, Corporate HQ, shared services, clinical systems, medical devices, external services, third parties and workforce                                           |
| Primary frameworks | STRIDE; MITRE ATT&CK; kill-chain analysis                                                                                                                                                     |
| Evidence rule      | No finding is treated as MedDefense fact unless supported by Project 0x00 evidence, Task 18 analysis, or a cited external intelligence source. “Not evidenced” is preserved where applicable. |

# Contents

- 1. Executive Summary
- 2. Scope and Methodology
- 3. Healthcare Sector Threat Overview
- 4. MedDefense Threat Actor Profiles
- 5. Attack Surface Analysis
- 6. Critical Attack Paths
- 7. STRIDE Analysis Summary
- 8. Threat Scenarios
- 9. Gap-Threat Correlation
- 10. Prioritized Recommendations
- Appendix A. Evidence and Intelligence Source Register
- Appendix B. Full Threat Scenarios
- Appendix C. ATT&CK Technique Crosswalk
- Appendix D. Recommendation Traceability Matrix

# 1. Executive Summary

Healthcare remains a high-value target because attackers can monetize both the confidentiality of patient information and the operational urgency of clinical services. For MedDefense, this external pressure aligns directly with Project 0x00 findings: a Critical EHR, PACS, Active Directory, Network Core and Medical IoT environment is connected by insufficient internal isolation, password-centric identity, non-isolated recovery, incomplete vulnerability management, and decentralized monitoring. [P0-CRIT; P0-GAP; P0-DM; P0-SPA; T15]

The single most dangerous threat is a ransomware affiliate or Initial Access Broker obtaining access through the FortiGate VPN or stolen credentials, moving through the flat internal network, compromising Active Directory, reaching `ehr-srv-01` / `ehr-db-01`, exfiltrating Restricted PHI, disabling accessible backup recovery points, and encrypting clinical systems. The modeled path affects approximately 50,000 patient records and can convert a perimeter compromise into simultaneous confidentiality, integrity, availability, regulatory and patient-care impact. [T2; T9; T10; T14; T16]

> **Board conclusion**  
> MedDefense is not exposed primarily because it lacks one product. It is exposed because several unrelated entry vectors converge on the same Critical assets through the same three control failures: insufficient internal isolation, identity trust based on reusable passwords, and weak centralized detection.

## Top 3 recommendations

1.  Create enforceable security zones around EHR, Active Directory, PACS, Medical IoT and backup management; harden the Network Core so a VPN or workstation foothold cannot directly reach Critical services (GAP-003, with GAP-006 and GAP-002 dependencies).

2.  Make stolen credentials insufficient and observable by enforcing MFA for privileged/remote/vendor access and centralizing high-value telemetry from FortiGate, Active Directory, EHR, servers and backups (GAP-007 and GAP-016).

3.  Protect recovery and initial-access choke points: isolate or make backup copies immutable, test restoration, and operate accelerated vulnerability management for Internet-facing assets - especially AST-043 and AST-011 - using active-exploitation intelligence such as CISA KEV (GAP-004 and GAP-011).

**Evidence:** P0-SPA Sections 1, 5 and 6; T10 cross-chain analysis; T15 Critical Three; T16 Top Five threats. External context: EXT-1, EXT-2, EXT-7, EXT-8.

# 2. Scope and Methodology

## 2.1 Scope

This report assesses the threat environment facing MedDefense Central Hospital (350-bed acute-care facility), Westside Clinic, Corporate HQ and the shared infrastructure connecting them. It covers Internet-facing services, O365/email, the FortiGate/VPN perimeter, internal servers, EHR, PACS/MRI, Active Directory, backup infrastructure, Medical IoT, clinical endpoints, workforce behavior, shadow IT and third-party access. [P0-SPA; T7]

## 2.2 Intelligence sources used

| **Source class**             | **Sources**                                                                                                                                                                                                                                                                                                               | **Use in this report**                                                                                    |
|------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| MedDefense internal evidence | Project 0x00 Asset Registry, Asset Criticality Assessment / Criticality Matrix, Data Map, Gap Analysis and Security Posture Assessment                                                                                                                                                                                    | Defines assets, data sensitivity, known incidents, control weaknesses and business/clinical consequences. |
| Task 18 analytical work      | Threat Actor Taxonomy; Ransomware Assessment; Insider Assessment; Social Engineering Analysis; Supply Chain Assessment; Threat Actor Matrix; Attack Surface Map; Technical Vectors; Vector-to-Asset Matrix; Kill Chains; STRIDE EHR; ATT&CK Mapping; Threat Scenarios; Gap-Threat Correlation; Threat Priority Assessment | Provides actor, vector, path, framework and prioritization evidence.                                      |
| Government intelligence      | FBI IC3 2025; HHS OCR breach/enforcement material; CISA ransomware advisories and Known Exploited Vulnerabilities                                                                                                                                                                                                         | Provides current sector frequency, regulatory and exploitation context.                                   |
| Industry intelligence        | Verizon 2025 Data Breach Investigations Report - Healthcare NAICS 62                                                                                                                                                                                                                                                      | Provides comparative healthcare incident, actor, motive and data-type statistics.                         |

## 2.3 Analytical frameworks

- STRIDE was applied to the EHR to test spoofing, tampering, repudiation, information disclosure, denial of service and elevation-of-privilege risks against MedDefense-specific controls and gaps. [T11]

- MITRE ATT&CK was used to map scenario behavior to tactics and techniques, including reconnaissance, phishing, scheduled tasks, remote system discovery, credential access, lateral movement, exfiltration and impact. [T13]

- Kill-chain analysis was used to model five end-to-end attack paths and identify break points where a preventive, detective or corrective control can interrupt progression. [T10]

- Cross-chain concentration analysis was then used to recalibrate Project 0x00 gaps by frequency of appearance across five kill chains and three threat scenarios. [T15]

## 2.4 Connection to the Project 0x00 Security Posture Assessment

Project 0x00 answers “where MedDefense is weak.” This report answers “who is most likely to exploit those weaknesses, by what route, against which assets, and with what business consequence.” The Asset Registry supplies concrete assets and identifiers; the Criticality Matrix establishes the clinical/business consequence of compromise; the Data Map establishes where Restricted PHI and recovery copies are located; and the Gap Analysis supplies the numbered control deficiencies used throughout the kill chains and recommendations. [P0-AR; P0-CRIT; P0-DM; P0-GAP; P0-SPA]

The original Asset Registry and Data Map files were not included as standalone attachments in the Task 18 package. Their content is therefore referenced only where it is explicitly carried forward in the Security Posture Assessment and the supplied threat-analysis deliverables; no additional asset or data facts have been inferred. [P0-SPA; T2; T5; T7; T8; T11; T15; T16]

# 3. Healthcare Sector Threat Overview

## 3.1 Why healthcare is targeted

| **Factor**                           | **Sector logic**                                                                                                                                 | **MedDefense connection**                                                                                                                                               |
|--------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Clinical urgency                     | Hospitals cannot tolerate extended loss of EHR, imaging, identity or bedside technology; downtime increases extortion leverage.                  | EHR, PACS, AD, Network Core, Medical IoT and backup infrastructure are Critical. A prior nine-hour EHR outage forced paper workflows. [P0-CRIT]                       |
| High-value, durable data             | PHI combines identity, insurance, clinical and financial information; double-extortion actors can monetize theft even when restoration succeeds. | The Data Map identifies Restricted EHR PHI, imaging, billing/insurance information, credentials, device data and aggregated backup copies. [P0-DM; T2]                |
| Technical debt and patch constraints | Healthcare retains legacy systems and difficult-to-patch devices that provide durable exploit paths.                                             | Windows XP MRI control workstation, Windows Server 2012 R2 print server, Ubuntu 18.04 billing host and vulnerable medical-device firmware are documented. [P0-AR; T8] |
| Complex trust relationships          | Hospitals depend on vendors, cloud services, insurers and remote support; a trusted provider can become a high-leverage entry path.              | MedTech has continuous privileged EHR maintenance access; O365 and other providers hold broad organizational reach. [T5]                                              |

## 3.2 Current trends and emerging threats

- Ransomware and data theft remain the dominant high-consequence pattern. Verizon’s 2025 Healthcare profile records 1,710 incidents and 1,542 confirmed disclosures; System Intrusion (the pattern containing ransomware) moved ahead of Miscellaneous Errors. [EXT-2]

- Financial motivation dominates healthcare breaches. Verizon reports 90% financial motive, while external actors account for 67% of healthcare breaches, internal actors 30%, and partners 4%. [EXT-2]

- Healthcare/Public Health led the critical-infrastructure ransomware complaint counts in the FBI’s 2025 IC3 report, with 460 ransomware complaints and 182 data-breach complaints. [EXT-1]

- Edge-device and VPN exploitation remains operationally important. CISA’s Known Exploited Vulnerabilities catalog includes Fortinet FortiOS vulnerabilities with evidence of exploitation and, for CVE-2025-24472, known ransomware use. This does not establish that MedDefense AST-043 is vulnerable; it establishes that FortiOS patch status is a threat-informed validation priority. [EXT-8; P0-AR; T16]

- Third-party concentration risk is material. HHS states that approximately 192.7 million individuals were impacted by the Change Healthcare incident as of 31 July 2025, demonstrating the scale available to attackers when a healthcare intermediary or trusted service is compromised. [EXT-4]

- Regulatory enforcement continues to follow ransomware and risk-analysis failures. By July 2026, OCR described its OSF Healthcare action as its 21st ransomware enforcement action. [EXT-6]

## 3.3 Sector statistics contextualizing MedDefense

| **Statistic**                  | **Sector result**                                                                                                                                  | **Implication for MedDefense**                                                                                                                          |
|--------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| FBI IC3 2025                   | Healthcare/Public Health: 460 ransomware complaints; 182 data breach complaints among critical-infrastructure reporting. [EXT-1]                 | Ransomware is not an abstract hospital risk; it is a leading reported critical-infrastructure threat.                                                   |
| Verizon DBIR 2025 - Healthcare | 1,710 incidents; 1,542 confirmed disclosures; 67% external actors; 30% internal; 4% partner; 90% financial motive. [EXT-2]                       | Supports prioritizing ransomware, insiders and third-party paths together rather than as separate programs.                                             |
| Verizon DBIR 2025 - data       | Medical data involved in 45% of healthcare breaches; personal data 40%. [EXT-2]                                                                  | Aligns directly with MedDefense’s Restricted EHR and imaging data.                                                                                      |
| Change Healthcare              | Approx. 192.7 million individuals impacted, as reported by HHS on 31 July 2025. [EXT-4]                                                          | Shows how a trusted healthcare intermediary can create systemic blast radius, validating MedTech access as a serious path despite lower APT likelihood. |
| HHS OCR 2026 enforcement       | Four ransomware settlements announced April 2026; OSF action in July 2026 identified as OCR’s 21st ransomware enforcement action. [EXT-5; EXT-6] | Recovery, risk analysis and ransomware preparedness have direct compliance consequences in addition to operational consequences.                        |

# 4. MedDefense Threat Actor Profiles

## 4.1 Six actor types assessed

| **Priority** | **Actor**                                 | **Likelihood** | **Capability**                        | **Most credible MedDefense path**                                                      | **Primary target**                    |
|--------------|-------------------------------------------|----------------|---------------------------------------|----------------------------------------------------------------------------------------|---------------------------------------|
| 1            | Ransomware groups / organized crime       | Critical       | Medium-High                           | FortiGate/VPN exploitation, phishing or valid credentials → AD → EHR/backups       | EHR; AD; backups                      |
| 2            | Insider - negligent                       | High           | Low technical / high effective access | Shadow IT, shared credentials, unsafe admin practices, unattended sessions             | PACS/MRI; EHR; AD                     |
| 3            | Insider - malicious                       | Medium         | Medium effective access               | Valid/stale accounts; legitimate exports; privileged sabotage                          | EHR/billing PHI; AD; Network Core     |
| 4            | Unskilled / opportunistic                 | High           | Low                                   | Automated exploitation of known Internet-facing vulnerabilities or credential stuffing | FortiGate; public web; billing server |
| 5            | Nation-state APT / sophisticated external | Low            | Very High                             | Zero-day/VPN or trusted third-party maintenance path                                   | AD; EHR; trusted relationships        |
| 6            | Hacktivist                                | Low            | Low-Medium                            | Public website/patient portal compromise or DDoS                                       | Public services / connectivity        |

**Evidence:** T6 Threat Actor Matrix; T16 Final Threat Ranking; P0-SPA and prior incidents.

## 4.2 Detailed profile - Rank 1: Ransomware groups

MedDefense fits the ransomware victim profile not because it is simply a hospital, but because the attacker’s operating model maps directly to the environment. AST-043 is the single firewall/VPN termination point; a FortiGate foothold or phished privileged user can reach a broadly connected internal network; Active Directory lacks mandatory MFA; `ehr-db-01:5432` is reachable more widely than necessary; backup infrastructure shares the production failure domain; and centralized detection is absent. `billing-srv-01` has already experienced ransomware and later cryptomining, demonstrating that hostile execution is not hypothetical. [P0-AR; P0-GAP; P0-SPA; T2; T6]

A BlackReef-style RaaS affiliate can buy initial access, enumerate AD and backups, harvest privileged credentials, exfiltrate Restricted patient/financial data, disable recovery and deploy ransomware through domain control. The business pressure is double extortion: restoration pressure plus threat of PHI publication. [T2; T14]

> **MedDefense-specific attack statement**  
> Ransomware groups using VPN exploitation or stolen credentials would target AST-043, traverse insufficiently segmented internal routes to `ad-dc-01/02`, use domain authority to reach `ehr-srv-01` / `ehr-db-01`, remove accessible recovery points on `backup-srv-01` / `NAS-01`, and encrypt the EHR while holding patient data for extortion. [T10; T14; T16]

## 4.3 Detailed profile - Rank 2: Negligent insider

This actor is High likelihood because the relevant behaviors are already documented: shared `raduser/radiology1` credentials, a personal Cardiology NAS containing patient information, a privileged AD credential placed in a script and emailed, and an unattended authenticated EHR session. These actions do not require malicious intent to create an exploitable foothold or to defeat accountability. The flat internal architecture converts local mistakes into enterprise exposure. [T3; T6; T7; P0-SPA]

The most serious target is PACS/MRI because the shared Radiology identity affects a Critical system containing Restricted imaging, the MRI depends on a Windows XP control workstation, and PACS has no evidenced recovery. In this environment, a shared credential complicates attribution and containment during an imaging compromise. [P0-CRIT; P0-GAP; T3; T15]

## 4.4 Detailed profile - Rank 3: Malicious insider

A malicious insider does not need to defeat the firewall. The modeled billing employee uses valid application access to export approximately 200 records per day, moves about 2,800 records to personal USB media, and—if offboarding fails—returns after termination to acquire another 400 records, for approximately 3,200 affected patient records. This path exploits legitimate access, weak DLP, decentralized monitoring and delayed deprovisioning. [T14]

This actor is lower likelihood than negligent insiders but has higher intentionality and can select high-value information or infrastructure while blending with normal workflows. GAP-014 is the strongest preventive/detective control for the bulk-theft portion of the scenario; GAP-013 closes post-termination access. [T15; T16]

# 5. Attack Surface Analysis

## 5.1 External surface

| **Exposure point**                               | **Evidence**                                                                                                                    | **Threat significance**                                                                                                                                                |
|--------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| AST-043 FortiGate 100F / VPN                     | Single firewall and VPN termination point for Westside and HQ; vulnerability/patch process is not mature. [P0-AR; P0-GAP; T7] | A successful exploit or stolen VPN credential provides a foothold adjacent to a network with insufficient internal containment; Rank-1 ransomware path starts here.    |
| AST-021 Patient Portal on AST-011 `web-srv-01` | Prior broken-access-control incident exposed another patient’s lab result; DMZ isolation is unresolved. [P0-AR; T7]           | Demonstrated PHI confidentiality exposure on an Internet-facing application; server compromise could become an internal path if DMZ isolation is weaker than intended. |
| AST-022 Public website on AST-011                | Previously defaced for approximately two hours. [P0-AR; T7]                                                                   | Demonstrates successful unauthorized modification of the exact Internet-facing host that also supports the portal.                                                     |
| Microsoft O365 email/collaboration               | Organization-wide email and collaboration; executive/IT phishing scenarios are credible. [T4; T5]                             | Primary human-entry route for spear phishing, credential theft and BEC; privileged users are especially high value.                                                    |
| Westside edge and trusted VPN                    | Consumer-grade perimeter and trusted route to Central are carried as GAP-017. [P0-GAP; T6; T7]                                | Alternative initial foothold can bypass improvements focused only on Central.                                                                                          |

## 5.2 Internal surface

| **Internal exposure**              | **Evidence**                                                                                                                  | **Consequence**                                                                                                         |
|------------------------------------|-------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------|
| Flat / permissive internal routing | Ordinary endpoints, servers, EHR database, backup management and medical devices remain broadly reachable. [P0-SPA; T7; T9] | Initial compromise is not contained; unrelated entry vectors converge on the same Critical assets.                      |
| EHR database reachability          | `ehr-db-01:5432` reachable from more systems than operationally required (GAP-006). [P0-GAP; T11]                         | Enables direct PHI extraction or database tampering after an internal foothold.                                         |
| Active Directory                   | Password-centric identity; mandatory MFA and centralized identity alerting absent (GAP-007). [P0-GAP]                       | Harvested credentials can become enterprise authority and ransomware deployment capability.                             |
| Backup management                  | Production and recovery share a failure domain (GAP-004); management interfaces are network-reachable. [P0-DM; P0-GAP; T10] | Ransomware can destroy recovery before encrypting production, extending clinical downtime.                              |
| PACS/MRI and legacy workstation    | PACS Critical; Windows XP MRI control workstation; no evidenced PACS recovery. [P0-CRIT; P0-GAP]                            | Supply-chain or internal compromise can affect imaging integrity/availability and approximately 45 MRI studies per day. |
| Medical IoT                        | ~80 monitors and ~120 infusion pumps; segmentation/monitoring/recovery gaps. [P0-SPA; P0-GAP]                               | A general network incident can extend toward bedside technology and patient-safety functions.                           |

## 5.3 Human surface

- IT Director spear phishing: a fake Fortinet emergency patch uses urgency and a look-alike domain; compromise of an IT user can lead toward Network Core and AD. [T4; T13]

- Shared Radiology account: `raduser/radiology1` eliminates individual attribution on PACS activity and increases credential exposure. [T3; T15]

- Offboarding weakness: a contractor account remained active for 47 days and authenticated after authorization ended. [T3; P0-GAP]

- Shadow IT: the personal Cardiology NAS stores patient information outside enterprise controls. [P0-GAP; T16]

- Privileged credential mishandling and unattended sessions show that human actions can bypass otherwise valid technical controls. [T3; T6]

## 5.4 Key exposure conclusion

The external, internal and human surfaces are not independent. A phishing email, vendor compromise, Internet exploit or insider action becomes dangerous when it reaches the same permissive internal network. That architecture is the conversion mechanism that turns diverse entry events into EHR, AD, PACS, backup or Medical IoT incidents. [T7; T9; T10; T15]

# 6. Critical Attack Paths

## 6.1 Five kill chains and break points

| **\#** | **Kill chain**                                                                  | **Primary business impact**                                                  | **Highest-value break points**                                                                      |
|--------|---------------------------------------------------------------------------------|------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| KC-1   | FortiGate VPN exploitation → EHR database compromise                          | EHR PHI theft/tampering/encryption; clinical downtime                        | Patch/harden AST-043; segment VPN from EHR; MFA; centralized EHR/database monitoring.               |
| KC-2   | Spear phishing → Active Directory → enterprise privilege                    | Credential/authorization compromise enabling downstream clinical control     | Email/endpoint controls; phishing-resistant MFA; tiered admin network; alert on privileged changes. |
| KC-3   | Compromised PACS/MRI supply chain → imaging integrity loss                    | Altered/lost diagnostic images; ~45 MRI studies/day disrupted                | Validate vendor software/access; isolate XP MRI workstation; PACS zone; tested PACS recovery.       |
| KC-4   | Phished IT administrator → backup destruction → ransomware recovery failure | Loss of recovery extends outage and extortion leverage                       | MFA/PAW; backup admin isolation; immutable/offline copies; independent sabotage alerts.             |
| KC-5   | Malicious privileged insider → Network Core control → clinical disruption   | Routing/firewall/VPN manipulation causes multi-site outage or control bypass | PAM/MFA; independent approval; two-person network change; configuration monitoring/rollback.        |

**Evidence:** T10 Kill Chains \#1-#5; P0-GAP; P0-CRIT.

## 6.2 Three most connected assets

| **Rank** | **Asset**    | **Evidenced vectors** | **Why it matters**                                                                                                                                  |
|----------|--------------|-----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| 1        | EHR System   | 7 of 8                | Highest connectivity plus Restricted PHI and Critical C/I/A; direct DB reachability means one foothold can become data theft, tampering and outage. |
| 2        | PACS / MRI   | 6 of 8                | Critical imaging, unpatchable XP dependency, shared identity and no evidenced PACS recovery.                                                        |
| 3        | Network Core | 6 of 8                | Force multiplier: FortiGate/Cisco compromise changes policy/connectivity for EHR, PACS, AD, devices, Westside and HQ.                               |

## 6.3 Three most versatile vectors

| **Rank** | **Vector**                | **Asset groups reachable** | **MedDefense significance**                                                                                                   |
|----------|---------------------------|----------------------------|-------------------------------------------------------------------------------------------------------------------------------|
| 1        | Phishing / spear phishing | 7 of 7                     | Can convert one user/admin endpoint into an internal foothold; flat network allows progression to every assessed asset group. |
| 2        | VPN exploit               | 7 of 7                     | AST-043 is a concentrated perimeter dependency; successful compromise bypasses perimeter separation.                          |
| 3        | Malicious insider         | 7 of 7                     | Legitimate credentials, physical presence and authorized connectivity can be combined with weak segmentation.                 |

**Evidence:** T9 Vector-to-Asset Matrix.

# 7. STRIDE Analysis Summary

## 7.1 EHR deep analysis

The EHR STRIDE model identifies two MedDefense-specific threats in each category. Tampering is assessed as the greatest STRIDE risk because an integrity compromise can leave the system available while presenting clinicians with false medication, allergy, diagnosis or treatment information. The risk is amplified by GAP-006 (`ehr-db-01:5432` excessive reachability) and GAP-016 (local logs without centralized correlation). [T11; P0-CRIT]

| **STRIDE**             | **Key EHR threat**                                                                                         | **Primary gaps / evidence**                                                       |
|------------------------|------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------|
| Spoofing               | Stolen clinician credentials or use of an unattended authenticated session.                                | GAP-007; prior unattended EHR session.                                            |
| Tampering              | Direct modification of records through broadly reachable PostgreSQL or compromised authenticated endpoint. | GAP-006; Critical EHR integrity.                                                  |
| Repudiation            | User denies changes or attacker alters local audit evidence after server compromise.                       | GAP-016; local logging.                                                           |
| Information Disclosure | Bulk PHI extraction from `ehr-db-01` or exposure through unmanaged/mobile endpoint.                      | GAP-006, GAP-014, GAP-016; ~25 physician iPads with unresolved management status. |
| Denial of Service      | Ransomware encrypts EHR or network-core/VPN manipulation makes it unreachable.                             | GAP-004, GAP-003, GAP-012; prior 9-hour outage.                                   |
| Elevation of Privilege | Compromised endpoint escalates through AD; stale former-user account retains capability.                   | GAP-007, GAP-013, GAP-016.                                                        |

**Evidence:** T11 STRIDE Threat Model; P0-CRIT; P0-GAP; P0-AR as carried forward.

## 7.2 PACS / MRI top threats

- Integrity: a compromised vendor/update path or legacy workstation can alter, replace, mismatch or delete diagnostic studies; the clinical danger is incorrect diagnosis/treatment rather than only data loss. [T10 KC-3]

- Availability: PACS has no evidenced recovery capability, and MRI depends on an unsupported Windows XP workstation; destructive compromise can interrupt approximately 45 studies/day. [P0-GAP; P0-CRIT; T10]

- Accountability/spoofing: shared `raduser/radiology1` credentials prevent reliable attribution, making malicious or compromised PACS activity harder to distinguish from normal technician activity. [T3; T15]

## 7.3 Active Directory top threats

- Spoofing/elevation: stolen IT or service credentials remain highly valuable because MFA is not mandatory across privileged/remote access. [GAP-007; T10 KC-2]

- Tampering/persistence: domain-admin compromise permits account creation, group membership changes and policy manipulation, enabling enterprise ransomware deployment. [P0-CRIT; T2; T13]

- Availability: loss or manipulation of AD can prevent staff from accessing EHR, file services and administrative systems across the organization. [P0-CRIT]

## 7.4 Network Core top threats

- External control-plane compromise: FortiGate exploitation can create an internal foothold with broad downstream reach. [T10 KC-1; EXT-8]

- Privileged tampering: an authorized network administrator can modify firewall, VPN, switch or route configuration to bypass controls or cause multi-site outage. [T10 KC-5]

- Denial of service / dependency failure: the FortiGate is the single VPN termination point for Westside and HQ, so failure or malicious change can disconnect sites from shared services. [P0-CRIT]

# 8. Threat Scenarios

Full scenario detail is provided in Appendix B. The summaries below identify the business decision each scenario tests.

| **Scenario**            | **Threat path**                                                                                                                                 | **Business impact**                                                                                                                       | **Primary gaps**                                                  |
|-------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------|
| S-1 Operation Flatline  | BlackReef exploits AST-043 → discovers flat network → compromises AD → exfiltrates EHR/HR data → destroys recovery → encrypts systems | Critical clinical outage; ~50,000 patient records in modeled environment; seven-figure extortion; breach notification and recovery crisis | GAP-011, 007, 006, 004, 008, 016, 002                             |
| S-2 The Quiet Departure | Billing employee uses valid access → exports ~200 records/day → ~2,800 to USB → post-termination VPN access → ~400 more                 | ~3,200 records disclosed; privacy/regulatory harm; demonstrates governance failure without malware or perimeter bypass                    | GAP-014, 016, 013, 007 (+ device-control weakness)                |
| S-3 Trusted Path        | MedTech support credential/tool compromised → `ehr-srv-01` → discovery → AD persistence → `ehr-db-01` access → covert collection  | Loss of trust in EHR and identity; containment may require deliberate clinical outage; vendor forensics and prolonged scoping             | GAP-007, 006, 003, 016, 014 + vendor-access governance deficiency |

**Evidence:** T14 The Three Threat Scenarios; T2; T5; T6; T9; T10; T13.

# 9. Gap-Threat Correlation

## 9.1 Threat-informed recalibration of Project 0x00

Threat analysis changes remediation order even when the underlying technical facts do not change. The strongest pattern is concentration: a small number of gaps repeatedly enable different actors to traverse the same Critical environment. [T15]

| **Gap**                                            | **Original** | **Threat-informed** | **Reason for movement**                                                                                |
|----------------------------------------------------|--------------|---------------------|--------------------------------------------------------------------------------------------------------|
| GAP-006 Excessive `ehr-db-01` reachability       | High         | Critical            | Directly used by ransomware and sophisticated third-party/APT paths; enables PHI extraction/tampering. |
| GAP-007 AD password dependence / weak alerting     | High         | Critical            | Appears across 3 of 5 kill chains and all 3 scenarios; converts credentials into enterprise authority. |
| GAP-014 No DLP for bulk Restricted-data extraction | High         | Critical            | Confidentiality objective appears in ransomware, malicious-insider and APT scenarios.                  |
| GAP-005 Cardiology personal NAS                    | Critical     | High                | Still dangerous, but no current T10/T14 attack path requires AST-057.                                  |
| GAP-010 Personal Marketing Google account          | High         | Medium              | Governance issue has materially lower attack-chain leverage than clinical/infrastructure gaps.         |

## 9.2 The Critical Three

| **Rank** | **Gap**                                                      | **Correlation**                 | **Threat-informed meaning**                                                                                                                      |
|----------|--------------------------------------------------------------|---------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| 1        | GAP-016 - No centralized security monitoring/log correlation | 5/5 kill chains + 3/3 scenarios | Every modeled path creates observable activity, but MedDefense keeps evidence separated across firewall, EHR, OS, identity and application logs. |
| 2        | GAP-003 - Network-core protection/internal isolation         | 5/5 kill chains + 2/3 scenarios | Highest-leverage preventive gap: a gateway/workstation/vendor foothold should not automatically reach EHR, AD, PACS or backups.                  |
| 3        | GAP-007 - AD MFA/identity protection                         | 3/5 kill chains + 3/3 scenarios | Stolen or stale credentials become enterprise authority; closure breaks ransomware, insider and third-party progression.                         |

## 9.3 The Surprise

The authoritative Project 0x00 numbered register contains 9 Critical, 9 High and 0 Medium numbered gaps. Creating a fictitious Medium/Low `GAP-xxx` to satisfy a format requirement would break traceability. The legitimate threat-informed surprise is therefore the shared Radiology `raduser/radiology1` subsidiary finding: it was treated as Medium and folded into the PACS finding, but threat analysis elevates it to High remediation priority. [P0-SPA; T15]

The reason is operational: the negligent insider is Rank 2, PACS/MRI is a Critical target, KC-3 shows a credible imaging compromise path, and a shared identity degrades attribution, behavioral baselining, revocation and incident containment. The finding should be tracked as High remediation priority without inventing a new gap ID. [T6; T10; T15]

# 10. Prioritized Recommendations

## 10.1 Top five threats and recommended actions

| **Threat priority** | **Specific threat**                                                             | **Specific gap(s)**                              | **Recommended action**                                                                                                                                                                                                 | **Timing**          |
|---------------------|---------------------------------------------------------------------------------|--------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------|
| 1 - Critical        | FortiGate/VPN ransomware → AD → EHR theft/encryption → backup destruction | GAP-003, 007, 016, 004, 011                      | Immediately restrict VPN/workstation reachability to EHR DB, AD admin and backup management; enforce MFA; centralize priority logs; isolate/immutabilize recovery; validate AST-043 exposure and patch state.          | Now-30 days         |
| 2 - High            | Negligent insider creates unmanaged foothold or weak accountability             | GAP-005; PACS subsidiary finding; GAP-018        | Migrate/erase/disconnect AST-057; replace shared PACS credential with named AD-backed identities; enforce change control for privileged changes.                                                                       | Now-30 days         |
| 3 - High            | Malicious insider / former employee exfiltrates Restricted PHI                  | GAP-014, 013, 016, 007                           | Implement EHR/billing bulk-export monitoring and DLP; block unauthorized removable media transfer; HR-integrated offboarding; alert on post-termination authentication.                                                | 30-90 days          |
| 4 - High            | Opportunistic exploitation of known Internet-facing vulnerabilities             | GAP-011, 008, 016                                | Create authoritative external vulnerability register for AST-043, AST-011 and other exposed services; prioritize KEV/Internet-exploited issues; deploy server EDR/egress restrictions to billing and critical servers. | Immediate + ongoing |
| 5 - Medium          | Compromised MedTech maintenance path → EHR/AD persistence                     | GAP-003, 007, 016 + vendor governance deficiency | Use named vendor identities with MFA through a dedicated jump host; time-box maintenance; restrict ports/targets; session-record privileged access; deny direct access to AD, DB, backups, PACS and IoT.               | 30-90 days          |

**Evidence:** T16 Top Five threats; T15 Critical Three; T5 Supply Chain; P0-GAP.

## 10.2 Strategic two-initiative recommendation

> **Initiative 1 - Critical-system segmentation and Network Core hardening**  
> Implement GAP-003 as the principal architectural control: VPN infrastructure, ordinary endpoints, vendor pathways, Radiology and Medical IoT should communicate with EHR, AD, PACS and backup management only through explicitly required flows. T10 shows segmentation interrupts four external/credential-driven kill chains after initial access and limits malicious-insider blast radius. [T10; T15; T16]

> **Initiative 2 - MFA plus targeted centralized identity/security monitoring**  
> Address GAP-007 and the highest-value portion of GAP-016 by making passwords insufficient and correlating privileged authentication, VPN reconnaissance, EHR exports, server/EDR events, backup changes and Network Core configuration changes. This creates a preventive and detective barrier across ransomware, insider and third-party scenarios. [T10; T15; T16]

## 10.3 Connection to Vulnerability Assessment (1x02)

The next phase should convert threat-informed hypotheses into verified vulnerability evidence. 1x02 should prioritize assets and pathways that appear in the highest-ranked kill chains rather than treating all scan findings as equivalent. Recommended validation scope:

- AST-043 FortiGate 100F: determine exact firmware/build, exposed management/VPN services, configuration, applicable CVEs/KEVs and whether compensating controls are present. Do not assume current vulnerability from product family alone. [GAP-011; EXT-8]

- AST-011 `web-srv-01`: validate portal/public-site software, authentication/authorization controls, DMZ/firewall-zone isolation and the previously demonstrated broken-access-control class. [T7]

- `ehr-db-01`: verify actual source networks allowed to TCP/5432 and test whether ACL changes can reduce reachability without clinical impact. [GAP-006; T11]

- Active Directory: review MFA coverage, privileged groups, service accounts, stale identities, admin workstation separation and alerting. [GAP-007, GAP-013]

- Backup environment: validate management-plane reachability, credential separation, immutability/offline retention and restoration evidence. [GAP-004; T10 KC-4]

- PACS/MRI and Medical IoT: inventory versions/firmware, validate segmentation, verify vendor access and test PACS recovery. [GAP-001, GAP-002, GAP-015]

- `billing-srv-01`: validate Apache/Ubuntu exposures, server-class EDR coverage, outbound controls and persistence/remnants from prior compromise. [GAP-008, GAP-011]

- MedTech access: identify the exact remote-access mechanism, named identities, MFA, source restrictions, maintenance windows, target/port scope and logging/session-recording controls. [T5]

1x02 prioritization rule: exploitability and CVSS should be combined with this report’s threat-path position. A moderate-severity weakness on AST-043, AD, EHR, backups or a trusted vendor path may merit higher remediation priority than a more severe isolated vulnerability on an asset that does not participate in a credible Critical attack chain.

# Appendix A. Evidence and Intelligence Source Register

## A.1 Project 0x00 and Task 18 evidence

| **ID**  | **Source**                                                                        | **Role in analysis**                                                                                              |
|---------|-----------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| P0-AR   | Project 0x00 Asset Registry (referenced through supplied downstream deliverables) | Asset identifiers, platform/service details, prior incidents, ownership/dependencies.                             |
| P0-CRIT | 1x00 - Asset Criticality Assessment / Criticality Matrix                          | Criticality of EHR, PACS, Medical IoT, AD, Network Core and other categories.                                     |
| P0-DM   | Project 0x00 Data Map (referenced through supplied downstream deliverables)       | Restricted PHI locations, backup/recovery data, EHR database control observations, shared-account accountability. |
| P0-GAP  | 1x00 - Prioritized Gap Analysis                                                   | GAP-001 through GAP-018 and original ratings.                                                                     |
| P0-SPA  | 1x00 - Security Posture Assessment                                                | Consolidated posture, scope, incidents, controls, recommendations and prior risk narrative.                       |
| T1      | Threat Actor Taxonomy                                                             | Actor classification and sophistication patterns.                                                                 |
| T2      | Ransomware Threat Assessment                                                      | BlackReef/RaaS lifecycle and MedDefense ransomware mapping.                                                       |
| T3      | Insider Assessment                                                                | Negligent/malicious insider scenarios and observed behaviors.                                                     |
| T4      | Social Engineering Analysis                                                       | Fortinet phish, BEC and human-vector control analysis.                                                            |
| T5      | Supply Chain Risk Assessment                                                      | MedTech/O365/Sophos access and compromise paths.                                                                  |
| T6      | Threat Actor Matrix                                                               | Six actor profiles and Top 3 ranking.                                                                             |
| T7      | Attack Surface Map                                                                | External/internal/human surfaces.                                                                                 |
| T8      | Technical Vector Assessment                                                       | Vulnerable/unsupported systems and other technical vectors.                                                       |
| T9      | Vector-to-Asset Matrix                                                            | Connected assets and versatile vectors.                                                                           |
| T10     | Kill Chains                                                                       | Five end-to-end attack paths and break points.                                                                    |
| T11     | STRIDE EHR                                                                        | MedDefense-specific EHR STRIDE model.                                                                             |
| T13     | MITRE ATT&CK Mapping                                                              | Technique mapping for modeled scenarios.                                                                          |
| T14     | Threat Scenarios                                                                  | Operation Flatline, Quiet Departure, Trusted Path.                                                                |
| T15     | Gap-Threat Correlation                                                            | Recalibration, Critical Three and Surprise.                                                                       |
| T16     | Prioritized Threat Assessment                                                     | Top Five threats and two strategic initiatives.                                                                   |

## A.2 External intelligence sources

| **ID** | **Source**                                                                                                                                             | **URL**                                                                                                                                   |
|--------|--------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| EXT-1  | Federal Bureau of Investigation, Internet Crime Complaint Center, 2025 IC3 Annual Report (published 2026).                                             | <https://www.fbi.gov/file-repository/2025_ic3report.pdf>                                                                                    |
| EXT-2  | Verizon, 2025 Data Breach Investigations Report - Healthcare NAICS 62.                                                                                 | <https://www.verizon.com/business/resources/T850/reports/2025-dbir-data-breach-investigations-report.pdf>                                   |
| EXT-3  | U.S. HHS Office for Civil Rights, Breach Portal - cases affecting 500 or more individuals; accessed 9 Sep 2026.                                        | <https://ocrportal.hhs.gov/ocr/breach/breach_report_hip.jsf>                                                                                |
| EXT-4  | HHS, Change Healthcare Cybersecurity Incident Frequently Asked Questions; updated information includes ~192.7M impacted individuals as of 31 Jul 2025. | <https://www.hhs.gov/hipaa/for-professionals/special-topics/change-healthcare-cybersecurity-incident-frequently-asked-questions/index.html> |
| EXT-5  | HHS OCR, Four HIPAA Security Rule Ransomware Investigations, 23 Apr 2026.                                                                              | <https://www.hhs.gov/press-room/ocr-settles-four-ransomware-investigations.html>                                                            |
| EXT-6  | HHS OCR, Ransomware Investigation with Healthcare System (OSF), 29 Jul 2026.                                                                           | <https://www.hhs.gov/press-room/hhs-ocr-settles-ransomware-investigation-with-healthcare-system.html>                                       |
| EXT-7  | CISA/FBI/ASD ACSC, \#StopRansomware: Play Ransomware, updated 4 Jun 2025.                                                                              | <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a>                                                                       |
| EXT-8  | CISA Known Exploited Vulnerabilities Catalog - Fortinet entries including CVE-2025-24472.                                                              | <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>                                                                              |

External-source use is contextual. Sector intelligence informs likelihood and attacker behavior; it does not substitute for validation of MedDefense firmware, configurations or vulnerabilities. Where external intelligence identifies a Fortinet issue, the report treats it as a 1x02 validation priority rather than claiming AST-043 is affected without version evidence.

# Appendix B. Full Threat Scenarios

## B.1 Scenario 1 - Operation Flatline: FortiGate-to-EHR Double Extortion

Actor and objective: BlackReef-style Ransomware-as-a-Service affiliate; financial gain through PHI theft plus encryption. Initial vector: AST-043 FortiGate VPN exploitation. Target: EHR, Active Directory and recovery infrastructure. [T14]

4.  Reconnaissance: an Initial Access Broker identifies MedDefense’s Internet-facing FortiGate VPN, a single point protecting access to Critical clinical and identity infrastructure.

5.  Initial access: the affiliate exploits an unremediated FortiGate vulnerability and establishes a foothold behind the perimeter, activating GAP-011.

6.  Discovery: broad reachability exposes `ad-dc-01/02`, `ehr-srv-01`, `ehr-db-01`, `billing-srv-01`, `backup-srv-01`, `NAS-01` and other clinical systems; the external exploit becomes an enterprise incident because internal containment is weak.

7.  Credential access / privilege escalation: the attacker harvests privileged/service authentication material and compromises Active Directory; password-centric identity under GAP-007 increases the value of harvested credentials.

8.  Collection and exfiltration: Restricted EHR PHI and HR/financial information are staged and removed before encryption. T14 models approximately 35 GB of EHR data and 8 GB of HR/financial information.

9.  Recovery sabotage: accessible recovery points, shadow copies and backup jobs are removed or disabled, exploiting GAP-004.

10. Impact: enterprise ransomware encrypts EHR and other reachable systems. The modeled environment includes approximately 50,000 patient records; clinicians may be forced to downtime procedures while extortion pressure includes both restoration and threatened data publication.

### Business impact

- Clinical: medication lists, allergies, diagnoses, orders, labs and histories become unavailable; prior nine-hour EHR outage demonstrates immediate workflow degradation.

- Financial: incident response, restoration, overtime, legal/forensic cost, lost revenue and possible seven-figure extortion.

- Regulatory: reportable Restricted-PHI breach, forensic scoping and notification obligations.

- Reputational: simultaneous data loss and clinical outage undermines patient and partner confidence.

### Gaps exploited

- GAP-011 vulnerability management

- GAP-007 AD MFA/identity protection

- GAP-006 EHR database reachability

- GAP-004 recovery failure domain

- GAP-008 server detection/egress

- GAP-016 centralized monitoring

- GAP-002 Medical IoT segmentation/blast radius

### Detection/break opportunities

- External vulnerability and configuration monitoring for AST-043

- VPN reconnaissance and anomalous internal scanning alerts

- Privileged-authentication and AD change monitoring

- Large EHR/database export detection and DLP

- Backup deletion/retention-change alerts

- EDR and coordinated incident response before encryption

## B.2 Scenario 2 - The Quiet Departure: Billing Insider PHI Exfiltration

Actor and objective: malicious billing employee; financial gain through patient-data theft. Initial vector: valid internal application access. Target: EHR/billing PHI. [T14]

11. Authorized collection: while still employed, the insider uses normal EHR permissions to export approximately 200 patient records per day, avoiding malware and perimeter controls.

12. Staging: exports are accumulated on the billing workstation; activity appears technically valid because the user is authenticated.

13. Exfiltration: approximately 2,800 records are transferred to personal USB media, exploiting the absence of targeted DLP/device-control prevention.

14. Termination gap: identity lifecycle controls fail to disable all access promptly. The attacker later reconnects through still-valid remote/account access.

15. Additional theft: approximately 400 more records are obtained after authorization has ended, producing approximately 3,200 affected records in the modeled scenario.

16. Detection challenge: EHR audit logs may show the exports and logins, but decentralized monitoring prevents timely behavioral correlation and escalation.

### Business impact

- Clinical: no immediate outage, but disclosed diagnoses, histories and prescriptions create direct patient harm.

- Financial: investigation, notification, legal/privacy response, fraud exposure and remediation.

- Regulatory: MedDefense must determine affected records/data elements and explain why bulk export, removable-media transfer and post-termination access were not prevented.

- Reputational: demonstrates that approved application functions and valid credentials can be abused repeatedly.

### Gaps exploited

- GAP-014 DLP/bulk Restricted-data extraction

- GAP-016 centralized monitoring

- GAP-013 offboarding

- GAP-007 MFA/identity alerting

- Separate scenario-derived removable-media/device-control weakness

### Detection/break opportunities

- Role-based thresholds for EHR exports

- Alerts on repeated bulk access inconsistent with job role

- Block/approve PHI transfer to removable media

- Daily HR-to-directory offboarding reconciliation

- Immediate alert on post-termination authentication

## B.3 Scenario 3 - Trusted Path: MedTech Maintenance Account Compromise

Actor and objective: sophisticated external / nation-state-style actor; covert collection and persistent access. Initial vector: compromised MedTech maintenance credential or support tooling. Target: `ehr-srv-01`, `ehr-db-01`, Active Directory and trusted healthcare relationships. [T5; T14]

17. Upstream compromise: MedTech credentials, endpoint or remote-support tooling are compromised outside MedDefense’s direct control.

18. Trusted entry: the attacker uses the legitimate maintenance pathway to reach `ehr-srv-01`, bypassing the need to exploit the public perimeter.

19. Discovery: from the EHR server, the attacker identifies broadly reachable database, identity, PACS, billing, backup and device networks because internal isolation is insufficient.

20. Privilege escalation/persistence: the attacker obtains or creates privileged identity material in Active Directory, transforming vendor access into independent MedDefense persistence.

21. Collection: `ehr-db-01` provides proximity to Restricted PHI; GAP-006 and GAP-014 increase the feasibility of covert bulk collection.

22. Covertness: local/decentralized logs under GAP-016 make a legitimate-looking vendor session, identity activity and EHR access harder to correlate.

23. Containment impact: even without destructive malware, MedDefense may need to take EHR or identity systems offline to re-establish trust and validate records/credentials.

### Business impact

- Clinical: potential deliberate EHR/AD outage during containment and integrity validation.

- Financial: vendor forensics, domain recovery, credential replacement, contract disputes, legal review and prolonged monitoring.

- Regulatory: potential Restricted-PHI disclosure with difficult scoping if evidence is incomplete.

- Strategic: loss of confidence that eviction is complete because persistence may survive vendor credential revocation.

### Gaps exploited

- GAP-007 identity protection

- GAP-006 EHR database reachability

- GAP-003 internal isolation

- GAP-016 centralized monitoring

- GAP-014 DLP

- Vendor-governance deficiency: MFA, jump host, time-boxing, session recording and least-privilege scope not evidenced

### Detection/break opportunities

- Named vendor identities with MFA and source restrictions

- Just-in-time/time-boxed access via dedicated jump host

- Session recording and command/activity monitoring

- Explicit deny rules from vendor path to AD, direct database access, backups, PACS, billing and IoT

- Correlate vendor login, internal discovery, AD changes and EHR access in a centralized detection platform

# Appendix C. MITRE ATT&CK Technique Crosswalk

| **Attack stage**        | **Representative technique**                   | **Technique ID** | **MedDefense example**                                                                 |
|-------------------------|------------------------------------------------|------------------|----------------------------------------------------------------------------------------|
| Reconnaissance          | Search Closed Sources: Purchase Technical Data | T1597.002        | BlackReef purchases FortiGate targeting/access data.                                   |
| Initial Access          | Phishing: Spearphishing Link                   | T1566.002        | Fortinet-themed message targets IT Director Sarah Park.                                |
| Execution               | Command and Scripting Interpreter: PowerShell  | T1059.001        | Malicious document launches PowerShell/reverse shell in modeled scenario.              |
| Persistence             | Scheduled Task/Job: Scheduled Task             | T1053.005        | Recurring backdoor on compromised admin workstation.                                   |
| Discovery               | Remote System Discovery                        | T1018            | Flat network allows enumeration of AD, EHR, billing and backup systems.                |
| Credential Access       | OS Credential Dumping                          | T1003            | Privileged/service credential harvesting prior to AD compromise.                       |
| Lateral Movement        | Remote Services / valid account use            | T1021 / T1078    | Movement to domain controllers, EHR and backup management using harvested credentials. |
| Collection/Exfiltration | Archive/Stage and exfiltrate data              | Multiple         | EHR and HR/financial data collected before ransomware impact.                          |
| Impact                  | Data Encrypted for Impact                      | T1486            | Ransomware encryption after recovery sabotage.                                         |

**Evidence:** T13 ATT&CK Mapping. Technique selection is scenario-specific; the crosswalk is a summary, not a replacement for the detailed T13 mapping.

# Appendix D. Recommendation Traceability Matrix

| **Recommendation**                                    | **Threat(s) addressed**                                                   | **Gap(s)**                                  | **Evidence of break point**               | **1x02 validation**                                                        |
|-------------------------------------------------------|---------------------------------------------------------------------------|---------------------------------------------|-------------------------------------------|----------------------------------------------------------------------------|
| Critical-system segmentation / Network Core hardening | Ransomware; negligent/malicious insider; opportunistic; vendor compromise | GAP-003, 006, 002                           | T10 KC-1 through KC-4; T15 Critical Three | Reachability tests, firewall/ACL review, segmentation verification         |
| MFA + privileged identity controls                    | Ransomware; malicious insider; vendor compromise; phishing                | GAP-007, 013                                | T10 KC-1, KC-2, KC-4, KC-5                | MFA coverage, privileged groups, stale/service accounts                    |
| Centralized monitoring                                | All five modeled kill chains / all three scenarios                        | GAP-016                                     | T15: 5/5 kill chains + 3/3 scenarios      | Log-source coverage, alert tests, retention/independence                   |
| Backup isolation/immutability                         | Ransomware / malicious sabotage                                           | GAP-004                                     | T10 KC-4; T14 S-1                         | Management reachability, immutability, credential separation, restore test |
| External vulnerability management                     | Ransomware / opportunistic                                                | GAP-011                                     | T10 KC-1; T16 Rank 4; CISA KEV            | Exact versions/CVEs on AST-043/AST-011 and exposed services                |
| PACS named identities + recovery                      | Negligent insider; supply chain / imaging compromise                      | GAP-001 + shared-account subsidiary finding | T10 KC-3; T15 Surprise                    | PACS authentication model, XP isolation, backup/restore                    |
| DLP / export monitoring                               | Malicious insider; ransomware exfiltration; APT collection                | GAP-014                                     | T14 S-1/S-2/S-3; T15 escalation           | EHR export thresholds, endpoint device controls, data-flow tests           |
| Vendor access gateway                                 | MedTech/supply-chain compromise                                           | GAP-003, 007, 016 + vendor deficiency       | T5; T14 S-3                               | Remote-access mechanism, MFA, scopes, logs/session recording               |

# Report Conclusion

The external threat landscape does not change the central conclusion of Project 0x00; it sharpens it. MedDefense’s highest risk is the repeated conversion of a foothold into Critical enterprise impact. Ransomware is the most dangerous actor because it combines high current sector activity with direct alignment to AST-043, Active Directory, EHR and recovery weaknesses. Insiders are next because MedDefense has already demonstrated shared credentials, shadow IT, stale access and other unsafe behaviors. Third-party and opportunistic paths remain significant because they can bypass deliberate targeting altogether. The remediation priority is therefore to break the common path: contain initial footholds, make credentials insufficient, centralize detection, protect recovery and validate exploitable Internet-facing weaknesses in 1x02.
