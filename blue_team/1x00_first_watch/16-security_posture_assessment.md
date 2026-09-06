# MedDefense Health Systems

## Security Posture Assessment

**Prepared for:** Executive Leadership and Board of Directors

**Assessment Scope:** MedDefense Central Hospital, Westside Clinic, Corporate HQ, shared technology services, clinical systems, medical devices, data repositories, security controls, and identified shadow IT

---

# 1. Executive Summary

MedDefense Health Systems has meaningful security controls, but its overall security posture is **high risk and materially below the level required for an organization whose technology directly supports patient care**. The organization has perimeter filtering, endpoint protection on managed Windows workstations, authentication controls, backups, local logging, physical security measures, and security awareness training; however, these controls are unevenly deployed and do not provide adequate defense-in-depth around the systems whose failure could disrupt clinical operations. None of MedDefense's five most critical asset groups is assessed as well protected: the EHR and Active Directory environments are only partially protected, while PACS/MRI, the network core, and medical IoT are under-protected.

The **single most critical structural finding is the absence of effective internal segmentation combined with inadequate security monitoring**. Central Hospital operates as an effectively flat environment in which workstations, servers, and medical devices remain broadly reachable. This means that compromise of one endpoint can create a path toward EHR, Active Directory, PACS, backup infrastructure, or bedside devices. The risk is amplified because security events are recorded primarily in local logs without centralized correlation or automated alerting; MedDefense's billing server previously ran unauthorized cryptomining malware for at least two weeks before the issue was recognized through performance symptoms rather than security detection.

### Top Three Recommended Actions

1. **Establish vulnerability and patch management.** Known vulnerabilities in internet-facing or critical infrastructure must be identified, prioritized, remediated, and independently verified. This directly reduces the probability of initial compromise and addresses a weakness that initiated two of the three external healthcare breach scenarios reviewed during this assessment.
2. **Segment critical clinical and infrastructure networks.** Medical devices, servers, administrative endpoints, and management interfaces should be separated using enforceable VLANs, ACLs, and default-deny communication rules. This limits lateral movement after an initial compromise and directly protects bedside clinical technology.
3. **Create resilient recovery and response capability.** MedDefense should establish an isolated or immutable secondary backup copy, perform recurring restoration tests, and implement a formal incident response process. Current backups share the production failure domain, meaning ransomware or a physical event could affect both production and recovery resources simultaneously.

**Budget implication:** The seven recommended first-year treatments require an estimated **$118,000 of the available $120,000 annual security budget**, leaving a $2,000 contingency and allowing the highest-leverage program to proceed without deferring a selected treatment solely for budget reasons.

---

# 2. Scope and Methodology

## 2.1 Assessment Scope

The assessment covered the three principal MedDefense operating locations:

* **MedDefense Central Hospital:** 350-bed acute-care facility containing the principal production server environment, EHR infrastructure, PACS, billing systems, Active Directory, backup infrastructure, clinical endpoints, and most connected medical devices.
* **Westside Clinic:** outpatient facility using local systems and shared Central services through a site-to-site VPN.
* **Corporate HQ:** administrative environment supporting Finance, HR, Legal, Marketing, executive leadership, and IT.

The technical scope included servers, endpoints, network devices, medical IoT, applications, data stores, cloud/shadow systems, physical security infrastructure, identity services, backup systems, and intersite connectivity. The environment includes approximately 80 connected patient monitors and approximately 120 networked infusion pumps, together with EHR, imaging, billing, authentication, and administrative systems.

## 2.2 Sources of Information

The assessment used evidence gathered throughout the project, including:

* IT asset and environment documentation;
* full-network scan results;
* Asset Registry and Asset Criticality Assessment;
* Data Map and classification analysis;
* firewall, SSH, antivirus, backup, physical security, and policy artifacts;
* Complete Control Matrix;
* physical security walk-through findings;
* billing-srv-01 diagnostics and incident root-cause analysis;
* historical incident records;
* Shadow IT findings;
* external healthcare breach summaries;
* Risk Treatment Decisions; and
* Marcus Webb's unfinished predecessor assessment, which was reconciled against the completed findings rather than accepted without validation.

The methodology deliberately combined **asset criticality, data sensitivity, control effectiveness, observed weaknesses, demonstrated incidents, and external healthcare breach patterns**. This approach prevents risk from being ranked solely by technical severity without considering clinical and business consequence.

## 2.3 Limitations and Assumptions

The assessment has four material limitations.

First, the network scan identified only assets that were powered on and responsive at the time of scanning. The inventory therefore cannot prove that every device has been discovered.

Second, endpoint counts remain approximate. Existing documentation and scan results differ, and the documented clinical thin-client population has not been fully reconciled. The Asset Registry specifically concludes that MedDefense still lacks a completely reconciled source of truth.

Third, where encryption, configuration, ownership, or management controls were not evidenced, this report uses **"not evidenced" rather than assuming absence**. This distinction is necessary because failure to produce evidence does not prove that a safeguard does not exist.

Fourth, several MRI-related controls in the Complete Control Matrix are design-state recommendations rather than operational safeguards. They are not treated as if they currently reduce risk.

---

# 3. Asset Landscape

## 3.1 Asset Inventory Summary

The formal Asset Registry contains **56 asset records**. Task 11 subsequently added AST-057, the personal Cardiology research NAS, and AST-058, the Marketing Google Drive controlled through a personal account. The assessment-wide inventory therefore comprises **58 identified asset records**. The underlying registry covers servers, endpoints, applications, network infrastructure, medical IoT, data stores, and physical infrastructure.

### Asset Count by Type

| Asset Type                 |  Count |
| -------------------------- | -----: |
| Servers                    |     14 |
| Endpoints                  |      8 |
| Physical Infrastructure    |      8 |
| Applications               |      7 |
| Medical IoT                |      7 |
| Network Devices            |      7 |
| Data Stores                |      6 |
| Cloud Service / Data Store |      1 |
| **Total**                  | **58** |

### Asset Count by Principal Site or Hosting Context

| Site / Hosting Context                                  | Identified Records |
| ------------------------------------------------------- | -----------------: |
| Central Hospital                                        |                 35 |
| Westside Clinic                                         |                 10 |
| Corporate HQ                                            |                  3 |
| Organization-wide / multi-site                          |                  4 |
| Shared logical assets not assigned to one physical site |                  5 |
| External SaaS used by Corporate HQ                      |                  1 |
| **Total**                                               |             **58** |

These counts represent **registry records rather than device quantities**. For example, the Philips monitor fleet and BD Alaris infusion-pump fleet are recorded as fleet assets even though they represent approximately 80 and 120 physical devices respectively. This avoids misleading the Board by equating a fleet record with a single device.

## 3.2 Top Five Critical Assets

### 1. EHR System — ehr-srv-01 and ehr-db-01

The EHR is MedDefense's highest-priority asset because confidentiality, integrity, and availability can each create direct clinical consequences. A prior nine-hour outage forced clinicians onto paper records, demonstrating that EHR unavailability immediately degrades coordinated patient care. Unauthorized modification could also affect medication, allergy, diagnosis, or treatment information, while unauthorized disclosure would expose PHI.

### 2. PACS and MRI Imaging Environment

PACS contains Restricted diagnostic imaging and supports diagnosis and treatment. The MRI performs approximately 45 studies per day and depends on connectivity to PACS. The environment also contains an unsupported Windows XP MRI control workstation that cannot be conventionally upgraded without affecting device certification.

### 3. Active Directory

Active Directory provides authentication and directory services across the organization. Compromise could permit account creation, privilege changes, credential resets, or persistent access across multiple departments, while loss of authentication services could affect access to clinical and administrative systems.

### 4. Network Core

The FortiGate, switching infrastructure, and site VPNs are common dependencies for nearly every MedDefense service. Because the current internal environment lacks effective segmentation, compromise or misconfiguration of the network core could enable lateral movement, traffic redirection, security-control bypass, or loss of connectivity across entire sites.

### 5. Medical IoT Fleet

Patient monitors, infusion pumps, and nurse-call systems directly support treatment. Integrity or availability compromise can therefore create a patient-safety issue rather than merely an IT inconvenience. Their exposure is increased because the medical-device environment remains broadly reachable from other internal systems.

## 3.3 Data Classification Summary

MedDefense uses four sensitivity levels, with **Restricted** reserved for PHI, credentials, financial information, and similarly sensitive personal information capable of creating severe regulatory or operational consequences.

The principal data categories assessed are:

| Data Category                                | Classification                                                          |
| -------------------------------------------- | ----------------------------------------------------------------------- |
| Patient medical records / EHR PHI            | **Restricted**                                                          |
| Medical imaging data                         | **Restricted**                                                          |
| Billing, claims and patient financial data   | **Restricted**                                                          |
| Employee HR and payroll records              | **Restricted**                                                          |
| System credentials and authentication data   | **Restricted**                                                          |
| Medical-device and bedside clinical data     | **Restricted**                                                          |
| Backup copies of sensitive enterprise data   | **Restricted**                                                          |
| Security and audit logs                      | **Confidential**                                                        |
| Marketing / internal business communications | **Confidential**, unless patient information is subsequently identified |

The dominant data-security concern is therefore not limited to confidentiality. MedDefense stores Restricted information in systems where incorrect data or prolonged loss of service can also affect clinical care.

---

# 4. Current Security Controls

## 4.1 Control Matrix Summary

The authoritative Complete Control Matrix contains **27 controls**. Six MRI-related entries remain largely proposed rather than operational and must not be interpreted as current risk reduction.

### Controls by Category and Function

| Category       | Preventive | Detective | Corrective | Compensating | Deterrent |  Total |
| -------------- | ---------: | --------: | ---------: | -----------: | --------: | -----: |
| Technical      |          9 |         6 |          2 |            1 |         0 | **18** |
| Administrative |          2 |         0 |          0 |            1 |         0 |  **3** |
| Physical       |          4 |         1 |          0 |            0 |         1 |  **6** |
| **Total**      |     **15** |     **7** |      **2** |        **2** |     **1** | **27** |

The matrix rates technical preventive controls as broadly **Adequate**, but technical detective capability sits at the lower boundary of Adequate, while several administrative and physical control functions have no evidenced controls.

## 4.2 Overall Maturity Assessment

MedDefense's security maturity is **developing and uneven**. The organization has implemented recognizable security safeguards, so it is not operating without controls. The weakness is that protection is concentrated in selected technical preventive mechanisms rather than in a balanced defense-in-depth model.

### Areas of Relative Strength

* Default-deny perimeter firewall capability;
* restricted public web exposure;
* strong SSH hardening on ehr-srv-01;
* password and account lockout policies;
* Sophos antivirus on most managed Windows workstations;
* nightly backup of six Central virtual machines;
* physical entry controls at selected entrances;
* security awareness training; and
* local logging across multiple platforms.

### Areas of Material Weakness

* internal segmentation;
* centralized security monitoring;
* incident response;
* enterprise vulnerability management;
* MFA;
* recovery isolation and testing;
* medical-device security;
* shadow IT governance;
* identity lifecycle management;
* administrative change management; and
* Westside perimeter security.

Administrative × Detective, Administrative × Corrective, Physical × Corrective, and Physical × Compensating are structurally empty in the matrix.

## 4.3 Key Control Effectiveness Findings

The EHR has the strongest control combination among critical systems, but it remains only **Partially Protected** because the database is broadly reachable, MFA is absent, logging lacks centralized alerting, physical protection is incomplete, and backups share the Central failure domain. PACS/MRI and medical IoT are **Under-Protected**, while Active Directory is only Partially Protected and the network core lacks dedicated corrective protection.

The principal maturity issue is therefore **misalignment between controls and criticality**: MedDefense has controls, but the controls are not consistently strongest where patient safety, PHI, enterprise authentication, and recovery dependencies are greatest.

---

# 5. Gap Analysis

The consolidated assessment contains **18 formal numbered security gaps: 9 Critical and 9 High**. No standalone Medium gap remains in the consolidated register. Medium and Low issues still exist—for example the shared Radiology credential and unsupported print server—but they are tracked as subsidiary findings or vulnerability-register items rather than Board-level numbered gaps. Marcus's predecessor review added GAP-016 through GAP-018 after the original Task 12 list was completed.

## 5.1 Critical Gaps

| Gap         | Description                                                                                              | Affected Assets                                                        | Potential Impact                                                                                                                                                                     | Recommended Treatment                                                                                                                        |
| ----------- | -------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| **GAP-001** | PACS has no evidenced recovery capability.                                                               | pacs-srv-01, PACS repository, MRI imaging environment                  | Destructive attack or storage failure could remove access to diagnostic images required for clinical decision-making; no evidenced PACS backup exists.                               | **Mitigate:** implement managed PACS backup/replication and recurring restoration testing.                                                   |
| **GAP-002** | Medical IoT is not adequately segmented, monitored, or recoverable.                                      | Patient monitors, infusion pumps, nurse-call systems                   | Compromise of an ordinary endpoint could provide access to bedside devices, with potential effects on monitoring, medication-related systems, patient data, and device availability. | **Mitigate:** dedicated VLANs, default-deny ACLs, targeted telemetry, configuration recovery, Biomedical Engineering governance.             |
| **GAP-003** | Network core remains exposed to unauthorized administrative control and insufficient internal isolation. | FortiGate, core/access switches, network closets                       | Unauthorized changes could redirect traffic, disable connectivity, or open pathways between clinical and administrative systems.                                                     | **Mitigate:** secure closets, remove exposed credentials, restrict management access, back up configurations, implement priority ACLs.       |
| **GAP-004** | Production and backup copies share the same failure domain.                                              | backup-srv-01, NAS-01, systems dependent on Veeam                      | Ransomware, fire, flood, or physical compromise could remove production data and the recovery mechanism simultaneously.                                                              | **Mitigate:** isolated/immutable secondary copy, separate backup credentials, restoration testing.                                           |
| **GAP-005** | Personal Cardiology research NAS operates outside enterprise controls.                                   | AST-057 personal NAS and connected internal environment                | Potential Restricted research/clinical data could be disclosed or destroyed, and the NAS could provide an unmanaged lateral-movement foothold.                                       | **Mitigate/Avoid:** migrate organizational data to approved storage, validate transfer, securely erase data, disconnect the device.          |
| **GAP-011** | No evidenced enterprise vulnerability and patch-management program.                                      | FortiGate, portal, servers, applications, supported medical technology | Known vulnerabilities may remain exploitable after vendor fixes are available, allowing preventable initial compromise.                                                              | **Mitigate:** vulnerability scanning, severity-based remediation targets, verification, documented exceptions.                               |
| **GAP-012** | No formal enterprise incident response and recovery coordination process.                                | Enterprise-wide                                                        | A major incident could be contained and restored inconsistently, extending EHR, imaging, network, or identity outages and increasing reinfection risk.                               | **Mitigate:** formal IR plan, defined roles, recovery priorities, communications procedures, tabletop exercise, external response contacts.  |
| **GAP-015** | Medical-device administrative credentials are not centrally governed.                                    | Medical IoT fleet                                                      | Default/shared/stale credentials could provide immediate administrative access after an attacker reaches device management interfaces.                                               | **Mitigate:** eliminate default credentials, establish device account ownership, unique credentials and controlled credential escrow.        |
| **GAP-016** | No centralized security monitoring or log-correlation capability.                                        | Enterprise-wide; all Critical asset groups                             | Successful compromise may remain undetected until an operational symptom occurs, increasing dwell time, lateral movement, and data loss.                                             | **Mitigate:** centralize high-value logs and alerting first; phase toward broader SIEM coverage as funding and operational processes mature. |

GAP-016 is supported by a demonstrated MedDefense failure: billing-srv-01 cryptomining operated for at least two weeks and was discovered through performance degradation rather than security detection.

## 5.2 High Gaps

| Gap         | Description                                                                            | Affected Assets                                                           | Potential Impact                                                                                                                               | Recommended Treatment                                                                                                                    |
| ----------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **GAP-006** | EHR database is reachable from more systems than operationally required.               | ehr-db-01, ehr-srv-01, EHR application                                    | Compromised internal systems may gain unnecessary network access to the Restricted EHR database, increasing PHI and record-integrity exposure. | **Mitigate:** restrict PostgreSQL access to approved application dependencies.                                                           |
| **GAP-007** | Active Directory relies on passwords without mandatory MFA or centralized alerting.    | ad-dc-01, ad-dc-02, enterprise identities                                 | Stolen valid credentials could enable privilege abuse and organization-wide compromise.                                                        | **Mitigate:** MFA, privileged-account separation, targeted AD alerting, tested recovery for both DCs.                                    |
| **GAP-008** | Billing server lacks server-class malware protection and effective egress restriction. | billing-srv-01 and billing database                                       | Repeated server compromise could expose Restricted financial/clinical information and interrupt revenue-cycle operations.                      | **Mitigate:** server EDR or equivalent detection and least-privilege outbound filtering.                                                 |
| **GAP-009** | HR and administrative access lacks adequate segmentation and strong authentication.    | file-srv-01, HR/Finance endpoints                                         | Unauthorized access could expose employee identity/payroll information or permit fraudulent data modification.                                 | **Mitigate:** MFA, access-path segmentation and stronger access governance.                                                              |
| **GAP-010** | Marketing data is controlled through a personal Google account.                        | AST-058                                                                   | MedDefense could lose control of corporate information, sharing permissions, retention and account lifecycle.                                  | **Mitigate/Avoid:** migrate to an enterprise-controlled collaboration platform and remove organizational data from the personal account. |
| **GAP-013** | User offboarding is not evidenced as automated or HR-integrated.                       | AD, VPN, EHR and administrative accounts                                  | Former employees or contractors could retain valid access after authorization ends.                                                            | **Mitigate:** HR-integrated deprovisioning, termination SLA, dormant/orphan account reconciliation.                                      |
| **GAP-014** | No evidenced DLP for bulk Restricted-data extraction.                                  | EHR, HR, billing and endpoints                                            | Valid or compromised users could extract large volumes of PHI or sensitive records without alerting.                                           | **Mitigate:** DLP, abnormal-volume monitoring, export controls and removable-media restrictions.                                         |
| **GAP-017** | Westside Clinic security undermines Central protections.                               | Westside consumer router, unmanaged switch, server closet, VPN trust path | Compromise of the consumer-grade perimeter or physical equipment could provide a trusted route toward Central systems.                         | **Mitigate:** managed firewall, locked closet, logging and restricted VPN ACLs.                                                          |
| **GAP-018** | No formal change-management process.                                                   | Enterprise-wide; particularly backup and network infrastructure           | Untested changes can silently disable protective or recovery controls; a prior untested cron change already produced a multi-week backup gap.  | **Mitigate:** approval, testing, peer review, rollback planning and maintenance windows for critical changes.                            |

GAP-017 is significant because Westside currently relies on a consumer-grade Netgear router, lacks a dedicated firewall, and terminates its site VPN on that same device. The change-management finding is similarly evidence-based rather than theoretical: the predecessor review records an untested change that produced an extended backup failure.

## 5.3 Medium Findings

There are **no standalone Medium gaps in the consolidated numbered register**. This does not mean Medium risk is absent. The shared Radiology `raduser` credential remains a Medium accountability weakness because multiple users share one identity, but it is incorporated into the broader PACS finding rather than treated as a separate Board-level gap. The unsupported Windows Server 2012 R2 print server is maintained as a lower-priority vulnerability-management issue.

## 5.4 Gap Distribution and Exposure Concentration

| Risk Level | Formal Gaps | Percentage |
| ---------- | ----------: | ---------: |
| Critical   |       **9** |    **50%** |
| High       |       **9** |    **50%** |
| Medium     |       **0** |     **0%** |
| **Total**  |      **18** |   **100%** |

The gaps are concentrated in three interconnected areas:

1. **Preventive containment:** segmentation, MFA, vulnerability management, egress restrictions, network management protection, and shadow-system governance.
2. **Detective capability:** centralized logging, identity alerting, server detection, and medical-device monitoring.
3. **Corrective capability:** isolated backups, PACS recovery, incident response, network configuration recovery, and tested restoration.

This concentration means MedDefense's greatest exposure is not one isolated application. It is the ability of an attacker to **enter through one weakness, move laterally through a permissive environment, remain undetected, and then compromise recovery capability**. The original Task 12 analysis reached the same conclusion: existing controls are strongest at the perimeter and on selected endpoints but are not consistently extended to servers, medical devices, databases, recovery infrastructure, or internal network paths.

---

# 6. Risk Treatment Recommendations

## 6.1 Seven Priority Recommendations

The available annual budget is **$120,000**. The recommended first-year portfolio uses **$118,000**, preserving a **$2,000 contingency**. Cost figures are planning estimates rather than vendor quotations.

| Priority | Recommendation                                                | Gap(s) Addressed                                | Treatment Strategy | FY Allocation | Target Timeline     |
| -------: | ------------------------------------------------------------- | ----------------------------------------------- | ------------------ | ------------: | ------------------- |
|    **1** | Establish enterprise vulnerability and patch management       | GAP-011; supports GAP-008                       | Mitigate           |   **$18,000** | Long-term, >1 month |
|    **2** | Segment and monitor medical IoT                               | GAP-002; partially GAP-016                      | Mitigate           |   **$30,000** | Long-term, >1 month |
|    **3** | Implement independent backup resilience                       | GAP-004                                         | Mitigate           |   **$25,000** | Within 1 month      |
|    **4** | Harden network-core administration and priority internal ACLs | GAP-003; supports GAP-006 and GAP-017           | Mitigate           |   **$12,000** | Within 1 month      |
|    **5** | Deploy MFA and targeted identity monitoring                   | GAP-007; partially GAP-009, GAP-013 and GAP-016 | Mitigate           |   **$22,000** | Long-term, >1 month |
|    **6** | Establish formal incident response capability                 | GAP-012                                         | Mitigate           |    **$8,000** | Within 1 month      |
|    **7** | Govern medical-device privileged credentials                  | GAP-015                                         | Mitigate           |    **$3,000** | Within 1 month      |
|          | **Total**                                                     |                                                 |                    |  **$118,000** |                     |
|          | **Annual Budget**                                             |                                                 |                    |  **$120,000** |                     |
|          | **Contingency**                                               |                                                 |                    |    **$2,000** |                     |

The program intentionally does **not** allocate approximately $80,000 to a full enterprise SIEM. The first-year strategy instead purchases broader attack-chain reduction through patching, segmentation, identity protection, targeted monitoring, isolated recovery, and response capability.

### Recommendation 1 — Vulnerability and Patch Management

**Treatment:** Mitigate GAP-011.

Implement an authoritative vulnerability-management process covering internet-facing systems, operating systems, applications, firewalls, VPN components, servers, and supported medical technology. Critical internet-facing vulnerabilities should receive accelerated remediation targets and unresolved exceptions should require documented management approval.

**Cost:** $18,000 planning allocation.
**Timeline:** Program establishment begins immediately; mature operation requires more than one month.

**Why this is first:** Two of the three healthcare breaches reviewed began through known vulnerabilities for which patches were already available. MedDefense also has internal evidence that vulnerable software can persist after system rebuilds. Vulnerability management therefore reduces the probability of compromise before segmentation, recovery, or response controls are needed.

### Recommendation 2 — Medical IoT Segmentation and Monitoring

**Treatment:** Mitigate GAP-002 and partially address GAP-016.

Place medical-device classes on dedicated VLANs, implement default-deny ACLs, explicitly permit required clinical communication, and create targeted monitoring for unexpected management or internet-bound traffic.

**Cost:** $30,000.
**Timeline:** More than one month because traffic dependencies must be mapped and validated with Biomedical Engineering.

This is required because approximately 80 monitors and 120 infusion pumps perform clinically significant functions while remaining broadly reachable in the current environment. An incorrect segmentation design could itself affect patient care, so staged deployment and rollback procedures are mandatory.

### Recommendation 3 — Independent Backup Resilience

**Treatment:** Mitigate GAP-004.

Establish an immutable, offline, or otherwise independently protected secondary copy using credentials not available to ordinary production administrators. Define recovery-point objectives and conduct recurring restoration tests.

**Cost:** $25,000.
**Timeline:** Within one month for initial secondary-copy capability and testing schedule.

The current NAS shares the production network and physical environment. A ransomware incident capable of lateral movement could therefore remove both the operational environment and its principal recovery mechanism.

### Recommendation 4 — Network-Core Protection

**Treatment:** Mitigate GAP-003 and provide enabling controls for GAP-006 and GAP-017.

Lock network closets, remove exposed/shared privileged credentials, use named administrative accounts, restrict management interfaces, back up firewall/switch configurations, and implement priority internal ACLs.

**Cost:** $12,000.
**Timeline:** Within one month for high-priority access and management changes; broader segmentation continues thereafter.

This recommendation has enterprise-wide leverage because every major clinical and administrative system depends on the network core.

### Recommendation 5 — MFA and Identity Monitoring

**Treatment:** Mitigate GAP-007 and partially mitigate GAP-009, GAP-013, and GAP-016.

Require MFA for privileged accounts, remote access, VPN use, and supported high-risk applications. Separate administrator accounts from normal user identities and centrally alert on high-value AD events including privileged-group changes, abnormal administrative logins, and account creation.

**Cost:** $22,000.
**Timeline:** More than one month for full coverage; VPN and privileged-account rollout should begin immediately.

MFA materially reduces the value of stolen passwords. Targeted identity monitoring also provides part of the detective capability currently missing from GAP-016.

### Recommendation 6 — Incident Response Capability

**Treatment:** Mitigate GAP-012.

Create an enterprise incident response plan defining severity levels, containment authority, clinical recovery priorities, executive escalation, evidence preservation, internal/external communications, and external response contacts. Conduct at least one ransomware or credential-compromise tabletop exercise.

**Cost:** $8,000.
**Timeline:** Within one month.

The control is inexpensive relative to the operational consequence it addresses. A technically recoverable incident can still become a prolonged clinical outage if responsibilities and recovery priorities are decided for the first time during the event.

### Recommendation 7 — Medical-Device Credential Governance

**Treatment:** Mitigate GAP-015.

Inventory privileged device accounts, change or disable vendor-default credentials where supported, introduce unique credentials, establish controlled credential storage, and define Biomedical Engineering ownership.

**Cost:** $3,000.
**Timeline:** Within one month, with default-credential review beginning immediately.

The recommendation is low cost but high leverage because eliminating known default credentials removes a direct administrative path once an attacker reaches a device management interface.

---

## 6.2 Quick Wins — Within One Week

The following actions can begin or complete within one week using existing staff and the approved program:

1. **Remove exposed network-device credentials and lock accessible network closets** — directly reduces GAP-003 without waiting for broader network redesign.
2. **Issue a formal critical-vulnerability remediation standard and create the initial internet-facing vulnerability list** — establishes the governance foundation for GAP-011.
3. **Begin MFA enforcement for privileged and VPN-access accounts where existing technology supports it** — immediately reduces the probability that a stolen password is sufficient for administrative access.
4. **Inventory medical-device default and shared administrative credentials and change those supported without clinical/vendor impact** — begins GAP-015 remediation.
5. **Draft the incident severity matrix, response contact tree, and executive escalation procedure** — establishes the minimum operational foundation for GAP-012.
6. **Restrict unnecessary access to ehr-db-01 where dependencies are already known and validated** — directly reduces GAP-006.
7. **Identify and isolate or remove confirmed unmanaged systems that have no approved business purpose** — reduces exposure from GAP-005 and other shadow systems.

Quick wins should not be represented as completion of the larger projects. Their purpose is to remove known high-risk conditions while the structural controls are being implemented.

---

## 6.3 Short-Term Priorities — Within One Month

By the end of the first month, MedDefense should target:

* an isolated secondary backup copy and documented restoration schedule;
* locked and access-controlled network equipment areas;
* protected network-device configuration backups;
* tightened Westside VPN access rules and a replacement plan for the consumer router;
* a completed incident response plan and initial tabletop exercise;
* initial medical-device credential remediation;
* a defined vulnerability-scanning cadence;
* MFA coverage for privileged and remote-access populations where technically feasible; and
* centralized collection or managed alerting for a limited set of highest-value events from Active Directory, the firewall, EHR infrastructure, and medical-device network enforcement points.

---

## 6.4 Long-Term Roadmap

After the first-month foundation, the roadmap should focus on:

### 1–3 Months

* implement medical IoT VLANs and enforcement rules;
* extend internal segmentation to servers, workstations, and management interfaces;
* mature vulnerability remediation reporting and exception governance;
* expand MFA to compatible clinical and administrative systems;
* establish HR-integrated identity lifecycle controls under GAP-013;
* replace Westside consumer perimeter equipment under GAP-017;
* establish formal change management under GAP-018; and
* begin migration of shadow IT data to approved platforms.

### 3–6 Months

* implement PACS backup/recovery under GAP-001;
* deploy server EDR and outbound restrictions for billing and other critical servers under GAP-008;
* establish DLP and bulk-data-export monitoring under GAP-014;
* migrate the Marketing personal Google Drive to an enterprise-controlled service;
* complete Cardiology NAS remediation;
* perform broader disaster-recovery testing; and
* reassess network segmentation effectiveness.

### Beyond 6 Months / Additional Funding

A full enterprise SIEM or equivalent managed detection platform should be reconsidered once asset ownership, segmentation, vulnerability management, identity governance, incident response, and alert requirements are sufficiently mature. GAP-016 remains **Critical** even though the current $120,000 budget funds only targeted monitoring. The broader monitoring gap should therefore remain an explicit residual-risk item for the Board rather than being treated as fully remediated.

The current risk decision similarly defers GAP-001, GAP-013, and GAP-014 beyond the first seven funded projects rather than presenting them as resolved.

---

# 7. Conclusion and Next Steps

MedDefense's security posture can be summarized in business terms as follows: **the organization has enough security controls to prevent some routine threats, but not enough coordinated prevention, detection, containment, and recovery capability to withstand a serious compromise without a material risk of clinical and financial disruption**.

The assessment does not identify a single defective product that can be replaced to solve the problem. The principal weaknesses form an attack chain:

**known vulnerability or stolen credential → initial access → lateral movement through a permissive network → delayed detection → access to clinical/identity systems → risk to network-connected backups → prolonged operational recovery.**

That sequence is credible because several stages have already occurred independently at MedDefense. billing-srv-01 has suffered ransomware and later unauthorized cryptomining; the EHR has experienced a nine-hour outage; an unmanaged personal laptop previously reached the HR environment; an unattended clinical workstation exposed an authenticated EHR session; and unmanaged/shadow systems have been identified on internal networks. The risk is therefore based on demonstrated organizational conditions rather than hypothetical threat modeling alone.

If the recommended actions are not implemented, MedDefense should expect the following residual business exposure to remain materially elevated:

* a known vulnerability may provide an avoidable initial foothold;
* a compromised endpoint may reach clinical, identity, or infrastructure systems because internal segmentation remains insufficient;
* stolen credentials may remain useful because MFA coverage is incomplete;
* security events may remain active for extended periods because monitoring is decentralized;
* ransomware may impair both production and recovery data;
* compromise of clinical devices may create patient-safety concerns;
* incident response may be delayed by unclear authority and recovery sequencing; and
* under-protected remote sites and shadow systems may bypass improvements made at Central.

The Board should therefore treat the proposed **$118,000 first-year program as a risk-reduction baseline, not as the completion of MedDefense's security program**.

## Transition to External Threat Landscape Assessment

This internal posture assessment establishes **where MedDefense is exposed**. The next phase should determine **which external threat actors and attack methods are most likely to exploit those exposures**.

Marcus Webb had already begun this transition before leaving. His unfinished assessment specifically identified the need to evaluate ransomware-as-a-service groups, insiders, exploit-based initial access, phishing, valid-account abuse, and threat behavior using frameworks such as MITRE ATT&CK, together with CISA, HHS 405(d), and HC3 healthcare threat information.

The next deliverable should therefore be an **External Threat Landscape Assessment** that:

* identifies the threat actor categories most relevant to a regional healthcare organization;
* maps their common initial-access and lateral-movement techniques to MedDefense's documented gaps;
* evaluates which vulnerabilities are most likely to be targeted;
* prioritizes likely attack scenarios against EHR, VPN, patient portal, Active Directory, PACS, and medical IoT;
* maps those scenarios to MITRE ATT&CK techniques; and
* reassesses whether the current remediation sequence remains appropriate when likelihood is combined with the internal impact analysis.

The current assessment establishes the necessary foundation for that work: MedDefense now knows what it must protect, where controls are insufficient, which risks have already produced operational consequences, and which remediation investments provide the greatest immediate reduction in exposure.
