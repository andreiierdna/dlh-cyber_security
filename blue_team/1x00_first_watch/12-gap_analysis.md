# MedDefense Health Systems

## Prioritized Gap Analysis

### 1. Purpose and Method

This analysis cross-references the Asset Criticality Assessment, Data Map, Complete Control Matrix, and Shadow IT findings to identify the security gaps that create the greatest mismatch between MedDefense's business and clinical exposure and its current control coverage.

The prioritization applies the required rules:

* **Critical** — the gap affects a Critical-rated asset or Restricted data and lacks an effective detective or corrective capability sufficient for that exposure.
* **High** — the gap affects a High-rated asset or Confidential data and existing controls provide incomplete coverage.
* **Medium** — the gap affects a Medium-rated asset, or partial controls materially reduce but do not eliminate the risk.
* **Low** — the gap affects a Low-rated asset and partial compensating measures are present.

The Complete Control Matrix confirms that none of MedDefense's five highest-priority asset groups is well protected: the EHR and Active Directory are only partially protected, while PACS/MRI, the network core, and medical IoT are under-protected.

---

# 2. Prioritized Security Gaps

## GAP-001 — PACS Has No Evidenced Recovery Capability

**Affected Asset(s):** AST-003 pacs-srv-01 and AST-018 PACS application/imaging repository — **Critical**, under the PACS and Diagnostic Imaging asset category. PACS is required for diagnostic imaging and receives studies from the MRI.

**Data at Risk:** Medical imaging data — **Restricted**. Diagnostic images constitute PHI and are directly used for diagnosis and treatment.

**Current Control Status:** General perimeter controls, password policy, physical controls, UPS protection, VPN controls, local logging, and awareness controls exist. However, the Complete Control Matrix specifically states that **no corrective control is evidenced for PACS**, and the proposed MRI controls are not currently implemented.

**What is Missing:**
Technical — **Corrective**: managed PACS backup, recovery replication, and tested restoration. Dedicated PACS monitoring is also inadequate because existing logging is local and does not provide centralized alerting.

**Risk Level:** **Critical**

**Risk Justification:** PACS is a Critical clinical asset containing Restricted imaging data, yet it is deliberately excluded from the Veeam backup scope. The Data Map identifies both the absence of PACS backup and the unsupported MRI dependency as material weaknesses. A destructive attack, corruption event, or storage failure could therefore eliminate access to imaging without an evidenced corrective mechanism capable of restoring the service.

**Potential Impact:** MedDefense could lose access to diagnostic studies required by Central Radiology and Westside imaging. Clinicians could be unable to retrieve images needed for diagnosis and treatment, while corruption or destruction of imaging data could require studies to be repeated where clinically possible. Loss of Restricted imaging data would also create regulatory, operational, and patient-care consequences.

---

## GAP-002 — Medical IoT Is Not Segmented, Monitored, or Recoverable

**Affected Asset(s):** AST-036 Philips IntelliVue monitor fleet, AST-037 BD Alaris infusion-pump fleet, AST-038 connected vital-sign monitor, and AST-039 nurse-call system — **Critical**, under Medical IoT and Clinical Devices. Management interfaces for monitors and infusion pumps remain broadly reachable.

**Data at Risk:** Medical-device and bedside clinical data — **Restricted**.

**Current Control Status:** C-001 perimeter firewall protection, C-004 perimeter logging, C-009 account policy where applicable, C-016 awareness training, and C-020 infrastructure UPS provide indirect protection. The Complete Control Matrix nevertheless states that there is **no dedicated fleet-wide monitoring, no corrective control, and no fleet-wide compensating control** for medical IoT.

**What is Missing:**
Technical — **Preventive:** enforced medical-device VLANs and default-deny internal access controls.
Technical — **Detective:** dedicated device/network behavioral monitoring.
Technical — **Corrective:** configuration recovery and documented device restoration procedures.

**Risk Level:** **Critical**

**Risk Justification:** Medical IoT is a Critical asset category because manipulation or disruption can affect bedside treatment. The Data Map confirms that these devices process Restricted patient-associated information while ordinary endpoints can reach the medical-device environment and endpoint antivirus does not protect the device fleet. The absence of dedicated containment, detection, and recovery therefore leaves no adequate control layer once an internal endpoint is compromised.

**Potential Impact:** An attacker gaining internal access could identify and target patient monitors, infusion pumps, or nurse-call infrastructure. Unauthorized alteration of device information or configurations could affect treatment decisions or medication delivery, while device outages could interrupt patient monitoring and clinical communications.

---

## GAP-003 — Network Core Is Exposed to Unauthorized Administrative Control

**Affected Asset(s):** AST-043 FortiGate 100F, AST-044 Central Cisco core switch, AST-045 access-switch fleet, and AST-051 Central network closets — **Critical**, under Network Core and Security Infrastructure. The FortiGate is MedDefense's single firewall and VPN termination point, while the Cisco infrastructure provides core internal connectivity.
**Data at Risk:** System credentials and authentication data — **Restricted**; clinical and administrative traffic traversing the infrastructure may also contain Restricted information.

**Current Control Status:** C-001 firewall enforcement, C-003 VPN source restriction, C-004 firewall logging, C-009 credential policy, C-017 badge controls, C-020 UPS, and C-027 VPN tunnels exist. The control matrix nevertheless rates the network core **Under-Protected**, with no evidenced corrective control and no dedicated compensating control.

**What is Missing:**
Physical — **Preventive/Detective:** restricted network-closet access, appropriate credential protection, and monitoring of sensitive network locations.
Technical — **Corrective:** protected configuration backups and tested restoration procedures for network infrastructure.

**Risk Level:** **Critical**

**Risk Justification:** Network infrastructure is Critical because changes to routing, switching, firewall, or VPN configurations can affect the confidentiality, integrity, and availability of numerous downstream assets simultaneously. AST-051 records that network infrastructure was inadequately secured and privileged credentials were exposed, providing a direct route to administrative control. Existing perimeter logging does not prevent a person with physical access and valid switch credentials from altering the internal network, and no evidenced corrective capability exists for destructive configuration changes.

**Potential Impact:** An attacker could disable ports or uplinks, redirect traffic, create unauthorized network paths, weaken segmentation efforts, or intercept communications. Because the same infrastructure supports EHR, PACS, Active Directory, medical devices, Westside, and HQ connectivity, a successful compromise could become an enterprise-wide outage or facilitate lateral compromise of multiple Restricted-data environments.

---

## GAP-004 — Production and Backup Copies Share the Same Failure Domain

**Affected Asset(s):** AST-009 backup-srv-01 and AST-010 NAS-01 — **Critical**, under Backup and Recovery Infrastructure. NAS-01 is located in the same server-room/rack area and network as production systems.

**Data at Risk:** Backup copies of sensitive enterprise data — **Restricted**, including EHR, billing, Active Directory, file-share, and patient-portal information.

**Current Control Status:** C-012 performs nightly Veeam backups of six Central virtual machines with 14-day retention. However, there is no offsite or cloud replication, PACS and several other systems are excluded, and only a partial file-server restoration has been tested.

**What is Missing:**
Technical — **Corrective:** geographically or logically isolated backup replication, immutable/offline recovery copies, comprehensive backup scope, and recurring restoration testing.

**Risk Level:** **Critical**

**Risk Justification:** The backup infrastructure is itself Critical because it is MedDefense's principal recovery mechanism. The Data Map states that Restricted backup copies are stored on a NAS in the same network, room, and rack area as production, creating correlated exposure to ransomware, fire, flood, and unauthorized physical access. It further states that only one partial restore has been performed and no full disaster-recovery test has occurred. A control intended to correct destructive events cannot provide reliable protection when the same event can destroy both the original and recovery copy.

**Potential Impact:** A ransomware outbreak or physical loss of the Central server room could simultaneously remove production systems and their primary backups. MedDefense could then be unable to restore EHR, billing, authentication, departmental files, or the patient portal within an acceptable period, significantly extending clinical and business disruption.

---

## GAP-005 — Unmanaged Cardiology NAS Operates Outside Enterprise Controls

**Affected Asset(s):** AST-057 Dr. Patel Personal Research NAS — **Shadow IT**. Task 8 did not assign this subsequently discovered asset a separate criticality rating; for prioritization, its exposure is driven by its connection to the Critical clinical environment and its potential handling of Restricted clinical data. The Shadow IT assessment confirms that it is personally purchased and not covered by managed endpoint protection, backup, centralized logging, or MedDefense identity controls.

**Data at Risk:** Cardiology research information potentially containing clinical information or PHI — **potentially Restricted**. The evidence confirms research data but does not establish that PHI is actually present.

**Current Control Status:** C-001/C-004 perimeter controls provide only indirect protection. C-011 does not cover the NAS; C-012 does not back it up; C-018 cannot be assumed to provide logging; and C-009/C-010 cannot be assumed to govern its local credentials.

**What is Missing:**
Administrative — **Preventive:** approved ownership, lifecycle management, data-governance approval, and configuration standards.
Technical — **Preventive/Detective/Corrective:** managed authentication, patching, endpoint protection, centralized monitoring, segmentation, and backup.

**Risk Level:** **Critical**

**Risk Justification:** The asset may contain Restricted clinical information and has no evidenced dedicated detective or corrective controls. It is also connected to MedDefense's broadly reachable internal network, allowing compromise to become an enterprise issue rather than remaining limited to locally stored research. The Shadow IT assessment identifies the worst credible outcome as both PHI disclosure and lateral movement toward EHR, PACS, Active Directory, file services, or medical devices.

**Potential Impact:** An attacker could disclose or destroy cardiology research data and use the NAS as an unmanaged persistent foothold to enumerate and attack critical MedDefense systems. MedDefense could also be unable to establish who administered the system, what data was present, or whether the data could be reliably recovered.

---

## GAP-006 — EHR Database Is Reachable from More Systems Than Operationally Required

**Affected Asset(s):** AST-002 ehr-db-01, AST-001 ehr-srv-01, AST-016 EHR application, and AST-017 EHR clinical database — **Critical**. The registry explicitly identifies ehr-db-01 as reachable more broadly than required.

**Data at Risk:** Patient medical records/EHR PHI — **Restricted**.

**Current Control Status:** EHR protections include C-001, C-003, C-005, C-006, C-008, C-009, C-016, C-017, C-020, and C-027 as preventive controls; C-004, C-007, and C-018 provide detective evidence; C-012 provides backups; and C-010 provides a compensating account-lockout control. The EHR is therefore assessed as **Partially Protected**, not unprotected.

**What is Missing:**
Technical — **Preventive:** database-level network segmentation and an allow-list restricting PostgreSQL access to only systems that have a documented operational requirement, principally ehr-srv-01.

**Risk Level:** **High**

**Risk Justification:** The affected asset and data are Critical/Restricted, but the risk does not meet the same condition as the Critical gaps above because detective logging and corrective backup controls already exist. Nevertheless, those controls operate after unauthorized access or damage occurs. The Data Map identifies broad database reachability, lack of evidenced encryption at rest, and the flat internal architecture as direct weaknesses around Restricted EHR records.

**Potential Impact:** A compromised workstation, unmanaged endpoint, or other internal system could gain network access to the EHR database service that it does not operationally require. If database authentication is subsequently compromised, an attacker could extract PHI, alter clinical records, or damage data used by clinicians.

---

## GAP-007 — Active Directory Relies on Passwords Without Mandatory MFA or Centralized Alerting

**Affected Asset(s):** AST-005 ad-dc-01 and AST-006 ad-dc-02 — **Critical**, under Identity and Authentication Infrastructure. Both domain controllers provide enterprise authentication, and ad-dc-02 is excluded from Veeam backup.

**Data at Risk:** System credentials and authentication data — **Restricted**.

**Current Control Status:** C-009 password policy, C-010 account lockout, network/perimeter controls, Windows event logging, and C-012 backup of ad-dc-01 provide partial coverage. The matrix rates Active Directory **Partially Protected** because MFA is absent, AD events lack automated alerting, the environment remains broadly connected, and ad-dc-02 has no backup.

**What is Missing:**
Technical — **Preventive:** mandatory MFA, especially for privileged and remote-access accounts.
Technical — **Detective:** centralized AD security-event correlation and automated alerting.
Technical — **Corrective:** complete recovery protection for both domain controllers.

**Risk Level:** **High**

**Risk Justification:** Active Directory is Critical and credentials are Restricted, but password policies, account lockout, logging, and partial backup provide meaningful existing control coverage. The residual risk remains High because possession of valid stolen credentials may still be sufficient for access, while local event logging may not identify misuse promptly.

**Potential Impact:** Compromise of a privileged or sufficiently trusted account could allow an attacker to create accounts, change group memberships, modify policies, disable users, access other systems, or establish persistence. Because AD is an enterprise authentication dependency, the resulting compromise could propagate to EHR, administrative applications, file services, and infrastructure management.

---

## GAP-008 — Billing Server Lacks Server Malware Protection and Effective Egress Restriction

**Affected Asset(s):** AST-004 billing-srv-01, AST-019 billing application, and AST-020 billing database — **High**, under Billing and Revenue-Cycle Infrastructure. The asset registry records both the prior ransomware incident and subsequent cryptomining compromise.

**Data at Risk:** Billing, claims, and patient financial information — **Restricted**.

**Current Control Status:** C-012 provides nightly backup, C-001/C-004 provide perimeter filtering and logging, and C-011 protects managed Windows workstations used to access the service. However, C-011 explicitly excludes Windows/Linux servers. The Data Map further states that unrestricted outbound policy allowed malware on billing-srv-01 to communicate with mining infrastructure.

**What is Missing:**
Technical — **Detective/Corrective:** server-capable endpoint detection and response or equivalent malware monitoring.
Technical — **Preventive:** least-privilege outbound/egress firewall rules for critical servers.

**Risk Level:** **High**

**Risk Justification:** Billing infrastructure is High-rated and processes Restricted information. Existing backup and perimeter controls provide incomplete coverage but have demonstrably failed to prevent repeated server compromise. The absence of server malware detection is particularly material because unauthorized cryptomining software was able to execute under the web-service account without being recognized by an endpoint security control.

**Potential Impact:** A future compromise could expose patient-linked financial information, alter claims or account balances, encrypt the billing application, or interrupt revenue collection. MedDefense has already experienced a four-day billing outage, demonstrating that the operational impact is not theoretical. The repeated compromise pattern also indicates that simply restoring service without improving detection and egress control would leave the underlying exposure unresolved.

---

## GAP-009 — HR and Administrative Data Access Lacks Adequate Segmentation and Strong Authentication

**Affected Asset(s):** AST-007 file-srv-01 and the Administrative Endpoints and Corporate Applications category — **High**. The latter includes HQ workstations, remote-capable laptops, O365, Finance and HR access systems.

**Data at Risk:** Employee HR and payroll records — **Restricted**.

**Current Control Status:** file-srv-01 is included in C-012 nightly backups; managed Windows endpoints have C-011 antivirus; C-009 password requirements and C-010 account lockout apply. However, MFA is not mandatory and an unmanaged intern laptop previously had network access to the HR share. The Data Map specifically identifies that exposure as evidence of inadequate segmentation around employee records.

**What is Missing:**
Technical — **Preventive:** mandatory MFA for administrative users and access-path segmentation around HR/Finance repositories.
Administrative — **Preventive:** stronger access governance and confirmation of the authoritative HR/payroll data repository.

**Risk Level:** **High**

**Risk Justification:** Administrative endpoints are High-rated and HR/payroll records are Restricted. Existing antivirus, passwords, lockout, and backup reduce risk but do not prevent a compromised or unmanaged internal device from reaching sensitive storage, nor do they protect effectively against stolen valid credentials.

**Potential Impact:** Unauthorized access could expose employee identifiers, salary information, payroll data, or other personnel records. An attacker could also alter HR or payroll files, creating incorrect payments, fraudulent account changes, employment-record integrity issues, or identity-theft exposure for MedDefense personnel.

---

## GAP-010 — Marketing Data Is Controlled Through a Personal Google Account

**Affected Asset(s):** AST-058 Marketing Shared Google Drive — Personal Account — mapped to **High-rated Administrative Endpoints and Corporate Applications** because it is a Corporate HQ business application/data repository. The asset is explicitly classified as Shadow IT.

**Data at Risk:** Marketing and business communications — **Confidential**. Patient-related material may also exist, but the evidence does not establish PHI and it is therefore not treated as confirmed Restricted data.

**Current Control Status:** MedDefense's password policy, account lockout, endpoint antivirus, Veeam backup, local audit logging, and site VPN controls do not establish administrative control over the personal Google account. The Shadow IT assessment explicitly identifies these control boundaries.

**What is Missing:**
Administrative — **Preventive:** organization-controlled identity, approved SaaS governance, ownership, retention, legal hold, access review, and employee-separation procedures.
Technical — **Detective:** enterprise cloud audit visibility.
Technical — **Corrective:** enterprise backup/recovery capability for the repository.

**Risk Level:** **High**

**Risk Justification:** The repository contains Confidential MedDefense information and falls within a High-rated corporate application context, but current enterprise controls provide incomplete rather than zero protection because managed endpoints and workforce policies still reduce some peripheral risks. The central problem is that MedDefense does not control the account itself and therefore cannot guarantee authentication configuration, sharing permissions, lifecycle administration, audit records, or recovery.

**Potential Impact:** Account compromise or loss could expose unreleased communications, executive information, campaign materials, internal photographs, or contact information. An attacker or departed employee could change sharing permissions, delete records, modify official communications, or deny Marketing access during an organizational crisis. If subsequent content review identifies patient information, the same gap could also create a PHI disclosure.

---

# 3. Gap Distribution Summary

## 3.1 Distribution by Risk Level

| Risk Level   | Number of Gaps | Percentage |
| ------------ | -------------: | ---------: |
| **Critical** |          **5** |    **50%** |
| **High**     |          **5** |    **50%** |
| **Medium**   |          **0** |     **0%** |
| **Low**      |          **0** |     **0%** |
| **Total**    |         **10** |   **100%** |

The absence of Medium and Low findings in this prioritized list does not mean MedDefense has no lower-severity weaknesses. It reflects the purpose of this analysis: the ten selected gaps represent the areas where asset criticality, data sensitivity, and insufficient control coverage combine to create the strongest Board-level priorities.

## 3.2 Asset Categories with the Most Gaps

| Asset Category                              | Gap Count | Relevant Gaps    | Interpretation                                                                                                             |
| ------------------------------------------- | --------: | ---------------- | -------------------------------------------------------------------------------------------------------------------------- |
| **Administrative / Corporate Applications** |     **2** | GAP-009, GAP-010 | Sensitive HR and corporate information is exposed through incomplete identity, segmentation, and SaaS-governance controls. |
| **PACS / Diagnostic Imaging**               |     **1** | GAP-001          | Critical clinical imaging lacks an evidenced recovery mechanism.                                                           |
| **Medical IoT / Clinical Devices**          |     **1** | GAP-002          | Clinical devices lack dedicated segmentation, monitoring, and recovery.                                                    |
| **Network Core / Security Infrastructure**  |     **1** | GAP-003          | Core infrastructure is exposed through physical and administrative weaknesses.                                             |
| **Backup / Recovery Infrastructure**        |     **1** | GAP-004          | Recovery copies share the same failure domain as production.                                                               |
| **Shadow Clinical Storage**                 |     **1** | GAP-005          | An unmanaged NAS operates outside normal enterprise control coverage.                                                      |
| **EHR**                                     |     **1** | GAP-006          | Restricted EHR database access is broader than operationally required.                                                     |
| **Identity / Authentication**               |     **1** | GAP-007          | Enterprise identity lacks mandatory MFA and centralized alerting.                                                          |
| **Billing / Revenue Cycle**                 |     **1** | GAP-008          | Repeated compromise demonstrates insufficient server detection and egress control.                                         |

Administrative/corporate systems have the largest count as a single category, but the more important concentration is across **critical clinical and shared infrastructure**. Six of the ten gaps directly concern EHR, imaging, medical devices, identity, network, backup, or unmanaged clinical storage. This aligns with the Complete Control Matrix's conclusion that control quantity overstates actual protection and that major detective and recovery functions remain deficient.

## 3.3 Concentration by Control Category and Function

The gaps are concentrated primarily in the **Technical** control category. Existing controls are strongest at the perimeter and on selected managed endpoints, but equivalent controls are not consistently extended to databases, servers, medical devices, backup infrastructure, internal network paths, or shadow systems.

Across the ten gaps, the recurring missing functions are:

| Control Function              | Concentration | Examples                                                                                                                  |
| ----------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------- |
| **Preventive / Containment**  | **Highest**   | Internal segmentation, MFA, egress filtering, medical-device isolation, shadow-IT governance, physical network protection |
| **Detective**                 | **High**      | Centralized logging, AD alerting, server malware detection, medical-device monitoring, shadow-system audit visibility     |
| **Corrective / Recovery**     | **High**      | PACS backup, offsite/isolated backup, network-configuration recovery, shadow-system recovery, complete AD recovery        |
| **Administrative Governance** | **Material**  | Shadow IT approval, SaaS ownership, asset lifecycle management, access governance                                         |

This pattern is supported by the Data Map's description of decentralized security logs: MedDefense has firewall, SSH, Windows, Linux, Apache, and EHR audit records, but no centralized forwarding, SIEM correlation, or automated alerting, allowing malicious activity to remain undetected for longer.

### Board-Level Conclusion

MedDefense's primary security problem is **not the complete absence of controls; it is the failure to align controls with the assets and data that carry the greatest clinical and organizational consequence**. Perimeter filtering, passwords, workstation antivirus, backups, local logging, and physical measures all exist, but their coverage becomes materially weaker around PACS, medical IoT, the network core, Active Directory, backup infrastructure, Restricted databases, and shadow systems.

The prioritized remediation sequence should therefore begin with the five Critical gaps: **PACS recovery, medical-device isolation and monitoring, network-core protection, independent backup resilience, and removal or migration of unmanaged clinical storage**. These gaps combine Critical assets or potentially Restricted data with insufficient detective or corrective capability and therefore create the greatest distance between MedDefense's required protection level and its actual control environment.
