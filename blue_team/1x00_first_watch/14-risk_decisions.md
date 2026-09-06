# MedDefense Health Systems

## Risk Treatment Decisions

### Treatment Approach

The seven highest-priority gaps are treated primarily through **mitigation**. Acceptance is not appropriate because the selected gaps affect Critical clinical or infrastructure assets, Restricted data, or enterprise-wide recovery capability, and the available breach evidence demonstrates losses far exceeding the proposed control costs. Transfer through cyber insurance could reduce some financial consequences, but it would not prevent patient-care disruption, data exposure, credential compromise, or prolonged system outages. Avoidance is also generally infeasible because MedDefense cannot discontinue core capabilities such as networking, Active Directory, backups, or connected clinical devices.

The recommended program therefore concentrates the available **$120,000 fiscal-year budget** on controls that reduce several attack paths at once. It deliberately does **not** purchase an $80,000 enterprise SIEM. Instead, the recommendations use targeted monitoring, segmentation, recovery, MFA, vulnerability management, and governance measures that provide broader risk reduction within the available funding.

Cost figures below are rough planning estimates rather than vendor quotations.

---

# 1. GAP-011 — No Evidenced Enterprise Vulnerability and Patch Management Program

**Gap ID:** GAP-011

**Gap Title:** No Evidenced Enterprise Vulnerability and Patch Management Program

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:**
This gap should be mitigated because it creates an initial-access path into several Critical and High-rated systems, including the FortiGate, patient portal, billing server, and other infrastructure requiring security updates. MedDefense currently lacks an evidenced process that identifies security advisories, assigns remediation deadlines, verifies patch deployment, and escalates overdue vulnerabilities.

External evidence makes the economics of mitigation particularly strong. Regional Hospital Alpha was compromised through a VPN vulnerability for which a patch had been available for four months; the resulting attack encrypted 23 servers and approximately 400 workstations and caused 11 days of EHR downtime. The reported recovery cost alone was $3.2 million, substantially exceeding the proposed annual investment in vulnerability management.

**Proposed Control(s):**

* **Administrative — Preventive:** Establish a formal vulnerability and patch-management policy covering servers, operating systems, applications, firewalls, VPN systems, web applications, and supported medical technologies.
* **Technical — Preventive:** Deploy vulnerability-scanning capability and maintain an authoritative inventory of systems requiring updates.
* **Administrative — Preventive:** Establish severity-based remediation targets, such as accelerated deadlines for Critical internet-facing vulnerabilities.
* **Technical — Detective:** Verify patch deployment through recurring scans rather than relying only on installation records.
* **Administrative — Preventive:** Require documented risk exceptions and management approval for patches that cannot be applied on schedule.

**Estimated Cost:** **$10–50K**
**FY Budget Allowance:** **$18,000**

**Implementation Effort:** **Long-term > 1 month**

**Expected Risk Reduction:**
**Substantial; expected residual risk: High.** The program reduces the probability that attackers can use already-known vulnerabilities as an initial entry point. It cannot eliminate zero-day vulnerabilities or systems that cannot be patched immediately, so residual risk remains. However, it removes a preventable failure mode that initiated two of the three healthcare breach scenarios assessed in Task 13.

**Trade-offs:**
Patching may require scheduled downtime for clinical and administrative systems, and some medical technologies may require vendor validation before updates can be applied. MedDefense will therefore need formal exception processes and compensating controls for systems that cannot be patched immediately. The program also creates ongoing operational workload for IT rather than being a one-time purchase.

---

# 2. GAP-002 — Medical IoT Is Not Segmented, Monitored, or Recoverable

**Gap ID:** GAP-002

**Gap Title:** Medical IoT Is Not Segmented, Monitored, or Recoverable

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:**
Medical IoT includes Critical patient monitors, infusion pumps, vital-sign monitors, and nurse-call infrastructure that process Restricted patient-associated data. Current controls provide only indirect perimeter protection, while MedDefense lacks dedicated device segmentation, fleet-wide monitoring, and corrective recovery procedures.

The Community Hospital Gamma breach demonstrates why acceptance would be inappropriate. Attackers moved from a compromised patient portal into the internal network, discovered directly reachable medical devices, accessed an infusion-pump management console, and remained active for 23 days because effective network monitoring was absent. Network isolation was also specifically identified as the principal mitigation for medical-device vulnerabilities that could not be patched.

**Proposed Control(s):**

* **Technical — Preventive:** Place medical-device classes on dedicated VLANs with default-deny access-control rules.
* **Technical — Preventive:** Permit only explicitly required communications between clinical devices, management systems, and approved clinical applications.
* **Technical — Detective:** Enable targeted network telemetry and alerting for unusual medical-device communication, management connections, and internet-bound traffic.
* **Technical — Corrective:** Establish documented restoration procedures and secure copies of recoverable device-management configurations.
* **Administrative — Preventive:** Require joint IT, Security, and Biomedical Engineering approval for device-network exceptions.

**Estimated Cost:** **$10–50K**
**FY Budget Allowance:** **$30,000**

**Implementation Effort:** **Long-term > 1 month**

**Expected Risk Reduction:**
**Substantial; expected residual risk: High.** Segmentation materially reduces the ability of a compromised workstation, server, or remote-access path to reach bedside devices. Targeted monitoring also reduces attacker dwell time. Risk remains because some legacy devices may contain unpatchable vulnerabilities and because operational requirements may require controlled communications across network segments.

**Trade-offs:**
Incorrect access-control rules could interrupt monitoring, medication-management, or nurse-call workflows. Implementation must therefore include traffic discovery, Biomedical Engineering validation, staged deployment, and rollback procedures. The proposed budget also funds targeted medical-device visibility rather than a full enterprise network-detection platform, leaving some monitoring limitations.

---

# 3. GAP-004 — Production and Backup Copies Share the Same Failure Domain

**Gap ID:** GAP-004

**Gap Title:** Production and Backup Copies Share the Same Failure Domain

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:**
MedDefense's primary backup NAS resides in the same network and server-room/rack environment as production systems. There is no offsite or cloud replication, and only a partial file-server restoration has been tested. A ransomware event, fire, flood, or unauthorized physical-access event could therefore affect both production systems and the mechanism intended to restore them.

This weakness directly matches Regional Hospital Alpha, where ransomware encrypted the network-accessible backup NAS together with production systems, leaving the hospital dependent on a five-week-old offsite copy. Because backups determine whether MedDefense can recover EHR, billing, authentication, and other critical services after destructive events, accepting this correlated failure risk would be inconsistent with the potential operational loss.

**Proposed Control(s):**

* **Technical — Corrective:** Create an isolated secondary backup copy using immutable/object-locked cloud storage, physically disconnected media, or another architecture that production credentials cannot modify.
* **Technical — Preventive:** Use separate privileged credentials and access controls for backup administration.
* **Technical — Corrective:** Establish scheduled restoration testing for critical systems rather than relying solely on successful backup-job status.
* **Administrative — Corrective:** Define backup retention, recovery priorities, recovery-point objectives, and test evidence requirements.

**Estimated Cost:** **$10–50K**
**FY Budget Allowance:** **$25,000**

**Implementation Effort:** **Short-term < 1 month**

**Expected Risk Reduction:**
**Substantial; expected residual risk: High.** An immutable or otherwise isolated secondary copy breaks the common ransomware failure domain between production and recovery data. Regular restoration testing also establishes whether the backup can actually support recovery. Residual risk remains because recovery can still require substantial time and because backup availability does not itself guarantee uninterrupted clinical operations.

**Trade-offs:**
Offsite or immutable storage creates recurring storage and retention costs. Additional backup copies may also increase recovery complexity and require bandwidth for replication. Restoration testing consumes infrastructure and staff time and must be scheduled to avoid production impact.

---

# 4. GAP-003 — Network Core Is Exposed to Unauthorized Administrative Control

**Gap ID:** GAP-003

**Gap Title:** Network Core Is Exposed to Unauthorized Administrative Control

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:**
The FortiGate, Cisco core infrastructure, access switches, and network closets support connectivity for EHR, PACS, Active Directory, medical devices, Westside, and HQ. Inadequate physical protection and exposed privileged credentials therefore create a route through which one compromise could alter routing, switching, VPN configuration, or segmentation across multiple Critical environments. No evidenced corrective capability currently exists for destructive network-configuration changes.

Mitigation has high leverage because stronger network-core protection also supports other recommended treatments, particularly medical-device isolation. The healthcare breach evidence shows that flat or permissive network architecture allowed attackers to move from initial footholds into Active Directory, servers, and medical-device environments.

**Proposed Control(s):**

* **Physical — Preventive:** Restrict and lock network closets and maintain authorized-access lists.
* **Physical — Detective:** Maintain access records for sensitive network locations where technically feasible.
* **Technical — Preventive:** Remove exposed or shared administrative credentials and implement named privileged accounts.
* **Technical — Preventive:** Restrict network-device management interfaces to approved administrative systems or management networks.
* **Technical — Corrective:** Automatically back up firewall and switch configurations to protected storage and periodically test restoration.
* **Technical — Preventive:** Implement priority internal ACLs and management-plane segmentation using existing network capability.

**Estimated Cost:** **$10–50K**
**FY Budget Allowance:** **$12,000**

**Implementation Effort:** **Short-term < 1 month**

**Expected Risk Reduction:**
**Substantial; expected residual risk: High.** Restricting administrative access and protecting configuration backups substantially lowers the probability that stolen credentials or physical access can produce an enterprise-wide network outage. Residual risk remains because network infrastructure is inherently a high-value dependency and because complete internal segmentation requires continued architecture work beyond this fiscal-year allocation.

**Trade-offs:**
More restrictive network administration can slow emergency troubleshooting. ACL and management-network changes can also cause service disruption if dependencies are not identified beforehand. Change management and documented emergency-access procedures are therefore required.

---

# 5. GAP-007 — Active Directory Relies on Passwords Without Mandatory MFA or Centralized Alerting

**Gap ID:** GAP-007

**Gap Title:** Active Directory Relies on Passwords Without Mandatory MFA or Centralized Alerting

**Risk Level:** High

**Treatment Strategy:** Mitigate

**Justification:**
Active Directory is a Critical enterprise dependency containing Restricted authentication information. Password policy, lockout, local logging, and partial backup provide meaningful existing controls, which is why the formal rating remains High rather than Critical. However, stolen valid credentials may still provide access, AD security events are not centrally alerted, and one domain controller lacks complete recovery coverage.

Health Network Beta demonstrates the limitation of password-only controls: a former employee retained valid VPN and EHR credentials for 47 days, successfully accessed the EHR 14 times, and downloaded 3,211 patient records because MFA and effective access monitoring were absent. Task 13 therefore retained the High rating but moved this gap toward the top of the High-priority remediation queue.

**Proposed Control(s):**

* **Technical — Preventive:** Require MFA for privileged accounts, remote access, VPN use, and supported high-risk administrative or clinical applications.
* **Technical — Preventive:** Separate privileged administrative accounts from ordinary user accounts.
* **Technical — Detective:** Forward high-value AD security events to centralized alerting or a lower-cost managed monitoring service rather than implementing a full enterprise SIEM.
* **Technical — Detective:** Alert on privileged-group changes, abnormal administrative logins, repeated lockouts, account creation, and other high-value identity events.
* **Technical — Corrective:** Ensure both domain controllers are incorporated into tested recovery procedures.

**Estimated Cost:** **$10–50K**
**FY Budget Allowance:** **$22,000**

**Implementation Effort:** **Long-term > 1 month**

**Expected Risk Reduction:**
**High; expected residual risk: Medium.** MFA directly reduces the usefulness of stolen passwords, while targeted AD alerting increases the probability that privilege abuse is identified before it propagates across the environment. Complete domain-controller recovery also improves resilience. Risk remains because MFA does not prevent every form of session theft, social engineering, privilege escalation, or insider misuse.

**Trade-offs:**
MFA introduces additional authentication steps and may encounter compatibility problems with legacy applications or medical workflows. MedDefense will need controlled exceptions and alternative strong-authentication methods where standard MFA cannot be deployed. Targeted AD monitoring is also narrower than a full SIEM, so broader cross-platform correlation remains a future improvement.

---

# 6. GAP-012 — No Formal Enterprise Incident Response and Recovery Coordination Process

**Gap ID:** GAP-012

**Gap Title:** No Formal Enterprise Incident Response and Recovery Coordination Process

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:**
MedDefense has technical recovery mechanisms but no evidenced enterprise corrective process establishing incident roles, containment authority, escalation, communications, evidence preservation, recovery sequencing, or return-to-service criteria. The weakness therefore affects multiple Critical systems simultaneously rather than one isolated technology.

The Regional Hospital Alpha breach demonstrates the financial and operational consequences of this gap. Its incident response was improvised, external consultants were not engaged until day three, and the hospital experienced an 11-day disruption. An incident response plan is comparatively inexpensive relative to the cost of an extended clinical outage, making acceptance economically unjustifiable.

**Proposed Control(s):**

* **Administrative — Corrective:** Develop a formal incident response plan with defined incident severity levels, decision authority, containment procedures, and escalation paths.
* **Administrative — Corrective:** Define clinical and business recovery priorities, including EHR, imaging, identity, network, billing, and medical-device dependencies.
* **Administrative — Corrective:** Establish internal and external communications procedures, including legal, regulatory, cyber-insurance, forensic, and law-enforcement contacts where appropriate.
* **Administrative — Corrective:** Conduct at least one ransomware/credential-compromise tabletop exercise and document corrective actions.
* **Administrative — Corrective:** Establish an external incident-response contact or retainer framework so procurement does not begin after a major incident has already occurred.

**Estimated Cost:** **$1–10K**
**FY Budget Allowance:** **$8,000**

**Implementation Effort:** **Short-term < 1 month**

**Expected Risk Reduction:**
**Substantial consequence reduction; expected residual risk: High.** Incident response planning does not reduce the probability of initial compromise as directly as MFA or patching. It reduces the duration and severity of successful incidents by defining containment, decision-making, recovery sequencing, and communications before a crisis occurs. Because the underlying cyberattack can still happen, residual risk remains High.

**Trade-offs:**
The plan requires participation from clinical leadership, IT, Security, Biomedical Engineering, Legal, HR, Communications, and executive management. Exercises temporarily consume staff time, and the plan will lose value if it is not updated after technology, staffing, or business-process changes.

---

# 7. GAP-015 — Medical-Device Administrative Credentials Are Not Evidenced as Centrally Governed

**Gap ID:** GAP-015

**Gap Title:** Medical-Device Administrative Credentials Are Not Evidenced as Centrally Governed

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:**
MedDefense has no evidenced fleet-wide baseline requiring vendor-default credentials to be disabled or changed, unique privileged credentials to be used where supported, or device administrative accounts to be inventoried and periodically reviewed. Because the same medical-device environment is also insufficiently segmented, default or uncontrolled credentials could provide immediate administrative access once an attacker reaches a device-management interface.

Community Hospital Gamma demonstrates the exact attack path: infusion-pump management interfaces were reachable from the compromised internal environment and still used vendor-default `admin/admin` credentials. This control gap can be materially reduced at comparatively low cost through governance and credential changes, making acceptance or transfer inappropriate.

**Proposed Control(s):**

* **Administrative — Preventive:** Establish a medical-device privileged-account and credential standard jointly owned by IT Security and Biomedical Engineering.
* **Technical — Preventive:** Change or disable vendor-default administrative credentials wherever supported.
* **Technical — Preventive:** Use unique privileged credentials rather than common passwords across device fleets where the technology permits.
* **Administrative — Preventive:** Maintain an inventory of medical-device administrative accounts and responsible owners.
* **Technical/Administrative — Preventive:** Store necessary privileged credentials in a controlled password vault or equivalent escrow mechanism.
* **Administrative — Detective:** Conduct recurring reviews for default, shared, stale, or undocumented device credentials.

**Estimated Cost:** **$1–10K**
**FY Budget Allowance:** **$3,000**

**Implementation Effort:** **Short-term < 1 month**

**Expected Risk Reduction:**
**Substantial; standalone residual risk: High.** Eliminating known default and unmanaged privileged credentials removes a direct route to device administration. When combined with the GAP-002 segmentation controls, the reduction is greater because an attacker must both reach the management interface and obtain an authorized credential. Residual risk remains because some legacy medical devices may not support modern credential controls.

**Trade-offs:**
Some clinical devices may use vendor-maintained accounts or fixed credentials that cannot be modified without affecting support agreements. Credential changes also create the possibility of clinical support personnel being unable to access equipment during emergencies unless credential escrow and emergency-access procedures are carefully designed.

---

# Budget Summary

| Priority | Gap                                               | Treatment | ROM Cost Category | FY Planning Allocation |
| -------: | ------------------------------------------------- | --------- | ----------------: | ---------------------: |
|        1 | GAP-011 — Vulnerability and Patch Management      | Mitigate  |           $10–50K |            **$18,000** |
|        2 | GAP-002 — Medical IoT Segmentation and Monitoring | Mitigate  |           $10–50K |            **$30,000** |
|        3 | GAP-004 — Independent Backup Resilience           | Mitigate  |           $10–50K |            **$25,000** |
|        4 | GAP-003 — Network-Core Protection                 | Mitigate  |           $10–50K |            **$12,000** |
|        5 | GAP-007 — MFA and Identity Monitoring             | Mitigate  |           $10–50K |            **$22,000** |
|        6 | GAP-012 — Incident Response Capability            | Mitigate  |            $1–10K |             **$8,000** |
|        7 | GAP-015 — Medical-Device Credential Governance    | Mitigate  |            $1–10K |             **$3,000** |
|          | **Total Recommended Investment**                  |           |                   |           **$118,000** |
|          | **Annual Security Budget**                        |           |                   |           **$120,000** |
|          | **Remaining Contingency**                         |           |                   |             **$2,000** |

## Budget Decision

The recommended treatments total **$118,000**, leaving **$2,000 of the $120,000 annual budget uncommitted**. No treatment within the selected top seven therefore needs to be deferred solely because of budget limitations.

The allocation intentionally distributes funding across prevention, detection, and recovery rather than spending approximately two-thirds of the annual budget on one enterprise SIEM license. This is consistent with the Reality Check, which found that the principal healthcare breaches resulted from failures across multiple stages of the attack chain: unpatched vulnerabilities, flat networks, inadequate monitoring, reachable backups, password-only authentication, missing response coordination, and poorly governed medical-device credentials.

The **$2,000 contingency should remain reserved** for unplanned implementation costs, such as additional MFA tokens, network hardware, backup-storage consumption, consulting hours, or medical-device vendor support. Committing the full $120,000 before implementation would create a risk that an otherwise viable control project must stop because of a relatively small unplanned expense.

## Items Deferred Beyond the Top-Seven Program

Although the selected treatments fit within the current budget, MedDefense still has material untreated gaps. Under Task 13's revised priority sequence, **GAP-001 — PACS recovery capability**, **GAP-013 — automated identity lifecycle/offboarding**, and **GAP-014 — DLP and abnormal data-export monitoring** follow the seven selected items.

These should be candidates for the next fiscal year rather than diverting funds from the current seven. PACS recovery should be the first additional project because the existing Gap Analysis identifies PACS as a Critical clinical asset with Restricted imaging data and no evidenced corrective recovery mechanism.

A full enterprise SIEM should also be deferred unless MedDefense receives additional funding. Targeted AD and medical-device alerting provides immediate coverage of the highest-risk use cases at substantially lower cost. A broader SIEM becomes more valuable after MedDefense has established the underlying processes—asset inventory, vulnerability management, segmentation, identity governance, incident response, and defined alert requirements—that determine what information the SIEM should collect and how alerts should be handled.

## Overall Risk Decision

The recommended $118,000 program prioritizes **attack-chain leverage** rather than equal spending across every identified weakness. Vulnerability management reduces the probability of initial compromise; medical-device and network segmentation constrain lateral movement; MFA and credential governance reduce unauthorized privilege use; targeted monitoring improves detection; isolated backups preserve recovery capability; and formal incident response reduces the duration and operational impact of incidents that still occur.

This approach provides materially greater risk reduction than concentrating most of the annual budget in one security product because the healthcare breach evidence shows that severe incidents occur when several basic controls fail in sequence rather than when one advanced product is absent.
