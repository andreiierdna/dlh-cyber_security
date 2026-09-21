# MedDefense Health Systems
# Security Strategy Document

**Prepared for:** Executive Leadership and Board of Directors  
**Strategy Horizon:** Six months  
**Annual Security Budget:** **$120,000**  
**Primary Frameworks:** NIST Cybersecurity Framework 2.0 and CIS Controls v8.1  
**Companion Deliverables:** Security Posture Assessment (1x00), Threat Landscape Report (1x01), Vulnerability Assessment Summary (1x02)

---

# 1. Executive Summary

MedDefense Health Systems remains in a **high-risk security posture** because Critical clinical and enterprise systems are connected through insufficient internal segmentation, identity controls remain too dependent on reusable passwords, recovery systems share trust with production, and security monitoring is not yet mature enough to reliably detect attacker progression. The vulnerability assessment reinforces that conclusion: the issue is not simply the number of scanner findings, but the way exploitable weaknesses, flat reachability, weak identity boundaries, and limited containment combine into realistic ransomware, EHR, Active Directory, medical-device, and recovery attack paths.  

The strategy adopts **NIST CSF 2.0 as the governance and risk-management framework** and **CIS Controls v8.1 as the implementation control set**. NIST provides the six-function structure—Govern, Identify, Protect, Detect, Respond, and Recover—while CIS provides specific operational safeguards for access control, logging, malware defense, recovery, network architecture, and monitoring. 

The **total Year-1 investment requested is $120,000**. The funded portfolio is network segmentation **$35,000**, MFA **$10,000**, Wazuh SIEM **$21,000**, EDR **$26,000**, Westside firewall replacement **$20,000**, and offsite immutable backup **$8,000**:

**$35,000 + $10,000 + $21,000 + $26,000 + $20,000 + $8,000 = $120,000**

**Budget remaining = $120,000 − $120,000 = $0**

Using the overlap-adjusted ransomware model developed in Task 8, the funded preventive/detective portfolio reduces modeled enterprise ransomware ALE from **$2,864,400** to **$247,627.38**:

**Risk reduction = $2,864,400 − $247,627.38 = $2,616,772.62/year**

This is an estimated modeled reduction, not a guarantee. The separate **$74,600/year** recovery-proxy benefit from immutable backup is not added to that ransomware reduction because doing so could double-count overlapping loss avoidance.

## Top Three Priority Actions

1. **Implement enforceable network segmentation.** Convert MedDefense's current flat internal architecture into default-deny zones for clinical workstations, servers, medical devices/imaging, management, guest/IoT, backups, and public services.
2. **Enforce MFA for VPN and administrative access.** Make stolen passwords insufficient for high-value access and reduce the credential-conversion stages in the ransomware and Active Directory kill chains.
3. **Build centralized detection with Wazuh SIEM and EDR.** Centralize logs, endpoint telemetry, and alerting so that movement toward EHR, Active Directory, backup infrastructure, and clinical systems is detected before business impact.

---

# 2. Governance Framework

## 2.1 Framework Selection Rationale

MedDefense should use **NIST CSF 2.0 as the strategic governance framework** because the current problem is broader than technical remediation. Governance, asset identification, safeguards, detection, incident response, and recovery all have material deficiencies. NIST CSF 2.0 provides the six functions needed to govern those capabilities as one program rather than as unrelated projects.

CIS Controls v8.1 should serve as the implementation layer. The selected controls already map directly to concrete MedDefense needs:

- CIS Control 6 — Access Control Management: MFA and privileged access.
- CIS Control 7 — Continuous Vulnerability Management: recurring vulnerability identification and remediation.
- CIS Control 8 — Audit Log Management: centralized logs and alerting.
- CIS Control 10 — Malware Defenses: EDR and behavior-based protection.
- CIS Control 11 — Data Recovery: isolated recovery and restore testing.
- CIS Control 12 — Network Infrastructure Management: segmentation and enterprise firewall policy.
- CIS Control 13 — Network Monitoring and Defense: inter-zone monitoring and security analytics.
- CIS Control 3 — Data Protection: future DLP and bulk-export controls.

This combination preserves a clear chain from **risk → framework function → CIS safeguard → funded control → measurable outcome**.

## 2.2 NIST CSF Current vs. Target Profile

| NIST CSF Function | Current Level | Six-Month Target | Strategic Meaning |
|---|---|---|---|
| **Govern (GV)** | Partial | Managed | Formalize risk ownership, policy authority, risk acceptance, review cadence, and executive oversight. |
| **Identify (ID)** | Partial | Managed | Turn project asset/risk data into a continuously maintained inventory, vulnerability process, and Risk Register. |
| **Protect (PR)** | Partial | Managed | Implement segmentation, MFA, EDR, hardened access, and repeatable platform/network safeguards. |
| **Detect (DE)** | Not Implemented | Managed | Move from local logs to centralized collection, correlation, alert ownership, and tested detection rules. |
| **Respond (RS)** | Partial | Managed | Establish repeatable incident declaration, containment, communications, evidence handling, and exercises. |
| **Recover (RC)** | Partial | Managed | Establish isolated recovery, restore testing, protected backup administration, and documented recovery priorities. |

The six-month objective is **Managed**, not Optimized. MedDefense can establish repeatable and owned processes within six months, but sustained measurement and continuous optimization require a longer operating history.

## 2.3 CIS Controls Maturity Scorecard

The uploaded strategy package does not contain a standalone prior CIS-maturity deliverable. This is therefore a **strategy-level maturity scorecard derived from documented controls and gaps**, using the project's maturity terminology rather than claiming an official CIS maturity-scoring methodology.

| CIS Control | Current State | Six-Month Target | Evidence / Strategy |
|---|---|---|---|
| **1 — Inventory and Control of Enterprise Assets** | Partial | Managed | Asset registry exists, but ownership and discovery remain incomplete; institutionalize recurring reconciliation. |
| **3 — Data Protection** | Partial | Partial | Restricted data is identified, but preventive DLP/USB controls are not funded in the primary Year-1 portfolio. |
| **5 — Account Management** | Partial | Managed | Strengthen account lifecycle, privileged identity separation, and stale-account review. |
| **6 — Access Control Management** | Partial | Managed | Deploy MFA to VPN and administrative access; restrict privileged paths. |
| **7 — Continuous Vulnerability Management** | Partial | Managed | Convert assessment activity into recurring scanning, remediation SLAs, exceptions, and verification. |
| **8 — Audit Log Management** | Partial | Managed | Deploy Wazuh; centralize high-value logs and recurring review. |
| **10 — Malware Defenses** | Partial | Managed | Upgrade endpoint/server detection to EDR. |
| **11 — Data Recovery** | Partial | Managed | Add immutable/offsite recovery and recurring restore validation. |
| **12 — Network Infrastructure Management** | Partial | Managed | Enforce routed VLANs, ACLs, default-deny policy, and enterprise Westside perimeter controls. |
| **13 — Network Monitoring and Defense** | Not Implemented | Managed | Combine SIEM, EDR, firewall telemetry, and monitored segmentation boundaries. |
| **15 — Service Provider Management** | Partial | Partial | Vendor paths are recognized, but mature third-party governance remains a later priority. |
| **17 — Incident Response Management** | Partial | Managed | Formalize roles, escalation, evidence preservation, communications, and exercises. |

## 2.4 Governance Structure and Roles

MedDefense's governance model separates **risk accountability**, **technical execution**, and **business/data ownership**. The CEO is accountable for budget, policy approval, and material risk acceptance. James Chen, Deputy CISO, is accountable for the security program, vulnerability prioritization, incident coordination, vendor-risk oversight, audit coordination, and maintenance of the risk-management process. Sarah Park, IT Director, is responsible for implementing controls across networks, endpoints, identity, servers, and backups. Department Heads own legitimate business or clinical use of departmental information, while the Security Analyst performs assessment, validation, monitoring, evidence collection, and Risk Register maintenance. Biomedical Engineering and Clinical Operations participate whenever controls affect clinical devices or workflows.

The current CISO vacancy remains a governance weakness. The strategy retains James as the internal operational leader and supports the Task 4 recommendation to use a **vCISO as an interim executive-security model only if separately funded**, because the binding control portfolio consumes the full $120,000 Year-1 security budget.

---

# 3. Quantitative Risk Analysis

## 3.1 Top Five Risks by ALE

| Rank | Risk | ALE Calculation | Current ALE |
|---:|---|---:|---:|
| **1** | EHR PHI breach | **$9,075,000 × (1 ÷ 3)** | **$3,025,000/year** |
| **2** | Enterprise ransomware / VPN-to-network compromise | **$9,548,000 × 0.30** | **$2,864,400/year** |
| **3** | Insider PHI exfiltration | **$120,000 × 2.5** | **$300,000/year** |
| **4** | Billing-server ransomware | **$473,000 × (1 ÷ 3.5)** | **≈ $135,143/year** |
| **5** | Medical-device compromise | **($250,000 × 0.10) + ($3,000,000 × 0.02)** | **$85,000/year** |

These figures must not be summed into an enterprise total because multiple scenarios contain overlapping EHR, ransomware, billing, and recovery consequences.

## 3.2 Risk Register Summary

| Risk ID | Risk | Inherent Score | ALE | Treatment | Residual Score |
|---|---|---:|---|---|---:|
| RISK-001 | Enterprise ransomware | **3 × 5 = 15** | **$2,864,400/year** | Mitigate | **2 × 4 = 8** |
| RISK-002 | EHR PHI breach | **3 × 5 = 15** | **$3,025,000/year** | Mitigate | **2 × 5 = 10** |
| RISK-003 | Active Directory compromise | **4 × 5 = 20** | Included in RISK-001 | Mitigate | **2 × 5 = 10** |
| RISK-004 | Undetected intrusion | **4 × 4 = 16** | Included in RISK-001 | Mitigate | **2 × 4 = 8** |
| RISK-005 | Known vulnerability exploitation | **4 × 5 = 20** | Billing subset **≈ $135,143/year** | Mitigate | **2 × 5 = 10** |
| RISK-006 | Insider PHI exfiltration | **5 × 3 = 15** | **$300,000/year** | Mitigate | **4 × 3 = 12** |
| RISK-007 | Backup destruction | **3 × 5 = 15** | Recovery proxy **$135,143 → $60,543/year** | Mitigate | **2 × 4 = 8** |
| RISK-008 | Medical-device compromise | **2 × 5 = 10** | **$85,000/year** | Mitigate | **1 × 5 = 5** |
| RISK-009 | PACS/MRI compromise | **3 × 5 = 15** | Not yet quantified | Mitigate | **2 × 5 = 10** |
| RISK-010 | Westside trusted-path compromise | **3 × 4 = 12** | Embedded in RISK-001 | Mitigate | **2 × 4 = 8** |

The Security Analyst maintains the register, James is accountable for governance and escalation, and each named Risk Owner is responsible for treatment status.

## 3.3 Proposed Risk Appetite Statement

The NIST profile confirms that a formal organizational risk appetite is not yet established. The following is therefore proposed for Board adoption:

> MedDefense has **very low risk appetite** for risks that could cause patient harm, widespread loss of clinical availability, unauthorized disclosure or alteration of Restricted PHI, compromise of enterprise identity, or destruction of recovery capability. MedDefense may temporarily tolerate **moderate residual risk** where the service is clinically necessary, immediate elimination is technically or financially infeasible, compensating controls are operating, a named owner and review date exist, and the CEO explicitly accepts the residual risk. No department or technical owner may independently accept enterprise-level cybersecurity risk.

---

# 4. Control Strategy

## 4.1 Cost-Benefit Analysis

| Control | Annual Cost | ALE Reduction | Net Value | Decision |
|---|---:|---:|---:|---|
| Network segmentation | **$35,000** | **$1,718,640** | **$1,683,640** | Fund |
| MFA | **$10,000** | **$1,432,200** | **$1,422,200** | Fund |
| Wazuh SIEM | **$21,000** | **$1,002,540** | **$981,540** | Fund |
| EDR | **$26,000** | **$859,320** | **$833,320** | Fund |
| Westside firewall | **$20,000** | **$143,220** | **$123,220** | Fund |
| Immutable backup | **$8,000** | **$74,600** | **$66,600** | Fund |
| 24/7 SOC | **$136,960** | **$195,495 incremental** | **$58,535** | Defer |
| Full dedicated medical-device architecture | **$95,000** | **$59,500** | **−$35,500** | Reject as proposed |

The individual ALE reductions are useful for comparing controls but cannot be added as if each avoided loss were independent.

## 4.2 Budget Allocation

The funded portfolio is:

**$35,000 + $10,000 + $21,000 + $26,000 + $20,000 + $8,000 = $120,000**

**Budget = 120000**  
**Funded spend = 120000**  
**Budget remaining = 0**

The outsourced SOC is deferred because **$136,960 − $120,000 = $16,960** over the entire annual budget. By deferring it, MedDefense accepts an estimated **$195,495/year** in modeled additional risk exposure.

The full dedicated medical-device architecture is rejected in its proposed form because:

**$59,500 − $95,000 = −$35,500**

MedDefense should instead use targeted segmentation, credential remediation, and monitoring.

## 4.3 Control Selection with Framework Mapping

| Control | CIS Mapping | NIST CSF | Principal Risks |
|---|---|---|---|
| Segmentation/default-deny zones | 12.2; 13.4 | PR.IR | RISK-001, 002, 005, 007, 008, 009, 010 |
| MFA | 6.4; 6.5 | PR.AA | RISK-001, 002, 003 |
| Wazuh SIEM | 8.9; 8.11; 13.1 | DE.CM, DE.AE | RISK-001, 002, 003, 004, 006, 007, 008, 009, 010 |
| EDR | 10.7; 13.7 | PR.PS, DE.CM | RISK-001, 004, 005, 006 |
| Immutable backup | 11.4; 11.5 | RC.RP | RISK-001, 007 |
| Westside firewall | 12.2; 13.4 | PR.IR | RISK-010 |

Segmentation architecture must precede specialized PACS/medical-device isolation. SIEM does not technically require EDR, but EDR materially improves SIEM telemetry. A 24/7 SOC should follow SIEM and EDR. Immutable recovery can proceed in parallel once the existing backup process and recovery credentials are validated.

## 4.4 Quick Wins

Immediate actions are:

- Remove exposed/shared network-device credentials and secure network closets.
- Restrict `ehr-db-01:5432` to documented sources.
- Begin MFA enforcement for VPN and privileged accounts.
- Inventory and replace supported medical-device default/shared credentials.
- Establish a Critical-vulnerability remediation standard and scan cadence.
- Define incident severity, escalation, and response authority.
- Isolate or remove unmanaged systems lacking approved business purpose.
- Restrict backup-management interfaces to controlled administrative sources.

---

# 5. Architecture Recommendations

## 5.1 Network Segmentation Design

The target architecture contains:

**5 required zones + 2 additional zones = 7 zones**

| Zone | Address Range | Purpose |
|---|---|---|
| Clinical Workstations | `10.10.1.0/24` | Nurse, physician, reception, clinical endpoints |
| Server | `10.10.2.0/24` | EHR, billing, AD, file/print, internal services |
| Medical Device / Imaging | `10.10.3.0/24` | PACS/MRI, monitors, pumps, clinical IoT |
| Management | `10.10.4.0/24` | Admin workstations, jump host, security tooling |
| Guest / Non-Clinical IoT | `10.10.5.0/24` | Visitor Wi-Fi and non-clinical IoT |
| Backup / Recovery | `10.10.6.0/24` | Backup server, NAS, immutable recovery systems |
| DMZ / Public Services | `10.10.7.0/24` | Patient portal and Internet-facing services |

The architectural rule is:

**Default deny between zones; explicitly allow only documented clinical and business flows.**

For EHR:

`EHR_App_Server -> EHR_DB : TCP/5432 : ALLOW`

but:

`ANY_OTHER_SOURCE -> EHR_DB : TCP/5432 : DENY`

Management and backup administration are similarly inaccessible from ordinary user and server zones.

## 5.2 Kill Chain Disruption

Segmentation disrupts the documented direct route in four of five kill chains:

- KC-1 VPN → EHR: direct PostgreSQL access is broken.
- KC-2 Phishing → AD: privileged management paths are restricted.
- KC-3 Supply Chain → PACS/MRI: imaging assets are confined to approved flows.
- KC-4 Phishing → Backup Destruction: backup administration is isolated.
- KC-5 Malicious Insider → Network Core: segmentation alone is insufficient because the actor may legitimately administer the network.

Therefore:

**4 disrupted chains ÷ 5 modeled chains × 100 = 80%**

The fifth chain requires PAM, MFA, separation of duties, configuration monitoring, and independent approval for high-impact network changes. 

---

# 6. Policy Foundation

## 6.1 AUP Summary

No standalone AUP artifact is included in the supplied capstone files, so this is the **required policy foundation derived from documented MedDefense behaviors**, rather than a claim that the exact language is already approved.

The Acceptable Use Policy should require organizational technology and data to be used only for authorized clinical and business purposes. Users must use individual accounts, protect credentials, comply with MFA, lock unattended sessions, and never share privileged or clinical credentials. Restricted MedDefense information may be stored only on approved enterprise systems; personal NAS devices, personal cloud accounts, and unauthorized storage services may not hold patient or organizational information. Removable media must be authorized and controlled. Unsupported or personal systems may not connect to clinical networks without approval. Users may not disable security tooling, bypass network restrictions, install unauthorized software, or establish shadow services. Vendor and remote access must use approved channels. Suspected phishing, credential exposure, malware, data loss, or unauthorized access must be reported promptly.

This directly addresses documented shared credentials, shadow storage, personal cloud use, unattended sessions, removable media, and unmanaged systems.

## 6.2 Policy Roadmap

| Timing | Policy / Standard |
|---|---|
| **Month 1** | Acceptable Use Policy |
| **Month 1** | Risk Management & Risk Acceptance Standard |
| **Month 1** | Access Control / MFA Standard |
| **Month 1** | Vulnerability & Patch Management Standard |
| **Month 1–2** | Incident Response Policy and ransomware/PHI playbooks |
| **Month 2** | Change Management Standard |
| **Month 2** | Backup & Recovery Standard |
| **Month 2–3** | Logging & Monitoring Standard |
| **Month 3** | Vendor / Third-Party Access Policy |
| **Month 3–4** | Medical Device Security Standard |
| **Month 4** | Data Handling / DLP Standard |
| **Month 5–6** | Cryptographic Standard |
| **Month 5–6** | Business Continuity / Disaster Recovery Policy |

---

# 7. Residual Risk Assessment

## 7.1 Red Team Findings / Validation Status

**No standalone red-team report is contained in the supplied source package.** This strategy therefore does not invent executed exploit results.

The existing five kill chains should become the Phase 3 red-team/purple-team validation scenarios:

1. Can a simulated VPN foothold reach EHR database services after segmentation?
2. Can a compromised ordinary workstation reach privileged Active Directory management paths?
3. Can a compromised PACS/MRI component communicate outside approved imaging/vendor flows?
4. Can a compromised endpoint reach or alter backup-management systems?
5. Can an authorized network administrator make high-impact infrastructure changes without independent approval or detection?

The expected result is that the first four paths are technically blocked and the fifth is constrained by governance and privileged-access controls.

## 7.2 Accepted / Temporarily Tolerated Residual Risks

The Risk Register formally assigns **Mitigate** to all ten top risks; no top-ten risk is unconditionally accepted. The following residual exposures require temporary management tolerance and explicit executive awareness:

| Residual Risk | Exposure | Justification |
|---|---|---|
| No 24/7 SOC | **$195,495/year** modeled opportunity cost | SOC costs **$136,960**, exceeding the **$120,000** total budget; reassess after SIEM/EDR generate operational evidence. |
| Insider PHI exfiltration without full DLP | Residual score **4 × 3 = 12**; current ALE **$300,000/year** | SIEM/EDR provide detection but do not fully prevent authorized-channel or removable-media exfiltration. |
| Legacy MRI | Residual score **2 × 5 = 10** | Platform cannot be treated as a normal patchable workstation; compensate with isolation and pursue vendor-approved modernization. |
| PACS/MRI recovery | Residual score **2 × 5 = 10**; ALE not quantified | PACS-specific recovery remains an identified clinical gap and requires additional validation/funding. |
| Full dedicated medical-device monitoring architecture | Residual targeted ALE **$25,500/year** | $95,000 design was not cost-justified; targeted segmentation and credential remediation are used instead. |

## 7.3 Year 2 Priorities

Year 2 should prioritize:

1. 24/7 SOC/MDR decision based on measured SIEM/EDR workload.
2. Enterprise DLP and removable-media control.
3. PACS-specific backup and recovery.
4. Privileged Access Management for network/core administrators.
5. Medical-device monitoring and lifecycle maturity.
6. Third-party and supply-chain risk governance.
7. Legacy MRI and unsupported-platform modernization.
8. Reassessment of permanent full-time CISO staffing.

---

# 8. Implementation Roadmap

## Phase 1 — Months 1–2: Quick Wins + Procurement

### Milestones

- Approve Risk Appetite, RACI authority, and $120,000 control portfolio.
- Publish AUP, risk acceptance, MFA/access, vulnerability-management, and incident-response standards.
- Begin MFA deployment.
- Restrict EHR PostgreSQL reachability.
- Map approved flows for EHR, AD, PACS/MRI, medical devices, backups, Westside, and DMZ.
- Establish Wazuh infrastructure.
- Procure/configure EDR, Westside firewall, segmentation infrastructure, and immutable backup.
- Separate backup administrative identities.
- Begin monthly Risk Register governance.

### Success Metrics

**MFA coverage = protected in-scope privileged/remote accounts ÷ total in-scope privileged/remote accounts × 100; target = 100%.**

**Critical flow documentation = approved critical flows ÷ identified critical flows × 100; target = 100%.**

**Risk ownership = risks with named owners ÷ 10 × 100 = 10 ÷ 10 × 100 = 100%.**

**Overdue Critical vulnerabilities without approved exception = 0.**

---

## Phase 2 — Months 3–4: Core Controls Deployment

### Milestones

- Enforce seven-zone segmentation and default-deny policy.
- Isolate backup administration and medical-device/imaging management.
- Deploy EDR and integrate telemetry with Wazuh.
- Centralize FortiGate, AD, EHR, EDR, backup, Westside, and network logs.
- Replace the Westside consumer perimeter.
- Enable immutable/offsite backup replication.
- Complete first controlled restore test.
- Publish change-management, recovery, logging, vendor-access, and medical-device standards.

### Success Metrics

**Unauthorized inter-zone paths discovered during validation = 0.**

**Critical log-source coverage = reporting required sources ÷ required sources × 100; target = 100%.**

**EDR coverage = healthy reporting agents ÷ supported in-scope systems × 100; target ≥ 95%.**

**Restore-test success = successful tests ÷ scheduled tests × 100; target = 100%.**

**Privileged logins without MFA = 0.**

---

## Phase 3 — Months 5–6: Validation + Optimization

### Milestones

- Conduct safe red-team/purple-team testing against the five kill-chain scenarios.
- Tune Wazuh detections for VPN reconnaissance, AD privilege changes, EHR anomalies, backup sabotage, medical-device access, and Westside traffic.
- Conduct a ransomware/credential-compromise tabletop exercise.
- Perform broader disaster-recovery testing.
- Reassess all ten Risk Register entries.
- Reassess NIST and CIS maturity.
- Approve Year-2 SOC, DLP, PACS recovery, PAM, vendor-risk, and legacy-modernization priorities.
- Publish the initial cryptographic baseline for Project 1x04.

### Success Metrics

**Segmentation kill-chain disruption = disrupted chains ÷ 5 × 100 = 4 ÷ 5 × 100 = 80% or better.**

**Critical validation findings without an owner = 0.**

**Risk Register review completion = reviewed risks ÷ 10 × 100 = 10 ÷ 10 × 100 = 100%.**

**Successful Critical-system restore tests ÷ scheduled Critical-system restore tests × 100 = 100%.**

**Critical alerts with documented disposition ÷ all Critical alerts × 100 = 100%.**

**NIST target attainment = functions at Managed ÷ 6 × 100; target = 6 ÷ 6 × 100 = 100%.**

---

# 9. Next Steps

## 9.1 Connection to Project 1x04 — Cryptographic Foundation

Project 1x04 should start from the cryptographic weaknesses already identified in the vulnerability assessment rather than from a generic encryption checklist. Existing evidence includes TLS 1.0 on the patient portal, weak DES/RC4 Kerberos support, unencrypted DICOM traffic, certificate lifecycle weaknesses, and incomplete protection of backup data.

The next project should define:

- Approved cryptographic protocols and cipher suites.
- Encryption requirements for Restricted data at rest and in transit.
- Certificate issuance, renewal, revocation, and monitoring.
- Key ownership, generation, storage, escrow, rotation, and destruction.
- Secrets-management standards.
- Medical-device and legacy-system cryptographic exceptions.
- Migration plans for systems unable to meet the target cryptographic baseline immediately.

## 9.2 Path from Strategy to Implementation

The strategy becomes an operating program through five recurring loops:

1. **Risk Register → Work:** each control project remains tied to a risk, owner, KRI, treatment decision, and review date.
2. **Architecture → Enforcement:** segmentation diagrams become tested VLANs, ACLs, management paths, and deny rules.
3. **Controls → Evidence:** MFA, EDR, SIEM, firewall, and backup deployments are not complete until operational evidence proves they work.
4. **Testing → Improvement:** incidents, alerts, vulnerability scans, restoration tests, and purple-team validation update control configurations and the Risk Register.
5. **Board Oversight → Funding:** residual risk, ALE, clinical consequence, and measured control performance determine the Year-2 investment plan.

The Year-1 objective is not to claim that MedDefense becomes risk-free. It is to move from an environment where one successful foothold can become an enterprise clinical incident into a security program where risk is **owned, segmented, monitored, recoverable, measured, and reviewed**.

# Board Decision Requested

The Board should approve:

1. The **$120,000** Year-1 control portfolio.
2. The proposed risk-appetite statement and risk-acceptance authority.
3. The six-month **Managed** target across all six NIST CSF functions.
4. The seven-zone default-deny segmentation architecture.
5. The policy roadmap and monthly Risk Register governance cycle.
6. Temporary tolerance of explicitly documented residual risks pending Year-2 review.
7. Transition to Project **1x04 — Cryptographic Foundation**.
