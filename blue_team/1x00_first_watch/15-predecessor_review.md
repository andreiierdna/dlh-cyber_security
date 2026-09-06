# MedDefense Health Systems

## The Predecessor's Notes: Comparative Analysis of Marcus Webb's Draft Assessment

### 0. Purpose and Method

This analysis reconciles the unfinished draft assessment left by the previous security analyst, Marcus Webb (dated three months prior, marked "DRAFT v0.3 -- INCOMPLETE"), against the completed Prioritized Gap Analysis (Task 12, GAP-001 through GAP-010) and the Reality Check breach validation (Task 13, GAP-011 through GAP-015). The objective is not simply to list overlaps, but to determine whether Marcus's independent, differently-scoped assessment strengthens, weakens, or extends the current findings, and to surface anything his draft caught that the completed work did not.

Marcus's document was authored from a network- and clinical-infrastructure-focused vantage point, apparently based on direct technical reconnaissance (network topology, device firmware, backup configuration) rather than the asset-registry/data-map/control-matrix method used in Tasks 12-13. Where the two methods converge independently on the same conclusion, that convergence is treated as corroborating evidence, not redundant evidence.

---

### 1. Comparative Analysis Table

| # | Finding | Marcus's Assessment | Your Assessment | Agree / Disagree | Resolution |
|---|---------|---------------------|------------------|-------------------|------------|
| 1 | Flat network, no VLANs/internal firewalls (M-01) | Critical -- single most dangerous finding; amplifies every other vulnerability | Not a standalone gap; the same architectural condition is the documented root cause of **GAP-002** (no medical-device VLAN enforcement), **GAP-003** (network core rated Under-Protected), **GAP-004** (backup shares production's network), and **GAP-006** (EHR database reachable more broadly than required) | Agree | No new gap number assigned. Recommend GAP-002/003/004/006 be formally cross-referenced as downstream consequences of one architectural cause, with internal segmentation confirmed as the top structural remediation priority (consistent with Task 13's revised remediation order, which already places GAP-002 and GAP-003 at positions #2 and #4) |
| 2 | Backup NAS on production network, no offsite/cloud replication, monthly tape rotation only (M-02) | Critical | **GAP-004** -- Critical | Agree | Exact match. Independently confirmed by the Hospital Alpha correlation in Task 13, which shows ransomware reaching a network-resident backup NAS in a real incident |
| 3 | Medical IoT exposure -- BD Alaris firmware 12.1.2 known vulnerability, default credentials, no isolation (M-03) | High (notes "potentially CRITICAL given patient safety implications") | **GAP-002** (segmentation/monitoring/recovery) -- Critical; **GAP-015** (device credential governance) -- Critical | Disagree on severity rating | Uphold Critical for both gaps. Task 12's own scoring rule -- "affects a Critical-rated asset... and lacks an effective detective or corrective capability" -- is unambiguously met; Marcus's hedge to High understates the patient-safety consequence he himself identifies. His specific citation of BD Alaris firmware 12.1.2 and the associated BD Security Bulletin is a new, concrete technical detail not previously documented -- add as supporting evidence to GAP-002 and GAP-015 rather than as a separate gap, since it is one specific instantiation of the already-scored "default credentials / unpatched firmware" weakness |
| 4 | Zero detective capability -- no SIEM, no IDS/IPS, no log centralization (M-04); illustrated by the billing-srv-01 crypto-miner running undetected for 2+ weeks | High | Not a standalone gap in Task 12/13; appears only as a recurring "Detective" deficiency inside GAP-001, 002, 003, 006, 007, and 008 (see Task 12 §3.3) | Disagree on treatment | Valid and under-formalized. A single centralized logging/SIEM capability would remediate the detective gap in six of the fifteen existing findings simultaneously, making it the highest-leverage single control in the entire assessment. Resolution: add as a new, explicitly documented finding -- **GAP-016** (below) -- rated **Critical**, one tier above Marcus's High, because it affects detection capability for every Critical asset category rather than one |
| 5 | No MFA anywhere -- VPN, EHR, AD admin, patient portal admin (M-05) | High | **GAP-007** (AD/MFA) -- High; supporting role in GAP-009, GAP-013, GAP-014 | Agree | Ratings match. Task 13 already elevates GAP-007 to the top of the High-tier remediation queue based on the Hospital Alpha and Health Network Beta correlations -- consistent with Marcus's framing that credential compromise is "a matter of when, not if" |
| 6 | Westside Clinic -- consumer router, no firewall, unmanaged switches, unlocked server closet, VPN terminates on the consumer router (M-06) | High | No corresponding Task 12/13 gap | Disagree on treatment (valid miss) | Valid and previously missed. Westside's posture is not academic: because the site-to-site VPN terminates on unmanaged consumer equipment, Westside directly bounds the effective protection of GAP-003 (network core) regardless of what remediation is applied at Central. Resolution: add as a new finding -- **GAP-017** (below) -- rated **High** |
| 7 | Shared "raduser/radiology1" credential on PACS workstations (M-07) | Medium ("would be HIGH except PACS access is limited to on-site") | Not separately scored; relevant to **GAP-001** (PACS recovery) | Agree | Rating logic matches Task 12 methodology exactly: on-site-only access is the same compensating condition that defines a Medium rating ("partial compensating measures are present"). Resolution: fold into GAP-001 documentation as a supplementary accountability/preventive-control deficiency rather than a new numbered gap; it does not independently meet the Critical/High threshold |
| 8 | print-srv-01 on Windows Server 2012 R2, EOL since October 2023 (M-08) | Low | Consistent with Task 12 scope, which explicitly limits the prioritized top-10 to Critical/High findings | Agree | Correctly excluded from the board-level priority list. Should remain tracked in the full asset/vulnerability register for compliance purposes (unsupported software is a HIPAA Security Rule finding even at low exploitation risk) |
| 9 | Patient portal (web-srv-01) still permits TLS 1.0 alongside 1.2 (undocumented, Section 2) | Not risk-rated (draft note only) | Not separately scored in Task 12/13 | Agree | Valid. Resolution: fold into **GAP-011** (enterprise vulnerability/patch management, Critical) as a concrete example of unremediated internet-facing exposure, since GAP-011 already covers "internet-facing systems" generally |
| 10 | No DLP controls; PHI/financial data can be exfiltrated via email, USB or cloud upload undetected (undocumented, Section 2) | Not risk-rated (draft note only) | **GAP-014** -- High | Agree | Exact substantive match, reached independently through a different method (infrastructure review vs. breach-pattern correlation). This convergence increases confidence in GAP-014's validity and priority |
| 11 | USB ports unrestricted on all workstations, no GPO control (undocumented, Section 2) | Not risk-rated (draft note only) | Not separately scored; relevant to **GAP-014** | Agree | Valid additional exfiltration channel for the same underlying risk already captured in GAP-014. Resolution: add "USB/removable-media control" explicitly to GAP-014's "What is Missing" list rather than opening a new gap |
| 12 | HQ building management system is landlord-managed; MedDefense has no visibility into that shared network, and the site-to-site VPN terminates on landlord-provided infrastructure (undocumented, Section 2) | Not risk-rated (draft note only) | No corresponding asset registry entry | Disagree on treatment | Cannot be independently validated or scored under Task 12 methodology -- there is no asset ID, no control-status evidence, and no data classification available for third-party infrastructure MedDefense does not administer. Resolution: do **not** add as a formal gap. Log as an open item for the next asset-discovery cycle: request a network diagram and segmentation evidence from the landlord/BMS vendor before this can be scored |
| 13 | No formal change management process; the untested cron-job change that caused a multi-week backup gap is cited as the example (undocumented, Section 2) | Not risk-rated (draft note only) | Not separately scored; the referenced backup-gap incident is consistent with GAP-004's note that "only a partial file-server restoration has been tested" | Agree | Valid and previously missed as a distinct administrative gap. Resolution: add as a new finding -- **GAP-018** (below) -- rated **High** |

---

### 2. New Findings Added to the Gap Analysis

Marcus's draft surfaces three findings that meet the Task 12 documentation and scoring standard but were not previously captured as standalone, numbered gaps.

#### GAP-016 -- No Centralized Security Monitoring or Log Correlation Capability

**Affected Asset(s):** Enterprise-wide. Every Critical asset category already documented in Task 12/13 -- EHR (GAP-001/006), PACS (GAP-001), Medical IoT (GAP-002/015), Network Core (GAP-003), Active Directory (GAP-007), and Billing (GAP-008) -- depends on this same missing capability for its detective control.

**Data at Risk:** All Restricted data categories in the environment (EHR PHI, imaging, credentials, billing/financial data), because detection latency directly extends the window in which any of these can be accessed, altered, or exfiltrated undetected.

**Current Control Status:** Firewall, authentication, application and system logs exist on individual devices, but Task 12's own control-concentration analysis (§3.3) already confirms these logs are stored locally with no centralized forwarding, no retention policy, and no review process. Marcus's draft supplies the concrete case study that proves the consequence: the billing-srv-01 crypto-miner executed for at least two weeks and was discovered only through a performance complaint, not through detection.

**What is Missing:**
Technical -- **Detective:** log centralization/SIEM (Marcus's draft specifically identifies Wazuh, an open-source option, as a feasible starting point), automated alerting rules for the highest-value assets first (firewall, domain controllers, EHR), and a defined log review/retention process.

**Risk Level:** **Critical**

**Risk Justification:** This finding is scored one tier above Marcus's own "High" rating. Task 12's Critical threshold is met because the missing capability affects *every* Critical-rated asset simultaneously, not a single asset class -- it is the one control whose absence is common to GAP-001, 002, 003, 006, 007, and 008. A gap that removes detective coverage from six Critical/High findings at once carries greater aggregate exposure than any one of those findings taken individually, and remediation here has outsized leverage: a single SIEM deployment materially closes the detective deficiency identified across the whole prioritized list.

**Potential Impact:** Any successful compromise of a Critical or High asset -- ransomware, credential misuse, medical-device tampering, bulk PHI exfiltration -- would go undetected until it produces a visible operational symptom (as it already has twice: the billing-srv-01 ransomware and crypto-miner incidents). Dwell time of weeks, rather than hours, materially increases both the scope of lateral movement and the volume of data an attacker can extract before discovery.

---

#### GAP-017 -- Westside Clinic Site Security Undermines Central's Network Protections

**Affected Asset(s):** Westside Clinic network infrastructure -- consumer-grade router (Netgear Nighthawk) serving as the site's sole perimeter device, unmanaged switches, and the server closet housing this equipment. Not previously assigned an asset ID in the registry reviewed for Task 12; recommend formal registration as part of remediation. The site-to-site VPN connecting Westside to Central terminates on this consumer equipment, making it functionally part of Central's network core (GAP-003).

**Data at Risk:** Whatever data classes traverse the Westside-Central VPN link, which per GAP-001 includes Westside imaging studies submitted to the central PACS -- **Restricted** data -- in addition to any general administrative traffic.

**Current Control Status:** None evidenced. There is no managed firewall, no logging, no physical access control (the server closet does not lock), and no documented review of what the site-to-site VPN's access-control list actually permits Westside to reach on the Central network.

**What is Missing:**
Technical -- **Preventive:** replacement of the consumer router with a managed firewall appliance capable of stateful VPN termination and access-list enforcement (Marcus's draft estimates a FortiGate 60F or equivalent at approximately $1,500).
Physical -- **Preventive:** a functioning lock on the server closet.
Administrative -- **Preventive:** a documented review and tightening of the VPN ACLs to restrict Westside's reachable scope on the Central network to only what is operationally required (e.g., PACS submission, not the full flat network described in GAP-003).

**Risk Level:** **High**

**Risk Justification:** Westside is not itself a Critical asset location, but it functions as an unmonitored, unmanaged entry point into Central's network core, which is independently rated Critical under GAP-003. Any remediation applied to Central's segmentation or firewall posture is undermined if an attacker can instead compromise the consumer-grade equipment at Westside and ride the existing VPN trust relationship inward. This mirrors the initial-access pattern documented in the Hospital Alpha breach correlation (Task 13), where a single under-protected perimeter device provided the foothold for an enterprise-wide incident.

**Potential Impact:** Compromise of the Westside router or physical theft of equipment from the unlocked closet could provide an attacker with a pre-authenticated path into the Central network, bypassing perimeter controls that exist at Central (C-001, C-003) entirely. This would effectively neutralize GAP-003 remediation efforts unless Westside is hardened in parallel.

---

#### GAP-018 -- No Formal Change Management Process

**Affected Asset(s):** Enterprise-wide -- all servers, network devices, and scheduled jobs subject to ad-hoc configuration changes. The specific documented consequence involves backup infrastructure (AST-009/AST-010, already Critical under GAP-004).

**Data at Risk:** Indirectly, all Restricted data dependent on the affected system's availability or integrity at the time of an untested change -- in the cited example, all Restricted backup copies described in GAP-004.

**Current Control Status:** None evidenced. Configuration changes to servers and network devices are made without documented testing or approval. Marcus's draft identifies a specific, dated consequence: an untested cron-job change caused a multi-week gap in backup execution, a condition consistent with GAP-004's own note that backup restoration has only been partially tested.

**What is Missing:**
Administrative -- **Preventive:** a documented change-management process requiring testing, peer review or approval, a rollback plan, and a maintenance window for changes to production servers, network devices, and scheduled jobs, with backup and other Critical/High-rated systems (per GAP-001 through GAP-011) subject to the strictest review tier.

**Risk Level:** **High**

**Risk Justification:** This is an administrative/preventive gap rather than a technical one, and it has already produced a demonstrated operational consequence (the multi-week backup gap) rather than a theoretical one. It does not reach Critical on its own because no single change failure has yet caused irreversible data loss or a patient-safety event, but it directly increases the likelihood and severity of failures in every Critical system it touches -- most acutely GAP-004 (backup), which depends on unattended scheduled jobs functioning correctly.

**Potential Impact:** Recurrence of an untested change against backup infrastructure, network core devices (GAP-003), or Active Directory (GAP-007) could silently disable a corrective or preventive control for an extended period before discovery, given the absence of monitoring described in GAP-016. The backup-gap incident already demonstrates this is not a hypothetical failure mode.

---

### 3. Findings Requiring Further Investigation (Not Yet Formal Gaps)

**Landlord-managed building management system (HQ):** Marcus's note that MedDefense's site-to-site VPN "terminates on whatever the building provides" and that MedDefense has no visibility into that shared infrastructure is a legitimate concern, but it cannot be scored against Task 12's methodology without an asset ID, control-status evidence, or a data-classification basis -- none of which exist for infrastructure MedDefense does not administer. This is logged as an open item: request a network diagram and segmentation evidence from the landlord or BMS vendor as a prerequisite to formal scoring in a future assessment cycle.

---

### 4. Gaps Identified in This Assessment That Marcus's Draft Missed

| Gap | Why It May Have Been Missed |
|-----|------------------------------|
| **GAP-001** -- PACS lacks an evidenced recovery capability | Requires reviewing the Veeam backup-scope configuration to identify that PACS is deliberately excluded -- a documentation/configuration audit rather than the network reconnaissance that appears to underpin Marcus's documented findings |
| **GAP-005** -- Dr. Patel's personal research NAS (Shadow IT) | Requires proactive discovery of unregistered devices (e.g., department interviews or DHCP/network-discovery review) rather than assessment of known, sanctioned infrastructure. Marcus's draft contains no shadow-IT findings of any kind, suggesting this discovery step had not yet been performed |
| **GAP-006** -- EHR database reachable more broadly than required | Implicitly covered by Marcus's flat-network finding (M-01) but never broken out to the specific EHR database asset. Consistent with the draft's own repeated admission that sections were left unfinished due to time pressure |
| **GAP-009** -- HR/administrative data lacks segmentation and MFA | Administrative/corporate systems fall outside a clinical-and-network-infrastructure-focused assessment's typical scope; none of Marcus's eight documented findings touch corporate/HR systems |
| **GAP-010** -- Marketing data controlled via personal Google account (Shadow IT) | Same scope gap as GAP-009 and GAP-005 -- unsanctioned SaaS use requires a data-governance review, not a network assessment |
| **GAP-011** -- No formal enterprise vulnerability/patch management program | Marcus documented two individual instances of this exact problem (BD Alaris firmware in M-03, print server EOL in M-08) but never generalized them into a single program-level finding -- consistent with a draft cut off mid-synthesis, still in the cataloguing phase rather than the pattern-recognition phase |
| **GAP-012** -- No formal incident response plan | An administrative/procedural gap requiring review of organizational roles and processes rather than technical configuration; Marcus's Section 3 notes show he was pivoting toward external threat-intelligence work when the document stops, meaning this procedural half of the assessment was never reached |
| **GAP-013** -- No automated identity lifecycle/offboarding process | Same category as GAP-012 -- a governance/HR-integration review that the draft, by its own account, did not get to before Marcus left |

---

### 5. Part 2 -- Reflection on the External Threat Landscape

Marcus's unfinished pivot toward an external threat-actor profile is the natural second half of the work this assessment has already completed: an internal posture assessment identifies *where* MedDefense is exposed, while a threat-landscape analysis identifies *who* is most likely to exploit that exposure and *how*. The internal findings already point toward the answer to his own questions -- a flat network, no MFA, no monitoring, and unpatched perimeter systems are precisely the combination that ransomware-as-a-service operators and opportunistic attackers exploiting known CVEs (not sophisticated nation-state actors) are best positioned to abuse, a conclusion the Reality Check's three breach correlations independently confirm. Understanding the threat landscape is the logical next step because it converts a list of internal weaknesses into a prioritized, threat-informed remediation sequence: MITRE ATT&CK mapping and STRIDE modeling would show precisely which of MedDefense's fifteen documented gaps sit on the most probable attack paths, rather than treating all Critical findings as equally likely to be exploited. Marcus's collected sources -- the CISA and HC3 advisories referenced in his notes -- should be recovered from IT's equipment-return inventory and used as the starting point for that formal Threat Landscape Report, since his internal findings and this completed gap analysis now give that report a validated internal posture to map against.
