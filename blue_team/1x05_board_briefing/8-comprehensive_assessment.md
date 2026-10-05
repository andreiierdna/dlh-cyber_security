# MedDefense Health Systems — Comprehensive Security Assessment

**Prepared for:** Dr. Morales (CEO) and the Board of Directors
**Prepared by:** Security Analyst, under James Chen, Deputy CISO
**Date:** 2026-10-05
**Status:** Emergency update — issued in response to CISA advisory AA26-077A ("Crimson Tide")

---

## 1. Executive Summary

MedDefense Health Systems is a 350-bed regional acute-care hospital with an outpatient clinic (Westside) and a corporate HQ, approximately 1,800–2,000 staff, and a technology estate that directly supports patient care. Over five weeks of assessment, four independent lines of analysis reached the same conclusion: **the organization has recognizable security controls, but they are not aligned to its most critical assets, and its internal network provides almost no containment.**

That conclusion is no longer theoretical. MedDefense matches **every one** of the four enabling conditions named in the current Crimson Tide ransomware advisory:

| Advisory enabling condition | MedDefense status |
|---|---|
| Unpatched FortiGate VPN appliance | Version **unknown**, support contract **lapsed**, two Critical CVEs potentially applicable |
| Flat internal network without segmentation | **Present** — designed but not deployed |
| Weak or absent Active Directory authentication controls | **Present** — RC4/DES enabled, no MFA, unsigned LDAP permitted |
| Unencrypted backup infrastructure on the production network | **Present** — NAS-01 unencrypted, same room, rack and network as production |

Three hospitals in MedDefense's region were compromised in the last ten days. One is 45 miles away and still in active containment with ambulance diversions. The attack chain in those incidents maps phase-by-phase onto MedDefense's environment with **no step that MedDefense currently blocks** except partial endpoint antivirus at the final stage.

**The single most urgent action** is to verify the FortiOS version on the FortiGate and, if it falls in the affected range, patch it or disable external SSL-VPN access immediately. The boundary figure is $2,400 — the cost of the support renewal that makes the patch obtainable — against an annualized exposure now estimated at **$4.49 million**.

**The financial picture has changed materially, not fundamentally.** Crimson Tide raised the estimated occurrence rate of an enterprise ransomware event by 57%, which increases the value of every control MedDefense already planned. It does not require a new strategy. It requires **faster execution of the existing one**, starting tonight.

---

## 2. Emergency Status

**The threat, in plain language.** Crimson Tide is a ransomware affiliate network. It breaks in through unpatched FortiGate VPNs, spends 4–7 days inside, steals patient and financial data, destroys backups, then encrypts systems — and demands payment twice (decryption plus non-publication). It targets 100–500-bed hospitals: MedDefense's exact profile.

**Is MedDefense in the blast radius? Yes.** Five hospitals hit in ten days, three in our region, one 45 miles away still in containment with ambulance diversions. Mapped against our environment, **6 of 7 attack phases are fully exposed**; only ransomware deployment is partially mitigated, by antivirus that does not cover servers. The FortiGate is our only perimeter device — once it falls, the flat network offers no second obstacle.

**72-hour plan (detail in Task 3).**
- **Tonight, $0:** verify FortiOS version, restrict SSL-VPN, hunt IOCs, disconnect NAS-01 after a verified backup, audit AD admin accounts.
- **Tomorrow, $2,400:** renew support and patch the FortiGate, enforce MFA, harden Kerberos, isolate backups properly.
- **This week:** start segmentation, deploy server detection, load IOCs into Wazuh, run an IR tabletop.

---

## 3. Security Posture Overview

### 3.1 Asset landscape

The asset registry contains **58 identified assets**, of which the network scan returned **47 responsive hosts**. Five asset groups are rated Critical: the **EHR** (`ehr-srv-01` / `ehr-db-01`), the **PACS/MRI imaging environment** (`pacs-srv-01`, `WS-RAD-01`), **Active Directory** (`ad-dc-01` / `ad-dc-02`), the **network core** (FortiGate 100F, Cisco switching, network closets), and the **medical IoT fleet** (approximately 80 patient monitors, 120 infusion pumps, nurse-call).

The estate is geographically split across Central Hospital, Westside Clinic, and Corporate HQ, and includes approximately 320 Central workstations, 60 thin clients, 45 Westside workstations, 120 HQ workstations, 30 laptops and 25 physician iPads. Two undocumented Linux hosts (`10.10.2.99` and `10.10.10.200`) remain classified as unmanaged shadow IT because no owner, purpose or management authority could be established.

**Material inventory weakness:** endpoint counts, the thin-client population and iPad management status remain unreconciled. MedDefense does not yet have a single authoritative source of truth, which is itself a finding rather than a documentation nuisance.

### 3.2 Control maturity (NIST CSF 2.0 profile)

MedDefense has adopted **NIST CSF 2.0** as its governance framework and **CIS Controls v8.1** as its implementation layer. Current profile against a six-month target of *Managed*:

| CSF Function | Current | Target | Principal deficiency |
|---|---|---|---|
| **Govern** | Partial | Managed | Risk ownership and acceptance exist on paper; review cadence untested until now |
| **Identify** | Partial | Managed | Asset registry incomplete; no recurring vulnerability management process |
| **Protect** | Partial | Managed | Segmentation, MFA and server hardening absent |
| **Detect** | **Not Implemented** | Managed | No centralized logging, no correlation, no alerting |
| **Respond** | Partial | Managed | No formal IR plan; January ransomware response was improvised |
| **Recover** | Partial | Managed | No tested disaster recovery; backups share the production failure domain |

**The decisive weakness is Detect.** MedDefense produces firewall, SSH, Windows, Linux, Apache and EHR audit records, but they remain local and manually reviewed. The organization's only demonstrated detection method is a user noticing that a system is slow — which is how the `billing-srv-01` crypto-miner was found after at least two weeks of operation.

### 3.3 Top gaps

Of **18 formal gaps** (9 Critical, 9 High), the four that Crimson Tide directly weaponizes:

- **GAP-003 — Network core exposed; insufficient internal isolation (Critical).** Intersects all five modeled kill chains. The advisory's Phase 3 depends on exactly this condition.
- **GAP-004 — Production and backup copies share one failure domain (Critical).** The advisory's Phase 5 depends on it.
- **GAP-007 — Active Directory relies on passwords without mandatory MFA or alerting (High).** Enables Phase 2 and Phase 3.
- **GAP-016 — No centralized security monitoring (Critical).** Explains why the four-to-seven-day dwell time would go unnoticed.

Two further gaps are acute and **unfunded**: **GAP-011** (no vulnerability/patch management — the reason the firewall version is unknown) and **GAP-012** (no incident response plan — the reason Phase 7 would be improvised). **GAP-017** (Westside perimeter) is funded at $20,000, but that line is the proposed source for emergency reallocation (Section 8.4).

---

## 4. Threat Landscape

### 4.1 Top three threat actors and current status

Ranking from the 1x01 Threat Actor Matrix (likelihood × impact):

| Rank | Actor | Original assessment | Current status |
|---|---|---|---|
| **1** | **Ransomware groups / organized crime** | Critical likelihood, Critical impact; FortiGate→EHR path ranked the single highest threat | **Escalated.** Named campaign (Crimson Tide) confirmed active in the region — three comparable hospitals hit in ten days. |
| **2** | **Insider — negligent** | High likelihood, High-to-Critical impact; already demonstrated (shared `raduser` credential, personal NAS holding patient data, privileged credential emailed in a script) | **Unchanged, higher consequence.** The same unsafe behaviors can hand Crimson Tide credentials or footholds on a flat network. |
| **3** | **Insider — malicious** | Medium likelihood, High-to-Critical impact; incomplete offboarding (a contractor account stayed active 47 days), no DLP | **Unchanged.** No DLP means a malicious insider and an attacker's Rclone exfiltration are equally invisible. |

Outside the top three: the **opportunistic attacker** (High likelihood) is directly relevant because CVE-2023-27997 is automatable; **nation-state APT** remains Low.

### 4.2 How Crimson Tide maps to the original threat model

The 1x01 assessment built **five kill chains**. Crimson Tide is not a new chain — it is **Kill Chain #1 executed by a specific group**, with elements of Kill Chain #4 appended.

| Crimson Tide phase | Existing MedDefense kill chain | Status |
|---|---|---|
| 1. FortiGate SSL-VPN exploitation | **KC-1, Step 1** — "Exploitation of the FortiGate 100F VPN service" | Identical vector; only the specific CVE is new |
| 2. Credential harvesting and reconnaissance | **KC-1, Step 2** | Identical |
| 3. Lateral movement across a flat network | **KC-1, Step 3** + **KC-2** (Kerberoasting, RC4) | Identical, plus the AD path already modeled |
| 4. Database exfiltration | **KC-1, Step 4** | Identical — and easier, because MedDefense databases are unencrypted at rest |
| 5. Backup destruction | **KC-4** — "phished IT administrator to backup destruction" | Same outcome, reached here from the firewall rather than from phishing |
| 6. Ransomware deployment by GPO | **KC-1, Step 5** (impact) | Identical |
| 7. Double extortion | **Scenario S-1 Operation Flatline** | Already modeled, including patient-record theft and recovery destruction |

**The uncomfortable conclusion:** MedDefense's own threat modeling, completed weeks before the advisory, described this attack. The gap was never analytical — it was that the controls which break these chains (segmentation, MFA, immutable backups, centralized detection) were designed, priced, and **not yet deployed**.

---

## 5. Vulnerability Status

### 5.1 The five findings that matter most

The scan produced **31 findings across 47 responsive hosts** (4 Critical, 7 High, 11 Medium, 5 Low, 4 Informational). After validation, **24 are actionable** and 2 were correctly closed as false positives. Misconfiguration — not missing patches — is the largest category at 39%.

| # | Finding | Asset | Why it matters now |
|---|---|---|---|
| **1** | **003 — PostgreSQL reachable from the entire `10.10.0.0/16`** | `ehr-db-01` | Crimson Tide's Phase 4 copies raw database files. Broad reachability plus no at-rest encryption is precisely that path. |
| **2** | **015 — DSM management reachable network-wide; backups unencrypted** | `NAS-01` | Crimson Tide's Phase 5 destroys backups first. This finding *is* the precondition. |
| **3** | **007 + 018 — LDAP signing not required; RC4/DES Kerberos enabled** | `ad-dc-01/02` | Phase 3 reports Kerberoasting in 3 of 5 incidents. MedDefense has the exact misconfiguration. |
| **4** | **001 + 002 — Apache mod_lua RCE plus privilege escalation to root** | `billing-srv-01` | A second, independent remote-entry-to-root chain on a server already compromised twice. |
| **5** | **004 — Unsupported Windows XP MRI workstation with weaponized RCEs** | `WS-RAD-01` | Unpatchable by design; only segmentation and monitoring can contain it. Enabled Phase 3 expansion if reached. |

Beyond the top five: **Finding 006** (MySQL bound to `0.0.0.0`), **Finding 005** (TLS 1.0 on the patient portal), **Finding 009** (password SSH without lockout), **Finding 010/016** (default medical-device credentials and broadly reachable clinical interfaces), and **Finding 023** (unrestricted USB across approximately 280 clinical workstations).

### 5.2 Remediation progress — what has been fixed and what has not

**This is the most important section in the report.**

| Status | Count | Detail |
|---|---:|---|
| Findings formally closed | **2** | Findings 020 and 031 — both closed as **false positives**, not remediated |
| Findings remediated | **0 evidenced** | No remediation is evidenced; James Chen's advisory note confirms the flat network, RC4 Kerberos, unencrypted backups and unencrypted EHR database are all still open |
| Controls deployed from the 1x03 strategy | **0 of 6** | Segmentation, MFA, SIEM, EDR, Westside firewall and immutable backup are all designed and funded but **not implemented** |
| Cryptographic controls deployed from 1x04 | **0** | 18 crypto findings identified; none deployed |
| Previously "fixed" systems | 1 rebuild | `billing-srv-01` was rebuilt after the January ransomware **without correcting the vulnerable software** and was then compromised again by a cryptominer through the same entry point |

The honest summary: **MedDefense has an excellent plan and no executed remediation.** The January ransomware incident was contained by improvisation, not process. The billing server has been compromised twice. The firewall's own firmware version is unknown to the organization that depends on it as its only perimeter. Crimson Tide did not find a new weakness — it found an organization that had not yet acted on what it already knew.

---

## 6. Risk Quantification

### 6.1 Updated top five ALE table

Crimson Tide changes the **occurrence rate**, not the loss size. Enterprise ransomware ARO moves from **0.30 to 0.470** (+57%), which re-orders the register.

| Rank | Risk | Before | **Updated** | Basis |
|---:|---|---:|---:|---|
| **1** | **Enterprise ransomware (RISK-001)** | $2,864,400 | **$4,487,560** | SLE $9,548,000 × ARO 0.470 (hazard model over a 30-day elevated window) |
| **2** | **EHR PHI breach (RISK-002)** | $3,025,000 | **$3,025,000** | SLE $9,075,000 ÷ 3 years — unchanged |
| **3** | **Insider PHI exfiltration (RISK-006)** | $300,000 | **$300,000** | $120,000 × 2.5 incidents/year — unchanged |
| **4** | **Billing-server ransomware (RISK-005)** | $135,143 | **$135,143** | $473,000 ÷ 3.5 years — unchanged |
| **5** | **Medical-device compromise (RISK-008)** | $85,000 | **$85,000** | ($250,000 × 0.10) + ($3,000,000 × 0.02) — unchanged |
| — | **New: FortiGate CVE-2023-27997 (RISK-NEW-001)** | — | **$4,487,560** | Same loss scenario as RISK-001, viewed through the entry vulnerability — **not additive** |

**Critical caveat carried forward from 1x03:** these ALE figures must **not** be summed. RISK-002, RISK-003, RISK-004, RISK-005, RISK-007 and RISK-NEW-001 are stages or pathways inside the same enterprise incident. Summing them would count the same avoided loss many times over.

**Sensitivity:** the updated ARO rests on an assumed **25** comparable hospitals in the region. At 15 the ALE is $5.57M; at 40 it is $3.76M. Even the most favourable assumption leaves a 31% increase over the original estimate.

### 6.2 Budget allocation status

| Decision | Control | Cost | Status |
|---|---|---:|---|
| Fund | Network segmentation | $35,000 | Allocated — **not deployed** |
| Fund | MFA (VPN/admin) | $10,000 | Allocated — **not deployed** |
| Fund | Wazuh SIEM | $21,000 | Allocated — **not deployed** |
| Fund | EDR upgrade | $26,000 | Allocated — **not deployed** |
| Fund | Westside firewall | $20,000 | Allocated — **not deployed** |
| Fund | Immutable offsite backup | $8,000 | Allocated — **not deployed** |
| | **Total** | **$120,000** | **$0 remaining; $0 deployed** |
| Defer | 24/7 outsourced SOC | $136,960 | Exceeds the entire annual budget alone |
| Reject | Full medical-device isolation | $95,000 | Net value −$35,500 |

### 6.3 ROI — implemented versus planned

| Category | Value |
|---|---:|
| **Realized risk reduction to date** | **$0** — no control has been deployed |
| **Planned annual risk reduction (original ARO, independent sum)** | $5,230,520 |
| **Planned annual risk reduction (updated ARO, independent sum)** | **$8,152,208** |
| **Emergency item: FortiGate support renewal** | $2,400 cost; break-even at **0.0535%** effectiveness; even at 1% effectiveness the ROI is **≈ 17.7×** |

*(The portfolio figures are the arithmetic sum of the six controls' individual ALE reductions from 1x03 Task 7 and are shown only to illustrate the scale of the change. They must not be read as an additive enterprise total — the controls reduce overlapping portions of the same ransomware loss, as 1x03 explicitly warns.)*

The updated ARO makes the already-approved portfolio roughly **1.57× more valuable** without changing its cost. The correct Board response is to accelerate deployment, not to re-plan.

---

## 7. Cryptographic Posture

### 7.1 Data protection coverage

The Task 0 Data Protection Map assessed **21 data-state combinations** (7 data categories × at-rest, in-transit, in-use):

| Classification | Cells | Share |
|---|---:|---:|
| **Adequate** | **3** | **14.3%** |
| Weak | 3 | 14.3% |
| **Absent** | **15** | **71.4%** |

The only three adequate cells are O365 email at rest, O365 email in transit, and site-to-site VPN traffic in transit — **everything adequate is protected by a third party (Microsoft) or by the VPN appliance**, not by a MedDefense-controlled design. **85.7% of MedDefense's data states are weak or unprotected.**

Task 15 produced **18 cryptographic findings** (CRYPTO-001 through CRYPTO-018). All 18 now have a defined remediation path — planning coverage is 100% — but **implementation coverage remains 14.3%**. The 1x04 implementation playbook (Task 22) defines five production changes; none has been executed.

### 7.2 Critical cryptographic gaps that Crimson Tide exploits

| Crypto weakness | Crimson Tide phase | Effect |
|---|---|---|
| **No at-rest encryption on the EHR or billing database volumes** | Phase 4 — Exfiltration | The advisory states that in 4 of 5 incidents the attacker **copied raw database files without needing database credentials**. MedDefense's databases are readable directly from the filesystem. |
| **Backups stored unencrypted on NAS-01** | Phase 5 — Backup destruction | In 3 of 5 incidents the attacker could verify the backups contained valuable data before destroying them. NAS-01 provides that same visibility. |
| **Kerberos RC4/DES still enabled; MD4 NT hashes** | Phase 3 — Lateral movement | Kerberoasting enables offline cracking of service-account passwords without touching account lockout. |
| **Plaintext PostgreSQL and MySQL transport** | Phase 2/4 | Credentials and record data cross the flat network in the clear, aiding credential collection. |
| **Portal TLS 1.0 permitted; certificate 23 days from expiry** | Not exploited by Crimson Tide | Independent availability and confidentiality exposure on the Internet-facing patient portal. |

Two honest limitations. First, volume encryption does not stop an attacker who already has root on a running server; it protects stolen disks, offline copies and backups. It complements segmentation and access control — it does not replace them. Second, Microsoft-managed O365 encryption is real but outside MedDefense's control, and it does not cover the PHI that physicians email in plaintext today.

### 7.3 Compliance status — HIPAA

**There is no completed HIPAA Security Rule assessment.** Legal has asserted compliance; no evidence has ever been produced to support that claim, and this was documented as a known unknown during onboarding.

What is established:

- **Security Rule risk analysis:** a formal, documented risk analysis is a required element. MedDefense has now produced one through this program (1x00–1x05), which is a meaningful step forward — but it has not been adopted as an organizational process with a review cadence until this week's register update.
- **Encryption:** HIPAA does not mandate a specific algorithm. HHS directs organizations toward encryption consistent with appropriate NIST standards and FIPS-validated implementations. MedDefense currently fails this in practice for 15 of 21 data states.
- **Breach notification:** the $25,000 notification figure and the $8.25M record-cost figure already used in the ALE model reflect the applicable exposure. If Crimson Tide succeeds, the exfiltration **precedes** encryption, so breach notification obligations trigger regardless of whether the ransom is paid.
- **Ransomware enforcement is active.** HHS OCR has continued pursuing ransomware cases specifically on risk-analysis and recovery failures, and had brought multiple ransomware investigations in 2026. Recovery capability and documented risk analysis are the recurring themes in those actions — both of which are precisely MedDefense's weaknesses (GAP-004, GAP-012).
- **Unsupported software:** the end-of-life MRI workstation and print server remain HIPAA Security Rule concerns even at low exploitation risk.

**Bottom line:** MedDefense cannot currently demonstrate HIPAA Security Rule compliance and should not represent otherwise to the Board, to patients, or to regulators.

---

## 8. Recommendations

### 8.1 Next 72 hours (from Task 3)

Each action traces to the advisory phase, the 1x02 finding, the 1x00 gap, the 1x03 control and its cost:

| # | Action | Phase | Finding | Gap | 1x03 control | Cost |
|---|---|---|---|---|---|---:|
| **1** | Verify FortiOS version on `AST-043` | 1 | CVE-2023-27997 (new) | GAP-011 | Vulnerability management | $0 |
| **2** | Restrict SSL-VPN access (IPSec tunnels stay up) | 1 | CVE-2023-27997 (new) | GAP-003 | Network segmentation | $0 |
| **3** | Disconnect NAS-01 after a verified backup | 5 | 015 | GAP-004 | Immutable offsite backup | $0 |
| **4** | Hunt IOCs in FortiGate logs; audit AD admin accounts | 1, 2, 6 | 007 | GAP-016 | Wazuh SIEM | $0 |
| **5** | Renew FortiGate support and patch | 1 | CVE-2023-27997 (new) | GAP-011 | Vulnerability management | **$2,400** (emergency) |
| **6** | Enforce MFA on VPN and admin access | 2, 3 | 007 | GAP-007 | MFA | $10,000 (funded) |
| **7** | Remove RC4/DES; require LDAP signing | 3 | 007, 018 | GAP-007 | MFA / AD hardening | $0 (labour) |
| **8** | Restrict PostgreSQL to `ehr-srv-01` | 4 | 003 | GAP-006 | Network segmentation | $4,000 (within the $35,000 line) |

### 8.2 30-day accelerated roadmap

The 1x03 strategy was a six-month plan. Crimson Tide compresses the sequencing but not the content.

| Window | Deliverable | Owner |
|---|---|---|
| Days 1–7 | FortiGate patched; MFA live; NAS-01 isolated; backup sets encrypted; PostgreSQL restricted | Sarah Park |
| Days 7–14 | Segmentation Phase 1: server / workstation / medical-device / management zones at Central | Sarah Park + network techs |
| Days 14–21 | Wazuh SIEM collecting FortiGate, AD, EHR and billing logs with Crimson Tide IOCs as detection rules | Security Analyst |
| Days 14–30 | Server-class EDR on `billing-srv-01`, `ehr-srv-01` and remaining servers; Westside perimeter replaced | Sarah Park + vendor |
| Days 21–30 | Incident-response tabletop on the Crimson Tide chain; IR plan drafted; immutable offsite backup validated with a full restore test | James Chen |

### 8.3 Year 1 strategic priorities

1. **Containment before detection before recovery.** Segmentation remains the highest-leverage investment because it limits blast radius regardless of how an attacker enters.
2. **Eliminate the single point of failure.** Redundant perimeter capability — the lack of it is the structural weakness Crimson Tide exposes.
3. **Convert the plan into an operating capability.** Vulnerability management, change management, and asset reconciliation must become recurring processes, not project deliverables.
4. **Close the compliance evidence gap.** Adopt the risk analysis formally, document risk acceptance at CEO level, and prepare for HIPAA Security Rule scrutiny.

### 8.4 Budget

| Item | Amount | Source |
|---|---:|---|
| Year-1 approved portfolio | $120,000 | Existing allocation — **$0 remaining** |
| Emergency: FortiGate support renewal | **$2,400** | Approve immediately |
| Emergency supplemental: vendor-assisted firewall remediation and segmentation acceleration | **up to $25,000** | Reallocate $20,000 freed by deferring the Westside firewall; supplement the remainder |
| Deferred: 24/7 outsourced SOC | $136,960 | Reconsider after SIEM/EDR telemetry exists |
| Rejected: full medical-device architecture | $95,000 | Fund the ~$27,000 targeted work instead |

---

## 9. Residual Risk Disclosure

**After full implementation of the funded program, the following risks remain.**

| Residual risk | Why it remains | Accepted by |
|---|---|---|
| **Valid-credential and phishing attacks** | MFA and segmentation reduce but do not eliminate credential abuse; attackers increasingly target people rather than devices | CEO |
| **The unpatchable MRI workstation** | Windows XP cannot be upgraded without invalidating vendor certification; only isolation and monitoring contain it | CEO / Radiology |
| **Medical-device compromise** | The $95,000 full isolation architecture was rejected on cost-benefit grounds; targeted segmentation reduces but does not eliminate reachability | CEO (documented risk acceptance) |
| **Westside Clinic** | A consumer-grade perimeter device continues to bound Central's security if the firewall replacement is deferred | CEO |
| **Insider exfiltration at volume** | Preventive DLP is not funded in Year 1; RISK-006 residual remains High (4 × 3 = 12) | CEO |
| **After-hours detection gap** | SIEM and EDR provide telemetry, but 24/7 monitoring is deferred; response outside business hours remains a person, not a process | CEO |
| **Record-level encryption of EHR/billing fields** | Deferred to Phase 2; volume encryption protects media, not authorized queries | CEO |
| **Application-layer compromise** | No WAF, no secure code review; the patient portal and EHR applications remain trust paths | CEO |
| **HIPAA compliance cannot be demonstrated** | No formal Security Rule assessment has been performed | CEO / General Counsel |

**What MedDefense is accepting, stated plainly:** even fully funded, this program does not make MedDefense secure. It removes the specific conditions that Crimson Tide is using right now, and it converts an environment where a single failure becomes an enterprise outage into one where failures are contained, detected, and recoverable. The residual risks above are accepted because their treatment costs exceed their modeled value, because regulatory or vendor constraints make them unavoidable in the near term, or because the capability must be built on foundations that do not yet exist. **Each of these acceptances must be recorded at CEO level, because Security and IT cannot accept risk on the organization's behalf.**

**One acceptance deserves specific attention.** If the Board declines even the $2,400 support renewal, MedDefense keeps an unverified perimeter device in front of an active, regionally confirmed campaign — accepting the full **$4.49 million per year** exposure to avoid a cost of about **0.05%** of that figure. That decision, if taken, should be minuted.

---

## 10. Next Module Preview

This assessment closes the *understanding* phase. The next module moves into **execution**: **endpoint hardening and infrastructure defense** — the hands-on work of hardening the operating systems and services that the last five projects identified, validated and prioritised. Expected focus areas: host hardening baselines for Windows and Linux servers, secure configuration of the EHR and billing platforms, service and account hardening, controlled change management, and the operating procedures that turn the 30-day roadmap into sustained capability.
