# MedDefense Health Systems  
## Task 10 — Risk Register

### Risk Scoring Definitions

**Likelihood**
- **1 — Rare:** Credible only under exceptional conditions; no recurring evidence.
- **2 — Unlikely:** Plausible but infrequent; strong prerequisites are required.
- **3 — Possible:** A realistic scenario supported by sector evidence or current MedDefense exposure.
- **4 — Likely:** Repeated control weaknesses, demonstrated exposure, or prior related compromise make recurrence likely.
- **5 — Almost Certain:** Expected to occur repeatedly; for quantified risks this generally corresponds to more than one event per year.

**Impact**
- **1 — Minor:** Localized inconvenience with negligible clinical, regulatory, or financial consequence.
- **2 — Moderate:** Limited operational disruption or contained data exposure.
- **3 — Significant:** Material investigation, remediation, reporting, or departmental disruption.
- **4 — Major:** Major outage, substantial financial loss, or serious regulatory consequence.
- **5 — Severe/Catastrophic:** Enterprise clinical disruption, large-scale PHI compromise, destruction of recovery capability, or potential patient-safety consequence.

**Inherent Risk Score = Likelihood × Impact**

Current register date: **2026-09-21**

Monthly review cadence:

**2026-09-21 + 1 month = 2026-10-21**

---

## RISK-001

**Risk ID:** RISK-001

**Risk Description:** A ransomware operator gains an internal foothold and uses MedDefense's flat network, weak identity boundaries, limited monitoring, and reachable backups to create an enterprise-wide ransomware and data-extortion incident.

**Risk Category:** Operational

**Threat Source:** TA-1 Ransomware Groups / Organized Crime

**Vulnerability:** Findings 003, 007, and 015; additional exposure from Findings 004 and 016

**Affected Asset(s):** AST-043 FortiGate 100F; AST-005/006 Active Directory; AST-001/002 EHR; AST-009/010 backup infrastructure; broader internal network

**Likelihood:** 3 — Possible; quantified ARO is **0.30**, equivalent to:

**1 ÷ 0.30 = 3.33 years per event**

**Impact:** 5 — Severe/Catastrophic; the modeled full campaign includes EHR exfiltration, billing disruption, identity compromise, and recovery destruction.

**Inherent Risk Score:**

**3 × 5 = 15**

**ALE:**

**$9,548,000 × 0.30 = $2,864,400/year**

**Risk Owner:** James Chen, Deputy CISO

**Treatment Decision:** Mitigate

**Treatment Justification:** The risk is too large to accept because one successful foothold can propagate across multiple Critical systems and recovery infrastructure.

**Planned Control(s):** Network segmentation; MFA on VPN and administrative accounts; Wazuh SIEM; EDR upgrade; offsite immutable backup replication.

**Residual Risk:** Medium-High — **2 × 4 = 8** after layered controls. Using the conservative segmentation-only model:

**$9,548,000 × 0.40 × 0.30 = $1,145,760/year**

MFA, SIEM, and EDR should reduce the risk further, but their effects are not added here to avoid double-counting.

**KRI:** Any unauthorized cross-zone path to EHR, AD, or backup infrastructure; confirmed ransomware execution; backup administration reachable from a normal user segment; privileged remote access without MFA.

**Review Date:** 2026-10-21

---

## RISK-002

**Risk ID:** RISK-002

**Risk Description:** An attacker or malicious insider exfiltrates the EHR patient database because `ehr-db-01` is reachable from more systems than operationally required.

**Risk Category:** Compliance

**Threat Source:** TA-1 Ransomware Groups / Organized Crime; TA-2 Nation-State APT; malicious insider

**Vulnerability:** Finding 003 — PostgreSQL unrestricted network access

**Affected Asset(s):** AST-001 `ehr-srv-01`; AST-002 `ehr-db-01`; AST-016 EHR application; AST-017 EHR clinical database

**Likelihood:** 3 — Possible; modeled as one material breach every three years:

**ARO = 1 ÷ 3 = 0.333**

**Impact:** 5 — Severe/Catastrophic due to large-scale PHI disclosure, litigation, notification, and patient-trust effects.

**Inherent Risk Score:**

**3 × 5 = 15**

**ALE:**

**$9,075,000 ÷ 3 = $3,025,000/year**

**Risk Owner:** Clinical Operations Director, with Sarah Park as technical custodian

**Treatment Decision:** Mitigate

**Treatment Justification:** Direct access to a Critical PHI database from broad internal sources creates an avoidable high-value exfiltration path.

**Planned Control(s):** Network segmentation; MFA for privileged administration; Wazuh SIEM.

**Residual Risk:** Medium-High — **2 × 5 = 10**. The Task 6 model reduces occurrence probability by 60%:

**Residual ARO = (1 ÷ 3) × 0.40 = 0.1333**

**Residual ALE = $9,075,000 × 0.1333 ≈ $1,210,000/year**

**KRI:** Any unauthorized source able to connect to TCP/5432; unexpected bulk EHR export; privileged EHR access from an unapproved device or network zone.

**Review Date:** 2026-10-21

---

## RISK-003

**Risk ID:** RISK-003

**Risk Description:** Stolen or relayed credentials are converted into enterprise privilege through weak Active Directory authentication controls and insufficient privileged-access protection.

**Risk Category:** Operational

**Threat Source:** TA-1 Ransomware Groups; TA-2 Nation-State APT; TA-3 Malicious Insider; TA-6 Opportunistic Attacker

**Vulnerability:** Finding 007 — LDAP signing not required; Finding 018 — weak Kerberos encryption types

**Affected Asset(s):** AST-005 `ad-dc-01`; AST-006 `ad-dc-02`; AST-025 Active Directory directory data

**Likelihood:** 4 — Likely because the environment is password-centric, broadly reachable, and the threat model repeatedly uses credential theft and directory privilege escalation.

**Impact:** 5 — Severe/Catastrophic because AD compromise can provide enterprise authentication authority and ransomware deployment capability.

**Inherent Risk Score:**

**4 × 5 = 20**

**ALE:** Not separately quantified because AD compromise is an enabling stage inside RISK-001's enterprise ransomware model:

**$9,548,000 × 0.30 = $2,864,400/year**

**Risk Owner:** Sarah Park, IT Director

**Treatment Decision:** Mitigate

**Treatment Justification:** Enterprise identity compromise creates authority over multiple Critical assets and cannot be rationally accepted while low-cost MFA and hardening options exist.

**Planned Control(s):** MFA on VPN and administrative accounts; Wazuh SIEM; EDR upgrade; network segmentation.

**Residual Risk:** Medium-High:

**2 × 5 = 10**

after MFA, LDAP hardening, monitoring, and reduced lateral reach.

**KRI:** Any privileged authentication without MFA; any unsigned LDAP bind after enforcement; newly created or modified privileged accounts without approved change evidence; weak Kerberos use after migration.

**Review Date:** 2026-10-21

---

## RISK-004

**Risk ID:** RISK-004

**Risk Description:** A material intrusion remains undetected long enough to progress from initial access to credential abuse, exfiltration, or destructive impact because MedDefense lacks centralized security monitoring and correlation.

**Risk Category:** Operational

**Threat Source:** TA-1 Ransomware Groups; TA-2 Nation-State APT; TA-3 Malicious Insider; TA-5 Hacktivist; TA-6 Opportunistic Attacker

**Vulnerability:** No single scanner finding measures SIEM absence; detectable attack conditions include Findings 001, 002, 003, 004, 007, 015, and 016.

**Affected Asset(s):** FortiGate, Active Directory, EHR, billing, backup infrastructure, PACS/MRI, endpoints, and medical IoT

**Likelihood:** 4 — Likely because MedDefense previously detected cryptomining through performance degradation rather than a security alert, demonstrating delayed detection in practice.

**Impact:** 4 — Major because delayed containment materially increases attacker dwell time and incident scope.

**Inherent Risk Score:**

**4 × 4 = 16**

**ALE:** Not separately quantified to avoid double-counting RISK-001. Task 7 models the SIEM effect as:

**$2,864,400 − $1,861,860 = $1,002,540/year**

of reduced ransomware exposure.

**Risk Owner:** James Chen, Deputy CISO

**Treatment Decision:** Mitigate

**Treatment Justification:** Centralized monitoring creates a detection opportunity across multiple threat paths regardless of how initial access occurs.

**Planned Control(s):** Wazuh SIEM; EDR upgrade; 24/7 SOC deferred to a later funding cycle.

**Residual Risk:** Medium:

**2 × 4 = 8**

after centralized log collection, correlation, and endpoint telemetry, with residual after-hours response exposure until a SOC is funded.

**KRI:** Any Critical system stops forwarding logs; material alerts remain untriaged beyond the approved response SLA; confirmed compromise is first discovered through service degradation or user report.

**Review Date:** 2026-10-21

---

## RISK-005

**Risk ID:** RISK-005

**Risk Description:** Known exploitable vulnerabilities on Internet-facing, server, and legacy clinical systems are exploited before MedDefense identifies and remediates them.

**Risk Category:** Operational

**Threat Source:** TA-1 Ransomware Groups; TA-2 Nation-State APT; TA-5 Hacktivist; TA-6 Opportunistic Attacker

**Vulnerability:** Findings 001, 002, 004, 008, 011, 026, and 029

**Affected Asset(s):** AST-004 `billing-srv-01`; AST-034 MRI workstation; AST-008 print server; AST-014 Westside unknown Linux/Grafana host

**Likelihood:** 4 — Likely because multiple exploitable or end-of-support systems coexist with an incomplete vulnerability-management process and prior compromise history.

**Impact:** 5 — Severe/Catastrophic because exploitation can become root access, clinical disruption, or an initial foothold for enterprise ransomware.

**Inherent Risk Score:**

**4 × 5 = 20**

**ALE:** Not separately quantified as an enterprise risk because several exploit paths feed RISK-001. The billing subset is quantified as:

**$473,000 ÷ 3.5 = $135,142.86 ≈ $135,143/year**

**Risk Owner:** James Chen, Deputy CISO

**Treatment Decision:** Mitigate

**Treatment Justification:** Publicly exploitable weaknesses provide preventable attacker entry points and have already produced real compromise on `billing-srv-01`.

**Planned Control(s):** EDR upgrade; network segmentation as compensating containment for legacy systems.

**Residual Risk:** Medium-High:

**2 × 5 = 10**

after patching/remediation, EDR, and segmentation; the MRI remains unpatchable and therefore retains residual risk.

**KRI:** Any Critical or High vulnerability remains open past its remediation SLA; any unsupported system lacks an approved exception and compensating control; new public exploit availability for an installed product.

**Review Date:** 2026-10-21

---

## RISK-006

**Risk ID:** RISK-006

**Risk Description:** A negligent or malicious insider removes Restricted patient information through removable media or other authorized channels without preventive DLP controls.

**Risk Category:** Compliance

**Threat Source:** TA-4 Negligent Insider; TA-3 Malicious Insider

**Vulnerability:** Finding 023 — USB mass storage not restricted

**Affected Asset(s):** AST-027 Central workstation fleet; patient information accessible through clinical endpoints and EHR sessions

**Likelihood:** 5 — Almost Certain under the Task 5 model because estimated frequency is:

**(2 + 3) ÷ 2 = 2.5 incidents/year**

which is greater than one event per year.

**Impact:** 3 — Significant because a typical incident triggers investigation, containment, remediation, and regulatory reporting.

**Inherent Risk Score:**

**5 × 3 = 15**

**ALE:**

**$120,000 × 2.5 = $300,000/year**

**Risk Owner:** Clinical Operations Director

**Treatment Decision:** Mitigate

**Treatment Justification:** Repeated insider-loss frequency creates meaningful annual exposure even when each individual event is smaller than ransomware or EHR breach losses.

**Planned Control(s):** Wazuh SIEM and EDR provide detective coverage; full preventive USB/DLP control remains outside the current T7 funded set.

**Residual Risk:** High:

**4 × 3 = 12**

because detective controls do not fully prevent removable-media or authorized-channel exfiltration. No lower residual ALE is claimed until preventive DLP/USB controls are funded.

**KRI:** Any bulk EHR export to removable media or personal cloud; use of stale accounts after termination; repeated abnormal record access inconsistent with job function.

**Review Date:** 2026-10-21

---

## RISK-007

**Risk ID:** RISK-007

**Risk Description:** A ransomware operator or malicious administrator destroys or encrypts MedDefense's primary backup copies because recovery systems share the production trust and failure domain.

**Risk Category:** Operational

**Threat Source:** TA-1 Ransomware Groups; TA-3 Malicious Insider

**Vulnerability:** Finding 015 — NAS management accessible broadly and backup data stored on the same production environment

**Affected Asset(s):** AST-009 `backup-srv-01`; AST-010 `NAS-01`; protected Central server workloads

**Likelihood:** 3 — Possible because backup destruction is a modeled ransomware stage rather than an independent frequent event.

**Impact:** 5 — Severe/Catastrophic because loss of recovery copies can convert a containable ransomware incident into prolonged clinical and operational outage.

**Inherent Risk Score:**

**3 × 5 = 15**

**ALE:** Not separately additive because this risk is part of the ransomware loss model. Using the billing-recovery proxy:

**Current ALE = $473,000 ÷ 3.5 ≈ $135,143/year**

With immutable recovery:

**Residual ALE = $211,900 ÷ 3.5 ≈ $60,543/year**

**Risk Owner:** Sarah Park, IT Director

**Treatment Decision:** Mitigate

**Treatment Justification:** Recovery capability is a required control after prevention fails, and current backup architecture allows correlated production and recovery loss.

**Planned Control(s):** Offsite immutable backup replication; network segmentation; Wazuh SIEM.

**Residual Risk:** Medium:

**2 × 4 = 8**

after immutable offsite copies, restricted administration, and restore testing.

**KRI:** Any failed restore test; backup administration reachable from a normal workstation; immutable copy not completing; recovery credentials reused with ordinary production administration.

**Review Date:** 2026-10-21

---

## RISK-008

**Risk ID:** RISK-008

**Risk Description:** An attacker reaches inadequately isolated medical devices and abuses default credentials or network trust, causing device disruption or a patient-safety event.

**Risk Category:** Operational

**Threat Source:** TA-6 Opportunistic Attacker; TA-1 Ransomware Groups after internal foothold

**Vulnerability:** Finding 010 — Alaris default credentials / weak isolation; Finding 016 — Philips IntelliVue interfaces broadly reachable

**Affected Asset(s):** AST-036 Philips IntelliVue monitor fleet; AST-037 BD Alaris infusion-pump fleet; associated medical-device network

**Likelihood:** 2 — Unlikely for a direct patient-safety attack, although opportunistic internal compromise remains plausible.

**Impact:** 5 — Severe/Catastrophic because failure can affect patient monitoring or medication-related clinical workflows.

**Inherent Risk Score:**

**2 × 5 = 10**

**ALE:**

**($250,000 × 0.10) + ($3,000,000 × 0.02)**

**= $25,000 + $60,000**

**= $85,000/year**

**Risk Owner:** Biomedical Engineering Lead / Clinical Operations

**Treatment Decision:** Mitigate

**Treatment Justification:** The financial ALE is lower than enterprise ransomware, but patient-safety consequence makes continued default credentials and broad reachability unacceptable.

**Planned Control(s):** Network segmentation; Wazuh SIEM. The $95,000 full dedicated medical-device architecture was rejected, so MedDefense should use targeted device segmentation and credential remediation.

**Residual Risk:** Medium:

**1 × 5 = 5**

Task 6 modeled residual ALE as:

**($250,000 × 0.03) + ($3,000,000 × 0.006)**

**= $7,500 + $18,000**

**= $25,500/year**

**KRI:** Any default device credential detected; any unauthorized source reaching a medical-device management interface; abnormal device traffic; failed clinical workflow after a security change.

**Review Date:** 2026-10-21

---

## RISK-009

**Risk ID:** RISK-009

**Risk Description:** Compromise of the unsupported MRI workstation or PACS pathway results in imaging disruption, image integrity loss, or inability to recover diagnostic imaging services.

**Risk Category:** Operational

**Threat Source:** TA-2 Nation-State/sophisticated supply-chain actor; TA-1 Ransomware Groups; TA-6 Opportunistic Attacker

**Vulnerability:** Finding 004 — Windows XP MRI with weaponized vulnerabilities; Finding 024 — unencrypted DICOM

**Affected Asset(s):** AST-034 `WS-RAD-01` MRI workstation; AST-003 `pacs-srv-01`; AST-018 PACS application and imaging repository

**Likelihood:** 3 — Possible because the MRI exposes mature remote exploits and cannot be conventionally upgraded without affecting certification.

**Impact:** 5 — Severe/Catastrophic because diagnostic imaging integrity and availability directly support clinical care.

**Inherent Risk Score:**

**3 × 5 = 15**

**ALE:** Not yet quantified; the prior project establishes Critical clinical consequence but does not provide a defensible monetary loss model for PACS/MRI outage or image-integrity failure.

**Risk Owner:** Radiology Department Head, with Sarah Park as technical custodian

**Treatment Decision:** Mitigate

**Treatment Justification:** The clinical service cannot simply be avoided, so MedDefense must use compensating isolation and monitoring around the unpatchable platform.

**Planned Control(s):** Network segmentation; Wazuh SIEM.

**Residual Risk:** Medium-High:

**2 × 5 = 10**

because segmentation reduces reachability but the unsupported certified workstation remains a persistent vulnerability.

**KRI:** Any MRI/PACS traffic outside the approved allowlist; RDP/SMB exposure from general user segments; failed PACS restore test; unauthorized DICOM destination.

**Review Date:** 2026-10-21

---

## RISK-010

**Risk ID:** RISK-010

**Risk Description:** Compromise of the Westside consumer perimeter or unmanaged Westside host provides a trusted path into Central and becomes an alternative ransomware entry point.

**Risk Category:** Operational

**Threat Source:** TA-6 Opportunistic Attacker; TA-1 Ransomware Groups

**Vulnerability:** Finding 014 — consumer-grade Westside router; Finding 029 — undocumented vulnerable Grafana host at Westside

**Affected Asset(s):** AST-047 Westside Netgear Nighthawk router; AST-014 Westside unknown Linux device; AST-012 Westside server; Central systems reachable through site-to-site VPN trust

**Likelihood:** 3 — Possible because the perimeter is consumer-grade and an undocumented vulnerable Linux/Grafana system exists inside the site.

**Impact:** 4 — Major because Westside compromise can provide a route into Central rather than remaining a local clinic event.

**Inherent Risk Score:**

**3 × 4 = 12**

**ALE:** Not separately quantified because Westside is modeled as one contributor to enterprise ransomware. Task 7 uses a conservative 5% contribution:

**$2,864,400 × 0.05 = $143,220/year**

of modeled avoidable ransomware exposure.

**Risk Owner:** Sarah Park, IT Director

**Treatment Decision:** Mitigate

**Treatment Justification:** The trusted site-to-site relationship means a weak branch perimeter can undermine stronger controls at Central.

**Planned Control(s):** Dedicated Westside firewall; network segmentation; Wazuh SIEM.

**Residual Risk:** Medium:

**2 × 4 = 8**

after enterprise firewall replacement, stronger ACLs, centralized logging, and disposition of undocumented systems.

**KRI:** Any unsupported or unmanaged Westside perimeter device; VPN configuration drift; unknown hosts on the Westside trusted segment; unauthorized Westside-to-Central traffic.

**Review Date:** 2026-10-21

---

# Risk Register Summary

| Risk ID | Short Name | Inherent Score | ALE | Treatment | Residual Risk |
|---|---|---:|---:|---|---:|
| RISK-001 | Enterprise ransomware | **3 × 5 = 15** | **$9,548,000 × 0.30 = $2,864,400/year** | Mitigate | **2 × 4 = 8** |
| RISK-002 | EHR PHI breach | **3 × 5 = 15** | **$9,075,000 ÷ 3 = $3,025,000/year** | Mitigate | **2 × 5 = 10** |
| RISK-003 | Active Directory compromise | **4 × 5 = 20** | Included in RISK-001 | Mitigate | **2 × 5 = 10** |
| RISK-004 | Undetected intrusion | **4 × 4 = 16** | Included in RISK-001; SIEM reduction model **$2,864,400 − $1,861,860 = $1,002,540/year** | Mitigate | **2 × 4 = 8** |
| RISK-005 | Exploitation of known vulnerabilities | **4 × 5 = 20** | Billing subset **$473,000 ÷ 3.5 ≈ $135,143/year** | Mitigate | **2 × 5 = 10** |
| RISK-006 | Insider PHI exfiltration | **5 × 3 = 15** | **$120,000 × 2.5 = $300,000/year** | Mitigate | **4 × 3 = 12** |
| RISK-007 | Backup destruction | **3 × 5 = 15** | Recovery proxy **$135,143/year → $60,543/year** | Mitigate | **2 × 4 = 8** |
| RISK-008 | Medical-device compromise | **2 × 5 = 10** | **$25,000 + $60,000 = $85,000/year** | Mitigate | **1 × 5 = 5** |
| RISK-009 | PACS/MRI compromise | **3 × 5 = 15** | Not yet quantified | Mitigate | **2 × 5 = 10** |
| RISK-010 | Westside trusted-path compromise | **3 × 4 = 12** | Embedded in RISK-001; modeled contribution **$2,864,400 × 0.05 = $143,220/year** | Mitigate | **2 × 4 = 8** |

**Important ALE note:** The ALE figures above must not be summed into one enterprise total because several risks are attack stages or pathways inside the same enterprise-ransomware loss scenario. For example, RISK-003, RISK-004, RISK-007, and RISK-010 overlap with RISK-001.

# Risk Register Governance Note

The **Security Analyst** maintains the working Risk Register and supporting evidence, while **James Chen, Deputy CISO**, is accountable for ensuring that entries are complete, assigned, reviewed, and escalated; individual Risk Owners are responsible for treatment execution and status updates within their domains. The register is reviewed **monthly**, so a register dated **2026-09-21** has its next scheduled review on **2026-10-21** because **2026-09-21 + 1 month = 2026-10-21**. An out-of-cycle review is triggered by a material incident, a new Critical vulnerability affecting a MedDefense asset, a significant change in threat intelligence, deployment failure of a planned control, a major architecture/vendor change, or evidence that an ALE or risk assumption is no longer valid. When a KRI threshold is breached, the Security Analyst records the breach, validates the evidence, and immediately escalates it to James and the named Risk Owner; the owner must define corrective action or formally request risk acceptance, and any material residual risk requiring acceptance is escalated to the CEO under the MedDefense governance model rather than being accepted unilaterally by Security or IT.
