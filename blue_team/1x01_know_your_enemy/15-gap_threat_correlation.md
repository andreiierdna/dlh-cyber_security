# MedDefense Health Systems

## Gap-Threat Correlation

### 1. Threat Reference Key

**Threat actors from T6**

* TA-1 — Ransomware Groups (Organized Crime)
* TA-2 — Nation-State APT
* TA-3 — Insider (Malicious)
* TA-4 — Insider (Negligent)
* TA-5 — Hacktivist
* TA-6 — Unskilled/Opportunistic Attacker

T6 ranks ransomware as the most significant actor because MedDefense's flat network, weak centralized detection, password-based identity, non-isolated backups, known vulnerable systems, and prior compromises closely match the ransomware operating model. Negligent and malicious insiders rank second and third respectively.

**T10 kill chains**

* **KC-1:** FortiGate VPN Exploitation → EHR Database Compromise
* **KC-2:** Spear Phishing → Active Directory / Enterprise Privilege
* **KC-3:** Compromised PACS/MRI Supply Chain → Imaging Integrity Loss
* **KC-4:** Phished IT Administrator → Backup Destruction
* **KC-5:** Malicious Privileged Insider → Network-Core Control

**T14 scenarios**

* **S-1:** Operation Flatline — FortiGate-to-EHR Double Extortion
* **S-2:** The Quiet Departure — Billing Insider PHI Exfiltration
* **S-3:** Trusted Path — MedTech Solutions Maintenance Account Compromise

---

# 2. Full Gap-Threat Correlation

| Gap         | Gap Description                                                                          | Original Risk | Threat Actors                                                                                          | Kill Chains                                                             | Scenarios                              | Threat-Informed Rating | Movement         |
| ----------- | ---------------------------------------------------------------------------------------- | ------------: | ------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------- | -------------------------------------- | ---------------------: | ---------------- |
| **GAP-001** | PACS has no evidenced recovery capability.                                               |      Critical | TA-1 Ransomware; TA-2 Nation-State/sophisticated supply-chain actor; TA-4 Negligent Insider            | **KC-3**                                                                | None directly                          |           **Critical** | Same             |
| **GAP-002** | Medical IoT is not adequately segmented, monitored, or recoverable.                      |      Critical | TA-1 Ransomware; TA-6 Opportunistic attacker after internal foothold                                   | No dedicated T10 device chain; cross-chain segmentation finding applies | **S-1** downstream blast radius        |           **Critical** | Same             |
| **GAP-003** | Network core exposed to unauthorized administration and insufficient internal isolation. |      Critical | TA-1 Ransomware; TA-2 Nation-State; TA-3 Malicious Insider; TA-4 Negligent Insider; TA-6 Opportunistic | **KC-1, KC-2, KC-3, KC-4, KC-5**                                        | **S-1, S-3**                           |           **Critical** | Same             |
| **GAP-004** | Production and backup copies share the same failure domain.                              |      Critical | TA-1 Ransomware; TA-3 Malicious Insider/saboteur                                                       | **KC-4**                                                                | **S-1**                                |           **Critical** | Same             |
| **GAP-005** | Personal Cardiology NAS operates outside enterprise controls.                            |      Critical | TA-4 Negligent Insider; external actors could exploit it only after gaining internal access            | None                                                                    | None                                   |               **High** | **Downgraded ↓** |
| **GAP-006** | EHR database reachable from more systems than operationally required.                    |          High | TA-1 Ransomware; TA-2 Nation-State APT                                                                 | **KC-1**                                                                | **S-1, S-3**                           |           **Critical** | **Upgraded ↑**   |
| **GAP-007** | Active Directory relies on passwords without mandatory MFA or centralized alerting.      |          High | TA-1 Ransomware; TA-2 Nation-State; TA-3 Malicious Insider; TA-4 Negligent Insider; TA-6 Opportunistic | **KC-1, KC-2, KC-4**                                                    | **S-1, S-2, S-3**                      |           **Critical** | **Upgraded ↑**   |
| **GAP-008** | Billing server lacks server-class malware protection and effective egress restriction.   |          High | TA-1 Ransomware; TA-3 Malicious Insider; TA-6 Opportunistic                                            | No T10 chain depends on it                                              | **S-1, S-2**                           |               **High** | Same             |
| **GAP-009** | HR/administrative access lacks adequate segmentation and strong authentication.          |          High | TA-3 Malicious Insider; TA-4 Negligent Insider; TA-1 Ransomware as a secondary lateral target          | None                                                                    | None                                   |               **High** | Same             |
| **GAP-010** | Marketing data controlled through a personal Google account.                             |          High | Primarily TA-4 Negligent Insider; TA-3 malicious account misuse is possible                            | None                                                                    | None                                   |             **Medium** | **Downgraded ↓** |
| **GAP-011** | No evidenced enterprise vulnerability and patch-management program.                      |      Critical | TA-1 Ransomware; TA-2 Nation-State; TA-5 Hacktivist; TA-6 Opportunistic                                | **KC-1; KC-3** legacy-vulnerability component                           | **S-1**                                |           **Critical** | Same             |
| **GAP-012** | No formal enterprise incident-response and recovery-coordination process.                |      Critical | TA-1 Ransomware; TA-5 Hacktivist; TA-3 destructive insider                                             | Not an initial-access dependency                                        | **S-1** consequence/recovery amplifier |           **Critical** | Same             |
| **GAP-013** | User offboarding is not automated or HR-integrated.                                      |          High | TA-3 Malicious Insider; TA-1 Ransomware/credential-abuse actor                                         | None                                                                    | **S-2**                                |               **High** | Same             |
| **GAP-014** | No evidenced DLP for bulk Restricted-data extraction.                                    |          High | TA-1 Ransomware; TA-2 Nation-State; TA-3 Malicious Insider                                             | None                                                                    | **S-1, S-2, S-3**                      |           **Critical** | **Upgraded ↑**   |
| **GAP-015** | Medical-device administrative credentials are not centrally governed.                    |      Critical | TA-6 Opportunistic; TA-1 Ransomware after lateral access                                               | None directly                                                           | None directly                          |           **Critical** | Same             |
| **GAP-016** | No centralized security monitoring or log correlation.                                   |      Critical | TA-1 Ransomware; TA-2 Nation-State; TA-3 Malicious Insider; TA-5 Hacktivist; TA-6 Opportunistic        | **KC-1, KC-2, KC-3, KC-4, KC-5**                                        | **S-1, S-2, S-3**                      |           **Critical** | Same             |
| **GAP-017** | Westside Clinic security undermines Central protections.                                 |          High | TA-6 Opportunistic; TA-1 Ransomware                                                                    | None explicitly                                                         | None explicitly                        |               **High** | Same             |
| **GAP-018** | No formal change-management process.                                                     |          High | TA-3 Malicious Insider; TA-4 Negligent Insider                                                         | **KC-5**                                                                | None                                   |               **High** | Same             |

---

## 2.1 GAP-001 — PACS Has No Evidenced Recovery Capability

**Justification:** The threat analysis validates the Critical rating. KC-3 specifically targets `pacs-srv-01` and `WS-RAD-01`, with the objective of deleting, encrypting, replacing, or manipulating diagnostic images. The chain identifies approximately 45 MRI studies per day as exposed and explicitly identifies the lack of PACS recovery as a break-point failure.
The threat evidence changes the interpretation of this gap from a generic backup deficiency to a **destructive clinical-system failure point**. An actor does not need to compromise the entire enterprise. Compromise of the PACS/vendor pathway alone could leave MedDefense unable to establish that diagnostic images are intact or recover the repository rapidly. Because PACS is a Critical clinical asset containing Restricted imaging data, the rating remains Critical.

## 2.2 GAP-002 — Medical IoT Is Not Adequately Segmented, Monitored, or Recoverable

**Justification:** T6 directly identifies poor medical-device segmentation as an expansion mechanism for ransomware. S-1 also identifies Medical IoT as part of the downstream blast radius once BlackReef gains control of the internal environment.
The five T10 chains do not contain a dedicated Medical-IoT objective, so GAP-002 is not one of the three highest-frequency attack-chain gaps. It remains Critical because the Criticality Matrix establishes that patient monitors, infusion pumps, and nurse-call systems directly support patient treatment, meaning integrity or availability compromise can become a patient-safety event.

## 2.3 GAP-003 — Network-Core and Internal Isolation Weakness

**Justification:** This is one of the strongest correlations in the entire project. GAP-003 intersects **all five kill chains**. KC-1 uses the flat network to move from FortiGate to EHR; KC-2 uses it to reach domain controllers; KC-3 uses it to move from Radiology into PACS; KC-4 uses it to reach backup-management infrastructure; and KC-5 directly targets the FortiGate/Cisco control plane itself.

T10 explicitly concludes that segmentation interrupts Kill Chains 1 through 4 after initial access has already succeeded. KC-5 then demonstrates why compromise of the Network Core is itself a force multiplier: changes to FortiGate or Cisco configuration can affect EHR, PACS, AD, Medical IoT, Westside, and HQ simultaneously.

S-1 relies on this condition when the FortiGate foothold becomes an enterprise compromise; S-3 explicitly lists GAP-003 because MedTech's authorized EHR pathway provides proximity to systems outside the vendor's legitimate maintenance scope.

The rating remains Critical and GAP-003 moves to **#2 overall**.

## 2.4 GAP-004 — Production and Backup Copies Share the Same Failure Domain

**Justification:** KC-4 is built around this gap. A phished administrator can move through the same production network to `backup-srv-01` and `NAS-01`, manipulate backup jobs, and destroy recovery data before ransomware is deployed.

S-1 reproduces the same sequence: BlackReef reaches the backup environment, removes recovery points, deletes shadow copies, and interferes with backup jobs before encrypting production.

The Data Map finding that Restricted recovery copies reside in the same production failure domain therefore sits directly on the Rank-1 ransomware kill chain. GAP-004 remains Critical.

## 2.5 GAP-005 — Personal Cardiology NAS Outside Enterprise Controls

**Updated Rating: High — Downgraded from Critical.**

**Justification:** The original Critical rating was driven by potentially Restricted research/clinical information and the possibility that AST-057 could become an unmanaged lateral-movement foothold. That remains a serious posture problem. However, none of the five T10 kill chains and none of the three T14 scenarios depends on AST-057.

T6 directly links the NAS to negligent insider behavior, but the modeled ransomware, APT, malicious-insider, and opportunistic attack paths do not select it as an entry point or required pivot.

Threat analysis therefore reduces **urgency**, not the need for remediation. The NAS should still be removed or brought under enterprise control, but it should not outrank controls that interrupt multiple demonstrated paths into EHR, AD, backups, and network infrastructure.

## 2.6 GAP-006 — Excessive Reachability of `ehr-db-01`

**Updated Rating: Critical — Upgraded from High.**

**Justification:** The original Gap Analysis rated GAP-006 High because EHR already has detective logging and backup coverage. Threat analysis changes the conclusion because excessive PostgreSQL reachability is no longer merely an architectural imperfection: it is a **direct objective-stage enabler in multiple high-consequence attacks**.

KC-1 explicitly moves from the FortiGate foothold to `ehr-db-01:5432`. S-1 then models BlackReef exporting approximately 35 GB of EHR information before encryption, while S-3 uses the compromised MedTech pathway to connect directly from the EHR environment to `ehr-db-01`.
The threat actors are also materially different: ransomware seeks PHI plus availability leverage; a Nation-State APT seeks long-term intelligence. The same network-access defect supports both objectives against MedDefense's highest-priority asset. GAP-006 is therefore upgraded to Critical.

## 2.7 GAP-007 — AD Password Dependence / Missing MFA and Centralized Alerting

**Updated Rating: Critical — Upgraded from High.**

**Justification:** GAP-007 has the third-highest attack-path concentration in the register.

It affects KC-1 when credentials harvested after VPN compromise are converted into privileged access; it is the central weakness in KC-2; and it is directly exploited in KC-4 when a phished administrator identity is used to reach recovery infrastructure. T10 explicitly states that Kill Chains 2 and 4 show how stolen passwords can become enterprise-level access when MFA is absent.

More importantly, GAP-007 appears in **all three T14 scenarios**. BlackReef uses reusable privileged authentication to compromise `ad-dc-01`; the terminated billing employee's still-valid password remains usable; and the MedTech-originated APT converts harvested authentication material into persistent AD authority.
T6 also connects GAP-007 to ransomware, Nation-State APTs, malicious insiders, negligent insiders, and opportunistic credential attackers. Because Active Directory is a Critical enterprise trust dependency, the original High rating understates its threat-chain leverage. GAP-007 is upgraded to Critical.

## 2.8 GAP-008 — Billing Server Detection and Egress Deficiency

**Justification:** The rating remains High, but the gap moves toward the top of the High tier. `billing-srv-01` has already suffered ransomware and later cryptomining, demonstrating actual rather than theoretical exploitability.

S-1 identifies it as an additional weak staging or command-and-control host during ransomware, while S-2 shows how reusable billing credentials compound the insider-exfiltration scenario.
It does not, however, constitute a mandatory stage in any of the five T10 kill chains. An attacker can compromise AD, EHR, backups, or PACS without using the billing server. High therefore remains appropriate.

## 2.9 GAP-009 — HR and Administrative Segmentation / Authentication

**Justification:** GAP-009 remains High. HR and payroll information is Restricted, and malicious or negligent insiders can abuse excessive access while ransomware operators could target the environment after gaining enterprise credentials.

However, none of the five T10 chains and none of the T14 scenarios requires GAP-009. Threat evidence therefore does not justify an upgrade. It should remain below identity, EHR, DLP, backup, and segmentation weaknesses that repeatedly appear in modeled attacks.

## 2.10 GAP-010 — Marketing Data in a Personal Google Account

**Updated Rating: Medium — Downgraded from High.**

**Justification:** The original issue remains valid: MedDefense does not control the personal account's authentication, lifecycle, sharing configuration, audit history, or recovery.

The threat analysis materially reduces urgency. No T10 kill chain passes through AST-058 and no T14 scenario depends on the Marketing account. T6 principally associates the condition with negligent insider behavior rather than the Rank-1 ransomware, APT, or malicious-insider attack paths.

The underlying data is also classified as Confidential unless a later review discovers patient information. GAP-010 should still be remediated through enterprise migration, but its threat-informed priority is Medium.

## 2.11 GAP-011 — Vulnerability and Patch Management

**Justification:** GAP-011 remains Critical and becomes one of the highest-priority initial-access controls.

S-1 begins when BlackReef exploits an unremediated vulnerability in AST-043, the single FortiGate/VPN termination point. KC-1 identifies disciplined perimeter vulnerability management and rapid FortiGate security updates as the first defensive break point.

KC-3 adds the legacy-vulnerability-management dimension through the Windows XP SP3 Radiology workstation. This does not mean the unsupported platform can simply be patched; rather, a mature vulnerability program must identify the exception and enforce compensating isolation around it.

T6 associates GAP-011 with ransomware, Nation-State APTs, hacktivists, and opportunistic attackers. It therefore protects against more initial-access actor classes than any gap except GAP-016.

## 2.12 GAP-012 — Incident Response and Recovery Coordination

**Justification:** GAP-012 remains Critical even though no T10 chain uses the absence of an incident-response plan as a technical exploitation step.

The reason is consequence amplification. Once a Rank-1 ransomware intrusion reaches EHR, AD, backups, and endpoints, lack of defined containment authority, recovery sequencing, evidence preservation, communications, and credential-reset procedures can convert a technically recoverable event into a prolonged clinical outage.

T6 explicitly identifies incomplete response coordination as a factor that can extend a ransomware outage and likewise notes it for disruptive hacktivist activity. S-1 is therefore treated as an **impact/recovery dependency**, rather than an initial-access dependency.

## 2.13 GAP-013 — Identity Lifecycle and Offboarding

**Justification:** GAP-013 remains High but moves above lower-frequency High findings.

S-2 directly demonstrates the weakness. After termination, Maria's VPN access remains technically valid; three days later she reconnects and extracts another 400 billing records, bringing the scenario total to approximately 3,200 records.

The scenario is especially important because firewalling and password-strength controls do not solve the problem: the credential remains technically correct but organizationally unauthorized. T6 therefore identifies stale legitimate accounts as an important malicious-insider vector. The gap remains High because only one of the three formal scenarios depends on it and none of the five kill chains is specifically an offboarding chain.

## 2.14 GAP-014 — DLP for Bulk Restricted-Data Extraction

**Updated Rating: Critical — Upgraded from High.**

**Justification:** Threat analysis substantially changes the importance of GAP-014.

S-2 depends directly on the absence of DLP: an authorized billing employee exports hundreds of patient records per day and transfers approximately 2,800 records to personal removable media before further post-termination theft.

S-3 also lists GAP-014 because a Nation-State actor using the trusted MedTech pathway can collect and exfiltrate EHR information through encrypted outbound traffic. S-1's STRIDE analysis separately associates bulk EHR disclosure with GAP-014 even though the abbreviated "Gaps Exploited" list emphasizes the broader ransomware chain.

The significant change is that **every T14 actor has a confidentiality objective**: ransomware operators steal before encrypting, malicious insiders steal patient information directly, and an APT's primary objective is covert collection. A control originally treated as a secondary protection against misuse therefore becomes a cross-scenario control protecting Restricted information from three different threat models. GAP-014 is upgraded to Critical.

## 2.15 GAP-015 — Medical-Device Credential Governance

**Justification:** GAP-015 remains Critical, although its current T10/T14 frequency is low.

The original Reality Check established that default or unmanaged device credentials can provide immediate administrative access once a device management interface is reachable. The affected assets are Critical clinical systems handling Restricted patient-associated information, and MedDefense lacks a fleet-wide credential baseline.

The current five kill chains and three scenarios do not use default medical-device credentials as a required step. This places GAP-015 below the Critical Three operationally. It remains Critical because compromise could affect device configuration, monitoring, or clinical availability and because the weakness has already been validated against a healthcare medical-device breach pattern.

## 2.16 GAP-016 — Centralized Security Monitoring and Log Correlation

**Justification:** GAP-016 is the **highest-priority threat-informed gap in MedDefense**.

It intersects **all five T10 kill chains**. T10 identifies observable behavior in every chain: VPN-originated scanning, unusual AD activity, unexpected PACS/vendor behavior, backup deletion, and unauthorized FortiGate/Cisco configuration changes. Centralized monitoring is therefore an independent break point regardless of how initial access occurs.

It also appears in **all three T14 scenarios**. BlackReef reconnaissance, credential abuse, exfiltration, and encryption remain disconnected across local logs; Maria's abnormal EHR exports are recorded but do not generate timely behavioral alerts; and the MedTech APT can manipulate local evidence because logs are not independently centralized.
The posture evidence also demonstrates that this failure has already occurred: cryptomining operated on `billing-srv-01` for at least two weeks and was discovered through performance degradation rather than a security alert.

The rating remains Critical because it was already at the highest level, but its **remediation position moves to #1**.

## 2.17 GAP-017 — Westside Clinic Security Undermines Central Protections

**Justification:** GAP-017 remains High. T6 explicitly identifies Westside's consumer-grade perimeter and trusted VPN path as an exposure relevant to opportunistic attackers.

No current T10 chain or T14 scenario begins at Westside, so there is insufficient threat evidence to upgrade the gap. Nevertheless, compromise of a consumer router or physically accessible equipment at Westside could provide an alternative trusted route into Central, so a downgrade would also be inappropriate.

## 2.18 GAP-018 — No Formal Change Management

**Justification:** GAP-018 remains High and is directly relevant to KC-5.

KC-5 models a privileged network administrator using legitimate access to alter firewall, VPN, switching, and routing configurations. Its principal defensive break point is controlled network change: independent approval, two-person review, version-controlled configuration, and rapid rollback.

T6 associates the gap with both malicious and negligent insiders. MedDefense also has internal evidence that an untested cron change previously produced a multi-week backup failure. The gap therefore remains High, but it does not reach Critical because only one kill chain and no T14 scenario directly depends on it.

---

# 3. Re-Prioritized Gap List

The following order ranks gaps first by their new threat-informed risk level and then by attack-path concentration, actor likelihood, Critical-asset exposure, and ability to break multiple attack stages.

|   Rank | Gap                                                        | Threat-Informed Rating | Kill Chains | Scenarios | Movement              | Priority Rationale                                                                                                                                                          |
| -----: | ---------------------------------------------------------- | ---------------------- | ----------: | --------: | --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|  **1** | **GAP-016 — Centralized monitoring/log correlation**       | **Critical**           |       **5** |     **3** | Same                  | Only gap intersecting every kill chain and every scenario; gives MedDefense an independent opportunity to stop progression regardless of entry vector.                      |
|  **2** | **GAP-003 — Network-core/internal isolation**              | **Critical**           |       **5** |     **2** | Same                  | Converts isolated initial compromises into enterprise incidents; segmentation is explicitly the highest-leverage T10 preventive control.                                    |
|  **3** | **GAP-007 — MFA/AD identity protection**                   | **Critical**           |       **3** |     **3** | **↑ High → Critical** | Stolen or retained passwords become enterprise authority across ransomware, insider, and vendor-compromise scenarios.                                                       |
|  **4** | **GAP-011 — Vulnerability/patch management**               | **Critical**           |       **2** |     **1** | Same                  | Directly breaks the FortiGate initial-access path used by Rank-1 ransomware and also reduces opportunistic public-service exploitation.                                     |
|  **5** | **GAP-006 — EHR database reachability**                    | **Critical**           |       **1** |     **2** | **↑ High → Critical** | Directly exposes Restricted PHI in both ransomware and APT paths; `ehr-db-01:5432` becomes reachable after unrelated footholds.                                             |
|  **6** | **GAP-014 — DLP / bulk Restricted-data extraction**        | **Critical**           |       **0** |     **3** | **↑ High → Critical** | Data theft is common to all three scenario objectives despite different actor types and entry methods.                                                                      |
|  **7** | **GAP-004 — Backup failure-domain isolation**              | **Critical**           |       **1** |     **1** | Same                  | Enables BlackReef and KC-4 to remove recovery before encryption, turning a security incident into prolonged clinical downtime.                                              |
|  **8** | **GAP-002 — Medical IoT segmentation/monitoring/recovery** | **Critical**           |       **0** |     **1** | Same                  | Lower frequency than the Critical Three but uniquely carries patient-safety consequences if ransomware reaches bedside systems.                                             |
|  **9** | **GAP-001 — PACS recovery**                                | **Critical**           |       **1** |     **0** | Same                  | Directly determines recoverability of the PACS/MRI destructive supply-chain chain affecting approximately 45 MRI studies per day.                                           |
| **10** | **GAP-012 — Incident response coordination**               | **Critical**           |       **0** |    **1*** | Same                  | Not an initial-access enabler, but materially determines containment and recovery duration in enterprise ransomware.                                                        |
| **11** | **GAP-015 — Medical-device credential governance**         | **Critical**           |       **0** |     **0** | Same                  | Low current model frequency but Critical clinical consequence and direct validation from the medical-device breach analysis.                                                |
| **12** | **GAP-008 — Billing server EDR/egress**                    | **High**               |       **0** |     **2** | Same                  | Demonstrated compromise history and relevance to two scenarios, but not a mandatory attack-chain dependency.                                                                |
| **13** | **GAP-018 — Change management**                            | **High**               |       **1** |     **0** | Same                  | Important break point against malicious or negligent privileged infrastructure changes in KC-5.                                                                             |
| **14** | **GAP-013 — Offboarding**                                  | **High**               |       **0** |     **1** | Same                  | Directly permits post-termination access in S-2; high insider relevance but limited cross-chain concentration.                                                              |
| **15** | **GAP-017 — Westside perimeter/VPN trust**                 | **High**               |       **0** |     **0** | Same                  | Credible alternative entry path for opportunistic or ransomware actors, but not used by the current kill chains or scenarios.                                               |
| **16** | **GAP-009 — HR/admin access controls**                     | **High**               |       **0** |     **0** | Same                  | Restricted HR/payroll exposure remains significant but does not currently sit on a modeled primary attack path.                                                             |
| **17** | **GAP-005 — Cardiology personal NAS**                      | **High**               |       **0** |     **0** | **↓ Critical → High** | Serious unmanaged foothold, but no current kill chain or scenario requires AST-057.                                                                                         |
| **18** | **GAP-010 — Personal Marketing Google account**            | **Medium**             |       **0** |     **0** | **↓ High → Medium**   | Governance issue remains valid, but current threat actors, kill chains, and scenarios show substantially lower attack-chain leverage than clinical and infrastructure gaps. |

*S-1 correlation for GAP-012 is an **impact/recovery dependency**, not a technical exploitation prerequisite.

---

# 4. The Critical Three

## #1 — GAP-016: No Centralized Security Monitoring or Log Correlation

**Frequency:** 5 of 5 kill chains + 3 of 3 scenarios = **8 correlations**

This is the widest-reaching gap in MedDefense. VPN exploitation, phishing, compromised vendor software, backup sabotage, malicious network changes, ransomware exfiltration, insider exports, and APT persistence all generate observable activity. MedDefense's weakness is that the evidence remains separated in firewall, EHR, operating-system, identity, and application logs.

Closing GAP-016 would not guarantee prevention of initial access, but it would provide a detection and containment opportunity in **every attack path modeled in T10 and T14**.

## #2 — GAP-003: Network-Core Protection and Internal Isolation

**Frequency:** 5 of 5 kill chains + 2 of 3 scenarios = **7 correlations**

The Criticality Matrix already identified the Network Core as a Critical common dependency. Threat analysis shows that the same architecture is also the principal **attack multiplier**.

A FortiGate exploit should compromise a gateway, not the EHR database. A phished workstation should compromise a workstation, not both domain controllers. A compromised Radiology system should not gain broad internal reach. A phished administrator workstation should not automatically reach backup-management interfaces.

Segmentation closes these paths after initial access has already occurred, making GAP-003 the highest-leverage preventive gap.

## #3 — GAP-007: Active Directory MFA and Identity Protection

**Frequency:** 3 of 5 kill chains + 3 of 3 scenarios = **6 correlations**

GAP-007 converts credentials into enterprise authority.

BlackReef uses harvested authentication material to control AD and distribute ransomware. The insider scenario shows that a technically valid password remains useful even after employment ends. The MedTech scenario shows a trusted third-party foothold being converted into independent privileged persistence.

Because Active Directory is already rated Critical by the Criticality Matrix and provides authentication authority across clinical and administrative environments, closure of GAP-007 breaks ransomware, insider, and third-party attack progression simultaneously.

---

# 5. The Surprise

### Source Constraint

The requested instruction calls for a gap originally rated **Medium or Low** that should now be upgraded. The authoritative 1x00 numbered register does not contain such a gap. The consolidated Security Posture Assessment explicitly records **9 Critical, 9 High, and 0 Medium numbered gaps**. It separately states that the shared Radiology `raduser` credential remains a **Medium subsidiary finding**, while the unsupported Windows Server 2012 R2 print server remains a lower-priority vulnerability-management issue.

Inventing a Medium/Low `GAP-xxx` solely to satisfy the format would break traceability to the prior project.

### Threat-Informed Surprise — Shared Radiology `raduser/radiology1` Credential

**Original posture treatment:** Medium subsidiary finding incorporated into the broader PACS finding rather than assigned a separate GAP ID.

**Threat-informed treatment:** **Upgrade to High remediation priority as a tracked PACS identity/accountability finding.**

**What changed:** T6 ranks the **Negligent Insider as MedDefense's #2 threat actor** and specifically identifies the shared Radiology account as a demonstrated MedDefense behavior affecting PACS/MRI. T6 identifies PACS/MRI as the negligent insider's primary Critical target and notes that the shared identity weakens accountability.

KC-3 then establishes that the PACS/MRI environment is a realistic Critical-asset attack path involving `pacs-srv-01`, `WS-RAD-01`, Restricted diagnostic imaging, and approximately 45 MRI studies per day.

The new understanding is therefore that `raduser/radiology1` is not merely an audit-quality problem. In an under-protected PACS environment, a shared credential makes malicious or compromised activity harder to attribute, weakens behavioral baselining, complicates incident containment, and makes credential revocation more disruptive because multiple users depend on the same identity.

The finding should therefore be elevated from **Medium to High remediation priority**, but it should **not be assigned an invented GAP ID** unless the formal Gap Analysis is subsequently revised.

The unsupported print-server finding does **not** receive the same upgrade because none of the five kill chains or three threat scenarios depends on that system.

---

# 6. Management Conclusion

The threat analysis materially changes the remediation order even where the underlying technical facts have not changed.

The most important finding is concentration. MedDefense does not face eighteen independent security problems. A relatively small group of weaknesses repeatedly enables different actors to traverse the same Critical environment.

**GAP-016, GAP-003, and GAP-007 account for the highest concentration of kill-chain and scenario dependencies.** Closing them would reduce attacker dwell time, constrain lateral movement, and prevent stolen credentials from being converted into enterprise control.

Three former High gaps warrant formal threat-informed escalation:

* **GAP-006: High → Critical** because unnecessary `ehr-db-01` reachability is used directly by both ransomware and Nation-State scenarios.
* **GAP-007: High → Critical** because password-centric AD appears across three kill chains and every T14 scenario.
* **GAP-014: High → Critical** because bulk data exfiltration is common to ransomware, malicious-insider, and APT objectives.

Two gaps move downward:

* **GAP-005: Critical → High** because AST-057 remains an unmanaged and potentially dangerous internal foothold but does not participate in any current T10 or T14 attack path.
* **GAP-010: High → Medium** because the personal Marketing account creates a governance and account-control problem but currently has minimal correlation to the actors and attack chains threatening MedDefense's Critical clinical environment.

The final threat-informed priority is therefore not simply "patch everything marked Critical." It is to close the weaknesses that repeatedly convert unrelated entry events into compromise of the same Critical assets:

**vulnerability or stolen credential → internal foothold → insufficient isolation → credential escalation → undetected access to Critical systems and Restricted data → compromised recovery → prolonged clinical impact.**
