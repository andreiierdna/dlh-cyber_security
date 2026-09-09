# The Three Threat Scenarios

## MedDefense Health System

# Scenario 1 — External: Operation Flatline — FortiGate-to-EHR Double Extortion

**Threat Actor:** Organized Crime / Ransomware-as-a-Service — **BlackReef**, aligned to **T6 Threat Actor Matrix #1: Ransomware Groups (Organized Crime), Rank 1**.

**Motivation:** **Financial gain.** BlackReef's operating model uses double extortion: patient and business information is stolen before encryption, after which the victim is pressured to pay both for restoration and to prevent publication of the stolen information. The BlackReef profile anticipates approximately $1–3 million ransom demands against a mid-sized hospital.

**Initial Vector:** **VPN Exploit — FortiGate 100F (AST-043).** This is one of the seven-asset vectors identified in the Vector-to-Asset Matrix. The matrix specifically maps a FortiGate VPN compromise to internal access, `ehr-db-01`, Active Directory, backup infrastructure, clinical endpoints, and medical devices.

**Attack Surface Exploited:** **External**, transitioning to the internal surface after compromise. The Attack Surface Map identifies AST-043 as MedDefense's single firewall and VPN termination point. VPN routes permit broad services, firewall logs are not centrally monitored, and compromise of a connected pathway is not adequately contained by internal segmentation.

## Attack Sequence

**Step 1 — BlackReef identifies MedDefense's FortiGate VPN — Reconnaissance.**
A BlackReef Initial Access Broker identifies the Internet-facing FortiGate 100F supporting MedDefense's remote and intersite connectivity. BlackReef's established model includes purchasing access or targeting data generated from exposed VPN infrastructure. MedDefense is particularly attractive because AST-043 is not a peripheral appliance; it is the single VPN termination point protecting access to Critical clinical and identity infrastructure.

**Step 2 — The attacker exploits the FortiGate VPN service — Initial Access.**
The affiliate exploits an unremediated FortiGate vulnerability and establishes an internal foothold through AST-043. This directly activates the vulnerability-management exposure previously associated with **GAP-011**. Once the gateway is compromised, the attacker is positioned behind the perimeter rather than limited to attacking a single Internet-facing application.

The existing Kill Chain already establishes that VPN exploitation provides a route from AST-043 to an environment in which the EHR and other internal services are broadly reachable.

**Step 3 — BlackReef enumerates the `10.10.0.0/16` environment — Discovery.**
From the VPN foothold, the affiliate conducts host and service discovery and identifies:

* `ad-dc-01` / `ad-dc-02` — AST-005 / AST-006;
* `ehr-srv-01` — AST-001;
* `ehr-db-01` — AST-002;
* `billing-srv-01` — AST-004;
* `backup-srv-01` — AST-009;
* `NAS-01` — AST-010; and
* other reachable clinical infrastructure.

This is the architectural conversion point in the scenario: the external exploit becomes an enterprise incident because the internal environment does not provide sufficient containment.

**Step 4 — BlackReef obtains reusable privileged authentication material — Credential Access.**
The affiliate targets privileged and service credentials on reachable administrative systems. BlackReef's documented playbook specifically includes Mimikatz and LSASS credential dumping and deliberately seeks Domain Administrator credentials. The existing T13 scenario demonstrated the consequence using the privileged `svc_backup` NTLM hash recovered from workstation memory.

**Step 5 — The attacker compromises `ad-dc-01` — Lateral Movement / Privilege Escalation.**
The harvested privileged authentication material is reused against `ad-dc-01`. Control of a Domain Administrator-level identity converts the attack from individual-host compromise into enterprise identity compromise. **GAP-007** is decisive at this stage because Active Directory lacks mandatory MFA and centralized automated alerting. The Criticality Matrix rates Active Directory Critical because compromise permits account creation, privilege changes, credential resets, policy manipulation, and persistent enterprise access.

**Step 6 — BlackReef extracts Restricted EHR and administrative data — Collection / Exfiltration.**
Using domain-level authority and the flat network, the attacker accesses `ehr-db-01:5432`, exports EHR information, stages the information, and transfers it externally. The established ATT&CK scenario models approximately **35 GB of EHR information and 8 GB of HR/financial information** leaving the environment without an alert.

This step directly exploits **GAP-006**. The Asset Registry and Data Map establish that `ehr-db-01` is reachable from the wider internal network rather than principally from `ehr-srv-01`, unnecessarily exposing the Restricted PHI repository to an attacker who has already gained an internal foothold.

**Step 7 — BlackReef destroys recovery options — Impact.**
Before encryption, the attacker reaches `backup-srv-01` and `NAS-01`, removes recovery points, deletes accessible shadow copies, and interferes with backup jobs. This directly activates **GAP-004 — Production and Backup Copies Share the Same Failure Domain**. NAS-01 contains Restricted backup copies of EHR, billing, Active Directory, file-share, and patient-portal information but has no isolated immutable or offsite recovery copy.

T13 maps this stage to **Inhibit System Recovery (T1490)**.

**Step 8 — BlackReef deploys ransomware through Active Directory — Impact.**
The attacker uses the compromised domain to distribute ransomware through Group Policy to reachable Windows systems and separately attacks accessible Linux servers. T13 maps the final encryption stage to **Data Encrypted for Impact (T1486)**, with malicious Group Policy modification supporting enterprise deployment.

`ehr-srv-01`, `ehr-db-01`, billing infrastructure, file services, workstations, and other accessible systems become unavailable. The EHR environment represents approximately **50,000 patient records**, and MedDefense has already demonstrated that even a nine-hour EHR outage forces clinicians back to paper workflows.

**Step 9 — BlackReef begins double extortion — Impact.**
MedDefense receives a ransom demand covering both decryption and non-publication of the stolen information. Even if some systems can eventually be rebuilt, restoration cannot reverse the PHI disclosure.

## STRIDE Categories Triggered

* **Spoofing — EHR-S1:** stolen or replayed legitimate credentials allow the attacker to operate as an authorized identity.
* **Tampering — EHR-T1:** privileged access to the EHR/database permits unauthorized modification or encryption of clinical information.
* **Information Disclosure — EHR-I1:** bulk Restricted PHI is extracted from `ehr-db-01`.
* **Denial of Service — EHR-D1:** ransomware removes clinical access to the EHR.
* **Elevation of Privilege — EHR-E1:** the attacker progresses from an initial foothold to privileged Active Directory and EHR access.

The STRIDE model specifically associates bulk EHR disclosure with **GAP-006, GAP-014, and GAP-016**.

## MedDefense Assets Impacted

* **AST-043 — FortiGate 100F**
* **AST-005 / AST-006 — `ad-dc-01` / `ad-dc-02`**
* **AST-001 — `ehr-srv-01`**
* **AST-002 — `ehr-db-01`**
* **AST-004 — `billing-srv-01`**
* **AST-009 — `backup-srv-01`**
* **AST-010 — `NAS-01`**
* Domain-joined clinical and administrative workstations
* Potential downstream PACS and medical-IoT systems because the internal network is insufficiently segmented

## Business Impact

**Clinical:** Loss of EHR access removes timely access to medication lists, allergies, diagnoses, orders, laboratory information, and patient histories. MedDefense's prior nine-hour outage already demonstrated the need to revert to paper records; ransomware combined with backup destruction could extend disruption substantially beyond that event.

**Financial:** MedDefense incurs incident-response, forensic, legal, restoration, overtime, system-rebuilding, lost-revenue, and potential extortion costs. BlackReef's profile anticipates a seven-figure ransom demand against an organization of this size.

**Regulatory:** Exfiltration of tens of thousands of patient records creates a reportable Restricted-PHI breach, forensic scoping requirements, breach notification obligations, and potential healthcare privacy enforcement.

**Reputational:** Patients, physicians, partner organizations, insurers, and the local community would see both loss of patient information and failure of clinical availability. Destruction of the hospital's recovery infrastructure would further demonstrate that the incident was not confined to a single infected endpoint.

## Gaps Exploited

* **GAP-011 — Vulnerability/Patch Management:** allows an exposed FortiGate vulnerability to remain exploitable.
* **GAP-007 — Active Directory Relies on Passwords Without Mandatory MFA or Centralized Alerting:** makes harvested privileged credentials sufficient for domain compromise.
* **GAP-006 — EHR Database Is Reachable from More Systems Than Operationally Required:** provides unnecessary direct network proximity to Restricted PHI.
* **GAP-004 — Production and Backup Copies Share the Same Failure Domain:** permits one compromised production environment to threaten both live services and their recovery copies.
* **GAP-008 — Billing Server Lacks Server Malware Protection and Effective Egress Restriction:** provides an additional weak staging/command-and-control host if the attacker pivots through billing infrastructure. The server has already suffered ransomware and cryptomining compromise.
* **GAP-016 — No Centralized Security Monitoring or Log Correlation:** allows reconnaissance, authentication anomalies, exfiltration, and destructive actions to remain disconnected in separate logs.
* **GAP-002 — Medical IoT Segmentation/Monitoring/Recovery:** increases the blast radius if ransomware or lateral movement reaches bedside technology.

The ransomware assessment already summarizes the core sequence as **GAP-008 → GAP-007 → GAP-006 → GAP-004**.

## Detection Opportunities

**Step 1–2:** External attack-surface monitoring, authenticated FortiGate vulnerability scanning, strict patch SLAs, IPS telemetry, appliance integrity monitoring, and centralized FortiGate logs could identify scanning or exploitation.

**Step 3:** East-west network monitoring and SIEM correlation could detect a VPN-originated host suddenly enumerating Active Directory, PostgreSQL, NAS management, and numerous internal systems.

**Step 4:** EDR on administrative endpoints should alert on LSASS access, Mimikatz-like behavior, credential dumping, unusual PowerShell, and suspicious service-account credential use.

**Step 5:** Identity analytics should immediately alert on privileged authentication from abnormal hosts, pass-the-hash indicators, Domain Admin use, new privileged accounts, and suspicious Group Policy changes.

**Step 6:** Database activity monitoring and DLP should detect bulk EHR exports, unusual `pg_dump` activity, archive creation, Rclone execution, and high-volume HTTPS transfer inconsistent with normal clinical operations.

**Step 7:** Backup infrastructure should generate independent alerts for mass deletion, retention changes, disabled jobs, repository administration, and shadow-copy deletion.

**Step 8:** Centralized endpoint and Active Directory monitoring should identify simultaneous encryption activity, malicious Group Policy deployment, mass file modification, and widespread endpoint communication before the campaign reaches full scale.

---

# Scenario 2 — Internal: The Quiet Departure — Billing Insider PHI Exfiltration

**Threat Actor:** **Malicious Insider — Billing Employee**, aligned to **T6 Threat Actor Matrix #3 / Rank 3: Insider (Malicious)** and the same legitimate-access misuse pattern documented in T3's malicious insider scenarios.

T6 rates malicious insiders Medium likelihood but High-to-Critical impact because they already possess organizational knowledge and legitimate access to Restricted information. The profile specifically cites incomplete offboarding, weak behavioral monitoring, limited DLP, and password-based authentication as MedDefense amplifiers.

**Motivation:** **Financial gain** for scenario-modeling purposes, consistent with the T6 malicious-insider motivation set. The source material also recognizes revenge, sabotage, and unauthorized curiosity as possible malicious-insider motives; the attack mechanics below do not depend on advanced technical skill.

**Initial Vector:** **Legitimate access abused — Valid Accounts.**

**Attack Surface Exploited:** **Internal / Human.** The insider begins from an authorized MedDefense billing workstation and normal application permissions. No perimeter bypass, malware exploit, or external foothold is required.

This scenario reflects the wider T3 conclusion that MedDefense's insider problem is not the existence of legitimate access itself, but the treatment of valid access as equivalent to legitimate use without adequate lifecycle, behavioral-monitoring, accountability, and DLP controls.

## Attack Sequence

**Step 1 — Maria uses her legitimate billing and read-only EHR account — Initial Access.**
Maria is an authorized billing employee with access to `billing-srv-01` and read-only EHR information. The EHR is Critical and holds Restricted PHI; the billing environment is High-rated and contains Restricted claims and patient financial information. ATT&CK maps this activity to **Valid Accounts (T1078)**.

**Step 2 — She determines the maximum information available through her normal permissions — Discovery.**
Maria tests her ordinary access and determines that it exposes names, dates of birth, insurance details, diagnoses, billing amounts, medical histories, and prescription information. She also determines that unusually high access volumes do not produce a real-time alert.

**Step 3 — She gradually exports EHR records into CSV files — Collection.**
Maria uses the legitimate EHR export capability to extract approximately **200 records per day**. Because export is available to users with read access and no secondary approval is required, the action is technically valid even though its purpose is malicious. The EHR logs the activity, but those logs are not proactively monitored. ATT&CK maps the collection to **Data from Information Repositories: Databases (T1213.006)**.

**Step 4 — She transfers 2,800 patient records to a personal USB device — Exfiltration.**
Over approximately two weeks, Maria moves the accumulated files to personally controlled removable media. MedDefense has no organization-wide USB restriction GPO, and the scenario records approximately **2,800 patient records** leaving the managed environment. ATT&CK maps the transfer to **Exfiltration Over Physical Medium: Exfiltration over USB (T1052.001)**.

**Step 5 — Maria deletes the staged CSV files — Defense Evasion.**
She deletes local copies and empties the Recycle Bin to reduce obvious evidence on her workstation. She cannot delete the separate EHR audit trail, but the value of that safeguard is reduced because EHR logs require a vendor export process and are not proactively correlated. ATT&CK maps this action to **Indicator Removal: File Deletion (T1070.004)**.

**Step 6 — She copies billing database credentials stored in a configuration file — Credential Access.**
Before leaving MedDefense, Maria discovers reusable billing database credentials in a workstation-accessible configuration file and copies them. ATT&CK maps the action to **Unsecured Credentials: Credentials In Files (T1552.001)**. The prior T13 analysis explicitly notes that this credential-storage weakness compounds the exposure of High-rated `billing-srv-01`, even though it was not assigned its own numbered gap.

**Step 7 — MedDefense fails to disable Maria's account promptly — Persistence.**
HR records the termination, but the associated identity-deactivation process is delayed. Her VPN access remains technically valid after employment has ended. This reproduces the lifecycle weakness documented in T3's **Ghost Account** scenario, where a contractor account remained active for 47 days after authorization ended. T3 identifies **GAP-013** as the absence of automated, HR-integrated account offboarding.

**Step 8 — Maria reconnects after termination and steals another 400 billing records — Initial Access / Collection.**
Three days after departure, Maria authenticates remotely using her still-active account and uses the previously copied database credentials to access `billing-srv-01`. She extracts another **400 patient records**, raising the scenario total to approximately **3,200 records**. ATT&CK maps the connection to **External Remote Services (T1133)** with **Valid Accounts (T1078)** also applicable.

## STRIDE Categories Triggered

* **Information Disclosure:** Restricted EHR, billing, insurance, diagnosis, prescription, and patient financial information is deliberately removed from MedDefense.
* **Repudiation:** Local evidence is deleted and centralized correlation is weak, increasing the difficulty of rapidly reconstructing and attributing the complete activity sequence.
* **Elevation of Privilege — EHR-E2:** once employment ends, Maria continues exercising capabilities that exceed her current organizational authorization because the account remains active.

The T3 assessment specifically identifies the combination of stale accounts, absent timely behavioral detection, and inability to control data movement as the systemic insider-risk problem.

## MedDefense Assets Impacted

* **AST-001 — `ehr-srv-01`**
* **AST-002 — `ehr-db-01`**
* EHR application / patient-record environment
* **AST-004 — `billing-srv-01`**
* **AST-019 — Billing Application**
* **AST-020 — Billing Database**
* Maria's managed workstation and removable-media interface
* VPN/identity services used after termination

## Business Impact

**Clinical:** The attack does not initially remove EHR availability or alter treatment records, so immediate clinical downtime is limited. However, the disclosed records include diagnoses, medical histories, and prescription information, creating direct patient-privacy harm and exposing highly sensitive clinical facts outside MedDefense's control.

**Financial:** MedDefense incurs forensic investigation, legal review, notification, privacy-response, credential-reset, identity-governance remediation, and potential fraud-related costs. Exposure of insurance and patient financial data increases the possibility of downstream identity or insurance fraud.

**Regulatory:** Approximately **3,200 patient records** leave authorized control. MedDefense must determine exactly which individuals and data elements were affected, assess reportability, document the privacy breach, and address why bulk exports, USB transfer, and post-termination access were not prevented.

**Reputational:** The incident would demonstrate that an employee could repeatedly extract patient information using approved application functionality and continue accessing the environment after termination. That is materially different from an isolated malware event because it calls MedDefense's internal governance of patient access into question.

## Gaps Exploited

* **GAP-014 — No Evidenced DLP for Bulk Restricted-Data Extraction:** allows high-volume patient information to be exported and transferred without automated prevention or alerting. The STRIDE model specifically identifies GAP-014 as a control weakness around bulk EHR extraction.
* **GAP-016 — No Centralized Security Monitoring or Log Correlation:** EHR audit records exist but do not become timely behavioral alerts. T3 identifies this as the principal gap allowing suspicious but technically valid EHR activity to remain unnoticed.
* **GAP-013 — Account Offboarding Is Not Automated or HR-Integrated:** allows the employee's technically valid VPN/account access to survive termination.
* **GAP-007 — Active Directory/Identity Relies on Passwords Without Mandatory MFA or Centralized Alerting:** means the still-valid password remains useful for remote access after termination.
* **GAP-008 — Billing Server Protection Deficiency:** the stored billing credential weakness is not itself defined as GAP-008, but it materially compounds a billing environment already classified as High and repeatedly compromised.

**Scenario-derived control weakness:** The USB transfer step exposes an endpoint device-control weakness. T13 explicitly states that this condition should not be retroactively assigned an unsupported gap ID; it should be recorded separately rather than mislabeled.

## Detection Opportunities

**Step 2:** EHR user-behavior analytics could identify access volumes or patient categories inconsistent with Maria's historical billing workload.

**Step 3:** EHR/database monitoring could alert when a billing employee repeatedly exports approximately 200 records per day or crosses a defined patient-record threshold.

**Step 4:** Endpoint DLP and removable-media controls could block Restricted CSV files from being copied to personal USB devices, while USB telemetry could generate an immediate incident.

**Step 5:** EDR could retain evidence of file creation/deletion and alert on bulk deletion of recently exported patient-data files.

**Step 6:** Secret scanning and secure configuration management could prevent reusable production database credentials from being stored in a user-accessible configuration file.

**Step 7:** Automated HR-to-identity reconciliation should disable AD, VPN, EHR, email, and dependent accounts at the recorded termination time and flag any orphan account.

**Step 8:** A post-termination authentication should be treated as a high-severity identity alert. Mandatory MFA, lifecycle-aware conditional access, and centralized VPN/identity correlation would either prevent the connection or detect it immediately.

---

# Scenario 3 — Third Party: Trusted Path — MedTech Solutions Maintenance Account Compromise

**Threat Actor:** **Nation-State APT / sophisticated external threat actor**, aligned to **T6 Threat Actor Matrix #2: Nation-State APT**.

This scenario uses a different actor type from Scenarios 1 and 2. T6 rates current nation-state targeting of MedDefense as Low because MedDefense does not operate a significant research program, but explicitly identifies **trusted supply-chain access and MedTech Solutions' continuous privileged access to `ehr-srv-01`** as a plausible path for a sophisticated actor.

**Motivation:** **Espionage / strategic intelligence collection.** The objective is persistent access to healthcare information, enterprise identity, and trusted healthcare relationships rather than immediate ransom payment.

**Initial Vector:** **Vendor access pathway — compromised MedTech Solutions maintenance credentials or remote-support tooling.**

**Attack Surface Exploited:** **External / Human trusted-third-party surface**, transitioning immediately to the **Internal** surface once the legitimate maintenance session reaches `ehr-srv-01`.

T7 identifies contractors and vendors as part of MedDefense's human surface because their endpoints, staffing, credential practices, and security culture remain partly outside MedDefense's control. Mandatory MFA, contractor-specific access review, and privileged-access management are not evidenced.

## Attack Sequence

**Step 1 — The attacker compromises a MedTech support identity — Initial Access against the supplier.**
A sophisticated external actor compromises MedTech's environment through credential theft, targeted phishing, or compromise of its remote-support tooling. This upstream event occurs outside MedDefense's direct control, which is precisely why the vendor relationship matters.

T5 explicitly identifies credential theft, phishing, and compromised remote-support tooling as credible ways an attacker could obtain MedTech's standing access.

**Step 2 — The attacker uses MedTech's standing maintenance pathway to access `ehr-srv-01` — Initial Access.**
Using the compromised vendor identity, the actor initiates what appears to be legitimate maintenance access to **AST-001 `ehr-srv-01`, 10.10.2.10**.

MedTech has continuous contracted network and application-level EHR maintenance access. No vendor-access session recording, least-privilege jump host, time-boxed maintenance restriction, or vendor-specific MFA is documented.

From MedDefense's perspective, the session initially resembles activity from an authorized supplier rather than an unknown Internet attacker.

**Step 3 — The actor enumerates systems reachable from the EHR foothold — Discovery.**
Once on `ehr-srv-01`, the attacker enumerates the surrounding `10.10.0.0/16` environment and identifies:

* `ehr-db-01` — AST-002;
* `ad-dc-01` / `ad-dc-02` — AST-005 / AST-006;
* `billing-srv-01` — AST-004;
* `pacs-srv-01` — AST-003;
* `file-srv-01` — AST-007;
* `backup-srv-01` / `NAS-01` — AST-009 / AST-010; and
* the medical-device addressing space.

T5 states that the contracted target is nominally the EHR server, but the flat network converts the EHR maintenance foothold into access proximity to all of these systems.

**Step 4 — The attacker harvests authentication material and targets Active Directory — Credential Access.**
The actor uses its internal position to identify reusable credentials, tokens, or authentication material associated with accessible services. T5 specifically models a pivot toward `ad-dc-01` involving the harvesting or forging of authentication tokens.

**Step 5 — The attacker establishes privileged domain persistence — Lateral Movement / Privilege Escalation / Persistence.**
After obtaining sufficient authentication material, the attacker accesses Active Directory and creates or preserves a privileged identity that is independent of the original MedTech session.

This step exploits **GAP-007**: Active Directory remains password-centric, lacks mandatory MFA, lacks centralized automated identity alerting, and provides enterprise-wide authentication authority. A single privileged identity can therefore provide downstream access to EHR, file services, administrative systems, and infrastructure management.

**Step 6 — The attacker accesses `ehr-db-01` directly — Collection.**
The actor connects to **AST-002 `ehr-db-01`, 10.10.2.11:5432** from the internal foothold. The Data Map and Gap Analysis already establish that PostgreSQL is reachable from more systems than operationally required rather than being principally limited to `ehr-srv-01`.

The actor collects Restricted patient information and potentially identity/authentication information for longer-term intelligence value. **GAP-006** removes a network barrier that should exist between the vendor maintenance path and the underlying clinical database.

**Step 7 — The actor creates persistence and reduces forensic visibility — Persistence / Defense Evasion.**
The attacker maintains an independent privileged account or equivalent persistence mechanism and manipulates local EHR/server evidence where possible. Because logs are not centrally forwarded to an independently protected monitoring environment, compromise of the server can also compromise part of the evidence required to reconstruct the attack.

The STRIDE model records this exact exposure as **EHR-R2** and ties it to **GAP-016**.

**Step 8 — The attacker exfiltrates intelligence while retaining access — Exfiltration.**
Collected PHI and identity information are transferred through encrypted outbound traffic. The attacker avoids intentionally encrypting the EHR because continued covert access is more valuable to an espionage actor than immediate service disruption.

The incident therefore differs fundamentally from Scenario 1: the principal objective is **persistent confidentiality compromise and enterprise identity access**, not ransomware.

## STRIDE Categories Triggered

* **Spoofing:** the attacker operates through a real MedTech identity or support channel, causing unauthorized activity to initially appear to originate from an authorized vendor.
* **Information Disclosure — EHR-I1:** Restricted PHI is collected directly from `ehr-db-01`.
* **Elevation of Privilege — EHR-E1:** vendor-level foothold is converted into privileged enterprise identity access.
* **Repudiation — EHR-R2:** local audit evidence can be altered or removed after privileged EHR/server compromise.
* **Tampering:** privileged persistence modifies MedDefense identity or server state even where the attacker deliberately avoids altering patient records.

## MedDefense Assets Impacted

* **AST-001 — `ehr-srv-01`**
* **AST-002 — `ehr-db-01`**
* **AST-005 / AST-006 — `ad-dc-01` / `ad-dc-02`**
* **AST-004 — `billing-srv-01`**, as a reachable lateral target
* **AST-003 — `pacs-srv-01`**, as a reachable clinical target
* **AST-007 — `file-srv-01`**
* **AST-009 / AST-010 — `backup-srv-01` / `NAS-01`**
* Potential medical-device infrastructure through the flat internal network

The T5 assessment rates MedTech **Critical** because it combines continuous contracted privileged access to the EHR with an architecture that can convert one vendor compromise into an organization-wide incident.

## Business Impact

**Clinical:** The actor's initial objective is covert collection rather than outage, so clinical systems may remain operational. However, compromise of the EHR application, database, and enterprise identity destroys MedDefense's assurance that clinical records and authentication state remain trustworthy. Containment may require intentionally taking EHR or identity services offline, creating a clinically significant outage even if the attacker never deploys destructive malware.

**Financial:** MedDefense faces incident response, vendor-forensics coordination, credential replacement, domain recovery, database validation, legal review, potential contract disputes, and possibly prolonged monitoring or infrastructure rebuilding because the attacker established persistence through a trusted third party.

**Regulatory:** Access to the EHR database constitutes potential disclosure of Restricted PHI. Weak logging can make the breach substantially harder to scope because MedDefense may be unable to determine confidently which records were accessed or whether they were modified.

**Reputational:** Patients and partner organizations would learn that compromise of a contracted EHR maintenance provider provided a path not merely to the EHR server, but toward enterprise identity and multiple clinical environments.

**Strategic:** Because the actor is modeled as an APT, the most important consequence is loss of confidence that eviction is complete. A vendor foothold plus privileged Active Directory persistence could support repeated access long after the original MedTech credential is disabled.

## Gaps Exploited

* **GAP-007 — Active Directory Relies on Passwords Without Mandatory MFA or Centralized Alerting:** supports privilege escalation and persistent valid-account abuse.
* **GAP-006 — EHR Database Is Reachable from More Systems Than Operationally Required:** permits the vendor-originated internal foothold unnecessary direct network proximity to Restricted PHI.
* **GAP-003 — Network-Core/Internal Isolation Weakness:** later project deliverables carry this gap forward as an insufficient-isolation condition that increases lateral movement across Critical systems.
* **GAP-016 — No Centralized Security Monitoring or Log Correlation:** allows a legitimate-looking vendor session, internal discovery, identity activity, and EHR access to remain separated across different log sources.
* **GAP-014 — No Evidenced DLP for Bulk Restricted-Data Extraction:** increases the likelihood that large EHR collections can leave the environment without prevention or timely alerting.

**Third-party governance deficiency:** T5 additionally documents the absence of MedTech-specific MFA evidence, session recording, least-privilege scoping, a confirmed jump host, and confirmed maintenance-window restrictions. The supplied T5 assessment documents this weakness directly but does not establish a separate standalone numbered 1x00 `GAP-xxx` identifier for it; it should therefore not be assigned an invented gap number.

## Detection Opportunities

**Step 1:** MedDefense has limited direct visibility into compromise inside MedTech. Contractual requirements should therefore require rapid vendor incident notification, strong supplier MFA, security-event reporting, and disclosure of compromised support credentials.

**Step 2:** A dedicated vendor-access gateway should validate the MedTech user, device, approved ticket, maintenance window, and MFA challenge before permitting access. All sessions should be recorded and attributable to a named vendor engineer.

**Step 3:** Network detection should alert when a MedTech-originated session communicates with `ad-dc-01`, `billing-srv-01`, `pacs-srv-01`, `NAS-01`, or the medical-device environment because none of those systems is part of the documented EHR maintenance target.

**Step 4–5:** Centralized Active Directory monitoring should detect unusual privileged authentication, token use, new administrative accounts, privilege-group changes, and vendor-originated domain-controller activity.

**Step 6:** Database network allow-listing should prevent the connection entirely unless it originates from an approved EHR application path. Database activity monitoring should separately detect bulk queries or exports inconsistent with maintenance behavior.

**Step 7:** EHR, Linux, Windows, firewall, identity, and vendor-session logs should be forwarded to an independently protected SIEM so that compromise of `ehr-srv-01` cannot erase the only useful evidence.

**Step 8:** DLP and egress analytics should identify high-volume encrypted transfers from the EHR environment or unusual outbound destinations associated with a vendor maintenance session.

---

# Board-Level Scenario Comparison

| Scenario                    | Actor                                           | Primary Vector          | Principal Posture Failure                                                                                                          | Primary Board Consequence                                                                                   |
| --------------------------- | ----------------------------------------------- | ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| **1 — Operation Flatline**  | Organized Crime / BlackReef RaaS                | FortiGate VPN exploit   | External vulnerability becomes domain compromise because identity, segmentation, recovery, and detection controls fail in sequence | EHR/enterprise ransomware, PHI theft, backup destruction, prolonged clinical outage, seven-figure extortion |
| **2 — The Quiet Departure** | Malicious Insider                               | Legitimate access abuse | Valid access is insufficiently governed, monitored, restricted, and deprovisioned                                                  | Approximately 3,200 patient records exfiltrated without malware or perimeter compromise                     |
| **3 — Trusted Path**        | Nation-State APT / sophisticated external actor | MedTech vendor access   | Trusted vendor access is not sufficiently isolated from the EHR database, Active Directory, and wider internal environment         | Covert PHI and identity compromise with persistent enterprise access and difficult forensic scoping         |

The three scenarios begin differently but converge on the same posture finding established by the Vector-to-Asset Matrix and Kill Chain analysis: **initial access is not the decisive MedDefense failure. The decisive failure is that a successful foothold can expand through insufficient segmentation, password-centric identity, broad access to Critical systems, weak data-loss controls, non-isolated recovery, and decentralized monitoring.** The Vector-to-Asset Matrix specifically identifies VPN exploitation and malicious-insider access as capable of reaching all seven assessed asset groups, while supply-chain compromise reaches five.

This is why the scenarios are directly connected to the prior **Asset Registry, Criticality Matrix, Data Map, and Gap Analysis** rather than merely describing generic healthcare threats. The assets being attacked are the assets MedDefense already classified as Critical or High; the information being stolen is the information already classified Restricted; and each attack succeeds by chaining weaknesses already identified in the posture assessment.

### Gap-ID Reconciliation Note

The later T3, T6, T11, and T13 project deliverables consistently reference **GAP-013, GAP-014, and GAP-016** for offboarding, DLP, and centralized monitoring respectively. The uploaded prioritized Gap Analysis file itself contains a ten-gap prioritized table ending at GAP-010. Those later project references have been preserved here because they are explicitly established in the supplied project deliverables; no new `GAP-xxx` identifiers have been invented for scenario-derived weaknesses such as unrestricted USB use or incomplete vendor-session governance.
