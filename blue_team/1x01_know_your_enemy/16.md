# MedDefense Health Systems

## Prioritized Threat Assessment

# 1. Top Five Threats

## Rank 1 — Ransomware Exploitation of the FortiGate-to-EHR Attack Path

**Rank:** 1

**Threat:** A ransomware affiliate exploits or obtains access through the FortiGate VPN, traverses MedDefense's flat internal network, compromises Active Directory, steals EHR PHI, destroys accessible backups, and encrypts clinical systems.

**Actor Type:** **T6 Actor #1 — Ransomware Groups (Organized Crime)**

**Primary Vector:** **Exploitation of AST-043 FortiGate 100F VPN**, with phishing or stolen valid credentials as alternative initial-access methods.

**Primary Target:** **EHR — AST-001 `ehr-srv-01` and AST-002 `ehr-db-01`**, with Active Directory and backup infrastructure targeted as enabling systems.

**Likelihood: Critical**

T6 ranks ransomware as MedDefense's highest-likelihood adversary. MedDefense is a 350-bed regional hospital matching the victim profile described in the threat analysis, and the environment contains the same conditions repeatedly used by healthcare ransomware operators: vulnerable public-facing infrastructure, password-centric identity, a flat internal network, weak centralized detection, and network-accessible backups. MedDefense has also already experienced ransomware and subsequent unauthorized cryptomining activity on `billing-srv-01`.

The threat is specifically supported by T10 Kill Chain #1. A FortiGate compromise provides an internal foothold from which an attacker can directly reach `ehr-db-01:5432` and enumerate Active Directory and other services because internal network boundaries do not provide effective containment.

T14 Scenario 1, **Operation Flatline**, extends that chain through credential theft, Domain Administrator compromise, approximately **35 GB of EHR data and 8 GB of HR/financial information exfiltration**, destruction of backup recovery points, and enterprise ransomware deployment.

**Impact: Critical**

The 1x00 Criticality Matrix ranks the EHR Critical across confidentiality, integrity, and availability. MedDefense has already experienced a nine-hour EHR outage that forced physicians onto paper records. A ransomware incident would therefore affect an asset whose availability has already demonstrated immediate clinical consequences.

The modeled attack affects approximately **50,000 patient records**, with ransomware capable of simultaneously creating PHI disclosure, unreliable clinical information, and loss of EHR availability.

**Overall Priority: Critical**

No other threat combines Critical likelihood, Critical clinical impact, demonstrated MedDefense compromise history, and such close alignment between attacker behavior and the existing architecture.

**Key Gap:** **GAP-003 — Network Core Remains Exposed to Unauthorized Administrative Control and Insufficient Internal Isolation**

Although patching AST-043 can prevent a specific exploit, ransomware actors can also enter through phishing or stolen credentials. Closing GAP-003 provides the broader defensive break point: even if initial access succeeds, the VPN or workstation foothold should not be able to communicate directly with `ehr-db-01`, domain-controller management services, PACS, medical-device networks, or backup-management interfaces. T10 identifies segmentation as the highest-leverage control because it interrupts Kill Chains 1 through 4 after initial access.

**Recommended Action — Short-term**

Implement **priority internal ACLs and security zones around EHR, Active Directory, and backup infrastructure**. Specifically, block VPN-originated and ordinary workstation traffic from `ehr-db-01:5432`, restrict domain-controller administrative services to authorized management systems, and prevent production endpoints from directly reaching `backup-srv-01` and `NAS-01` management interfaces. This should begin with the highest-risk flows immediately and expand into full server/clinical segmentation.

---

## Rank 2 — Negligent Insider Creates an Unmanaged Internal Foothold

**Rank:** 2

**Threat:** A MedDefense employee introduces or uses unmanaged technology, shared credentials, or mishandled privileged credentials inside the trusted network, creating a foothold that exposes Critical clinical or identity systems without requiring an external exploit.

**Actor Type:** **T6 Actor #4 — Insider (Negligent)**

**Primary Vector:** **Unsafe use of authorized access**, particularly unmanaged shadow IT such as AST-057 Cardiology NAS, shared Radiology credentials, and mishandled administrative credentials.

**Primary Target:** **Critical clinical and identity infrastructure reachable from the internal network**, particularly PACS/MRI, EHR, and Active Directory.

**Likelihood: High**

Unlike many external threats, negligent insider activity is already documented at MedDefense. T6 identifies three concrete behaviors: Radiology personnel sharing the `raduser/radiology1` account, Dr. Patel connecting a personal NAS containing patient information, and an administrator placing a privileged Active Directory credential in a script and sending it through email. T6 therefore ranks negligent insiders above malicious insiders because the behavior is both frequent and already observable inside MedDefense.

The Asset Registry shows why these actions are more dangerous than ordinary policy violations. MedDefense's network uses different IP ranges but lacks meaningful VLAN/firewall isolation; the scan confirmed that systems across the routed environment remain broadly reachable.

An unmanaged endpoint or storage system is therefore not confined to a low-value local segment.

**Impact: Critical**

The PACS/MRI environment, EHR, and Active Directory are all Critical according to the 1x00 Criticality Matrix. PACS supports diagnostic imaging and approximately 45 MRI studies each day; Active Directory controls enterprise authentication; and EHR compromise can directly affect clinical care.

The impact of negligent behavior can also become indirect. A personal NAS, exposed password, or administrator credential may not itself destroy a clinical system, but it can provide the foothold or authentication material later used by ransomware or another external actor.

**Overall Priority: High**

The actor is highly likely and already demonstrated. The threat ranks below ransomware because negligent insiders usually lack deliberate destructive intent, but MedDefense's flat environment allows routine unsafe behavior to create Critical downstream exposure.

**Key Gap:** **GAP-005 — Personal Cardiology Research NAS Operates Outside Enterprise Controls**

AST-057 is the clearest formal 1x00 example of negligent behavior creating an unmanaged persistent presence inside the clinical environment. It lacks enterprise authentication, centralized logging, managed protection, approved lifecycle management, and reliable recovery.

**Recommended Action — Quick Win**

**Migrate all organizational data from AST-057 to approved managed storage, validate the transfer, securely erase the device, and disconnect it from the MedDefense network.** The action removes a known unmanaged foothold rather than waiting for a broader shadow-IT program to mature.

---

## Rank 3 — Malicious Insider or Former Employee Exfiltrates Restricted Patient Data

**Rank:** 3

**Threat:** A current or recently terminated employee uses valid EHR and billing access to collect Restricted patient information gradually, removes it through an uncontrolled channel, and continues access after termination if credentials remain active.

**Actor Type:** **T6 Actor #3 — Insider (Malicious)**

**Primary Vector:** **Abuse of legitimate or stale valid accounts**

**Primary Target:** **EHR and Billing — AST-001/AST-002 and AST-004/AST-020**

**Likelihood: Medium**

T6 rates malicious insiders Medium likelihood. Healthcare workers have legitimate access to sensitive information, and MedDefense has specific control conditions that make intentional abuse credible: incomplete offboarding, weak behavioral monitoring, limited DLP, and password-based authentication. A prior project scenario also documented an account remaining technically valid for 47 days after authorization ended.

T14 Scenario 2, **The Quiet Departure**, demonstrates the MedDefense-specific path. An authorized billing employee uses normal EHR permissions to export approximately **200 records per day**, transfers approximately **2,800 records** to personal USB media, and later reconnects after termination to obtain another **400 records**, resulting in approximately **3,200 patient records** leaving MedDefense.

No malware or perimeter exploit is required.

**Impact: Critical**

The EHR is the #1 Critical asset in the 1x00 Criticality Matrix and contains Restricted clinical data. Billing infrastructure is rated High and contains patient financial and claims information.

The principal impact is confidentiality rather than immediate clinical outage: diagnoses, medical histories, prescription information, insurance information, and patient financial data can leave organizational control using otherwise legitimate application functionality.

**Overall Priority: High**

Likelihood is lower than negligent insider activity, but intent substantially increases impact because the insider can deliberately select high-value records, avoid obvious malware indicators, and exploit knowledge of MedDefense's workflows.

**Key Gap:** **GAP-014 — No Evidenced Data Loss Prevention for Bulk Restricted-Data Extraction**

Closing GAP-013 would prevent the final post-termination access, but it would not stop the majority of the modeled theft that occurs while the user remains legitimately employed. GAP-014 is therefore the stronger threat-reduction control.

**Recommended Action — Short-term**

Implement **targeted DLP and EHR export monitoring for Restricted patient information**, including alerts and secondary approval for abnormal bulk exports and blocking transfer of identified PHI files to unauthorized removable media. The control should distinguish normal individual-record clinical use from repeated high-volume extraction by a user whose role does not require it.

---

## Rank 4 — Opportunistic Exploitation of Known Internet-Facing Vulnerabilities

**Rank:** 4

**Threat:** Automated scanners or commodity attackers identify an unpatched FortiGate, patient-facing web service, or vulnerable server and exploit it without specifically selecting MedDefense in advance.

**Actor Type:** **T6 Actor #6 — Unskilled / Opportunistic Attacker**

**Primary Vector:** **Automated exploitation of known vulnerabilities or credential stuffing**

**Primary Target:** **AST-043 FortiGate 100F**, public-facing web services, or `billing-srv-01`

**Likelihood: High**

T6 rates opportunistic attackers High likelihood because MedDefense does not need to be deliberately selected. Automated scanning continuously identifies exposed vulnerable services. The threat is already demonstrated internally: `billing-srv-01` suffered unauthorized cryptomining activity that the predecessor assessment attributed to automated vulnerability exploitation rather than deliberate hospital targeting.

The Asset Registry further records that `billing-srv-01` previously suffered ransomware and later cryptomining, while AST-043 is MedDefense's single Internet firewall and VPN termination point.

The same vulnerability-management weakness was validated in the previous project's Reality Check: known vulnerabilities in exposed VPN and web infrastructure provided initial access in comparable healthcare incidents.

**Impact: Critical**

The most serious opportunistic target is AST-043. The Criticality Matrix rates Network Core and Security Infrastructure Critical because compromise of the FortiGate or switching environment can bypass security controls, redirect traffic, enable lateral movement, or disconnect entire sites.

An opportunistic attacker may initially seek cryptomining or botnet access rather than clinical disruption, but compromise of AST-043 can be resold or reused as the initial foothold for a more capable criminal actor.

**Overall Priority: High**

The attack requires little actor sophistication and has already occurred in a related form at MedDefense. It ranks below the deliberate malicious-insider threat because opportunistic objectives are often narrower, but the high probability of automated exposure makes it a continuing priority.

**Key Gap:** **GAP-011 — No Evidenced Enterprise Vulnerability and Patch-Management Program**

This is the principal gap identified by T6 for opportunistic actors and is the control most directly capable of removing known exploitable conditions before automated scanning finds them.

**Recommended Action — Quick Win**

Create an **authoritative Internet-facing vulnerability register covering AST-043, AST-011, and other externally reachable services**, assign critical vulnerabilities an accelerated remediation deadline, and verify deployment rather than relying on installation assumptions. Initial FortiGate and public-service review should begin immediately; broader enterprise vulnerability management should follow as a long-term operating process.

---

## Rank 5 — Compromise of MedTech's Trusted EHR Maintenance Path

**Rank:** 5

**Threat:** A sophisticated external actor compromises MedTech Solutions' support identity or remote-support tooling, enters directly through the authorized EHR maintenance pathway, pivots from `ehr-srv-01` to Active Directory and `ehr-db-01`, and maintains covert PHI and identity access.

**Actor Type:** **T6 Actor #2 — Nation-State APT / Sophisticated External Threat Actor**

**Primary Vector:** **Compromised MedTech Solutions maintenance credentials or remote-support tooling**

**Primary Target:** **AST-001 `ehr-srv-01`, followed by AST-002 `ehr-db-01` and AST-005/AST-006 Active Directory**

**Likelihood: Low**

T6 rates current nation-state targeting of MedDefense Low because the hospital does not presently hold the pharmaceutical research, vaccine research, clinical-trial information, or genomic data that commonly increases strategic healthcare targeting.

The threat nevertheless remains in the Top Five because MedDefense has an unusually consequential trusted access pathway. T14 Scenario 3 establishes that MedTech has continuous contracted maintenance access to `ehr-srv-01`, while vendor-specific MFA, time-boxed access, session recording, and a least-privilege jump host are not evidenced.

Once the attacker reaches the EHR server, the flat `10.10.0.0/16` architecture exposes proximity to `ehr-db-01`, domain controllers, PACS, billing, file services, backup infrastructure, and the medical-device environment.

**Impact: Critical**

Both EHR and Active Directory are Critical assets. A persistent APT could collect Restricted PHI without triggering immediate service disruption, compromise enterprise authentication, manipulate or create privileged identities, and make forensic scoping difficult.

The impact can still become clinical even if the attacker does not deploy ransomware: MedDefense may need to deliberately take EHR or identity systems offline to contain the intrusion and re-establish trust. T14 identifies that as a clinically significant consequence of the Trusted Path scenario.

**Overall Priority: Medium**

The potential impact is Critical, but present targeting likelihood is materially lower than ransomware, insider misuse, and automated exploitation. The threat remains in the Top Five because a trusted vendor compromise bypasses the perimeter and immediately places a sophisticated actor on MedDefense's most Critical application server.

**Key Gap:** **GAP-003 — Network-Core/Internal Isolation Weakness**

MedDefense cannot prevent every compromise inside MedTech's environment. The strongest internal defense is therefore to ensure that a legitimate EHR maintenance connection cannot be converted into access to Active Directory, `ehr-db-01`, PACS, backups, billing, or Medical IoT.

**Recommended Action — Long-term**

Implement a **dedicated MedTech vendor-access gateway/jump host** requiring named vendor identities and MFA, with maintenance access restricted to approved EHR systems and required ports only. Explicitly deny the vendor pathway from reaching domain controllers, `ehr-db-01` directly, backup infrastructure, PACS, billing, and medical-device networks, and record all privileged maintenance sessions.

---

# 2. Final Threat Ranking

|  Rank | Threat                                                                                 | Actor                                     | Likelihood   | Impact       | Overall Priority | Key Gap     |
| ----: | -------------------------------------------------------------------------------------- | ----------------------------------------- | ------------ | ------------ | ---------------- | ----------- |
| **1** | FortiGate/VPN ransomware → AD → EHR theft/encryption → backup destruction              | Ransomware Groups                         | **Critical** | **Critical** | **Critical**     | **GAP-003** |
| **2** | Negligent insider introduces unmanaged/unsafe access into the flat clinical network    | Insider — Negligent                       | **High**     | **Critical** | **High**         | **GAP-005** |
| **3** | Valid-account insider exfiltrates EHR/billing PHI and retains access after termination | Insider — Malicious                       | **Medium**   | **Critical** | **High**         | **GAP-014** |
| **4** | Automated exploitation of known FortiGate/public-server vulnerabilities                | Unskilled / Opportunistic                 | **High**     | **Critical** | **High**         | **GAP-011** |
| **5** | Compromised MedTech maintenance access → EHR/AD persistence and covert PHI theft       | Nation-State APT / Sophisticated External | **Low**      | **Critical** | **Medium**       | **GAP-003** |

Hacktivism does not enter the Top Five. T6 rates the actor Low likelihood, MedDefense has no strong political profile, and the most plausible objective is visible website or patient-portal disruption rather than compromise of the organization's highest-value clinical assets.

---

# 3. Strategic Recommendation

If MedDefense can fund only **two defensive initiatives in the next quarter**, the first should be **critical-system segmentation and network-core hardening under GAP-003**. T10 shows that effective segmentation interrupts four external/credential-driven kill chains after initial access and also limits the destructive capability of a privileged insider; specifically, VPN infrastructure should not reach `ehr-db-01`, normal endpoints should not reach privileged AD or backup-management services, and vendor/Radiology/medical-device environments should be constrained to explicitly required flows. The second initiative should be **MFA plus targeted centralized identity/security monitoring around Active Directory, FortiGate, EHR, and backups**, addressing GAP-007 and the highest-value portion of GAP-016. Stolen passwords and valid accounts appear across the ransomware, insider, and third-party scenarios, while T10 identifies observable malicious activity in every kill chain; making passwords insufficient and correlating privileged authentication, VPN reconnaissance, EHR exports, and backup changes therefore creates both a preventive and detective barrier across the majority of the Top Five threats. These two investments provide greater cross-threat reduction than funding a point solution for one asset because they directly address the recurring MedDefense attack pattern established by the Asset Registry, Criticality Matrix, Gap Analysis, Data Map, Kill Chains, and Threat Scenarios: **a successful foothold becomes a Critical incident when internal reachability, identity trust, and detection controls all fail together**.
