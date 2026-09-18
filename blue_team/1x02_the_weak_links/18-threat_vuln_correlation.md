# Task 18 — The Threat-Vulnerability Correlation

## Threat-Vulnerability Correlation Matrix

Finding 001 | Threat Actor(s): Ransomware Groups (Organized Crime); Unskilled/Opportunistic Attacker | Vector: Automated exploitation of known vulnerable servers / Vulnerable Software Exploit; ransomware may also arrive through VPN exploitation or phishing before pivoting to billing | Kill Chain: No direct T10 chain; functions as an internal foothold that can feed the common foothold → flat network → Critical asset pattern | Scenario: Scenario 1 — Operation Flatline, where `billing-srv-01` is enumerated as a reachable internal system and GAP-008 is identified as an additional weak staging/C2 host; the scenario does not explicitly exploit CVE-2021-44790 | Gap: GAP-008 — Billing Server Lacks Server Malware Protection and Effective Egress Restriction

Finding 002 | Threat Actor(s): Ransomware Groups (Organized Crime); Unskilled/Opportunistic Attacker | Vector: Vulnerable Software Exploit after an attacker already gains execution on `billing-srv-01`; Finding 001 supplies the low-privilege foothold | Kill Chain: No direct T10 chain; privilege-escalation stage supporting an internal foothold | Scenario: Scenario 1 — Operation Flatline as a possible billing-server escalation/staging path; CVE-2019-0211 itself is not explicitly used in T14 | Gap: GAP-008 — Billing Server Lacks Server Malware Protection and Effective Egress Restriction

Finding 003 | Threat Actor(s): Ransomware Groups (Organized Crime); Nation-State APT | Vector: VPN Exploit or trusted third-party/vendor compromise → internal foothold → direct PostgreSQL access to `ehr-db-01:5432` | Kill Chain: Kill Chain #1 — FortiGate VPN Exploitation to EHR Database Compromise, Steps 3-4 | Scenario: Scenario 1 — Operation Flatline, Step 6; also Scenario 3 — Trusted Path, Step 6, where the nation-state actor accesses `ehr-db-01` directly | Gap: GAP-006 — EHR Database Is Reachable from More Systems Than Operationally Required

Finding 004 | Threat Actor(s): Nation-State APT; Ransomware Groups; Unskilled/Opportunistic Attacker | Vector: Vulnerable Software Exploit against the Windows XP MRI workstation; T9 also maps VPN compromise and trusted supply-chain compromise into the PACS/MRI environment | Kill Chain: Kill Chain #3 — Compromised PACS/MRI Supply Chain to Diagnostic Imaging Integrity Loss | Scenario: No T14 scenario directly exploits BlueKeep/EternalBlue/MS08-067 on `WS-RAD-01`; Scenario 1 and Scenario 3 only establish downstream proximity to PACS/clinical systems. T10 Kill Chain #3 is the direct source-supported MRI attack scenario | Gap: GAP-001 — PACS Has No Evidenced Recovery Capability; this amplifies impact, while T12 contains no separate numbered legacy-Windows-XP gap

Finding 007 | Threat Actor(s): Ransomware Groups (Organized Crime); Nation-State APT; Insider (Malicious) | Vector: Spear Phishing / stolen valid credentials / trusted vendor foothold → LDAP, Kerberos and SMB access to Active Directory | Kill Chain: Kill Chain #2 — Spear Phishing to Active Directory and Enterprise Privilege, especially Step 3 lateral movement/escalation | Scenario: Scenario 1 — Operation Flatline, Step 5 compromises `ad-dc-01`; Scenario 3 — Trusted Path, Steps 4-5 harvest authentication material and establish privileged domain persistence | Gap: GAP-007 — Active Directory Relies on Passwords Without Mandatory MFA or Centralized Alerting

Finding 010 | Threat Actor(s): Ransomware Groups (Organized Crime); Insider (Malicious); Nation-State APT as a trusted-supply-chain actor | Vector: Phishing or VPN Exploit → internal foothold → reachable medical-device interfaces; T9 also identifies Vulnerable Software Exploit and Supply Chain Compromise as Medical IoT vectors | Kill Chain: No dedicated T10 kill chain; medical-device isolation is identified as a cross-chain containment requirement | Scenario: Scenario 1 — Operation Flatline identifies medical IoT as a downstream ransomware blast-radius target; Scenario 3 — Trusted Path gives the compromised vendor foothold proximity to the medical-device addressing space | Gap: GAP-002 — Medical IoT Is Not Segmented, Monitored, or Recoverable

Finding 015 | Threat Actor(s): Ransomware Groups (Organized Crime); Insider (Malicious) | Vector: Spear Phishing of an IT administrator or stolen privileged credentials → flat network → `NAS-01:5000/5001`; malicious backup administrators can instead abuse legitimate access | Kill Chain: Kill Chain #4 — Phished IT Administrator to Backup Destruction and Ransomware Recovery Failure, Steps 3-4 | Scenario: Scenario 1 — Operation Flatline, Step 7, where BlackReef reaches `backup-srv-01` and `NAS-01`, destroys recovery points and interferes with backup jobs before enterprise encryption | Gap: GAP-004 — Production and Backup Copies Share the Same Failure Domain

Finding 016 | Threat Actor(s): Ransomware Groups (Organized Crime); Insider (Malicious); Nation-State APT as a trusted-supply-chain actor | Vector: Phishing or VPN Exploit → internal foothold → HTTP/HTTPS and HL7 management interfaces; Supply Chain Compromise and malicious insider access are also mapped to Medical IoT in T9 | Kill Chain: No dedicated T10 kill chain; medical-device segmentation is identified as a cross-chain defensive break point | Scenario: Scenario 1 — Operation Flatline identifies bedside medical IoT as potential downstream ransomware impact; Scenario 3 — Trusted Path places the medical-device environment within reach of a compromised vendor session | Gap: GAP-002 — Medical IoT Is Not Segmented, Monitored, or Recoverable

---

## Correlation Basis

The T6 Threat Actor Matrix identifies **Ransomware Groups as MedDefense's highest-priority actor**, with FortiGate/VPN exploitation, phishing and stolen credentials as preferred entry vectors. It specifically links ransomware exposure to GAP-008 on billing, GAP-007 on Active Directory, GAP-006 on the EHR database, GAP-004 on backups and GAP-002 on medical devices. T6 also identifies automated exploitation of known vulnerabilities as the preferred technique of the Unskilled/Opportunistic Attacker and identifies trusted supply-chain access as a preferred Nation-State technique.

T9 shows why the flat network causes those actors and vulnerabilities to intersect. Phishing and VPN exploitation can reach all seven assessed asset groups; vulnerable-software exploitation provides paths from legacy systems toward EHR, PACS/MRI and Active Directory; and malicious-insider access reaches all seven groups. The matrix summarizes the common progression as **initial access → internal foothold → flat network → broadly reachable Critical services → compromise of a Critical asset**.

### Findings 001 and 002 — Billing Exploit Chain

T6 gives these findings their strongest direct actor correlation. The Unskilled/Opportunistic Attacker uses automated exploitation of known vulnerabilities, and T6 explicitly identifies `billing-srv-01` as MedDefense's strongest demonstrated opportunistic target because hostile cryptomining software has already compromised it. Ransomware groups are also relevant because the same server has previously suffered ransomware.

T14 Scenario 1 does not explicitly invoke CVE-2021-44790 or CVE-2019-0211. It does, however, enumerate `billing-srv-01` after the attacker gains internal access and identifies GAP-008 as a weakness that can provide an additional staging or command-and-control host.
The exact gap is **GAP-008**, which records repeated compromise of `billing-srv-01`, missing server-class malware detection and unrestricted outbound communication.

The relationship is therefore:

**known Apache vulnerability → billing-server foothold → privilege escalation → internal staging/pivot opportunity.**

---

### Finding 003 — EHR Database Exposure

Finding 003 has the strongest multi-scenario correlation.

T9 maps a **VPN Exploit** directly from the FortiGate to `ehr-db-01:5432`, while supply-chain compromise can reach the EHR through trusted vendor software or support access.

T10 Kill Chain #1 explicitly makes the EHR database the final target of the FortiGate attack path. After initial VPN compromise, the attacker moves laterally and can directly reach PostgreSQL port 5432 before accessing, stealing, altering or encrypting EHR information.
T14 then validates this correlation through **two separate actor scenarios**. In Scenario 1, BlackReef uses domain-level authority and the flat network to access `ehr-db-01:5432` and exfiltrate Restricted EHR information. In Scenario 3, the Nation-State actor reaches the same database directly from a compromised MedTech maintenance path; the scenario explicitly states that GAP-006 removes a network barrier that should separate vendor access from the underlying clinical database.

The corresponding gap is **GAP-006**, which identifies the EHR database as Critical, containing Restricted PHI, but reachable from more systems than operationally required.

---

### Finding 004 — Legacy MRI Vulnerabilities

Finding 004 maps directly to T9's **Vulnerable Software Exploit** vector. T9 describes compromise of Windows XP `WS-RAD-01` followed by use of the connected imaging workflow and flat network to reach `pacs-srv-01`.

T10 provides the strongest direct scenario through **Kill Chain #3: Compromised PACS/MRI Supply Chain to Diagnostic Imaging Integrity Loss**. It targets `pacs-srv-01` and `WS-RAD-01` and describes compromise, alteration or loss of diagnostic imaging and interruption of approximately 45 MRI studies per day.

The supplied T14 contains only three scenarios—Operation Flatline, The Quiet Departure and Trusted Path. None directly exploits BlueKeep, EternalBlue or MS08-067 on the MRI workstation. Therefore, this matrix does not falsely attribute one of those T14 scenarios to the CVEs.

The closest T12 gap is **GAP-001**, because lack of evidenced PACS recovery magnifies the consequence if the vulnerable MRI/PACS environment is destroyed or corrupted.

---

### Finding 007 — Active Directory

Finding 007 has strong ransomware and Nation-State correlation.

T9 maps spear phishing to stolen IT credentials and onward access to `ad-dc-01` and `ad-dc-02`. VPN exploitation also supplies unrestricted reachability to Kerberos, LDAP, SMB and LDAPS services.

T10 Kill Chain #2 is specifically **Spear Phishing to Active Directory and Enterprise Privilege** and describes enterprise credential and authorization compromise as the expected impact.

T14 reinforces this twice. Scenario 1 has BlackReef compromise `ad-dc-01`; the scenario states that domain-level control converts an individual-host compromise into enterprise identity compromise. Scenario 3 has the Nation-State actor harvest authentication material and then establish privileged domain persistence independent of the original vendor session.

Both scenarios explicitly identify **GAP-007** as an enabling weakness. The Gap Analysis states that AD is Critical, handles Restricted authentication data, lacks mandatory MFA and centralized automated alerting, and can propagate compromise into EHR, administrative systems, file services and infrastructure management.

---

### Findings 010 and 016 — Medical IoT

T9 maps several vectors to Medical IoT: phishing can compromise a clinician endpoint and then reach Philips or BD management interfaces; VPN compromise produces an internal foothold with medical-device reachability; vulnerable-software exploitation targets Alaris devices; supply-chain compromise can affect Philips or BD firmware; and malicious insiders can directly reach broadly accessible device-management interfaces.

One important source detail must be preserved: T9 deliberately leaves the **Default / Shared Credentials** vector row empty because the evidence used to build that matrix did not establish such credentials across the seven assessed asset groups. Therefore Finding 010's confirmed `admin/admin` observation from the later vulnerability scan should not be retroactively presented as a T9 vector.

Neither Finding 010 nor Finding 016 receives its own dedicated T10 kill chain. Instead, T10 treats medical-device isolation as a cross-chain containment requirement.

T14 Scenario 1 explicitly states that the VPN exploit can reach medical devices and identifies medical IoT as a possible downstream blast-radius target of the ransomware attack. Scenario 3 similarly places the medical-device addressing space within reach of a compromised MedTech vendor session.

Both findings correspond directly to **GAP-002**, which states that the Philips and Alaris fleets are Critical, broadly reachable, and lack enforced VLAN isolation, dedicated behavioral monitoring and documented recovery controls.

---

### Finding 015 — Backup NAS Exposure

Finding 015 has the clearest direct ransomware correlation.

T9 maps phishing to compromised IT-administrator credentials followed by access to `backup-srv-01` and `NAS-01:5000/5001`. VPN exploitation creates the same network proximity, while malicious backup administrators already possess legitimate access.

T10 Kill Chain #4 is explicitly **Phished IT Administrator to Backup Destruction and Ransomware Recovery Failure**, with destruction or encryption of recovery copies before enterprise ransomware deployment as its expected impact.

T14 Scenario 1 reproduces that attack operationally. In Step 7, BlackReef reaches `backup-srv-01` and `NAS-01`, removes recovery points and interferes with backup jobs before ransomware is deployed.

This maps exactly to **GAP-004**, which states that the backup environment is Critical but exists in the same network and physical failure domain as production and lacks isolated immutable or offsite recovery copies.

---

# Highest-Damage Correlation

**Finding 007 — LDAP Signing Not Required on `ad-dc-01` — has the greatest potential systemic damage of the eight findings if it is successfully leveraged into privileged Active Directory compromise.** The reason is not simply the scanner's High rating; it is where the weakness sits in MedDefense's full threat model. T6 ranks ransomware groups as the highest-priority threat actor and specifically notes that Domain Controller control enables broad ransomware deployment. T10 Kill Chain #2 establishes Active Directory as the route from a stolen IT identity to enterprise privilege, while T14 Scenario 1 shows the consequence: once `ad-dc-01` is compromised, the attacker can use domain authority to reach the EHR, destroy backups and distribute ransomware across reachable systems. Scenario 3 independently shows a Nation-State actor using the same identity layer to establish persistent privileged access after compromising a trusted vendor account. Because Active Directory is an enterprise trust dependency rather than a single application, successful exploitation can convert one foothold into control over multiple Critical assets. Finding 004 may have more mature standalone exploit code and Finding 003 directly exposes MedDefense's highest-value PHI repository, but **Finding 007 offers the widest enterprise blast radius because privileged identity compromise enables the attacker to reach and manipulate the other critical systems rather than only one of them**.
