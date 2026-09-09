# Task 13 – MITRE ATT&CK Mapping

# Scenario Alpha: “Operation Flatline” — Ransomware Campaign

### Step 1: BlackReef purchases technical targeting data identifying MedDefense's FortiGate VPN

**Tactic:** Reconnaissance
**Technique:** **Search Closed Sources: Purchase Technical Data (T1597.002)**
**Alternative:** Active Scanning (T1595) would describe the broker's original internet scanning, but BlackReef's action in this numbered step is specifically purchasing the resulting technical data.

**MedDefense Factor:** The purchased list is useful because MedDefense operates **AST-043 FortiGate 100F as its single firewall and VPN termination point**, making identification of that external service directly relevant to targeting the organization. The prior Gap Analysis classifies the network core as **Critical** and under-protected. The scenario specifically states that the purchased list was created from FortiGate scanning and included MedDefense.

---

### Step 2: Spearphishing link delivers a malicious document that launches PowerShell and a reverse shell

**Tactic:** Initial Access
**Technique:** **Phishing: Spearphishing Link (T1566.002)**
**Alternatives:** User Execution: Malicious File (T1204.002) applies when Sarah opens the downloaded document, while Command and Scripting Interpreter: PowerShell (T1059.001) applies to the macro-launched PowerShell command.

**MedDefense Factor:** The phishing message is specifically tailored to Sarah Park, MedDefense's IT Director, and impersonates Fortinet support, making the organization's known FortiGate dependency part of the social-engineering pretext. The malicious document is successfully opened on **WS-HQ-01**, and its macro is able to invoke PowerShell and download a reverse-shell payload. The prior Gap Analysis documents antivirus on managed Windows endpoints but does not identify a corresponding control that would prevent this Office-macro/PowerShell execution path.

---

### Step 3: Scheduled task establishes a recurring backdoor on Sarah's workstation

**Tactic:** Persistence
**Technique:** **Scheduled Task/Job: Scheduled Task (T1053.005)**
**Alternative:** The active reverse-shell connection also represents Command and Control activity, but the defining new behavior in this step is the recurring scheduled task.

**MedDefense Factor:** The attacker is able to create a task disguised as a Windows Update task that reconnects every 30 minutes. MedDefense's posture makes this particularly dangerous because its logs are decentralized: firewall, Windows, Linux, application, and EHR logs exist, but there is **no centralized SIEM correlation or automated alerting**, increasing the likelihood that repeated persistence activity will remain unnoticed.

---

### Step 4: BlackReef enumerates domain resources and discovers critical servers across the flat network

**Tactic:** Discovery
**Technique:** **Remote System Discovery (T1018)**
**Alternatives:** Permission Groups Discovery: Domain Groups (T1069.002) also applies to `net group "Domain Admins" /domain`, while other network-discovery techniques could describe individual commands.

**MedDefense Factor:** The attacker discovers **ad-dc-01, ehr-srv-01, ehr-db-01, billing-srv-01, backup-srv-01, and NAS-01** because Corporate HQ is connected to Central through the site-to-site VPN and the internal architecture is flat enough for the compromised workstation to see the broader 10.10.0.0/16 environment. This is consistent with the Data Map finding carried into **GAP-006**, which identifies flat internal architecture and excessive EHR database reachability as direct weaknesses.

---

### Step 5: Mimikatz extracts the svc_backup NTLM hash from workstation memory

**Tactic:** Credential Access
**Technique:** **OS Credential Dumping: LSASS Memory (T1003.001)**
**Alternative:** Cached Domain Credentials (T1003.005) could be considered if the captured material came specifically from the Windows domain credential cache; however, the scenario's Mimikatz memory-dumping behavior and recovery of an NTLM hash from a previous privileged session make LSASS Memory the stronger mapping.

**MedDefense Factor:** Sarah has local administrative rights, providing the privilege needed for credential-dumping activity, and the privileged **svc_backup** domain account had previously authenticated to her workstation during troubleshooting. That operational practice leaves privileged credential material on an ordinary administrative endpoint. The Criticality Matrix and Gap Analysis also classify Active Directory as Critical and its credential data as Restricted.

---

### Step 6: BlackReef uses the stolen svc_backup NTLM hash to access ad-dc-01

**Tactic:** Lateral Movement
**Technique:** **Use Alternate Authentication Material: Pass the Hash (T1550.002)**
**Alternative:** The subsequent query of all domain computer objects is Discovery activity, but the principal action is authentication to another system using the stolen NTLM hash.

**MedDefense Factor:** The stolen hash belongs to **svc_backup**, which has Domain Admin privileges, so one credential recovered from Sarah's workstation provides administrative access to **ad-dc-01** and subsequently the wider domain. This directly compounds **GAP-007**: Active Directory lacks mandatory MFA, centralized security-event correlation, and automated alerting, while remaining broadly connected to the rest of the environment.

---

### Step 7: EHR and HR data are collected, compressed, and exfiltrated with Rclone to cloud storage

**Tactic:** Exfiltration
**Technique:** **Exfiltration Over Web Service: Exfiltration to Cloud Storage (T1567.002)**
**Alternatives:** Data from Information Repositories: Databases (T1213.006) applies to the PostgreSQL `pg_dump`, and Archive Collected Data: Archive via Utility (T1560.001) applies to compressing the stolen datasets before transfer.

**MedDefense Factor:** This step exploits two posture findings simultaneously. First, **GAP-006** states that Critical **ehr-db-01** is reachable from more systems than operationally required and that the Data Map identifies broad database reachability and flat internal architecture. Second, **GAP-009** documents inadequate segmentation around Restricted HR/payroll information. The scenario converts those weaknesses into a concrete loss: approximately **35 GB of EHR data and 8 GB of HR/financial data** are transferred using Rclone over HTTPS without generating an alert.

---

### Step 8: BlackReef deletes NAS backups and Windows Volume Shadow Copies

**Tactic:** Impact
**Technique:** **Inhibit System Recovery (T1490)**
**Alternative:** File deletion is present operationally, but the attacker's purpose is specifically to eliminate recovery capability before encryption.

**MedDefense Factor:** This step is an almost direct exploitation of **GAP-004 — Production and Backup Copies Share the Same Failure Domain**. The Asset Registry/Criticality findings classify **backup-srv-01 and NAS-01 as Critical**, while the Data Map records that backup copies reside in the same network and physical environment as production and lack offsite or immutable replication. The scenario then demonstrates the consequence: the attacker reaches NAS-01 through the same compromised environment, deletes stored backups, and runs the exact `vssadmin delete shadows /all /quiet` behavior ATT&CK associates with T1490.

---

### Step 9: BlackReef uses Group Policy and SSH to deploy ransomware enterprise-wide

**Tactic:** Impact
**Technique:** **Data Encrypted for Impact (T1486)**
**Alternatives:** Domain or Tenant Policy Modification: Group Policy Modification (T1484.001) describes the malicious GPO used for Windows deployment, while Remote Services: SSH (T1021.004) describes separate access to the Linux servers.

**MedDefense Factor:** Domain Admin compromise allows BlackReef to use **ad-dc-01** as an enterprise distribution mechanism, converting the identity-system weakness in GAP-007 into organization-wide ransomware deployment. The ransomware reaches domain-joined Windows assets and accessible network shares, while credentials stored in a file allow separate SSH attacks against **ehr-srv-01 and billing-srv-01**. This also compounds **GAP-008**, which records that billing-srv-01 lacks server-capable malware detection and has already experienced ransomware and cryptomining compromises.

---

# Scenario Beta: “The Quiet Departure” — Insider Data Theft

### Step 1: Maria begins the attack with legitimate billing and read-only EHR access

**Tactic:** Initial Access
**Technique:** **Valid Accounts (T1078)**
**Alternative:** Domain Accounts (T1078.002) would be more specific if the billing/EHR authentication were confirmed to use Maria's AD domain account; the narrative does not explicitly establish that detail.

**MedDefense Factor:** Unlike Scenario Alpha, no perimeter compromise is required. Maria is already an authorized billing employee with legitimate access to **billing-srv-01** and read-only EHR access. This places two significant data stores within the attack path: the EHR assets are Critical and contain Restricted PHI, while billing infrastructure is High-rated and contains Restricted billing, claims, and patient financial information.

---

### Step 2: Maria determines how much patient information her normal application permissions expose

**Tactic:** Discovery
**Technique:** **Permission Groups Discovery (T1069) — best-fit mapping**
**Alternative:** **Data from Information Repositories: Databases (T1213.006)** is also defensible if the act of viewing the patient records is treated as Collection rather than discovery.

**MedDefense Factor:** Maria establishes that her normal billing and EHR permissions expose names, dates of birth, insurance details, diagnoses, billing amounts, medical history, and prescription information, and she discovers that the EHR does not impose a session-level volume limit or generate alerts for unusually large access volumes. This is significant because the prior posture assessment already identified a wider detective-control problem: security logging exists, but centralized correlation and automated alerting do not.

---

### Step 3: Maria exports approximately 200 EHR records per day into CSV files

**Tactic:** Collection
**Technique:** **Data from Information Repositories: Databases (T1213.006)**
**Alternative:** Data from Information Repositories (T1213) is the less specific parent technique.

**MedDefense Factor:** The EHR's built-in export capability is available to every user with read access and requires no additional authorization. Maria therefore uses an approved application feature to collect roughly 200 records per day while blending the activity into normal billing work. The EHR audit log records the events but no one reviews it. This aligns with the Gap Analysis conclusion that detective capability is materially weaker than the existence of logging alone would suggest.

---

### Step 4: Maria copies 2,800 patient records to a personal USB drive

**Tactic:** Exfiltration
**Technique:** **Exfiltration Over Physical Medium: Exfiltration over USB (T1052.001)**
**Alternative:** None is more specific for the actual transfer mechanism described.

**MedDefense Factor:** No Group Policy restricts removable storage on MedDefense workstations, and routine employee use of personal USB devices has normalized the behavior. Maria is therefore able to transfer approximately **2,800 patient records** to personally controlled media over two weeks without interruption. This represents an additional **endpoint device-control/DLP gap** not explicitly identified among the ten prioritized findings in the previous Gap Analysis; it should therefore be treated as a new scenario-derived weakness rather than retroactively attributed to one of the documented gaps.

---

### Step 5: Maria deletes the local CSV files and empties the Recycle Bin

**Tactic:** Defense Evasion
**Technique:** **Indicator Removal: File Deletion (T1070.004)**
**Alternative:** None is more specific to the deletion behavior described.

**MedDefense Factor:** Maria can remove the locally staged evidence from her workstation, although she cannot alter the separate EHR audit trail. The residual safeguard is weak because those EHR audit logs require a 48-hour vendor export request and are not reviewed proactively. The earlier Data Map/Gap Analysis likewise identified decentralized logging and the absence of automated correlation or alerting as a recurring detective weakness.

---

### Step 6: Maria steals billing database credentials stored in a configuration file

**Tactic:** Credential Access
**Technique:** **Unsecured Credentials: Credentials In Files (T1552.001)**
**Alternative:** Exfiltration over USB (T1052.001) also applies when the configuration file is subsequently copied to her removable drive.

**MedDefense Factor:** The billing application stores database connection credentials in a workstation configuration file accessible to Maria. She copies those credentials before departure, preserving a second authentication path to **billing-srv-01** after her ordinary employee access should have ended. This configuration-file credential exposure is **not explicitly one of GAP-008's documented missing controls**, but it materially compounds GAP-008 because the affected billing infrastructure is High-rated, contains Restricted financial/patient information, and already has a history of repeated compromise.

---

### Step 7: Delayed offboarding leaves Maria's account and VPN credentials active after termination

**Tactic:** Persistence
**Technique:** **Valid Accounts (T1078)**
**Alternative:** External Remote Services (T1133) becomes applicable when the still-valid account is actually used through the VPN in Step 8.

**MedDefense Factor:** HR initiates Maria's departure, but the IT deactivation ticket remains unprocessed for **five business days** because there is no offboarding SLA or automated identity deactivation linked to HR termination. Her VPN credentials consequently remain valid after employment ends. This specific offboarding-control failure was not explicitly captured in the previous top-ten Gap Analysis, although it directly compounds **GAP-007's identity weakness**, particularly the absence of mandatory MFA for remote and privileged access.

---

### Step 8: Maria reconnects through the VPN after termination and extracts another 400 billing records

**Tactic:** Initial Access
**Technique:** **External Remote Services (T1133)**
**Alternatives:** Valid Accounts (T1078) applies to the still-active VPN credentials, and Data from Information Repositories: Databases (T1213.006) applies to the subsequent extraction of billing records.

**MedDefense Factor:** Three days after termination, Maria can still connect remotely because her VPN account remains enabled. She then combines that identity-lifecycle failure with the database credentials stolen in Step 6 to directly access **billing-srv-01** and extract another **400 patient records**. The previous posture assessment makes the risk more severe: GAP-007 identifies missing mandatory MFA for remote access, while GAP-008 classifies the billing environment as High-rated and its billing, claims, and patient financial data as Restricted.

---

# ATT&CK Coverage Assessment

Across the two scenarios, the most important overlapping ATT&CK tactics are **Initial Access, Persistence, Credential Access, and Exfiltration**; both attacks also involve activity concerned with identifying or acquiring sensitive data, although Beta Step 2 creates a boundary between Discovery and Collection depending on how strictly the behavior is interpreted. The overlap demonstrates that MedDefense's highest-priority detection requirement is not a ransomware-specific signature set but visibility across **identity use, credential access, sensitive-data access, and outbound data movement**. Alpha reaches those stages through a compromised workstation, LSASS credential dumping, pass-the-hash movement, broad internal reachability, and Rclone exfiltration; Beta reaches the same security objectives using legitimate privileges, unrestricted exports, removable media, stored database credentials, and a still-active VPN account. The prior Gap Analysis already identifies the structural reason these different attack paths can converge: Active Directory lacks mandatory MFA and centralized alerting, EHR database access is broader than necessary, sensitive administrative repositories are inadequately segmented, and security logs are decentralized without SIEM correlation or automated alerting. MedDefense therefore needs detection capability most urgently around **anomalous authentication and post-termination account use; LSASS/credential-dumping behavior; privileged account and hash reuse; unusual EHR and billing database queries or exports; USB transfers of Restricted data; cloud-storage/Rclone egress; and destructive backup activity**. This detection priority directly connects the ATT&CK exercise to the Asset Registry/Criticality Matrix, Data Map, and Gap Analysis: the greatest monitoring urgency is concentrated around the Critical EHR, Active Directory, network, and backup assets and the Restricted patient, credential, HR, and financial datasets previously identified as carrying MedDefense's greatest business and clinical exposure.
