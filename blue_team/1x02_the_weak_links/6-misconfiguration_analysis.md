# Task 6 — The Misconfiguration Findings

**Research date:** September 17, 2026

## 1. Finding 003 — PostgreSQL Unrestricted Network Access

**Finding ID:** Finding 003 — Critical

**Host:** `10.10.2.11 (ehr-db-01)`

**Misconfiguration:** PostgreSQL accepts connections from the entire `10.10.0.0/16` internal network. The detected configuration is `host all all 10.10.0.0/16 md5` with `listen_addresses = '*'`, and there is no firewall or network ACL restricting TCP/5432 to the EHR application server. Consequently, any compromised internal host can establish a network connection directly to the patient database.

**Why No CVE:** PostgreSQL is not failing because of a defect in its code. The database administrator intentionally configured PostgreSQL to listen broadly and permitted an unnecessarily large source network in `pg_hba.conf`. The vulnerability therefore results from how a legitimate product feature was configured, not from a software flaw requiring a vendor patch.

**Severity Assessment: Critical.** The affected systems are **AST-002 `ehr-db-01`** and **AST-017 EHR clinical database**, which contain PHI and support a clinically critical EHR service. The Asset Registry specifically records that the PostgreSQL service is reachable more broadly than required. The scanner itself rated the condition Critical, and the exposure removes an important defensive layer between an ordinary compromised endpoint and Restricted EHR information.

**Cross-Reference 1x00:** This is a direct technical confirmation of **GAP-006 — EHR Database Is Reachable from More Systems Than Operationally Required**. GAP-006 identifies AST-002, AST-001, AST-016 and AST-017 and specifically calls for database-level segmentation and an allow-list permitting PostgreSQL principally from `ehr-srv-01`.

**Threat Cross-Reference 1x01:** This condition directly supports the **Ransomware Groups** attack path. The threat matrix explicitly identifies GAP-006 as providing unnecessary network proximity to the EHR database after an attacker obtains an internal foothold. It also identifies the EHR as the primary ransomware target because it combines Restricted PHI with clinical-availability pressure.

**Comparable CVE Risk:** **CVE-2020-1938 (Ghostcat)** from Finding 031 is a strong comparison. The scan records Ghostcat on the EHR application server and states that exploitation could expose configuration files containing database credentials. NVD currently rates CVE-2020-1938 **9.8 Critical**, and it is listed in CISA's Known Exploited Vulnerabilities catalog. Ghostcat creates a software-based path toward sensitive EHR information; Finding 003 creates a configuration-based path directly to the EHR database from the entire routed internal network. Once an attacker has obtained database credentials, the absence of network restriction can make the misconfiguration just as operationally important as the CVE because there is no segmentation layer left to stop the connection.

## 2. Finding 006 — MySQL Unrestricted Network Binding

**Finding ID:** Finding 006 — High

**Host:** `10.10.2.15 (billing-srv-01)`

**Misconfiguration:** MySQL is configured with `bind-address = 0.0.0.0`, causing TCP/3306 to listen on all network interfaces. The scanner confirmed that the database contains financial and billing records and that the flat network allows compromised internal systems to attempt direct database connections.

**Why No CVE:** Binding MySQL to all interfaces is supported product behavior. Nothing in MySQL must malfunction for the exposure to exist. The risk was introduced by selecting an unnecessarily permissive network-binding configuration instead of localhost or an allow-list of authorized application hosts.

**Severity Assessment: High.** The affected environment includes **AST-004 `billing-srv-01`** and **AST-020 Billing database**. AST-004 has already experienced ransomware and unauthorized cryptomining, while AST-020 contains billing, claims, and patient financial information. Authentication is still a barrier, so the finding does not automatically equal unauthenticated database compromise; however, MedDefense has already demonstrated that attackers can obtain code execution on this host, making unnecessary database exposure materially dangerous.

**Cross-Reference 1x00:** This finding materially amplifies **GAP-008 — Billing Server Lacks Server Malware Protection and Effective Egress Restriction**. GAP-008 covers AST-004, AST-019 and AST-020 and documents repeated compromise of the billing server. Although GAP-008 focuses on malware detection and egress rather than MySQL binding specifically, unrestricted TCP/3306 increases what a compromised internal system can reach and increases the consequences of the already-documented control weakness.

**Threat Cross-Reference 1x01:** The strongest mappings are **Ransomware Groups** and **Unskilled/Opportunistic Attackers**. The ransomware analysis directly maps GAP-008 to the ransomware attack sequence, while the opportunistic-attacker entry notes that `billing-srv-01` has already been compromised through commodity attack activity and identifies GAP-008 as a principal weakness.
**Comparable CVE Risk:** **CVE-2019-0211**, present as Finding 002 on the same billing server, is an appropriate comparison. The scan rates it 7.8 and explains that an attacker who has gained a lower-privileged foothold can escalate to root. NVD describes the vulnerability as allowing code executing in lower-privileged Apache child processes to obtain the privileges of the parent process. The MySQL exposure has different mechanics, but the operational concern is similar: after initial compromise, a condition that looks less important in isolation can give the attacker access to substantially more valuable billing data. Its lack of a CVSS score does not reduce the value of the resulting attack path.

## 3. Finding 007 — LDAP Signing Not Required

**Finding ID:** Finding 007 — High

**Host:** `10.10.2.20 (ad-dc-01)`

**Misconfiguration:** The primary Domain Controller accepts LDAP communications without requiring LDAP signing. This enables LDAP relay scenarios in which an attacker can relay authenticated sessions and potentially modify directory objects. The scan further notes that the flat network allows hosts throughout the environment to reach the Domain Controller.

**Why No CVE:** LDAP signing is a security-policy setting. Windows is operating according to the administrator-selected configuration; there is no defective function that Microsoft must patch for this specific finding. The weakness exists because stronger authentication-integrity controls were not enforced.

**Severity Assessment: High.** **AST-005 `ad-dc-01`** is MedDefense's primary Active Directory, DNS and authentication server and is described in the Asset Registry as a core authentication dependency. Successful directory manipulation can therefore affect identities, group memberships, privileges and downstream access across the enterprise. I retain a High rather than Critical rating because exploitation still requires appropriate relay conditions and is not equivalent to unauthenticated Domain Controller compromise.

**Cross-Reference 1x00:** Finding 007 directly reinforces **GAP-007 — Active Directory Relies on Passwords Without Mandatory MFA or Centralized Alerting**. GAP-007 identifies AST-005 and AST-006 as Critical assets and states that valid stolen credentials may be sufficient for access while security-event monitoring is incomplete. Unsigned LDAP adds another means by which authentication material can be abused rather than requiring the attacker to defeat Active Directory cryptographically.

**Threat Cross-Reference 1x01:** **Ransomware Groups** are especially relevant because the matrix identifies Active Directory as a deliberate ransomware target: Domain Controller control can enable broad ransomware deployment. The same actor entry specifically identifies GAP-007 as part of the ransomware attack chain. The **Nation-State APT** scenario also targets Active Directory for persistence and credential control and maps directly to GAP-007.

**Comparable CVE Risk:** **CVE-2021-34527 (PrintNightmare)** is a reasonable risk comparison because successful exploitation can provide SYSTEM-level code execution and therefore major control of a Windows host. NVD rates it **8.8 High** and confirms that it is in CISA's KEV catalog. The scan also identifies PrintNightmare as weaponized with public proof-of-concept code. LDAP relay is not identical to remote SYSTEM execution, but compromise of directory objects on a Domain Controller can have an enterprise-wide effect that exceeds compromise of one ordinary server. The absence of a CVE therefore should not cause the LDAP control failure to fall below a host-level 8.8 vulnerability automatically.

## 4. Finding 009 — SSH Password Authentication Enabled

**Finding ID:** Finding 009 — High

**Host:** `10.10.2.15 (billing-srv-01)`

**Misconfiguration:** SSH permits password authentication and the Linux host has no account-lockout policy. This allows repeated password attempts against SSH accounts rather than requiring cryptographic key authentication. The scan specifically contrasts this configuration with `ehr-srv-01`, where SSH key-only authentication is already implemented correctly.

**Why No CVE:** Password authentication is an intentional OpenSSH feature. OpenSSH is not vulnerable merely because the feature is enabled. The weakness results from MedDefense's authentication-policy decision—password login combined with the absence of lockout—rather than a defect in OpenSSH code.

**Severity Assessment: High.** This configuration exists on **AST-004 `billing-srv-01`**, a High-rated server processing Restricted billing information and a host with a documented history of ransomware and cryptomining compromise. Successful password guessing or reuse would provide an authenticated shell and could bypass the need to exploit a software vulnerability altogether.

**Cross-Reference 1x00:** The closest direct control relationship is again **GAP-008**, because the affected asset is AST-004 and the gap demonstrates that existing protection has already failed to prevent repeated compromise. Finding 009 adds an additional preventable access path to a server that already lacks server-class detection. It is therefore not merely an isolated SSH hardening observation; it worsens a documented High-risk billing-server gap.

**Threat Cross-Reference 1x01:** **Unskilled/Opportunistic Attackers** are a direct fit because the threat matrix identifies credential stuffing and commodity attack techniques as preferred mechanisms and specifically names `billing-srv-01` as MedDefense's clearest demonstrated target. Ransomware affiliates can also use stolen or guessed valid credentials as initial or lateral access, making the same configuration relevant to the ransomware scenario.

**Comparable CVE Risk:** **CVE-2019-0211**, rated 7.8 in the scan, is again a useful comparison. It allows an attacker who has already achieved low-privileged execution on Apache to escalate to root. A weak SSH authentication configuration addresses a different attack stage, but a successfully guessed or reused administrative password can provide direct authenticated execution without exploiting memory corruption or privilege-escalation code at all. In real operations, an attacker does not care whether access came from a CVE or a password policy error; the resulting shell is what creates the risk.

## 5. Finding 015 — Synology DSM Management Interface Accessible to the Entire Internal Network

**Finding ID:** Finding 015 — Medium in scanner output

**Host:** `10.10.2.41 (NAS-01 — Backup Storage)`

**Misconfiguration:** The Synology DSM administrative interface on TCP/5000 and TCP/5001 is reachable from the entire internal network rather than only authorized administrative systems. The scanner also states that the backup data stored on the NAS is unencrypted.

**Why No CVE:** Synology DSM is intended to provide an administrative web interface. The problem is that MedDefense's network policy exposes that interface too broadly. No software flaw is required: the security failure is the lack of network access controls around a high-value management plane and backup repository.

**Severity Assessment: High.** The scanner's Medium score understates the contextual impact. **AST-010 NAS-01** is MedDefense's primary backup repository, is located on the same network and in the same physical server-room/rack area as production systems, and already represents a correlated ransomware exposure. A compromised internal endpoint therefore gains direct network reachability to the administrative surface of the organization's principal recovery repository. Authentication still prevents the exposure from automatically becoming compromise, so High is more defensible than Critical for the individual finding.

**Cross-Reference 1x00:** This finding directly aggravates **GAP-004 — Production and Backup Copies Share the Same Failure Domain**. GAP-004 identifies AST-009 and AST-010 as Critical recovery assets and states that ransomware could simultaneously remove production systems and their primary backups. Broad DSM management access introduces an additional route for a compromised internal system to attack the same recovery infrastructure on which remediation depends.

**Threat Cross-Reference 1x01:** **Ransomware Groups** are the primary threat. The threat matrix specifically identifies GAP-004 as part of the MedDefense ransomware chain because reachable backup infrastructure can be attacked before enterprise encryption is deployed. The significance is therefore not merely whether an attacker can view a NAS login page; it is whether an enterprise foothold can reach and attempt to neutralize the organization's recovery mechanism.

**Comparable CVE Risk:** **CVE-2017-0144 (EternalBlue)** from Finding 004 provides an appropriate real-world comparison because of its ransomware relevance. The scan identifies it as weaponized and used in WannaCry. Current NVD data rates CVE-2017-0144 **8.8 High**, and CISA's KEV catalog marks it as known to have been used in ransomware campaigns. EternalBlue can provide or propagate a foothold; an exposed backup-management plane can determine whether the organization can recover after that foothold becomes ransomware. From a business-impact perspective, a configuration that enables attackers to reach the recovery repository can therefore be as consequential as the exploit that enabled the initial compromise.

## 6. Finding 016 — Medical Device HTTP/HL7 Interfaces Accessible Across the Network

**Finding ID:** Finding 016 — Medium in scanner output

**Host:** Multiple Philips IntelliVue patient monitors, `10.10.3.10–32`

**Misconfiguration:** Philips IntelliVue patient monitors expose HTTP/HTTPS management interfaces and HL7 TCP/2575 to the broader internal network. The scanner states that these interfaces have no authentication protection beyond the network layer, while MedDefense's flat network makes that network layer ineffective as an access boundary. Thirteen monitors with exposed web interfaces were directly detected.

**Why No CVE:** The interfaces themselves are legitimate management and clinical communication services. The vulnerability arises because MedDefense has deployed the devices on a broadly reachable network without enforced segmentation or default-deny access controls. No underlying Philips software defect must be present for an unauthorized internal system to reach them.

**Severity Assessment: Critical.** **AST-036 Philips IntelliVue monitor fleet** is categorized as Medical IoT supporting patient monitoring, with no enforced VLAN separation and management interfaces reachable across the internal network. The 1x00 analysis classifies the medical-device environment as Critical because manipulation or disruption can affect bedside treatment. This finding therefore has potential patient-safety and clinical-availability consequences, not merely IT confidentiality consequences.

**Cross-Reference 1x00:** Finding 016 is a direct validation of **GAP-002 — Medical IoT Is Not Segmented, Monitored, or Recoverable**. GAP-002 explicitly lists AST-036 and states that medical-device management interfaces remain broadly reachable. The missing preventive control is enforced device VLANs with default-deny internal access.

**Threat Cross-Reference 1x01:** **Ransomware Groups** are again relevant because the threat matrix explicitly maps GAP-002 to an expanded ransomware blast radius. A ransomware operator that compromises an ordinary workstation should not automatically gain network proximity to clinical monitoring infrastructure; this misconfiguration allows exactly that unnecessary proximity.

**Comparable CVE Risk:** **CVE-2020-25165**, which appears in Finding 010 against BD Alaris infusion pumps, is the closest like-for-like comparison. The MedDefense scan assigns it **7.5 High** and states that exploitation can cause denial of service, with network isolation recommended as the primary mitigation. NVD independently confirms a **7.5 High** rating and explains that exploitation can interrupt wireless capability and force manual operation of the affected Alaris PC Unit. Finding 016 has no CVSS number, yet it exposes another class of bedside clinical device across the flat network without an effective authentication boundary. Because the asset category is Critical and disruption of monitoring can affect patient care, its organizational risk can equal or exceed a formally scored 7.5 medical-device CVE.

## Why “Our CVE scan shows nothing critical, we are secure” Is Dangerous False Assurance

The statement is dangerous because CVE scanning measures only one class of security weakness: defects that have been assigned vulnerability identifiers. It does not measure whether systems are securely architected or configured. At MedDefense, the absence of a CVE does not prevent an internal attacker from reaching the EHR database through Finding 003, attempting direct connections to the billing database through Finding 006, abusing unsigned LDAP against a Critical Domain Controller through Finding 007, attacking password-based SSH authentication through Finding 009, reaching the management plane of the primary backup repository through Finding 015, or communicating directly with clinical patient monitors through Finding 016. These conditions map directly to previously documented Critical or High assets and gaps—especially GAP-002, GAP-004, GAP-006, GAP-007 and GAP-008—and they align with the attack paths already identified for ransomware, opportunistic attackers and sophisticated intruders. A CVSS score describes characteristics of a standardized vulnerability; it does not calculate MedDefense's complete business or clinical risk. Security assurance must therefore combine CVE intelligence with asset criticality, configuration review, architecture, segmentation, identity controls, threat likelihood, recovery capability and observed attack paths. A dashboard showing “zero Critical CVEs” could still coexist with a Critical exposure of PHI, Active Directory, backups, or bedside medical devices.
