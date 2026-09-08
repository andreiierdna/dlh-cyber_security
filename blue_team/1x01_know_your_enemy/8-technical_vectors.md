# MedDefense Health Systems

# 1. Technical Vector Assessment
## Vector 1 — Vulnerable Software

**Vector Category:** Vulnerable Software

**MedDefense Evidence:**
The task evidence identifies **Apache 2.4.29 on `billing-srv-01`** as outdated software. The Asset Registry independently confirms that `billing-srv-01` (`AST-004`, `10.10.2.15`) hosts the Apache billing application and MySQL database on Ubuntu 18.04 and has already experienced both ransomware and a later cryptomining compromise through the `www-data` service account.

The Network Scan Summary further establishes that Ubuntu 18.04 standard support ended in June 2023 and that Extended Security Maintenance is available but **not activated**. The same scan identifies **BD Alaris firmware 12.1.2** across the infusion-pump fleet and specifically notes known CVEs for that version together with a vendor recommendation for network isolation that MedDefense has not implemented.
This directly aligns with **GAP-011**, which found no evidenced enterprise vulnerability and patch-management program; known vulnerabilities can therefore remain exploitable even after remediation becomes available.

**Affected Asset(s):**
`billing-srv-01` (AST-004), Billing/Claims Application (AST-019), Billing Database (AST-020), BD Alaris infusion-pump fleet (AST-037), and—through lateral movement—the Critical EHR, Active Directory, PACS/MRI, backup infrastructure, and medical-device environments.

**Actor Most Likely to Exploit:**
**Ransomware-as-a-Service affiliate / financially motivated exploit-based actor**, consistent with the ransomware and exploit-based initial-access actor set carried forward into T6. MedDefense's own history makes financially motivated exploitation particularly credible because `billing-srv-01` has already suffered ransomware and unauthorized cryptocurrency mining.

**Exploitation Scenario:**
A ransomware affiliate or initial-access broker exploits the outdated Apache stack or another unremediated component on `billing-srv-01`, gaining execution under the web-service context. Because the host has no server-class EDR, broad outbound access, and resides in MedDefense's permissive internal environment, the attacker can establish persistence, obtain credentials, and move from a High-rated billing asset containing Restricted financial information toward EHR, Active Directory, backups, or other clinical systems.

**Current Protection:**
C-001 Default-Deny Firewall Policy and C-004 Firewall Traffic Logging provide perimeter filtering and event records, while C-012 provides nightly Veeam backup of `billing-srv-01`. However, C-011 Sophos antivirus covers managed Windows workstations rather than Windows/Linux servers, leaving the billing host outside that endpoint-protection scope; C-018 local logging is also rated Weak because it lacks centralized correlation and alerting.
**Gap Reference:**
**GAP-011 — No evidenced enterprise vulnerability and patch-management program.**
Also materially amplified by **GAP-008 — Billing server lacks server-class malware protection and effective egress restriction** and **GAP-016 — No centralized security monitoring or log correlation**.
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Vector 2 — Unsupported Systems

**Vector Category:** Unsupported Systems

**MedDefense Evidence:**
The Network Scan Summary confirms two active end-of-life systems: `WS-RAD-01` at `10.10.1.70`, the Siemens MRI control workstation running **Windows XP SP3**, and `print-srv-01` at `10.10.2.31`, running **Windows Server 2012 R2**. The scan also places Ubuntu 18.04 on `billing-srv-01` outside standard support.

The Asset Registry establishes that `WS-RAD-01` is not simply an obsolete office endpoint. It controls the Siemens MAGNETOM MRI, must transfer studies to PACS, and cannot be conventionally upgraded without affecting the device's certification baseline. `print-srv-01`, meanwhile, was previously believed to be unverified but was confirmed active by the scan, proving that end-of-support infrastructure remains operational rather than decommissioned.
The Criticality Assessment rates the **PACS/MRI environment Critical** because imaging supports diagnosis and treatment, with approximately 45 MRI studies performed per day.

**Affected Asset(s):**
`WS-RAD-01` / Siemens MAGNETOM MRI control workstation (AST-034), PACS server and repository (AST-003/AST-018), `print-srv-01` (AST-008), and systems reachable from these hosts through the flat Central network.

**Actor Most Likely to Exploit:**
**Ransomware-as-a-Service affiliate / opportunistic cybercriminal**, particularly an actor already possessing internal access and scanning for legacy SMB, RPC, workstation, or server services with a limited ability to receive security fixes.

**Exploitation Scenario:**
After compromising an ordinary workstation, a ransomware affiliate enumerates `WS-RAD-01` and identifies Windows XP SP3 with SMB/RPC services available inside the same unsegmented Central environment. Exploitation of the legacy host provides a durable foothold adjacent to PACS, allowing an attacker to interfere with the MRI-to-PACS workflow or use the imaging workstation as another lateral-movement node; disruption would affect a Critical clinical service processing Restricted diagnostic imaging.

**Current Protection:**
Perimeter controls C-001 and site-network controls provide only indirect protection once the attacker is internal. The Complete Control Matrix defines C-021 dedicated MRI VLANs, C-022 virtual patching/IPS and egress filtering, C-023 IPS alerting, C-024 MRI monitoring, C-025 a legacy-device exception process, and C-026 removable-media controls, but each is **design-state or not evidenced as operational**, so these controls cannot currently be credited with reducing the risk.

**Gap Reference:**
**GAP-011 — No evidenced enterprise vulnerability and patch-management program**, with the MRI's unpatchable status also incorporated into the PACS/MRI legacy-system risk rather than represented as a separate numbered Board-level gap. The Security Posture Assessment similarly records the unsupported `print-srv-01` as a subsidiary vulnerability-management finding.

---

## Vector 3 — Open Service Ports

**Vector Category:** Open Service Ports

**MedDefense Evidence:**
The Network Scan Summary identifies multiple services that are exposed more broadly than operational requirements justify:

* PostgreSQL on `ehr-db-01`, `10.10.2.11:5432`, is reachable from the entire internal network.
* MySQL on `billing-srv-01`, `10.10.2.15:3306`, is reachable network-wide.
* RDP/3389 is enabled on reception and administrative workstations without a network-level restriction.
* NAS-01 management ports 5000/5001 are reachable throughout the network.
* Philips monitors and BD Alaris pumps expose HTTP/HTTPS management interfaces across the internal environment.

The scan also identifies representative medical-device ports directly: Philips IntelliVue monitors expose 80/443/2575, BD Alaris pumps expose 80/443, nurse-call systems expose 80/5060, and multiple HID devices expose 80/443. Approximately 65 additional Philips monitors and 110 additional Alaris pumps show the same profiles.

**Affected Asset(s):**
`ehr-db-01` and EHR clinical database (AST-002/AST-017); `billing-srv-01` and billing database (AST-004/AST-020); reception and administration workstation fleets; NAS-01 (AST-010); medical IoT fleet (AST-036 through AST-039); and Active Directory or other critical infrastructure reachable after lateral movement.

**Actor Most Likely to Exploit:**
**Ransomware-as-a-Service affiliate / post-compromise cybercriminal**, because these services are especially valuable after any initial foothold: database ports expose Restricted information, RDP enables interactive movement, and management interfaces expose administrative surfaces.

**Exploitation Scenario:**
An attacker who compromises a single workstation can scan MedDefense's internal address space and directly discover PostgreSQL 5432, MySQL 3306, RDP 3389, NAS management ports, and medical-device web interfaces without crossing an internal security boundary. The attacker can then target stolen database credentials against `ehr-db-01`, use RDP to establish interactive sessions on administrative endpoints, or reach medical-device management pages, turning one endpoint compromise into access to Critical clinical and recovery assets.

**Current Protection:**
The EHR has strong SSH controls—C-005 through C-008—and benefits from C-001 firewalling, C-004 logging, C-009 password policy, C-010 lockout, and C-012 backup. Those controls explain why the Gap Analysis rates EHR as **Partially Protected**, but they do not restrict PostgreSQL to the application systems that actually require it.

**Gap Reference:**
**GAP-006 — EHR database is reachable from more systems than operationally required.**
**GAP-002 — Medical IoT is not adequately segmented, monitored, or recoverable.**
**GAP-008 — Billing server lacks server-class malware protection and effective egress restriction.**
The broader exposure is enabled by **GAP-003**, which addresses insufficient internal isolation.
------------------------------------------------------------------------------------------------

## Vector 4 — Default Credentials

**Vector Category:** Default Credentials

**MedDefense Evidence:**
The posture assessment identifies **GAP-015 — Medical-device administrative credentials are not centrally governed**, specifically warning that default, shared, or stale credentials could provide immediate administrative access after an attacker reaches device management interfaces. The required remediation is to remove vendor defaults, establish ownership, issue unique credentials, and place privileged credentials under controlled escrow.

The PACS/MRI environment contains a second credential weakness: Radiology uses the shared `raduser` identity. The Gap Analysis classifies this as a Medium accountability weakness because multiple individuals operate through one shared identity, while the Complete Control Matrix incorporates the condition into the broader under-protected PACS/MRI assessment.
For the BD Alaris interfaces specifically, the evidence supports **default/shared credential risk**, not a verified claim that every pump currently retains a known vendor default. The correct assessment is therefore that MedDefense has not centrally demonstrated or governed the administrative credential state of a fleet whose HTTP/HTTPS interfaces are broadly reachable.

**Affected Asset(s):**
PACS and MRI imaging environment; BD Alaris infusion-pump fleet; Philips monitor fleet; nurse-call and other medical-device management interfaces; and potentially other systems using shared or locally managed credentials.

**Actor Most Likely to Exploit:**
**Ransomware or financially motivated valid-account-abuse actor**, with an insider representing a secondary concern for the shared PACS identity. Once a technical path reaches the management interface, credential reuse or an unchanged vendor credential can eliminate the need for further exploitation.

**Exploitation Scenario:**
A ransomware affiliate first compromises a workstation and uses the flat network to connect directly to HTTP/HTTPS management interfaces on the Alaris and monitor fleets. The actor then tests vendor-default or previously obtained shared credentials; successful authentication provides administrative-level access to clinically significant devices, while use of `raduser` against the imaging environment obscures which legitimate or malicious individual performed subsequent activity.

**Current Protection:**
C-009 establishes organization-wide password requirements and C-010 applies five-attempt lockout to Windows domain and remote-access accounts. These controls are only partially relevant because locally managed medical-device accounts may not be governed by Active Directory, and the supplied evidence specifically identifies medical-device credential governance as unresolved.

**Gap Reference:**
**GAP-015 — Medical-device administrative credentials are not centrally governed.**
The shared PACS `raduser` account is a **subsidiary PACS/MRI credential finding**, not a separate numbered gap. The lack of MFA for enterprise identities under **GAP-007** further increases the value of valid credentials once stolen.
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Vector 5 — Unsecure Networks

**Vector Category:** Unsecure Networks

**MedDefense Evidence:**
The strongest technical evidence is the Network Scan Summary's confirmation that Central's endpoint, server, and medical-device “subnets” are addressing conventions rather than security boundaries: there is **no VLAN or firewall separation** between `10.10.1.0/24`, `10.10.2.0/24`, and `10.10.3.0/24`. The scan host at Corporate HQ could reach the other internal subnets without access restriction, proving that a device on one nominal segment can reach systems on another.
Westside adds a separate exposure. Its `10.10.10.0/24` environment reaches Central through an IPSec VPN terminating on a **Netgear consumer router**; the Asset Registry states that Westside has no dedicated firewall and relies on this device for both its internet edge and VPN connectivity.
Central also operates 12 UniFi APs supporting internal/guest wireless connectivity, while the physician iPad fleet's exact wireless segment is unknown. The prior registry specifically records undocumented Westside wireless equipment and unresolved iPad management, so wireless client/guest isolation should be treated as **not evidenced**, rather than assumed absent or correctly implemented.

**Affected Asset(s):**
Effectively the full MedDefense internal environment: Central workstations and servers, EHR, PACS/MRI, Active Directory, NAS/backup infrastructure, medical IoT, Central UniFi wireless environment, Westside systems and X-ray workstation, and systems reachable through site VPN trust.

**Actor Most Likely to Exploit:**
**Ransomware-as-a-Service affiliate / financially motivated lateral-movement actor.** This vector is most valuable after initial access because it converts a single compromised endpoint, remote site, or unmanaged device into a path toward multiple Critical systems.

**Exploitation Scenario:**
An attacker compromises a Westside workstation or exploits the consumer-grade perimeter and enters a network connected to Central through the trusted IPSec path. Because VPN permissions are broad and Central has no enforceable segmentation between ordinary endpoints, servers, and clinical IoT, the actor can enumerate and move toward `ehr-db-01`, Active Directory, PACS, NAS-01, or medical-device management interfaces rather than remaining contained at the original site.

**Current Protection:**
C-001 provides a default-deny perimeter firewall, C-003 limits recognized VPN source/destination networks, and C-027 provides encrypted site-to-site VPN tunnels. However, C-003 permits service `ALL` on approved VPN paths, while C-027 terminates Westside connectivity on the consumer router; neither control creates the missing internal security boundaries.
**Gap Reference:**
**GAP-003 — Network core remains exposed to unauthorized administrative control and insufficient internal isolation.**
**GAP-002 — Medical IoT is not adequately segmented, monitored, or recoverable.**
**GAP-006 — EHR database is reachable more broadly than operationally required.**
**GAP-017 — Westside Clinic security undermines Central protections.** The posture assessment specifically states that Westside's consumer router, unmanaged switch, server closet, and VPN trust path can provide a route toward Central systems.
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Vector 6 — Removable Devices / Unmanaged Endpoints

**Vector Category:** Removable Devices / Unmanaged Endpoints

**MedDefense Evidence:**
The task evidence identifies **no USB-restriction GPO**, leaving removable storage use without an evidenced organization-wide technical restriction. This is consistent with the Complete Control Matrix: C-026 proposes physical and removable-media restrictions specifically for the MRI workstation, but the control is rated Weak because deployment is not evidenced. GAP-014 likewise recommends removable-media restrictions as part of MedDefense's missing DLP capability.
The Asset Registry identifies approximately **25 physician iPads** used for EHR/PACS access, but MDM enrollment is unclear, the devices cannot be reconciled to the network scan, and their exact wireless segment is unknown. It also records an unmanaged intern laptop that operated on the internal network for three weeks while running a torrent client and was able to reach the HR file share.

Shadow IT extends the vector beyond conventional endpoints. The scan identifies `UNKNOWN-01` at `10.10.2.99` with SSH and web services on 8888/9090 and an undocumented Westside Linux system at `10.10.10.200` with SSH, HTTP, and port 3000; Westside personnel could not identify the latter's approved purpose. The posture assessment also adds the personally operated Cardiology research NAS, which can function as an unmanaged lateral-movement foothold.

**Affected Asset(s):**
Physician iPad fleet (AST-032); unmanaged intern laptop (AST-033); `UNKNOWN-01` (AST-013); Westside unknown Linux device (AST-014); personal Cardiology NAS (AST-057); HR/file-share environment; and any EHR, PACS, Active Directory, backup, or medical-device system reachable from those endpoints.

**Actor Most Likely to Exploit:**
**Insider/contractor-enabled threat or financially motivated ransomware actor using an unmanaged foothold.** The insider need not be malicious: an uncontrolled endpoint or removable device can introduce malware that is subsequently operated by an external ransomware affiliate.

**Exploitation Scenario:**
A personally managed laptop, unverified iPad, shadow server, or infected removable device connects to the internal environment without the control baseline applied to MedDefense-managed Windows endpoints. Malware on that endpoint can then exploit the flat network to discover file shares, database services, Active Directory, medical devices, or Restricted-data repositories; this is not hypothetical, because an unmanaged intern laptop previously remained connected for three weeks and could already reach the HR file share.

**Current Protection:**
C-011 Sophos antivirus provides useful detection on managed Windows 10/11 workstations, but it covers only 372 endpoints, only 88.1% have current signatures, and **servers and mobile platforms are excluded**. C-009 password policy and C-010 lockout may protect enterprise accounts used from those devices, but they do not establish device compliance, MDM enrollment, USB restrictions, patch status, or endpoint detection on the unmanaged systems themselves.

**Gap Reference:**
**GAP-005 — Personal Cardiology research NAS operates outside enterprise controls.**
**GAP-009 — HR and administrative access lacks adequate segmentation and strong authentication**, supported by the prior unmanaged-laptop access to the HR share.
**GAP-014 — No evidenced DLP for bulk Restricted-data extraction**, including the requirement for removable-media restrictions.
The unresolved iPad/MDM and other unmanaged-device findings also form part of the broader **shadow IT governance weakness** identified in the Security Posture Assessment.
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# 2. Overall Assessment

The six Security+ technical-vector categories do not operate independently at MedDefense. Their significance comes from the way they combine:

**outdated or unsupported software → exposed internal service → weak/shared credential or unmanaged endpoint → flat-network lateral movement → Critical clinical or identity asset → delayed detection.**

The Network Scan Summary provides direct evidence for every major stage except the attacker's actions themselves: active end-of-life systems, network-wide database and management ports, medical-device web interfaces, undocumented systems, and the absence of enforceable internal segmentation. The Asset Registry then identifies exactly what those technical paths lead to, including the Critical EHR/PACS/medical-device environment and shadow systems. The Criticality Assessment and Data Map establish that the destination systems either support patient care or contain Restricted PHI, diagnostic imaging, financial information, credentials, or bedside clinical data.
The Complete Control Matrix does not show an environment with no security controls. MedDefense has perimeter filtering, VPN controls, endpoint antivirus, authentication policy, backups, and local logging. The problem is coverage: workstation antivirus does not protect servers or mobile platforms; perimeter filtering does not create internal containment; local logs do not provide reliable centralized detection; and the MRI safeguards specifically designed to compensate for Windows XP remain proposed rather than operational.
Accordingly, the highest-priority technical vector is not one isolated port or operating system. It is the **combination of vulnerability exposure and unrestricted lateral reach**. GAP-011 permits avoidable vulnerabilities to persist, GAP-003/GAP-002 leave internal systems and medical devices insufficiently isolated, GAP-006 exposes the Critical EHR database more broadly than required, GAP-015 leaves medical-device administrative credentials insufficiently governed, and GAP-016 reduces MedDefense's ability to recognize successful exploitation before operational symptoms appear. This is the same structural weakness identified in the Project 1x00 posture assessment and therefore maintains direct continuity between the posture assessment and the external threat analysis.
