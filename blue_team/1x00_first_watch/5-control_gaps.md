# The Missing Pieces

## MedDefense Health Systems Control Gap Analysis

The Control Summary Matrix shows that MedDefense has **16 identified controls**, but coverage is uneven across security functions and asset classes. Technical preventive controls dominate the environment, while several administrative, corrective, compensating, and physical functions have no evidenced controls at all. 

### Gap ID: G-001

**Gap Description:**
No administrative detective control is documented. MedDefense has administrative preventive controls in the form of the password policy and security awareness training, but there is no evidenced administrative process for identifying, reviewing, or escalating security incidents, policy violations, suspicious user behavior, or control failures.

**Category × Function Missing:**
Administrative × Detective

**Affected Asset(s) or Zone:**
All MedDefense systems, users, and locations, including Corporate HQ, MedDefense Central, and Westside Clinic.

**Risk if Unaddressed:**
Security events may occur without being recognized or formally escalated. This threatens **confidentiality** if unauthorized access to patient or business information is not identified, **integrity** if inappropriate changes are not investigated, and **availability** if operational disruptions are not recognized early enough for effective response. Preventive policies alone cannot determine whether a control has been bypassed or violated.

**Evidence:**
The Control Summary Matrix contains no Administrative Detective control. The only administrative controls identified are C-009, Password Complexity, Rotation and History Policy, and C-016, Security Awareness Training Program, both classified as preventive. The inventory specifically notes that no documented incident-response-related administrative control was evidenced.  

---

### Gap ID: G-002

**Gap Description:**
No administrative corrective control is documented. Although MedDefense has a technical backup mechanism, there is no evidenced administrative procedure defining how personnel should contain an incident, coordinate recovery, assign responsibilities, communicate during an event, or return operations to normal.

**Category × Function Missing:**
Administrative × Corrective

**Affected Asset(s) or Zone:**
Enterprise-wide operations, including the EHR environment, billing systems, Active Directory, file services, public web services, and the workforce responsible for incident recovery.

**Risk if Unaddressed:**
An incident may be technically recoverable but operationally unmanaged. This creates an **availability** risk because recovery can be delayed by unclear responsibilities and procedures; an **integrity** risk because systems could be restored incorrectly or before the cause of compromise is contained; and a **confidentiality** risk if compromised accounts, systems, or access paths remain active during recovery.

**Evidence:**
The Administrative Corrective cell in the matrix is empty. The inventory explicitly states that no documented incident response plan was provided. C-012 provides technical backups, but it does not constitute an administrative incident recovery procedure.  

---

### Gap ID: G-003

**Gap Description:**
No administrative compensating control is documented. MedDefense has known weaknesses, including the absence of mandatory MFA for remote access, but the matrix contains no administrative procedure designed to compensate for such weaknesses through additional approvals, monitoring requirements, access restrictions, or exception-management processes.

**Category × Function Missing:**
Administrative × Compensating

**Affected Asset(s) or Zone:**
Remote-access users, Windows domain accounts, VPN-accessible systems, and internal servers.

**Risk if Unaddressed:**
Where a preferred safeguard cannot be implemented, MedDefense lacks a documented procedural fallback. This increases **confidentiality** and **integrity** risk because compromised credentials may provide unauthorized access without an administrative layer requiring additional verification or review. The existing account lockout control reduces repeated password guessing but does not compensate for credential theft or successful phishing to the same extent as MFA.

**Evidence:**
C-010 is identified as a **Technical Compensating** control for the absence of mandatory MFA, but the Administrative Compensating cell remains empty. The underlying password policy only recommends MFA rather than requiring it.  

---

### Gap ID: G-004

**Gap Description:**
Endpoint antivirus does not cover servers, macOS devices, or mobile devices. C-011 protects Windows 10/11 workstations only, leaving several classes of endpoints and critical servers outside the evidenced malware detection capability.

**Category × Function Missing:**
Technical × Detective

**Affected Asset(s) or Zone:**
Windows and Linux servers, including critical server infrastructure where applicable, together with macOS and mobile devices.

**Risk if Unaddressed:**
Malware executing on an uncovered system may remain undetected. On critical servers, this could expose sensitive information and therefore affect **confidentiality**, allow unauthorized modification or ransomware encryption and therefore affect **integrity**, and interrupt applications or infrastructure and therefore affect **availability**. The gap is especially significant because server systems include core business services.

**Evidence:**
C-011 covers 372 managed Windows 10/11 workstations and explicitly excludes Windows/Linux servers, macOS, and mobile devices. The same control record also shows that antivirus coverage is not universal even within the managed device population. 

---

### Gap ID: G-005

**Gap Description:**
Firewall and SSH logs are generated locally, but no centralized log forwarding or retention capability is evidenced. MedDefense therefore has some technical detective controls, but their effectiveness is limited because evidence remains on the systems or devices that an attacker may compromise.

**Category × Function Missing:**
Technical × Detective — centralized monitoring and log aggregation coverage

**Affected Asset(s) or Zone:**
Firewall-protected network zones, VPN ingress, internet-facing traffic, ehr-srv-01, and other systems for which centralized event correlation would be required.

**Risk if Unaddressed:**
An attacker who bypasses preventive controls may operate for longer before being detected because events are not centrally correlated. Local logs can also be deleted or altered after system compromise, weakening **integrity** of forensic evidence. Delayed detection increases the potential impact on **confidentiality**, **integrity**, and **availability** because malicious activity can continue without an enterprise-wide monitoring capability.

**Evidence:**
C-004 records firewall traffic locally, but the inventory states that logs are not forwarded or centrally retained. C-007 records detailed SSH authentication events on ehr-srv-01, but those logs are likewise not forwarded to a central system.  

---

### Gap ID: G-006

**Gap Description:**
The backup control exists, but there is no evidenced recurring recovery-testing process for the critical systems protected by the backup job. Only one restore of file-srv-01 is documented, and that test occurred eight months ago; no restore test is identified for the EHR application, EHR database, billing system, domain controller, or web server.

**Category × Function Missing:**
Technical × Corrective — validated recovery capability across critical assets

**Affected Asset(s) or Zone:**
ehr-srv-01, ehr-db-01, billing-srv-01, ad-dc-01, and web-srv-01; potentially file-srv-01 if its previous test no longer reflects the current environment.

**Risk if Unaddressed:**
Backups may exist but fail when actually required because of corruption, configuration changes, incomplete dependencies, or an unverified restoration process. This creates a major **availability** risk because critical healthcare and business systems may not be recoverable within an acceptable period. It also creates an **integrity** risk if restored data is incomplete, inconsistent, or unusable.

**Evidence:**
C-012 backs up six critical virtual machines nightly with 14-day retention, but the only documented successful restore was for file-srv-01 eight months earlier. No recovery validation is identified for the remaining critical systems. 

---

### Gap ID: G-007

**Gap Description:**
Physical detective coverage does not include the server room, network closets, or administrative wing. CCTV exists, but it is concentrated at entrances and the parking garage rather than around critical infrastructure.

**Category × Function Missing:**
Physical × Detective

**Affected Asset(s) or Zone:**
Server room, network closets, administrative wing, and the critical information systems physically located in those areas.

**Risk if Unaddressed:**
Unauthorized physical access, equipment tampering, theft, or sabotage in critical internal areas may occur without video evidence. This can affect **confidentiality** if storage devices or systems containing sensitive information are accessed, **integrity** if hardware or configurations are altered, and **availability** if servers or network equipment are damaged, disconnected, or removed.

**Evidence:**
C-015 provides cameras at MedDefense Central's main entrance, ER entrance, parking garage entrance, and Westside Clinic's front entrance. The control description explicitly states that CCTV does **not** cover the server room, network closets, or administrative wing. 

---

### Gap ID: G-008

**Gap Description:**
No physical corrective control is evidenced for restoring or protecting critical infrastructure after a physical or environmental event. In particular, no documented fire suppression, environmental protection, or alternate-site arrangement exists for the server room.

**Category × Function Missing:**
Physical × Corrective

**Affected Asset(s) or Zone:**
Server room, network infrastructure, and systems physically hosted at MedDefense facilities.

**Risk if Unaddressed:**
A fire, environmental failure, or other physical event could damage critical infrastructure without an evidenced physical mechanism for limiting damage or supporting recovery. The principal impact is to **availability**, because critical healthcare and business services could become inaccessible. **Integrity** may also be affected if storage or systems are physically damaged and data becomes corrupted.

**Evidence:**
The Physical Corrective cell in the matrix is empty. The observations accompanying the matrix specifically state that no fire suppression, environmental control, or alternate-site arrangement was documented for the server room.  

---

### Gap ID: G-009

**Gap Description:**
Physical preventive access control at the main entrance is limited to staffed hours. Visitor registration and badge verification operate only Monday through Friday from 07:00 to 19:00, leaving no evidenced equivalent preventive control for the same entrance outside those hours.

**Category × Function Missing:**
Physical × Preventive — after-hours coverage

**Affected Asset(s) or Zone:**
MedDefense Central main entrance and lobby outside weekday staffed hours.

**Risk if Unaddressed:**
If no separate after-hours access control exists, unauthorized individuals may have an increased opportunity to enter the facility without visitor registration or badge verification. Successful physical intrusion could threaten **confidentiality** through access to sensitive information, **integrity** through tampering with systems or records, and **availability** through theft, sabotage, or equipment damage.

**Evidence:**
C-014 protects the MedDefense Central main entrance and lobby specifically **during staffed hours, weekdays 07:00–19:00**. No additional after-hours physical preventive control is identified in the matrix or control inventory. 

## Overall Pattern

MedDefense's security posture is **predominantly prevention-oriented**: six Technical Preventive controls and two Administrative Preventive controls are documented, while several detective and corrective functions are absent or only partially implemented.  This means that if an attacker bypasses the existing preventive controls, MedDefense has comparatively weak capabilities to identify the intrusion quickly, coordinate a structured response, and demonstrate that critical systems can be reliably recovered, increasing the potential duration and impact of a security incident.
