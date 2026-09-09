# MedDefense Health Systems

## STRIDE Threat Model for the EHR

# 1. STRIDE Threat Inventory

## S — Spoofing

### EHR-S1 — Stolen Clinician Credentials Used to Impersonate an Authorized EHR User

**Category:** S — Spoofing

**Threat ID:** EHR-S1

**Description:**
Malware or credential theft on a nurse, physician, pharmacy, laboratory, or other clinical endpoint could obtain a legitimate MedDefense identity. The attacker could then authenticate as that user and access the EHR under the clinician's identity rather than attempting to bypass the application anonymously. This is particularly credible because the posture assessment identifies incomplete MFA coverage and states that stolen credentials may remain useful after compromise.

**Attack Vector:**
**T8 — Removable Devices / Unmanaged Endpoints** combined with **T8 — Unsecure Networks**. Task 8 establishes that unmanaged endpoints can connect without MedDefense's normal endpoint baseline and can then enumerate Critical systems across the flat internal network. Approximately 25 physician iPads are used for EHR/PACS access, but their MDM status and exact wireless segmentation remain unresolved.

**Impact:**
The attacker could view patient records, place or modify entries under the clinician's identity, access medication or allergy information, or use the account as a foothold for further EHR activity. Because the EHR audit trail would initially record the legitimate clinician identity, unauthorized activity could appear to be authorized clinical activity.

**Existing Control:**

* **C-009 — Password requirements**
* **C-010 — Account lockout**
* **C-011 — Sophos antivirus** on managed Windows endpoints
* **C-016 — Security awareness training**

C-011 provides useful protection on managed Windows workstations but does not cover mobile platforms or unmanaged devices.

**Gap:**

* **GAP-007 — Active Directory relies on passwords without mandatory MFA or centralized alerting.**
* **GAP-016 — No centralized security monitoring or log-correlation capability.**

The identity-control weakness means possession of a stolen valid credential may still be sufficient to access dependent enterprise systems.

---

### EHR-S2 — Unauthorized Person Uses an Existing Authenticated Clinical Session

**Category:** S — Spoofing

**Threat ID:** EHR-S2

**Description:**
An unauthorized person gains physical access to an unattended clinical workstation on which a clinician has already authenticated to the EHR. The unauthorized user does not need to steal or crack the clinician's password; actions performed through the live session are attributed to the authenticated user.

This threat is directly supported by MedDefense's prior posture assessment, which records that **an unattended clinical workstation previously exposed an authenticated EHR session**.

**Attack Vector:**
**T8 — Removable Devices / Unmanaged Endpoints / endpoint-control exposure**, operating through an already authenticated clinical endpoint rather than through direct server exploitation.

**Impact:**
The unauthorized user could view PHI, inspect records unrelated to legitimate treatment, enter or change patient information, or leave the authenticated session in a state that causes later actions to be attributed to the clinician. In a clinical environment, the consequence is not limited to privacy: unauthorized modification could affect subsequent treatment.

**Existing Control:**

* **C-016 — Security awareness training**
* **C-017 — Physical/badge access controls**
* **C-018 — Local logging/audit evidence**

Password and lockout controls do not materially interrupt this scenario because the legitimate user has already authenticated.

**Gap:**

* **GAP-016 — No centralized security monitoring or log-correlation capability.**

No separate numbered EHR workstation-session gap is identified in the consolidated Gap Analysis; the unattended-session condition remains an evidenced subsidiary endpoint weakness. GAP-016 materially increases its significance because suspicious EHR activity may not be correlated promptly with endpoint or identity events.

---

# T — Tampering

### EHR-T1 — Direct Modification of EHR Records Through Broad PostgreSQL Reachability

**Category:** T — Tampering

**Threat ID:** EHR-T1

**Description:**
After compromising an ordinary workstation or another internal host, an attacker can directly reach PostgreSQL on `ehr-db-01` at `10.10.2.11:5432`. If the attacker subsequently obtains valid database credentials, the attacker could bypass normal EHR application workflows and directly modify rows containing patient medications, allergies, diagnoses, treatment information, or other clinical records.

Task 8 specifically identifies `ehr-db-01:5432` as reachable from the entire internal network and describes targeting stolen database credentials against that service after a workstation compromise.

**Attack Vector:**
**T8 — Open Service Ports** combined with **T8 — Unsecure Networks**.

**Impact:**
A clinician could make a treatment decision using data that appears legitimate but has been maliciously altered. Incorrect medication, allergy, diagnosis, or treatment information creates direct patient-safety risk. Unlike a visible outage, integrity compromise may remain undetected while clinicians continue trusting the system.

**Existing Control:**

* **C-001 — Default-deny perimeter firewall**
* **C-004 — Firewall traffic logging**
* **C-005 through C-008 — Strong SSH hardening controls on `ehr-srv-01`**
* **C-012 — Veeam backup**
* **C-018 — Local logging**

These controls provide useful perimeter, administrative-access, detective, and recovery capabilities but do not restrict PostgreSQL to the application server.

**Gap:**

* **GAP-006 — EHR database is reachable from more systems than operationally required.**
* **GAP-016 — No centralized security monitoring or log correlation.**

GAP-006 specifically requires a database network allow-list that restricts PostgreSQL principally to `ehr-srv-01`.

---

### EHR-T2 — Compromised Clinician Endpoint Alters Records Through Legitimate EHR Functions

**Category:** T — Tampering

**Threat ID:** EHR-T2

**Description:**
Malware controlling a clinical workstation can operate inside an authenticated clinician session and use normal EHR application functions to change patient records. Rather than attacking PostgreSQL directly, the attacker submits apparently legitimate changes through `ehr-srv-01`, causing the application itself to commit malicious data to `ehr-db-01`.

This path is important because the EHR application may correctly process the transaction technically while the human identity associated with the transaction has been compromised.

**Attack Vector:**
**T8 — Removable Devices / Unmanaged Endpoints**, followed by **T8 — Unsecure Networks**.

Task 8 demonstrates that unmanaged or uncontrolled endpoints can operate inside MedDefense's flat network and reach EHR and other Critical assets.

**Impact:**
An attacker could alter medication lists, allergy information, clinical notes, diagnoses, orders, or other treatment-relevant fields. The change may appear to have been entered by the clinician whose session was compromised, increasing the risk that corrupted information is accepted as clinically trustworthy.

**Existing Control:**

* **C-009 — Password policy**
* **C-010 — Account lockout**
* **C-011 — Sophos antivirus on managed Windows workstations**
* **C-018 — Local EHR/audit logging**
* **C-012 — Backup**, providing recovery after detected corruption

**Gap:**

* **GAP-007 — Lack of mandatory MFA and centralized identity alerting**
* **GAP-016 — No centralized security monitoring or log correlation**

Centralized correlation is particularly important because endpoint compromise, abnormal login behavior, and unusual EHR record changes currently reside in separate logging sources.

---

# R — Repudiation

### EHR-R1 — User Alters a Patient Record and Later Denies Performing the Action

**Category:** R — Repudiation

**Threat ID:** EHR-R1

**Description:**
A malicious insider or an attacker using a legitimate clinician account modifies a patient's EHR record and later denies responsibility. MedDefense has EHR audit records, but those records are decentralized rather than centrally correlated with identity, workstation, firewall, and server telemetry.

The Data Map establishes that MedDefense maintains firewall, SSH, Windows, Linux, Apache, and EHR audit records, but lacks centralized forwarding, SIEM correlation, and automated alerting.

**Attack Vector:**
**T8 — Unsecure Networks**, using a legitimate or compromised account from an internal clinical endpoint.

**Impact:**
MedDefense may be unable to establish quickly whether a clinically significant change was made by the clinician, by another person using the clinician's session, or by an attacker using stolen credentials. This creates patient-safety, investigation, disciplinary, legal, and regulatory consequences.

**Existing Control:**

* **C-018 — Local logging/audit evidence**
* **C-004 — Firewall traffic logging**
* **C-009 — Named-account password controls**, where individual accounts are used

**Gap:**

* **GAP-016 — No centralized security monitoring or log-correlation capability.**

The gap affects the evidentiary value of otherwise useful logs because events must be reconstructed manually across systems rather than correlated automatically.

---

### EHR-R2 — Attacker Deletes or Alters Local EHR/Server Logs After Compromise

**Category:** R — Repudiation

**Threat ID:** EHR-R2

**Description:**
An attacker who obtains privileged access to `ehr-srv-01` or another EHR component could tamper with locally stored audit or system logs to conceal the path used to access patient records. Because logs are not centrally forwarded to an independently controlled repository, compromise of the host can also compromise part of the evidence required to reconstruct the incident.

**Attack Vector:**
**T8 — Open Service Ports** and **T8 — Unsecure Networks**, following lateral movement to the EHR environment.

**Impact:**
MedDefense could lose the ability to determine which records were accessed or changed, which account performed the activity, how long the attacker remained present, and whether PHI disclosure occurred. This could delay containment and complicate breach assessment and regulatory notification.

**Existing Control:**

* **C-007 — EHR/SSH-related logging control**
* **C-018 — Local logging**
* **C-004 — Firewall traffic logging**
* **C-005 through C-008 — SSH hardening**, reducing direct administrative compromise

**Gap:**

* **GAP-016 — No centralized security monitoring or log-correlation capability.**

This gap is classified as Critical enterprise-wide because a successful compromise may remain undetected until operational symptoms appear.

---

# I — Information Disclosure

### EHR-I1 — Bulk PHI Exfiltration Directly from `ehr-db-01`

**Category:** I — Information Disclosure

**Threat ID:** EHR-I1

**Description:**
An attacker with an internal foothold can establish network communication directly with `ehr-db-01:5432`. If database credentials are stolen or otherwise obtained, the attacker could query and export Restricted patient medical records without routing those queries through the expected EHR application path on `ehr-srv-01`.

The Data Map further records that encryption at rest for the EHR database is **not evidenced**. This assessment does not assume encryption is absent; it records that the posture assessment could not validate that control.

**Attack Vector:**
**T8 — Open Service Ports** plus **T8 — Unsecure Networks**.

**Impact:**
Large volumes of Restricted PHI could be exposed, creating privacy breach notification requirements, investigation costs, legal/regulatory exposure, and loss of patient trust. Direct database access may also expose more information than the compromised user's normal EHR role would display.

**Existing Control:**

* **C-001 — Perimeter firewall**
* **C-003 — VPN source restrictions**
* **C-004 — Firewall logging**
* **C-005 through C-008 — SSH hardening**
* **C-018 — Local audit logging**

**Gap:**

* **GAP-006 — EHR database overly broad internal reachability**
* **GAP-014 — No evidenced DLP for bulk Restricted-data extraction**
* **GAP-016 — No centralized security monitoring/log correlation**

GAP-014 specifically identifies EHR data and the risk that a valid or compromised user could extract large volumes of PHI without alerting.

---

### EHR-I2 — PHI Exposure Through an Unmanaged Physician iPad or Other Uncontrolled Clinical Endpoint

**Category:** I — Information Disclosure

**Threat ID:** EHR-I2

**Description:**
The Asset Registry identifies approximately 25 physician iPads used for EHR/PACS access, but MDM enrollment cannot be confirmed and their exact wireless segment is unresolved. A compromised, lost, or otherwise uncontrolled device with EHR credentials or an active authenticated session could expose patient information outside the protection baseline applied to managed Windows workstations.

This threat does not assume that PHI is permanently stored on the iPad; the exposure can occur through credentials, cached/session information, or authenticated application access.

**Attack Vector:**
**T8 — Removable Devices / Unmanaged Endpoints**.

**Impact:**
An unauthorized party could view patient records through the physician's legitimate access path or capture information presented through the EHR session. If the device is malware-infected, the attacker could also collect credentials and use them from another system.

**Existing Control:**

* **C-009 — Password policy**
* **C-010 — Account lockout**
* **C-016 — Security awareness**

**C-011 Sophos antivirus does not provide the required compensating control because mobile platforms are outside its documented scope.**

**Gap:**

* **GAP-014 — No evidenced DLP for bulk Restricted-data extraction**
* **GAP-016 — No centralized security monitoring/log correlation**

The unresolved iPad/MDM condition is also part of the broader shadow-IT and unmanaged-device governance weakness documented in the posture assessment; it is not represented by a dedicated EHR-specific numbered gap.

---

# D — Denial of Service

### EHR-D1 — Ransomware Encrypts `ehr-srv-01` and/or `ehr-db-01`

**Category:** D — Denial of Service

**Threat ID:** EHR-D1

**Description:**
A ransomware affiliate compromises an initial MedDefense endpoint or vulnerable internal system and then traverses the flat network toward the EHR. The attacker encrypts `ehr-srv-01`, `ehr-db-01`, or both, removing clinical access to patient records.

This chain is consistent with Task 8's demonstrated pattern: exploitable or uncontrolled systems can provide an internal foothold, after which unrestricted internal connectivity exposes Critical systems. MedDefense's own billing server has already experienced ransomware and a subsequent malware compromise, demonstrating that malware execution inside the environment is not theoretical.

**Attack Vector:**
Combination of:

* **T8 — Vulnerable Software**
* **T8 — Removable Devices / Unmanaged Endpoints**
* **T8 — Unsecure Networks**
* **T8 — Open Service Ports**

**Impact:**
Clinicians lose access to the EHR and must revert to downtime procedures. MedDefense has already experienced a **nine-hour EHR outage that required paper records**, demonstrating the immediate clinical consequence of EHR unavailability. A ransomware event could last substantially longer if recovery infrastructure is also affected.

**Existing Control:**

* **C-001 — Perimeter firewall**
* **C-011 — Sophos antivirus on managed Windows endpoints**
* **C-012 — Nightly Veeam backup**
* **C-018 — Local logging**

**Gap:**

* **GAP-004 — Production and backup copies share the same failure domain**
* **GAP-006 — Excessive internal reachability to the EHR database**
* **GAP-016 — No centralized security monitoring/log correlation**

C-012 reduces the impact of data destruction, but GAP-004 establishes that backup copies remain in the same network and physical environment as production, allowing ransomware to threaten both operational data and recovery capability.

---

### EHR-D2 — Network-Core or Westside Path Compromise Makes the EHR Unreachable

**Category:** D — Denial of Service

**Threat ID:** EHR-D2

**Description:**
An attacker who gains administrative control over FortiGate/Cisco infrastructure, or compromises the weak Westside trust path, could alter routing, firewall, switching, or VPN configuration so that clinical workstations cannot reach `ehr-srv-01`. The EHR application and database could remain technically operational while clinicians are unable to access them.

This threat is within the EHR system model because the network connection between clinical endpoints and the EHR is a required EHR dependency.

**Attack Vector:**
**T8 — Unsecure Networks.**

Task 8 records that Westside uses an IPSec VPN terminating on a consumer-grade Netgear router and that the Central environment lacks enforceable internal segmentation.

**Impact:**
A routing or VPN disruption could disconnect clinical workstations, Westside users, or entire network segments from the EHR, forcing paper workflows and reducing coordinated access to patient information. The previous nine-hour EHR outage demonstrates that loss of access produces immediate clinical degradation.

**Existing Control:**

* **C-001 — Default-deny firewall**
* **C-003 — VPN source restrictions**
* **C-027 — Encrypted site-to-site VPN tunnels**
* **C-020 — Infrastructure UPS**

C-003 and C-027 provide useful perimeter/site controls but do not create the missing internal segmentation, and C-003 permits service `ALL` on approved VPN paths.

**Gap:**

* **GAP-003 — Network core exposed to unauthorized administrative control and insufficient internal isolation**
* **GAP-017 — Westside Clinic security undermines Central protections**

GAP-003 explicitly recognizes that unauthorized changes to routing, switching, firewall, or VPN configuration can affect numerous downstream systems, including the EHR.

---

# E — Elevation of Privilege

### EHR-E1 — Compromised Endpoint Escalates Through Active Directory to Privileged EHR Access

**Category:** E — Elevation of Privilege

**Threat ID:** EHR-E1

**Description:**
An attacker begins with control of an ordinary clinician or administrative endpoint and uses the flat internal network to reach Active Directory. Stolen credentials, tokens, or other authentication material are then used to obtain a privileged domain identity. Once elevated, the attacker can use the stronger identity to administer or access EHR systems beyond the rights available to the originally compromised user.

The Criticality Assessment identifies Active Directory as an enterprise authentication dependency whose compromise can permit account creation, privilege changes, credential resets, and persistent access across departments.

**Attack Vector:**
Combination of:

* **T8 — Removable Devices / Unmanaged Endpoints**
* **T8 — Unsecure Networks**
* **T8 — Open Service Ports**

**Impact:**
A compromise that begins with one clinician can become privileged control over `ehr-srv-01`, EHR identities, or related database access. The attacker may then disable accounts, access Restricted PHI, alter patient records, install persistence, or prepare ransomware deployment.

**Existing Control:**

* **C-009 — Password policy**
* **C-010 — Account lockout**
* **C-005 through C-008 — Strong SSH controls on `ehr-srv-01`**
* Windows/AD event logging
* **C-018 — Local logging**

**Gap:**

* **GAP-007 — No mandatory MFA or centralized AD alerting**
* **GAP-003 — Insufficient internal isolation**
* **GAP-016 — No centralized security monitoring/log correlation**

The Gap Analysis specifically concludes that possession of valid stolen credentials may still be sufficient for access and that AD misuse may not be identified promptly through local logs alone.

---

### EHR-E2 — Former Employee or Contractor Retains Privileged EHR Access After Authorization Ends

**Category:** E — Elevation of Privilege

**Threat ID:** EHR-E2

**Description:**
A former employee, contractor, or transferred staff member retains an active EHR, AD, or VPN account because deprovisioning is not reliably integrated with HR termination processes. The user therefore continues exercising capabilities that are no longer authorized.

This is an elevation-of-privilege condition because the account holder possesses effective system capabilities beyond their current organizational authorization, even if no software exploit is required.

**Attack Vector:**
**T8 — Unsecure Networks**, potentially using MedDefense's remote/VPN trust path with still-valid credentials.

**Impact:**
A former privileged user could access EHR PHI, alter clinical records, create persistence, or misuse administrative functions after the business authorization for that access has ended. Because the credentials remain technically valid, the activity may initially appear legitimate.

**Existing Control:**

* **C-009 — Password policy**
* **C-010 — Account lockout**
* **C-003 — VPN source restrictions**
* **C-027 — Encrypted site-to-site VPN controls**
* **C-018 — Local logging**

These controls govern authentication and connectivity but do not ensure that authorization is revoked promptly when employment or contractual status changes.

**Gap:**

* **GAP-013 — User offboarding is not evidenced as automated or HR-integrated**
* **GAP-007 — No mandatory MFA for enterprise identities**
* **GAP-016 — No centralized security monitoring/log correlation**

GAP-013 explicitly identifies **AD, VPN, EHR, and administrative accounts** as affected and states that former employees or contractors could retain valid access after authorization ends.

---

# 2. STRIDE Coverage Summary

| STRIDE Category            | Threat ID | Primary MedDefense-Specific Exposure                                    |
| -------------------------- | --------- | ----------------------------------------------------------------------- |
| **Spoofing**               | EHR-S1    | Stolen clinician credentials used without mandatory MFA                 |
| **Spoofing**               | EHR-S2    | Unauthorized use of an existing authenticated clinical session          |
| **Tampering**              | EHR-T1    | Direct record modification through broadly reachable `ehr-db-01:5432`   |
| **Tampering**              | EHR-T2    | Malicious record changes through a compromised authenticated endpoint   |
| **Repudiation**            | EHR-R1    | User or compromised account denies EHR changes                          |
| **Repudiation**            | EHR-R2    | Local audit evidence altered or deleted after server compromise         |
| **Information Disclosure** | EHR-I1    | Bulk PHI extraction directly from PostgreSQL                            |
| **Information Disclosure** | EHR-I2    | PHI exposure through unmanaged physician/mobile endpoint                |
| **Denial of Service**      | EHR-D1    | Ransomware encrypts EHR application/database                            |
| **Denial of Service**      | EHR-D2    | Network/VPN manipulation removes clinician access to EHR                |
| **Elevation of Privilege** | EHR-E1    | Endpoint compromise escalates through AD to privileged EHR access       |
| **Elevation of Privilege** | EHR-E2    | Stale former-user account retains capabilities after authorization ends |

---

# 3. STRIDE Summary for EHR

**Tampering represents the greatest STRIDE risk to the MedDefense EHR.** Denial of Service has a demonstrated clinical consequence—the previous nine-hour EHR outage forced clinicians onto paper records—and Information Disclosure would expose Restricted PHI, but an integrity compromise can be more dangerous because the system may remain fully available while presenting clinicians with false information. The Criticality Assessment specifically identifies medication, allergy, diagnosis, and treatment information as areas where unauthorized modification can directly affect care. That risk is intensified by **GAP-006**, because `ehr-db-01:5432` is reachable from systems that have no operational requirement to communicate directly with the database, and by **GAP-016**, because EHR audit records are not centrally correlated with endpoint, identity, and network telemetry. An attacker who compromises a clinical endpoint and obtains database or privileged credentials could therefore alter patient information without causing an obvious outage. In a healthcare environment, that combination is particularly dangerous: clinicians are trained to rely on the EHR as the authoritative patient record, so corrupted information can influence treatment precisely because the system still appears to be functioning normally.
