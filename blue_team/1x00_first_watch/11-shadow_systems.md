# The Shadow Systems — Shadow IT Risk Assessment

## 1. Personal NAS — Dr. Patel, Cardiology

### Risk Assessment

**Sensitive data that may be stored or accessed**

The personal NAS may contain **Restricted clinical or research data**, including patient identifiers, cardiology test results, imaging-related information, study records, research datasets derived from patient care, or other protected health information (PHI). The available information establishes only that Dr. Patel stores “research data,” so the presence of PHI should not be stated as confirmed. However, because the device is operated by a Cardiology physician within a hospital and is being used as an alternative to the hospital shared drive, it is reasonable to treat the contents as potentially sensitive until a data review proves otherwise. MedDefense already classifies patient medical records and medical imaging information as Restricted because unauthorized disclosure could create regulatory consequences and clinical harm.

The NAS also provides an additional network-accessible storage endpoint inside MedDefense Central. Because the current network architecture is effectively flat, compromise of the NAS would not necessarily remain limited to the research data stored locally. The Asset Registry specifically identifies broad internal reachability as a reason unmanaged systems create elevated enterprise risk.

**Official controls that do not adequately cover the system**

Several controls in the Task 10 matrix do not provide meaningful protection to this NAS:

* **C-011 — Sophos Endpoint Antivirus:** This control covers managed Windows 10/11 workstations and explicitly excludes servers and other platforms. A personally purchased NAS therefore falls outside the evidenced endpoint-malware protection scope.
* **C-012 — Nightly Veeam Backup Job:** The backup scope is limited to six specified Central virtual machines. A personally owned NAS is not included, so there is no evidenced managed backup or tested recovery process for the research data.
* **C-018 — Local Operating-System and Application Audit Logging:** Although the matrix identifies logging on managed Windows and Linux systems, MedDefense has no evidence that the personal NAS has equivalent audit logging enabled, retained, reviewed, or centrally monitored. The existing logging control is already rated Weak because records are largely local and there is no SIEM or automated correlation.
* **C-009/C-010 — Password Policy and Account Lockout:** These controls apply to MedDefense accounts and Windows/domain accounts. A personally administered NAS may use local credentials selected and managed outside Active Directory, so MedDefense cannot assume that password, lockout, access-review, or account-termination requirements are enforced.
* **C-001/C-004 — Firewall Enforcement and Firewall Logging:** These controls provide useful perimeter protection, but they do not solve the principal risk created by a device already attached to the internal network. MedDefense’s internal environment remains broadly reachable, so perimeter filtering does not prevent lateral communication between the NAS and internal systems.

**Worst-case scenario**

The worst credible scenario is compromise of the NAS followed by both **data disclosure and lateral movement**. An attacker could obtain research information containing PHI, encrypt or destroy the only unmanaged copy of the research data, and use the NAS as a persistent foothold from which to identify or attack EHR, PACS, Active Directory, file services, or medical devices. The severity is increased by the lack of evidenced endpoint detection, centralized monitoring, managed backups, and internal segmentation. A compromise would therefore potentially affect confidentiality through PHI exposure, integrity through alteration of research data, and availability through ransomware or destruction.

### Recommended Response — **Migrate**

The appropriate response is to **migrate the research data to an approved MedDefense-managed storage platform and remove the personal NAS from the production network**.

Migration is preferable to legitimization because the business requirement is storage performance, not the personal NAS itself. MedDefense can address the underlying complaint that the shared drive is too slow by assigning Cardiology an approved high-performance research share, managed NAS, or other sanctioned research-storage service with appropriate capacity and performance. This preserves the legitimate clinical-research requirement while eliminating a personally owned device whose patching, administrator credentials, logging, backup, encryption, lifecycle, and physical disposition are outside IT control.

Before the NAS is disconnected, IT and Security should inventory its contents, determine whether PHI or other Restricted data is present, validate ownership and retention requirements, transfer the data securely, verify that the migrated copy is complete, and securely erase any MedDefense data remaining on the personal device.

### Asset Registry Update

| Asset ID    | Name                            | Type       | Location                             | Owner (Dept)           | OS/Platform                   | Critical Services                | Network Segment                                           | Status        | Notes                                                                                                                                                                                                                                                                                                                                                                                                        |
| ----------- | ------------------------------- | ---------- | ------------------------------------ | ---------------------- | ----------------------------- | -------------------------------- | --------------------------------------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **AST-057** | Dr. Patel Personal Research NAS | Data Store | Central Hospital — Cardiology office | Cardiology / Dr. Patel | Unknown personal NAS platform | Cardiology research-data storage | Central internal network; exact IP/MAC pending validation | **Shadow IT** | Personally purchased NAS connected to a hospital wall port without formal IT approval. May contain sensitive research data or PHI. Not evidenced as covered by managed endpoint protection, Veeam backup, centralized logging, or MedDefense identity controls. Recommended action: migrate data to approved managed storage, validate transfer, securely erase organizational data, and disconnect the NAS. |

---

## 2. Marketing Shared Google Drive — Personal Gmail Account

### Risk Assessment

**Sensitive data that may be stored or accessed**

The shared Google Drive may contain **Confidential business information**, including unreleased press statements, media strategy, executive communications, campaign materials, contact lists, internal announcements, photographs, and embargoed communications.

There is also a plausible possibility that Marketing stores patient photographs, testimonials, event material, or patient-related communications in the Drive. If those materials contain identifiable health information, their sensitivity would increase substantially. The supplied evidence does not establish that such PHI is present, so it should be verified rather than assumed.

The principal governance concern is that the Drive is linked to an employee’s **personal Gmail account**. Consequently, MedDefense may not control the account lifecycle, password policy, MFA configuration, sharing permissions, audit records, retention settings, legal hold capabilities, or recovery mechanism. If the individual leaves the organization, loses the account, or changes credentials, MedDefense could lose both access and administrative control over organizational information.

**Official controls that do not adequately cover the system**

* **C-009 — Password Complexity, Rotation and History Policy:** MedDefense cannot enforce its enterprise password requirements against a personally controlled Google account.
* **C-010 — Account Lockout Policy:** This control is implemented through Active Directory for Windows/domain and remote-access accounts. It does not govern a personal Gmail identity.
* **C-011 — Sophos Endpoint Antivirus:** Endpoint antivirus may protect some Windows computers used to access the Drive, but it does not govern the cloud repository itself, its sharing permissions, account ownership, or data retention.
* **C-012 — Nightly Veeam Backup Job:** The Google Drive is outside the six-VM Veeam backup scope, so MedDefense has no evidenced enterprise backup or tested recovery mechanism for the marketing repository.
* **C-018 — Local Audit Logging:** Local operating-system and application logs do not provide MedDefense with authoritative administrative audit visibility into activity occurring inside a personally owned Google account.
* **C-027 — Site-to-Site VPN Tunnels:** VPN protection applies to communications among MedDefense sites. It does not establish governance or administrative control over an external cloud service owned through a personal account.
* **C-016 — Security Awareness Training:** Training applies to the workforce, but its existence has not prevented this practice, and completion is uneven. It is therefore an administrative influence rather than a technical control over the Drive.

**Worst-case scenario**

The worst credible scenario is compromise or loss of the personal Gmail account resulting in unauthorized disclosure, deletion, or public release of MedDefense communications and media. If patient-related material is present, the incident could also become a PHI disclosure. Because the account is personally controlled, an attacker or former employee could alter sharing permissions, permanently delete information, impersonate Marketing through stored communications, or prevent MedDefense from recovering the repository.

The risk is therefore not limited to confidentiality. Integrity is threatened because unauthorized users could modify official communications or media, while availability is threatened because the organization could lose access to materials required for public communications during a crisis.

### Recommended Response — **Migrate**

The appropriate response is to **migrate the Marketing repository to an organization-approved, enterprise-controlled collaboration platform**.

Migration is preferable to attempting to secure the current Drive because the primary defect is ownership. Even strong settings on the existing Drive would leave the root administrative identity under personal rather than organizational control. MedDefense should use an enterprise account in which IT can enforce authentication requirements, control external sharing, retain audit logs, recover accounts, apply retention requirements, and revoke access when personnel leave.

Before migration, Marketing and IT should inventory all files and current sharing relationships, identify any patient or other Restricted information, transfer approved content, recreate only legitimate external-sharing permissions, preserve required records, validate access, and then remove MedDefense content from the personal account.

### Asset Registry Update

| Asset ID    | Name                                             | Type                       | Location                                               | Owner (Dept) | OS/Platform                                   | Critical Services                                | Network Segment          | Status        | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ----------- | ------------------------------------------------ | -------------------------- | ------------------------------------------------------ | ------------ | --------------------------------------------- | ------------------------------------------------ | ------------------------ | ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **AST-058** | Marketing Shared Google Drive — Personal Account | Cloud Service / Data Store | External cloud service; used by Corporate HQ Marketing | Marketing    | Google Drive linked to personal Gmail account | Marketing media storage and press communications | Internet / external SaaS | **Shadow IT** | Shared Marketing repository is controlled through a personal Gmail identity rather than an organization-managed account. MedDefense cannot evidence enforcement of corporate identity controls, enterprise backup, centralized audit administration, retention, or lifecycle management. Recommended action: migrate content to an approved organization-controlled collaboration platform and remove MedDefense data from the personal account after validation. |

---

## 3. Raspberry Pi — Central Hospital Second Floor

### Risk Assessment

**Sensitive data that may be stored or accessed**

The Raspberry Pi was reportedly installed as a network-monitoring system. A network monitor can provide access to security-sensitive information even when it does not store ordinary business records. Depending on its configuration, it may contain or expose:

* IP addresses, hostnames, device identities, operating-system information, and service information;
* internal network topology and communication relationships;
* system logs and monitoring histories;
* packet captures containing application or authentication traffic;
* administrator credentials, API keys, SNMP community strings, or monitoring-service credentials;
* information showing which clinical and infrastructure systems are active and how they communicate.

This data would substantially reduce the reconnaissance effort required by an attacker. If the device captures traffic rather than merely collecting basic availability metrics, it could also contain patient or authentication information transmitted across monitored network paths.

The network scan identified `10.10.2.99 / UNKNOWN-01`, a Linux 4.x system with SSH and two web services on ports 8888 and 9090. It has no DNS hostname or previous documentation, and Sarah Park specifically noted that it could belong to Marcus or the former intern. This makes `UNKNOWN-01` a plausible match for the described Raspberry Pi, but that identity is **not yet proven**. The Asset Registry already classifies `UNKNOWN-01` as unmanaged shadow IT because its owner and approved purpose are unknown.

**Official controls that do not adequately cover the system**

* **C-011 — Sophos Endpoint Antivirus:** The control covers managed Windows workstations and explicitly excludes Linux systems. A Raspberry Pi running Linux therefore falls outside the documented Sophos scope.
* **C-012 — Nightly Veeam Backup Job:** The Pi is not one of the six systems covered by Veeam. No approved configuration backup or recovery mechanism is evidenced.
* **C-018 — Local Audit Logging:** A Linux system can generate logs, but an abandoned device cannot be assumed to have logging correctly configured, protected, retained, or reviewed. MedDefense’s general logging capability is already rated Weak because records remain decentralized and are not automatically correlated or alerted.
* **C-009/C-010 — Enterprise credential controls:** There is no evidence that the Pi authenticates through MedDefense Active Directory. It may retain old local credentials belonging to Marcus or the former intern.
* **C-001/C-004 — Perimeter firewall and logging:** These controls do not adequately contain a device already operating internally. The scan confirmed that internal subnets are broadly reachable, so a compromised Pi could interact with systems beyond its physical second-floor location.
* **C-021 through C-026:** These controls are specific to the MRI environment and are largely proposed rather than operational; they cannot be treated as protection for the Raspberry Pi. The control matrix explicitly distinguishes these design-state safeguards from implemented protection.

**Worst-case scenario**

The worst credible scenario is compromise of the Pi followed by its use as a **persistent internal reconnaissance and interception platform**. Because a network-monitoring device may already be designed to observe traffic and communicate with many internal systems, an attacker who obtains administrative access may inherit unusually broad visibility.

The attacker could capture network information, harvest credentials where exposed, identify vulnerable servers and clinical devices, maintain persistence through an inconspicuous device that no current employee owns, and use the Pi as a staging point for attacks against EHR, PACS, Active Directory, or medical equipment. The risk is increased by the fact that MedDefense’s network core and medical-device environments are already documented as under-protected and broadly connected.

### Recommended Response — **Decommission**

The appropriate response is to **decommission the existing Raspberry Pi**.

Although network monitoring is a legitimate security function, the existing device should not automatically be legitimized merely because Marcus may originally have requested it. The personnel who designed and maintained it have left, no current owner is identified, its configuration and credentials are unknown, and nobody has maintained it. These conditions make it impossible to establish that the device remains patched, trustworthy, necessary, or correctly configured.

Before removal, Security should identify the device physically, record its MAC address, IP address, connected switch port, running services, operating system, installed monitoring software, configured destinations, local accounts, scheduled tasks, and stored data. This review should also determine whether the device is `10.10.2.99 / UNKNOWN-01`. If the identifiers match, the existing AST-013 entry and the new Raspberry Pi entry should be reconciled into a single canonical record rather than maintained as duplicate assets.

Any security-relevant configuration or logs required for investigation should be preserved. The device should then be disconnected and securely wiped. If MedDefense still requires the monitoring function, IT and Security should deploy a new, formally approved monitoring platform with documented ownership, patch management, hardened authentication, centralized logging, configuration backup, network restrictions, and an established review process rather than reusing an abandoned system of uncertain integrity.

### Asset Registry Update

| Asset ID    | Name                                       | Type                      | Location                        | Owner (Dept)                                   | OS/Platform                                 | Critical Services                      | Network Segment                                                    | Status        | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ----------- | ------------------------------------------ | ------------------------- | ------------------------------- | ---------------------------------------------- | ------------------------------------------- | -------------------------------------- | ------------------------------------------------------------------ | ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **AST-059** | Former Intern Raspberry Pi Network Monitor | Network Monitoring Device | Central Hospital — second floor | Formerly Security/IT; current owner unassigned | Raspberry Pi / Linux; exact version unknown | Historical network-monitoring function | Central internal network; exact IP/MAC pending physical validation | **Shadow IT** | Reportedly installed by a former intern at Marcus Webb’s request and subsequently abandoned. May retain network telemetry, packet captures, monitoring credentials, or privileged configuration. Possible match for AST-013 / `10.10.2.99 UNKNOWN-01`, but identity must be confirmed through MAC address, switch-port tracing, or physical inspection before records are merged. Recommended action: preserve necessary evidence/configuration, decommission and securely wipe the device; replace with an approved monitoring platform only if the business requirement remains. |

---

# Shadow IT Policy Recommendation

MedDefense should establish a **mandatory pre-connection and cloud-service approval policy** requiring every device, application, storage platform, and external SaaS service that will connect to the MedDefense network or store/process MedDefense information to receive documented IT and Security approval **before use**. Approval should require a named business owner, technical owner, defined purpose, data classification, security review, authentication method, patch and vulnerability-management responsibility, logging requirements, backup and recovery requirements, and formal registration in the Asset Registry. Network Access Control or equivalent switch-port enforcement should support the policy by preventing unregistered devices from receiving normal production-network access wherever technically feasible, while procurement and expense procedures should prevent reimbursement for unapproved technology. This single governance change addresses the common root cause demonstrated by all three cases: users can currently solve legitimate operational problems by introducing technology without creating ownership, security, or lifecycle accountability. A documented approval path must also be sufficiently responsive to business needs, because a policy that only prohibits shadow IT without providing a timely route to approved storage, collaboration, or monitoring solutions would preserve the incentive for staff to bypass IT governance.
