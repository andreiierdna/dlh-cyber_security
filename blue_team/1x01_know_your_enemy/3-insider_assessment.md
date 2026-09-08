# MedDefense Health Systems

## The Insider File

## Scenario 1 — The Shared Login

**Classification: Negligent.**
There is no evidence that the Radiology technicians are intentionally using the shared `raduser/radiology1` account to steal, alter, or disclose information. The risk arises from a convenience-driven departmental practice that eliminates individual accountability. This is nevertheless significant because PACS is a **Critical** asset containing **Restricted** diagnostic imaging data. The prior Data Map specifically concludes that the shared `raduser` credential prevents reliable attribution and increases the consequences of credential disclosure.

**Behavioral Indicators:**

1. **Continuous `raduser` sessions spanning multiple technicians or shifts.** Authentication or PACS-access records would show one identity remaining active through periods when different technicians were scheduled to operate the workstation.
2. **The same account appearing across multiple Radiology workstations or simultaneous sessions.** This would indicate credential sharing rather than a uniquely authenticated user.
3. **Absence of individual login/logout events between patient examinations.** A workstation repeatedly accessing different patient studies without any associated user transition is a direct indicator that accountability controls are being bypassed.

**Existing Control (from Complete Control Matrix): C-018 — Local Operating-System and Application Audit Logging.**
C-018 should provide evidence of PACS/application activity, but the shared identity substantially defeats its purpose because the resulting record establishes only that `raduser` performed an action, not which technician performed it. C-018 is already rated **Weak** because logs are decentralized and lack automated correlation or alerting.

**Gap Exploited (from Gap Analysis): No standalone numbered gap; supplementary deficiency associated with GAP-001.**
The predecessor review explicitly assessed the shared `raduser/radiology1` credential as finding **M-07**, rated Medium, and determined that it should be incorporated into **GAP-001** as a supplementary PACS accountability/preventive-control deficiency rather than assigned a separate Critical/High gap number.

**Recommended Mitigation: Technical — unique PACS user authentication.**
Replace `raduser` with **named, individual AD-backed PACS accounts** for every Radiology technician and configure the workstation to require rapid user switching or badge-based re-authentication between operators. PACS audit events would then identify the actual technician responsible for each patient-record access without imposing a full system logout between examinations.

---

## Scenario 2 — The Ghost Account

**Classification: Malicious use enabled by negligent account administration.**
Leaving the contractor's account enabled for 47 days after contract termination is a negligent organizational control failure. However, the three successful authentications after authorization had ended—particularly during off-hours—constitute **suspected malicious valid-account use** unless forensic investigation demonstrates that an external attacker had stolen the credentials. A former contractor has no legitimate authorization to authenticate after the contract termination date.

**Behavioral Indicators:**

1. **An active VPN account whose owner had already reached the HR or contract termination date.** A daily reconciliation between active remote-access accounts and current workforce/contractor records would have identified the account before any subsequent login.
2. **Successful VPN authentication after the contractor's termination date.** The first post-termination authentication should have generated an immediate identity-security alert.
3. **Off-hours activity inconsistent with the contractor's historical access pattern.** Three post-termination authentications outside normal working hours provide a strong behavioral signal even though technically valid credentials were used.

**Existing Control (from Complete Control Matrix): None adequately covers identity lifecycle termination.**
C-009 governs password complexity and rotation, while C-010 locks remote-access/domain accounts after repeated failed attempts. Neither determines whether a person is still authorized to possess the account. C-004 can record VPN-related network activity, but its logs are local and are not centrally correlated or actively monitored.

**Gap Exploited (from Gap Analysis): GAP-013 — User Account Offboarding Is Not Evidenced as Automated or HR-Integrated.**
GAP-013 directly identifies the absence of HR-to-IT lifecycle integration, automated deprovisioning, defined deactivation deadlines, and recurring orphan-account reviews. The prior assessment specifically warns that a former employee, contractor, or vendor could continue accessing VPN, EHR, file shares, and other systems using credentials that still appear technically valid. The risk is compounded by **GAP-007**, because mandatory MFA and centralized identity alerting are also absent.

**Recommended Mitigation: Administrative/Technical — HR-integrated automated account deprovisioning.**
Connect the authoritative HR/contractor system to the identity lifecycle process so that **AD, VPN, EHR, email, and other dependent accounts are automatically disabled at the recorded contract end time**, with an exception requiring documented manager and Security approval. This removes the valid credential before post-termination activity can occur.

---

## Scenario 3 — The Personal NAS

**Classification: Negligent.**
Dr. Patel appears to be pursuing a legitimate clinical/research convenience objective rather than intentionally attempting to expose patient information. However, deliberately connecting personally owned storage to a hospital network and placing patient-file copies on an unencrypted, unmonitored and unbacked device constitutes negligent handling of Restricted information. The earlier Shadow IT assessment conservatively treated PHI on the NAS as only *potential* because the evidence then established only “research data”; this scenario now establishes that patient-file convenience copies are present. The prior assessment already identified the device as **AST-057 Dr. Patel Personal Research NAS** and GAP-005 as a Critical shadow-storage weakness.

**Behavioral Indicators:**

1. **A previously unknown MAC address/storage appliance appearing on Dr. Patel's office switch port.** Network access-control or switch inventory reconciliation would identify a device not present in the approved asset inventory.
2. **Regular SMB/NFS or other storage traffic between Cardiology endpoints and an unregistered internal IP address.** Large or recurring patient-file transfers to a non-MedDefense storage endpoint would be abnormal.
3. **Asset-management discrepancy.** A continuously active network device with no MedDefense owner, endpoint agent, AD membership, backup job, patch status, or approved configuration would indicate shadow IT.

**Existing Control (from Complete Control Matrix): None adequately covers the NAS.**
The prior Shadow IT assessment explicitly found that **C-011 Sophos does not cover the NAS, C-012 does not back it up, C-018 logging cannot be assumed to operate on it, and C-009/C-010 cannot be assumed to govern its local credentials**. Perimeter controls C-001/C-004 also do not prevent a device already attached inside the network from communicating laterally.

**Gap Exploited (from Gap Analysis): GAP-005 — Unmanaged Cardiology NAS Operates Outside Enterprise Controls.**
GAP-005 is rated **Critical** because the NAS may contain Restricted clinical information while lacking managed authentication, endpoint protection, centralized monitoring, segmentation and backup. Its attachment to MedDefense's broadly connected internal network means compromise could provide a path toward EHR, PACS, Active Directory, file services or medical devices.

**Recommended Mitigation: Technical — network admission control for unmanaged devices.**
Implement **802.1X/NAC on hospital access ports so only inventory-registered, MedDefense-managed devices are permitted onto the production network**. AST-057 should be quarantined, its patient and research data migrated to an approved MedDefense-managed encrypted research repository, and the personal NAS denied further production-network access. This implements the migration direction already established in the Shadow IT assessment.

---

## Scenario 4 — The Curious Employee

**Classification: Malicious.**
The clerk intentionally accessed a politician's medical record without a legitimate registration or treatment purpose and intentionally disclosed the information to a friend. The fact that she did not modify the EHR does not make the conduct negligent: the unauthorized access and subsequent disclosure were deliberate confidentiality violations involving **Restricted PHI**. The Criticality Assessment rates the EHR **Critical across confidentiality, integrity and availability**, with unauthorized PHI disclosure specifically identified as a regulatory and legal consequence.

**Behavioral Indicators:**

1. **EHR access without a corresponding registration encounter, assigned workflow or care relationship.** A front-desk clerk opening the politician's clinical record when she had no registration task associated with that patient is contextually abnormal even though her credentials are valid.
2. **Access to a high-profile/VIP patient's record by a user outside the treatment or registration team.** The access event itself could generate an alert before the information is disclosed externally.
3. **Unusual record-search behavior for the employee's role.** Searches or chart views unrelated to patients being processed at the clerk's workstation would distinguish curiosity-driven access from ordinary registration activity.

**Existing Control (from Complete Control Matrix): C-018 — Local Operating-System and Application Audit Logging.**
The EHR does generate audit records, but C-018 is Weak: EHR audit access can depend on a vendor export taking approximately 48 hours, and there is no automated correlation or alerting. The Data Map similarly states that EHR audit logs are not routinely centrally reviewed.

**Gap Exploited (from Gap Analysis): GAP-016 — No Centralized Security Monitoring or Log Correlation Capability.**
No existing numbered gap specifically addresses contextual “minimum necessary” or treatment-relationship monitoring inside the EHR. However, **GAP-016** is the principal enabling detective gap because valid but suspicious EHR access is recorded without being converted into a timely alert. GAP-016 is rated Critical and specifically calls for centralized high-value logs and automated alerting for EHR, domain-controller and firewall activity. GAP-014 is less directly applicable because this scenario involves viewing and verbal disclosure rather than bulk electronic extraction.

**Recommended Mitigation: Technical — real-time contextual EHR access monitoring.**
Configure EHR audit monitoring to **alert the Privacy/Security team immediately when VIP records or other sensitive charts are accessed by a user without an associated encounter, care-team assignment or registration workflow**. Where supported, require a documented “break-glass” justification for exceptional access. This preserves necessary clinical access while making illegitimate use of valid access observable.

---

## Scenario 5 — The Overworked Admin

**Classification: Negligent.**
The administrator's objective is operational—to reduce a password-reset backlog—and there is no indication that he intends to compromise Active Directory. Nevertheless, embedding an AD administrator credential in plaintext and distributing it through email is a serious negligent handling of privileged authentication material. The **Data Map classifies system credentials and authentication information as Restricted**, specifically because compromise of privileged credentials could provide access to multiple systems and permit organization-wide privilege manipulation. Active Directory itself is rated **Critical** because directory-level compromise could alter accounts, group membership, policies and access rights throughout MedDefense.

**Behavioral Indicators:**

1. **Plaintext credential material written to a user desktop.** Endpoint content inspection or secret-scanning controls could identify passwords, administrator usernames or authentication strings embedded in scripts.
2. **A script containing privileged authentication material sent as an email attachment.** DLP or mail security inspection could identify the attempted distribution before the colleague receives reusable credentials.
3. **Routine password resets being performed with a highly privileged AD administrator identity from an ordinary workstation.** Repeated privileged reset activity outside a controlled administrative host or delegated helpdesk role would indicate excessive privilege use.

**Existing Control (from Complete Control Matrix): C-009 — Password Complexity, Rotation and History Policy, but coverage is inadequate.**
C-009 applies to MedDefense user accounts and establishes password requirements, but it does not govern **how privileged secrets are stored, embedded in automation, retrieved, or shared**. No dedicated Privileged Access Management or credential-vault control is identified in the Complete Control Matrix.

**Gap Exploited (from Gap Analysis): GAP-007 — Active Directory Relies on Passwords Without Mandatory MFA or Centralized Alerting.**
GAP-007 is the closest existing identity gap because AD relies on reusable passwords and lacks centralized alerting; the Complete Control Matrix describes AD as only Partially Protected for the same reason. The scenario is also compounded by **GAP-018 — No Formal Change Management Process**, because administrator-developed production automation is not subject to mandatory testing, peer review or approval before distribution.

**Recommended Mitigation: Technical — Privileged Access Management with delegated automation identities.**
Implement a **PAM/secrets-management control in which scripts cannot contain administrator passwords**. Password-reset automation should execute through a dedicated managed identity or delegated service account permitted only to perform approved reset functions, with its credential held in a protected vault or managed automatically rather than stored on an administrator workstation or transmitted by email.

---

## Pattern Assessment

The systemic weakness that makes insider threats particularly dangerous at MedDefense is that the organization grants legitimate users necessary access to **Critical systems and Restricted data without an equally mature capability to establish individual accountability, govern the lifecycle of that access, detect abnormal use, or prevent users from moving sensitive information outside managed controls**. The Asset Criticality Assessment establishes that EHR, PACS and enterprise identity are all Critical, so misuse of an ordinary clinical or administrative credential can immediately reach high-consequence assets rather than low-value peripheral systems. The Data Map then shows the practical weakness around those assets: PACS activity cannot be reliably attributed because of the shared `raduser` account, EHR and AD logs are not centrally alerted, and Restricted authentication material may exist on administrator endpoints. The Gap Analysis reinforces the same pattern through **GAP-005** for unmanaged clinical storage, **GAP-013** for incomplete offboarding, and **GAP-016** for missing centralized behavioral detection. Consequently, MedDefense's principal insider-risk failure is not that staff have access—they require broad access to provide healthcare—but that **valid access is too often treated as equivalent to legitimate use**. Shared identities obscure who acted, stale accounts preserve authorization after employment ends, unmanaged devices bypass enterprise safeguards, EHR activity is recorded without timely contextual analysis, and privileged credentials can be handled outside controlled administrative processes. This combination permits both malicious insiders and negligent employees to operate inside trusted workflows for too long before MedDefense can distinguish appropriate clinical access from a security incident.
