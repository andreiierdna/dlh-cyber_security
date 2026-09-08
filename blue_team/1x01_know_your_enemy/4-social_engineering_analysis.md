# MedDefense Health Systems

## The Human Vector

## Scenario 1 — Fake FortiGate Emergency Patch

**Vector Type: Phishing**

The primary Security+ 2.2 vector is **phishing** because the attack is delivered through email and attempts to induce Sarah Park to follow a malicious link. Brand impersonation is a supporting technique because the attacker is posing as FortiGate/Fortinet support.

**Target:** **Sarah Park — IT Director.** She is a high-value target because IT controls MedDefense's network infrastructure and she has a legitimate operational reason to respond quickly to firewall vulnerabilities. The Asset Registry identifies **AST-043 FortiGate 100F** as MedDefense's single firewall and VPN termination point for Central, Westside, and HQ. The deception is particularly credible because **GAP-011** already establishes that MedDefense lacks a formal enterprise vulnerability and patch-management process covering firewalls, VPN systems, and other critical infrastructure.

**Psychological Lever: Urgency**

The attacker creates a 24-hour deadline and threatens service termination, encouraging Sarah to bypass normal verification and change-control practices.

**Red Flags:**

1. The sender uses `fortinet-support.net`, a look-alike domain rather than the expected official vendor domain.
2. The message instructs Sarah to obtain a critical infrastructure firmware update through an embedded email link rather than through an authenticated vendor support or firmware portal.
3. The threat of service termination within 24 hours creates artificial urgency inconsistent with a controlled security-advisory and patch-management process.

**Technical Control:** **Email security gateway with vendor-domain impersonation and malicious-URL analysis.** Configure O365 mail protection to identify newly registered or look-alike domains resembling approved security vendors and detonate or rewrite embedded URLs before delivery.

**Administrative Control:** **Formal vulnerability and patch-verification procedure.** Under the process required by GAP-011, firewall firmware advisories must be independently verified through the approved Fortinet security advisory/customer portal, and firmware must be downloaded only from the approved vendor repository after change review. An email link must never be treated as the authoritative patch source.

This control is especially important because compromise of AST-043 would not be confined to a single workstation: the prior assessment establishes that the FortiGate and switching infrastructure are common dependencies for almost every MedDefense service and that weak internal segmentation magnifies any network-core compromise.

---

## Scenario 2 — Fraudulent CEO Wire Transfer

**Vector Type: Business Email Compromise (BEC)**

This is a classic **business email compromise** scenario: an attacker impersonates executive leadership to manipulate a financial decision-maker into making an unauthorized payment.

**Target:** **Robert Kim — CFO.** The CFO has legitimate authority to initiate or approve significant financial transactions, making a payment request inherently plausible. His workstation also belongs to the **Administrative Endpoints and Corporate Applications** category, which the Criticality Assessment rates **High** because Finance and HR systems can access sensitive financial, employee, email, and business information.

**Psychological Lever: Authority**

The attacker exploits the CEO's organizational authority and combines it with confidentiality instructions to discourage Robert from seeking independent verification.

**Red Flags:**

1. The sender address differs subtly from Dr. Patricia Morales's legitimate email address even though the display name appears correct.
2. The CEO allegedly instructs Robert to transfer **$85,000 immediately** while bypassing ordinary discussion or approval channels.
3. The phrases **“Do not discuss with anyone”** and **“email only”** deliberately prevent the out-of-band verification that would expose the impersonation.

**Technical Control:** **Executive-impersonation and look-alike-domain detection in O365.** Configure email security controls to flag messages using executive display names when the underlying sender address or domain does not match MedDefense's authorized mail domain, with enhanced protection for the CEO, CFO, and other payment-authorizing executives.

**Administrative Control:** **Dual authorization and out-of-band verification for wire transfers.** Any new-beneficiary or exceptional wire transfer of this magnitude must require approval by a second authorized Finance employee and confirmation with the requesting executive using a previously established telephone number or approved internal communications channel. The contact information supplied inside the suspicious email must never be used for verification.

The procedure is necessary because MedDefense's **GAP-009** already identifies Finance and administrative endpoints as High-rated and confirms that stronger authentication and access governance are required around Finance and HR functions.

---

## Scenario 3 — “Mike from IT” Requests an EHR Password

**Vector Type: Vishing**

The primary vector is **vishing** because the attacker uses a telephone conversation to obtain authentication information. The fabricated emergency-security-audit story is also a pretext, while “Mike from IT” is an impersonated identity.

**Target:** **Nurse at MedDefense Central.** Nurses legitimately use the EHR throughout clinical shifts and are accustomed to cooperating with IT when systems interfere with patient care. The attacker makes the request more convincing by referencing the real billing-server incident and framing the call as an emergency security activity.

**Psychological Lever: Helpfulness**

The nurse is encouraged to believe that providing credentials will help IT complete an urgent security task and prevent further disruption.

**Red Flags:**

1. An alleged IT employee asks the nurse to disclose her **EHR password**. Legitimate administrators should not require a user's password to test whether an account works.
2. The call is unsolicited and relies on the previous billing-server incident to make an unrelated credential request appear legitimate.
3. The caller requests both username and password rather than directing the nurse to an approved IT helpdesk process or asking her to authenticate through a legitimate system.

**Technical Control:** **Phishing-resistant MFA for EHR access.** Even if the nurse discloses her password, possession of the password alone should not permit the attacker to authenticate. MedDefense currently lacks mandatory MFA; GAP-007 explicitly identifies this as a High identity risk.

**Administrative Control:** **IT identity-verification and password-disclosure procedure.** Security policy should state explicitly that IT and EHR support personnel will **never request a user's password by telephone, email, SMS, or chat**. Employees receiving unsolicited support calls must terminate the conversation and call the helpdesk through the published internal extension or service portal.

The consequence is greater than loss of one nurse's account. The Data Map identifies patient medical records as Restricted, while the prior posture assessment notes that EHR information is MedDefense's highest-priority data environment and that internal exposure is already broader than required.

---

## Scenario 4 — Fake Staff Parking Renewal Text

**Vector Type: Smishing**

The attack is **smishing** because malicious credential-harvesting content is delivered through SMS.

**Target:** **All MedDefense employees with staff parking privileges.** The message can target clinical, administrative, and technical employees simultaneously because parking is a common workforce service and does not depend on the recipient's technical role. Staff working long or irregular clinical shifts are particularly likely to respond quickly to a towing threat.

**Psychological Lever: Urgency**

The attacker provides an immediate deadline—“expires tomorrow”—and threatens towing to encourage users to act before checking the message.

**Red Flags:**

1. An unsolicited SMS requests immediate action concerning an employment benefit or facility service.
2. The link leads to an authentication page reached from a text message and requests **Active Directory credentials**.
3. The towing threat and next-day deadline pressure the employee to authenticate without first checking the official HR or parking system.

**Technical Control:** **Mandatory phishing-resistant MFA for Active Directory and remote-access services.** A stolen password captured through the fake HR page should not be sufficient to authenticate to MedDefense systems. The prior Gap Analysis identifies both missing MFA and weak identity monitoring under **GAP-007**.

**Administrative Control:** **Defined employee-notification standard for HR and facilities messages.** Parking, payroll, benefits, and other workforce notices should originate only through approved O365 or intranet channels. MedDefense should formally state that SMS messages will not contain links requesting AD credentials and instruct employees to navigate independently to the HR portal rather than use authentication links received by text.

The exposure is material because the Data Map classifies MedDefense authentication information as **Restricted**, and AD credentials may provide access well beyond the service imitated by the attacker.

---

## Scenario 5 — Compromised Healthcare Association Website

**Vector Type: Watering Hole Attack**

This is a **watering hole attack** because the attacker compromises a legitimate website known to be regularly visited by members of the target population and waits for MedDefense users to visit it.

**Target:** **MedDefense physicians completing CME activities.** Physicians visit the Regional Healthcare Association website approximately monthly for legitimate professional-development purposes. The attacker therefore does not need to convince them to visit an unfamiliar malicious site; normal work behavior delivers the victims to the compromised resource.

**Psychological Lever: Familiarity**

The website is already trusted because physicians routinely use it for CME credits, lowering suspicion compared with an unsolicited link.

**Red Flags:**

1. A normal CME page unexpectedly redirects the browser away from the Regional Healthcare Association's expected domain.
2. The site unexpectedly initiates a file download, browser-extension request, software-installation prompt, or other action unrelated to CME activity.
3. Browser, endpoint-security, or certificate warnings appear while accessing pages that previously functioned normally.

**Technical Control:** **Centrally managed browser and endpoint patching with rapid deployment of security updates.** The attack depends on successful exploitation of a browser vulnerability. Removing known exploitable browser versions reduces the likelihood that simply visiting the compromised site produces code execution. This directly aligns with **GAP-011**, which states that MedDefense lacks a formal vulnerability-management capability for operating systems and applications.

**Administrative Control:** **Managed-endpoint requirement for workforce web access.** CME and other professional sites used for work should be accessed from supported, MedDefense-managed endpoints subject to security updates and endpoint protection. Staff must report unexpected redirects or security warnings rather than bypassing them to complete time-sensitive training.

This scenario also exposes a limitation in existing **C-011 Sophos Endpoint Antivirus**: earlier control analysis found incomplete endpoint coverage and currency rather than universal protection, reinforcing the need for patch management rather than relying on malware detection alone.

---

## Scenario 6 — `meddefence-portal.com`

**Vector Type: Typosquatting**

The principal Security+ vector is **typosquatting** because the attacker deliberately registers `meddefence-portal.com`, exploiting a plausible misspelling of the legitimate MedDefense name. The pixel-perfect copy is also brand impersonation, but the fraudulent domain is the mechanism that creates the attack infrastructure.

**Target:** **MedDefense patients and patient-portal users.** This is the one scenario whose intended victim is external to the MedDefense workforce. Patients are vulnerable because they may locate the portal through a search engine rather than a saved institutional link, and the purchased advertisement places the fraudulent site above the legitimate search result.

The **Asset Registry** identifies **AST-021 Patient Portal** as an internet-facing application providing patients access to laboratory and health information; it has already experienced a broken-access-control incident that exposed other patients' laboratory results.

**Psychological Lever: Familiarity**

The attacker reproduces MedDefense branding and the expected patient-portal appearance so the victim sees a familiar service rather than an obviously malicious website.

**Red Flags:**

1. The domain uses **`meddefence`** rather than the legitimate MedDefense spelling.
2. The result appears as a paid or sponsored search result rather than a portal reached through MedDefense's known primary website.
3. A password manager or browser that normally recognizes the genuine portal does not recognize or automatically populate credentials on the fraudulent domain.

**Technical Control:** **Defensive domain registration and continuous look-alike-domain monitoring.** MedDefense should register high-probability typo variants of its patient-facing domains and monitor new DNS registrations and certificate issuance for domains containing MedDefense brand variants so fraudulent portals can be detected and submitted for takedown rapidly.

**Administrative Control:** **Canonical patient-portal access procedure and patient communication.** Appointment messages, discharge material, billing communications, and the main MedDefense website should consistently direct patients to one published portal address and instruct them not to locate the portal through search advertising.

The prior posture assessment is relevant here because existing **C-002 Web Server Inbound Service Restriction** protects the real `web-srv-01`, but perimeter controls on the genuine portal cannot prevent an attacker from creating an independent external copy of the MedDefense brand. The attack therefore bypasses a control that is effective for its intended scope rather than defeating it directly.

---

## Scenario 7 — Person in Scrubs Tailgates into the IT Corridor

**Vector Type: Impersonation**

The Security+ vector is **impersonation**. The attacker constructs the appearance of a legitimate healthcare worker using scrubs, a stethoscope, a hospital-branded coffee cup, and a plausible explanation for not presenting a badge. The physical technique used to cross the door is tailgating, which is already specifically addressed by MedDefense's existing awareness curriculum.

**Target:** **A MedDefense staff member authorized to enter the restricted administrative/IT corridor.** Employees routinely encounter clinicians wearing scrubs throughout Central Hospital, so the attacker's appearance reduces the likelihood of challenge. The employee is also placed in the socially uncomfortable position of either holding the door for an apparent colleague or refusing entry.

**Psychological Lever: Helpfulness**

The attacker relies on the staff member's willingness to assist an apparently legitimate colleague who claims to have temporarily misplaced access credentials.

**Red Flags:**

1. The person explicitly admits that they do **not have a working badge available** for a badge-controlled restricted area.
2. Their partially concealed visitor badge is **expired by two days**, directly contradicting the appearance of current authorization.
3. They attempt to enter immediately behind another employee instead of authenticating individually or requesting assistance from Security.

**Technical Control:** **Individual badge enforcement with anti-tailgating detection at the IT corridor.** Each entrant should be required to present a valid credential, with door-position or occupancy monitoring generating an alert when multiple people pass on one authentication where technically feasible.

This strengthens **C-017 — HID Electronic Badge Access**, which the Complete Control Matrix rates **Weak** because access-control coverage and enforcement are incomplete. The Asset Registry also documents physical weaknesses around critical infrastructure, including generic badge access, missing camera coverage and an unauthenticated route into the restricted administrative wing.

**Administrative Control:** **Strict no-tailgating and visitor-challenge procedure.** Employees must not badge unknown persons into controlled areas regardless of clothing, apparent clinical role, urgency, or familiarity. Anyone without a functioning current credential must be redirected to Security or escorted under the documented visitor process.

MedDefense already possesses **C-014 Visitor Registration and Badge Verification** and **C-016 Security Awareness Training**, but C-014 primarily protects the staffed lobby and C-016 has incomplete participation. The scenario therefore exploits an enforcement gap between initial visitor registration and access to sensitive internal areas.

---

## Overall Human-Vector Assessment

The seven scenarios show that MedDefense's social-engineering exposure is amplified by the same weaknesses identified in the previous posture assessment. The attacks are not isolated “user awareness” problems. A successful phish against Sarah Park could place the **Critical FortiGate/network core** at risk; a nurse's disclosed password could expose the **Critical EHR**; a smished AD credential could exploit **GAP-007's missing MFA**; a compromised physician workstation could benefit from **GAP-011's weak vulnerability-management process**; and physical impersonation could exploit already documented weaknesses surrounding MedDefense's restricted facilities. The Criticality Matrix specifically rates physical security infrastructure as Critical overall because unauthorized physical access could affect EHR, billing, authentication, backups, and other clinical systems simultaneously.

The common weakness is therefore **excessive reliance on successful human recognition without sufficient technical containment when recognition fails**. C-016 gives MedDefense a valid awareness foundation, but training alone cannot compensate for the absence of mandatory MFA, executive-payment verification, systematic patch verification, look-alike-domain detection, centralized monitoring, and stronger internal physical access enforcement. The prior Security Posture Assessment reached the same broader conclusion: MedDefense has meaningful controls, but they are unevenly aligned with the assets and data whose compromise would create the greatest clinical or business consequences.
