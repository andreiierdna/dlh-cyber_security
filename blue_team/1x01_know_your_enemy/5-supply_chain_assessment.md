# MedDefense Health Systems — Supply Chain Risk Assessment

## 1. MedTech Solutions

**Service:** EHR maintenance and software updates (contract value $145,000/yr, SLA 4hr response for critical issues / 24hr standard; covers software updates only, not hardware).

**Access Type:** Network (remote maintenance connectivity) + Application (direct administrative access to the EHR application stack).

**Access Scope:** MedTech's contracted access target is ehr-srv-01 (AST-001, `10.10.2.10`), the EHR application server serving both Central (~1,400 staff) and Westside (~180 staff). However, the application's own dependency chain extends this access further than the contract implies: ehr-db-01 (AST-002, `10.10.2.11:5432`) is documented as reachable from the entire `10.10.0.0/16` range rather than being restricted to ehr-srv-01 alone. Because Central has no VLAN segmentation (Environment Summary §2.3; Asset Registry Reconciliation Note §1 confirms Sarah Park's own HQ workstation could reach all subnets without restriction), any remote-access foothold on ehr-srv-01 is, in practice, a foothold on the same broadcast domain as ad-dc-01/02 (AST-005/006, authentication), billing-srv-01 (AST-004, already compromised once by ransomware and cryptomining), pacs-srv-01 (AST-003), file-srv-01 (AST-007), and backup-srv-01/NAS-01 (AST-009/010). The contract does not document whether MedTech's access is scoped to a jump host, a VPN tunnel, or direct server login, nor whether it is time-boxed to maintenance windows (Known Unknown #11).

**Compromise Scenario:** MedTech's own environment is breached (credential theft, phishing, or a compromised remote-support tool). The attacker uses MedTech's standing maintenance access to reach ehr-srv-01. From there, because ehr-db-01 is network-wide reachable and SSH password authentication remains enabled on every Linux host except ehr-srv-01 (Environment Summary §2.6), the attacker pivots laterally across the flat `10.10.0.0/16` segment to ad-dc-01 (harvesting or forging authentication tokens), to billing-srv-01 (a host with a demonstrated prior compromise history), and to pacs-srv-01. The result is not a contained "EHR maintenance vendor incident" but a domain-wide compromise: EHR application and database access is lost or ransomed, PHI for the full Central and Westside patient population is exposed, and — because ehr-db-01 sits on the same segment as the medical-device subnet addressing (`10.10.3.0/24`, no enforced VLAN separation per AST-036/037) — the blast radius extends toward patient monitors and infusion pumps.

**Existing Controls:** SSH key-only authentication is confirmed only on ehr-srv-01 itself (Environment Summary §2.6), which reduces brute-force risk on that single host but does nothing to contain lateral movement once a session is established, and does not apply to ehr-db-01. No MFA is deployed anywhere in the organization except James Chen's personal account (self-configured). No network segmentation limits how far a MedTech-originated session could travel. No vendor-access logging, session recording, or least-privilege scoping is documented in the MedTech contract.

**Risk Assessment: CRITICAL.** This is the single vendor with continuous, contracted, privileged access to the most clinically critical system in the environment (AST-016, EHR — previously responsible for a nine-hour outage that forced a return to paper records), combined with a network architecture that converts any compromise of that access into an organization-wide incident.

---

## 2. Microsoft (O365 E3)

**Service:** Organization-wide email, SharePoint, and OneDrive (AST-024); largest single IT line item at $432,000/yr, renewing every September. The task brief notes O365 "manages identity if Entra ID is used" — the source material does not document whether MedDefense's on-premises Active Directory (ad-dc-01/02, AST-025) is synchronized to Entra ID/Azure AD, so hybrid-identity exposure is an open question, not a confirmed fact.

**Access Type:** Data (cloud-hosted mailboxes, files, collaboration data) and, conditionally, Identity (unconfirmed).

**Access Scope:** All ~2,000 employees across Central, Westside, and HQ use O365 for email and file collaboration, including HQ's Finance, HR, Legal, and Executive Leadership functions — the departments most likely to handle financial data, employee PII, and privileged legal communications. Critically, O365 data is explicitly excluded from the Veeam backup scope (AST-024 notes), meaning MedDefense has no independent copy of its own email and SharePoint data outside Microsoft's platform.

**Compromise Scenario:** Two distinct paths exist, and the more probable one is not "Microsoft's infrastructure is breached" but "MedDefense's own accounts on Microsoft's infrastructure are breached," because no MFA is deployed org-wide (Environment Summary §2.6) despite the $432,000 annual O365 E3 spend that includes MFA capability. A single phished or credential-stuffed account belonging to, for example, an HQ Finance or Legal staff member yields direct access to that mailbox and any SharePoint/OneDrive content they can reach, with no second factor to stop it — enabling business email compromise, wire-fraud instructions to Finance, or lateral phishing using a trusted internal sender identity. The lower-probability but higher-impact path is a platform-level or supply-chain event at Microsoft (comparable to nation-state token-forging incidents affecting M365 in recent years), which — given the absence of independent backups — would leave MedDefense with no fallback copy of organization-wide email and document data.

**Existing Controls:** None beyond the unconfigured MFA capability included in the O365 E3 license. No conditional access policies, data loss prevention rules, or independent backup are documented.

**Risk Assessment: CRITICAL.** The severity here is driven less by Microsoft's platform security (generally strong) and more by MedDefense's own implementation gap: an organization-wide, un-backed-up data store protected by password-only authentication is a single point of failure regardless of vendor quality.

---

## 3. Sophos

**Service:** Endpoint protection agent installed on all managed endpoints, with vendor-side capability to push updates and configuration changes ($18,000/yr, renews January).

**Access Type:** Application (privileged code/policy execution on every managed endpoint via the management console).

**Access Scope:** Potentially the full managed endpoint population: ~320 Central workstations, ~60 clinical thin clients, ~45 Westside workstations, ~120 HQ workstations, and ~30 HQ laptops (Environment Summary §2.4; Asset Registry AST-027–031), though the Environment Summary explicitly flags that "current status on all machines" is unverified (§3.4), and Marcus Webb's notes independently confirm he never established whether Sophos was current fleet-wide. An EDR/AV console is, by design, a trusted software-distribution channel with the ability to push arbitrary configuration or code to every enrolled device simultaneously.

**Compromise Scenario:** An attacker compromises Sophos's cloud management console — most plausibly via phished MedDefense IT-admin credentials to that console, since no MFA is documented anywhere in the organization — and pushes a malicious policy or signed "update" through the same trusted channel used for legitimate protection. Because Sophos is deployed across all three sites, this is one of the few vectors that could reach Central clinical workstations, Westside endpoints, and HQ Finance/Legal/Executive machines in a single coordinated action, without needing to traverse the network at all. The unresolved currency gap compounds this: some endpoints may already be running outdated agents, meaning the fleet is simultaneously exposed to this distribution-channel risk and under-protected against conventional malware.

**Existing Controls:** None are documented specific to the Sophos management console — no mention of restricted admin access, MFA on the console, or change-approval workflow for pushed policies. The contract, per Known Unknown #11, defines service and cost only.

**Risk Assessment: HIGH.** Reach is comparable to O365 in scale, but likelihood is lower absent evidence of active targeting or console misconfiguration; it is rated below MedTech (which has confirmed standing access to the most critical clinical system on an unsegmented network) but above Greenfield.

---

## 4. Siemens (MRI Scanner Manufacturer)

**Service:** Periodic maintenance of the MRI control workstation and firmware updates for the Siemens MAGNETOM scanner.

**Access Type:** Physical (on-site field service) + Network/Application (diagnostic and firmware access to the control workstation).

**Access Scope:** The maintenance target is WS-RAD-01 (AST-034, `10.10.1.70`), confirmed by the network scan to still run Windows XP SP3 — an operating system out of support for over a decade, which cannot be patched or upgraded because doing so would void the device's medical-device certification (Marcus Webb's notes flag this as CRITICAL). WS-RAD-01 sits on the same flat, unsegmented Central clinical subnet as WS-RAD-02 and other radiology endpoints, and must maintain live connectivity to pacs-srv-01 (AST-018) to transfer completed studies — meaning Siemens's legitimate maintenance access sits directly on the MRI-to-PACS data path.

**Compromise Scenario:** Siemens's remote diagnostic tooling, a field engineer's service laptop, or a firmware update package is compromised upstream (a documented class of real-world attack against medical-device vendors and industrial firmware supply chains). Because WS-RAD-01 cannot be patched, any foothold gained through this vendor is exceptionally difficult to remediate short of full network isolation or device replacement — there is no patch to apply. From WS-RAD-01, an attacker can reach other Central radiology endpoints on the same unsegmented subnet and, via the required PACS connectivity, the imaging repository holding every patient's diagnostic study history. This is a distinct risk profile from MedTech: lower access frequency (periodic maintenance, not continuous), but a fundamentally unremediable landing point once compromised.

**Existing Controls:** None documented. No network segmentation isolates WS-RAD-01 from the rest of Central's clinical subnet, and no compensating host-based controls (application allow-listing, host firewall) are recorded for a workstation that cannot receive OS-level security patches.

**Risk Assessment: HIGH.** Access frequency and vendor breach likelihood are lower than MedTech's continuous EHR access, but the complete inability to patch or contain the landing point, combined with life-safety-adjacent equipment, keeps this above Medium.

---

## 5. Greenfield Building Management

**Service:** Manages the underlying network infrastructure of the HQ building; MedDefense operates its own VLAN on Greenfield's shared infrastructure (network/internet cost is bundled into the lease, no standalone fee).

**Access Type:** Network (physical and logical control of the switching infrastructure underlying MedDefense's HQ VLAN).

**Access Scope:** Greenfield's infrastructure carries traffic for all ~220 HQ staff (Finance, HR, Legal, Marketing, Executive Leadership, IT) and terminates the HQ-to-Central site-to-site VPN, which connects back to the single FortiGate 100F (AST-043) that also serves as Westside's VPN termination point (Environment Summary §2.3, §3.2). Marcus Webb's notes state the HQ VPN "seems properly configured" but that its ACLs were never actually audited (Known Unknown #5). HQ has no on-premises servers, so there is no local data-at-rest exposure through this vendor, but session traffic — including O365 authentication, VPN credentials, and Finance/Legal/Executive communications — transits infrastructure MedDefense does not control.

**Compromise Scenario:** An attacker compromises Greenfield's building-wide network management plane (a lower-profile but plausible target, since building operators typically have weaker security investment than technology vendors). From there, VLAN misconfiguration or hopping techniques are used to attempt access to MedDefense's logically separated VLAN, or to intercept/manipulate traffic bound for the Central VPN tunnel. Because the VLAN's ACLs have never been audited, the actual strength of this logical separation is unverified rather than confirmed.

**Existing Controls:** MedDefense's dedicated VLAN provides a documented layer of logical separation, but its effectiveness is unverified. No additional encryption, monitoring, or landlord-side security requirements are documented in the lease-included arrangement.

**Risk Assessment: MEDIUM.** Impact is bounded — no PHI or clinical systems live at HQ — and building-network operators are a lower-probability target than an active clinical-system maintenance vendor, but the unaudited ACL and single-firewall dependency prevent a Low rating.

---

## Supply Chain Risk Summary

**Which single vendor compromise would cause the most damage, and why?** MedTech Solutions. Answering James Chen's original question directly: if MedTech is breached tomorrow, the attacker does not just gain access to "the EHR server" — they gain a foothold on the same unsegmented `10.10.0.0/16` network as ad-dc-01/02 (authentication for the entire organization), billing-srv-01 (a host with a *documented prior compromise*), pacs-srv-01, and the medical-device addressing space, because ehr-db-01 is reachable from the entire internal network rather than restricted to ehr-srv-01, and because Central has no VLAN segmentation to contain a maintenance session that goes wrong. O365 and Sophos both have broader raw *reach* (every endpoint or every mailbox, respectively), but their risk is driven primarily by MedDefense's own missing MFA, not by the vendor relationship itself. MedTech is unique in combining continuous, privileged, contracted access to the single most clinically critical system in the environment (EHR — AST-016, previously responsible for a nine-hour paper-records outage) with a network architecture that offers that access no containment whatsoever. **The one control MedDefense should implement first, across all five vendors, is network segmentation of vendor and administrative access into a dedicated, monitored, least-privilege zone** (e.g., a jump host or bastion isolating remote maintenance sessions from ehr-db-01, ad-dc-01/02, billing-srv-01, and the medical-device subnet, with MFA required to reach it). This single control directly interrupts the compromise path described for MedTech, Sophos, Siemens, and Greenfield alike, all of which are amplified by the same underlying fact confirmed independently by both Marcus Webb's notes and the network scan: MedDefense's internal environment is currently one flat, unsegmented network in which no vendor's access can be contained to its intended scope.
